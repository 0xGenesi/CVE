# Path Traversal in MediaUploadTrait::deleteFile() leading to arbitrary file deletion

**Affected versions:** Grav CMS >= 1.7.0 through develop branch (2.0.16), including the latest release 2.0.15

## Summary

Grav CMS exposes an authenticated media deletion endpoint through the admin panel (`media.delete` task). In the audited Grav CMS develop branch (version 2.0.16) — with code identical to the latest release 2.0.15 (confirmed via source diff), and present since at least 1.7.0 — a low-privileged authenticated user can delete arbitrary files outside the intended media directory because `MediaUploadTrait::deleteFile()` only validates the basename of the supplied filename with `Utils::checkFilename()` and does not validate the path component (dirname / pathname).

An attacker can submit a filename containing `../` traversal sequences (e.g. `../../../../config/security.yaml`) through the admin panel media deletion AJAX request. Because `basename('security.yaml')` contains no dangerous characters it passes the check, after which the attacker-controlled pathname is reassembled and concatenated into the final `unlink()` target, deleting a file outside the expected media folder.

## Vulnerability Description

The media deletion flow is reachable through `FlexMediaTrait::deleteMediaFile(string $filename)`, which receives the filename from the HTTP request and forwards it directly to `$media->deleteFile($filename)` without any path validation. `FlexForm::getFileDeleteAjaxRoute()` generates the `/edit.json/task:media.delete` route that serves this request.

Inside `MediaUploadTrait::deleteFile()`, the application validates only the basename of the filename:

```php
public function deleteFile(string $filename, ?array $settings = null): void
{
    $settings = $this->getUploadSettings($settings);
    $filesystem = Filesystem::getInstance(false);

    // First check for allowed filename.
    $basename = $filesystem->basename($filename);
    if (!Utils::checkFilename($basename)) {  // BUG: only checks basename, not pathname
        throw new RuntimeException(...);
    }

    $path = $settings['destination'] ?? $this->getPath();
    ...
    $pathname = $filesystem->pathname($filename);  // attacker-controlled path part
    [$base, $ext,,] = $this->getFileParts($basename);
    $name = "{$pathname}{$base}.{$ext}";  // reassembles with traversal path

    // Remove file and all the associated metadata.
    $this->doRemove($name, $path);  // calls unlink("{$folder}/{$name}")
}
```

Because `Utils::checkFilename()` is only applied to the basename extracted via `$filesystem->basename($filename)`, the traversal sequences in the pathname portion are never inspected. When the filename is later reassembled as `$name = "{$pathname}{$base}.{$ext}"` and passed into `doRemove()`, the attacker-controlled traversal path is preserved. `doRemove()` ultimately calls `unlink("{$folder}/{$name}")`, where `$folder` is the resolved media directory and `$name` contains the injected traversal sequence, so the final path escapes the intended directory boundary.

This contrasts with `checkFileMetadata()` in the same class (the upload validation path), which validates the complete `$filepath`. The delete path omits validation of the path component, making it the vulnerable counterpart.

The vulnerable entry points and sink:

- **Source:** admin panel media deletion AJAX request `filename` parameter, passed through `FlexMediaTrait::deleteMediaFile(string $filename)` or form submission data in `FlexMediaTrait::saveUpdatedMedia()`.
- **Sink:** `unlink("{$folder}/{$filename}")` inside `MediaUploadTrait::doRemove()` (line 538), where `$filename` contains the attacker-injected traversal sequence.
- **CWE:** CWE-22 (Path Traversal). This is the same CWE category as the historical Grav CMS advisories CVE-2024-29035 (arbitrary file deletion) and CVE-2024-29034 (arbitrary file read).

## Exploitation

1. Authenticate as any user with at least page-editing privileges and obtain a valid admin session cookie.
2. Navigate to a page that contains media files (e.g. `/admin/pages/01.blog/post-1`) to reach the media management area.
3. Send an AJAX request to the `media.delete` task endpoint with a `filename` parameter containing path traversal sequences.

```text
POST /admin/pages/01.blog/post-1/edit.json/task:media.delete HTTP/1.1
Host: target-site.com
Cookie: [authenticated session cookie]
Content-Type: application/x-www-form-urlencoded

filename=../../../../.htaccess
```

4. The server returns HTTP 200 with a success message. Internally, the request traverses the following chain:

   - `FlexMediaTrait::deleteMediaFile(string $filename)` receives the raw `filename` from the HTTP request and passes it to `$media->deleteFile($filename)` with no path validation.
   - `deleteFile()` extracts `basename('../../../../.htaccess')` = `.htaccess`, which contains no dangerous characters, so `checkFilename()` passes. The `../` sequences in the pathname are ignored.
   - `pathname('../../../../.htaccess')` = `../../../../` is reassembled with the basename into `$name = ../../../../.htaccess`.
   - `doRemove()` executes `unlink("{$folder}/../../../../.htaccess")`. With `$folder` resolved to e.g. `/var/www/grav/user/pages/01.blog/post-1`, the final path traverses to `/var/www/grav/.htaccess` and deletes it.

5. Verify the deletion by requesting the target file directly:

```text
GET /.htaccess HTTP/1.1
Host: target-site.com
```

   An HTTP 404 Not Found response confirms that `.htaccess` has been deleted. Directory browsing restrictions are now lifted, potentially exposing sensitive directories such as `user/config/` and `accounts/`.

## Impact

An authenticated low-privileged user can delete arbitrary files on the server through the admin panel media deletion feature. Practical attack scenarios include:

1. Deleting `security.yaml` to disable XSS protection and the Twig sandbox, enabling further exploitation through stored XSS or server-side template injection.
2. Deleting `.htaccess` to lift directory browsing restrictions and expose sensitive files and directory structures.
3. Deleting system configuration files to cause a denial of service.
4. Deleting Twig cache files to trigger race conditions during cache rebuild.

In multi-user CMS environments such as blogs or community sites that allow user registration, this vulnerability can be exploited by low-privileged users to cause severe impact, including complete compromise of the Grav installation integrity.

## Remediation

In `deleteFile()`, apply `checkFilename()` to the complete `$filename` (including the path component) rather than only the basename. The recommended approaches are:

1. Validate the full assembled filepath: run `checkFilename($pathname . $basename)` before reassembling the final path.
2. Or reject any filename containing path separators outright and accept only a plain filename.

Refer to the correct implementation in `checkFileMetadata()` (lines 156-163) in the same file, which validates the complete `$filepath = $folder . $filename`.
