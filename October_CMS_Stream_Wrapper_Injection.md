# Incomplete scheme validation in October CMS ResizeImages enables PHP stream wrapper injection

**Affected versions:** October CMS <= 4.3.4 (4.x branch, commit 30ed4b41e)
**CVE:** Pending
**CVSS 3.1:** 7.5 (High) — `CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H`
**CWE:** CWE-22 (Improper Limitation of a Pathname to a Restricted Directory), CWE-918 (Server-Side Request Forgery)

## Summary

The `System\Classes\ResizeImages` class in October CMS implements SSRF protections (`validateExternalImageUrl`, `validateExternalImageHost`, `validateImageContents`) that are applied to image paths classified as "external." However, the classification logic in `getSourcePathForResize()` uses an incomplete prefix check — `strpos($realSourcePath, 'http') === 0` — that only matches paths beginning with `http`. PHP stream wrapper URIs using other schemes (`phar://`, `file://`, `ftp://`, `php://`) are classified as local paths and bypass all three validation layers entirely, passing through unmodified to `Resizer::open()`.

The most severe consequence is PHAR deserialization: when a `phar://` URI reaches the Resizer, PHP's stream wrapper subsystem deserializes the PHAR archive's metadata, which can contain an arbitrary PHP object payload. If a POP gadget chain exists in the application's autoloaded classes, this leads to Remote Code Execution. The `/resize/{file}` route is publicly accessible without authentication, meaning any cached malicious path can be triggered by an unauthenticated visitor.

## Vulnerability Description

The image resize system accepts image paths through `ResizeImages::resize()`, which is exposed to Twig templates as the `|resize` filter and called internally by several backend components (MediaFinder, list column image processing).

### Path classification in ResizeImageItem

When `$image` is a string, `ResizeImageItem::fromObject()` resolves it. Any string containing `://` that does not resolve to a local file is stored verbatim as both the URL and the filesystem path:

```php
// modules/system/classes/ResizeImageItem.php:261-278
elseif (is_string($image)) {
    $path = $this->parseFileName($image);   // file_exists() check — itself triggers phar:// deserialization

    if ($path !== null) {
        $result['source'] = 'local';
    }
    elseif (strpos($image, '://') !== false) {
        $result['url'] = $result['path'] = $image;    // stored without scheme validation
        $result['extension'] = explode('?', File::extension($image))[0];
        $result['source'] = 'url';
    }
}
```

### Incomplete scheme check in getSourcePathForResize

The cached path is later processed in `processImage()`, which passes it to `getSourcePathForResize()`. The critical flaw is on line 191:

```php
// modules/system/classes/ResizeImages.php:189-237
protected function getSourcePathForResize($realSourcePath, $tempSourcePath)
{
    $isExternal = strpos($realSourcePath, 'http') === 0;           // line 191 — BUG
    $sourcePath = $isExternal ? $tempSourcePath : $realSourcePath;  // line 192

    if ($isExternal) {                                               // line 194
        // These three checks ONLY execute for http(s) URLs:
        if (!$this->validateExternalImageUrl($realSourcePath)) { ... }    // extension whitelist
        elseif (!$this->validateExternalImageHost($realSourcePath)) { ... } // SSRF IP filtering
        else {
            $contents = @file_get_contents($realSourcePath, false, stream_context_create([...]));
            if ($this->validateImageContents($contents)) { ... }          // MIME-type check
        }
    }

    return $sourcePath;  // line 237 — phar://, file://, ftp:// pass through unvalidated
}
```

The check `strpos($realSourcePath, 'http') === 0` matches both `http://` and `https://` (since `https` starts with `http`), but no other scheme. The following table shows which protections apply to each scheme:

| Scheme | `validateExternalImageUrl` | `validateExternalImageHost` | `validateImageContents` | Reaches `Resizer::open()` |
|--------|:---:|:---:|:---:|:---:|
| `http://` | Yes | Yes | Yes | Via temp copy |
| `https://` | Yes | Yes | Yes | Via temp copy |
| `phar://` | **No** | **No** | **No** | **Direct (raw path)** |
| `file://` | **No** | **No** | **No** | **Direct (raw path)** |
| `ftp://` | **No** | **No** | **No** | **Direct (raw path)** |
| `php://` | **No** | **No** | **No** | **Direct (raw path)** |

### Resizer processes the unvalidated path

The unvalidated `$sourcePath` is passed to `Resizer::open()`, whose constructor wraps it in a Symfony `File` object and immediately performs file I/O:

```php
// October\Rain\Resize\Resizer (src/Resize/Resizer.php:76-88)
public function __construct($file)
{
    if (is_string($file)) {
        $file = new FileObj($file);                      // Symfony\Component\HttpFoundation\File\File
    }
    $this->file = $file;
    $this->extension = $file->guessExtension();           // triggers stream wrapper I/O
    $this->mime = $file->getMimeType();                   // triggers stream wrapper I/O via finfo
    $this->image = $this->openImage($file);               // Intervention Image GD driver reads file
}
```

When the path uses `phar://`, PHP's PHAR stream wrapper opens the archive and deserializes its metadata via `php_var_unserialize()` — regardless of the `phar.readonly` INI setting (which only prevents writing PHARs, not reading them).

### Affected source and sink

- **Source:** Any code path that passes a user-influenced string to `ResizeImages::resize()`. Confirmed callers include:
  - Twig `|resize` filter (`modules/system/twig/Extension.php:157`) — used in theme templates
  - `MediaFinder` form widget (`modules/media/formwidgets/MediaFinder.php:184`) — passes `$file->publicUrl`
  - Backend list image column processor (`modules/backend/widgets/lists/HasValueProcessor.php:124`)
- **Sink:** `Resizer::open($sourcePath)` at `modules/system/classes/ResizeImages.php:159`, where `$sourcePath` contains the unvalidated stream wrapper URI.

## Exploitation

### Prerequisites

This vulnerability requires the following preconditions to be exploitable:

1. **Controllable image path:** The attacker must be able to influence a string value that reaches `ResizeImages::resize()`. This depends on the application's theme and plugin configuration — for example, a front-end form that stores a user-supplied image URL in a content field later processed with `|resize` in a Twig template.
2. **PHAR file on server:** The attacker must have previously uploaded a crafted PHAR archive (disguised as a PNG/image) to a known path on the server, e.g., through the FileUpload widget, Media Manager, or any front-end upload form.
3. **POP gadget chain:** A deserialization gadget chain must exist in the application's autoloaded classes. October CMS depends on Laravel 12, whose dependency tree has historically provided exploitable chains.

### Attack flow

1. Upload a PHAR-PNG polyglot file (a valid PHAR archive with a PNG magic header) containing a serialized POP chain payload in its metadata. Note the resulting server path, e.g., `storage/app/uploads/public/000/1000/000/abc-file.png`.

2. Submit a user-controllable image field value as `phar://storage/app/uploads/public/000/1000/000/abc-file.png`.

3. When the page renders, `ResizeImages::resize()` creates a cache entry containing the `phar://` path and returns a resize URL (e.g., `/resize/{cacheKey}-1`).

4. The `/resize/{file}` endpoint is publicly accessible without authentication:

```php
// modules/system/routes.php:17
Route::get('resize/{file}', [\System\Classes\SystemController::class, 'resize']);
```

5. When any visitor's browser requests the resize URL, the execution chain is: `SystemController::resize()` → `ResizeImages::getContents()` → `processImage()` → `getSourcePathForResize()` (returns the `phar://` path unvalidated) → `Resizer::open('phar://...')` → PHP PHAR stream wrapper deserializes the metadata → POP gadget chain executes → Remote Code Execution.

## Impact

Depending on the injected scheme and available preconditions:

1. **Remote Code Execution** via `phar://` deserialization — complete server compromise. This is the highest-severity outcome.
2. **Blind SSRF** via `ftp://`, `gopher://`, or other network stream wrappers — bypasses `validateExternalImageHost()` IP range restrictions entirely, enabling interaction with internal network services.
3. **Local file disclosure** via `file://` — reads arbitrary files accessible to the web server user through GD image processing.

The `/resize/` endpoint requires no authentication. Once a cache entry containing a malicious path has been created, the vulnerable code path can be triggered by any unauthenticated visitor, making the RCE vector triggerable without credentials.

## Remediation

Replace the `http`-prefix check with an explicit scheme whitelist and reject all other stream wrapper URIs:

```php
protected function getSourcePathForResize($realSourcePath, $tempSourcePath)
{
    $isExternal = preg_match('#^https?://#i', $realSourcePath);
    $sourcePath = $isExternal ? $tempSourcePath : $realSourcePath;

    if ($isExternal) {
        // Existing SSRF validation (validateExternalImageUrl, validateExternalImageHost, validateImageContents)
        ...
    }
    elseif (strpos($realSourcePath, '://') !== false) {
        // Reject any non-http(s) stream wrapper (phar://, file://, ftp://, php://, gopher://, etc.)
        throw new ApplicationException("Disallowed stream wrapper scheme in image path");
    }

    return $sourcePath;
}
```

Additionally, validate that local file paths are confined to expected application directories (uploads, media, themes, plugins, modules) using `realpath()` containment checks, following the pattern already implemented in `Backend\Models\ImportModel\DecodesZip::safeResolvePath()`.
