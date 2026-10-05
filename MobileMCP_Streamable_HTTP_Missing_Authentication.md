# mobile-mcp Streamable HTTP Mode Missing Authentication — Unauthenticated Full Device Control

### Summary

mobile-mcp (`main` branch, https://github.com/mobile-next/mobile-mcp) implements authentication in its `--listen` MCP Streamable HTTP mode as a purely optional environment variable: `src/index.ts:33-47` registers the Bearer-check middleware **only** when `MOBILEMCP_AUTH` is set; when unset, the server starts normally and accepts any unauthenticated connection (a console warning is the only signal). The official `README.md:417` documents `--listen 0.0.0.0:3000` for remote use, and `README.md:434` confirms unauthenticated connections are accepted without a token. In that documented configuration, any network-reachable attacker can invoke the full `mobile_*` tool surface (~30 tools) via `POST /mcp` with no credentials: screenshot/screen recording, clipboard read/write, GPS spoofing, key/touch injection, app install/uninstall, device logs, URL opening.

Dynamically verified (verified 2026-10-04) with a Node harness replicating the middleware registration and `/mcp` handler 1:1: unauthenticated garbage-token requests reached the full MCP tool surface with HTTP 200 (`[VULN] FINAL: Confirmed — when MOBILEMCP_AUTH is unset, ALL requests reach the full MCP tool surface. Only a console warning is emitted, no auth enforcement exists`).

This is CWE-306: Missing Authentication for Critical Function.

### Details

**Root cause.** Authentication enforcement is downgraded to a warning: a missing `MOBILEMCP_AUTH` does not fail startup — the HTTP server runs with no auth middleware at all. This is a fail-open design; the presence of the security control depends entirely on operator configuration.

**Trust boundary failure.** The network interface is the trust boundary, and it is crossed without any validation: bound to `0.0.0.0` (the officially documented remote deployment), the unauthenticated MCP endpoint is open to any routable client. Without a token there is no authentication layer, so requests from untrusted networks are indistinguishable from trusted local traffic.

**Source-to-sink path (line-verified, dynamically confirmed):**

1. **Source — untrusted remote request.** `src/index.ts:59-61`: `app.post("/mcp", ...)` unconditionally mounts the MCP handler, passing `req.body` (fully attacker-controlled JSON-RPC, including `tools/call` `params.name` and `params.arguments`).
2. **Missing gate — conditional middleware.** `src/index.ts:33-36`: unset `MOBILEMCP_AUTH` only calls `error(...)`; the Bearer check exists solely inside `if (authToken)` (`:38-47`).
3. **Exposure — network bind.** `app.listen(port, host)` binds the unauthenticated endpoint to all interfaces when `0.0.0.0` is used; documented at `README.md:417` / `README.md:434`.
4. **Dispatch.** `src/server.ts:122-158`: the `tool()` wrapper invokes the selected tool callback with attacker-chosen arguments.
5. **Sinks — device control and data return.** All ~30 `mobile_*` tools are reachable, including:
   - `mobile_take_screenshot` (`src/server.ts:857-909`) / `mobile_list_elements_on_screen`: continuous screen reading (SMS codes, chats, email); screenshots returned base64 to the caller (`:896-909`).
   - `mobile_clipboard` (`:1010-1022`): read/write device clipboard (copied passwords, wallet addresses).
   - `mobile_get_device_logs` (`:1036-1055`): device logs (common token-leak source).
   - `mobile_type_keys` / `mobile_click_on_screen_at_coordinates`: UI input injection (e.g. executing transfers inside logged-in apps).
   - `mobile_open_url` (`src/android.ts:402-404`): phishing URLs; `mobile_set_location`: GPS spoofing; `mobile_install_app`/`mobile_uninstall_app`: arbitrary app management.
   - File-write sinks `src/server.ts:837` and `:1052` (`fs.writeFileSync`) write attacker-influenced content to the server filesystem.

Core vulnerable code path:

```ts
const authToken = process.env.MOBILEMCP_AUTH;
if (!authToken) {
  error("WARNING: MOBILEMCP_AUTH is not set. The HTTP server will accept unauthenticated connections...");
}
if (authToken) { /* Bearer check — only exists when a token is configured */ }
// ...
app.post("/mcp", (req, res) => { void node(req, res, req.body); });
```

### PoC

Verified 2026-10-04 with a harness replicating the exact middleware semantics:

1. Run mobile-mcp per official remote documentation: `npx mobile-mcp --listen 0.0.0.0:3000` with `MOBILEMCP_AUTH` unset.
2. From any network-reachable host, invoke a device-control tool with a garbage token:

```bash
curl -X POST http://TARGET:3000/mcp \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer garbage" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call",
       "params":{"name":"mobile_take_screenshot","arguments":{}}}'
```

Harness output:

```
[DETECTED] MCP /mcp handler reached - processing tool call: mobile_install_app
[VULN] Unauthenticated request reached MCP handler (HTTP 200) - any request processed
[VULN] FINAL: Confirmed - when MOBILEMCP_AUTH is unset, ALL requests (even with garbage
tokens) reach the full MCP tool surface. Only a console warning is emitted, no auth
enforcement exists. On 0.0.0.0 binding this exposes ~30 device-control tools.
```

### Impact

Under the officially documented remote deployment (0.0.0.0 binding, no `MOBILEMCP_AUTH`), any network-reachable attacker without credentials gains complete control of the connected phone/emulator: install/uninstall arbitrary APKs, read and write the clipboard (passwords, 2FA codes), spoof GPS, inject key/touch input (e.g. executing transfers inside logged-in apps), capture screens and recordings, read device logs, and open attacker URLs. The server applies no rate limiting, so the attack is fully silent and repeatable. The default localhost binding with DNS-rebinding protection is the safe configuration; exposure occurs exactly in the remote-use combination the project README itself presents.
