# `/mux` Terminal WebSocket Accepts Any Origin and Any Terminal ID in Agent Orchestrator, Allowing Hijack of Existing Agent Session PTYs

| Field | Value |
|---|---|
| Project | [Untrivial-ai/agent-orchestrator](https://github.com/Untrivial-ai/agent-orchestrator) |
| Vulnerability Type | Missing Origin / Authorization Check on WebSocket (CWE-346, CWE-862) |
| Severity | High — CVSS 3.1 Base Score: 7.5 |
| CVSS Vector | `AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H` |
| Affected Versions | <= 0.13.7 (verified on 0.13.7, latest release as of 2026-10-14; commit `4273bec`) |
| Authentication | None (browser content on a trusted preview origin) |

---

## Summary

`GET /mux` upgrades to a WebSocket with `websocket.AcceptOptions{InsecureSkipVerify: true}` (`backend/internal/httpd/terminal_mux.go:36-43`), disabling coder/websocket's same-origin verification, while the CORS middleware admits `*.localhost` preview origins. The mux protocol's `open` frame takes a client-supplied terminal id and attaches to it without any ownership check (`newAttachment` → `runtimeAdapter.Attach` with `ports.RuntimeHandle{ID: id}`, `internal/terminal/manager.go`), and subsequent `data` frames write base64 keystrokes straight into the shared PTY with output echoed back on the same connection.

Under the same precondition as the shell-terminal issue — attacker-controlled JavaScript running on a workspace preview origin — this gives two capabilities without creating anything new: silently reading the live terminal stream of existing agent sessions (source code, tokens, credentials, internal dialogue), and injecting keystrokes to drive an agent mid-task: approving dangerous commands it proposed, or interrupting with Ctrl+C and typing shell commands directly. Session ids are predictable (`<lowercased projectID>-<counter>` or `standalone-<N>`), so no information leak is needed to find targets. This bypasses the product's entire approval workflow, which is an equivalent of code execution with the user's authority.

## Details

`terminal_mux.go`:

```go
// InsecureSkipVerify disables coder/websocket's same-origin check: the
// daemon binds loopback only and the desktop renderer's origin differs
// from the loopback host, mirroring the legacy Node mux server.
c, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true})
```

`internal/terminal/manager.go` — the open path trusts the client's id:

```go
case msgOpen:
    c.openTerminal(msg.ID, msg.Rows, msg.Cols, msg.Role)
case msgData:
    raw, err := base64.StdEncoding.DecodeString(msg.Data)
    ...
    if a := c.lookup(msg.ID); a != nil {
        c.mgr.writeInput(msg.ID, a, raw, release)
    }
```

There is no mapping between a WebSocket connection and the terminal handles it may address; every connected client may open and write to every handle. Contrast the codex-account middleware (`cors.go:89-105`), which rejects origins not in an exact allow-list — the same treatment is absent here.

## PoC

Verified against the release 0.13.7 backend (commit `4273bec`, default configuration). The stdlib PoC client connects as preview-origin browser content. (The transcript below is the same live run reported in the companion shell-terminal advisory — it demonstrates the `/mux` protocol exactly as this issue describes.)

**Step 1: the WebSocket accepts a preview origin with no verification**

```
-- [2] ws /mux: open handle, inject command, read output --
    upgrade: HTTP/1.1 101 Switching Protocols
    opened: True  output excerpt: ...live PTY framebuffer bytes...
```

**Step 2: keystroke injection into the opened PTY**

```
    [VULN] marker file exists: Mac-Mini.local
```

The `open` frame addressed a handle the connection had no relationship to, and the `data` frame's keystrokes executed in that PTY. Against an existing agent-session terminal the same frames read the live output stream (returned as `data` messages on the same socket) and inject approvals or shell commands.

**Real-environment reproduction** (the product itself, run for this test): live 0.13.7 daemon, real `101 Switching Protocols` upgrade from a `*.localhost` origin, real PTY attachment and keystroke injection captured in the transcript.

![Real-environment verification](agentorchestrator_mux_terminal_no_ownership.png)

---

## Impact

From hostile preview content:

- **Session eavesdropping** — continuous capture of agent/user terminal output: proprietary source, secrets, API tokens, and internal agent dialogue leave the machine through the attacker's page
- **Approval-workflow bypass** — injected keystrokes can accept dangerous tool calls an agent is waiting on, or hijack the terminal after interrupting the agent, achieving user-privileged execution without touching the shell-terminal route
- **Chaining** — independent of the shell-spawn issue; fixing either one alone leaves this path open

### Remediation

1. Re-enable origin verification on the `/mux` upgrade, or replace it with a per-connection capability minted by the desktop app (token in the query string/header at upgrade time).
2. Bind terminal handles to the creating connection or window session; `open`/`data` on foreign handles must be rejected.
3. Make session ids non-enumerable (random rather than `<project>-<n>`), and require an explicit user gesture for attaching to an already-running terminal.
4. Log and alert on terminal attachments from connections that did not create the terminal.
