# Chitchatter (develop) SDK postMessage Origin Self-Validation Bypass — Session and Persistent Identity Takeover

### Summary

Chitchatter (https://github.com/jeremyckahn/chitchatter, `develop` branch) was confirmed vulnerable to an origin self-validation bypass in SDK/embed mode. `isConfigMessageEvent` (`src/models/sdk.ts:44-61`) anchors the "trusted parent" origin to the `parentDomain` URL query parameter of the embedded iframe itself — a value supplied by the embedding party (the attacker). The check compares `event.origin` against an attacker-written string, so any malicious page can pass it and inject an arbitrary user identity (userId, username, RSA `publicKey`/`privateKey` `CryptoKey` pair) into the victim's chitchatter session.

The vulnerability was dynamically verified (verified 2026-10-04) with a Node.js harness replicating `isConfigMessageEvent` exactly: attacker-originated config messages passed validation, and the injected keys (`userId: attacker-controlled-peer-id-666`, attacker key pair) were accepted and persisted to the browser's IndexedDB under the legitimate chitchatter origin.

This is CWE-346: Origin Validation Error.

### Details

**Root cause.** Embed mode treats the parent page as the configuration authority, but the parent's identity anchor is taken from an attacker-controlled URL rather than any deployment-time or server-side trust source:

```ts
// src/models/sdk.ts:44-61
export const isConfigMessageEvent = (event: MessageEvent): event is ConfigMessageEvent => {
  const queryParams = new URLSearchParams(window.location.search)
  const parentDomain = queryParams.get(QueryParamKeys.PARENT_DOMAIN)
  if (parentDomain === null) return false
  const { origin: parentFrameOrigin } = new URL(decodeURIComponent(parentDomain))
  if (event.origin !== parentFrameOrigin) return false   // self-referential check
  ...
}
```

**Source-to-sink path:**

1. **Source:** attacker page embeds `https://chitchatter.im/?getSdkConfig=&parentDomain=https%3A%2F%2Fevil.example` (or holds a `window.open` reference). Both `parentDomain` and subsequent `message` payloads are attacker-controlled.
2. `src/Bootstrap.tsx:158` detects `getSdkConfig`; `getConfigFromSdk` (lines 56-88) decodes `parentFrameOrigin=evil.example` and postMessages `CONFIG_REQUESTED` to the attacker page, opening a ~3 s negotiation window.
3. `isConfigMessageEvent` accepts the attacker reply `{name:'config', payload:{userId, customUsername, publicKey, privateKey}}` — `event.origin` matches the attacker's own `parentDomain`. WebCrypto `CryptoKey` values cross postMessage via structured clone.
4. `src/Bootstrap.tsx:160-177` merges the payload into `setUserSettings`, replacing the in-session identity; the persistent-override listener `handleConfigMessage` (lines 193-215, merge at 202-207) accepts further overwrites under the same broken check.
5. **Sink (persistence):** `persistUserSettings` (lines 112-127, invoked at 180) serializes the injected `CryptoKey`s (`Serialization.ts:47-49`) and writes them to IndexedDB `USER_SETTINGS` under the **legitimate** chitchatter origin.
6. Any later normal (non-embedded) visit loads the attacker's keys as the victim identity (`src/Bootstrap.tsx:142-150`); room identity signatures are then produced with the attacker's private key (`useRoom.ts:492-495, 604-607`), so an attacker holding the key pair passes peer signature verification and displays VERIFIED (`useRoom.ts:316-320`; these keys are the "prove a peer's identity" material per `Encryption.ts:11-14`).

### PoC

Verified 2026-10-04 with a Node harness replicating `isConfigMessageEvent` 1:1:

```
Scenario 1 (control): message from trusted.example with parentDomain=trusted.example -> accepted (correct)
Scenario 2 (attack):  message from evil.example   with parentDomain=evil.example   -> accepted (BYPASS)
[VULN] origin 自证校验被绕过: 攻击者消息通过 isConfigMessageEvent 校验
[VULN] 注入后 userId: attacker-controlled-peer-id-666
[VULN] 注入后 privateKey: ATTACKER_GENERATED_PRIVATE_KEY_BASE64
[VULN] 攻击者密钥对被持久化到受害者浏览器 IndexedDB (chitchatter origin 下)
```

Browser exploitation: host a page that iframes `https://chitchatter.im/public/room?getSdkConfig&parentDomain=https%3A%2F%2Fattacker.tld` (no `embed` param for the persistent variant) and, within the ~3 s negotiation window, respond to the `CONFIG_REQUESTED` postMessage with a config payload containing attacker-generated WebCrypto keys. The victim's subsequent normal visits load the attacker-controlled identity.

### Impact

1. **Session identity control:** an attacker page embedding chitchatter defines the session's userId and signing key pair — the victim converses under an identity the attacker created and can impersonate.
2. **Persistent identity takeover:** via the `getSdkConfig` + `parentDomain` (no `embed`) path, injected keys are persisted to IndexedDB under the genuine chitchatter origin; the victim's later legitimate visits load the attacker's identity, letting the attacker impersonate the victim in peer-signature verification flows.
3. **Security-boundary collapse:** every downstream check relying on `isConfigMessageEvent` is void.
Mitigating factors: exploitation requires luring the victim (iframe/window.open); the full identity-takeover impact materializes as the signature-verification flow is enabled.
