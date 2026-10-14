# Widget API `send_event` Honors `content.redacts` Before the Send-Capability Check, Letting a Widget Redact Arbitrary Events Without the Redaction Capability in matrix-rust-sdk

| Field | Value |
|---|---|
| Project | [matrix-org/matrix-rust-sdk](https://github.com/matrix-org/matrix-rust-sdk) |
| Vulnerability Type | Incorrect Authorization (CWE-863) / Authorization Bypass (CWE-285) |
| Severity | High — CVSS 3.1 Base Score: 7.1 |
| CVSS Vector | `AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:L` |
| Affected Versions | `matrix-sdk` widget API behind the `experimental-widgets` feature, enabled by default for Element X through `bindings/matrix-sdk-ffi`; verified on main commit `4bddd82f` (2026-10-14), crate version 0.19.1 (latest release 2026-09-18) |
| Authentication | None for the widget; the victim only needs to run a client that hosts the widget and approve any single send capability |

---

## Summary

Under MSC2762, a widget (third-party JavaScript in an iframe/webview) may only send events for event types the host user explicitly granted via a `send.event:<type>` capability. The crate enforces this in `process_send_event_request`, but the capability filter only inspects the **declared** `event_type` (and `state_key`). The execution path it authorizes, `MatrixDriver::send`, then examines the request **content**: if the content carries a parseable `redacts` event ID, it discards the declared type entirely and performs `Room::redact` — a privileged operation that the crate's own integration test (`test_send_redaction`) gates behind a dedicated `send.event:m.room.redaction` capability.

The two halves therefore disagree: a widget holding *any* message-like send capability (say, `send.event:org.example.custom`) can submit `send_event` with `type: org.example.custom` and `content: {"redacts": "$victim"}`, and the host client will redact `$victim` as the user, with no `m.room.redaction` capability ever requested or granted. The redaction request is issued with the host user's full authority; homeserver power-level checks then apply exactly as if the user had chosen to redact the event themselves.

## Details

The capability check only sees the declared type — `crates/matrix-sdk/src/widget/filter.rs` (conversion feeding `FilterInput`):

```rust
fn from(request: &'a SendEventRequest) -> Self {
    match &request.state_key {
        None => match request.event_type.as_str() {
            ...
            _ => FilterInput::message_like(&request.event_type),   // content ignored
        },
        Some(state_key) => FilterInput::state(&request.event_type, state_key),
    }
}
```

The authorized execution path switches on the content — `crates/matrix-sdk/src/widget/matrix.rs` (`MatrixDriver::send`):

```rust
if let Some(redacts) = from_raw_json_value::<Value, serde_json::Error>(&content)
    .ok()
    .and_then(|b| b["redacts"].as_str().and_then(|s| EventId::parse(s).ok()))
{
    return Ok(SendEventResponse::from_event_id(
        self.room.redact(&redacts, None, None).await?.event_id,
    ));
}
```

The project's own test `test_send_redaction` (`crates/matrix-sdk/tests/integration/widget.rs`) establishes the intended contract: redaction requires the negotiated capability `org.matrix.msc2762.send.event:m.room.redaction`. The check-then-execute mismatch above bypasses that contract for every other send capability, message-like or state.

## PoC

Verified by running the crate's real widget integration harness (mock homeserver, `WidgetDriver` negotiated over the actual postMessage protocol) on main `4bddd82f`, with one added test that negotiates **only** `org.matrix.msc2762.send.event:org.example.custom`:

**Step 1 — negative control: an honestly declared `m.room.redaction` is denied without its capability:**

```
Json string sent from the widget {"action":"send_event",...,"data":{"content":{},"type":"m.room.redaction"},...}
control (declared m.room.redaction, no capability) -> denied: "Not allowed to send event"
```

**Step 2 — attack: declared type is the granted custom type, target embedded in `content.redacts`; the homeserver mock receives a real redaction PUT:**

```
Json string sent from the widget {"action":"send_event",...,"data":{"content":{"redacts":"$1234"},"type":"org.example.custom"},...}
DEBUG redact:send{... method=PUT uri="http://127.0.0.1:57079/_matrix/client/v3/rooms/!a98sd12bjh:example.org/redact/$1234/<txn>" ... status=200}
attack (org.example.custom + content.redacts) -> event_id $poc_redaction served by the m.room.redaction endpoint mock
test widget::test_poc_redaction_via_unrelated_send_capability ... ok
```

The `status=200` line is the mock homeserver answering the redaction request the host client emitted; the `mock_once()` expectation makes the test fail unless exactly one such request arrives. The full widget suite (39 tests, including the original `test_send_redaction`) passes alongside.

**Real-environment reproduction** (the product itself, run for this test): the crate's `WidgetDriver` executed the untrusted-widget protocol against a live mock homeserver; the widget held only the `org.example.custom` send capability, and the driver still issued `PUT /_matrix/client/v3/rooms/!…/redact/$1234/…` in the host user's session.

![Real-environment verification](matrixsdk_widget_send_event_redaction_bypass.png)

---

## Impact

Any widget the user runs — embedded maps, bridges, polling apps, or anything a room or integration can convince a client to render — can silently redact arbitrary events in any room the host user occupies (limited only by the user's redaction power level in each room), while showing the user a capability prompt that mentions only a harmless custom event type. Redactions are propagating, hard-to-undo state events: content is removed for every member, and the action is attributed to the victim. The bypass fully defeats the MSC2762 send-capability boundary for the redaction primitive. Element X and other FFI consumers enable `experimental-widgets` by default, so the code path ships in current clients.

### Remediation

1. In `MatrixDriver::send`, only honor `content.redacts` when the negotiated capability set actually contains `send.event:m.room.redaction`; otherwise return an error (or send the event as its declared type) rather than silently switching operations.
2. Preferably, make the redaction attempt fail closed at the chokepoint: include a marker derived from the matched `FilterInput` in the send call so the driver cannot perform an operation different from the one that was authorized.
3. Extend `FilterInput::from(&SendEventRequest)` to detect a `redacts` field in the content and require the redaction capability during filtering, covering state and delayed variants too.
4. Add a regression test: widget with a single unrelated send capability submits `content.redacts`; assert no redaction request reaches the homeserver and an error returns to the widget.
