# workflow-plugin-signal

Signal protocol primitives for Workflow

## Installation

```sh
wfctl plugin install workflow-plugin-signal
```

## Development

```sh
# Build
make build

# Test
make test

# Install locally
make install-local
```

## Step Types

- `step.signal_session_prepare` - create a public pre-key bundle for a local identity store.
- `step.signal_encrypt` - encrypt plaintext into a Signal session envelope.
- `step.signal_decrypt` - decrypt an inbound Signal session envelope after the configured principal gate passes.
- `step.signal_fingerprint` - compute a Signal safety number and scannable fingerprint from serialized identity public keys.
- `step.signal_account_keys` - derive account entropy, SVR, backup, backup-id, and PIN hash keys.
- `step.signal_username_link_create` - create an encrypted Signal username link payload.
- `step.signal_username_link_decrypt` - decrypt an encrypted Signal username link payload.
- `step.signal_service_contract_check` - validate the disabled/test-double official-service boundary and return upstream compatibility metadata.
- `step.signal_service_compliance_check` - report official-service readiness requirements, blocked live actions, and upstream service metadata without opening live transport.
- `step.signal_service_policy_check` - evaluate live-service approval metadata and requested actions without opening live transport.
- `step.signal_service_approval_validate` - validate machine-checkable live-service approval metadata and return denial reasons.
- `step.signal_service_live_submit` - submit fake/sandbox service operations through a registered transport or return a no-egress live denial.
- `step.signal_service_test_register` - exercise deterministic fake registration with idempotency and ref-only outputs.
- `step.signal_service_test_link_device` - exercise deterministic fake linked-device setup with idempotency and ref-only outputs.
- `step.signal_service_test_send` - exercise deterministic fake sends, including challenge-required status.
- `step.signal_service_test_receive` - exercise deterministic fake receives with idempotency and ref-only outputs.
- `step.signal_custody_create` - create account/device custody refs and return sealed custody metadata.
- `step.signal_custody_rotate` - rotate custody KEK metadata while preserving ref-only outputs.
- `step.signal_custody_restore` - restore a sealed custody bundle through host-managed KEK refs.
- `step.signal_custody_revoke` - mark a custody ref revoked and return redacted audit metadata.
- `step.signal_custody_inspect` - inspect custody metadata without exposing key material.

## Modules

- `signal.identity_store` - in-memory Phase 1 identity, pre-key, and session state.
- `signal.space` - typed configuration surface for binding encrypted spaces to rooms/eventbus.
- `signal.official_service_boundary` - typed disabled/test-double boundary for selected upstream service wire shapes.
- `signal.service_transport` - registered fake, sandbox, or approval-gated live transport boundary.
- `signal.key_custody` - host-managed key custody refs for exportable secret refs or non-exportable key handles.
- `signal.persistent_custody` - host-secret-backed encrypted local custody for non-exportable key handles.
- `signal.custody_store` - v2 custody-store contract with backend, KEK, schema, and storage metadata.
- `signal.account_ref` - account/device/consent/audit refs bound to host custody for fake official-service tests.
- `trigger.signal_envelope` - typed trigger-module contract for encrypted envelope transports.
- `trigger.signal_service_envelope` - typed trigger-module contract for future service-envelope transports; no live stream is opened in this phase.

Phase 1 identity stores remain in-memory for application composition and
conformance testing. Production deployments should bind identities to
`signal.key_custody` and host-managed persistence before relying on restart
survival.

`signal.persistent_custody` stores encrypted custody state in a host-selected
file and registers only non-exportable key handles with Workflow. `local_file`
requires a host secret resolver; `test_file` is explicitly marked non-production
and requires opt-in for conformance tests.

`signal.custody_store` is the v2 custody contract for durable host-managed
key custody. Its step contracts return custody refs and metadata only; plain key
bytes are not ordinary Workflow outputs. The existing `signal.persistent_custody`
module remains available for backward compatibility.

The `scenarios/signal-custody-restart` fixture covers the v2 custody lifecycle:
create a sealed custody ref, reload the store after a simulated restart, restore
by ref, rotate KEK metadata, inspect redacted metadata, revoke the ref, and
reject restore after revocation. The scenario uses the `test_file` backend only;
production hosts should use `local_file` with host-managed KEK custody.

Official Signal service registration, linked-device, send, and receive steps in
this release use deterministic `libsignal-service-go/fake` clients only. They
return request IDs, statuses, challenge refs, and host secret refs; they do not
register accounts, link devices, send messages, receive messages, reserve
usernames, upload backups, download backups, or contact the official Signal
service. Live transport remains unavailable until a later approval-bearing
egress transition.

`step.signal_service_live_submit` supports fake and sandbox transport exercises
for register, linked device, send, receive, username reserve, backup
upload/download, and challenge response operations. Live mode returns a denied
result unless the approval package is machine-checkable and complete; this
plugin still ships no official Signal service endpoint constants or automatic
production egress.

## Module

Go module: `github.com/GoCodeAlone/workflow-plugin-signal`
