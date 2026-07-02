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
- `step.signal_outbox_enqueue` - queue a ciphertext envelope with sender, recipient, custody, authorization, and message refs.
- `step.signal_outbox_claim` - claim a queued outbox envelope for host transport without exposing plaintext.
- `step.signal_inbox_receive` - admit a ciphertext envelope into an inbox queue for a recipient ref.
- `step.signal_inbox_decrypt` - decrypt an inbox envelope only when the caller supplies custody and authorization refs.
- `step.signal_fingerprint` - compute a Signal safety number and scannable fingerprint from serialized identity public keys.
- `step.signal_account_keys` - derive account entropy, SVR, backup, backup-id, and PIN hash keys.
- `step.signal_username_link_create` - create an encrypted Signal username link payload.
- `step.signal_username_link_decrypt` - decrypt an encrypted Signal username link payload.
- `step.signal_service_contract_check` - validate the disabled/test-double official-service boundary and return upstream compatibility metadata.
- `step.signal_service_compliance_check` - report official-service readiness requirements, blocked live actions, and upstream service metadata without opening live transport.
- `step.signal_service_policy_check` - evaluate live-service approval metadata and requested actions without opening live transport.
- `step.signal_service_approval_validate` - validate machine-checkable live-service approval metadata and return denial reasons.
- `step.signal_service_live_submit` - submit fake/sandbox service operations through a registered transport or return a no-egress live denial.
- `step.signal_service_register_prepare` - build a register operation envelope without submitting it, enriched from registered account/custody refs when available.
- `step.signal_service_link_prepare` - build a linked-device operation envelope with consent, revocation, and unlink proof metadata.
- `step.signal_service_send_prepare` - build a send operation envelope using recipient and payload refs only, with custody attestation metadata when account custody is registered.
- `step.signal_service_receive_admit` - build a receive admission envelope using cursor refs only, with custody attestation metadata when account custody is registered.
- `step.signal_service_challenge_respond` - build a challenge response envelope using challenge and response refs only, with custody attestation metadata when account custody is registered.
- `step.signal_username_proof_prepare` - report username proof readiness without reserving usernames.
- `step.signal_backup_manifest_verify` - report backup manifest readiness without uploading or downloading backups.
- `step.signal_backup_auth_prepare` - report backup auth readiness without opening service transport.
- `step.signal_service_test_register` - exercise deterministic fake registration with idempotency and ref-only outputs.
- `step.signal_service_test_link_device` - exercise deterministic fake linked-device setup with idempotency and ref-only outputs.
- `step.signal_service_test_send` - exercise deterministic fake sends, including challenge-required status.
- `step.signal_service_test_receive` - exercise deterministic fake receives with idempotency and ref-only outputs.
- `step.signal_service_test_username_reserve` - exercise deterministic fake username reservation with idempotency and ref-only outputs.
- `step.signal_service_test_backup_upload` - exercise deterministic fake backup upload with idempotency and ref-only outputs.
- `step.signal_service_test_backup_download` - exercise deterministic fake backup download with idempotency and ref-only outputs.
- `step.signal_custody_create` - create account/device custody refs and return sealed custody metadata.
- `step.signal_custody_rotate` - rotate custody KEK metadata while preserving ref-only outputs.
- `step.signal_custody_restore` - restore a sealed custody bundle through host-managed KEK refs.
- `step.signal_custody_revoke` - mark a custody ref revoked and return redacted audit metadata.
- `step.signal_custody_inspect` - inspect custody metadata without exposing key material.
- `step.signal_custody_attest` - return custody attestation and evidence refs for application policy checks.
- `step.signal_custody_export_request` - create ref-only export review metadata that remains approval-required.

## Modules

- `signal.identity_store` - in-memory identity, pre-key, and session state for local composition and conformance tests.
- `signal.envelope_store` - memory or explicit local-file ciphertext queues for outbox/inbox application flows.
- `signal.space` - typed configuration surface for binding encrypted spaces to rooms/eventbus.
- `signal.official_service_boundary` - typed disabled/test-double boundary for selected upstream service wire shapes.
- `signal.service_transport` - registered fake, sandbox, or approval-gated live transport boundary.
- `signal.live_policy` - operation-specific approval and local operator-fixture policy metadata.
- `signal.key_custody` - host-managed key custody refs for exportable secret refs or non-exportable key handles.
- `signal.persistent_custody` - host-secret-backed encrypted local custody for non-exportable key handles.
- `signal.custody_store` - v2 custody-store contract with backend, KEK, schema, and storage metadata.
- `signal.account_ref` - account/device/consent/audit refs bound to host custody for fake official-service tests.
- `trigger.signal_envelope` - typed trigger-module contract for encrypted envelope transports.
- `trigger.signal_service_envelope` - typed trigger-module contract for service-envelope transports; no live stream is opened unless a host supplies an approved transport.

The built-in identity store remains in-memory for application composition and
conformance testing. Production deployments should bind identities to
`signal.key_custody` and host-managed persistence before relying on restart
survival.

`signal.envelope_store` keeps queued outbox and inbox payloads as Signal
ciphertext plus redacted routing metadata. The memory backend is intended for
application composition and conformance tests. The `local_file` backend must be
explicitly enabled, is rejected under production policy mode, and persists only
ciphertext envelopes and refs. Inbox decrypt requires both custody and
authorization refs before it delegates to the local Signal decrypt primitive.

`signal.persistent_custody` stores encrypted custody state in a host-selected
file and registers only non-exportable key handles with Workflow. `local_file`
requires both `allow_local_file_custody: true` and a host secret resolver.
`test_file` is explicitly marked non-production and requires opt-in for
conformance tests. Production policy mode rejects both file-backed custody
backends; production hosts should provide approved KMS/HSM/security service
refs instead of local files. Hermetic `test://signal/...` KEK refs derive
deterministic test secrets only when no host resolver is configured.

`signal.custody_store` is the v2 custody contract for durable host-managed
key custody. Its step contracts return custody refs and metadata only; plain key
bytes are not ordinary Workflow outputs. Attestation and export-request steps
return refs/evidence/status metadata for application policy checks and do not
restore sealed material. The existing `signal.persistent_custody` module remains
available for backward compatibility.

The `scenarios/signal-custody-restart` fixture covers the v2 custody lifecycle:
create a sealed custody ref, reload the store after a simulated restart, restore
by ref, rotate KEK metadata, inspect redacted metadata, revoke the ref, and
reject restore after revocation. The scenario uses the `test_file` backend only;
production hosts should use `local_file` with host-managed KEK custody.
The standalone `testdata/pipelines/signal-custody.yaml` fixture can be run with
`WFCTL_PLUGIN_DIR` pointing at a local plugin install and exercises create,
attest, rotate, and export-request steps through `wfctl pipeline run`.

Official Signal service registration, linked-device, send, and receive steps
support deterministic `libsignal-service-go/fake` clients and host-supplied
sandbox/operator fixtures. They
return request IDs, statuses, challenge refs, and host secret refs; they do not
register accounts, link devices, send messages, receive messages, reserve
usernames, upload backups, download backups, or contact the official Signal
service via any bundled production endpoint client. Official Signal service
egress remains unavailable unless a host supplies an approved transport and a
complete machine-checkable approval package.

Operation-specific `*_prepare`, `receive_admit`, and `challenge_respond` steps
produce `ServiceOperationEnvelope` metadata for application composition and
approval review. When `signal.account_ref` and `signal.key_custody` or
`signal.persistent_custody` are registered, prepare steps inherit device,
credential, consent, audit, custody, and non-exportable key refs, validate
custody ownership, and return custody attestation metadata plus readiness
warnings. Linked-device envelopes require display name, consent evidence,
consent expiry, revocation URI, and unlink proof refs, and reject replayed or
revoked ceremony artifacts. Username and backup steps expose readiness
classifications rather than claiming upstream parity without vector proof.

`step.signal_service_live_submit` supports fake and sandbox transport exercises
for register, linked device, send, receive, username reserve, backup
upload/download, and challenge response operations. Live mode returns a denied
result unless the approval package is machine-checkable and complete; this
plugin still ships no official Signal service endpoint constants or automatic
production egress.

`scenarios/signal-service-operator-fixture` documents the local operator-fixture
path for operation-specific prepare/admit steps. The fixture uses loopback
transport metadata only and remains default-deny for production egress.
Optional official live smoke tests require an external operator approval package,
account-owner consent, custody policy, abuse policy, audit policy, and endpoint
allowlist supplied by the host application; they are not CI or release gates.

## Module

Go module: `github.com/GoCodeAlone/workflow-plugin-signal`
