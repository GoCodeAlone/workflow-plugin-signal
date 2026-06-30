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

## Modules

- `signal.identity_store` - in-memory Phase 1 identity, pre-key, and session state.
- `signal.space` - typed configuration surface for binding encrypted spaces to rooms/eventbus.
- `signal.official_service_boundary` - typed disabled/test-double boundary for selected upstream service wire shapes.
- `trigger.signal_envelope` - typed trigger-module contract for encrypted envelope transports.
- `trigger.signal_service_envelope` - typed trigger-module contract for future service-envelope transports; no live stream is opened in this phase.

Phase 1 identity stores are in-memory and intended for application composition
and conformance testing. Production deployments should provide host-managed
persistent key custody before relying on restart survival.

Official Signal service login/send/receive, registration, linked-device
automation, username hash/proof, and Encrypted Spaces proof-system features are
deferred until their service and cryptographic boundaries are designed.

## Module

Go module: `github.com/GoCodeAlone/workflow-plugin-signal`
