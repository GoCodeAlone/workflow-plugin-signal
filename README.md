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

## Modules

- `signal.identity_store` - in-memory Phase 1 identity, pre-key, and session state.
- `signal.space` - typed configuration surface for binding encrypted spaces to rooms/eventbus.
- `trigger.signal_envelope` - typed trigger-module contract for encrypted envelope transports.

Phase 1 identity stores are in-memory and intended for application composition
and conformance testing. Production deployments should provide host-managed
persistent key custody before relying on restart survival.

Official Signal service login/send/receive and Encrypted Spaces proof-system
features are deferred until their service and cryptographic boundaries are
designed.

## Module

Go module: `github.com/GoCodeAlone/workflow-plugin-signal`
