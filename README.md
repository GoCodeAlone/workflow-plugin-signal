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

- `step.signal_fingerprint` — Compute a Signal safety number and scannable fingerprint from serialized identity public keys.

Planned M1 steps after typed contract generation:

- `step.signal_session_prepare`
- `step.signal_encrypt`
- `step.signal_decrypt`

Official Signal service login/send/receive and Encrypted Spaces proof-system
features are deferred until their service and cryptographic boundaries are
designed.

## Module

Go module: `github.com/GoCodeAlone/workflow-plugin-signal`
