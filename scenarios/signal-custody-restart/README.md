# signal-custody-restart

Scenario fixture for the `v0.8.0` custody-store release.

The workflow documents the intended custody lifecycle: create a sealed ref,
restart/reload the store, restore by ref without key bytes, rotate KEK metadata,
inspect redacted metadata, revoke the ref, and reject restore after revocation.

`wfctl plugin test` validates this plugin's manifest lifecycle. The package test
`TestSignalCustodyRestartScenarioLifecycle` executes the same lifecycle against
the sealed local backend.
