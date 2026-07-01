# signal-service-operator-fixture

Scenario fixture for the `v0.9.0` service-operation contract release.

The workflow documents operation-specific prepare/admit steps for register,
linked-device, send, receive, challenge response, username proof readiness, and
backup readiness. It uses only a local operator fixture endpoint and does not
contact the official Signal service.

`wfctl plugin test` validates this plugin's manifest lifecycle. Package tests
execute the local operator fixture adapter and verify approval-gated behavior.
