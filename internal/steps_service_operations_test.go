package internal

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/GoCodeAlone/workflow/plugin/external/sdk"

	contracts "github.com/GoCodeAlone/workflow-plugin-signal/internal/contracts"
)

func TestServiceOperationPrepareBuildsEnvelopeWithoutSubmit(t *testing.T) {
	t.Cleanup(resetServiceTestState)

	result, err := ExecuteSignalServiceSendPrepare(context.Background(), sdk.TypedStepRequest[*contracts.ServiceSendPrepareConfig, *contracts.ServiceSendPrepareInput]{
		Config: &contracts.ServiceSendPrepareConfig{AccountRef: "account://alice"},
		Input: &contracts.ServiceSendPrepareInput{
			OperationId:     "op://send/1",
			IdempotencyKey:  "send-1",
			DeviceRef:       "device://alice/1",
			CustodyRef:      "custody://alice/1",
			RecipientRef:    "recipient://bob",
			PayloadRef:      "payload://ciphertext/1",
			ConsentRef:      "consent://send/1",
			AuditRef:        "audit://send/1",
			CredentialRef:   "credential://alice",
			RequestedAtUnix: 1_783_000_000,
		},
	})
	if err != nil {
		t.Fatalf("prepare send: %v", err)
	}
	out := result.Output
	if out.GetLiveEgressAttempted() {
		t.Fatal("prepare attempted live egress")
	}
	if got := out.GetEnvelope().GetOperation(); got != "send" {
		t.Fatalf("operation = %q, want send", got)
	}
	if got := out.GetEnvelope().GetPayloadRef(); got != "payload://ciphertext/1" {
		t.Fatalf("payload_ref = %q", got)
	}

	fallback, err := ExecuteSignalServiceSendPrepare(context.Background(), sdk.TypedStepRequest[*contracts.ServiceSendPrepareConfig, *contracts.ServiceSendPrepareInput]{
		Config: &contracts.ServiceSendPrepareConfig{AccountRef: "account://alice"},
		Input:  &contracts.ServiceSendPrepareInput{RecipientRef: "recipient://bob", PayloadRef: "payload://ciphertext/1"},
	})
	if err != nil {
		t.Fatalf("fallback prepare send: %v", err)
	}
	if strings.Contains(fallback.Output.GetEnvelope().GetOperationId(), "://account://") || strings.Contains(fallback.Output.GetEnvelope().GetIdempotencyKey(), "://") {
		t.Fatalf("fallback ids contain nested scheme: %+v", fallback.Output.GetEnvelope())
	}
	if strings.Contains(fallback.Output.GetAuditRef(), "op://") {
		t.Fatalf("fallback audit_ref contains nested operation scheme: %q", fallback.Output.GetAuditRef())
	}
}

func TestServiceOperationPrepareResolvesAccountCustodyReadiness(t *testing.T) {
	t.Cleanup(resetServiceTestState)
	custody, err := newKeyCustodyModule("custody", &contracts.KeyCustodyConfig{
		CustodyRef:          "custody://signal/alice/device-1",
		AccountRef:          "account://signal/alice",
		NonExportableKeyRef: "kms://signal/account-a/device-1",
	})
	if err != nil {
		t.Fatalf("new custody: %v", err)
	}
	if err := custody.Init(); err != nil {
		t.Fatalf("custody init: %v", err)
	}
	account, err := newAccountRefModule("account", &contracts.AccountRefConfig{
		AccountRef:    "account://signal/alice",
		DeviceRef:     "device://signal/alice/1",
		CustodyRef:    "custody://signal/alice/device-1",
		CredentialRef: "secret://signal/credential",
		ConsentRef:    "consent://case/1",
		AuditRef:      "audit://case/1",
	})
	if err != nil {
		t.Fatalf("new account: %v", err)
	}
	if err := account.Init(); err != nil {
		t.Fatalf("account init: %v", err)
	}

	result, err := ExecuteSignalServiceSendPrepare(context.Background(), sdk.TypedStepRequest[*contracts.ServiceSendPrepareConfig, *contracts.ServiceSendPrepareInput]{
		Config: &contracts.ServiceSendPrepareConfig{AccountRef: "account://signal/alice"},
		Input: &contracts.ServiceSendPrepareInput{
			IdempotencyKey: "send-1",
			RecipientRef:   "recipient://bob",
			PayloadRef:     "payload://ciphertext/1",
		},
	})
	if err != nil {
		t.Fatalf("prepare send: %v", err)
	}
	out := result.Output
	if !out.GetCustodyAttested() {
		t.Fatalf("custody_attested = false, output = %+v", out)
	}
	if out.GetCustodyAttestationRef() != "attest://signal/custody/custody-signal-alice-device-1" {
		t.Fatalf("custody_attestation_ref = %q", out.GetCustodyAttestationRef())
	}
	if got := out.GetEnvelope().GetCustodyRef(); got != "custody://signal/alice/device-1" {
		t.Fatalf("custody_ref = %q", got)
	}
	if got := out.GetEnvelope().GetNonExportableKeyRef(); got != "kms://signal/account-a/device-1" {
		t.Fatalf("non_exportable_key_ref = %q", got)
	}
	if got := out.GetEnvelope().GetCredentialRef(); got != "secret://signal/credential" {
		t.Fatalf("credential_ref = %q", got)
	}
	if got := out.GetEnvelope().GetDeviceRef(); got != "device://signal/alice/1" {
		t.Fatalf("device_ref = %q", got)
	}
	if got := out.GetEnvelope().GetAuditRef(); got != "audit://case/1" {
		t.Fatalf("audit_ref = %q", got)
	}

	otherCustody, err := newKeyCustodyModule("other-custody", &contracts.KeyCustodyConfig{
		CustodyRef:          "custody://signal/bob/device-1",
		AccountRef:          "account://signal/bob",
		NonExportableKeyRef: "kms://signal/account-b/device-1",
	})
	if err != nil {
		t.Fatalf("new other custody: %v", err)
	}
	if err := otherCustody.Init(); err != nil {
		t.Fatalf("other custody init: %v", err)
	}
	_, err = ExecuteSignalServiceSendPrepare(context.Background(), sdk.TypedStepRequest[*contracts.ServiceSendPrepareConfig, *contracts.ServiceSendPrepareInput]{
		Config: &contracts.ServiceSendPrepareConfig{AccountRef: "account://signal/alice"},
		Input: &contracts.ServiceSendPrepareInput{
			CustodyRef:   "custody://signal/bob/device-1",
			RecipientRef: "recipient://bob",
			PayloadRef:   "payload://ciphertext/1",
		},
	})
	if err == nil || !strings.Contains(err.Error(), "belongs to account") {
		t.Fatalf("mismatched custody error = %v", err)
	}
}

func TestServiceLinkPrepareValidatesCeremony(t *testing.T) {
	t.Cleanup(resetServiceTestState)
	ctx := context.Background()
	base := func(consent, unlink string) *contracts.ServiceLinkPrepareInput {
		return &contracts.ServiceLinkPrepareInput{
			OperationId:    "op://link/" + consent,
			AccountRef:     "account://alice",
			IdempotencyKey: "link-" + consent,
			LinkedDevice: &contracts.LinkedDeviceCeremony{
				DeviceDisplayName:  "Alice laptop",
				ConsentRef:         consent,
				ConsentExpiresUnix: 1_783_000_000,
				RevocationUri:      "https://operator.example/revoke/link",
				UnlinkProofRef:     unlink,
			},
		}
	}

	if _, err := ExecuteSignalServiceLinkPrepare(ctx, sdk.TypedStepRequest[*contracts.ServiceLinkPrepareConfig, *contracts.ServiceLinkPrepareInput]{
		Config: &contracts.ServiceLinkPrepareConfig{},
		Input:  base("", "unlink://proof/1"),
	}); err == nil {
		t.Fatal("missing linked-device consent succeeded")
	}
	expired := base("consent://link/expired", "unlink://proof/expired")
	expired.LinkedDevice.ConsentExpiresUnix = 1
	if _, err := ExecuteSignalServiceLinkPrepare(ctx, sdk.TypedStepRequest[*contracts.ServiceLinkPrepareConfig, *contracts.ServiceLinkPrepareInput]{
		Config: &contracts.ServiceLinkPrepareConfig{},
		Input:  expired,
	}); err == nil {
		t.Fatal("expired linked-device consent succeeded")
	}
	if _, err := ExecuteSignalServiceLinkPrepare(ctx, sdk.TypedStepRequest[*contracts.ServiceLinkPrepareConfig, *contracts.ServiceLinkPrepareInput]{
		Config: &contracts.ServiceLinkPrepareConfig{},
		Input:  base("consent://link/1", "revoked://unlink/1"),
	}); err == nil {
		t.Fatal("revoked unlink proof succeeded")
	}
	if _, err := ExecuteSignalServiceLinkPrepare(ctx, sdk.TypedStepRequest[*contracts.ServiceLinkPrepareConfig, *contracts.ServiceLinkPrepareInput]{
		Config: &contracts.ServiceLinkPrepareConfig{},
		Input:  base("consent://link/1", "unlink://proof/1"),
	}); err != nil {
		t.Fatalf("first link prepare: %v", err)
	}
	if _, err := ExecuteSignalServiceLinkPrepare(ctx, sdk.TypedStepRequest[*contracts.ServiceLinkPrepareConfig, *contracts.ServiceLinkPrepareInput]{
		Config: &contracts.ServiceLinkPrepareConfig{},
		Input:  base("consent://link/1", "unlink://proof/2"),
	}); err == nil {
		t.Fatal("replayed linked-device consent succeeded")
	}
}

func TestServiceOperationReportsAndAuditAreRedacted(t *testing.T) {
	username, err := ExecuteSignalUsernameProofPrepare(context.Background(), sdk.TypedStepRequest[*contracts.UsernameProofPrepareConfig, *contracts.UsernameProofPrepareInput]{
		Config: &contracts.UsernameProofPrepareConfig{AccountRef: "account://alice"},
		Input:  &contracts.UsernameProofPrepareInput{Username: "alice.1", IdempotencyKey: "username-1"},
	})
	if err != nil {
		t.Fatalf("username proof: %v", err)
	}
	if username.Output.GetReportClassification() != "structural" {
		t.Fatalf("username classification = %q", username.Output.GetReportClassification())
	}
	backup, err := ExecuteSignalBackupManifestVerify(context.Background(), sdk.TypedStepRequest[*contracts.BackupManifestVerifyConfig, *contracts.BackupManifestVerifyInput]{
		Config: &contracts.BackupManifestVerifyConfig{AccountRef: "account://alice"},
		Input:  &contracts.BackupManifestVerifyInput{BackupRef: "backup://manifest/1", BackupId: "backup-id://1"},
	})
	if err != nil {
		t.Fatalf("backup manifest: %v", err)
	}
	if backup.Output.GetReportClassification() != "deferred" || backup.Output.GetDeferredReason() == "" {
		t.Fatalf("backup report = %+v", backup.Output)
	}

	raw, err := json.Marshal(backup.Output)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"message_body", "phone_number", "private_key", "token"} {
		if bytes.Contains(raw, []byte(forbidden)) {
			t.Fatalf("operation output leaked %s: %s", forbidden, raw)
		}
	}
	if strings.Contains(string(raw), "+15551234567") {
		t.Fatalf("operation output leaked phone value: %s", raw)
	}
}
