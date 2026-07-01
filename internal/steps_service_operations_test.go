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
