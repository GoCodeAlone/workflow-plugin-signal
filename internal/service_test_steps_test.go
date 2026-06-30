package internal

import (
	"context"
	"testing"

	"github.com/GoCodeAlone/workflow/plugin/external/sdk"

	contracts "github.com/GoCodeAlone/workflow-plugin-signal/internal/contracts"
)

func TestServicePolicyCheckReportsMissingApprovals(t *testing.T) {
	result, err := ExecuteSignalServicePolicyCheck(context.Background(), sdk.TypedStepRequest[*contracts.ServicePolicyCheckConfig, *contracts.ServicePolicyCheckInput]{
		Config: &contracts.ServicePolicyCheckConfig{Mode: "live"},
		Input: &contracts.ServicePolicyCheckInput{
			Approvals:        []string{"operator_live_service_approval"},
			RequestedActions: []string{"send"},
		},
	})
	if err != nil {
		t.Fatalf("ExecuteSignalServicePolicyCheck: %v", err)
	}
	out := result.Output
	if out.GetLiveTransportAllowed() {
		t.Fatalf("live transport allowed with missing approvals: %+v", out)
	}
	if !containsString(out.GetMissingApprovals(), "legal_tos_review") {
		t.Fatalf("missing approvals = %v", out.GetMissingApprovals())
	}
	if !containsString(out.GetBlockedActions(), "send") {
		t.Fatalf("blocked actions = %v", out.GetBlockedActions())
	}
}

func TestServiceTestStepsUseDeterministicFakeAndRefsOnly(t *testing.T) {
	t.Cleanup(resetServiceTestState)
	registerServiceTestAccount(t)

	ctx := context.Background()
	register, err := ExecuteSignalServiceTestRegister(ctx, sdk.TypedStepRequest[*contracts.ServiceTestRegisterConfig, *contracts.ServiceTestRegisterInput]{
		Config: &contracts.ServiceTestRegisterConfig{AccountRef: "account-a"},
		Input: &contracts.ServiceTestRegisterInput{
			IdempotencyKey: "idem-register-1",
			Username:       "alice.1",
		},
	})
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if register.Output.GetStatus() != "accepted" {
		t.Fatalf("register status = %q", register.Output.GetStatus())
	}
	if register.Output.GetRequestId() != "idem-register-1" {
		t.Fatalf("register request id = %q", register.Output.GetRequestId())
	}
	if register.Output.GetCredentialRef() != "secret://signal/credential" {
		t.Fatalf("credential ref = %q", register.Output.GetCredentialRef())
	}

	replay, err := ExecuteSignalServiceTestRegister(ctx, sdk.TypedStepRequest[*contracts.ServiceTestRegisterConfig, *contracts.ServiceTestRegisterInput]{
		Config: &contracts.ServiceTestRegisterConfig{AccountRef: "account-a"},
		Input: &contracts.ServiceTestRegisterInput{
			IdempotencyKey: "idem-register-1",
			Username:       "alice.1",
		},
	})
	if err != nil {
		t.Fatalf("register replay: %v", err)
	}
	if replay.Output.GetRequestId() != register.Output.GetRequestId() {
		t.Fatalf("replay request id = %q, want %q", replay.Output.GetRequestId(), register.Output.GetRequestId())
	}

	if _, err := ExecuteSignalServiceTestRegister(ctx, sdk.TypedStepRequest[*contracts.ServiceTestRegisterConfig, *contracts.ServiceTestRegisterInput]{
		Config: &contracts.ServiceTestRegisterConfig{AccountRef: "account-a"},
		Input: &contracts.ServiceTestRegisterInput{
			IdempotencyKey: "idem-register-1",
			Username:       "bob.2",
		},
	}); err == nil {
		t.Fatal("expected idempotency conflict")
	}

	link, err := ExecuteSignalServiceTestLinkDevice(ctx, sdk.TypedStepRequest[*contracts.ServiceTestLinkDeviceConfig, *contracts.ServiceTestLinkDeviceInput]{
		Config: &contracts.ServiceTestLinkDeviceConfig{AccountRef: "account-a"},
		Input: &contracts.ServiceTestLinkDeviceInput{
			IdempotencyKey: "idem-link-1",
			LinkCodeRef:    "secret://signal/link-code",
		},
	})
	if err != nil {
		t.Fatalf("link device: %v", err)
	}
	if link.Output.GetStatus() != "accepted" {
		t.Fatalf("link status = %q", link.Output.GetStatus())
	}

	send, err := ExecuteSignalServiceTestSend(ctx, sdk.TypedStepRequest[*contracts.ServiceTestSendConfig, *contracts.ServiceTestSendInput]{
		Config: &contracts.ServiceTestSendConfig{AccountRef: "account-a"},
		Input: &contracts.ServiceTestSendInput{
			IdempotencyKey: "idem-send-1",
			RecipientRef:   "recipient://bob",
			PayloadRef:     "payload://ciphertext/1",
			ChallengeRef:   "challenge://send/1",
		},
	})
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	if send.Output.GetStatus() != "challenge_required" {
		t.Fatalf("send status = %q", send.Output.GetStatus())
	}
	if send.Output.GetChallengeRef() != "challenge://send/1" {
		t.Fatalf("send challenge = %q", send.Output.GetChallengeRef())
	}

	receive, err := ExecuteSignalServiceTestReceive(ctx, sdk.TypedStepRequest[*contracts.ServiceTestReceiveConfig, *contracts.ServiceTestReceiveInput]{
		Config: &contracts.ServiceTestReceiveConfig{AccountRef: "account-a"},
		Input: &contracts.ServiceTestReceiveInput{
			IdempotencyKey: "idem-receive-1",
			CursorRef:      "cursor://inbox/1",
		},
	})
	if err != nil {
		t.Fatalf("receive: %v", err)
	}
	if receive.Output.GetStatus() != "accepted" {
		t.Fatalf("receive status = %q", receive.Output.GetStatus())
	}
}

func registerServiceTestAccount(t *testing.T) {
	t.Helper()
	custody, err := newKeyCustodyModule("custody", &contracts.KeyCustodyConfig{
		CustodyRef:          "custody-a",
		AccountRef:          "account-a",
		NonExportableKeyRef: "kms://signal/account-a/device-1",
	})
	if err != nil {
		t.Fatalf("new custody: %v", err)
	}
	if err := custody.Init(); err != nil {
		t.Fatalf("custody init: %v", err)
	}
	account, err := newAccountRefModule("account", &contracts.AccountRefConfig{
		AccountRef:    "account-a",
		DeviceRef:     "device-1",
		CustodyRef:    "custody-a",
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
}
