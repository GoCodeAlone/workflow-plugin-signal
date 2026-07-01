package internal

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/GoCodeAlone/libsignal-service-go/serviceclient"
	"github.com/GoCodeAlone/libsignal-service-go/servicepolicy"
	"github.com/GoCodeAlone/workflow/plugin/external/sdk"

	contracts "github.com/GoCodeAlone/workflow-plugin-signal/internal/contracts"
)

func TestServiceTransportModuleValidatesModes(t *testing.T) {
	t.Cleanup(resetServiceTestState)

	fakeModule, err := newServiceTransportModule("fake", &contracts.ServiceTransportConfig{
		TransportRef: "transport-fake",
		Mode:         "fake",
	})
	if err != nil {
		t.Fatalf("fake transport: %v", err)
	}
	if err := fakeModule.Init(); err != nil {
		t.Fatalf("fake init: %v", err)
	}

	_, err = newServiceTransportModule("sandbox-missing", &contracts.ServiceTransportConfig{
		TransportRef: "transport-sandbox",
		Mode:         "sandbox",
	})
	if !errors.Is(err, serviceclient.ErrMissingSandboxEndpoint) {
		t.Fatalf("sandbox missing endpoint error = %v", err)
	}

	sandboxModule, err := newServiceTransportModule("sandbox", &contracts.ServiceTransportConfig{
		TransportRef:     "transport-sandbox",
		Mode:             "sandbox",
		SandboxEndpoint:  "https://signal-sandbox.invalid",
		RequestedActions: []string{"send"},
	})
	if err != nil {
		t.Fatalf("sandbox transport: %v", err)
	}
	if err := sandboxModule.Init(); err != nil {
		t.Fatalf("sandbox init: %v", err)
	}

	_, err = newServiceTransportModule("live", &contracts.ServiceTransportConfig{
		TransportRef:     "transport-live",
		Mode:             "live",
		RequestedActions: []string{"send"},
	})
	if !errors.Is(err, servicepolicy.ErrLiveServiceDisabled) {
		t.Fatalf("live incomplete approval error = %v", err)
	}

	_, err = newServiceTransportModule("bogus", &contracts.ServiceTransportConfig{
		TransportRef: "transport-bogus",
		Mode:         "bogus",
	})
	if !errors.Is(err, serviceclient.ErrUnsupportedTransportMode) {
		t.Fatalf("bogus mode error = %v", err)
	}
}

func TestServiceApprovalValidateReturnsDenialReasons(t *testing.T) {
	result, err := ExecuteSignalServiceApprovalValidate(context.Background(), sdk.TypedStepRequest[*contracts.ServiceApprovalValidateConfig, *contracts.ServiceApprovalValidateInput]{
		Config: &contracts.ServiceApprovalValidateConfig{Mode: "live"},
		Input: &contracts.ServiceApprovalValidateInput{
			RequestedActions: []string{"send"},
			Approval: &contracts.ApprovalPackage{
				OperatorApprovalId:          "approval-1",
				OperatorApprovalScope:       "signal-live",
				ServiceAuthorizationType:    "none",
				AccountRef:                  "account-a",
				AbuseIdempotencyRequired:    true,
				AbuseRateLimitRef:           "policy://rate",
				AbuseChallengePolicyRef:     "policy://challenge",
				AbuseBackoffPolicyRef:       "policy://backoff",
				EgressEndpointAllowlist:     []string{"https://signal-sandbox.invalid"},
				EgressTlsPolicyRef:          "policy://tls",
				AuditRef:                    "audit://case/1",
				AuditRetentionRef:           "policy://retention",
				AuditRedactionRef:           "policy://redaction",
				OperatorApprovalExpiresUnix: time.Now().Add(time.Hour).Unix(),
			},
		},
	})
	if err != nil {
		t.Fatalf("approval validate: %v", err)
	}
	out := result.Output
	if out.GetLiveTransportAllowed() {
		t.Fatalf("live allowed with incomplete approval: %+v", out)
	}
	for _, reason := range []string{
		"service_authorization_unsupported",
		"service_authorization_evidence_missing",
		"account_consent_evidence_missing",
		"custody_key_handle_missing",
		"abuse_audience_missing",
	} {
		if !containsString(out.GetDeniedReasons(), reason) {
			t.Fatalf("missing denial reason %q in %v", reason, out.GetDeniedReasons())
		}
	}
}

func TestServiceLiveSubmitRefusesIncompleteLiveWithoutEgress(t *testing.T) {
	t.Cleanup(resetServiceTestState)
	registerServiceTestAccount(t)

	result, err := ExecuteSignalServiceLiveSubmit(context.Background(), sdk.TypedStepRequest[*contracts.ServiceLiveSubmitConfig, *contracts.ServiceLiveSubmitInput]{
		Config: &contracts.ServiceLiveSubmitConfig{Mode: "live", AccountRef: "account-a"},
		Input: &contracts.ServiceLiveSubmitInput{
			Operation:      "send",
			IdempotencyKey: "live-send-1",
			RecipientRef:   "phone:+15551234567",
			PayloadRef:     "hello from plaintext",
		},
	})
	if err != nil {
		t.Fatalf("live submit should return denial output, not error: %v", err)
	}
	out := result.Output
	if out.GetLiveEgressAttempted() {
		t.Fatalf("live egress attempted on denied approval: %+v", out)
	}
	if out.GetStatus() != "denied" {
		t.Fatalf("status = %q, want denied", out.GetStatus())
	}
	if len(out.GetDeniedReasons()) == 0 {
		t.Fatalf("denied reasons empty: %+v", out)
	}
	if got := len(signalServiceTransportRecords("")); got != 0 {
		t.Fatalf("fake transport records = %d, want no egress", got)
	}
}

func TestServiceLiveSubmitFakeAndSandboxOperationsUseTransport(t *testing.T) {
	t.Cleanup(resetServiceTestState)
	registerServiceTestAccount(t)
	registerServiceTransportForTest(t, "transport-fake", "fake", "")
	registerServiceTransportForTest(t, "transport-sandbox", "sandbox", "https://signal-sandbox.invalid")

	ctx := context.Background()
	cases := []struct {
		name         string
		transportRef string
		input        *contracts.ServiceLiveSubmitInput
	}{
		{name: "register", transportRef: "transport-fake", input: &contracts.ServiceLiveSubmitInput{Operation: "register", IdempotencyKey: "idem-register", Username: "alice.1"}},
		{name: "link", transportRef: "transport-fake", input: &contracts.ServiceLiveSubmitInput{Operation: "linked_device", IdempotencyKey: "idem-link", LinkCodeRef: "secret://link-code"}},
		{name: "send", transportRef: "transport-sandbox", input: &contracts.ServiceLiveSubmitInput{Operation: "send", IdempotencyKey: "idem-send", RecipientRef: "recipient://bob", PayloadRef: "payload://ciphertext/1", ChallengeRef: "challenge://send/1"}},
		{name: "receive", transportRef: "transport-sandbox", input: &contracts.ServiceLiveSubmitInput{Operation: "receive", IdempotencyKey: "idem-receive", CursorRef: "cursor://inbox/1"}},
		{name: "username", transportRef: "transport-fake", input: &contracts.ServiceLiveSubmitInput{Operation: "username_reserve", IdempotencyKey: "idem-username", Username: "alice.2"}},
		{name: "backup-upload", transportRef: "transport-fake", input: &contracts.ServiceLiveSubmitInput{Operation: "backup_upload", IdempotencyKey: "idem-backup-up", BackupRef: "backup://snapshot/1"}},
		{name: "backup-download", transportRef: "transport-fake", input: &contracts.ServiceLiveSubmitInput{Operation: "backup_download", IdempotencyKey: "idem-backup-down", BackupId: "backup-id://snapshot/1"}},
		{name: "challenge", transportRef: "transport-fake", input: &contracts.ServiceLiveSubmitInput{Operation: "challenge_response", IdempotencyKey: "idem-challenge", ChallengeRef: "challenge://send/1", ChallengeResponseRef: "secret://challenge-response"}},
	}
	for _, tc := range cases {
		tc.input.TransportRef = tc.transportRef
		tc.input.AccountRef = "account-a"
		t.Run(tc.name, func(t *testing.T) {
			result, err := ExecuteSignalServiceLiveSubmit(ctx, sdk.TypedStepRequest[*contracts.ServiceLiveSubmitConfig, *contracts.ServiceLiveSubmitInput]{
				Config: &contracts.ServiceLiveSubmitConfig{},
				Input:  tc.input,
			})
			if err != nil {
				t.Fatalf("submit: %v", err)
			}
			if result.Output.GetStatus() != "accepted" && result.Output.GetStatus() != "challenge_required" {
				t.Fatalf("status = %q", result.Output.GetStatus())
			}
			if result.Output.GetTransportMode() == "" {
				t.Fatalf("missing transport mode: %+v", result.Output)
			}
		})
	}
	if got := len(signalServiceTransportRecords("transport-fake")) + len(signalServiceTransportRecords("transport-sandbox")); got != len(cases) {
		t.Fatalf("transport records = %d, want %d", got, len(cases))
	}
}

func TestServiceLiveSubmitOutputRedactsRawInputs(t *testing.T) {
	t.Cleanup(resetServiceTestState)
	registerServiceTestAccount(t)
	registerServiceTransportForTest(t, "transport-fake", "fake", "")

	result, err := ExecuteSignalServiceLiveSubmit(context.Background(), sdk.TypedStepRequest[*contracts.ServiceLiveSubmitConfig, *contracts.ServiceLiveSubmitInput]{
		Config: &contracts.ServiceLiveSubmitConfig{},
		Input: &contracts.ServiceLiveSubmitInput{
			TransportRef:        "transport-fake",
			Operation:           "send",
			AccountRef:          "account-a",
			IdempotencyKey:      "idem-redact",
			RecipientRef:        "phone:+15551234567",
			PayloadRef:          "hello from plaintext",
			CredentialRef:       "credential-raw-secret",
			AuditRef:            "audit://case/1",
			ChallengeRef:        "challenge://send/1",
			NonExportableKeyRef: "kms://signal/account-a/device-1",
		},
	})
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	raw, err := json.Marshal(result.Output)
	if err != nil {
		t.Fatalf("marshal output: %v", err)
	}
	for _, secret := range []string{"phone:+15551234567", "hello from plaintext", "credential-raw-secret"} {
		if jsonContains(raw, secret) {
			t.Fatalf("output leaked %q: %s", secret, raw)
		}
	}
}

func registerServiceTransportForTest(t *testing.T, ref, mode, sandboxEndpoint string) {
	t.Helper()
	module, err := newServiceTransportModule("transport", &contracts.ServiceTransportConfig{
		TransportRef:    ref,
		Mode:            mode,
		SandboxEndpoint: sandboxEndpoint,
	})
	if err != nil {
		t.Fatalf("new transport %s: %v", ref, err)
	}
	if err := module.Init(); err != nil {
		t.Fatalf("transport init %s: %v", ref, err)
	}
}

func jsonContains(raw []byte, value string) bool {
	return len(value) > 0 && strings.Contains(string(raw), value)
}
