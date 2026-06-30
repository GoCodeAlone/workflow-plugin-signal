package internal

import (
	"context"
	"testing"

	"github.com/GoCodeAlone/libsignal-service-go/servicemetadata"
	"github.com/GoCodeAlone/workflow/plugin/external/sdk"

	contracts "github.com/GoCodeAlone/workflow-plugin-signal/internal/contracts"
)

func TestExecuteSignalServiceComplianceCheckBlocksLiveActions(t *testing.T) {
	result, err := ExecuteSignalServiceComplianceCheck(context.Background(), sdk.TypedStepRequest[*contracts.ServiceComplianceCheckConfig, *contracts.ServiceComplianceCheckInput]{
		Config: &contracts.ServiceComplianceCheckConfig{Mode: "disabled"},
		Input: &contracts.ServiceComplianceCheckInput{
			RequestedActions: []string{"send", "receive", "production_egress"},
		},
	})
	if err != nil {
		t.Fatalf("ExecuteSignalServiceComplianceCheck: %v", err)
	}
	out := result.Output
	if out.GetApproved() {
		t.Fatalf("approved live actions: %+v", out)
	}
	if !out.GetLiveServiceDisabled() {
		t.Fatal("live service should be disabled")
	}
	for _, action := range []string{"send", "receive", "production_egress"} {
		if !containsString(out.GetBlockedActions(), action) {
			t.Fatalf("missing blocked action %q in %v", action, out.GetBlockedActions())
		}
	}
	for _, approval := range []string{
		"operator_live_service_approval",
		"legal_tos_review",
		"account_owner_consent",
		"abuse_rate_limit_plan",
		"credential_custody_plan",
		"audit_retention_plan",
		"egress_allowlist",
	} {
		if !containsString(out.GetRequiredApprovals(), approval) {
			t.Fatalf("missing required approval %q in %v", approval, out.GetRequiredApprovals())
		}
	}
}

func TestExecuteSignalServiceComplianceCheckDeniesLiveMode(t *testing.T) {
	result, err := ExecuteSignalServiceComplianceCheck(context.Background(), sdk.TypedStepRequest[*contracts.ServiceComplianceCheckConfig, *contracts.ServiceComplianceCheckInput]{
		Config: &contracts.ServiceComplianceCheckConfig{Mode: "live"},
		Input:  &contracts.ServiceComplianceCheckInput{},
	})
	if err != nil {
		t.Fatalf("ExecuteSignalServiceComplianceCheck: %v", err)
	}
	out := result.Output
	if out.GetApproved() {
		t.Fatalf("approved live mode: %+v", out)
	}
	if !out.GetLiveServiceDisabled() {
		t.Fatal("live service should be disabled")
	}
}

func TestExecuteSignalServiceComplianceCheckDefaultsModeToDisabled(t *testing.T) {
	result, err := ExecuteSignalServiceComplianceCheck(context.Background(), sdk.TypedStepRequest[*contracts.ServiceComplianceCheckConfig, *contracts.ServiceComplianceCheckInput]{
		Config: &contracts.ServiceComplianceCheckConfig{},
		Input:  &contracts.ServiceComplianceCheckInput{},
	})
	if err != nil {
		t.Fatalf("ExecuteSignalServiceComplianceCheck: %v", err)
	}
	if result.Output.GetMode() != "disabled" {
		t.Fatalf("mode = %q, want disabled", result.Output.GetMode())
	}
	if !result.Output.GetApproved() {
		t.Fatalf("disabled/no-action report denied: %+v", result.Output)
	}
}

func TestExecuteSignalServiceComplianceCheckFallsBackToConfigActionsAfterFilteringInput(t *testing.T) {
	result, err := ExecuteSignalServiceComplianceCheck(context.Background(), sdk.TypedStepRequest[*contracts.ServiceComplianceCheckConfig, *contracts.ServiceComplianceCheckInput]{
		Config: &contracts.ServiceComplianceCheckConfig{
			Mode:             "disabled",
			RequestedActions: []string{"send"},
		},
		Input: &contracts.ServiceComplianceCheckInput{
			RequestedActions: []string{"", ""},
		},
	})
	if err != nil {
		t.Fatalf("ExecuteSignalServiceComplianceCheck: %v", err)
	}
	if !containsString(result.Output.GetBlockedActions(), "send") {
		t.Fatalf("blocked actions = %v, want send", result.Output.GetBlockedActions())
	}
}

func TestExecuteSignalServiceComplianceCheckUsesMetadataBaseline(t *testing.T) {
	baseline := servicemetadata.Current()
	result, err := ExecuteSignalServiceComplianceCheck(context.Background(), sdk.TypedStepRequest[*contracts.ServiceComplianceCheckConfig, *contracts.ServiceComplianceCheckInput]{
		Config: &contracts.ServiceComplianceCheckConfig{Mode: "disabled"},
		Input:  &contracts.ServiceComplianceCheckInput{},
	})
	if err != nil {
		t.Fatalf("ExecuteSignalServiceComplianceCheck: %v", err)
	}
	out := result.Output
	if !out.GetApproved() {
		t.Fatalf("disabled/no-action report denied: %+v", out)
	}
	if out.GetUpstreamTag() != baseline.UpstreamTag {
		t.Fatalf("upstream tag = %q, want %q", out.GetUpstreamTag(), baseline.UpstreamTag)
	}
	if out.GetDescriptorChecksum() != baseline.DescriptorChecksum {
		t.Fatalf("descriptor checksum = %q, want %q", out.GetDescriptorChecksum(), baseline.DescriptorChecksum)
	}
	if out.GetManifestDigest() != baseline.ManifestDigest {
		t.Fatalf("manifest digest = %q, want %q", out.GetManifestDigest(), baseline.ManifestDigest)
	}
	if len(out.GetSelectedDomains()) != len(baseline.SelectedDomains) {
		t.Fatalf("selected domains = %v, want %v", out.GetSelectedDomains(), baseline.SelectedDomains)
	}
}

func containsString(values []string, want string) bool {
	for _, got := range values {
		if got == want {
			return true
		}
	}
	return false
}
