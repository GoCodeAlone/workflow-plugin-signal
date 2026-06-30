package internal

import (
	"context"
	"errors"
	"testing"

	"github.com/GoCodeAlone/libsignal-service-go/servicepolicy"
	"github.com/GoCodeAlone/workflow/plugin/external/sdk"

	contracts "github.com/GoCodeAlone/workflow-plugin-signal/internal/contracts"
)

func TestExecuteSignalServiceContractCheck(t *testing.T) {
	result, err := ExecuteSignalServiceContractCheck(context.Background(), sdk.TypedStepRequest[*contracts.ServiceContractCheckConfig, *contracts.ServiceContractCheckInput]{
		Config: &contracts.ServiceContractCheckConfig{Mode: "test_double"},
		Input:  &contracts.ServiceContractCheckInput{},
	})
	if err != nil {
		t.Fatalf("ExecuteSignalServiceContractCheck: %v", err)
	}
	out := result.Output
	if out.GetMode() != "test_double" {
		t.Fatalf("mode = %q", out.GetMode())
	}
	if out.GetUpstreamTag() != "v0.96.4" {
		t.Fatalf("upstream tag = %q", out.GetUpstreamTag())
	}
	if out.GetDescriptorChecksum() == "" {
		t.Fatal("descriptor checksum is empty")
	}
	if !out.GetLiveServiceDisabled() {
		t.Fatal("live service should be disabled")
	}
	if len(out.GetSelectedDomains()) == 0 {
		t.Fatal("selected domains are empty")
	}
}

func TestServiceBoundaryRejectsLiveMode(t *testing.T) {
	_, err := newOfficialServiceBoundaryModule("svc", &contracts.OfficialServiceBoundaryConfig{Mode: "live"})
	if !errors.Is(err, servicepolicy.ErrLiveServiceDisabled) {
		t.Fatalf("live mode error = %v, want %v", err, servicepolicy.ErrLiveServiceDisabled)
	}
	_, err = ExecuteSignalServiceContractCheck(context.Background(), sdk.TypedStepRequest[*contracts.ServiceContractCheckConfig, *contracts.ServiceContractCheckInput]{
		Config: &contracts.ServiceContractCheckConfig{},
		Input:  &contracts.ServiceContractCheckInput{Mode: "live"},
	})
	if !errors.Is(err, servicepolicy.ErrLiveServiceDisabled) {
		t.Fatalf("live check error = %v, want %v", err, servicepolicy.ErrLiveServiceDisabled)
	}
}
