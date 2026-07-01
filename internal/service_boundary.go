package internal

import (
	"context"
	"fmt"

	"github.com/GoCodeAlone/libsignal-service-go/servicemetadata"
	"github.com/GoCodeAlone/libsignal-service-go/servicepolicy"
	"github.com/GoCodeAlone/workflow/plugin/external/sdk"

	contracts "github.com/GoCodeAlone/workflow-plugin-signal/internal/contracts"
)

func ExecuteSignalServiceContractCheck(
	_ context.Context,
	req sdk.TypedStepRequest[*contracts.ServiceContractCheckConfig, *contracts.ServiceContractCheckInput],
) (*sdk.TypedStepResult[*contracts.ServiceContractCheckOutput], error) {
	mode := firstNonEmpty(req.Input.GetMode(), req.Config.GetMode())
	if err := validateServiceBoundaryMode(mode); err != nil {
		return nil, fmt.Errorf("signal service contract check: %w", err)
	}
	if mode == "" {
		mode = string(servicepolicy.ModeDisabled)
	}
	baseline := servicemetadata.Current()
	return &sdk.TypedStepResult[*contracts.ServiceContractCheckOutput]{
		Output: &contracts.ServiceContractCheckOutput{
			Mode:                mode,
			UpstreamTag:         baseline.UpstreamTag,
			DescriptorChecksum:  baseline.DescriptorChecksum,
			SelectedDomains:     append([]string(nil), baseline.SelectedDomains...),
			LiveServiceDisabled: true,
		},
	}, nil
}

func validateServiceBoundaryMode(mode string) error {
	policy := servicepolicy.Policy{Mode: servicepolicy.Mode(mode)}
	if err := policy.Validate(); err != nil {
		return err
	}
	return nil
}
