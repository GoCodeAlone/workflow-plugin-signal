package internal

import (
	"context"
	"fmt"

	"github.com/GoCodeAlone/libsignal-service-go/servicepolicy"
	"github.com/GoCodeAlone/workflow/plugin/external/sdk"

	contracts "github.com/GoCodeAlone/workflow-plugin-signal/internal/contracts"
)

const (
	serviceBoundaryUpstreamTag        = "v0.96.4"
	serviceBoundaryDescriptorChecksum = "9f647ca4a75f581514cbe080c792871e10d7dbd7b22bd6faf2832e15d447e484"
)

var serviceBoundaryDomains = []string{
	"account",
	"device",
	"messages",
	"profile",
	"keys",
	"backups_metadata",
	"challenge",
	"credentials",
	"chat_websocket",
}

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
	return &sdk.TypedStepResult[*contracts.ServiceContractCheckOutput]{
		Output: &contracts.ServiceContractCheckOutput{
			Mode:                mode,
			UpstreamTag:         serviceBoundaryUpstreamTag,
			DescriptorChecksum:  serviceBoundaryDescriptorChecksum,
			SelectedDomains:     append([]string(nil), serviceBoundaryDomains...),
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
