package internal

import (
	"context"

	"github.com/GoCodeAlone/libsignal-service-go/servicemetadata"
	"github.com/GoCodeAlone/libsignal-service-go/servicepolicy"
	"github.com/GoCodeAlone/workflow/plugin/external/sdk"

	contracts "github.com/GoCodeAlone/workflow-plugin-signal/internal/contracts"
)

func ExecuteSignalServiceComplianceCheck(
	_ context.Context,
	req sdk.TypedStepRequest[*contracts.ServiceComplianceCheckConfig, *contracts.ServiceComplianceCheckInput],
) (*sdk.TypedStepResult[*contracts.ServiceComplianceCheckOutput], error) {
	mode := firstNonEmpty(req.Input.GetMode(), req.Config.GetMode())
	if mode == "" {
		mode = string(servicepolicy.ModeDisabled)
	}
	actions := serviceComplianceActions(req.Input.GetRequestedActions(), req.Config.GetRequestedActions())
	report := servicepolicy.EvaluateCompliance(servicepolicy.ComplianceRequest{
		Mode:             servicepolicy.Mode(mode),
		RequestedActions: actions,
	})
	baseline := servicemetadata.Current()

	return &sdk.TypedStepResult[*contracts.ServiceComplianceCheckOutput]{
		Output: &contracts.ServiceComplianceCheckOutput{
			Mode:                string(report.Mode),
			Approved:            report.Approved,
			LiveServiceDisabled: report.LiveServiceDisabled,
			BlockedActions:      servicePolicyActionsToStrings(report.BlockedActions),
			RequiredApprovals:   append([]string(nil), report.RequiredApprovals...),
			DeferredDomains:     append([]string(nil), report.DeferredDomains...),
			UpstreamTag:         baseline.UpstreamTag,
			DescriptorChecksum:  baseline.DescriptorChecksum,
			ManifestDigest:      baseline.ManifestDigest,
			SelectedDomains:     append([]string(nil), baseline.SelectedDomains...),
		},
	}, nil
}

func serviceComplianceActions(inputActions, configActions []string) []servicepolicy.Action {
	actions := nonEmptyServicePolicyActions(inputActions)
	if len(actions) == 0 {
		actions = nonEmptyServicePolicyActions(configActions)
	}
	return actions
}

func nonEmptyServicePolicyActions(values []string) []servicepolicy.Action {
	actions := make([]servicepolicy.Action, 0, len(values))
	for _, value := range values {
		if value == "" {
			continue
		}
		actions = append(actions, servicepolicy.Action(value))
	}
	return actions
}

func servicePolicyActionsToStrings(actions []servicepolicy.Action) []string {
	values := make([]string, 0, len(actions))
	for _, action := range actions {
		values = append(values, string(action))
	}
	return values
}
