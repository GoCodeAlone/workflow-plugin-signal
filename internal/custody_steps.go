package internal

import (
	"context"

	"github.com/GoCodeAlone/workflow/plugin/external/sdk"

	contracts "github.com/GoCodeAlone/workflow-plugin-signal/internal/contracts"
)

func ExecuteSignalCustodyCreate(
	_ context.Context,
	req sdk.TypedStepRequest[*contracts.CustodyCreateConfig, *contracts.CustodyCreateInput],
) (*sdk.TypedStepResult[*contracts.CustodyCreateOutput], error) {
	ref := firstNonEmpty(req.Input.GetStoreRef(), req.Config.GetStoreRef())
	return &sdk.TypedStepResult[*contracts.CustodyCreateOutput]{
		Output: &contracts.CustodyCreateOutput{CustodyRef: ref},
	}, nil
}

func ExecuteSignalCustodyRotate(
	_ context.Context,
	req sdk.TypedStepRequest[*contracts.CustodyRotateConfig, *contracts.CustodyRotateInput],
) (*sdk.TypedStepResult[*contracts.CustodyRotateOutput], error) {
	return &sdk.TypedStepResult[*contracts.CustodyRotateOutput]{
		Output: &contracts.CustodyRotateOutput{CustodyRef: req.Input.GetCustodyRef()},
	}, nil
}

func ExecuteSignalCustodyRestore(
	_ context.Context,
	req sdk.TypedStepRequest[*contracts.CustodyRestoreConfig, *contracts.CustodyRestoreInput],
) (*sdk.TypedStepResult[*contracts.CustodyRestoreOutput], error) {
	return &sdk.TypedStepResult[*contracts.CustodyRestoreOutput]{
		Output: &contracts.CustodyRestoreOutput{CustodyRef: req.Input.GetCustodyRef()},
	}, nil
}

func ExecuteSignalCustodyRevoke(
	_ context.Context,
	req sdk.TypedStepRequest[*contracts.CustodyRevokeConfig, *contracts.CustodyRevokeInput],
) (*sdk.TypedStepResult[*contracts.CustodyRevokeOutput], error) {
	return &sdk.TypedStepResult[*contracts.CustodyRevokeOutput]{
		Output: &contracts.CustodyRevokeOutput{CustodyRef: req.Input.GetCustodyRef()},
	}, nil
}

func ExecuteSignalCustodyInspect(
	_ context.Context,
	req sdk.TypedStepRequest[*contracts.CustodyInspectConfig, *contracts.CustodyInspectInput],
) (*sdk.TypedStepResult[*contracts.CustodyInspectOutput], error) {
	return &sdk.TypedStepResult[*contracts.CustodyInspectOutput]{
		Output: &contracts.CustodyInspectOutput{CustodyRef: req.Input.GetCustodyRef()},
	}, nil
}
