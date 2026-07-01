package internal

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/GoCodeAlone/workflow/plugin/external/sdk"

	contracts "github.com/GoCodeAlone/workflow-plugin-signal/internal/contracts"
	sealedcustody "github.com/GoCodeAlone/workflow-plugin-signal/internal/custody"
)

func ExecuteSignalCustodyCreate(
	_ context.Context,
	req sdk.TypedStepRequest[*contracts.CustodyCreateConfig, *contracts.CustodyCreateInput],
) (*sdk.TypedStepResult[*contracts.CustodyCreateOutput], error) {
	storeRef := firstNonEmpty(req.Input.GetStoreRef(), req.Config.GetStoreRef())
	store, err := lookupSignalCustodyStore(storeRef)
	if err != nil {
		return nil, err
	}
	ref := "custody://" + firstNonEmpty(req.Input.GetIdempotencyKey(), req.Input.GetAccountRef(), storeRef)
	material := map[string][]byte{}
	for _, materialRef := range req.Input.GetMaterialRefs() {
		material[materialRef] = []byte(materialRef)
	}
	meta, err := store.Create(sealedcustody.CreateRequest{
		RefID:      ref,
		AccountRef: req.Input.GetAccountRef(),
		DeviceRef:  req.Input.GetDeviceRef(),
		Material:   material,
		Now:        custodyUnixTime(req.Input.GetRequestedAtUnix()),
	})
	if err != nil {
		return nil, err
	}
	return &sdk.TypedStepResult[*contracts.CustodyCreateOutput]{
		Output: &contracts.CustodyCreateOutput{
			CustodyRef: ref,
			Metadata:   custodyMetadata(meta),
			AuditRef:   custodyAuditRef(ref),
		},
	}, nil
}

func ExecuteSignalCustodyRotate(
	_ context.Context,
	req sdk.TypedStepRequest[*contracts.CustodyRotateConfig, *contracts.CustodyRotateInput],
) (*sdk.TypedStepResult[*contracts.CustodyRotateOutput], error) {
	store, err := lookupSignalCustodyStore(req.Config.GetStoreRef())
	if err != nil {
		return nil, err
	}
	current, err := store.Inspect(req.Input.GetCustodyRef())
	if err != nil {
		return nil, err
	}
	meta, err := store.Rotate(sealedcustody.RotateRequest{
		RefID:              req.Input.GetCustodyRef(),
		ExpectedKekVersion: current.KEKVersion,
		NewKekRef:          req.Input.GetNewKekRef(),
		NewKekVersion:      req.Input.GetNewKekVersion(),
		Now:                custodyUnixTime(req.Input.GetRequestedAtUnix()),
	})
	if err != nil {
		return nil, err
	}
	return &sdk.TypedStepResult[*contracts.CustodyRotateOutput]{
		Output: &contracts.CustodyRotateOutput{
			CustodyRef:  req.Input.GetCustodyRef(),
			Metadata:    custodyMetadata(meta),
			OldRefState: current.State,
			AuditRef:    custodyAuditRef(req.Input.GetCustodyRef()),
		},
	}, nil
}

func ExecuteSignalCustodyRestore(
	_ context.Context,
	req sdk.TypedStepRequest[*contracts.CustodyRestoreConfig, *contracts.CustodyRestoreInput],
) (*sdk.TypedStepResult[*contracts.CustodyRestoreOutput], error) {
	store, err := lookupSignalCustodyStore(req.Config.GetStoreRef())
	if err != nil {
		return nil, err
	}
	meta, err := store.Restore(req.Input.GetCustodyRef())
	if err != nil {
		return nil, err
	}
	if err := validateCustodyRestoreHints(req.Input, meta); err != nil {
		return nil, err
	}
	return &sdk.TypedStepResult[*contracts.CustodyRestoreOutput]{
		Output: &contracts.CustodyRestoreOutput{CustodyRef: req.Input.GetCustodyRef(), Metadata: custodyMetadata(meta), AuditRef: custodyAuditRef(req.Input.GetCustodyRef())},
	}, nil
}

func ExecuteSignalCustodyRevoke(
	_ context.Context,
	req sdk.TypedStepRequest[*contracts.CustodyRevokeConfig, *contracts.CustodyRevokeInput],
) (*sdk.TypedStepResult[*contracts.CustodyRevokeOutput], error) {
	store, err := lookupSignalCustodyStore(req.Config.GetStoreRef())
	if err != nil {
		return nil, err
	}
	meta, err := store.Revoke(req.Input.GetCustodyRef(), custodyUnixTime(req.Input.GetRequestedAtUnix()))
	if err != nil {
		return nil, err
	}
	return &sdk.TypedStepResult[*contracts.CustodyRevokeOutput]{
		Output: &contracts.CustodyRevokeOutput{CustodyRef: req.Input.GetCustodyRef(), Metadata: custodyMetadata(meta), AuditRef: custodyAuditRef(req.Input.GetCustodyRef())},
	}, nil
}

func ExecuteSignalCustodyInspect(
	_ context.Context,
	req sdk.TypedStepRequest[*contracts.CustodyInspectConfig, *contracts.CustodyInspectInput],
) (*sdk.TypedStepResult[*contracts.CustodyInspectOutput], error) {
	store, err := lookupSignalCustodyStore(req.Config.GetStoreRef())
	if err != nil {
		return nil, err
	}
	meta, err := store.Inspect(req.Input.GetCustodyRef())
	if err != nil {
		return nil, err
	}
	return &sdk.TypedStepResult[*contracts.CustodyInspectOutput]{
		Output: &contracts.CustodyInspectOutput{CustodyRef: req.Input.GetCustodyRef(), Metadata: custodyMetadata(meta)},
	}, nil
}

func custodyMetadata(meta sealedcustody.Metadata) *contracts.CustodyMetadata {
	revokedAt := int64(0)
	if !meta.RevokedAt.IsZero() {
		revokedAt = meta.RevokedAt.Unix()
	}
	return &contracts.CustodyMetadata{
		BackendId:     meta.BackendID,
		RefId:         meta.RefID,
		SchemaVersion: meta.SchemaVersion,
		KekRef:        meta.KEKRef,
		KekVersion:    meta.KEKVersion,
		CreatedAtUnix: meta.CreatedAt.Unix(),
		RotatedAtUnix: meta.RotatedAt.Unix(),
		RevokedAtUnix: revokedAt,
		State:         meta.State,
		AccountRef:    meta.AccountRef,
		DeviceRef:     meta.DeviceRef,
	}
}

func custodyUnixTime(ts int64) time.Time {
	if ts == 0 {
		return time.Now().UTC()
	}
	return time.Unix(ts, 0).UTC()
}

func custodyAuditRef(custodyRef string) string {
	suffix := strings.TrimPrefix(custodyRef, "custody://")
	suffix = strings.ReplaceAll(suffix, "://", "/")
	suffix = strings.Trim(suffix, "/")
	if suffix == "" {
		suffix = "unknown"
	}
	return "audit://custody/" + suffix
}

func validateCustodyRestoreHints(in *contracts.CustodyRestoreInput, meta sealedcustody.Metadata) error {
	if sealedBundleRef := in.GetSealedBundleRef(); sealedBundleRef != "" && sealedBundleRef != in.GetCustodyRef() {
		return fmt.Errorf("signal custody restore: sealed_bundle_ref %q does not match custody_ref", sealedBundleRef)
	}
	if kekRef := in.GetKekRef(); kekRef != "" && kekRef != meta.KEKRef {
		return fmt.Errorf("signal custody restore: kek_ref %q does not match sealed metadata", kekRef)
	}
	if kekVersion := in.GetKekVersion(); kekVersion != "" && kekVersion != meta.KEKVersion {
		return fmt.Errorf("signal custody restore: kek_version %q does not match sealed metadata", kekVersion)
	}
	return nil
}
