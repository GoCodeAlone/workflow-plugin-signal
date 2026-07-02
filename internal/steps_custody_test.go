package internal

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/GoCodeAlone/workflow/plugin/external/sdk"

	contracts "github.com/GoCodeAlone/workflow-plugin-signal/internal/contracts"
)

func TestSignalCustodyStepsUseSealedStoreWithoutKeyBytes(t *testing.T) {
	t.Cleanup(resetServiceTestState)
	restore := setSignalHostSecretResolverForTest(map[string][]byte{
		"secret://signal/kek": bytes.Repeat([]byte{0x42}, 32),
	})
	t.Cleanup(restore)

	store, err := newCustodyStoreModule("store", &contracts.CustodyStoreConfig{
		BackendId:        "local-test",
		Backend:          "test_file",
		StoragePath:      filepath.Join(t.TempDir(), "custody"),
		KekRef:           "secret://signal/kek",
		KekVersion:       "v1",
		SchemaVersion:    1,
		AllowTestBackend: true,
	})
	if err != nil {
		t.Fatalf("newCustodyStoreModule: %v", err)
	}
	if err := store.Init(); err != nil {
		t.Fatalf("store init: %v", err)
	}

	created, err := ExecuteSignalCustodyCreate(context.Background(), sdk.TypedStepRequest[*contracts.CustodyCreateConfig, *contracts.CustodyCreateInput]{
		Config: &contracts.CustodyCreateConfig{StoreRef: "store"},
		Input: &contracts.CustodyCreateInput{
			AccountRef:      "account-a",
			DeviceRef:       "device-1",
			MaterialRefs:    []string{"secret://signal/private-key"},
			IdempotencyKey:  "create-1",
			RequestedAtUnix: 1_783_000_000,
		},
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if created.Output.GetCustodyRef() == "" || created.Output.GetMetadata().GetBackendId() != "local-test" {
		t.Fatalf("create output = %+v", created.Output)
	}
	if created.Output.GetAuditRef() != "audit://custody/create-1" {
		t.Fatalf("create audit_ref = %q", created.Output.GetAuditRef())
	}

	inspected, err := ExecuteSignalCustodyInspect(context.Background(), sdk.TypedStepRequest[*contracts.CustodyInspectConfig, *contracts.CustodyInspectInput]{
		Config: &contracts.CustodyInspectConfig{StoreRef: "store"},
		Input:  &contracts.CustodyInspectInput{CustodyRef: created.Output.GetCustodyRef()},
	})
	if err != nil {
		t.Fatalf("inspect: %v", err)
	}
	raw, err := json.Marshal(inspected.Output)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("private-key")) {
		t.Fatalf("custody step output exposed secret material: %s", raw)
	}

	rotated, err := ExecuteSignalCustodyRotate(context.Background(), sdk.TypedStepRequest[*contracts.CustodyRotateConfig, *contracts.CustodyRotateInput]{
		Config: &contracts.CustodyRotateConfig{StoreRef: "store"},
		Input: &contracts.CustodyRotateInput{
			CustodyRef:      created.Output.GetCustodyRef(),
			NewKekVersion:   "v2",
			RequestedAtUnix: 1_783_000_060,
		},
	})
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if rotated.Output.GetOldRefState() != "active" {
		t.Fatalf("old_ref_state = %q", rotated.Output.GetOldRefState())
	}
	if rotated.Output.GetAuditRef() != "audit://custody/create-1" {
		t.Fatalf("rotate audit_ref = %q", rotated.Output.GetAuditRef())
	}

	if _, err := ExecuteSignalCustodyRestore(context.Background(), sdk.TypedStepRequest[*contracts.CustodyRestoreConfig, *contracts.CustodyRestoreInput]{
		Config: &contracts.CustodyRestoreConfig{StoreRef: "store"},
		Input: &contracts.CustodyRestoreInput{
			CustodyRef: created.Output.GetCustodyRef(),
			KekVersion: "v1",
		},
	}); err == nil {
		t.Fatal("restore with stale requested kek_version succeeded")
	}
}

func TestSignalCustodyAttestAndExportRequestReturnRefsOnly(t *testing.T) {
	t.Cleanup(resetServiceTestState)
	restore := setSignalHostSecretResolverForTest(map[string][]byte{
		"secret://signal/kek": bytes.Repeat([]byte{0x51}, 32),
	})
	t.Cleanup(restore)

	store, err := newCustodyStoreModule("store", &contracts.CustodyStoreConfig{
		BackendId:        "local-test",
		Backend:          "test_file",
		StoragePath:      filepath.Join(t.TempDir(), "custody"),
		KekRef:           "secret://signal/kek",
		KekVersion:       "v1",
		SchemaVersion:    1,
		AllowTestBackend: true,
	})
	if err != nil {
		t.Fatalf("newCustodyStoreModule: %v", err)
	}
	if err := store.Init(); err != nil {
		t.Fatalf("store init: %v", err)
	}

	created, err := ExecuteSignalCustodyCreate(context.Background(), sdk.TypedStepRequest[*contracts.CustodyCreateConfig, *contracts.CustodyCreateInput]{
		Config: &contracts.CustodyCreateConfig{StoreRef: "store"},
		Input: &contracts.CustodyCreateInput{
			AccountRef:      "account-a",
			DeviceRef:       "device-1",
			MaterialRefs:    []string{"secret://signal/private-key"},
			IdempotencyKey:  "create-1",
			RequestedAtUnix: 1_783_000_000,
		},
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	attested, err := ExecuteSignalCustodyAttest(context.Background(), sdk.TypedStepRequest[*contracts.CustodyAttestConfig, *contracts.CustodyAttestInput]{
		Config: &contracts.CustodyAttestConfig{StoreRef: "store"},
		Input: &contracts.CustodyAttestInput{
			CustodyRef:      created.Output.GetCustodyRef(),
			AudienceRef:     "workflow://scenario/custody-round-trip",
			RequestedAtUnix: 1_783_000_060,
		},
	})
	if err != nil {
		t.Fatalf("attest: %v", err)
	}
	if attested.Output.GetAttestationRef() == "" || attested.Output.GetEvidenceRef() == "" {
		t.Fatalf("attest output missing refs: %+v", attested.Output)
	}
	if attested.Output.GetMetadata().GetAccountRef() != "account-a" {
		t.Fatalf("attest metadata = %+v", attested.Output.GetMetadata())
	}

	exportRequest, err := ExecuteSignalCustodyExportRequest(context.Background(), sdk.TypedStepRequest[*contracts.CustodyExportRequestConfig, *contracts.CustodyExportRequestInput]{
		Config: &contracts.CustodyExportRequestConfig{StoreRef: "store"},
		Input: &contracts.CustodyExportRequestInput{
			CustodyRef:      created.Output.GetCustodyRef(),
			RequesterRef:    "principal://operator-a",
			ReasonRef:       "ticket://signal/export-review-1",
			RequestedAtUnix: 1_783_000_120,
		},
	})
	if err != nil {
		t.Fatalf("export request: %v", err)
	}
	if exportRequest.Output.GetStatus() != "approval_required" {
		t.Fatalf("export request status = %q", exportRequest.Output.GetStatus())
	}
	if exportRequest.Output.GetExportRequestRef() == "" || exportRequest.Output.GetApprovalRequiredRef() == "" {
		t.Fatalf("export request output missing refs: %+v", exportRequest.Output)
	}

	raw, err := json.Marshal(struct {
		Attested      *contracts.CustodyAttestOutput
		ExportRequest *contracts.CustodyExportRequestOutput
	}{Attested: attested.Output, ExportRequest: exportRequest.Output})
	if err != nil {
		t.Fatal(err)
	}
	encodedKey := []byte(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x51}, 32)))
	if bytes.Contains(raw, []byte("private-key")) ||
		bytes.Contains(raw, bytes.Repeat([]byte{0x51}, 32)) ||
		bytes.Contains(raw, encodedKey) {
		t.Fatalf("custody proof steps exposed key material: %s", raw)
	}
}
