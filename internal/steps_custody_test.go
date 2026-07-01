package internal

import (
	"bytes"
	"context"
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
}
