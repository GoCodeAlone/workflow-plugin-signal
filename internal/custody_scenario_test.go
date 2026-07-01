package internal

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/GoCodeAlone/workflow/plugin/external/sdk"

	contracts "github.com/GoCodeAlone/workflow-plugin-signal/internal/contracts"
	sealedcustody "github.com/GoCodeAlone/workflow-plugin-signal/internal/custody"
)

func TestSignalCustodyRestartScenarioLifecycle(t *testing.T) {
	t.Cleanup(resetServiceTestState)
	restore := setSignalHostSecretResolverForTest(map[string][]byte{
		"secret://signal/kek": bytes.Repeat([]byte{0x42}, 32),
	})
	t.Cleanup(restore)

	scenarioPath := filepath.Join("..", "scenarios", "signal-custody-restart", "workflow.yaml")
	rawScenario, err := os.ReadFile(scenarioPath)
	if err != nil {
		t.Fatalf("read scenario: %v", err)
	}
	for _, required := range []string{
		"step.signal_custody_create",
		"step.signal_custody_restore",
		"step.signal_custody_rotate",
		"step.signal_custody_revoke",
		"step.signal_custody_inspect",
	} {
		if !bytes.Contains(rawScenario, []byte(required)) {
			t.Fatalf("scenario %s missing %s", scenarioPath, required)
		}
	}

	storageDir := t.TempDir()
	storeCfg := &contracts.CustodyStoreConfig{
		BackendId:        "local-test",
		Backend:          "test_file",
		StoragePath:      storageDir,
		KekRef:           "secret://signal/kek",
		KekVersion:       "v1",
		SchemaVersion:    1,
		AllowTestBackend: true,
	}
	startCustodyStoreForScenario(t, "custody_store", storeCfg)

	created, err := ExecuteSignalCustodyCreate(context.Background(), sdk.TypedStepRequest[*contracts.CustodyCreateConfig, *contracts.CustodyCreateInput]{
		Config: &contracts.CustodyCreateConfig{StoreRef: "custody_store"},
		Input: &contracts.CustodyCreateInput{
			AccountRef:      "account://signal/alice",
			DeviceRef:       "device://signal/alice/1",
			MaterialRefs:    []string{"secret://signal/alice/identity-key"},
			IdempotencyKey:  "alice-device-1",
			RequestedAtUnix: 1_783_000_000,
		},
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	ref := created.Output.GetCustodyRef()
	if ref == "" {
		t.Fatal("create returned empty custody ref")
	}

	resetCustodyStoresForScenario()
	startCustodyStoreForScenario(t, "custody_store", storeCfg)
	restored, err := ExecuteSignalCustodyRestore(context.Background(), sdk.TypedStepRequest[*contracts.CustodyRestoreConfig, *contracts.CustodyRestoreInput]{
		Config: &contracts.CustodyRestoreConfig{StoreRef: "custody_store"},
		Input:  &contracts.CustodyRestoreInput{CustodyRef: ref},
	})
	if err != nil {
		t.Fatalf("restore after restart: %v", err)
	}
	if restored.Output.GetMetadata().GetRefId() != ref {
		t.Fatalf("restored ref = %q, want %q", restored.Output.GetMetadata().GetRefId(), ref)
	}

	rotated, err := ExecuteSignalCustodyRotate(context.Background(), sdk.TypedStepRequest[*contracts.CustodyRotateConfig, *contracts.CustodyRotateInput]{
		Config: &contracts.CustodyRotateConfig{StoreRef: "custody_store"},
		Input: &contracts.CustodyRotateInput{
			CustodyRef:      ref,
			NewKekVersion:   "v2",
			RequestedAtUnix: 1_783_000_060,
		},
	})
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if got := rotated.Output.GetMetadata().GetKekVersion(); got != "v2" {
		t.Fatalf("rotated kek_version = %q, want v2", got)
	}

	if _, err := ExecuteSignalCustodyRevoke(context.Background(), sdk.TypedStepRequest[*contracts.CustodyRevokeConfig, *contracts.CustodyRevokeInput]{
		Config: &contracts.CustodyRevokeConfig{StoreRef: "custody_store"},
		Input: &contracts.CustodyRevokeInput{
			CustodyRef:      ref,
			RequestedAtUnix: 1_783_000_120,
		},
	}); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	_, err = ExecuteSignalCustodyRestore(context.Background(), sdk.TypedStepRequest[*contracts.CustodyRestoreConfig, *contracts.CustodyRestoreInput]{
		Config: &contracts.CustodyRestoreConfig{StoreRef: "custody_store"},
		Input:  &contracts.CustodyRestoreInput{CustodyRef: ref},
	})
	if !errors.Is(err, sealedcustody.ErrRevokedRef) {
		t.Fatalf("restore after revoke error = %v, want %v", err, sealedcustody.ErrRevokedRef)
	}
}

func startCustodyStoreForScenario(t *testing.T, name string, cfg *contracts.CustodyStoreConfig) {
	t.Helper()
	store, err := newCustodyStoreModule(name, cfg)
	if err != nil {
		t.Fatalf("new custody store: %v", err)
	}
	if err := store.Init(); err != nil {
		t.Fatalf("init custody store: %v", err)
	}
}

func resetCustodyStoresForScenario() {
	signalCustodyStoresMu.Lock()
	clear(signalCustodyStores)
	signalCustodyStoresMu.Unlock()
}
