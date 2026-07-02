package internal

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/GoCodeAlone/workflow/plugin/external/sdk"

	contracts "github.com/GoCodeAlone/workflow-plugin-signal/internal/contracts"
)

func TestPersistentCustodyAcceptsHostSecretBackedConfig(t *testing.T) {
	t.Cleanup(resetServiceTestState)
	restore := setSignalHostSecretResolverForTest(map[string][]byte{
		"secret://signal/kek": bytes.Repeat([]byte{0x42}, 32),
	})
	t.Cleanup(restore)

	module, err := newPersistentCustodyModule("persistent", &contracts.PersistentCustodyConfig{
		CustodyRef:            "custody-a",
		AccountRef:            "account-a",
		Backend:               persistentCustodyBackendLocalFile,
		StoragePath:           filepath.Join(t.TempDir(), "custody.json"),
		KeyHandle:             "kms://signal/account-a/device-1",
		HostSecretRef:         "secret://signal/kek",
		AllowTestBackend:      false,
		AllowLocalFileCustody: true,
	})
	if err != nil {
		t.Fatalf("newPersistentCustodyModule: %v", err)
	}
	if err := module.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}

	custody, err := lookupSignalKeyCustody("custody-a")
	if err != nil {
		t.Fatalf("lookup custody: %v", err)
	}
	if custody.nonExportableKeyRef != "kms://signal/account-a/device-1" {
		t.Fatalf("key handle = %q", custody.nonExportableKeyRef)
	}
	meta, err := lookupPersistentCustodyMetadata("custody-a")
	if err != nil {
		t.Fatalf("lookup metadata: %v", err)
	}
	if meta.TestBackend {
		t.Fatalf("local file backend marked test-only: %+v", meta)
	}
	if meta.HostSecretRef != "secret://signal/kek" || meta.KeyHandle != "kms://signal/account-a/device-1" {
		t.Fatalf("metadata refs = %+v", meta)
	}
}

func TestPersistentCustodyLocalFileRequiresExplicitDevelopmentOptIn(t *testing.T) {
	t.Cleanup(resetServiceTestState)
	if _, err := newPersistentCustodyModule("persistent", &contracts.PersistentCustodyConfig{
		CustodyRef:    "custody-a",
		AccountRef:    "account-a",
		Backend:       persistentCustodyBackendLocalFile,
		StoragePath:   filepath.Join(t.TempDir(), "custody.json"),
		KeyHandle:     "kms://signal/account-a/device-1",
		HostSecretRef: "secret://signal/kek",
	}); err == nil {
		t.Fatal("expected local file custody to require explicit opt-in")
	}

	if _, err := newPersistentCustodyModule("persistent", &contracts.PersistentCustodyConfig{
		CustodyRef:            "custody-a",
		AccountRef:            "account-a",
		Backend:               persistentCustodyBackendLocalFile,
		StoragePath:           filepath.Join(t.TempDir(), "custody.json"),
		KeyHandle:             "kms://signal/account-a/device-1",
		HostSecretRef:         "secret://signal/kek",
		AllowLocalFileCustody: true,
		PolicyMode:            "production",
	}); err == nil {
		t.Fatal("expected production policy to reject local file custody")
	}

	if _, err := newCustodyStoreModule("store", &contracts.CustodyStoreConfig{
		BackendId:     "local",
		Backend:       persistentCustodyBackendLocalFile,
		StoragePath:   filepath.Join(t.TempDir(), "store"),
		KekRef:        "secret://signal/kek",
		KekVersion:    "v1",
		SchemaVersion: 1,
	}); err == nil {
		t.Fatal("expected local file custody store to require explicit opt-in")
	}

	if _, err := newCustodyStoreModule("store", &contracts.CustodyStoreConfig{
		BackendId:             "local",
		Backend:               persistentCustodyBackendLocalFile,
		StoragePath:           filepath.Join(t.TempDir(), "store"),
		KekRef:                "secret://signal/kek",
		KekVersion:            "v1",
		SchemaVersion:         1,
		AllowLocalFileCustody: true,
		PolicyMode:            "production",
	}); err == nil {
		t.Fatal("expected production policy to reject local file custody store")
	}
}

func TestPersistentCustodyTestBackendIsNonProduction(t *testing.T) {
	t.Cleanup(resetServiceTestState)
	restore := setSignalHostSecretResolverForTest(map[string][]byte{
		"secret://signal/test-kek": bytes.Repeat([]byte{0x24}, 32),
	})
	t.Cleanup(restore)

	if _, err := newPersistentCustodyModule("persistent", &contracts.PersistentCustodyConfig{
		CustodyRef:    "custody-a",
		AccountRef:    "account-a",
		Backend:       persistentCustodyBackendTestFile,
		StoragePath:   filepath.Join(t.TempDir(), "custody.json"),
		KeyHandle:     "test://signal/account-a/device-1",
		HostSecretRef: "secret://signal/test-kek",
	}); err == nil {
		t.Fatal("expected test backend to require explicit opt-in")
	}

	module, err := newPersistentCustodyModule("persistent", &contracts.PersistentCustodyConfig{
		CustodyRef:       "custody-a",
		AccountRef:       "account-a",
		Backend:          persistentCustodyBackendTestFile,
		StoragePath:      filepath.Join(t.TempDir(), "custody.json"),
		KeyHandle:        "test://signal/account-a/device-1",
		HostSecretRef:    "secret://signal/test-kek",
		AllowTestBackend: true,
	})
	if err != nil {
		t.Fatalf("newPersistentCustodyModule: %v", err)
	}
	if err := module.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}
	meta, err := lookupPersistentCustodyMetadata("custody-a")
	if err != nil {
		t.Fatalf("lookup metadata: %v", err)
	}
	if !meta.TestBackend {
		t.Fatalf("test backend metadata = %+v", meta)
	}
}

func TestCustodyStoreTestBackendCanUseHermeticTestSecretRefs(t *testing.T) {
	t.Cleanup(resetServiceTestState)

	store, err := newCustodyStoreModule("store", &contracts.CustodyStoreConfig{
		BackendId:        "local-test",
		Backend:          persistentCustodyBackendTestFile,
		StoragePath:      filepath.Join(t.TempDir(), "custody"),
		KekRef:           "test://signal/kek",
		KekVersion:       "v1",
		SchemaVersion:    1,
		AllowTestBackend: true,
	})
	if err != nil {
		t.Fatalf("newCustodyStoreModule: %v", err)
	}
	if err := store.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if _, err := ExecuteSignalCustodyCreate(t.Context(), sdk.TypedStepRequest[*contracts.CustodyCreateConfig, *contracts.CustodyCreateInput]{
		Config: &contracts.CustodyCreateConfig{StoreRef: "store"},
		Input: &contracts.CustodyCreateInput{
			AccountRef:     "account-a",
			DeviceRef:      "device-1",
			MaterialRefs:   []string{"secret://signal/private-key"},
			IdempotencyKey: "create-1",
		},
	}); err != nil {
		t.Fatalf("create: %v", err)
	}
}

func TestPersistentCustodyRestartReloadsHandleAndDerivesSameKey(t *testing.T) {
	t.Cleanup(resetServiceTestState)
	restore := setSignalHostSecretResolverForTest(map[string][]byte{
		"secret://signal/kek": bytes.Repeat([]byte{0x7c}, 32),
	})
	t.Cleanup(restore)
	storagePath := filepath.Join(t.TempDir(), "custody.json")
	cfg := &contracts.PersistentCustodyConfig{
		CustodyRef:            "custody-a",
		AccountRef:            "account-a",
		Backend:               persistentCustodyBackendLocalFile,
		StoragePath:           storagePath,
		KeyHandle:             "kms://signal/account-a/device-1",
		HostSecretRef:         "secret://signal/kek",
		AllowLocalFileCustody: true,
	}

	first, err := newPersistentCustodyModule("persistent", cfg)
	if err != nil {
		t.Fatalf("new first module: %v", err)
	}
	if err := first.Init(); err != nil {
		t.Fatalf("first init: %v", err)
	}
	firstKey, err := derivePersistentCustodyKey("custody-a", "account-backup-key")
	if err != nil {
		t.Fatalf("first derive: %v", err)
	}

	resetServiceTestState()

	second, err := newPersistentCustodyModule("persistent", cfg)
	if err != nil {
		t.Fatalf("new second module: %v", err)
	}
	if err := second.Init(); err != nil {
		t.Fatalf("second init: %v", err)
	}
	secondKey, err := derivePersistentCustodyKey("custody-a", "account-backup-key")
	if err != nil {
		t.Fatalf("second derive: %v", err)
	}
	if !bytes.Equal(firstKey, secondKey) {
		t.Fatalf("derived key changed across restart")
	}
	custody, err := lookupSignalKeyCustody("custody-a")
	if err != nil {
		t.Fatalf("lookup custody: %v", err)
	}
	if custody.nonExportableKeyRef != "kms://signal/account-a/device-1" {
		t.Fatalf("reloaded handle = %q", custody.nonExportableKeyRef)
	}
}

func TestPersistentCustodyMetadataRedactsKeyMaterial(t *testing.T) {
	t.Cleanup(resetServiceTestState)
	hostSecret := bytes.Repeat([]byte{0x66}, 32)
	restore := setSignalHostSecretResolverForTest(map[string][]byte{
		"secret://signal/kek": hostSecret,
	})
	t.Cleanup(restore)
	storagePath := filepath.Join(t.TempDir(), "custody.json")
	module, err := newPersistentCustodyModule("persistent", &contracts.PersistentCustodyConfig{
		CustodyRef:            "custody-a",
		AccountRef:            "account-a",
		Backend:               persistentCustodyBackendLocalFile,
		StoragePath:           storagePath,
		KeyHandle:             "kms://signal/account-a/device-1",
		HostSecretRef:         "secret://signal/kek",
		AllowLocalFileCustody: true,
	})
	if err != nil {
		t.Fatalf("newPersistentCustodyModule: %v", err)
	}
	if err := module.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}

	meta, err := lookupPersistentCustodyMetadata("custody-a")
	if err != nil {
		t.Fatalf("lookup metadata: %v", err)
	}
	metaJSON, err := json.Marshal(meta)
	if err != nil {
		t.Fatalf("marshal metadata: %v", err)
	}
	stored, err := os.ReadFile(storagePath)
	if err != nil {
		t.Fatalf("read storage: %v", err)
	}
	if bytes.Contains(metaJSON, hostSecret) || bytes.Contains(stored, hostSecret) {
		t.Fatalf("custody output contains host secret material")
	}
	if bytes.Contains(metaJSON, []byte("seed")) {
		t.Fatalf("custody metadata exposes seed fields: %s", metaJSON)
	}
	if !bytes.Contains(metaJSON, []byte("kms://signal/account-a/device-1")) {
		t.Fatalf("metadata should expose handle refs only: %s", metaJSON)
	}
}
