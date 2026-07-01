package custody

import (
	"bytes"
	"errors"
	"os"
	"sync"
	"testing"
	"time"
)

func TestSealedStoreCreateStoresEnvelopeMetadata(t *testing.T) {
	store := newTestStore(t, "v1")
	meta, err := store.Create(CreateRequest{
		RefID:      "custody-a",
		AccountRef: "account-a",
		DeviceRef:  "device-1",
		Material:   map[string][]byte{"private_key": []byte("super-secret-key")},
		Now:        testTime(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if meta.BackendID != "test-backend" || meta.RefID != "custody-a" || meta.SchemaVersion != 1 {
		t.Fatalf("metadata = %+v", meta)
	}
	if meta.KEKRef != "secret://signal/kek" || meta.KEKVersion != "v1" {
		t.Fatalf("kek metadata = %+v", meta)
	}
	if meta.CreatedAt.IsZero() || meta.RotatedAt.IsZero() || meta.State != StateActive {
		t.Fatalf("timestamps/state = %+v", meta)
	}
}

func TestSealedStoreReloadRestoresRefsWithoutKeyBytes(t *testing.T) {
	dir := t.TempDir()
	store := newTestStoreAt(t, dir, "v1")
	created, err := store.Create(CreateRequest{
		RefID:      "custody-a",
		AccountRef: "account-a",
		DeviceRef:  "device-1",
		Material:   map[string][]byte{"private_key": []byte("super-secret-key")},
		Now:        testTime(),
	})
	if err != nil {
		t.Fatal(err)
	}
	reloaded := newTestStoreAt(t, dir, "v1")
	restored, err := reloaded.Restore("custody-a")
	if err != nil {
		t.Fatal(err)
	}
	if restored.RefID != created.RefID || restored.AccountRef != "account-a" || restored.DeviceRef != "device-1" {
		t.Fatalf("restored metadata = %+v", restored)
	}
	encoded, err := restored.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte("super-secret-key")) || bytes.Contains(encoded, []byte("private_key")) {
		t.Fatalf("metadata exposed key material: %s", encoded)
	}
}

func TestSealedStoreRejectsPartialBundle(t *testing.T) {
	store := newTestStore(t, "v1")
	if err := os.WriteFile(store.path("custody-a"), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Restore("custody-a"); !errors.Is(err, ErrPartialBundle) {
		t.Fatalf("error = %v, want %v", err, ErrPartialBundle)
	}
}

func TestSealedStoreRejectsStaleKEKVersion(t *testing.T) {
	dir := t.TempDir()
	store := newTestStoreAt(t, dir, "v1")
	if _, err := store.Create(CreateRequest{RefID: "custody-a", Material: map[string][]byte{"key": []byte("value")}, Now: testTime()}); err != nil {
		t.Fatal(err)
	}
	reloaded := newTestStoreAt(t, dir, "v2")
	if _, err := reloaded.Restore("custody-a"); !errors.Is(err, ErrStaleKEKVersion) {
		t.Fatalf("error = %v, want %v", err, ErrStaleKEKVersion)
	}
}

func TestSealedStoreRotateValidatesRequest(t *testing.T) {
	store := newTestStore(t, "v1")
	if _, err := store.Rotate(RotateRequest{ExpectedKekVersion: "v1", NewKekVersion: "v2"}); err == nil {
		t.Fatal("empty ref_id rotate succeeded")
	}
	if _, err := store.Rotate(RotateRequest{RefID: "custody-a", NewKekVersion: "v2"}); err == nil {
		t.Fatal("empty expected_kek_version rotate succeeded")
	}
	if _, err := store.Rotate(RotateRequest{RefID: "custody-a", ExpectedKekVersion: "v1"}); err == nil {
		t.Fatal("empty new_kek_version rotate succeeded")
	}
}

func TestSealedStoreRotateCanChangeKEKRef(t *testing.T) {
	dir := t.TempDir()
	store := newTestStoreWithSecrets(t, dir, "secret://signal/kek/v1", "v1", map[string][]byte{
		"secret://signal/kek/v1": bytes.Repeat([]byte{0x42}, 32),
		"secret://signal/kek/v2": bytes.Repeat([]byte{0x43}, 32),
	})
	if _, err := store.Create(CreateRequest{RefID: "custody-a", Material: map[string][]byte{"key": []byte("value")}, Now: testTime()}); err != nil {
		t.Fatal(err)
	}
	rotated, err := store.Rotate(RotateRequest{
		RefID:              "custody-a",
		ExpectedKekVersion: "v1",
		NewKekRef:          "secret://signal/kek/v2",
		NewKekVersion:      "v2",
		Now:                testTime().Add(time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	if rotated.KEKRef != "secret://signal/kek/v2" || rotated.KEKVersion != "v2" {
		t.Fatalf("rotated metadata = %+v", rotated)
	}
	reloaded := newTestStoreWithSecrets(t, dir, "secret://signal/kek/v2", "v2", map[string][]byte{
		"secret://signal/kek/v1": bytes.Repeat([]byte{0x42}, 32),
		"secret://signal/kek/v2": bytes.Repeat([]byte{0x43}, 32),
	})
	if _, err := reloaded.Restore("custody-a"); err != nil {
		t.Fatalf("restore with rotated KEK ref: %v", err)
	}
}

func TestSealedStoreConcurrentRotateReturnsConflict(t *testing.T) {
	store := newTestStore(t, "v1")
	if _, err := store.Create(CreateRequest{RefID: "custody-a", Material: map[string][]byte{"key": []byte("value")}, Now: testTime()}); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for i := range 2 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := store.Rotate(RotateRequest{
				RefID:              "custody-a",
				ExpectedKekVersion: "v1",
				NewKekVersion:      "v2",
				Now:                testTime().Add(time.Duration(i) * time.Second),
			})
			errs <- err
		}(i)
	}
	wg.Wait()
	close(errs)
	conflicts := 0
	successes := 0
	for err := range errs {
		switch {
		case err == nil:
			successes++
		case errors.Is(err, ErrRotateConflict):
			conflicts++
		default:
			t.Fatalf("unexpected rotate error: %v", err)
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("successes=%d conflicts=%d, want 1/1", successes, conflicts)
	}
}

func TestSealedStoreRevokedRefRestoreFails(t *testing.T) {
	store := newTestStore(t, "v1")
	if _, err := store.Create(CreateRequest{RefID: "custody-a", Material: map[string][]byte{"key": []byte("value")}, Now: testTime()}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Revoke("custody-a", testTime().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Restore("custody-a"); !errors.Is(err, ErrRevokedRef) {
		t.Fatalf("error = %v, want %v", err, ErrRevokedRef)
	}
}

func newTestStore(t *testing.T, kekVersion string) *Store {
	t.Helper()
	return newTestStoreAt(t, t.TempDir(), kekVersion)
}

func newTestStoreAt(t *testing.T, dir, kekVersion string) *Store {
	t.Helper()
	return newTestStoreWithSecrets(t, dir, "secret://signal/kek", kekVersion, map[string][]byte{
		"secret://signal/kek": bytes.Repeat([]byte{0x42}, 32),
	})
}

func newTestStoreWithSecrets(t *testing.T, dir, kekRef, kekVersion string, secrets map[string][]byte) *Store {
	t.Helper()
	store, err := NewSealedStore(Config{
		BackendID:     "test-backend",
		StorageDir:    dir,
		KEKRef:        kekRef,
		KEKVersion:    kekVersion,
		SchemaVersion: 1,
		ResolveSecret: func(ref string) ([]byte, error) {
			secret, ok := secrets[ref]
			if !ok {
				return nil, os.ErrNotExist
			}
			return append([]byte(nil), secret...), nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func testTime() time.Time {
	return time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
}
