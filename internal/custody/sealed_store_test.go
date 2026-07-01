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
	store, err := NewSealedStore(Config{
		BackendID:     "test-backend",
		StorageDir:    dir,
		KEKRef:        "secret://signal/kek",
		KEKVersion:    kekVersion,
		SchemaVersion: 1,
		ResolveSecret: func(string) ([]byte, error) {
			return bytes.Repeat([]byte{0x42}, 32), nil
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
