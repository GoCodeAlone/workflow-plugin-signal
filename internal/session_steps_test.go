package internal

import (
	"bytes"
	"context"
	"testing"

	"github.com/GoCodeAlone/workflow/plugin/external/sdk"

	contracts "github.com/GoCodeAlone/workflow-plugin-signal/internal/contracts"
)

func TestSignalSessionPrepareEncryptDecryptRoundTrip(t *testing.T) {
	resetIdentityStoresForTest()
	ctx := context.Background()

	registerIdentityForTest(t, "alice-store", &contracts.IdentityStoreConfig{
		IdentityRef:    "alice",
		LocalId:        "alice@example.test",
		DeviceId:       1,
		RegistrationId: 1001,
	})
	registerIdentityForTest(t, "bob-store", &contracts.IdentityStoreConfig{
		IdentityRef:    "bob",
		LocalId:        "bob@example.test",
		DeviceId:       1,
		RegistrationId: 2002,
	})

	prepared, err := ExecuteSignalSessionPrepare(ctx, sdk.TypedStepRequest[*contracts.SessionPrepareConfig, *contracts.SessionPrepareInput]{
		Config: &contracts.SessionPrepareConfig{IdentityRef: "bob"},
		Input:  &contracts.SessionPrepareInput{},
	})
	if err != nil {
		t.Fatalf("prepare bob: %v", err)
	}
	if prepared.Output.GetBundle().GetIdentityKey() == "" {
		t.Fatal("prepare returned empty identity key")
	}

	plaintext := []byte("private workflow message")
	encrypted, err := ExecuteSignalEncrypt(ctx, sdk.TypedStepRequest[*contracts.SignalEncryptConfig, *contracts.SignalEncryptInput]{
		Config: &contracts.SignalEncryptConfig{IdentityRef: "alice"},
		Input: &contracts.SignalEncryptInput{
			RemoteId:       "bob@example.test",
			RemoteDeviceId: 1,
			RemoteBundle:   prepared.Output.GetBundle(),
			Plaintext:      plaintext,
		},
	})
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if encrypted.Output.GetEnvelope().GetMessageType() != "prekey" {
		t.Fatalf("message type = %q, want prekey", encrypted.Output.GetEnvelope().GetMessageType())
	}
	if bytes.Contains(encrypted.Output.GetEnvelope().GetCiphertext(), plaintext) {
		t.Fatal("ciphertext contains plaintext")
	}

	decrypted, err := ExecuteSignalDecrypt(ctx, sdk.TypedStepRequest[*contracts.SignalDecryptConfig, *contracts.SignalDecryptInput]{
		Config: &contracts.SignalDecryptConfig{IdentityRef: "bob", RequiredPrincipal: "bob-user"},
		Input: &contracts.SignalDecryptInput{
			Principal: "bob-user",
			Envelope:  encrypted.Output.GetEnvelope(),
		},
	})
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if decrypted.Output.GetDenied() {
		t.Fatalf("decrypt denied: %s", decrypted.Output.GetError())
	}
	if !bytes.Equal(decrypted.Output.GetPlaintext(), plaintext) {
		t.Fatalf("plaintext = %q, want %q", decrypted.Output.GetPlaintext(), plaintext)
	}
}

func TestSignalDecryptDeniesUnauthorizedPrincipalWithoutPlaintext(t *testing.T) {
	resetIdentityStoresForTest()
	ctx := context.Background()

	registerIdentityForTest(t, "alice-store", &contracts.IdentityStoreConfig{
		IdentityRef:    "alice",
		LocalId:        "alice@example.test",
		DeviceId:       1,
		RegistrationId: 1001,
	})
	registerIdentityForTest(t, "bob-store", &contracts.IdentityStoreConfig{
		IdentityRef:    "bob",
		LocalId:        "bob@example.test",
		DeviceId:       1,
		RegistrationId: 2002,
	})

	prepared, err := ExecuteSignalSessionPrepare(ctx, sdk.TypedStepRequest[*contracts.SessionPrepareConfig, *contracts.SessionPrepareInput]{
		Config: &contracts.SessionPrepareConfig{IdentityRef: "bob"},
		Input:  &contracts.SessionPrepareInput{},
	})
	if err != nil {
		t.Fatalf("prepare bob: %v", err)
	}
	encrypted, err := ExecuteSignalEncrypt(ctx, sdk.TypedStepRequest[*contracts.SignalEncryptConfig, *contracts.SignalEncryptInput]{
		Config: &contracts.SignalEncryptConfig{IdentityRef: "alice"},
		Input: &contracts.SignalEncryptInput{
			RemoteId:       "bob@example.test",
			RemoteDeviceId: 1,
			RemoteBundle:   prepared.Output.GetBundle(),
			Plaintext:      []byte("do not reveal"),
		},
	})
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	decrypted, err := ExecuteSignalDecrypt(ctx, sdk.TypedStepRequest[*contracts.SignalDecryptConfig, *contracts.SignalDecryptInput]{
		Config: &contracts.SignalDecryptConfig{IdentityRef: "bob", RequiredPrincipal: "bob-user"},
		Input: &contracts.SignalDecryptInput{
			Principal: "mallory",
			Envelope:  encrypted.Output.GetEnvelope(),
		},
	})
	if err != nil {
		t.Fatalf("decrypt unauthorized: %v", err)
	}
	if !decrypted.Output.GetDenied() {
		t.Fatal("unauthorized decrypt was not denied")
	}
	if len(decrypted.Output.GetPlaintext()) != 0 {
		t.Fatalf("unauthorized plaintext leaked: %q", decrypted.Output.GetPlaintext())
	}
}

func registerIdentityForTest(t *testing.T, name string, cfg *contracts.IdentityStoreConfig) {
	t.Helper()
	module := newIdentityStoreModule(name, cfg)
	if err := module.Init(); err != nil {
		t.Fatalf("init identity module %s: %v", name, err)
	}
}

func resetIdentityStoresForTest() {
	signalIdentitiesMu.Lock()
	clear(signalIdentities)
	signalIdentitiesMu.Unlock()
}
