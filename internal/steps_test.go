package internal

import (
	"bytes"
	"context"
	"encoding/hex"
	"testing"

	"github.com/GoCodeAlone/workflow/plugin/external/sdk"

	contracts "github.com/GoCodeAlone/workflow-plugin-signal/internal/contracts"
)

func TestExecuteSignalFingerprint(t *testing.T) {
	got, err := ExecuteSignalFingerprint(context.Background(), sdk.TypedStepRequest[*contracts.SignalFingerprintConfig, *contracts.SignalFingerprintInput]{
		Config: &contracts.SignalFingerprintConfig{Version: 1, Iterations: 5200},
		Input: &contracts.SignalFingerprintInput{
			LocalId:   "+14152222222",
			LocalKey:  "0506863bc66d02b40d27b8d49ca7c09e9239236f9d7d25d6fcca5ce13c7064d868",
			RemoteId:  "+14153333333",
			RemoteKey: "05f781b6fb32fed9ba1cf2de978d4d5da28dc34046ae814402b5c0dbd96fda907b",
		},
	})
	if err != nil {
		t.Fatalf("ExecuteSignalFingerprint: %v", err)
	}

	if got.Output.GetDisplay() != "300354477692869396892869876765458257569162576843440918079131" {
		t.Fatalf("display = %q", got.Output.GetDisplay())
	}
	if got.Output.GetScannableHex() != "080112220a201e301a0353dce3dbe7684cb8336e85136cdc0ee96219494ada305d62a7bd61df1a220a20d62cbf73a11592015b6b9f1682ac306fea3aaf3885b84d12bca631e9d4fb3a4d" {
		t.Fatalf("scannable = %q", got.Output.GetScannableHex())
	}
}

func TestExecuteSignalAccountKeys(t *testing.T) {
	aci := mustHex(t, "659aa5f4a28dfcc11ea1b997537a3d95")
	salt := mustHex(t, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	got, err := ExecuteSignalAccountKeys(context.Background(), sdk.TypedStepRequest[*contracts.AccountKeysConfig, *contracts.AccountKeysInput]{
		Config: &contracts.AccountKeysConfig{},
		Input: &contracts.AccountKeysInput{
			EntropyPool: "dtjs858asj6tv0jzsqrsmj0ubp335pisj98e9ssnss8myoc08drhtcktyawvx45l",
			Aci:         aci,
			Pin:         "password",
			PinSalt:     salt,
		},
	})
	if err != nil {
		t.Fatalf("ExecuteSignalAccountKeys: %v", err)
	}
	if got.Output.GetEntropyPool() == "" {
		t.Fatal("empty entropy pool")
	}
	if !bytes.Equal(got.Output.GetSvrKey(), mustHex(t, "cdfecb856b148ca1c7f7557904f1ec698d0ccc4d4d68ed4c58c74a21e5c1c6c1")) {
		t.Fatalf("svr key = %x", got.Output.GetSvrKey())
	}
	if !bytes.Equal(got.Output.GetBackupKey(), mustHex(t, "ea26a2ddb5dba5ef9e34e1b8dea1f5ae7f255306a6d2d883e542306eaa9fe985")) {
		t.Fatalf("backup key = %x", got.Output.GetBackupKey())
	}
	if !bytes.Equal(got.Output.GetBackupId(), mustHex(t, "8a624fbc45379043f39f1391cddc5fe8")) {
		t.Fatalf("backup id = %x", got.Output.GetBackupId())
	}
	if !bytes.Equal(got.Output.GetPinAccessKey(), mustHex(t, "ab7e8499d21f80a6600b3b9ee349ac6d72c07e3359fe885a934ba7aa844429f8")) {
		t.Fatalf("pin access key = %x", got.Output.GetPinAccessKey())
	}
	if len(got.Output.GetPinEncryptionKey()) != 32 {
		t.Fatalf("pin encryption key length = %d", len(got.Output.GetPinEncryptionKey()))
	}
}

func TestExecuteSignalUsernameLinkRoundTrip(t *testing.T) {
	entropy := mustHex(t, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	created, err := ExecuteSignalUsernameLinkCreate(context.Background(), sdk.TypedStepRequest[*contracts.UsernameLinkCreateConfig, *contracts.UsernameLinkCreateInput]{
		Config: &contracts.UsernameLinkCreateConfig{},
		Input: &contracts.UsernameLinkCreateInput{
			Username: "test_username.42",
			Entropy:  entropy,
		},
	})
	if err != nil {
		t.Fatalf("ExecuteSignalUsernameLinkCreate: %v", err)
	}
	if !bytes.Equal(created.Output.GetEntropy(), entropy) {
		t.Fatalf("entropy = %x, want %x", created.Output.GetEntropy(), entropy)
	}
	if len(created.Output.GetEncryptedUsername()) == 0 || len(created.Output.GetLinkBuffer()) == 0 {
		t.Fatal("username link create returned empty encrypted payload")
	}

	decrypted, err := ExecuteSignalUsernameLinkDecrypt(context.Background(), sdk.TypedStepRequest[*contracts.UsernameLinkDecryptConfig, *contracts.UsernameLinkDecryptInput]{
		Config: &contracts.UsernameLinkDecryptConfig{},
		Input: &contracts.UsernameLinkDecryptInput{
			LinkBuffer: created.Output.GetLinkBuffer(),
		},
	})
	if err != nil {
		t.Fatalf("ExecuteSignalUsernameLinkDecrypt: %v", err)
	}
	if decrypted.Output.GetUsername() != "test_username.42" {
		t.Fatalf("username = %q", decrypted.Output.GetUsername())
	}
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	raw, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
