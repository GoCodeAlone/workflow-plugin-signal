package internal

import (
	"context"
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
