package internal

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/GoCodeAlone/workflow/plugin/external/sdk"
	"google.golang.org/protobuf/types/known/wrapperspb"

	contracts "github.com/GoCodeAlone/workflow-plugin-signal/internal/contracts"
)

func TestExecuteSignalFingerprint(t *testing.T) {
	input := signalFingerprintInput{
		Version:    1,
		Iterations: 5200,
		LocalID:    "+14152222222",
		LocalKey:   "0506863bc66d02b40d27b8d49ca7c09e9239236f9d7d25d6fcca5ce13c7064d868",
		RemoteID:   "+14153333333",
		RemoteKey:  "05f781b6fb32fed9ba1cf2de978d4d5da28dc34046ae814402b5c0dbd96fda907b",
	}
	payload, err := json.Marshal(input)
	if err != nil {
		t.Fatalf("marshal input: %v", err)
	}

	got, err := ExecuteSignalFingerprint(context.Background(), sdk.TypedStepRequest[*contracts.SignalFingerprintConfig, *contracts.SignalFingerprintInput]{
		Input: wrapperspb.String(string(payload)),
	})
	if err != nil {
		t.Fatalf("ExecuteSignalFingerprint: %v", err)
	}

	var output signalFingerprintOutput
	if err := json.Unmarshal([]byte(got.Output.Value), &output); err != nil {
		t.Fatalf("unmarshal output: %v", err)
	}
	if output.Display != "300354477692869396892869876765458257569162576843440918079131" {
		t.Fatalf("display = %q", output.Display)
	}
	if output.ScannableHex != "080112220a201e301a0353dce3dbe7684cb8336e85136cdc0ee96219494ada305d62a7bd61df1a220a20d62cbf73a11592015b6b9f1682ac306fea3aaf3885b84d12bca631e9d4fb3a4d" {
		t.Fatalf("scannable = %q", output.ScannableHex)
	}
}
