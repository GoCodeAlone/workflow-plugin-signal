package internal

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/GoCodeAlone/libsignal-go/curve"
	"github.com/GoCodeAlone/libsignal-go/fingerprint"
	"github.com/GoCodeAlone/workflow/plugin/external/sdk"
	"google.golang.org/protobuf/types/known/wrapperspb"

	contracts "github.com/GoCodeAlone/workflow-plugin-signal/internal/contracts"
)

type signalFingerprintInput struct {
	Version    uint32 `json:"version"`
	Iterations uint32 `json:"iterations"`
	LocalID    string `json:"localId"`
	LocalKey   string `json:"localKey"`
	RemoteID   string `json:"remoteId"`
	RemoteKey  string `json:"remoteKey"`
}

type signalFingerprintOutput struct {
	Display      string `json:"display"`
	ScannableHex string `json:"scannableHex"`
}

// ExecuteSignalFingerprint computes a Signal safety number and scannable
// fingerprint from serialized identity public keys.
func ExecuteSignalFingerprint(
	ctx context.Context,
	req sdk.TypedStepRequest[*contracts.SignalFingerprintConfig, *contracts.SignalFingerprintInput],
) (*sdk.TypedStepResult[*contracts.SignalFingerprintOutput], error) {
	_ = ctx
	if req.Input == nil || req.Input.Value == "" {
		return nil, fmt.Errorf("signal fingerprint: missing JSON input")
	}
	var input signalFingerprintInput
	if err := json.Unmarshal([]byte(req.Input.Value), &input); err != nil {
		return nil, fmt.Errorf("signal fingerprint: decode input: %w", err)
	}
	localKey, err := decodePublicKey(input.LocalKey)
	if err != nil {
		return nil, fmt.Errorf("signal fingerprint: localKey: %w", err)
	}
	remoteKey, err := decodePublicKey(input.RemoteKey)
	if err != nil {
		return nil, fmt.Errorf("signal fingerprint: remoteKey: %w", err)
	}
	fp, err := fingerprint.New(input.Version, input.Iterations, []byte(input.LocalID), localKey, []byte(input.RemoteID), remoteKey)
	if err != nil {
		return nil, fmt.Errorf("signal fingerprint: compute: %w", err)
	}
	scannable, err := fp.Scannable.Serialize()
	if err != nil {
		return nil, fmt.Errorf("signal fingerprint: serialize scannable: %w", err)
	}
	output, err := json.Marshal(signalFingerprintOutput{
		Display:      fp.DisplayString(),
		ScannableHex: hex.EncodeToString(scannable),
	})
	if err != nil {
		return nil, fmt.Errorf("signal fingerprint: encode output: %w", err)
	}
	return &sdk.TypedStepResult[*contracts.SignalFingerprintOutput]{
		Output: wrapperspb.String(string(output)),
	}, nil
}

func decodePublicKey(value string) (curve.PublicKey, error) {
	raw, err := hex.DecodeString(value)
	if err != nil {
		return curve.PublicKey{}, err
	}
	return curve.DeserializePublicKey(raw)
}
