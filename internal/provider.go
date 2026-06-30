package internal

import (
	"fmt"

	contracts "github.com/GoCodeAlone/workflow-plugin-signal/internal/contracts"
	pb "github.com/GoCodeAlone/workflow/plugin/external/proto"
	"github.com/GoCodeAlone/workflow/plugin/external/sdk"
	"google.golang.org/protobuf/types/known/anypb"
)

// Version is injected by the release build so runtime manifests report the tag.
var Version = "dev"

// SignalProvider implements sdk.PluginProvider, sdk.TypedStepProvider, and sdk.ContractProvider.
type SignalProvider struct{}

// NewSignalProvider creates a new SignalProvider.
func NewSignalProvider() *SignalProvider {
	return &SignalProvider{}
}

// Manifest implements sdk.PluginProvider.
func (p *SignalProvider) Manifest() sdk.PluginManifest {
	return sdk.PluginManifest{
		Name:        "workflow-plugin-signal",
		Version:     sdk.ResolveBuildVersion(Version),
		Author:      "GoCodeAlone",
		Description: "Signal protocol primitives for Workflow",
	}
}

// TypedStepTypes implements sdk.TypedStepProvider.
func (p *SignalProvider) TypedStepTypes() []string {
	return []string{"step.signal_fingerprint"}
}

// CreateTypedStep implements sdk.TypedStepProvider.
func (p *SignalProvider) CreateTypedStep(typeName, name string, config *anypb.Any) (sdk.StepInstance, error) {
	switch typeName {
	case "step.signal_fingerprint":
		factory := sdk.NewTypedStepFactory(
			"step.signal_fingerprint",
			&contracts.SignalFingerprintConfig{},
			&contracts.SignalFingerprintInput{},
			ExecuteSignalFingerprint,
		)
		return factory.CreateTypedStep(typeName, name, config)
	}
	return nil, fmt.Errorf("%w: step type %q", sdk.ErrTypedContractNotHandled, typeName)
}

// ContractRegistry implements sdk.ContractProvider.
func (p *SignalProvider) ContractRegistry() *pb.ContractRegistry {
	return &pb.ContractRegistry{Contracts: []*pb.ContractDescriptor{
		{
			Kind:          pb.ContractKind_CONTRACT_KIND_STEP,
			StepType:      "step.signal_fingerprint",
			ConfigMessage: "google.protobuf.StringValue",
			InputMessage:  "google.protobuf.StringValue",
			OutputMessage: "google.protobuf.StringValue",
			Mode:          pb.ContractMode_CONTRACT_MODE_STRICT_PROTO,
		},
	}}
}
