package internal

import (
	"fmt"

	contracts "github.com/GoCodeAlone/workflow-plugin-signal/internal/contracts"
	pb "github.com/GoCodeAlone/workflow/plugin/external/proto"
	"github.com/GoCodeAlone/workflow/plugin/external/sdk"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/known/anypb"
)

// Version is injected by the release build so runtime manifests report the tag.
var Version = "dev"

// SignalProvider implements sdk.PluginProvider, sdk.TypedModuleProvider,
// sdk.TypedStepProvider, and sdk.ContractProvider.
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

var signalModuleTypes = []string{
	"signal.identity_store",
	"signal.space",
	"trigger.signal_envelope",
}

var signalStepTypes = []string{
	"step.signal_session_prepare",
	"step.signal_encrypt",
	"step.signal_decrypt",
	"step.signal_fingerprint",
	"step.signal_account_keys",
	"step.signal_username_link_create",
	"step.signal_username_link_decrypt",
}

// TypedModuleTypes implements sdk.TypedModuleProvider.
func (p *SignalProvider) TypedModuleTypes() []string {
	return append([]string(nil), signalModuleTypes...)
}

// CreateTypedModule implements sdk.TypedModuleProvider.
func (p *SignalProvider) CreateTypedModule(typeName, name string, config *anypb.Any) (sdk.ModuleInstance, error) {
	switch typeName {
	case "signal.identity_store":
		factory := sdk.NewTypedModuleFactory(typeName, &contracts.IdentityStoreConfig{}, func(name string, cfg *contracts.IdentityStoreConfig) (sdk.ModuleInstance, error) {
			return newIdentityStoreModule(name, cfg), nil
		})
		return factory.CreateTypedModule(typeName, name, config)
	case "signal.space":
		factory := sdk.NewTypedModuleFactory(typeName, &contracts.SpaceConfig{}, func(name string, cfg *contracts.SpaceConfig) (sdk.ModuleInstance, error) {
			return newSpaceModule(name, cfg), nil
		})
		return factory.CreateTypedModule(typeName, name, config)
	case "trigger.signal_envelope":
		factory := sdk.NewTypedModuleFactory(typeName, &contracts.EnvelopeTriggerConfig{}, func(name string, cfg *contracts.EnvelopeTriggerConfig) (sdk.ModuleInstance, error) {
			return newEnvelopeTriggerModule(name, cfg), nil
		})
		return factory.CreateTypedModule(typeName, name, config)
	}
	return nil, fmt.Errorf("%w: module type %q", sdk.ErrTypedContractNotHandled, typeName)
}

// TypedStepTypes implements sdk.TypedStepProvider.
func (p *SignalProvider) TypedStepTypes() []string {
	return append([]string(nil), signalStepTypes...)
}

// CreateTypedStep implements sdk.TypedStepProvider.
func (p *SignalProvider) CreateTypedStep(typeName, name string, config *anypb.Any) (sdk.StepInstance, error) {
	switch typeName {
	case "step.signal_session_prepare":
		factory := sdk.NewTypedStepFactory(
			typeName,
			&contracts.SessionPrepareConfig{},
			&contracts.SessionPrepareInput{},
			ExecuteSignalSessionPrepare,
		)
		return factory.CreateTypedStep(typeName, name, config)
	case "step.signal_encrypt":
		factory := sdk.NewTypedStepFactory(
			typeName,
			&contracts.SignalEncryptConfig{},
			&contracts.SignalEncryptInput{},
			ExecuteSignalEncrypt,
		)
		return factory.CreateTypedStep(typeName, name, config)
	case "step.signal_decrypt":
		factory := sdk.NewTypedStepFactory(
			typeName,
			&contracts.SignalDecryptConfig{},
			&contracts.SignalDecryptInput{},
			ExecuteSignalDecrypt,
		)
		return factory.CreateTypedStep(typeName, name, config)
	case "step.signal_fingerprint":
		factory := sdk.NewTypedStepFactory(
			typeName,
			&contracts.SignalFingerprintConfig{},
			&contracts.SignalFingerprintInput{},
			ExecuteSignalFingerprint,
		)
		return factory.CreateTypedStep(typeName, name, config)
	case "step.signal_account_keys":
		factory := sdk.NewTypedStepFactory(
			typeName,
			&contracts.AccountKeysConfig{},
			&contracts.AccountKeysInput{},
			ExecuteSignalAccountKeys,
		)
		return factory.CreateTypedStep(typeName, name, config)
	case "step.signal_username_link_create":
		factory := sdk.NewTypedStepFactory(
			typeName,
			&contracts.UsernameLinkCreateConfig{},
			&contracts.UsernameLinkCreateInput{},
			ExecuteSignalUsernameLinkCreate,
		)
		return factory.CreateTypedStep(typeName, name, config)
	case "step.signal_username_link_decrypt":
		factory := sdk.NewTypedStepFactory(
			typeName,
			&contracts.UsernameLinkDecryptConfig{},
			&contracts.UsernameLinkDecryptInput{},
			ExecuteSignalUsernameLinkDecrypt,
		)
		return factory.CreateTypedStep(typeName, name, config)
	}
	return nil, fmt.Errorf("%w: step type %q", sdk.ErrTypedContractNotHandled, typeName)
}

// ContractRegistry implements sdk.ContractProvider.
func (p *SignalProvider) ContractRegistry() *pb.ContractRegistry {
	const pkg = "workflow.plugins.signal.v1."
	return &pb.ContractRegistry{
		FileDescriptorSet: &descriptorpb.FileDescriptorSet{
			File: []*descriptorpb.FileDescriptorProto{
				protodesc.ToFileDescriptorProto(contracts.File_proto_signal_proto),
			},
		},
		Contracts: []*pb.ContractDescriptor{
			moduleContract("signal.identity_store", pkg+"IdentityStoreConfig"),
			moduleContract("signal.space", pkg+"SpaceConfig"),
			moduleContract("trigger.signal_envelope", pkg+"EnvelopeTriggerConfig"),
			stepContract("step.signal_session_prepare", pkg+"SessionPrepareConfig", pkg+"SessionPrepareInput", pkg+"SessionPrepareOutput"),
			stepContract("step.signal_encrypt", pkg+"SignalEncryptConfig", pkg+"SignalEncryptInput", pkg+"SignalEncryptOutput"),
			stepContract("step.signal_decrypt", pkg+"SignalDecryptConfig", pkg+"SignalDecryptInput", pkg+"SignalDecryptOutput"),
			stepContract("step.signal_fingerprint", pkg+"SignalFingerprintConfig", pkg+"SignalFingerprintInput", pkg+"SignalFingerprintOutput"),
			stepContract("step.signal_account_keys", pkg+"AccountKeysConfig", pkg+"AccountKeysInput", pkg+"AccountKeysOutput"),
			stepContract("step.signal_username_link_create", pkg+"UsernameLinkCreateConfig", pkg+"UsernameLinkCreateInput", pkg+"UsernameLinkCreateOutput"),
			stepContract("step.signal_username_link_decrypt", pkg+"UsernameLinkDecryptConfig", pkg+"UsernameLinkDecryptInput", pkg+"UsernameLinkDecryptOutput"),
		},
	}
}

func moduleContract(moduleType, configMessage string) *pb.ContractDescriptor {
	return &pb.ContractDescriptor{
		Kind:          pb.ContractKind_CONTRACT_KIND_MODULE,
		ModuleType:    moduleType,
		ConfigMessage: configMessage,
		Mode:          pb.ContractMode_CONTRACT_MODE_STRICT_PROTO,
	}
}

func stepContract(stepType, configMessage, inputMessage, outputMessage string) *pb.ContractDescriptor {
	return &pb.ContractDescriptor{
		Kind:          pb.ContractKind_CONTRACT_KIND_STEP,
		StepType:      stepType,
		ConfigMessage: configMessage,
		InputMessage:  inputMessage,
		OutputMessage: outputMessage,
		Mode:          pb.ContractMode_CONTRACT_MODE_STRICT_PROTO,
	}
}
