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
	"signal.official_service_boundary",
	"signal.service_transport",
	"signal.key_custody",
	"signal.persistent_custody",
	"signal.custody_store",
	"signal.account_ref",
	"trigger.signal_envelope",
	"trigger.signal_service_envelope",
}

var signalStepTypes = []string{
	"step.signal_session_prepare",
	"step.signal_encrypt",
	"step.signal_decrypt",
	"step.signal_fingerprint",
	"step.signal_account_keys",
	"step.signal_username_link_create",
	"step.signal_username_link_decrypt",
	"step.signal_service_contract_check",
	"step.signal_service_compliance_check",
	"step.signal_service_policy_check",
	"step.signal_service_approval_validate",
	"step.signal_service_live_submit",
	"step.signal_service_test_register",
	"step.signal_service_test_link_device",
	"step.signal_service_test_send",
	"step.signal_service_test_receive",
	"step.signal_custody_create",
	"step.signal_custody_rotate",
	"step.signal_custody_restore",
	"step.signal_custody_revoke",
	"step.signal_custody_inspect",
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
	case "signal.official_service_boundary":
		factory := sdk.NewTypedModuleFactory(typeName, &contracts.OfficialServiceBoundaryConfig{}, func(name string, cfg *contracts.OfficialServiceBoundaryConfig) (sdk.ModuleInstance, error) {
			return newOfficialServiceBoundaryModule(name, cfg)
		})
		return factory.CreateTypedModule(typeName, name, config)
	case "signal.service_transport":
		factory := sdk.NewTypedModuleFactory(typeName, &contracts.ServiceTransportConfig{}, func(name string, cfg *contracts.ServiceTransportConfig) (sdk.ModuleInstance, error) {
			return newServiceTransportModule(name, cfg)
		})
		return factory.CreateTypedModule(typeName, name, config)
	case "signal.key_custody":
		factory := sdk.NewTypedModuleFactory(typeName, &contracts.KeyCustodyConfig{}, func(name string, cfg *contracts.KeyCustodyConfig) (sdk.ModuleInstance, error) {
			return newKeyCustodyModule(name, cfg)
		})
		return factory.CreateTypedModule(typeName, name, config)
	case "signal.persistent_custody":
		factory := sdk.NewTypedModuleFactory(typeName, &contracts.PersistentCustodyConfig{}, func(name string, cfg *contracts.PersistentCustodyConfig) (sdk.ModuleInstance, error) {
			return newPersistentCustodyModule(name, cfg)
		})
		return factory.CreateTypedModule(typeName, name, config)
	case "signal.custody_store":
		factory := sdk.NewTypedModuleFactory(typeName, &contracts.CustodyStoreConfig{}, func(name string, cfg *contracts.CustodyStoreConfig) (sdk.ModuleInstance, error) {
			return newCustodyStoreModule(name, cfg), nil
		})
		return factory.CreateTypedModule(typeName, name, config)
	case "signal.account_ref":
		factory := sdk.NewTypedModuleFactory(typeName, &contracts.AccountRefConfig{}, func(name string, cfg *contracts.AccountRefConfig) (sdk.ModuleInstance, error) {
			return newAccountRefModule(name, cfg)
		})
		return factory.CreateTypedModule(typeName, name, config)
	case "trigger.signal_envelope":
		factory := sdk.NewTypedModuleFactory(typeName, &contracts.EnvelopeTriggerConfig{}, func(name string, cfg *contracts.EnvelopeTriggerConfig) (sdk.ModuleInstance, error) {
			return newEnvelopeTriggerModule(name, cfg), nil
		})
		return factory.CreateTypedModule(typeName, name, config)
	case "trigger.signal_service_envelope":
		factory := sdk.NewTypedModuleFactory(typeName, &contracts.ServiceEnvelopeTriggerConfig{}, func(name string, cfg *contracts.ServiceEnvelopeTriggerConfig) (sdk.ModuleInstance, error) {
			return newServiceEnvelopeTriggerModule(name, cfg), nil
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
	case "step.signal_service_contract_check":
		factory := sdk.NewTypedStepFactory(
			typeName,
			&contracts.ServiceContractCheckConfig{},
			&contracts.ServiceContractCheckInput{},
			ExecuteSignalServiceContractCheck,
		)
		return factory.CreateTypedStep(typeName, name, config)
	case "step.signal_service_compliance_check":
		factory := sdk.NewTypedStepFactory(
			typeName,
			&contracts.ServiceComplianceCheckConfig{},
			&contracts.ServiceComplianceCheckInput{},
			ExecuteSignalServiceComplianceCheck,
		)
		return factory.CreateTypedStep(typeName, name, config)
	case "step.signal_service_policy_check":
		factory := sdk.NewTypedStepFactory(
			typeName,
			&contracts.ServicePolicyCheckConfig{},
			&contracts.ServicePolicyCheckInput{},
			ExecuteSignalServicePolicyCheck,
		)
		return factory.CreateTypedStep(typeName, name, config)
	case "step.signal_service_approval_validate":
		factory := sdk.NewTypedStepFactory(
			typeName,
			&contracts.ServiceApprovalValidateConfig{},
			&contracts.ServiceApprovalValidateInput{},
			ExecuteSignalServiceApprovalValidate,
		)
		return factory.CreateTypedStep(typeName, name, config)
	case "step.signal_service_live_submit":
		factory := sdk.NewTypedStepFactory(
			typeName,
			&contracts.ServiceLiveSubmitConfig{},
			&contracts.ServiceLiveSubmitInput{},
			ExecuteSignalServiceLiveSubmit,
		)
		return factory.CreateTypedStep(typeName, name, config)
	case "step.signal_service_test_register":
		factory := sdk.NewTypedStepFactory(
			typeName,
			&contracts.ServiceTestRegisterConfig{},
			&contracts.ServiceTestRegisterInput{},
			ExecuteSignalServiceTestRegister,
		)
		return factory.CreateTypedStep(typeName, name, config)
	case "step.signal_service_test_link_device":
		factory := sdk.NewTypedStepFactory(
			typeName,
			&contracts.ServiceTestLinkDeviceConfig{},
			&contracts.ServiceTestLinkDeviceInput{},
			ExecuteSignalServiceTestLinkDevice,
		)
		return factory.CreateTypedStep(typeName, name, config)
	case "step.signal_service_test_send":
		factory := sdk.NewTypedStepFactory(
			typeName,
			&contracts.ServiceTestSendConfig{},
			&contracts.ServiceTestSendInput{},
			ExecuteSignalServiceTestSend,
		)
		return factory.CreateTypedStep(typeName, name, config)
	case "step.signal_service_test_receive":
		factory := sdk.NewTypedStepFactory(
			typeName,
			&contracts.ServiceTestReceiveConfig{},
			&contracts.ServiceTestReceiveInput{},
			ExecuteSignalServiceTestReceive,
		)
		return factory.CreateTypedStep(typeName, name, config)
	case "step.signal_custody_create":
		factory := sdk.NewTypedStepFactory(
			typeName,
			&contracts.CustodyCreateConfig{},
			&contracts.CustodyCreateInput{},
			ExecuteSignalCustodyCreate,
		)
		return factory.CreateTypedStep(typeName, name, config)
	case "step.signal_custody_rotate":
		factory := sdk.NewTypedStepFactory(
			typeName,
			&contracts.CustodyRotateConfig{},
			&contracts.CustodyRotateInput{},
			ExecuteSignalCustodyRotate,
		)
		return factory.CreateTypedStep(typeName, name, config)
	case "step.signal_custody_restore":
		factory := sdk.NewTypedStepFactory(
			typeName,
			&contracts.CustodyRestoreConfig{},
			&contracts.CustodyRestoreInput{},
			ExecuteSignalCustodyRestore,
		)
		return factory.CreateTypedStep(typeName, name, config)
	case "step.signal_custody_revoke":
		factory := sdk.NewTypedStepFactory(
			typeName,
			&contracts.CustodyRevokeConfig{},
			&contracts.CustodyRevokeInput{},
			ExecuteSignalCustodyRevoke,
		)
		return factory.CreateTypedStep(typeName, name, config)
	case "step.signal_custody_inspect":
		factory := sdk.NewTypedStepFactory(
			typeName,
			&contracts.CustodyInspectConfig{},
			&contracts.CustodyInspectInput{},
			ExecuteSignalCustodyInspect,
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
				protodesc.ToFileDescriptorProto(contracts.File_internal_contracts_signal_proto),
			},
		},
		Contracts: []*pb.ContractDescriptor{
			moduleContract("signal.identity_store", pkg+"IdentityStoreConfig"),
			moduleContract("signal.space", pkg+"SpaceConfig"),
			moduleContract("signal.official_service_boundary", pkg+"OfficialServiceBoundaryConfig"),
			moduleContract("signal.service_transport", pkg+"ServiceTransportConfig"),
			moduleContract("signal.key_custody", pkg+"KeyCustodyConfig"),
			moduleContract("signal.persistent_custody", pkg+"PersistentCustodyConfig"),
			moduleContract("signal.custody_store", pkg+"CustodyStoreConfig"),
			moduleContract("signal.account_ref", pkg+"AccountRefConfig"),
			moduleContract("trigger.signal_envelope", pkg+"EnvelopeTriggerConfig"),
			moduleContract("trigger.signal_service_envelope", pkg+"ServiceEnvelopeTriggerConfig"),
			stepContract("step.signal_session_prepare", pkg+"SessionPrepareConfig", pkg+"SessionPrepareInput", pkg+"SessionPrepareOutput"),
			stepContract("step.signal_encrypt", pkg+"SignalEncryptConfig", pkg+"SignalEncryptInput", pkg+"SignalEncryptOutput"),
			stepContract("step.signal_decrypt", pkg+"SignalDecryptConfig", pkg+"SignalDecryptInput", pkg+"SignalDecryptOutput"),
			stepContract("step.signal_fingerprint", pkg+"SignalFingerprintConfig", pkg+"SignalFingerprintInput", pkg+"SignalFingerprintOutput"),
			stepContract("step.signal_account_keys", pkg+"AccountKeysConfig", pkg+"AccountKeysInput", pkg+"AccountKeysOutput"),
			stepContract("step.signal_username_link_create", pkg+"UsernameLinkCreateConfig", pkg+"UsernameLinkCreateInput", pkg+"UsernameLinkCreateOutput"),
			stepContract("step.signal_username_link_decrypt", pkg+"UsernameLinkDecryptConfig", pkg+"UsernameLinkDecryptInput", pkg+"UsernameLinkDecryptOutput"),
			stepContract("step.signal_service_contract_check", pkg+"ServiceContractCheckConfig", pkg+"ServiceContractCheckInput", pkg+"ServiceContractCheckOutput"),
			stepContract("step.signal_service_compliance_check", pkg+"ServiceComplianceCheckConfig", pkg+"ServiceComplianceCheckInput", pkg+"ServiceComplianceCheckOutput"),
			stepContract("step.signal_service_policy_check", pkg+"ServicePolicyCheckConfig", pkg+"ServicePolicyCheckInput", pkg+"ServicePolicyCheckOutput"),
			stepContract("step.signal_service_approval_validate", pkg+"ServiceApprovalValidateConfig", pkg+"ServiceApprovalValidateInput", pkg+"ServiceApprovalValidateOutput"),
			stepContract("step.signal_service_live_submit", pkg+"ServiceLiveSubmitConfig", pkg+"ServiceLiveSubmitInput", pkg+"ServiceSubmitOutput"),
			stepContract("step.signal_service_test_register", pkg+"ServiceTestRegisterConfig", pkg+"ServiceTestRegisterInput", pkg+"ServiceTestOutput"),
			stepContract("step.signal_service_test_link_device", pkg+"ServiceTestLinkDeviceConfig", pkg+"ServiceTestLinkDeviceInput", pkg+"ServiceTestOutput"),
			stepContract("step.signal_service_test_send", pkg+"ServiceTestSendConfig", pkg+"ServiceTestSendInput", pkg+"ServiceTestOutput"),
			stepContract("step.signal_service_test_receive", pkg+"ServiceTestReceiveConfig", pkg+"ServiceTestReceiveInput", pkg+"ServiceTestOutput"),
			stepContract("step.signal_custody_create", pkg+"CustodyCreateConfig", pkg+"CustodyCreateInput", pkg+"CustodyCreateOutput"),
			stepContract("step.signal_custody_rotate", pkg+"CustodyRotateConfig", pkg+"CustodyRotateInput", pkg+"CustodyRotateOutput"),
			stepContract("step.signal_custody_restore", pkg+"CustodyRestoreConfig", pkg+"CustodyRestoreInput", pkg+"CustodyRestoreOutput"),
			stepContract("step.signal_custody_revoke", pkg+"CustodyRevokeConfig", pkg+"CustodyRevokeInput", pkg+"CustodyRevokeOutput"),
			stepContract("step.signal_custody_inspect", pkg+"CustodyInspectConfig", pkg+"CustodyInspectInput", pkg+"CustodyInspectOutput"),
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
