package internal

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	pb "github.com/GoCodeAlone/workflow/plugin/external/proto"
	"github.com/GoCodeAlone/workflow/plugin/external/sdk"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
)

func TestSignalProviderDeclaresStrictPhaseOneContracts(t *testing.T) {
	provider := NewSignalProvider()
	moduleProvider, ok := any(provider).(sdk.TypedModuleProvider)
	if !ok {
		t.Fatal("expected typed module provider")
	}
	stepProvider, ok := any(provider).(sdk.TypedStepProvider)
	if !ok {
		t.Fatal("expected typed step provider")
	}
	contractProvider, ok := any(provider).(sdk.ContractProvider)
	if !ok {
		t.Fatal("expected contract provider")
	}

	assertStringSet(t, moduleProvider.TypedModuleTypes(), []string{
		"signal.identity_store",
		"signal.space",
		"signal.official_service_boundary",
		"signal.service_transport",
		"signal.live_policy",
		"signal.key_custody",
		"signal.persistent_custody",
		"signal.custody_store",
		"signal.account_ref",
		"trigger.signal_envelope",
		"trigger.signal_service_envelope",
	})
	assertStringSet(t, stepProvider.TypedStepTypes(), []string{
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
		"step.signal_service_register_prepare",
		"step.signal_service_link_prepare",
		"step.signal_service_send_prepare",
		"step.signal_service_receive_admit",
		"step.signal_service_challenge_respond",
		"step.signal_username_proof_prepare",
		"step.signal_backup_manifest_verify",
		"step.signal_backup_auth_prepare",
		"step.signal_service_test_register",
		"step.signal_service_test_link_device",
		"step.signal_service_test_send",
		"step.signal_service_test_receive",
		"step.signal_service_test_username_reserve",
		"step.signal_service_test_backup_upload",
		"step.signal_service_test_backup_download",
		"step.signal_custody_create",
		"step.signal_custody_rotate",
		"step.signal_custody_restore",
		"step.signal_custody_revoke",
		"step.signal_custody_inspect",
	})

	registry := contractProvider.ContractRegistry()
	if registry == nil {
		t.Fatal("expected contract registry")
	}
	if registry.FileDescriptorSet == nil || len(registry.FileDescriptorSet.File) == 0 {
		t.Fatal("expected descriptor set")
	}
	files, err := protodesc.NewFiles(registry.FileDescriptorSet)
	if err != nil {
		t.Fatalf("descriptor set: %v", err)
	}

	contractsByKey := map[string]*pb.ContractDescriptor{}
	for _, descriptor := range registry.Contracts {
		if descriptor.Mode != pb.ContractMode_CONTRACT_MODE_STRICT_PROTO {
			t.Fatalf("%s mode = %s, want strict proto", contractKey(descriptor), descriptor.Mode)
		}
		switch descriptor.Kind {
		case pb.ContractKind_CONTRACT_KIND_MODULE:
			contractsByKey["module:"+descriptor.ModuleType] = descriptor
		case pb.ContractKind_CONTRACT_KIND_STEP:
			contractsByKey["step:"+descriptor.StepType] = descriptor
		default:
			t.Fatalf("unexpected contract kind %s", descriptor.Kind)
		}
		for _, name := range []string{descriptor.ConfigMessage, descriptor.InputMessage, descriptor.OutputMessage} {
			if name == "" {
				continue
			}
			if _, err := files.FindDescriptorByName(protoreflect.FullName(name)); err != nil {
				t.Fatalf("%s references unknown message %s: %v", contractKey(descriptor), name, err)
			}
			if name == "google.protobuf.StringValue" {
				t.Fatalf("%s still uses wrapper JSON contract", contractKey(descriptor))
			}
		}
	}

	for _, key := range []string{
		"module:signal.identity_store",
		"module:signal.space",
		"module:signal.official_service_boundary",
		"module:signal.service_transport",
		"module:signal.live_policy",
		"module:signal.key_custody",
		"module:signal.persistent_custody",
		"module:signal.custody_store",
		"module:signal.account_ref",
		"module:trigger.signal_envelope",
		"module:trigger.signal_service_envelope",
		"step:step.signal_session_prepare",
		"step:step.signal_encrypt",
		"step:step.signal_decrypt",
		"step:step.signal_fingerprint",
		"step:step.signal_account_keys",
		"step:step.signal_username_link_create",
		"step:step.signal_username_link_decrypt",
		"step:step.signal_service_contract_check",
		"step:step.signal_service_compliance_check",
		"step:step.signal_service_policy_check",
		"step:step.signal_service_approval_validate",
		"step:step.signal_service_live_submit",
		"step:step.signal_service_register_prepare",
		"step:step.signal_service_link_prepare",
		"step:step.signal_service_send_prepare",
		"step:step.signal_service_receive_admit",
		"step:step.signal_service_challenge_respond",
		"step:step.signal_username_proof_prepare",
		"step:step.signal_backup_manifest_verify",
		"step:step.signal_backup_auth_prepare",
		"step:step.signal_service_test_register",
		"step:step.signal_service_test_link_device",
		"step:step.signal_service_test_send",
		"step:step.signal_service_test_receive",
		"step:step.signal_service_test_username_reserve",
		"step:step.signal_service_test_backup_upload",
		"step:step.signal_service_test_backup_download",
		"step:step.signal_custody_create",
		"step:step.signal_custody_rotate",
		"step:step.signal_custody_restore",
		"step:step.signal_custody_revoke",
		"step:step.signal_custody_inspect",
	} {
		if _, ok := contractsByKey[key]; !ok {
			t.Fatalf("missing contract %s", key)
		}
	}
}

func TestPluginJSONCapabilitiesMatchRuntimeProvider(t *testing.T) {
	provider := NewSignalProvider()
	var manifest struct {
		Capabilities struct {
			ModuleTypes  []string `json:"moduleTypes"`
			StepTypes    []string `json:"stepTypes"`
			TriggerTypes []string `json:"triggerTypes"`
		} `json:"capabilities"`
	}
	raw, err := os.ReadFile(filepath.Join("..", "plugin.json"))
	if err != nil {
		t.Fatalf("read plugin.json: %v", err)
	}
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatalf("decode plugin.json: %v", err)
	}
	assertStringSet(t, manifest.Capabilities.ModuleTypes, []string{
		"signal.identity_store",
		"signal.space",
		"signal.official_service_boundary",
		"signal.service_transport",
		"signal.live_policy",
		"signal.key_custody",
		"signal.persistent_custody",
		"signal.custody_store",
		"signal.account_ref",
	})
	assertStringSet(t, manifest.Capabilities.TriggerTypes, []string{
		"trigger.signal_envelope",
		"trigger.signal_service_envelope",
	})
	assertStringSet(t, manifest.Capabilities.StepTypes, provider.TypedStepTypes())
}

func TestProviderContractsDeclareCustodyV2(t *testing.T) {
	provider := NewSignalProvider()
	moduleProvider, ok := any(provider).(sdk.TypedModuleProvider)
	if !ok {
		t.Fatal("expected typed module provider")
	}
	stepProvider, ok := any(provider).(sdk.TypedStepProvider)
	if !ok {
		t.Fatal("expected typed step provider")
	}
	contractProvider, ok := any(provider).(sdk.ContractProvider)
	if !ok {
		t.Fatal("expected contract provider")
	}

	assertStringSetContains(t, moduleProvider.TypedModuleTypes(), []string{
		"signal.persistent_custody",
		"signal.custody_store",
	})
	assertStringSetContains(t, stepProvider.TypedStepTypes(), []string{
		"step.signal_custody_create",
		"step.signal_custody_rotate",
		"step.signal_custody_restore",
		"step.signal_custody_revoke",
		"step.signal_custody_inspect",
	})

	contractsByKey := map[string]*pb.ContractDescriptor{}
	for _, descriptor := range contractProvider.ContractRegistry().Contracts {
		switch descriptor.Kind {
		case pb.ContractKind_CONTRACT_KIND_MODULE:
			contractsByKey["module:"+descriptor.ModuleType] = descriptor
		case pb.ContractKind_CONTRACT_KIND_STEP:
			contractsByKey["step:"+descriptor.StepType] = descriptor
		}
	}
	for _, key := range []string{
		"module:signal.persistent_custody",
		"module:signal.custody_store",
		"step:step.signal_custody_create",
		"step:step.signal_custody_rotate",
		"step:step.signal_custody_restore",
		"step:step.signal_custody_revoke",
		"step:step.signal_custody_inspect",
	} {
		if _, ok := contractsByKey[key]; !ok {
			t.Fatalf("missing contract %s", key)
		}
	}
}

func TestProviderContractsDeclareServiceOperationContracts(t *testing.T) {
	provider := NewSignalProvider()
	moduleProvider, ok := any(provider).(sdk.TypedModuleProvider)
	if !ok {
		t.Fatal("expected typed module provider")
	}
	stepProvider, ok := any(provider).(sdk.TypedStepProvider)
	if !ok {
		t.Fatal("expected typed step provider")
	}
	contractProvider, ok := any(provider).(sdk.ContractProvider)
	if !ok {
		t.Fatal("expected contract provider")
	}

	assertStringSetContains(t, moduleProvider.TypedModuleTypes(), []string{
		"signal.live_policy",
		"signal.service_transport",
		"signal.persistent_custody",
	})
	assertStringSetContains(t, stepProvider.TypedStepTypes(), []string{
		"step.signal_service_register_prepare",
		"step.signal_service_link_prepare",
		"step.signal_service_send_prepare",
		"step.signal_service_receive_admit",
		"step.signal_service_challenge_respond",
		"step.signal_username_proof_prepare",
		"step.signal_backup_manifest_verify",
		"step.signal_backup_auth_prepare",
		"step.signal_service_approval_validate",
		"step.signal_service_live_submit",
	})

	contractsByKey := map[string]*pb.ContractDescriptor{}
	for _, descriptor := range contractProvider.ContractRegistry().Contracts {
		switch descriptor.Kind {
		case pb.ContractKind_CONTRACT_KIND_MODULE:
			contractsByKey["module:"+descriptor.ModuleType] = descriptor
		case pb.ContractKind_CONTRACT_KIND_STEP:
			contractsByKey["step:"+descriptor.StepType] = descriptor
		}
	}
	for _, key := range []string{
		"module:signal.live_policy",
		"step:step.signal_service_register_prepare",
		"step:step.signal_service_link_prepare",
		"step:step.signal_service_send_prepare",
		"step:step.signal_service_receive_admit",
		"step:step.signal_service_challenge_respond",
		"step:step.signal_username_proof_prepare",
		"step:step.signal_backup_manifest_verify",
		"step:step.signal_backup_auth_prepare",
		"step:step.signal_service_approval_validate",
		"step:step.signal_service_live_submit",
	} {
		if _, ok := contractsByKey[key]; !ok {
			t.Fatalf("missing contract %s", key)
		}
	}
}

func TestLibsignalServiceGoPinnedForOperationAdapters(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "go.mod"))
	if err != nil {
		t.Fatalf("read go.mod: %v", err)
	}
	if !strings.Contains(string(raw), "github.com/GoCodeAlone/libsignal-service-go v0.5.0") {
		t.Fatalf("go.mod does not pin libsignal-service-go v0.5.0:\n%s", raw)
	}
}

func contractKey(descriptor *pb.ContractDescriptor) string {
	switch descriptor.Kind {
	case pb.ContractKind_CONTRACT_KIND_MODULE:
		return "module:" + descriptor.ModuleType
	case pb.ContractKind_CONTRACT_KIND_STEP:
		return "step:" + descriptor.StepType
	default:
		return descriptor.Kind.String()
	}
}

func assertStringSet(t *testing.T, got, want []string) {
	t.Helper()
	seen := make(map[string]int, len(got))
	for _, value := range got {
		seen[value]++
	}
	for _, value := range want {
		if seen[value] != 1 {
			t.Fatalf("values = %v, want exactly one %q", got, value)
		}
	}
	if len(got) != len(want) {
		t.Fatalf("values = %v, want %v", got, want)
	}
}

func assertStringSetContains(t *testing.T, got, want []string) {
	t.Helper()
	seen := make(map[string]int, len(got))
	for _, value := range got {
		seen[value]++
	}
	for _, value := range want {
		if seen[value] != 1 {
			t.Fatalf("values = %v, want exactly one %q", got, value)
		}
	}
}
