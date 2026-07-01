package internal

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/GoCodeAlone/libsignal-service-go/fake"
	"github.com/GoCodeAlone/libsignal-service-go/serviceclient"
	"github.com/GoCodeAlone/libsignal-service-go/servicepolicy"
	"github.com/GoCodeAlone/workflow/plugin/external/sdk"

	contracts "github.com/GoCodeAlone/workflow-plugin-signal/internal/contracts"
)

var (
	signalServiceTransportsMu sync.Mutex
	signalServiceTransports   = map[string]*signalServiceTransport{}
)

type serviceTransportModule struct {
	lifecycleModule
	name   string
	config *contracts.ServiceTransportConfig
}

type signalServiceTransport struct {
	ref       string
	mode      serviceclient.TransportMode
	endpoint  string
	approval  servicepolicy.ApprovalPackage
	actions   []servicepolicy.Action
	ledger    map[string]fake.LedgerRecord
	records   []fake.ServiceClientRecord
	testOnly  bool
	createdAt time.Time
}

func newServiceTransportModule(name string, cfg *contracts.ServiceTransportConfig) (*serviceTransportModule, error) {
	if cfg == nil {
		cfg = &contracts.ServiceTransportConfig{}
	}
	if cfg.GetTransportRef() == "" {
		return nil, fmt.Errorf("signal service transport: transport_ref is required")
	}
	transportCfg := serviceTransportConfig(cfg.GetMode(), cfg.GetSandboxEndpoint(), cfg.GetApproval(), cfg.GetRequestedActions())
	if _, err := serviceclient.NewTransport(fake.NewServiceClient(), transportCfg); err != nil {
		return nil, err
	}
	return &serviceTransportModule{name: name, config: cfg}, nil
}

func (m *serviceTransportModule) Init() error {
	mode := serviceclient.TransportMode(m.config.GetMode())
	if mode == "" {
		mode = serviceclient.TransportModeFake
	}
	transport := &signalServiceTransport{
		ref:       m.config.GetTransportRef(),
		mode:      mode,
		endpoint:  m.config.GetSandboxEndpoint(),
		approval:  approvalPackageFromContract(m.config.GetApproval()),
		actions:   serviceComplianceActions(m.config.GetRequestedActions(), nil),
		ledger:    map[string]fake.LedgerRecord{},
		testOnly:  mode == serviceclient.TransportModeFake || mode == serviceclient.TransportModeSandbox,
		createdAt: time.Now().UTC(),
	}
	signalServiceTransportsMu.Lock()
	signalServiceTransports[transport.ref] = transport
	signalServiceTransportsMu.Unlock()
	return nil
}

func ExecuteSignalServiceApprovalValidate(
	_ context.Context,
	req sdk.TypedStepRequest[*contracts.ServiceApprovalValidateConfig, *contracts.ServiceApprovalValidateInput],
) (*sdk.TypedStepResult[*contracts.ServiceApprovalValidateOutput], error) {
	mode := firstNonEmpty(req.Input.GetMode(), req.Config.GetMode())
	if mode == "" {
		mode = string(servicepolicy.ModeLive)
	}
	actions := serviceComplianceActions(req.Input.GetRequestedActions(), req.Config.GetRequestedActions())
	approval := req.Config.GetApproval()
	if req.Input.GetApproval() != nil {
		approval = req.Input.GetApproval()
	}
	report := servicepolicy.ValidateApprovalPackage(approvalPackageFromContract(approval), time.Now().UTC(), actions)
	liveAllowed := mode == string(servicepolicy.ModeLive) && report.LiveAllowed
	return &sdk.TypedStepResult[*contracts.ServiceApprovalValidateOutput]{
		Output: &contracts.ServiceApprovalValidateOutput{
			Mode:                 mode,
			LiveTransportAllowed: liveAllowed,
			LiveServiceDisabled:  true,
			DeniedReasons:        append([]string(nil), report.DeniedReasons...),
			RequestedActions:     servicePolicyActionsToStrings(actions),
		},
	}, nil
}

func ExecuteSignalServiceLiveSubmit(
	ctx context.Context,
	req sdk.TypedStepRequest[*contracts.ServiceLiveSubmitConfig, *contracts.ServiceLiveSubmitInput],
) (*sdk.TypedStepResult[*contracts.ServiceSubmitOutput], error) {
	transport, transportCfg, transportRef, err := resolveSubmitTransport(req.Config, req.Input)
	if err != nil {
		if errors.Is(err, servicepolicy.ErrLiveServiceDisabled) {
			return deniedSubmitResult(req.Config, req.Input, err), nil
		}
		return nil, fmt.Errorf("signal service submit: %w", err)
	}
	account, meta, opts, err := serviceTestRequestContext(req.Config.GetAccountRef(), req.Config.GetExpiredCredentials(), req.Input)
	if err != nil {
		return nil, fmt.Errorf("signal service submit: %w", err)
	}
	operation := req.Input.GetOperation()
	if operation == "" {
		return nil, fmt.Errorf("signal service submit: operation is required")
	}
	if req.Input.GetExpiredCredentials() {
		opts = append(opts, fake.WithExpiredCredentials())
	}
	if challengeRef := req.Input.GetChallengeRef(); challengeRef != "" {
		opts = append(opts, fake.WithChallenge(operation, challengeRef))
	}

	ledger, update := transportLedger(transport)
	client := serviceTestClientWithLedger(ledger, opts...)
	serviceTransport, err := serviceclient.NewTransport(client, transportCfg)
	if err != nil {
		if errors.Is(err, servicepolicy.ErrLiveServiceDisabled) {
			return deniedSubmitResult(req.Config, req.Input, err), nil
		}
		return nil, fmt.Errorf("signal service submit: %w", err)
	}
	response, err := executeServiceOperation(ctx, serviceTransport, operation, meta, req.Input)
	if err != nil {
		return nil, fmt.Errorf("signal service submit: %w", err)
	}
	update(client)
	return serviceSubmitResult(transportRef, string(serviceTransport.Mode()), operation, account, meta, response.Common()), nil
}

func resolveSubmitTransport(cfg *contracts.ServiceLiveSubmitConfig, in *contracts.ServiceLiveSubmitInput) (*signalServiceTransport, serviceclient.TransportConfig, string, error) {
	transportRef := firstNonEmpty(in.GetTransportRef(), cfg.GetTransportRef())
	if transportRef != "" {
		transport, err := lookupServiceTransport(transportRef)
		if err != nil {
			return nil, serviceclient.TransportConfig{}, transportRef, err
		}
		return transport, serviceclient.TransportConfig{
			Mode:             transport.mode,
			SandboxEndpoint:  transport.endpoint,
			ApprovalPackage:  transport.approval,
			ApprovalTime:     time.Now().UTC(),
			RequestedActions: transport.actions,
		}, transport.ref, nil
	}
	mode := firstNonEmpty(in.GetMode(), cfg.GetMode())
	if mode == "" {
		mode = string(serviceclient.TransportModeFake)
	}
	approval := cfg.GetApproval()
	if in.GetApproval() != nil {
		approval = in.GetApproval()
	}
	actions := operationActions(in.GetOperation())
	return nil, serviceTransportConfig(mode, firstNonEmpty(in.GetSandboxEndpoint(), cfg.GetSandboxEndpoint()), approval, servicePolicyActionsToStrings(actions)), "", nil
}

func lookupServiceTransport(ref string) (*signalServiceTransport, error) {
	signalServiceTransportsMu.Lock()
	defer signalServiceTransportsMu.Unlock()
	transport := signalServiceTransports[ref]
	if transport == nil {
		return nil, fmt.Errorf("signal service transport: %q is not registered", ref)
	}
	return transport, nil
}

func transportLedger(transport *signalServiceTransport) (map[string]fake.LedgerRecord, func(*fake.ServiceClient)) {
	if transport == nil {
		return cloneServiceTestLedger(nil), func(client *fake.ServiceClient) {
			signalServiceTestLedgerMu.Lock()
			signalServiceTestLedger = cloneServiceTestLedger(client.Ledger())
			signalServiceTestLedgerMu.Unlock()
		}
	}
	signalServiceTransportsMu.Lock()
	ledger := cloneServiceTestLedger(transport.ledger)
	signalServiceTransportsMu.Unlock()
	return ledger, func(client *fake.ServiceClient) {
		signalServiceTransportsMu.Lock()
		transport.ledger = cloneServiceTestLedger(client.Ledger())
		transport.records = append(transport.records, client.Records()...)
		signalServiceTransportsMu.Unlock()
	}
}

func serviceTestClientWithLedger(ledger map[string]fake.LedgerRecord, opts ...fake.ServiceClientOption) *fake.ServiceClient {
	allOpts := []fake.ServiceClientOption{fake.WithLedger(ledger)}
	allOpts = append(allOpts, opts...)
	return fake.NewServiceClient(allOpts...)
}

type commonServiceResponse interface {
	Common() serviceclient.ResponseMetadata
}

func executeServiceOperation(ctx context.Context, transport *serviceclient.Transport, operation string, meta serviceclient.RequestMetadata, in *contracts.ServiceLiveSubmitInput) (commonServiceResponse, error) {
	switch servicepolicy.Action(operation) {
	case servicepolicy.ActionRegister:
		return transport.Register(ctx, serviceclient.RegisterRequest{Metadata: meta, Username: in.GetUsername()})
	case servicepolicy.ActionLinkedDevice:
		return transport.LinkDevice(ctx, serviceclient.LinkDeviceRequest{Metadata: meta, LinkCodeRef: in.GetLinkCodeRef()})
	case servicepolicy.ActionSend:
		return transport.Send(ctx, serviceclient.SendRequest{Metadata: meta, RecipientRef: in.GetRecipientRef(), PayloadRef: in.GetPayloadRef()})
	case servicepolicy.ActionReceive:
		return transport.Receive(ctx, serviceclient.ReceiveRequest{Metadata: meta, CursorRef: in.GetCursorRef()})
	case servicepolicy.ActionUsernameReserve:
		return transport.ReserveUsername(ctx, serviceclient.ReserveUsernameRequest{Metadata: meta, Username: in.GetUsername()})
	case servicepolicy.ActionBackupUpload:
		return transport.UploadBackup(ctx, serviceclient.UploadBackupRequest{Metadata: meta, BackupRef: in.GetBackupRef()})
	case servicepolicy.ActionBackupDownload:
		return transport.DownloadBackup(ctx, serviceclient.DownloadBackupRequest{Metadata: meta, BackupID: in.GetBackupId()})
	case servicepolicy.Action("challenge_response"):
		return transport.RespondToChallenge(ctx, serviceclient.RespondToChallengeRequest{Metadata: meta, ChallengeRef: in.GetChallengeRef(), ResponseRef: in.GetChallengeResponseRef()})
	default:
		return nil, fmt.Errorf("unsupported operation %q", operation)
	}
}

func serviceSubmitResult(transportRef, mode, operation string, account *signalAccountRef, reqMeta serviceclient.RequestMetadata, meta serviceclient.ResponseMetadata) *sdk.TypedStepResult[*contracts.ServiceSubmitOutput] {
	secretRefs := map[string]string{}
	for key, value := range meta.SecretRefs {
		secretRefs[key] = safeSignalRef(value)
	}
	return &sdk.TypedStepResult[*contracts.ServiceSubmitOutput]{
		Output: &contracts.ServiceSubmitOutput{
			TransportRef:        transportRef,
			TransportMode:       mode,
			Operation:           operation,
			AccountRef:          safeSignalRef(account.ref),
			DeviceRef:           safeSignalRef(reqMeta.DeviceRef),
			RequestId:           meta.RequestID,
			Status:              meta.Status,
			ChallengeRef:        safeSignalRef(meta.ChallengeRef),
			SecretRefs:          secretRefs,
			CredentialRef:       safeSignalRef(secretRefs["credential"]),
			AuditRef:            safeSignalRef(reqMeta.AuditRef),
			LiveEgressAttempted: false,
		},
	}
}

func deniedSubmitResult(cfg *contracts.ServiceLiveSubmitConfig, in *contracts.ServiceLiveSubmitInput, err error) *sdk.TypedStepResult[*contracts.ServiceSubmitOutput] {
	approval := cfg.GetApproval()
	if in.GetApproval() != nil {
		approval = in.GetApproval()
	}
	reasons := servicepolicy.ValidateApprovalPackage(approvalPackageFromContract(approval), time.Now().UTC(), operationActions(in.GetOperation())).DeniedReasons
	if len(reasons) == 0 && err != nil {
		reasons = []string{err.Error()}
	}
	return &sdk.TypedStepResult[*contracts.ServiceSubmitOutput]{
		Output: &contracts.ServiceSubmitOutput{
			TransportRef:        firstNonEmpty(in.GetTransportRef(), cfg.GetTransportRef()),
			TransportMode:       firstNonEmpty(in.GetMode(), cfg.GetMode()),
			Operation:           in.GetOperation(),
			AccountRef:          safeSignalRef(firstNonEmpty(in.GetAccountRef(), cfg.GetAccountRef())),
			Status:              "denied",
			LiveEgressAttempted: false,
			DeniedReasons:       reasons,
		},
	}
}

func serviceTransportConfig(mode, endpoint string, approval *contracts.ApprovalPackage, requested []string) serviceclient.TransportConfig {
	transportMode := serviceclient.TransportMode(mode)
	if transportMode == "" {
		transportMode = serviceclient.TransportModeFake
	}
	return serviceclient.TransportConfig{
		Mode:             transportMode,
		SandboxEndpoint:  endpoint,
		ApprovalPackage:  approvalPackageFromContract(approval),
		ApprovalTime:     time.Now().UTC(),
		RequestedActions: serviceComplianceActions(requested, nil),
	}
}

func approvalPackageFromContract(in *contracts.ApprovalPackage) servicepolicy.ApprovalPackage {
	if in == nil {
		return servicepolicy.ApprovalPackage{}
	}
	return servicepolicy.ApprovalPackage{
		OperatorApproval: servicepolicy.OperatorApproval{
			ID:        in.GetOperatorApprovalId(),
			Scope:     in.GetOperatorApprovalScope(),
			ExpiresAt: unixTime(in.GetOperatorApprovalExpiresUnix()),
		},
		ServiceAuthorization: servicepolicy.ServiceAuthorization{
			Type:        servicepolicy.ServiceAuthorizationType(in.GetServiceAuthorizationType()),
			EvidenceRef: in.GetServiceAuthorizationEvidenceRef(),
			ExpiresAt:   unixTime(in.GetServiceAuthorizationExpiresUnix()),
		},
		AccountConsent: servicepolicy.AccountConsent{
			AccountRef:  in.GetAccountRef(),
			EvidenceRef: in.GetAccountConsentEvidenceRef(),
			ExpiresAt:   unixTime(in.GetAccountConsentExpiresUnix()),
		},
		CustodyPolicy: servicepolicy.CustodyPolicy{
			Backend:      in.GetCustodyBackend(),
			KeyHandleRef: in.GetCustodyKeyHandleRef(),
			BackupRef:    in.GetCustodyBackupRef(),
			RotationRef:  in.GetCustodyRotationRef(),
		},
		AbusePolicy: servicepolicy.AbusePolicy{
			IdempotencyRequired:   in.GetAbuseIdempotencyRequired(),
			RateLimitRef:          in.GetAbuseRateLimitRef(),
			RecipientAllowlistRef: in.GetAbuseRecipientAllowlistRef(),
			DeclaredAudienceRef:   in.GetAbuseDeclaredAudienceRef(),
			ChallengePolicyRef:    in.GetAbuseChallengePolicyRef(),
			BackoffPolicyRef:      in.GetAbuseBackoffPolicyRef(),
		},
		EgressPolicy: servicepolicy.EgressPolicy{
			EndpointAllowlist: append([]string(nil), in.GetEgressEndpointAllowlist()...),
			TLSPolicyRef:      in.GetEgressTlsPolicyRef(),
			DryRun:            in.GetEgressDryRun(),
		},
		AuditPolicy: servicepolicy.AuditPolicy{
			AuditRef:     in.GetAuditRef(),
			RetentionRef: in.GetAuditRetentionRef(),
			RedactionRef: in.GetAuditRedactionRef(),
		},
	}
}

func unixTime(seconds int64) time.Time {
	if seconds == 0 {
		return time.Time{}
	}
	return time.Unix(seconds, 0).UTC()
}

func operationActions(operation string) []servicepolicy.Action {
	if operation == "" {
		return nil
	}
	if operation == "challenge_response" {
		return []servicepolicy.Action{servicepolicy.ActionProductionEgress}
	}
	return []servicepolicy.Action{servicepolicy.Action(operation)}
}

func safeSignalRef(value string) string {
	if value == "" || strings.Contains(value, "://") {
		return value
	}
	return "redacted"
}

func signalServiceTransportRecords(ref string) []fake.ServiceClientRecord {
	signalServiceTransportsMu.Lock()
	defer signalServiceTransportsMu.Unlock()
	if ref == "" {
		var out []fake.ServiceClientRecord
		for _, transport := range signalServiceTransports {
			out = append(out, transport.records...)
		}
		return out
	}
	transport := signalServiceTransports[ref]
	if transport == nil {
		return nil
	}
	out := make([]fake.ServiceClientRecord, len(transport.records))
	copy(out, transport.records)
	return out
}
