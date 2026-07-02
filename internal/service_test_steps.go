package internal

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/GoCodeAlone/libsignal-service-go/fake"
	"github.com/GoCodeAlone/libsignal-service-go/serviceclient"
	"github.com/GoCodeAlone/libsignal-service-go/servicepolicy"
	"github.com/GoCodeAlone/workflow/plugin/external/sdk"

	contracts "github.com/GoCodeAlone/workflow-plugin-signal/internal/contracts"
)

var (
	signalServiceTestLedgerMu sync.Mutex
	signalServiceTestLedger   = map[string]fake.LedgerRecord{}
)

func ExecuteSignalServicePolicyCheck(
	_ context.Context,
	req sdk.TypedStepRequest[*contracts.ServicePolicyCheckConfig, *contracts.ServicePolicyCheckInput],
) (*sdk.TypedStepResult[*contracts.ServicePolicyCheckOutput], error) {
	mode := firstNonEmpty(req.Input.GetMode(), req.Config.GetMode())
	if mode == "" {
		mode = string(servicepolicy.ModeDisabled)
	}
	approvals := mergeNonEmptyStrings(req.Config.GetApprovals(), req.Input.GetApprovals())
	required := servicepolicy.RequiredLiveApprovals()
	approvalSet := servicepolicy.NewLiveApprovalSet(approvals...)
	missing := missingApprovals(required, approvalSet)
	actions := serviceComplianceActions(req.Input.GetRequestedActions(), req.Config.GetRequestedActions())
	report := servicepolicy.EvaluateCompliance(servicepolicy.ComplianceRequest{
		Mode:             servicepolicy.Mode(mode),
		RequestedActions: actions,
	})
	liveAllowed := (servicepolicy.Policy{Mode: servicepolicy.Mode(mode)}).AllowsLiveTransport(servicepolicy.ApprovalPackage{}, time.Now().UTC(), actions...)

	return &sdk.TypedStepResult[*contracts.ServicePolicyCheckOutput]{
		Output: &contracts.ServicePolicyCheckOutput{
			Mode:                 string(report.Mode),
			Approved:             report.Approved && (mode != string(servicepolicy.ModeLive) || liveAllowed),
			LiveServiceDisabled:  true,
			LiveTransportAllowed: liveAllowed,
			RequiredApprovals:    required,
			MissingApprovals:     missing,
			BlockedActions:       servicePolicyActionsToStrings(report.BlockedActions),
		},
	}, nil
}

func ExecuteSignalServiceTestRegister(
	ctx context.Context,
	req sdk.TypedStepRequest[*contracts.ServiceTestRegisterConfig, *contracts.ServiceTestRegisterInput],
) (*sdk.TypedStepResult[*contracts.ServiceTestOutput], error) {
	account, meta, opts, err := serviceTestRequestContext(req.Config.GetAccountRef(), req.Config.GetExpiredCredentials(), req.Input)
	if err != nil {
		return nil, fmt.Errorf("signal service test register: %w", err)
	}
	client := serviceTestClient(opts...)
	resp, err := client.Register(ctx, serviceclient.RegisterRequest{
		Metadata: meta,
		Username: req.Input.GetUsername(),
	})
	if err != nil {
		return nil, fmt.Errorf("signal service test register: %w", err)
	}
	return serviceTestResult(account, meta, resp.Common(), client.Ledger()), nil
}

func ExecuteSignalServiceTestLinkDevice(
	ctx context.Context,
	req sdk.TypedStepRequest[*contracts.ServiceTestLinkDeviceConfig, *contracts.ServiceTestLinkDeviceInput],
) (*sdk.TypedStepResult[*contracts.ServiceTestOutput], error) {
	account, meta, opts, err := serviceTestRequestContext(req.Config.GetAccountRef(), req.Config.GetExpiredCredentials(), req.Input)
	if err != nil {
		return nil, fmt.Errorf("signal service test link device: %w", err)
	}
	client := serviceTestClient(opts...)
	resp, err := client.LinkDevice(ctx, serviceclient.LinkDeviceRequest{
		Metadata:    meta,
		LinkCodeRef: req.Input.GetLinkCodeRef(),
	})
	if err != nil {
		return nil, fmt.Errorf("signal service test link device: %w", err)
	}
	return serviceTestResult(account, meta, resp.Common(), client.Ledger()), nil
}

func ExecuteSignalServiceTestSend(
	ctx context.Context,
	req sdk.TypedStepRequest[*contracts.ServiceTestSendConfig, *contracts.ServiceTestSendInput],
) (*sdk.TypedStepResult[*contracts.ServiceTestOutput], error) {
	account, meta, opts, err := serviceTestRequestContext(req.Config.GetAccountRef(), req.Config.GetExpiredCredentials(), req.Input)
	if err != nil {
		return nil, fmt.Errorf("signal service test send: %w", err)
	}
	client := serviceTestClient(opts...)
	resp, err := client.Send(ctx, serviceclient.SendRequest{
		Metadata:     meta,
		RecipientRef: req.Input.GetRecipientRef(),
		PayloadRef:   req.Input.GetPayloadRef(),
	})
	if err != nil {
		return nil, fmt.Errorf("signal service test send: %w", err)
	}
	return serviceTestResult(account, meta, resp.Common(), client.Ledger()), nil
}

func ExecuteSignalServiceTestReceive(
	ctx context.Context,
	req sdk.TypedStepRequest[*contracts.ServiceTestReceiveConfig, *contracts.ServiceTestReceiveInput],
) (*sdk.TypedStepResult[*contracts.ServiceTestOutput], error) {
	account, meta, opts, err := serviceTestRequestContext(req.Config.GetAccountRef(), req.Config.GetExpiredCredentials(), req.Input)
	if err != nil {
		return nil, fmt.Errorf("signal service test receive: %w", err)
	}
	client := serviceTestClient(opts...)
	resp, err := client.Receive(ctx, serviceclient.ReceiveRequest{
		Metadata:  meta,
		CursorRef: req.Input.GetCursorRef(),
	})
	if err != nil {
		return nil, fmt.Errorf("signal service test receive: %w", err)
	}
	return serviceTestResult(account, meta, resp.Common(), client.Ledger()), nil
}

func ExecuteSignalServiceTestUsernameReserve(
	ctx context.Context,
	req sdk.TypedStepRequest[*contracts.ServiceTestUsernameReserveConfig, *contracts.ServiceTestUsernameReserveInput],
) (*sdk.TypedStepResult[*contracts.ServiceTestOutput], error) {
	account, meta, opts, err := serviceTestRequestContext(req.Config.GetAccountRef(), req.Config.GetExpiredCredentials(), req.Input)
	if err != nil {
		return nil, fmt.Errorf("signal service test username reserve: %w", err)
	}
	client := serviceTestClient(opts...)
	resp, err := client.ReserveUsername(ctx, serviceclient.ReserveUsernameRequest{
		Metadata: meta,
		Username: req.Input.GetUsername(),
	})
	if err != nil {
		return nil, fmt.Errorf("signal service test username reserve: %w", err)
	}
	return serviceTestResult(account, meta, resp.Common(), client.Ledger()), nil
}

func ExecuteSignalServiceTestBackupUpload(
	ctx context.Context,
	req sdk.TypedStepRequest[*contracts.ServiceTestBackupUploadConfig, *contracts.ServiceTestBackupUploadInput],
) (*sdk.TypedStepResult[*contracts.ServiceTestOutput], error) {
	account, meta, opts, err := serviceTestRequestContext(req.Config.GetAccountRef(), req.Config.GetExpiredCredentials(), req.Input)
	if err != nil {
		return nil, fmt.Errorf("signal service test backup upload: %w", err)
	}
	client := serviceTestClient(opts...)
	resp, err := client.UploadBackup(ctx, serviceclient.UploadBackupRequest{
		Metadata:  meta,
		BackupRef: req.Input.GetBackupRef(),
	})
	if err != nil {
		return nil, fmt.Errorf("signal service test backup upload: %w", err)
	}
	return serviceTestResult(account, meta, resp.Common(), client.Ledger()), nil
}

func ExecuteSignalServiceTestBackupDownload(
	ctx context.Context,
	req sdk.TypedStepRequest[*contracts.ServiceTestBackupDownloadConfig, *contracts.ServiceTestBackupDownloadInput],
) (*sdk.TypedStepResult[*contracts.ServiceTestOutput], error) {
	account, meta, opts, err := serviceTestRequestContext(req.Config.GetAccountRef(), req.Config.GetExpiredCredentials(), req.Input)
	if err != nil {
		return nil, fmt.Errorf("signal service test backup download: %w", err)
	}
	client := serviceTestClient(opts...)
	resp, err := client.DownloadBackup(ctx, serviceclient.DownloadBackupRequest{
		Metadata: meta,
		BackupID: req.Input.GetBackupId(),
	})
	if err != nil {
		return nil, fmt.Errorf("signal service test backup download: %w", err)
	}
	return serviceTestResult(account, meta, resp.Common(), client.Ledger()), nil
}

type serviceTestInput interface {
	GetAccountRef() string
	GetDeviceRef() string
	GetCustodyRef() string
	GetIdempotencyKey() string
	GetConsentRef() string
	GetAuditRef() string
	GetCredentialRef() string
	GetNonExportableKeyRef() string
	GetChallengeRef() string
	GetExpiredCredentials() bool
}

func serviceTestRequestContext(configAccountRef string, configExpired bool, in serviceTestInput) (*signalAccountRef, serviceclient.RequestMetadata, []fake.ServiceClientOption, error) {
	accountRef := firstNonEmpty(in.GetAccountRef(), configAccountRef)
	account, err := lookupSignalAccountRef(accountRef)
	if err != nil {
		return nil, serviceclient.RequestMetadata{}, nil, err
	}
	if custodyRef := in.GetCustodyRef(); custodyRef != "" {
		custody, err := lookupSignalKeyCustody(custodyRef)
		if err != nil {
			return nil, serviceclient.RequestMetadata{}, nil, err
		}
		if custody.accountRef != account.ref {
			return nil, serviceclient.RequestMetadata{}, nil, fmt.Errorf("custody %q belongs to account %q", custody.ref, custody.accountRef)
		}
		account = &signalAccountRef{
			ref:           account.ref,
			deviceRef:     account.deviceRef,
			credentialRef: account.credentialRef,
			consentRef:    account.consentRef,
			auditRef:      account.auditRef,
			custody:       custody,
		}
	}
	meta := serviceclient.RequestMetadata{
		AccountRef:       account.ref,
		DeviceRef:        firstNonEmpty(in.GetDeviceRef(), account.deviceRef),
		IdempotencyKey:   in.GetIdempotencyKey(),
		ConsentRef:       firstNonEmpty(in.GetConsentRef(), account.consentRef),
		AuditRef:         firstNonEmpty(in.GetAuditRef(), account.auditRef),
		CredentialRef:    firstNonEmpty(in.GetCredentialRef(), account.credentialRef),
		NonExportableKey: in.GetNonExportableKeyRef(),
	}
	if meta.NonExportableKey == "" && account.custody != nil {
		meta.NonExportableKey = account.custody.nonExportableKeyRef
	}
	opts := []fake.ServiceClientOption{}
	if in.GetExpiredCredentials() || configExpired {
		opts = append(opts, fake.WithExpiredCredentials())
	}
	if challengeRef := in.GetChallengeRef(); challengeRef != "" {
		opts = append(opts, fake.WithChallenge(serviceTestOperation(in), challengeRef))
	}
	return account, meta, opts, nil
}

func serviceTestOperation(in serviceTestInput) string {
	switch in.(type) {
	case *contracts.ServiceTestRegisterInput:
		return "register"
	case *contracts.ServiceTestLinkDeviceInput:
		return "linked_device"
	case *contracts.ServiceTestSendInput:
		return "send"
	case *contracts.ServiceTestReceiveInput:
		return "receive"
	case *contracts.ServiceTestUsernameReserveInput:
		return "username_reserve"
	case *contracts.ServiceTestBackupUploadInput:
		return "backup_upload"
	case *contracts.ServiceTestBackupDownloadInput:
		return "backup_download"
	default:
		return ""
	}
}

func serviceTestClient(opts ...fake.ServiceClientOption) *fake.ServiceClient {
	signalServiceTestLedgerMu.Lock()
	ledger := cloneServiceTestLedger(signalServiceTestLedger)
	signalServiceTestLedgerMu.Unlock()

	allOpts := []fake.ServiceClientOption{fake.WithLedger(ledger)}
	allOpts = append(allOpts, opts...)
	return fake.NewServiceClient(allOpts...)
}

func serviceTestResult(account *signalAccountRef, reqMeta serviceclient.RequestMetadata, meta serviceclient.ResponseMetadata, ledger map[string]fake.LedgerRecord) *sdk.TypedStepResult[*contracts.ServiceTestOutput] {
	signalServiceTestLedgerMu.Lock()
	signalServiceTestLedger = cloneServiceTestLedger(ledger)
	signalServiceTestLedgerMu.Unlock()

	secretRefs := map[string]string{}
	for key, value := range meta.SecretRefs {
		secretRefs[key] = value
	}
	return &sdk.TypedStepResult[*contracts.ServiceTestOutput]{
		Output: &contracts.ServiceTestOutput{
			AccountRef:    account.ref,
			DeviceRef:     reqMeta.DeviceRef,
			RequestId:     meta.RequestID,
			Status:        meta.Status,
			ChallengeRef:  meta.ChallengeRef,
			SecretRefs:    secretRefs,
			CredentialRef: secretRefs["credential"],
			AuditRef:      reqMeta.AuditRef,
		},
	}
}

func mergeNonEmptyStrings(configValues, inputValues []string) []string {
	values := make([]string, 0, len(configValues)+len(inputValues))
	for _, value := range configValues {
		if value != "" {
			values = append(values, value)
		}
	}
	for _, value := range inputValues {
		if value != "" {
			values = append(values, value)
		}
	}
	return values
}

func missingApprovals(required []string, approvals servicepolicy.LiveApprovalSet) []string {
	missing := make([]string, 0, len(required))
	for _, approval := range required {
		if !approvals[approval] {
			missing = append(missing, approval)
		}
	}
	return missing
}

func cloneServiceTestLedger(in map[string]fake.LedgerRecord) map[string]fake.LedgerRecord {
	out := make(map[string]fake.LedgerRecord, len(in))
	for key, record := range in {
		out[key] = record
	}
	return out
}
