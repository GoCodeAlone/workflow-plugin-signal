package internal

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/GoCodeAlone/libsignal-service-go/service"
	"github.com/GoCodeAlone/workflow/plugin/external/sdk"

	contracts "github.com/GoCodeAlone/workflow-plugin-signal/internal/contracts"
)

var (
	linkedDeviceCeremoniesMu   sync.Mutex
	linkedDeviceCeremonyClaims = map[string]int64{}
)

func ExecuteSignalServiceRegisterPrepare(
	_ context.Context,
	req sdk.TypedStepRequest[*contracts.ServiceRegisterPrepareConfig, *contracts.ServiceRegisterPrepareInput],
) (*sdk.TypedStepResult[*contracts.ServiceOperationPrepareOutput], error) {
	return serviceOperationPrepared(service.OperationRegister, serviceEnvelopeFields{
		OperationID:         req.Input.GetOperationId(),
		AccountRef:          firstNonEmpty(req.Input.GetAccountRef(), req.Config.GetAccountRef()),
		DeviceRef:           req.Input.GetDeviceRef(),
		CustodyRef:          req.Input.GetCustodyRef(),
		IdempotencyKey:      req.Input.GetIdempotencyKey(),
		Username:            req.Input.GetUsername(),
		ConsentRef:          req.Input.GetConsentRef(),
		AuditRef:            req.Input.GetAuditRef(),
		CredentialRef:       req.Input.GetCredentialRef(),
		NonExportableKeyRef: req.Input.GetNonExportableKeyRef(),
		RequestedAtUnix:     req.Input.GetRequestedAtUnix(),
	}), nil
}

func ExecuteSignalServiceLinkPrepare(
	_ context.Context,
	req sdk.TypedStepRequest[*contracts.ServiceLinkPrepareConfig, *contracts.ServiceLinkPrepareInput],
) (*sdk.TypedStepResult[*contracts.ServiceOperationPrepareOutput], error) {
	if err := validateLinkedDeviceCeremony(req.Input.GetLinkedDevice()); err != nil {
		return nil, err
	}
	return serviceOperationPrepared(service.OperationLinkDevice, serviceEnvelopeFields{
		OperationID:         req.Input.GetOperationId(),
		AccountRef:          firstNonEmpty(req.Input.GetAccountRef(), req.Config.GetAccountRef()),
		DeviceRef:           req.Input.GetDeviceRef(),
		CustodyRef:          req.Input.GetCustodyRef(),
		IdempotencyKey:      req.Input.GetIdempotencyKey(),
		ConsentRef:          firstNonEmpty(req.Input.GetConsentRef(), req.Input.GetLinkedDevice().GetConsentRef()),
		AuditRef:            req.Input.GetAuditRef(),
		CredentialRef:       req.Input.GetCredentialRef(),
		NonExportableKeyRef: req.Input.GetNonExportableKeyRef(),
		RequestedAtUnix:     req.Input.GetRequestedAtUnix(),
		LinkedDevice:        req.Input.GetLinkedDevice(),
	}), nil
}

func validateLinkedDeviceCeremony(ceremony *contracts.LinkedDeviceCeremony) error {
	if ceremony == nil {
		return fmt.Errorf("signal service link prepare: linked_device is required")
	}
	if ceremony.GetDeviceDisplayName() == "" {
		return fmt.Errorf("signal service link prepare: device_display_name is required")
	}
	if ceremony.GetConsentRef() == "" {
		return fmt.Errorf("signal service link prepare: consent_ref is required")
	}
	if ceremony.GetConsentExpiresUnix() == 0 {
		return fmt.Errorf("signal service link prepare: consent_expires_unix is required")
	}
	now := time.Now().UTC().Unix()
	if ceremony.GetConsentExpiresUnix() <= now {
		return fmt.Errorf("signal service link prepare: consent is expired")
	}
	if ceremony.GetRevocationUri() == "" {
		return fmt.Errorf("signal service link prepare: revocation_uri is required")
	}
	if ceremony.GetUnlinkProofRef() == "" {
		return fmt.Errorf("signal service link prepare: unlink_proof_ref is required")
	}
	if strings.HasPrefix(ceremony.GetUnlinkProofRef(), "revoked://") {
		return fmt.Errorf("signal service link prepare: unlink proof is revoked")
	}
	linkedDeviceCeremoniesMu.Lock()
	defer linkedDeviceCeremoniesMu.Unlock()
	for claim, expires := range linkedDeviceCeremonyClaims {
		if expires <= now {
			delete(linkedDeviceCeremonyClaims, claim)
		}
	}
	claim := ceremony.GetConsentRef()
	if _, ok := linkedDeviceCeremonyClaims[claim]; ok {
		return fmt.Errorf("signal service link prepare: linked-device consent replay")
	}
	linkedDeviceCeremonyClaims[claim] = ceremony.GetConsentExpiresUnix()
	return nil
}

func ExecuteSignalServiceSendPrepare(
	_ context.Context,
	req sdk.TypedStepRequest[*contracts.ServiceSendPrepareConfig, *contracts.ServiceSendPrepareInput],
) (*sdk.TypedStepResult[*contracts.ServiceOperationPrepareOutput], error) {
	return serviceOperationPrepared(service.OperationSend, serviceEnvelopeFields{
		OperationID:         req.Input.GetOperationId(),
		AccountRef:          firstNonEmpty(req.Input.GetAccountRef(), req.Config.GetAccountRef()),
		DeviceRef:           req.Input.GetDeviceRef(),
		CustodyRef:          req.Input.GetCustodyRef(),
		IdempotencyKey:      req.Input.GetIdempotencyKey(),
		RecipientRef:        req.Input.GetRecipientRef(),
		PayloadRef:          req.Input.GetPayloadRef(),
		ConsentRef:          req.Input.GetConsentRef(),
		AuditRef:            req.Input.GetAuditRef(),
		CredentialRef:       req.Input.GetCredentialRef(),
		NonExportableKeyRef: req.Input.GetNonExportableKeyRef(),
		RequestedAtUnix:     req.Input.GetRequestedAtUnix(),
	}), nil
}

func ExecuteSignalServiceReceiveAdmit(
	_ context.Context,
	req sdk.TypedStepRequest[*contracts.ServiceReceiveAdmitConfig, *contracts.ServiceReceiveAdmitInput],
) (*sdk.TypedStepResult[*contracts.ServiceOperationPrepareOutput], error) {
	return serviceOperationPrepared(service.OperationReceive, serviceEnvelopeFields{
		OperationID:         req.Input.GetOperationId(),
		AccountRef:          firstNonEmpty(req.Input.GetAccountRef(), req.Config.GetAccountRef()),
		DeviceRef:           req.Input.GetDeviceRef(),
		CustodyRef:          req.Input.GetCustodyRef(),
		IdempotencyKey:      req.Input.GetIdempotencyKey(),
		CursorRef:           req.Input.GetCursorRef(),
		ConsentRef:          req.Input.GetConsentRef(),
		AuditRef:            req.Input.GetAuditRef(),
		CredentialRef:       req.Input.GetCredentialRef(),
		NonExportableKeyRef: req.Input.GetNonExportableKeyRef(),
		RequestedAtUnix:     req.Input.GetRequestedAtUnix(),
	}), nil
}

func ExecuteSignalServiceChallengeRespond(
	_ context.Context,
	req sdk.TypedStepRequest[*contracts.ServiceChallengeRespondConfig, *contracts.ServiceChallengeRespondInput],
) (*sdk.TypedStepResult[*contracts.ServiceOperationPrepareOutput], error) {
	return serviceOperationPrepared(service.OperationChallenge, serviceEnvelopeFields{
		OperationID:          req.Input.GetOperationId(),
		AccountRef:           firstNonEmpty(req.Input.GetAccountRef(), req.Config.GetAccountRef()),
		DeviceRef:            req.Input.GetDeviceRef(),
		CustodyRef:           req.Input.GetCustodyRef(),
		IdempotencyKey:       req.Input.GetIdempotencyKey(),
		ChallengeRef:         req.Input.GetChallengeRef(),
		ChallengeResponseRef: req.Input.GetChallengeResponseRef(),
		ConsentRef:           req.Input.GetConsentRef(),
		AuditRef:             req.Input.GetAuditRef(),
		CredentialRef:        req.Input.GetCredentialRef(),
		NonExportableKeyRef:  req.Input.GetNonExportableKeyRef(),
		RequestedAtUnix:      req.Input.GetRequestedAtUnix(),
	}), nil
}

func ExecuteSignalUsernameProofPrepare(
	_ context.Context,
	req sdk.TypedStepRequest[*contracts.UsernameProofPrepareConfig, *contracts.UsernameProofPrepareInput],
) (*sdk.TypedStepResult[*contracts.ServiceOperationPrepareOutput], error) {
	return serviceOperationReport(service.OperationUsername, "structural", "username proof vectors are tracked in libsignal-go proof reports", serviceEnvelopeFields{
		OperationID:     req.Input.GetOperationId(),
		AccountRef:      firstNonEmpty(req.Input.GetAccountRef(), req.Config.GetAccountRef()),
		IdempotencyKey:  req.Input.GetIdempotencyKey(),
		Username:        req.Input.GetUsername(),
		AuditRef:        req.Input.GetAuditRef(),
		RequestedAtUnix: req.Input.GetRequestedAtUnix(),
	}), nil
}

func ExecuteSignalBackupManifestVerify(
	_ context.Context,
	req sdk.TypedStepRequest[*contracts.BackupManifestVerifyConfig, *contracts.BackupManifestVerifyInput],
) (*sdk.TypedStepResult[*contracts.ServiceOperationPrepareOutput], error) {
	return serviceOperationReport(service.OperationBackup, "deferred", "backup manifest parity depends on upstream backup vectors", serviceEnvelopeFields{
		OperationID:     req.Input.GetOperationId(),
		AccountRef:      firstNonEmpty(req.Input.GetAccountRef(), req.Config.GetAccountRef()),
		IdempotencyKey:  req.Input.GetIdempotencyKey(),
		BackupRef:       req.Input.GetBackupRef(),
		BackupID:        req.Input.GetBackupId(),
		AuditRef:        req.Input.GetAuditRef(),
		RequestedAtUnix: req.Input.GetRequestedAtUnix(),
	}), nil
}

func ExecuteSignalBackupAuthPrepare(
	_ context.Context,
	req sdk.TypedStepRequest[*contracts.BackupAuthPrepareConfig, *contracts.BackupAuthPrepareInput],
) (*sdk.TypedStepResult[*contracts.ServiceOperationPrepareOutput], error) {
	return serviceOperationReport(service.OperationBackup, "deferred", "backup auth parity depends on upstream backup credential vectors", serviceEnvelopeFields{
		OperationID:     req.Input.GetOperationId(),
		AccountRef:      firstNonEmpty(req.Input.GetAccountRef(), req.Config.GetAccountRef()),
		IdempotencyKey:  req.Input.GetIdempotencyKey(),
		BackupRef:       req.Input.GetBackupRef(),
		AuditRef:        req.Input.GetAuditRef(),
		RequestedAtUnix: req.Input.GetRequestedAtUnix(),
	}), nil
}

type serviceEnvelopeFields struct {
	OperationID          string
	AccountRef           string
	DeviceRef            string
	CustodyRef           string
	IdempotencyKey       string
	ConsentRef           string
	AuditRef             string
	CredentialRef        string
	NonExportableKeyRef  string
	RecipientRef         string
	PayloadRef           string
	CursorRef            string
	Username             string
	BackupRef            string
	BackupID             string
	ChallengeRef         string
	ChallengeResponseRef string
	RequestedAtUnix      int64
	LinkedDevice         *contracts.LinkedDeviceCeremony
}

func serviceOperationPrepared(operation service.Operation, fields serviceEnvelopeFields) *sdk.TypedStepResult[*contracts.ServiceOperationPrepareOutput] {
	return serviceOperationReport(operation, "prepared", "", fields)
}

func serviceOperationReport(operation service.Operation, classification, reason string, fields serviceEnvelopeFields) *sdk.TypedStepResult[*contracts.ServiceOperationPrepareOutput] {
	envelope := serviceOperationEnvelope(operation, fields)
	return &sdk.TypedStepResult[*contracts.ServiceOperationPrepareOutput]{
		Output: &contracts.ServiceOperationPrepareOutput{
			Envelope:             envelope,
			Status:               "prepared",
			ReportClassification: classification,
			DeferredReason:       reason,
			AuditRef:             safeSignalRef(firstNonEmpty(fields.AuditRef, serviceOperationAuditRef(envelope))),
			LiveEgressAttempted:  false,
		},
	}
}

func serviceOperationEnvelope(operation service.Operation, fields serviceEnvelopeFields) *contracts.ServiceOperationEnvelope {
	requestedAt := fields.RequestedAtUnix
	if requestedAt == 0 {
		requestedAt = time.Now().UTC().Unix()
	}
	idempotencyKey := fields.IdempotencyKey
	if idempotencyKey == "" {
		idempotencyKey = string(operation) + "-" + signalRefSegment(firstNonEmpty(fields.AccountRef, "account"))
	}
	operationID := fields.OperationID
	if operationID == "" {
		operationID = "op://" + string(operation) + "/" + idempotencyKey
	}
	return &contracts.ServiceOperationEnvelope{
		OperationId:          operationID,
		Operation:            string(operation),
		IdempotencyKey:       idempotencyKey,
		AccountRef:           safeSignalRef(fields.AccountRef),
		DeviceRef:            safeSignalRef(fields.DeviceRef),
		CustodyRef:           safeSignalRef(fields.CustodyRef),
		RequestedAtUnix:      requestedAt,
		ConsentRef:           safeSignalRef(fields.ConsentRef),
		AuditRef:             safeSignalRef(fields.AuditRef),
		CredentialRef:        safeSignalRef(fields.CredentialRef),
		NonExportableKeyRef:  safeSignalRef(fields.NonExportableKeyRef),
		RecipientRef:         safeSignalRef(fields.RecipientRef),
		PayloadRef:           safeSignalRef(fields.PayloadRef),
		CursorRef:            safeSignalRef(fields.CursorRef),
		Username:             fields.Username,
		BackupRef:            safeSignalRef(fields.BackupRef),
		BackupId:             safeSignalRef(fields.BackupID),
		ChallengeRef:         safeSignalRef(fields.ChallengeRef),
		ChallengeResponseRef: safeSignalRef(fields.ChallengeResponseRef),
		LinkedDevice:         fields.LinkedDevice,
	}
}

func serviceOperationAuditRef(envelope *contracts.ServiceOperationEnvelope) string {
	return "audit://signal/" + signalRefSegment(envelope.GetOperation()) + "/" + signalRefSegment(envelope.GetOperationId())
}

func signalRefSegment(value string) string {
	value = strings.TrimSpace(value)
	value = strings.TrimPrefix(value, "op://")
	value = strings.ReplaceAll(value, "://", "-")
	replacer := strings.NewReplacer("/", "-", ":", "-", " ", "-")
	value = replacer.Replace(value)
	value = strings.Trim(value, "-")
	if value == "" {
		return "ref"
	}
	return value
}
