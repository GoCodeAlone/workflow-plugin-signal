package internal

import (
	"context"
	"fmt"

	"github.com/GoCodeAlone/workflow/plugin/external/sdk"

	contracts "github.com/GoCodeAlone/workflow-plugin-signal/internal/contracts"
)

func ExecuteSignalOutboxEnqueue(
	_ context.Context,
	req sdk.TypedStepRequest[*contracts.OutboxEnqueueConfig, *contracts.OutboxEnqueueInput],
) (*sdk.TypedStepResult[*contracts.OutboxEnqueueOutput], error) {
	store, err := lookupSignalEnvelopeStore(firstNonEmpty(req.Input.GetStoreRef(), req.Config.GetStoreRef()))
	if err != nil {
		return nil, err
	}
	record, err := store.enqueueOutbox(req.Input)
	if err != nil {
		return nil, err
	}
	return &sdk.TypedStepResult[*contracts.OutboxEnqueueOutput]{
		Output: &contracts.OutboxEnqueueOutput{
			EnvelopeRef: record.EnvelopeRef,
			Status:      record.Status,
			Metadata:    envelopeMetadata(record),
		},
	}, nil
}

func ExecuteSignalOutboxClaim(
	_ context.Context,
	req sdk.TypedStepRequest[*contracts.OutboxClaimConfig, *contracts.OutboxClaimInput],
) (*sdk.TypedStepResult[*contracts.OutboxClaimOutput], error) {
	store, err := lookupSignalEnvelopeStore(firstNonEmpty(req.Input.GetStoreRef(), req.Config.GetStoreRef()))
	if err != nil {
		return nil, err
	}
	record, err := store.claimOutbox(req.Input)
	if err != nil {
		return nil, err
	}
	return &sdk.TypedStepResult[*contracts.OutboxClaimOutput]{
		Output: &contracts.OutboxClaimOutput{
			EnvelopeRef: record.EnvelopeRef,
			Status:      record.Status,
			Envelope:    cloneSignalEnvelope(record.Envelope),
			LeaseRef:    record.LeaseRef,
			Metadata:    envelopeMetadata(record),
		},
	}, nil
}

func ExecuteSignalInboxReceive(
	_ context.Context,
	req sdk.TypedStepRequest[*contracts.InboxReceiveConfig, *contracts.InboxReceiveInput],
) (*sdk.TypedStepResult[*contracts.InboxReceiveOutput], error) {
	store, err := lookupSignalEnvelopeStore(firstNonEmpty(req.Input.GetStoreRef(), req.Config.GetStoreRef()))
	if err != nil {
		return nil, err
	}
	record, err := store.receiveInbox(req.Input)
	if err != nil {
		return nil, err
	}
	return &sdk.TypedStepResult[*contracts.InboxReceiveOutput]{
		Output: &contracts.InboxReceiveOutput{
			EnvelopeRef: record.EnvelopeRef,
			Status:      record.Status,
			Metadata:    envelopeMetadata(record),
		},
	}, nil
}

func ExecuteSignalInboxDecrypt(
	ctx context.Context,
	req sdk.TypedStepRequest[*contracts.InboxDecryptConfig, *contracts.InboxDecryptInput],
) (*sdk.TypedStepResult[*contracts.InboxDecryptOutput], error) {
	store, err := lookupSignalEnvelopeStore(firstNonEmpty(req.Input.GetStoreRef(), req.Config.GetStoreRef()))
	if err != nil {
		return nil, err
	}
	if req.Input.GetCustodyRef() == "" {
		return nil, fmt.Errorf("signal inbox decrypt: custody_ref is required")
	}
	if req.Input.GetAuthzRef() == "" {
		return nil, fmt.Errorf("signal inbox decrypt: authz_ref is required")
	}
	record, err := store.inbox(req.Input.GetEnvelopeRef())
	if err != nil {
		return nil, err
	}
	decrypted, err := ExecuteSignalDecrypt(ctx, sdk.TypedStepRequest[*contracts.SignalDecryptConfig, *contracts.SignalDecryptInput]{
		Config: &contracts.SignalDecryptConfig{
			IdentityRef:       firstNonEmpty(req.Input.GetIdentityRef(), req.Config.GetIdentityRef()),
			RequiredPrincipal: req.Config.GetRequiredPrincipal(),
		},
		Input: &contracts.SignalDecryptInput{
			IdentityRef: firstNonEmpty(req.Input.GetIdentityRef(), req.Config.GetIdentityRef()),
			Principal:   req.Input.GetPrincipal(),
			Envelope:    cloneSignalEnvelope(record.Envelope),
		},
	})
	if err != nil {
		return nil, err
	}
	metadata := envelopeMetadata(record)
	metadata.CustodyRef = req.Input.GetCustodyRef()
	metadata.AuthzRef = req.Input.GetAuthzRef()
	return &sdk.TypedStepResult[*contracts.InboxDecryptOutput]{
		Output: &contracts.InboxDecryptOutput{
			Denied:    decrypted.Output.GetDenied(),
			Error:     decrypted.Output.GetError(),
			Plaintext: decrypted.Output.GetPlaintext(),
			Metadata:  metadata,
		},
	}, nil
}
