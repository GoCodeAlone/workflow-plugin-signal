package internal

import (
	"bytes"
	"context"
	"path/filepath"
	"testing"

	"github.com/GoCodeAlone/workflow/plugin/external/sdk"

	contracts "github.com/GoCodeAlone/workflow-plugin-signal/internal/contracts"
)

func TestEnvelopeStoreQueuesCiphertextAndDecryptRequiresCustodyAndAuthz(t *testing.T) {
	t.Cleanup(resetServiceTestState)
	store, err := newEnvelopeStoreModule("envelopes", &contracts.EnvelopeStoreConfig{
		StoreRef:       "envelopes",
		Backend:        "memory",
		RetentionLimit: 16,
	})
	if err != nil {
		t.Fatalf("newEnvelopeStoreModule: %v", err)
	}
	if err := store.Init(); err != nil {
		t.Fatalf("store init: %v", err)
	}

	plaintext := []byte("private workflow message")
	envelope := &contracts.SignalEnvelope{
		SenderId:          "alice@example.test",
		SenderDeviceId:    1,
		RecipientId:       "bob@example.test",
		RecipientDeviceId: 1,
		MessageType:       "signal",
		Ciphertext:        []byte("ciphertext-only"),
	}
	enqueued, err := ExecuteSignalOutboxEnqueue(context.Background(), sdk.TypedStepRequest[*contracts.OutboxEnqueueConfig, *contracts.OutboxEnqueueInput]{
		Config: &contracts.OutboxEnqueueConfig{StoreRef: "envelopes"},
		Input: &contracts.OutboxEnqueueInput{
			Envelope:       envelope,
			MessageRef:     "message://fixture/1",
			SenderRef:      "principal://alice",
			RecipientRef:   "principal://bob",
			CustodyRef:     "custody://alice/device-1",
			AuthzRef:       "authz://send/1",
			IdempotencyKey: "send-1",
		},
	})
	if err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	if enqueued.Output.GetEnvelopeRef() == "" || enqueued.Output.GetStatus() != "queued" {
		t.Fatalf("enqueue output = %+v", enqueued.Output)
	}

	claim, err := ExecuteSignalOutboxClaim(context.Background(), sdk.TypedStepRequest[*contracts.OutboxClaimConfig, *contracts.OutboxClaimInput]{
		Config: &contracts.OutboxClaimConfig{StoreRef: "envelopes"},
		Input: &contracts.OutboxClaimInput{
			EnvelopeRef: enqueued.Output.GetEnvelopeRef(),
			ClaimantRef: "worker://signal/outbox",
			LeaseId:     "lease-1",
		},
	})
	if err != nil {
		t.Fatalf("claim: %v", err)
	}
	if !bytes.Equal(claim.Output.GetEnvelope().GetCiphertext(), []byte("ciphertext-only")) {
		t.Fatalf("claim envelope = %+v", claim.Output.GetEnvelope())
	}
	if claim.Output.GetLeaseRef() == "" || !bytes.Contains([]byte(claim.Output.GetLeaseRef()), []byte("lease-1")) {
		t.Fatalf("claim lease ref = %q, want lease id", claim.Output.GetLeaseRef())
	}
	if _, err := ExecuteSignalOutboxClaim(context.Background(), sdk.TypedStepRequest[*contracts.OutboxClaimConfig, *contracts.OutboxClaimInput]{
		Config: &contracts.OutboxClaimConfig{StoreRef: "envelopes"},
		Input: &contracts.OutboxClaimInput{
			EnvelopeRef: enqueued.Output.GetEnvelopeRef(),
			ClaimantRef: "worker://signal/outbox/second",
			LeaseId:     "lease-2",
		},
	}); err == nil {
		t.Fatal("second claim of already claimed envelope succeeded")
	}

	received, err := ExecuteSignalInboxReceive(context.Background(), sdk.TypedStepRequest[*contracts.InboxReceiveConfig, *contracts.InboxReceiveInput]{
		Config: &contracts.InboxReceiveConfig{StoreRef: "envelopes"},
		Input: &contracts.InboxReceiveInput{
			Envelope:       claim.Output.GetEnvelope(),
			EnvelopeRef:    claim.Output.GetEnvelopeRef(),
			RecipientRef:   "principal://bob",
			IdempotencyKey: "receive-1",
		},
	})
	if err != nil {
		t.Fatalf("receive: %v", err)
	}
	if received.Output.GetStatus() != "received" {
		t.Fatalf("receive output = %+v", received.Output)
	}

	if _, err := ExecuteSignalInboxDecrypt(context.Background(), sdk.TypedStepRequest[*contracts.InboxDecryptConfig, *contracts.InboxDecryptInput]{
		Config: &contracts.InboxDecryptConfig{StoreRef: "envelopes", IdentityRef: "bob"},
		Input: &contracts.InboxDecryptInput{
			EnvelopeRef: received.Output.GetEnvelopeRef(),
			Principal:   "principal://bob",
		},
	}); err == nil {
		t.Fatal("decrypt without custody/authz context succeeded")
	}

	raw, err := envelopeStoreSnapshot("envelopes")
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if bytes.Contains(raw, plaintext) || bytes.Contains(raw, []byte("private workflow message")) {
		t.Fatalf("envelope store snapshot exposed plaintext: %s", raw)
	}
}

func TestEnvelopeStoreRejectsAmbiguousEnvelopeAndClaimRefs(t *testing.T) {
	t.Cleanup(resetServiceTestState)
	store, err := newEnvelopeStoreModule("envelopes", &contracts.EnvelopeStoreConfig{StoreRef: "envelopes", Backend: "memory"})
	if err != nil {
		t.Fatalf("newEnvelopeStoreModule: %v", err)
	}
	if err := store.Init(); err != nil {
		t.Fatalf("store init: %v", err)
	}
	envelope := &contracts.SignalEnvelope{
		SenderId:          "alice@example.test",
		SenderDeviceId:    1,
		RecipientId:       "bob@example.test",
		RecipientDeviceId: 1,
		MessageType:       "signal",
		Ciphertext:        []byte("ciphertext-only"),
	}
	if _, err := ExecuteSignalOutboxEnqueue(context.Background(), sdk.TypedStepRequest[*contracts.OutboxEnqueueConfig, *contracts.OutboxEnqueueInput]{
		Config: &contracts.OutboxEnqueueConfig{StoreRef: "envelopes"},
		Input: &contracts.OutboxEnqueueInput{
			Envelope:     envelope,
			SenderRef:    "principal://alice",
			RecipientRef: "principal://bob",
			CustodyRef:   "custody://alice/device-1",
			AuthzRef:     "authz://send/1",
		},
	}); err == nil {
		t.Fatal("enqueue without idempotency_key or message_ref succeeded")
	}
	enqueued, err := ExecuteSignalOutboxEnqueue(context.Background(), sdk.TypedStepRequest[*contracts.OutboxEnqueueConfig, *contracts.OutboxEnqueueInput]{
		Config: &contracts.OutboxEnqueueConfig{StoreRef: "envelopes"},
		Input: &contracts.OutboxEnqueueInput{
			Envelope:       envelope,
			SenderRef:      "principal://alice",
			RecipientRef:   "principal://bob",
			CustodyRef:     "custody://alice/device-1",
			AuthzRef:       "authz://send/1",
			IdempotencyKey: "send-1",
		},
	})
	if err != nil {
		t.Fatalf("enqueue with stable refs: %v", err)
	}
	if _, err := ExecuteSignalOutboxClaim(context.Background(), sdk.TypedStepRequest[*contracts.OutboxClaimConfig, *contracts.OutboxClaimInput]{
		Config: &contracts.OutboxClaimConfig{StoreRef: "envelopes"},
		Input:  &contracts.OutboxClaimInput{EnvelopeRef: enqueued.Output.GetEnvelopeRef()},
	}); err == nil {
		t.Fatal("claim without claimant_ref succeeded")
	}
}

func TestEnvelopeStoreFileBackendReloadsQueuedEnvelope(t *testing.T) {
	t.Cleanup(resetServiceTestState)
	storagePath := filepath.Join(t.TempDir(), "envelopes.json")
	cfg := &contracts.EnvelopeStoreConfig{
		StoreRef:               "file-envelopes",
		Backend:                "local_file",
		StoragePath:            storagePath,
		AllowLocalFileEnvelope: true,
		RetentionLimit:         8,
	}
	first, err := newEnvelopeStoreModule("file-envelopes", cfg)
	if err != nil {
		t.Fatalf("new first store: %v", err)
	}
	if err := first.Init(); err != nil {
		t.Fatalf("first init: %v", err)
	}
	enqueued, err := ExecuteSignalOutboxEnqueue(context.Background(), sdk.TypedStepRequest[*contracts.OutboxEnqueueConfig, *contracts.OutboxEnqueueInput]{
		Config: &contracts.OutboxEnqueueConfig{StoreRef: "file-envelopes"},
		Input: &contracts.OutboxEnqueueInput{
			Envelope: &contracts.SignalEnvelope{
				SenderId:          "alice@example.test",
				SenderDeviceId:    1,
				RecipientId:       "bob@example.test",
				RecipientDeviceId: 1,
				MessageType:       "signal",
				Ciphertext:        []byte("persisted-ciphertext"),
			},
			SenderRef:      "principal://alice",
			RecipientRef:   "principal://bob",
			CustodyRef:     "custody://alice/device-1",
			AuthzRef:       "authz://send/1",
			IdempotencyKey: "persist-1",
		},
	})
	if err != nil {
		t.Fatalf("enqueue: %v", err)
	}

	resetServiceTestState()
	second, err := newEnvelopeStoreModule("file-envelopes", cfg)
	if err != nil {
		t.Fatalf("new second store: %v", err)
	}
	if err := second.Init(); err != nil {
		t.Fatalf("second init: %v", err)
	}
	claimed, err := ExecuteSignalOutboxClaim(context.Background(), sdk.TypedStepRequest[*contracts.OutboxClaimConfig, *contracts.OutboxClaimInput]{
		Config: &contracts.OutboxClaimConfig{StoreRef: "file-envelopes"},
		Input: &contracts.OutboxClaimInput{
			EnvelopeRef: enqueued.Output.GetEnvelopeRef(),
			ClaimantRef: "worker://signal/outbox",
			LeaseId:     "lease-1",
		},
	})
	if err != nil {
		t.Fatalf("claim after reload: %v", err)
	}
	if !bytes.Equal(claimed.Output.GetEnvelope().GetCiphertext(), []byte("persisted-ciphertext")) {
		t.Fatalf("claimed envelope after reload = %+v", claimed.Output.GetEnvelope())
	}
}
