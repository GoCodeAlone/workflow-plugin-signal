package internal

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	contracts "github.com/GoCodeAlone/workflow-plugin-signal/internal/contracts"
)

const (
	envelopeStoreBackendMemory    = "memory"
	envelopeStoreBackendLocalFile = "local_file"
)

type envelopeStoreModule struct {
	lifecycleModule
	name   string
	config *contracts.EnvelopeStoreConfig
}

type envelopeStore struct {
	mu     sync.Mutex
	config *contracts.EnvelopeStoreConfig
	state  envelopeStoreState
}

type envelopeStoreState struct {
	Version uint32                     `json:"version"`
	Outbox  map[string]*envelopeRecord `json:"outbox"`
	Inbox   map[string]*envelopeRecord `json:"inbox"`
}

type envelopeRecord struct {
	Envelope       *contracts.SignalEnvelope `json:"envelope"`
	EnvelopeRef    string                    `json:"envelope_ref"`
	Queue          string                    `json:"queue"`
	Status         string                    `json:"status"`
	SenderRef      string                    `json:"sender_ref,omitempty"`
	RecipientRef   string                    `json:"recipient_ref,omitempty"`
	CustodyRef     string                    `json:"custody_ref,omitempty"`
	AuthzRef       string                    `json:"authz_ref,omitempty"`
	MessageRef     string                    `json:"message_ref,omitempty"`
	CreatedAtUnix  int64                     `json:"created_at_unix,omitempty"`
	ClaimedAtUnix  int64                     `json:"claimed_at_unix,omitempty"`
	ReceivedAtUnix int64                     `json:"received_at_unix,omitempty"`
	LeaseRef       string                    `json:"lease_ref,omitempty"`
}

var (
	errEnvelopeStoreLocalFileDenied = errors.New("signal envelope store: local_file backend requires explicit opt-in")

	signalEnvelopeStoresMu sync.RWMutex
	signalEnvelopeStores   = map[string]*envelopeStore{}
)

func newEnvelopeStoreModule(name string, cfg *contracts.EnvelopeStoreConfig) (*envelopeStoreModule, error) {
	if cfg == nil {
		cfg = &contracts.EnvelopeStoreConfig{}
	}
	backend := cfg.GetBackend()
	if backend == "" {
		backend = envelopeStoreBackendMemory
		cfg.Backend = backend
	}
	switch backend {
	case envelopeStoreBackendMemory:
	case envelopeStoreBackendLocalFile:
		if !cfg.GetAllowLocalFileEnvelope() {
			return nil, errEnvelopeStoreLocalFileDenied
		}
		if cfg.GetStoragePath() == "" {
			return nil, fmt.Errorf("signal envelope store: storage_path is required")
		}
		if productionPolicyMode(cfg.GetPolicyMode()) {
			return nil, fmt.Errorf("signal envelope store: production policy rejects local_file backend")
		}
	default:
		return nil, fmt.Errorf("signal envelope store: unsupported backend %q", backend)
	}
	return &envelopeStoreModule{name: name, config: cfg}, nil
}

func (m *envelopeStoreModule) Init() error {
	store := &envelopeStore{
		config: m.config,
		state: envelopeStoreState{
			Version: 1,
			Outbox:  map[string]*envelopeRecord{},
			Inbox:   map[string]*envelopeRecord{},
		},
	}
	if m.config.GetBackend() == envelopeStoreBackendLocalFile {
		if err := store.load(); err != nil {
			return err
		}
	}
	signalEnvelopeStoresMu.Lock()
	signalEnvelopeStores[m.name] = store
	if ref := m.config.GetStoreRef(); ref != "" {
		signalEnvelopeStores[ref] = store
	}
	signalEnvelopeStoresMu.Unlock()
	return nil
}

func lookupSignalEnvelopeStore(ref string) (*envelopeStore, error) {
	if ref == "" {
		return nil, fmt.Errorf("signal envelope store: store_ref is required")
	}
	signalEnvelopeStoresMu.RLock()
	store := signalEnvelopeStores[ref]
	signalEnvelopeStoresMu.RUnlock()
	if store == nil {
		return nil, fmt.Errorf("signal envelope store: %q is not registered", ref)
	}
	return store, nil
}

func envelopeStoreSnapshot(ref string) ([]byte, error) {
	store, err := lookupSignalEnvelopeStore(ref)
	if err != nil {
		return nil, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	return json.Marshal(store.state)
}

func (s *envelopeStore) enqueueOutbox(in *contracts.OutboxEnqueueInput) (*envelopeRecord, error) {
	if in.GetEnvelope() == nil {
		return nil, fmt.Errorf("signal outbox enqueue: envelope is required")
	}
	if len(in.GetEnvelope().GetCiphertext()) == 0 {
		return nil, fmt.Errorf("signal outbox enqueue: ciphertext is required")
	}
	if in.GetCustodyRef() == "" {
		return nil, fmt.Errorf("signal outbox enqueue: custody_ref is required")
	}
	if in.GetAuthzRef() == "" {
		return nil, fmt.Errorf("signal outbox enqueue: authz_ref is required")
	}
	ref := envelopeRef("outbox", in.GetIdempotencyKey(), in.GetSenderRef(), in.GetRecipientRef(), in.GetMessageRef())
	now := envelopeUnixTime(in.GetRequestedAtUnix())
	record := &envelopeRecord{
		Envelope:      cloneSignalEnvelope(in.GetEnvelope()),
		EnvelopeRef:   ref,
		Queue:         "outbox",
		Status:        "queued",
		SenderRef:     in.GetSenderRef(),
		RecipientRef:  in.GetRecipientRef(),
		CustodyRef:    in.GetCustodyRef(),
		AuthzRef:      in.GetAuthzRef(),
		MessageRef:    in.GetMessageRef(),
		CreatedAtUnix: now,
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state.Outbox[ref] = record
	s.enforceRetentionLocked(s.state.Outbox)
	if err := s.persistLocked(); err != nil {
		return nil, err
	}
	return cloneEnvelopeRecord(record), nil
}

func (s *envelopeStore) claimOutbox(in *contracts.OutboxClaimInput) (*envelopeRecord, error) {
	if in.GetEnvelopeRef() == "" {
		return nil, fmt.Errorf("signal outbox claim: envelope_ref is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	record := s.state.Outbox[in.GetEnvelopeRef()]
	if record == nil {
		return nil, fmt.Errorf("signal outbox claim: %q is not queued", in.GetEnvelopeRef())
	}
	record.Status = "claimed"
	record.ClaimedAtUnix = envelopeUnixTime(in.GetRequestedAtUnix())
	record.LeaseRef = "lease://signal/outbox/" + firstNonEmpty(in.GetLeaseId(), in.GetEnvelopeRef())
	if err := s.persistLocked(); err != nil {
		return nil, err
	}
	return cloneEnvelopeRecord(record), nil
}

func (s *envelopeStore) receiveInbox(in *contracts.InboxReceiveInput) (*envelopeRecord, error) {
	if in.GetEnvelope() == nil {
		return nil, fmt.Errorf("signal inbox receive: envelope is required")
	}
	if len(in.GetEnvelope().GetCiphertext()) == 0 {
		return nil, fmt.Errorf("signal inbox receive: ciphertext is required")
	}
	ref := firstNonEmpty(in.GetEnvelopeRef(), envelopeRef("inbox", in.GetIdempotencyKey(), in.GetRecipientRef(), in.GetEnvelope().GetSenderId(), ""))
	record := &envelopeRecord{
		Envelope:       cloneSignalEnvelope(in.GetEnvelope()),
		EnvelopeRef:    ref,
		Queue:          "inbox",
		Status:         "received",
		RecipientRef:   in.GetRecipientRef(),
		ReceivedAtUnix: envelopeUnixTime(in.GetRequestedAtUnix()),
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state.Inbox[ref] = record
	s.enforceRetentionLocked(s.state.Inbox)
	if err := s.persistLocked(); err != nil {
		return nil, err
	}
	return cloneEnvelopeRecord(record), nil
}

func (s *envelopeStore) inbox(ref string) (*envelopeRecord, error) {
	if ref == "" {
		return nil, fmt.Errorf("signal inbox decrypt: envelope_ref is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	record := s.state.Inbox[ref]
	if record == nil {
		return nil, fmt.Errorf("signal inbox decrypt: %q is not received", ref)
	}
	return cloneEnvelopeRecord(record), nil
}

func (s *envelopeStore) load() error {
	raw, err := os.ReadFile(s.config.GetStoragePath())
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("signal envelope store: read storage: %w", err)
	}
	var state envelopeStoreState
	if err := json.Unmarshal(raw, &state); err != nil {
		return fmt.Errorf("signal envelope store: decode storage: %w", err)
	}
	if state.Version != 1 {
		return fmt.Errorf("signal envelope store: unsupported storage version %d", state.Version)
	}
	if state.Outbox == nil {
		state.Outbox = map[string]*envelopeRecord{}
	}
	if state.Inbox == nil {
		state.Inbox = map[string]*envelopeRecord{}
	}
	s.state = state
	return nil
}

func (s *envelopeStore) persistLocked() error {
	if s.config.GetBackend() != envelopeStoreBackendLocalFile {
		return nil
	}
	raw, err := json.MarshalIndent(s.state, "", "  ")
	if err != nil {
		return fmt.Errorf("signal envelope store: encode storage: %w", err)
	}
	path := s.config.GetStoragePath()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("signal envelope store: create storage dir: %w", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return fmt.Errorf("signal envelope store: write storage temp: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("signal envelope store: replace storage: %w", err)
	}
	return nil
}

func (s *envelopeStore) enforceRetentionLocked(queue map[string]*envelopeRecord) {
	limit := int(s.config.GetRetentionLimit())
	if limit <= 0 || len(queue) <= limit {
		return
	}
	for len(queue) > limit {
		var oldestRef string
		var oldest int64
		for ref, record := range queue {
			ts := record.CreatedAtUnix
			if ts == 0 {
				ts = record.ReceivedAtUnix
			}
			if oldestRef == "" || ts < oldest {
				oldestRef = ref
				oldest = ts
			}
		}
		delete(queue, oldestRef)
	}
}

func envelopeMetadata(record *envelopeRecord) *contracts.EnvelopeQueueMetadata {
	if record == nil {
		return nil
	}
	return &contracts.EnvelopeQueueMetadata{
		EnvelopeRef:    record.EnvelopeRef,
		Queue:          record.Queue,
		Status:         record.Status,
		SenderRef:      record.SenderRef,
		RecipientRef:   record.RecipientRef,
		CustodyRef:     record.CustodyRef,
		AuthzRef:       record.AuthzRef,
		MessageRef:     record.MessageRef,
		CreatedAtUnix:  record.CreatedAtUnix,
		ClaimedAtUnix:  record.ClaimedAtUnix,
		ReceivedAtUnix: record.ReceivedAtUnix,
		LeaseRef:       record.LeaseRef,
	}
}

func envelopeRef(queue, idempotencyKey, senderRef, recipientRef, messageRef string) string {
	base := firstNonEmpty(idempotencyKey, messageRef, senderRef+"\x00"+recipientRef)
	base = strings.Trim(base, "/")
	base = strings.NewReplacer("://", "-", "/", "-", "\x00", "-").Replace(base)
	if base == "" {
		base = fmt.Sprint(time.Now().UTC().UnixNano())
	}
	return "signal-envelope://" + queue + "/" + base
}

func envelopeUnixTime(ts int64) int64 {
	if ts != 0 {
		return ts
	}
	return time.Now().UTC().Unix()
}

func cloneSignalEnvelope(in *contracts.SignalEnvelope) *contracts.SignalEnvelope {
	if in == nil {
		return nil
	}
	return &contracts.SignalEnvelope{
		SenderId:          in.GetSenderId(),
		SenderDeviceId:    in.GetSenderDeviceId(),
		RecipientId:       in.GetRecipientId(),
		RecipientDeviceId: in.GetRecipientDeviceId(),
		MessageType:       in.GetMessageType(),
		Ciphertext:        bytes.Clone(in.GetCiphertext()),
	}
}

func cloneEnvelopeRecord(in *envelopeRecord) *envelopeRecord {
	if in == nil {
		return nil
	}
	out := *in
	out.Envelope = cloneSignalEnvelope(in.Envelope)
	return &out
}

func productionPolicyMode(mode string) bool {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "production", "prod":
		return true
	default:
		return false
	}
}
