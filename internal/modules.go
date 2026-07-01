package internal

import (
	"context"
	"crypto/rand"
	"fmt"
	"sync"

	"github.com/GoCodeAlone/libsignal-go/curve"
	"github.com/GoCodeAlone/libsignal-go/kem"
	"github.com/GoCodeAlone/libsignal-go/stores/inmem"

	contracts "github.com/GoCodeAlone/workflow-plugin-signal/internal/contracts"
)

type lifecycleModule struct{}

func (m *lifecycleModule) Init() error { return nil }

func (m *lifecycleModule) Start(context.Context) error { return nil }

func (m *lifecycleModule) Stop(context.Context) error { return nil }

type identityStoreModule struct {
	lifecycleModule
	name   string
	config *contracts.IdentityStoreConfig
}

func newIdentityStoreModule(name string, cfg *contracts.IdentityStoreConfig) *identityStoreModule {
	return &identityStoreModule{name: name, config: cfg}
}

func (m *identityStoreModule) Init() error {
	identity, err := newSignalIdentity(m.config)
	if err != nil {
		return err
	}
	signalIdentitiesMu.Lock()
	signalIdentities[identity.ref] = identity
	signalIdentitiesMu.Unlock()
	return nil
}

type spaceModule struct {
	lifecycleModule
	name   string
	config *contracts.SpaceConfig
}

func newSpaceModule(name string, cfg *contracts.SpaceConfig) *spaceModule {
	return &spaceModule{name: name, config: cfg}
}

type envelopeTriggerModule struct {
	lifecycleModule
	name   string
	config *contracts.EnvelopeTriggerConfig
}

func newEnvelopeTriggerModule(name string, cfg *contracts.EnvelopeTriggerConfig) *envelopeTriggerModule {
	return &envelopeTriggerModule{name: name, config: cfg}
}

type officialServiceBoundaryModule struct {
	lifecycleModule
	name   string
	config *contracts.OfficialServiceBoundaryConfig
}

func newOfficialServiceBoundaryModule(name string, cfg *contracts.OfficialServiceBoundaryConfig) (*officialServiceBoundaryModule, error) {
	if err := validateServiceBoundaryMode(cfg.GetMode()); err != nil {
		return nil, err
	}
	return &officialServiceBoundaryModule{name: name, config: cfg}, nil
}

type serviceEnvelopeTriggerModule struct {
	lifecycleModule
	name   string
	config *contracts.ServiceEnvelopeTriggerConfig
}

type livePolicyModule struct {
	lifecycleModule
	name   string
	config *contracts.LivePolicyConfig
}

func newServiceEnvelopeTriggerModule(name string, cfg *contracts.ServiceEnvelopeTriggerConfig) *serviceEnvelopeTriggerModule {
	return &serviceEnvelopeTriggerModule{name: name, config: cfg}
}

func newLivePolicyModule(name string, cfg *contracts.LivePolicyConfig) (*livePolicyModule, error) {
	if cfg == nil {
		cfg = &contracts.LivePolicyConfig{}
	}
	if err := validateServiceBoundaryMode(cfg.GetMode()); err != nil {
		return nil, err
	}
	return &livePolicyModule{name: name, config: cfg}, nil
}

type signalIdentity struct {
	ref            string
	localID        string
	deviceID       uint32
	registrationID uint32

	identity  curve.KeyPair
	signedPre curve.KeyPair
	oneTime   curve.KeyPair
	kyber     kem.KeyPair

	preKeyID       uint32
	signedPreKeyID uint32
	kyberPreKeyID  uint32

	identityStore *inmem.IdentityKeyStore
	sessionStore  *inmem.SessionStore
}

var (
	signalIdentitiesMu sync.RWMutex
	signalIdentities   = map[string]*signalIdentity{}
)

func newSignalIdentity(cfg *contracts.IdentityStoreConfig) (*signalIdentity, error) {
	if cfg == nil {
		cfg = &contracts.IdentityStoreConfig{}
	}
	ref := cfg.GetIdentityRef()
	if ref == "" {
		return nil, fmt.Errorf("signal identity store: identity_ref is required")
	}
	localID := cfg.GetLocalId()
	if localID == "" {
		localID = ref
	}
	deviceID := cfg.GetDeviceId()
	if deviceID == 0 {
		deviceID = 1
	}
	registrationID := cfg.GetRegistrationId()
	if registrationID == 0 {
		registrationID = 1
	}

	identity, err := curve.GenerateKeyPair(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("signal identity store: identity key: %w", err)
	}
	signedPre, err := curve.GenerateKeyPair(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("signal identity store: signed pre-key: %w", err)
	}
	oneTime, err := curve.GenerateKeyPair(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("signal identity store: one-time pre-key: %w", err)
	}
	kyber, err := kem.GenerateKeyPair(kem.KeyTypeKyber1024, rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("signal identity store: kyber pre-key: %w", err)
	}

	return &signalIdentity{
		ref:            ref,
		localID:        localID,
		deviceID:       deviceID,
		registrationID: registrationID,
		identity:       identity,
		signedPre:      signedPre,
		oneTime:        oneTime,
		kyber:          kyber,
		preKeyID:       1,
		signedPreKeyID: 2,
		kyberPreKeyID:  3,
		identityStore:  inmem.NewIdentityKeyStore(identity, registrationID),
		sessionStore:   inmem.NewSessionStore(),
	}, nil
}

func lookupSignalIdentity(ref string) (*signalIdentity, error) {
	if ref == "" {
		return nil, fmt.Errorf("signal identity: identity_ref is required")
	}
	signalIdentitiesMu.RLock()
	identity := signalIdentities[ref]
	signalIdentitiesMu.RUnlock()
	if identity == nil {
		return nil, fmt.Errorf("signal identity: %q is not registered", ref)
	}
	return identity, nil
}
