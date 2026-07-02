package internal

import (
	"errors"
	"fmt"
	"sync"

	contracts "github.com/GoCodeAlone/workflow-plugin-signal/internal/contracts"
)

var (
	errExportableCustodyRefDenied = errors.New("exportable Signal custody secret refs require explicit opt-in")

	signalCustodiesMu sync.RWMutex
	signalCustodies   = map[string]*signalKeyCustody{}

	signalAccountsMu sync.RWMutex
	signalAccounts   = map[string]*signalAccountRef{}
)

type keyCustodyModule struct {
	lifecycleModule
	name   string
	config *contracts.KeyCustodyConfig
}

type accountRefModule struct {
	lifecycleModule
	name   string
	config *contracts.AccountRefConfig
}

type signalKeyCustody struct {
	ref                 string
	accountRef          string
	secretRefs          []string
	nonExportableKeyRef string
}

type signalAccountRef struct {
	ref           string
	deviceRef     string
	custodyRef    string
	credentialRef string
	consentRef    string
	auditRef      string
	custody       *signalKeyCustody
}

func newKeyCustodyModule(name string, cfg *contracts.KeyCustodyConfig) (*keyCustodyModule, error) {
	if cfg == nil {
		cfg = &contracts.KeyCustodyConfig{}
	}
	if cfg.GetCustodyRef() == "" {
		return nil, fmt.Errorf("signal key custody: custody_ref is required")
	}
	if cfg.GetAccountRef() == "" {
		return nil, fmt.Errorf("signal key custody: account_ref is required")
	}
	if len(cfg.GetSecretRefs()) > 0 && !cfg.GetAllowExportableSecretRefs() {
		return nil, errExportableCustodyRefDenied
	}
	if cfg.GetNonExportableKeyRef() == "" && len(cfg.GetSecretRefs()) == 0 {
		return nil, fmt.Errorf("signal key custody: non_exportable_key_ref or secret_refs is required")
	}
	return &keyCustodyModule{name: name, config: cfg}, nil
}

func (m *keyCustodyModule) Init() error {
	custody := &signalKeyCustody{
		ref:                 m.config.GetCustodyRef(),
		accountRef:          m.config.GetAccountRef(),
		secretRefs:          append([]string(nil), m.config.GetSecretRefs()...),
		nonExportableKeyRef: m.config.GetNonExportableKeyRef(),
	}
	signalCustodiesMu.Lock()
	signalCustodies[custody.ref] = custody
	signalCustodiesMu.Unlock()
	return nil
}

func newAccountRefModule(name string, cfg *contracts.AccountRefConfig) (*accountRefModule, error) {
	if cfg == nil {
		cfg = &contracts.AccountRefConfig{}
	}
	if cfg.GetAccountRef() == "" {
		return nil, fmt.Errorf("signal account ref: account_ref is required")
	}
	return &accountRefModule{name: name, config: cfg}, nil
}

func (m *accountRefModule) Init() error {
	var custody *signalKeyCustody
	custodyRef := m.config.GetCustodyRef()
	if custodyRef != "" {
		var ok bool
		custody, ok = registeredSignalKeyCustody(custodyRef)
		if !ok {
			custody = nil
		} else if custody.accountRef != "" && custody.accountRef != m.config.GetAccountRef() {
			return fmt.Errorf("signal account ref: custody %q belongs to account %q", custody.ref, custody.accountRef)
		}
	}
	account := &signalAccountRef{
		ref:           m.config.GetAccountRef(),
		deviceRef:     m.config.GetDeviceRef(),
		custodyRef:    custodyRef,
		credentialRef: m.config.GetCredentialRef(),
		consentRef:    m.config.GetConsentRef(),
		auditRef:      m.config.GetAuditRef(),
		custody:       custody,
	}
	signalAccountsMu.Lock()
	signalAccounts[account.ref] = account
	signalAccountsMu.Unlock()
	return nil
}

func lookupSignalKeyCustody(ref string) (*signalKeyCustody, error) {
	if ref == "" {
		return nil, fmt.Errorf("signal key custody: custody_ref is required")
	}
	signalCustodiesMu.RLock()
	custody := signalCustodies[ref]
	signalCustodiesMu.RUnlock()
	if custody == nil {
		return nil, fmt.Errorf("signal key custody: %q is not registered", ref)
	}
	return custody, nil
}

func registeredSignalKeyCustody(ref string) (*signalKeyCustody, bool) {
	if ref == "" {
		return nil, false
	}
	signalCustodiesMu.RLock()
	custody := signalCustodies[ref]
	signalCustodiesMu.RUnlock()
	return custody, custody != nil
}

func lookupSignalAccountRef(ref string) (*signalAccountRef, error) {
	if ref == "" {
		return nil, fmt.Errorf("signal account ref: account_ref is required")
	}
	signalAccountsMu.RLock()
	account := signalAccounts[ref]
	signalAccountsMu.RUnlock()
	if account == nil {
		return nil, fmt.Errorf("signal account ref: %q is not registered", ref)
	}
	return account, nil
}

func registeredSignalAccountRef(ref string) (*signalAccountRef, bool) {
	if ref == "" {
		return nil, false
	}
	signalAccountsMu.RLock()
	account := signalAccounts[ref]
	signalAccountsMu.RUnlock()
	return account, account != nil
}

func resetServiceTestState() {
	signalCustodiesMu.Lock()
	clear(signalCustodies)
	signalCustodiesMu.Unlock()
	signalAccountsMu.Lock()
	clear(signalAccounts)
	signalAccountsMu.Unlock()
	signalPersistentCustodiesMu.Lock()
	clear(signalPersistentCustodies)
	signalPersistentCustodiesMu.Unlock()
	signalCustodyStoresMu.Lock()
	clear(signalCustodyStores)
	signalCustodyStoresMu.Unlock()
	signalServiceTestLedgerMu.Lock()
	clear(signalServiceTestLedger)
	signalServiceTestLedgerMu.Unlock()
	signalServiceTransportsMu.Lock()
	clear(signalServiceTransports)
	signalServiceTransportsMu.Unlock()
	linkedDeviceCeremoniesMu.Lock()
	clear(linkedDeviceCeremonyClaims)
	linkedDeviceCeremoniesMu.Unlock()
}
