package internal

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	contracts "github.com/GoCodeAlone/workflow-plugin-signal/internal/contracts"
	sealedcustody "github.com/GoCodeAlone/workflow-plugin-signal/internal/custody"
)

const (
	persistentCustodyBackendLocalFile = "local_file"
	persistentCustodyBackendTestFile  = "test_file"
)

var (
	errSignalCustodyTestBackendDenied  = errors.New("signal custody: test backend requires explicit opt-in")
	errSignalCustodyLocalFileDenied    = errors.New("signal custody: local file backend requires explicit development opt-in")
	errSignalCustodyProductionFile     = errors.New("signal custody: production policy rejects file-backed custody")
	errSignalHostSecretResolverMissing = errors.New("signal custody: host secret resolver is not configured")

	signalHostSecretResolverMu sync.RWMutex
	signalHostSecretResolver   func(string) ([]byte, error)

	signalPersistentCustodiesMu sync.RWMutex
	signalPersistentCustodies   = map[string]*persistentCustodyRecord{}

	signalCustodyStoresMu sync.RWMutex
	signalCustodyStores   = map[string]*sealedcustody.Store{}
)

type persistentCustodyModule struct {
	lifecycleModule
	name   string
	config *contracts.PersistentCustodyConfig
}

type custodyStoreModule struct {
	lifecycleModule
	name   string
	config *contracts.CustodyStoreConfig
}

type persistentCustodyRecord struct {
	CustodyRef    string `json:"custody_ref"`
	AccountRef    string `json:"account_ref"`
	Backend       string `json:"backend"`
	KeyHandle     string `json:"key_handle"`
	HostSecretRef string `json:"host_secret_ref"`
	TestBackend   bool   `json:"test_backend"`

	seed []byte
}

type persistentCustodyEnvelope struct {
	Version       int    `json:"version"`
	CustodyRef    string `json:"custody_ref"`
	AccountRef    string `json:"account_ref"`
	Backend       string `json:"backend"`
	KeyHandle     string `json:"key_handle"`
	HostSecretRef string `json:"host_secret_ref"`
	Nonce         string `json:"nonce"`
	Ciphertext    string `json:"ciphertext"`
}

func newPersistentCustodyModule(name string, cfg *contracts.PersistentCustodyConfig) (*persistentCustodyModule, error) {
	if cfg == nil {
		cfg = &contracts.PersistentCustodyConfig{}
	}
	if cfg.GetCustodyRef() == "" {
		return nil, fmt.Errorf("signal persistent custody: custody_ref is required")
	}
	if cfg.GetAccountRef() == "" {
		return nil, fmt.Errorf("signal persistent custody: account_ref is required")
	}
	if cfg.GetStoragePath() == "" {
		return nil, fmt.Errorf("signal persistent custody: storage_path is required")
	}
	if cfg.GetKeyHandle() == "" {
		return nil, fmt.Errorf("signal persistent custody: key_handle is required")
	}
	if cfg.GetHostSecretRef() == "" {
		return nil, fmt.Errorf("signal persistent custody: host_secret_ref is required")
	}
	switch cfg.GetBackend() {
	case persistentCustodyBackendLocalFile:
		if productionPolicyMode(cfg.GetPolicyMode()) {
			return nil, errSignalCustodyProductionFile
		}
		if !cfg.GetAllowLocalFileCustody() {
			return nil, errSignalCustodyLocalFileDenied
		}
	case persistentCustodyBackendTestFile:
		if productionPolicyMode(cfg.GetPolicyMode()) {
			return nil, errSignalCustodyProductionFile
		}
		if !cfg.GetAllowTestBackend() {
			return nil, errSignalCustodyTestBackendDenied
		}
	default:
		return nil, fmt.Errorf("signal persistent custody: unsupported backend %q", cfg.GetBackend())
	}
	return &persistentCustodyModule{name: name, config: cfg}, nil
}

func newCustodyStoreModule(name string, cfg *contracts.CustodyStoreConfig) (*custodyStoreModule, error) {
	if cfg == nil {
		cfg = &contracts.CustodyStoreConfig{}
	}
	if cfg.GetBackendId() == "" {
		return nil, fmt.Errorf("signal custody store: backend_id is required")
	}
	if cfg.GetStoragePath() == "" {
		return nil, fmt.Errorf("signal custody store: storage_path is required")
	}
	if cfg.GetKekRef() == "" {
		return nil, fmt.Errorf("signal custody store: kek_ref is required")
	}
	if cfg.GetKekVersion() == "" {
		return nil, fmt.Errorf("signal custody store: kek_version is required")
	}
	switch cfg.GetBackend() {
	case persistentCustodyBackendLocalFile:
		if productionPolicyMode(cfg.GetPolicyMode()) {
			return nil, errSignalCustodyProductionFile
		}
		if !cfg.GetAllowLocalFileCustody() {
			return nil, errSignalCustodyLocalFileDenied
		}
	case persistentCustodyBackendTestFile:
		if productionPolicyMode(cfg.GetPolicyMode()) {
			return nil, errSignalCustodyProductionFile
		}
		if !cfg.GetAllowTestBackend() {
			return nil, errSignalCustodyTestBackendDenied
		}
	default:
		return nil, fmt.Errorf("signal custody store: unsupported backend %q", cfg.GetBackend())
	}
	return &custodyStoreModule{name: name, config: cfg}, nil
}

func productionPolicyMode(mode string) bool {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "production", "prod":
		return true
	default:
		return false
	}
}

func (m *custodyStoreModule) Init() error {
	store, err := sealedcustody.NewSealedStore(sealedcustody.Config{
		BackendID:     m.config.GetBackendId(),
		StorageDir:    m.config.GetStoragePath(),
		KEKRef:        m.config.GetKekRef(),
		KEKVersion:    m.config.GetKekVersion(),
		SchemaVersion: m.config.GetSchemaVersion(),
		ResolveSecret: resolveSignalHostSecret,
	})
	if err != nil {
		return err
	}
	signalCustodyStoresMu.Lock()
	signalCustodyStores[m.name] = store
	signalCustodyStoresMu.Unlock()
	return nil
}

func lookupSignalCustodyStore(ref string) (*sealedcustody.Store, error) {
	if ref == "" {
		return nil, fmt.Errorf("signal custody store: store_ref is required")
	}
	signalCustodyStoresMu.RLock()
	store := signalCustodyStores[ref]
	signalCustodyStoresMu.RUnlock()
	if store == nil {
		return nil, fmt.Errorf("signal custody store: %q is not registered", ref)
	}
	return store, nil
}

func (m *persistentCustodyModule) Init() error {
	secret, err := resolveSignalHostSecret(m.config.GetHostSecretRef())
	if err != nil {
		return err
	}
	key := sha256.Sum256(secret)
	seed, err := loadOrCreatePersistentCustodySeed(m.config, key[:])
	if err != nil {
		return err
	}
	record := &persistentCustodyRecord{
		CustodyRef:    m.config.GetCustodyRef(),
		AccountRef:    m.config.GetAccountRef(),
		Backend:       m.config.GetBackend(),
		KeyHandle:     m.config.GetKeyHandle(),
		HostSecretRef: m.config.GetHostSecretRef(),
		TestBackend:   m.config.GetBackend() == persistentCustodyBackendTestFile,
		seed:          seed,
	}

	signalPersistentCustodiesMu.Lock()
	signalPersistentCustodies[record.CustodyRef] = record
	signalPersistentCustodiesMu.Unlock()

	signalCustodiesMu.Lock()
	signalCustodies[record.CustodyRef] = &signalKeyCustody{
		ref:                 record.CustodyRef,
		accountRef:          record.AccountRef,
		nonExportableKeyRef: record.KeyHandle,
	}
	signalCustodiesMu.Unlock()
	return nil
}

func loadOrCreatePersistentCustodySeed(cfg *contracts.PersistentCustodyConfig, key []byte) ([]byte, error) {
	if raw, err := os.ReadFile(cfg.GetStoragePath()); err == nil {
		return decryptPersistentCustodySeed(raw, cfg, key)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("signal persistent custody: read storage: %w", err)
	}

	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		return nil, fmt.Errorf("signal persistent custody: seed: %w", err)
	}
	raw, err := encryptPersistentCustodySeed(seed, cfg, key)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(cfg.GetStoragePath()), 0o700); err != nil {
		return nil, fmt.Errorf("signal persistent custody: create storage dir: %w", err)
	}
	if err := os.WriteFile(cfg.GetStoragePath(), raw, 0o600); err != nil {
		return nil, fmt.Errorf("signal persistent custody: write storage: %w", err)
	}
	return seed, nil
}

func encryptPersistentCustodySeed(seed []byte, cfg *contracts.PersistentCustodyConfig, key []byte) ([]byte, error) {
	gcm, err := persistentCustodyAEAD(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("signal persistent custody: nonce: %w", err)
	}
	env := persistentCustodyEnvelope{
		Version:       1,
		CustodyRef:    cfg.GetCustodyRef(),
		AccountRef:    cfg.GetAccountRef(),
		Backend:       cfg.GetBackend(),
		KeyHandle:     cfg.GetKeyHandle(),
		HostSecretRef: cfg.GetHostSecretRef(),
		Nonce:         base64.StdEncoding.EncodeToString(nonce),
		Ciphertext:    base64.StdEncoding.EncodeToString(gcm.Seal(nil, nonce, seed, persistentCustodyAAD(cfg))),
	}
	raw, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("signal persistent custody: marshal storage: %w", err)
	}
	return raw, nil
}

func decryptPersistentCustodySeed(raw []byte, cfg *contracts.PersistentCustodyConfig, key []byte) ([]byte, error) {
	var env persistentCustodyEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, fmt.Errorf("signal persistent custody: decode storage: %w", err)
	}
	if env.Version != 1 {
		return nil, fmt.Errorf("signal persistent custody: unsupported storage version %d", env.Version)
	}
	if env.CustodyRef != cfg.GetCustodyRef() || env.AccountRef != cfg.GetAccountRef() || env.KeyHandle != cfg.GetKeyHandle() || env.HostSecretRef != cfg.GetHostSecretRef() {
		return nil, fmt.Errorf("signal persistent custody: storage refs do not match config")
	}
	gcm, err := persistentCustodyAEAD(key)
	if err != nil {
		return nil, err
	}
	nonce, err := base64.StdEncoding.DecodeString(env.Nonce)
	if err != nil {
		return nil, fmt.Errorf("signal persistent custody: nonce decode: %w", err)
	}
	ciphertext, err := base64.StdEncoding.DecodeString(env.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("signal persistent custody: ciphertext decode: %w", err)
	}
	seed, err := gcm.Open(nil, nonce, ciphertext, persistentCustodyAAD(cfg))
	if err != nil {
		return nil, fmt.Errorf("signal persistent custody: decrypt storage: %w", err)
	}
	return seed, nil
}

func persistentCustodyAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("signal persistent custody: aead: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("signal persistent custody: gcm: %w", err)
	}
	return gcm, nil
}

func persistentCustodyAAD(cfg *contracts.PersistentCustodyConfig) []byte {
	return []byte(cfg.GetCustodyRef() + "\x00" + cfg.GetAccountRef() + "\x00" + cfg.GetKeyHandle() + "\x00" + cfg.GetHostSecretRef())
}

func lookupPersistentCustodyMetadata(ref string) (persistentCustodyRecord, error) {
	signalPersistentCustodiesMu.RLock()
	record := signalPersistentCustodies[ref]
	signalPersistentCustodiesMu.RUnlock()
	if record == nil {
		return persistentCustodyRecord{}, fmt.Errorf("signal persistent custody: %q is not registered", ref)
	}
	return persistentCustodyRecord{
		CustodyRef:    record.CustodyRef,
		AccountRef:    record.AccountRef,
		Backend:       record.Backend,
		KeyHandle:     record.KeyHandle,
		HostSecretRef: record.HostSecretRef,
		TestBackend:   record.TestBackend,
	}, nil
}

func derivePersistentCustodyKey(ref, label string) ([]byte, error) {
	if label == "" {
		return nil, fmt.Errorf("signal persistent custody: label is required")
	}
	signalPersistentCustodiesMu.RLock()
	record := signalPersistentCustodies[ref]
	signalPersistentCustodiesMu.RUnlock()
	if record == nil {
		return nil, fmt.Errorf("signal persistent custody: %q is not registered", ref)
	}
	mac := hmac.New(sha256.New, record.seed)
	_, _ = mac.Write([]byte(label))
	return mac.Sum(nil), nil
}

func resolveSignalHostSecret(ref string) ([]byte, error) {
	signalHostSecretResolverMu.RLock()
	resolver := signalHostSecretResolver
	signalHostSecretResolverMu.RUnlock()
	if resolver == nil {
		if strings.HasPrefix(ref, "test://signal/") {
			sum := sha256.Sum256([]byte("workflow-plugin-signal-test-secret\x00" + ref))
			return sum[:], nil
		}
		return nil, errSignalHostSecretResolverMissing
	}
	secret, err := resolver(ref)
	if err != nil {
		return nil, err
	}
	if len(secret) == 0 {
		return nil, fmt.Errorf("signal persistent custody: host secret %q is empty", ref)
	}
	return append([]byte(nil), secret...), nil
}

func setSignalHostSecretResolverForTest(secrets map[string][]byte) func() {
	snapshot := make(map[string][]byte, len(secrets))
	for ref, secret := range secrets {
		snapshot[ref] = append([]byte(nil), secret...)
	}
	signalHostSecretResolverMu.Lock()
	previous := signalHostSecretResolver
	signalHostSecretResolver = func(ref string) ([]byte, error) {
		secret, ok := snapshot[ref]
		if !ok {
			return nil, fmt.Errorf("signal persistent custody: host secret %q is not registered", ref)
		}
		return append([]byte(nil), secret...), nil
	}
	signalHostSecretResolverMu.Unlock()
	return func() {
		signalHostSecretResolverMu.Lock()
		signalHostSecretResolver = previous
		signalHostSecretResolverMu.Unlock()
	}
}
