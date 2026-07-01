package custody

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	StateActive  = "active"
	StateRevoked = "revoked"
)

var (
	ErrPartialBundle   = errors.New("partial sealed custody bundle")
	ErrStaleKEKVersion = errors.New("stale KEK version")
	ErrRotateConflict  = errors.New("custody rotate conflict")
	ErrRevokedRef      = errors.New("revoked custody ref")
)

type SecretResolver func(string) ([]byte, error)

type Config struct {
	BackendID     string
	StorageDir    string
	KEKRef        string
	KEKVersion    string
	SchemaVersion uint32
	ResolveSecret SecretResolver
}

type Store struct {
	cfg Config
	mu  sync.Mutex
}

type Metadata struct {
	BackendID     string    `json:"backend_id"`
	RefID         string    `json:"ref_id"`
	SchemaVersion uint32    `json:"schema_version"`
	KEKRef        string    `json:"kek_ref"`
	KEKVersion    string    `json:"kek_version"`
	CreatedAt     time.Time `json:"created_at"`
	RotatedAt     time.Time `json:"rotated_at"`
	RevokedAt     time.Time `json:"revoked_at,omitempty"`
	State         string    `json:"state"`
	AccountRef    string    `json:"account_ref,omitempty"`
	DeviceRef     string    `json:"device_ref,omitempty"`
}

type CreateRequest struct {
	RefID      string
	AccountRef string
	DeviceRef  string
	Material   map[string][]byte
	Now        time.Time
}

type RotateRequest struct {
	RefID              string
	ExpectedKekVersion string
	NewKekRef          string
	NewKekVersion      string
	Now                time.Time
}

type sealedBundle struct {
	Metadata   Metadata `json:"metadata"`
	Nonce      string   `json:"nonce"`
	Ciphertext string   `json:"ciphertext"`
}

func NewSealedStore(cfg Config) (*Store, error) {
	if cfg.BackendID == "" {
		return nil, fmt.Errorf("sealed custody: backend_id is required")
	}
	if cfg.StorageDir == "" {
		return nil, fmt.Errorf("sealed custody: storage_dir is required")
	}
	if cfg.KEKRef == "" {
		return nil, fmt.Errorf("sealed custody: kek_ref is required")
	}
	if cfg.KEKVersion == "" {
		return nil, fmt.Errorf("sealed custody: kek_version is required")
	}
	if cfg.SchemaVersion == 0 {
		cfg.SchemaVersion = 1
	}
	if cfg.ResolveSecret == nil {
		return nil, fmt.Errorf("sealed custody: secret resolver is required")
	}
	return &Store{cfg: cfg}, nil
}

func (s *Store) Config() Config {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cfg
}

func (s *Store) Create(req CreateRequest) (Metadata, error) {
	if req.RefID == "" {
		return Metadata{}, fmt.Errorf("sealed custody: ref_id is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := nonZeroTime(req.Now)
	cfg := s.cfg
	meta := Metadata{
		BackendID:     cfg.BackendID,
		RefID:         req.RefID,
		SchemaVersion: cfg.SchemaVersion,
		KEKRef:        cfg.KEKRef,
		KEKVersion:    cfg.KEKVersion,
		CreatedAt:     now,
		RotatedAt:     now,
		State:         StateActive,
		AccountRef:    req.AccountRef,
		DeviceRef:     req.DeviceRef,
	}
	if err := s.writeBundleLocked(cfg, meta, req.Material); err != nil {
		return Metadata{}, err
	}
	return meta, nil
}

func (s *Store) Restore(refID string) (Metadata, error) {
	if refID == "" {
		return Metadata{}, fmt.Errorf("sealed custody: ref_id is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	bundle, _, err := s.readBundleLocked(s.cfg, refID)
	if err != nil {
		return Metadata{}, err
	}
	if bundle.Metadata.State == StateRevoked {
		return Metadata{}, ErrRevokedRef
	}
	return bundle.Metadata, nil
}

func (s *Store) Inspect(refID string) (Metadata, error) {
	if refID == "" {
		return Metadata{}, fmt.Errorf("sealed custody: ref_id is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	bundle, _, err := s.readBundleLocked(s.cfg, refID)
	if err != nil {
		return Metadata{}, err
	}
	return bundle.Metadata, nil
}

func (s *Store) Rotate(req RotateRequest) (Metadata, error) {
	if req.RefID == "" {
		return Metadata{}, fmt.Errorf("sealed custody: ref_id is required")
	}
	if req.ExpectedKekVersion == "" {
		return Metadata{}, fmt.Errorf("sealed custody: expected_kek_version is required")
	}
	if req.NewKekVersion == "" {
		return Metadata{}, fmt.Errorf("sealed custody: new_kek_version is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	cfg := s.cfg
	bundle, material, err := s.readBundleLocked(cfg, req.RefID)
	if err != nil {
		return Metadata{}, err
	}
	if bundle.Metadata.State == StateRevoked {
		return Metadata{}, ErrRevokedRef
	}
	if bundle.Metadata.KEKVersion != req.ExpectedKekVersion {
		return Metadata{}, ErrRotateConflict
	}
	newKekRef := req.NewKekRef
	if newKekRef == "" {
		newKekRef = cfg.KEKRef
	}
	cfg.KEKRef = newKekRef
	cfg.KEKVersion = req.NewKekVersion
	bundle.Metadata.KEKRef = newKekRef
	bundle.Metadata.KEKVersion = req.NewKekVersion
	bundle.Metadata.RotatedAt = nonZeroTime(req.Now)
	if err := s.writeBundleLocked(cfg, bundle.Metadata, material); err != nil {
		return Metadata{}, err
	}
	s.cfg = cfg
	return bundle.Metadata, nil
}

func (s *Store) Revoke(refID string, now time.Time) (Metadata, error) {
	if refID == "" {
		return Metadata{}, fmt.Errorf("sealed custody: ref_id is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	bundle, material, err := s.readBundleLocked(s.cfg, refID)
	if err != nil {
		return Metadata{}, err
	}
	bundle.Metadata.State = StateRevoked
	bundle.Metadata.RevokedAt = nonZeroTime(now)
	if err := s.writeBundleLocked(s.cfg, bundle.Metadata, material); err != nil {
		return Metadata{}, err
	}
	return bundle.Metadata, nil
}

func (s *Store) readBundleLocked(cfg Config, refID string) (sealedBundle, map[string][]byte, error) {
	raw, err := os.ReadFile(pathFor(cfg.StorageDir, refID))
	if err != nil {
		return sealedBundle{}, nil, err
	}
	var bundle sealedBundle
	if err := json.Unmarshal(raw, &bundle); err != nil {
		return sealedBundle{}, nil, ErrPartialBundle
	}
	if bundle.Metadata.KEKRef != cfg.KEKRef || bundle.Metadata.KEKVersion != cfg.KEKVersion {
		return sealedBundle{}, nil, ErrStaleKEKVersion
	}
	material, err := s.decryptMaterial(cfg, bundle)
	if err != nil {
		return sealedBundle{}, nil, err
	}
	return bundle, material, nil
}

func (s *Store) writeBundleLocked(cfg Config, meta Metadata, material map[string][]byte) error {
	if err := os.MkdirAll(cfg.StorageDir, 0o700); err != nil {
		return err
	}
	nonce, ciphertext, err := s.encryptMaterial(cfg, meta, material)
	if err != nil {
		return err
	}
	raw, err := json.MarshalIndent(sealedBundle{
		Metadata:   meta,
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
		Ciphertext: base64.StdEncoding.EncodeToString(ciphertext),
	}, "", "  ")
	if err != nil {
		return err
	}
	path := pathFor(cfg.StorageDir, meta.RefID)
	tmp, err := os.CreateTemp(cfg.StorageDir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(raw); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

func (s *Store) encryptMaterial(cfg Config, meta Metadata, material map[string][]byte) ([]byte, []byte, error) {
	gcm, err := aead(cfg)
	if err != nil {
		return nil, nil, err
	}
	plain, err := json.Marshal(material)
	if err != nil {
		return nil, nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, err
	}
	return nonce, gcm.Seal(nil, nonce, plain, aad(meta)), nil
}

func (s *Store) decryptMaterial(cfg Config, bundle sealedBundle) (map[string][]byte, error) {
	gcm, err := aead(cfg)
	if err != nil {
		return nil, err
	}
	nonce, err := base64.StdEncoding.DecodeString(bundle.Nonce)
	if err != nil {
		return nil, ErrPartialBundle
	}
	ciphertext, err := base64.StdEncoding.DecodeString(bundle.Ciphertext)
	if err != nil {
		return nil, ErrPartialBundle
	}
	plain, err := gcm.Open(nil, nonce, ciphertext, aad(bundle.Metadata))
	if err != nil {
		return nil, err
	}
	var material map[string][]byte
	if err := json.Unmarshal(plain, &material); err != nil {
		return nil, ErrPartialBundle
	}
	return material, nil
}

func aead(cfg Config) (cipher.AEAD, error) {
	secret, err := cfg.ResolveSecret(cfg.KEKRef)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(secret)
	block, err := aes.NewCipher(sum[:])
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func (s *Store) path(refID string) string {
	return pathFor(s.cfg.StorageDir, refID)
}

func pathFor(storageDir, refID string) string {
	sum := sha256.Sum256([]byte(refID))
	return filepath.Join(storageDir, hex.EncodeToString(sum[:16])+".json")
}

func aad(meta Metadata) []byte {
	return []byte(meta.BackendID + "\x00" + meta.RefID + "\x00" + meta.KEKRef + "\x00" + meta.KEKVersion)
}

func nonZeroTime(t time.Time) time.Time {
	if t.IsZero() {
		return time.Now().UTC()
	}
	return t.UTC()
}

func (m Metadata) MarshalJSON() ([]byte, error) {
	type metadata Metadata
	return json.Marshal(metadata(m))
}
