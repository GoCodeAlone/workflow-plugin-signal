package custody

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestAuditJSONLRedactsKeyTokenAndCredentialMaterial(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	writer := NewAuditWriter(path)
	if err := writer.Append(AuditEvent{
		Action:    "create",
		RefID:     "custody-a",
		Status:    "ok",
		SecretRef: "secret://signal/kek",
		Fields: map[string]string{
			"private_key": "raw-private-key",
			"token":       "raw-token",
			"credential":  "raw-credential",
			"safe_ref":    "custody-a",
		},
	}); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range [][]byte{
		[]byte("raw-private-key"),
		[]byte("raw-token"),
		[]byte("raw-credential"),
		[]byte("secret://signal/kek"),
	} {
		if bytes.Contains(raw, forbidden) {
			t.Fatalf("audit leaked secret material %q in %s", forbidden, raw)
		}
	}
	if !bytes.Contains(raw, []byte("custody-a")) {
		t.Fatalf("audit should retain safe refs: %s", raw)
	}
}
