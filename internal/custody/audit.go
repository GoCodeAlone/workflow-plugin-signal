package custody

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type AuditWriter struct {
	path string
}

type AuditEvent struct {
	Action    string
	RefID     string
	Status    string
	SecretRef string
	Fields    map[string]string
	Time      time.Time
}

func NewAuditWriter(path string) *AuditWriter {
	return &AuditWriter{path: path}
}

func (w *AuditWriter) Append(event AuditEvent) error {
	if err := os.MkdirAll(filepath.Dir(w.path), 0o700); err != nil {
		return err
	}
	row := map[string]any{
		"action": event.Action,
		"ref_id": event.RefID,
		"status": event.Status,
		"ts":     nonZeroTime(event.Time).Format(time.RFC3339Nano),
		"fields": redactFields(event.Fields),
	}
	raw, err := json.Marshal(row)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(w.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.Write(append(raw, '\n')); err != nil {
		return err
	}
	return f.Sync()
}

func redactFields(fields map[string]string) map[string]string {
	out := make(map[string]string, len(fields))
	for key, value := range fields {
		if sensitiveField(key) {
			out[key] = "[redacted]"
			continue
		}
		out[key] = value
	}
	return out
}

func sensitiveField(key string) bool {
	normalized := strings.ToLower(key)
	for _, part := range []string{"private_key", "secret", "token", "credential"} {
		if strings.Contains(normalized, part) {
			return true
		}
	}
	return false
}
