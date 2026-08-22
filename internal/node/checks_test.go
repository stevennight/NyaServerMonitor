package node

import (
	"os"
	"testing"
)

func TestLoadChecksRejectsUnknownTypes(t *testing.T) {
	path := t.TempDir() + "/checks.json"
	if err := os.WriteFile(path, []byte(`[{"id":"x","name":"x","type":"shell","target":"id"}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadChecks(path); err == nil {
		t.Fatal("shell checks must be rejected")
	}
}
