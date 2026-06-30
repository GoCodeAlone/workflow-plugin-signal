package internal

import (
	"errors"
	"testing"

	contracts "github.com/GoCodeAlone/workflow-plugin-signal/internal/contracts"
)

func TestKeyCustodyRequiresHostManagedRefs(t *testing.T) {
	t.Cleanup(resetServiceTestState)

	_, err := newKeyCustodyModule("custody", &contracts.KeyCustodyConfig{
		CustodyRef: "custody-a",
		AccountRef: "account-a",
		SecretRefs: []string{"host-secret/exportable"},
	})
	if !errors.Is(err, errExportableCustodyRefDenied) {
		t.Fatalf("exportable secret ref error = %v, want %v", err, errExportableCustodyRefDenied)
	}

	custody, err := newKeyCustodyModule("custody", &contracts.KeyCustodyConfig{
		CustodyRef:                "custody-a",
		AccountRef:                "account-a",
		NonExportableKeyRef:       "kms://signal/account-a/device-1",
		AllowExportableSecretRefs: false,
	})
	if err != nil {
		t.Fatalf("newKeyCustodyModule: %v", err)
	}
	if err := custody.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}

	account, err := newAccountRefModule("account", &contracts.AccountRefConfig{
		AccountRef:    "account-a",
		DeviceRef:     "device-1",
		CustodyRef:    "custody-a",
		CredentialRef: "secret://signal/credential",
		ConsentRef:    "consent://case/1",
		AuditRef:      "audit://case/1",
	})
	if err != nil {
		t.Fatalf("newAccountRefModule: %v", err)
	}
	if err := account.Init(); err != nil {
		t.Fatalf("account Init: %v", err)
	}

	got, err := lookupSignalAccountRef("account-a")
	if err != nil {
		t.Fatalf("lookup account: %v", err)
	}
	if got.custody.nonExportableKeyRef != "kms://signal/account-a/device-1" {
		t.Fatalf("non-exportable key ref = %q", got.custody.nonExportableKeyRef)
	}
}

func TestAccountRefRejectsUnknownCustody(t *testing.T) {
	t.Cleanup(resetServiceTestState)

	account, err := newAccountRefModule("account", &contracts.AccountRefConfig{
		AccountRef: "account-a",
		CustodyRef: "missing",
	})
	if err != nil {
		t.Fatalf("newAccountRefModule: %v", err)
	}
	if err := account.Init(); err == nil {
		t.Fatal("expected missing custody error")
	}
}
