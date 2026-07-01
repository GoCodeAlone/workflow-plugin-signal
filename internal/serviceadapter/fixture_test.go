package serviceadapter

import (
	"context"
	"errors"
	"testing"

	"github.com/GoCodeAlone/libsignal-service-go/service"
	"github.com/GoCodeAlone/libsignal-service-go/servicepolicy"
)

func TestOperatorFixtureUsesAllowlistedLiveAdapter(t *testing.T) {
	adapter, err := NewOperatorFixture(OperatorFixtureConfig{Endpoint: "127.0.0.1:19091"})
	if err != nil {
		t.Fatalf("fixture adapter: %v", err)
	}
	result, err := adapter.SubmitOperation(context.Background(), service.OperationEnvelope{
		OperationID:    "op://register/1",
		Operation:      service.OperationRegister,
		IdempotencyKey: "register-1",
		AccountRef:     "account://alice",
		RequestedAt:    ApprovalTime(),
	})
	if err != nil {
		t.Fatalf("submit operation: %v", err)
	}
	if result.OperationID != "op://register/1" || result.Status == "" {
		t.Fatalf("result = %+v", result)
	}
}

func TestLiveAdapterRejectsMissingApprovalBeforeSubmit(t *testing.T) {
	transport := NewCountingTransport()
	_, err := service.NewAdapter(transport, service.AdapterConfig{Mode: service.AdapterModeLive})
	if !errors.Is(err, servicepolicy.ErrLiveServiceDisabled) {
		t.Fatalf("error = %v, want %v", err, servicepolicy.ErrLiveServiceDisabled)
	}
	if transport.Calls() != 0 {
		t.Fatalf("transport calls = %d, want 0", transport.Calls())
	}
}
