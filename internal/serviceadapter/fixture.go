package serviceadapter

import (
	"context"
	"sync"
	"time"

	"github.com/GoCodeAlone/libsignal-service-go/fake"
	"github.com/GoCodeAlone/libsignal-service-go/operatorfixture"
	"github.com/GoCodeAlone/libsignal-service-go/service"
)

type OperatorFixtureConfig struct {
	Endpoint string
	Now      time.Time
}

func NewOperatorFixture(cfg OperatorFixtureConfig) (*service.Adapter, error) {
	return operatorfixture.NewAdapter(operatorfixture.Config{
		Endpoint: cfg.Endpoint,
		Now:      cfg.Now,
	})
}

func ApprovalTime() time.Time {
	return operatorfixture.ApprovalTime()
}

func NewCountingTransport() *CountingTransport {
	return &CountingTransport{}
}

type CountingTransport struct {
	mu    sync.Mutex
	calls int
	fake  fake.Adapter
}

func (t *CountingTransport) SubmitOperation(ctx context.Context, env service.OperationEnvelope) (service.OperationResult, error) {
	t.mu.Lock()
	t.calls++
	t.mu.Unlock()
	return t.fake.SubmitOperation(ctx, env)
}

func (t *CountingTransport) Calls() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.calls
}
