package resourceio

import (
	"context"
	"io"
	"sync"
)

// InvocationLifetime binds admission and resource publication to one revocable
// invocation. No network wait holds its lock.
type InvocationLifetime struct {
	mu     sync.Mutex
	ctx    context.Context
	cancel context.CancelFunc
	closed bool
	active sync.WaitGroup
}

func NewInvocationLifetime(parent context.Context) *InvocationLifetime {
	ctx, cancel := context.WithCancel(parent)
	return &InvocationLifetime{ctx: ctx, cancel: cancel}
}
func (l *InvocationLifetime) Context() context.Context { return l.ctx }
func (l *InvocationLifetime) Acquire(ctx context.Context) (context.Context, func(), error) {
	l.mu.Lock()
	if l.closed || l.ctx.Err() != nil {
		l.mu.Unlock()
		return nil, nil, ErrResourceClosed
	}
	l.active.Add(1)
	l.mu.Unlock()
	operation, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(l.ctx, cancel)
	if l.ctx.Err() != nil {
		cancel()
	}
	var once sync.Once
	return operation, func() { once.Do(func() { stop(); cancel(); l.active.Done() }) }, nil
}
func (l *InvocationLifetime) Stop() {
	l.mu.Lock()
	l.closed = true
	l.cancel()
	l.mu.Unlock()
}
func (l *InvocationLifetime) Wait() { l.active.Wait() }

func (s *Service) openResource(inv Invocation, kind Kind, resource io.Closer) (HandleID, error) {
	if inv.Lifetime != nil {
		inv.Lifetime.mu.Lock()
		defer inv.Lifetime.mu.Unlock()
		if inv.Lifetime.closed || inv.Lifetime.ctx.Err() != nil {
			return 0, ErrResourceClosed
		}
	}
	return s.table.Open(inv.Owner, kind, resource)
}
func (s *Service) openCreatedResource(inv Invocation, kind Kind, create func() (io.Closer, error)) (HandleID, error) {
	if inv.Lifetime != nil {
		inv.Lifetime.mu.Lock()
		defer inv.Lifetime.mu.Unlock()
		if inv.Lifetime.closed || inv.Lifetime.ctx.Err() != nil {
			return 0, ErrResourceClosed
		}
	}
	return s.table.OpenCreated(inv.Owner, kind, create)
}
