package resourceio

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

func TestStoppedInvocationCannotPublishLateResource(t *testing.T) {
	table, _ := NewTable(8)
	service, _ := NewService(table, nil, nil)
	life := NewInvocationLifetime(context.Background())
	ctx, done, err := life.Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	life.Stop()
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("stopping the invocation did not cancel its admitted operation")
	}
	resource := io.NopCloser(strings.NewReader("late"))
	if _, err := service.openResource(Invocation{Lifetime: life}, KindHTTPBody, resource); !errors.Is(err, ErrResourceClosed) {
		t.Fatalf("late publication: %v", err)
	}
	done()
	life.Wait()
	if _, _, err := life.Acquire(context.Background()); !errors.Is(err, ErrResourceClosed) {
		t.Fatalf("late admission: %v", err)
	}
}

func TestInFlightResourceCannotPublishAfterRevocation(t *testing.T) {
	table, _ := NewTableWithLimits(DefaultLimits())
	service, _ := NewService(table, nil, nil)
	life := NewInvocationLifetime(context.Background())
	inv := fixtureInvocation("late-open")
	inv.Lifetime = life
	_, done, err := life.Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	ready, resume := make(chan struct{}), make(chan struct{})
	result := make(chan error, 1)
	go func() {
		defer done()
		resource := io.NopCloser(strings.NewReader("late"))
		close(ready)
		<-resume
		_, err := service.openResource(inv, KindHTTPBody, resource)
		_ = resource.Close()
		result <- err
	}()
	<-ready
	life.Stop()
	if err := service.Revoke(nil); err != nil {
		t.Fatal(err)
	}
	close(resume)
	select {
	case err := <-result:
		if !errors.Is(err, ErrResourceClosed) {
			t.Fatalf("late publication: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("late open did not return")
	}
	life.Wait()
	if table.Len() != 0 {
		t.Fatal("revocation leaked a late resource")
	}
}
