package host

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/floegence/redevplugin/v3/pkg/manifest"
	processruntime "github.com/floegence/redevplugin/v3/pkg/process"
)

func TestHostRuntimeIOProcessRequiresWritableSession(t *testing.T) {
	supervisor, err := processruntime.NewSupervisor(processruntime.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := supervisor.Shutdown(context.Background()); err != nil {
			t.Error(err)
		}
	}()
	broker, err := newHostRuntimeIOBroker(normalizedAdapters{ProcessSupervisor: supervisor})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := broker.closeAll(); err != nil {
			t.Error(err)
		}
	}()
	for _, operation := range []string{"start", "write_stdin", "close_stdin", "terminate", "kill", "close"} {
		t.Run(operation, func(t *testing.T) {
			inv := runtimeIOTestInvocation("readonly-"+operation, "session", "channel")
			reg, err := newHostRuntimeIORegistration(inv, workerBrokerAccess{Process: []workerProcessBrokerAccess{{Operations: []string{operation}}}}, map[string]string{string(manifest.PermissionProcessLocal): "grant"})
			if err != nil {
				t.Fatal(err)
			}
			_, err = broker.dispatchProcess(context.Background(), reg, runtimeIOControlRequest{Operation: "process." + operation, Arguments: json.RawMessage("{}")})
			if !errors.Is(err, errRuntimeIOStorageDenied) {
				t.Fatalf("read-only %s error = %v, want permission denial before dispatch", operation, err)
			}
		})
	}
}

func TestHostRuntimeIOProcessReadEffectCannotMutate(t *testing.T) {
	supervisor, err := processruntime.NewSupervisor(processruntime.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := supervisor.Shutdown(context.Background()); err != nil {
			t.Error(err)
		}
	}()
	broker, err := newHostRuntimeIOBroker(normalizedAdapters{ProcessSupervisor: supervisor})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := broker.closeAll(); err != nil {
			t.Error(err)
		}
	}()
	inv := runtimeIOTestInvocation("read-effect", "session", "channel")
	inv.CanWrite = true
	reg, err := newHostRuntimeIORegistration(inv, workerBrokerAccess{Process: []workerProcessBrokerAccess{{Operations: []string{"start", "status"}}}}, map[string]string{string(manifest.PermissionProcessLocal): "grant"})
	if err != nil {
		t.Fatal(err)
	}
	reg.readOnly = true
	_, err = broker.dispatchProcess(context.Background(), reg, runtimeIOControlRequest{Operation: "process.start", Arguments: json.RawMessage("{}")})
	if !errors.Is(err, errRuntimeIOStorageDenied) {
		t.Fatalf("read effect started process: %v", err)
	}
	_, err = broker.dispatchProcess(context.Background(), reg, runtimeIOControlRequest{Operation: "process.status", Arguments: json.RawMessage("{}")})
	if !errors.Is(err, processruntime.ErrNotFound) {
		t.Fatalf("read operation did not reach supervisor: %v", err)
	}
	inv.CanRead = false
	reg.resource = inv
	_, err = broker.dispatchProcess(context.Background(), reg, runtimeIOControlRequest{Operation: "process.status", Arguments: json.RawMessage("{}")})
	if !errors.Is(err, errRuntimeIOStorageDenied) {
		t.Fatalf("unreadable session reached supervisor: %v", err)
	}
}
