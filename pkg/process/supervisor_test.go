package process

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestProcessFixture(t *testing.T) {
	if os.Getenv("RDP_PROCESS_FIXTURE") != "1" {
		return
	}
	defer os.Exit(0)
	switch os.Getenv("RDP_PROCESS_MODE") {
	case "environment":
		_ = json.NewEncoder(os.Stdout).Encode(os.Environ())
	case "overflow":
		_, _ = os.Stdout.Write(bytes.Repeat([]byte{0xa5}, 8192))
		_, _ = os.Stderr.Write([]byte("error-stream"))
	case "hold":
		_, _ = io.Copy(io.Discard, os.Stdin)
	default:
		_, _ = io.Copy(os.Stdout, os.Stdin)
		_, _ = os.Stderr.Write([]byte("stderr"))
	}
}

func testOwner() Owner {
	return Owner{PluginInstanceID: "plugin-one", UserScope: "user-one", EnvironmentScope: "environment-one", SessionScope: "session-one", ChannelScope: "channel-one"}
}

func fixtureSpec(t *testing.T, mode string) StartRequest {
	t.Helper()
	program, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return StartRequest{
		Program:     program,
		Argv:        []string{"-test.run=^TestProcessFixture$"},
		Environment: map[string]string{"RDP_PROCESS_FIXTURE": "1", "RDP_PROCESS_MODE": mode},
		ClientKey:   "fixture",
	}
}

func testSupervisor(t *testing.T, options Options) *Supervisor {
	t.Helper()
	supervisor, err := NewSupervisor(options)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := supervisor.Shutdown(ctx); err != nil {
			t.Error(err)
		}
	})
	return supervisor
}

func testContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func TestBinaryStreamsAndOpaqueStatus(t *testing.T) {
	supervisor := testSupervisor(t, Options{})
	owner, ctx := testOwner(), testContext(t)
	status, err := supervisor.Start(ctx, owner, fixtureSpec(t, "echo"))
	if err != nil {
		t.Fatal(err)
	}
	data := []byte{0, 255, 1, 2, '\n'}
	if written, err := supervisor.WriteStdin(ctx, owner, status.Handle, data); err != nil || written != len(data) {
		t.Fatalf("write: %d %v", written, err)
	}
	if err := supervisor.CloseStdin(owner, status.Handle); err != nil {
		t.Fatal(err)
	}
	exit, err := supervisor.Wait(ctx, owner, status.Handle)
	if err != nil || exit.ExitCode == nil || *exit.ExitCode != 0 {
		t.Fatalf("exit: %#v %v", exit, err)
	}
	stdout, err := supervisor.Read(ctx, owner, status.Handle, Stdout, ReadRequest{MaxBytes: 100})
	if err != nil || !bytes.Equal(stdout.Data, data) || !stdout.EOF || stdout.StreamGap {
		t.Fatalf("stdout: %#v %v", stdout, err)
	}
	stderr, err := supervisor.Read(ctx, owner, status.Handle, Stderr, ReadRequest{MaxBytes: 100})
	if err != nil || string(stderr.Data) != "stderr" || stderr.Cursor != 6 || !stderr.EOF {
		t.Fatalf("stderr: %#v %v", stderr, err)
	}
	raw, err := json.Marshal(exit)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"pid", "handle_id", "program", "environment", "argv", "fd"} {
		if strings.Contains(string(raw), `"`+forbidden+`"`) {
			t.Fatalf("private process identity exposed: %s", raw)
		}
	}
}

func TestListAndConvenienceStreamReadsRespectOwnerScope(t *testing.T) {
	supervisor := testSupervisor(t, Options{})
	owner, ctx := testOwner(), testContext(t)
	firstSpec := fixtureSpec(t, "echo")
	firstSpec.ClientKey = "first"
	first, err := supervisor.Start(ctx, owner, firstSpec)
	if err != nil {
		t.Fatal(err)
	}
	secondSpec := fixtureSpec(t, "echo")
	secondSpec.ClientKey = "second"
	second, err := supervisor.Start(ctx, owner, secondSpec)
	if err != nil {
		t.Fatal(err)
	}
	if err := supervisor.CloseStdin(owner, first.Handle); err != nil {
		t.Fatal(err)
	}
	if err := supervisor.CloseStdin(owner, second.Handle); err != nil {
		t.Fatal(err)
	}
	if _, err := supervisor.Wait(ctx, owner, first.Handle); err != nil {
		t.Fatal(err)
	}
	if _, err := supervisor.Wait(ctx, owner, second.Handle); err != nil {
		t.Fatal(err)
	}
	statuses, err := supervisor.List(owner)
	if err != nil || len(statuses) != 2 {
		t.Fatalf("list: %#v %v", statuses, err)
	}
	if statuses[0].Handle > statuses[1].Handle {
		t.Fatalf("list is not stable: %#v", statuses)
	}
	stdout, err := supervisor.ReadStdout(ctx, owner, first.Handle, ReadRequest{MaxBytes: 16})
	if err != nil || !stdout.EOF {
		t.Fatalf("stdout convenience read: %#v %v", stdout, err)
	}
	stderr, err := supervisor.ReadStderr(ctx, owner, second.Handle, ReadRequest{MaxBytes: 16})
	if err != nil || !stderr.EOF {
		t.Fatalf("stderr convenience read: %#v %v", stderr, err)
	}
	foreign := owner
	foreign.SessionScope = "session-two"
	if statuses, err := supervisor.List(foreign); err != nil || len(statuses) != 0 {
		t.Fatalf("foreign list: %#v %v", statuses, err)
	}
}

func TestOutputOverflowHasIndependentCursors(t *testing.T) {
	supervisor := testSupervisor(t, Options{})
	owner, ctx := testOwner(), testContext(t)
	spec := fixtureSpec(t, "overflow")
	spec.Limits.OutputBufferBytes = 1024
	status, err := supervisor.Start(ctx, owner, spec)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := supervisor.Wait(ctx, owner, status.Handle); err != nil {
		t.Fatal(err)
	}
	stdout, err := supervisor.Read(ctx, owner, status.Handle, Stdout, ReadRequest{MaxBytes: 2048})
	if err != nil || !stdout.StreamGap || stdout.DroppedBytes != 7168 || stdout.Cursor != 8192 || len(stdout.Data) != 1024 {
		t.Fatalf("stdout gap: %#v %v", stdout, err)
	}
	stderr, err := supervisor.Read(ctx, owner, status.Handle, Stderr, ReadRequest{MaxBytes: 100})
	if err != nil || stderr.StreamGap || string(stderr.Data) != "error-stream" {
		t.Fatalf("stderr: %#v %v", stderr, err)
	}
	if _, err := supervisor.Read(ctx, owner, status.Handle, Stdout, ReadRequest{Cursor: 8193, MaxBytes: 10}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("future cursor accepted: %v", err)
	}
}

func TestOutputGapHonorsRequestedMaximum(t *testing.T) {
	supervisor := testSupervisor(t, Options{})
	owner, ctx := testOwner(), testContext(t)
	spec := fixtureSpec(t, "overflow")
	spec.Limits.OutputBufferBytes = 1024
	status, err := supervisor.Start(ctx, owner, spec)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := supervisor.Wait(ctx, owner, status.Handle); err != nil {
		t.Fatal(err)
	}
	result, err := supervisor.Read(ctx, owner, status.Handle, Stdout, ReadRequest{MaxBytes: 10})
	if err != nil {
		t.Fatal(err)
	}
	if !result.StreamGap || result.DroppedBytes != 7168 || len(result.Data) != 10 || result.Cursor != 7178 {
		t.Fatalf("bounded gap: %#v", result)
	}
}

func TestClientKeyReuseAndOwnerIsolation(t *testing.T) {
	supervisor := testSupervisor(t, Options{})
	owner, ctx := testOwner(), testContext(t)
	spec := fixtureSpec(t, "hold")
	var group sync.WaitGroup
	results := make(chan Status, 8)
	for index := 0; index < 8; index++ {
		group.Go(func() {
			status, err := supervisor.Start(ctx, owner, spec)
			if err != nil {
				t.Error(err)
				return
			}
			results <- status
		})
	}
	group.Wait()
	close(results)
	handle := ""
	for result := range results {
		if handle != "" && handle != result.Handle {
			t.Fatal("duplicate client key launched multiple processes")
		}
		handle = result.Handle
	}
	attached, err := supervisor.Attach(owner, spec.ClientKey)
	if err != nil || attached.Handle != handle {
		t.Fatalf("attach: %#v %v", attached, err)
	}
	spec.Argv = append(spec.Argv, "changed")
	if _, err := supervisor.Start(ctx, owner, spec); !errors.Is(err, ErrLaunchConflict) {
		t.Fatalf("changed launch silently reused: %v", err)
	}
	for _, foreign := range []Owner{
		{PluginInstanceID: "plugin-two", UserScope: owner.UserScope, EnvironmentScope: owner.EnvironmentScope},
		{PluginInstanceID: owner.PluginInstanceID, UserScope: "user-two", EnvironmentScope: owner.EnvironmentScope},
		{PluginInstanceID: owner.PluginInstanceID, UserScope: owner.UserScope, EnvironmentScope: "environment-two"},
	} {
		if _, err := supervisor.GetStatus(foreign, handle); !errors.Is(err, ErrNotFound) {
			t.Fatalf("foreign status authorized: %v", err)
		}
		if err := supervisor.Kill(foreign, handle); !errors.Is(err, ErrNotFound) {
			t.Fatalf("foreign kill authorized: %v", err)
		}
	}
}

func TestMinimalEnvironmentAndSecretReferences(t *testing.T) {
	t.Setenv("RDP_HOST_CREDENTIAL", "must-not-inherit")
	supervisor := testSupervisor(t, Options{Secrets: func(ctx context.Context, owner Owner, reference string) (string, error) {
		if owner != testOwner() || reference != "bound-secret" {
			return "", errors.New("sensitive resolver error")
		}
		return "explicit-secret", nil
	}})
	owner, ctx := testOwner(), testContext(t)
	spec := fixtureSpec(t, "environment")
	spec.SecretReferences = map[string]string{"BOUND_SECRET": "bound-secret"}
	status, err := supervisor.Start(ctx, owner, spec)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := supervisor.Wait(ctx, owner, status.Handle); err != nil {
		t.Fatal(err)
	}
	output, err := supervisor.Read(ctx, owner, status.Handle, Stdout, ReadRequest{MaxBytes: 4096})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(output.Data), "RDP_HOST_CREDENTIAL") || !strings.Contains(string(output.Data), "BOUND_SECRET=explicit-secret") {
		t.Fatalf("invalid child environment: %q", output.Data)
	}
	spec.ClientKey = "bad-secret"
	spec.SecretReferences["BOUND_SECRET"] = "missing"
	if _, err := supervisor.Start(ctx, owner, spec); !errors.Is(err, ErrSecretUnavailable) || strings.Contains(err.Error(), "sensitive") {
		t.Fatalf("resolver error disclosed: %v", err)
	}
}

func TestInvalidLaunchRequestsFailBeforeExecution(t *testing.T) {
	supervisor := testSupervisor(t, Options{})
	for _, mutate := range []func(*StartRequest){
		func(spec *StartRequest) { spec.Program = "" },
		func(spec *StartRequest) { spec.Program += "\x00" },
		func(spec *StartRequest) { spec.Argv = []string{"\x00"} },
		func(spec *StartRequest) { spec.Argv = make([]string, MaxArguments+1) },
		func(spec *StartRequest) { spec.Argv = []string{strings.Repeat("x", MaxArgumentBytes+1)} },
		func(spec *StartRequest) { spec.Environment["INVALID=KEY"] = "value" },
		func(spec *StartRequest) { spec.Environment["VALID"] = "\x00" },
		func(spec *StartRequest) { spec.Cwd = "relative-directory" },
		func(spec *StartRequest) { spec.ClientKey = "" },
		func(spec *StartRequest) { spec.Limits.OutputBufferBytes = -1 },
		func(spec *StartRequest) { spec.Limits.OutputBufferBytes = MaxOutputBufferBytes + 1 },
	} {
		spec := fixtureSpec(t, "echo")
		mutate(&spec)
		if _, err := supervisor.Start(testContext(t), testOwner(), spec); !errors.Is(err, ErrInvalidRequest) {
			t.Errorf("invalid request accepted: %v", err)
		}
	}
}

func TestConflictingEnvironmentSourcesAreRejected(t *testing.T) {
	supervisor := testSupervisor(t, Options{})
	for _, mutate := range []func(*StartRequest){
		func(spec *StartRequest) { spec.EnvironmentRemovals = []string{"RDP_PROCESS_MODE", "RDP_PROCESS_MODE"} },
		func(spec *StartRequest) { spec.SecretReferences = map[string]string{"RDP_PROCESS_MODE": "mode"} },
	} {
		spec := fixtureSpec(t, "echo")
		mutate(&spec)
		if _, err := supervisor.Start(testContext(t), testOwner(), spec); !errors.Is(err, ErrInvalidRequest) {
			t.Errorf("conflicting environment source accepted: %v", err)
		}
	}
}

func TestClientKeyReuseRejectsLimitChanges(t *testing.T) {
	supervisor := testSupervisor(t, Options{})
	owner, ctx := testOwner(), testContext(t)
	spec := fixtureSpec(t, "hold")
	status, err := supervisor.Start(ctx, owner, spec)
	if err != nil {
		t.Fatal(err)
	}
	spec.Limits.OutputBufferBytes = 1024
	if _, err := supervisor.Start(ctx, owner, spec); !errors.Is(err, ErrLaunchConflict) {
		t.Fatalf("limit change reused session: %v", err)
	}
	if err := supervisor.Kill(owner, status.Handle); err != nil {
		t.Fatal(err)
	}
}

func TestShutdownRevokeAndTimeout(t *testing.T) {
	supervisor := testSupervisor(t, Options{GracePeriod: 20 * time.Millisecond})
	owner, ctx := testOwner(), testContext(t)
	spec := fixtureSpec(t, "hold")
	spec.Limits.MaxRuntimeMS = 30
	status, err := supervisor.Start(ctx, owner, spec)
	if err != nil {
		t.Fatal(err)
	}
	exit, err := supervisor.Wait(ctx, owner, status.Handle)
	if err != nil || exit.TerminationReason != "timeout" {
		t.Fatalf("timeout: %#v %v", exit, err)
	}
	if err := supervisor.Close(ctx, owner, status.Handle); err != nil {
		t.Fatal(err)
	}
	if _, err := supervisor.Attach(owner, spec.ClientKey); !errors.Is(err, ErrNotFound) {
		t.Fatalf("closed session still attachable: %v", err)
	}
	spec.Limits.MaxRuntimeMS = 0
	status, err = supervisor.Start(ctx, owner, spec)
	if err != nil {
		t.Fatal(err)
	}
	if err := supervisor.Revoke(ctx, owner); err != nil {
		t.Fatal(err)
	}
	if _, err := supervisor.GetStatus(owner, status.Handle); !errors.Is(err, ErrNotFound) {
		t.Fatalf("revoked process still accessible: %v", err)
	}
	if _, err := supervisor.Start(ctx, owner, spec); !errors.Is(err, ErrRevoked) {
		t.Fatalf("revoked owner can start: %v", err)
	}
	if err := supervisor.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := supervisor.Start(ctx, owner, spec); !errors.Is(err, ErrClosed) {
		t.Fatalf("closed supervisor can start: %v", err)
	}
}

func TestRevokePluginCleansAllUserScopes(t *testing.T) {
	supervisor := testSupervisor(t, Options{GracePeriod: 20 * time.Millisecond})
	ctx := testContext(t)
	ownerA := testOwner()
	ownerB := ownerA
	ownerB.UserScope = "user-two"
	specA := fixtureSpec(t, "hold")
	specA.ClientKey = "client-a"
	specB := fixtureSpec(t, "hold")
	specB.ClientKey = "client-b"
	statusA, err := supervisor.Start(ctx, ownerA, specA)
	if err != nil {
		t.Fatal(err)
	}
	statusB, err := supervisor.Start(ctx, ownerB, specB)
	if err != nil {
		t.Fatal(err)
	}
	if err := supervisor.RevokePlugin(ctx, ownerA.PluginInstanceID, ownerA.EnvironmentScope); err != nil {
		t.Fatal(err)
	}
	for _, ownerAndHandle := range []struct {
		owner  Owner
		handle string
	}{
		{ownerA, statusA.Handle},
		{ownerB, statusB.Handle},
	} {
		if _, err := supervisor.GetStatus(ownerAndHandle.owner, ownerAndHandle.handle); !errors.Is(err, ErrNotFound) {
			t.Fatalf("revoked plugin process still accessible: %v", err)
		}
	}
	if _, err := supervisor.Start(ctx, ownerB, specB); !errors.Is(err, ErrRevoked) {
		t.Fatalf("revoked plugin can start in another user scope: %v", err)
	}
}
