package runtimeclient

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/floegence/redevplugin/v3/pkg/capability"
	"github.com/floegence/redevplugin/v3/pkg/execution"
	"github.com/floegence/redevplugin/v3/pkg/observability"
	"github.com/floegence/redevplugin/v3/pkg/sessionctx"
	"github.com/floegence/redevplugin/v3/pkg/version"
)

func TestMain(m *testing.M) {
	if os.Getenv("REDEVPLUGIN_RUNTIMECLIENT_FIXED_FD_HELPER") == "1" {
		runFixedFDLayoutHelper()
		return
	}
	if rawExitCode := os.Getenv("REDEVPLUGIN_RUNTIMECLIENT_EXIT_CODE"); rawExitCode != "" {
		exitCode, err := strconv.Atoi(rawExitCode)
		if err != nil {
			os.Exit(255)
		}
		_, _ = os.Stderr.WriteString("IPC_WRITER_WRITE_FAILED bearer token must be ignored\n")
		os.Exit(exitCode)
	}
	if os.Getenv("REDEVPLUGIN_RUNTIMECLIENT_HELPER") == "1" {
		writeRuntimeHelperStartMarker()
		runRuntimeClientHelper()
		return
	}
	if os.Getenv("REDEVPLUGIN_RUNTIMECLIENT_BAD_HELPER") == "1" {
		writeRuntimeHelperStartMarker()
		ipcWrite := os.NewFile(runtimeIPCWriteFD, "redevplugin-ipc-write")
		if ipcWrite == nil {
			os.Exit(254)
		}
		_, _ = ipcWrite.WriteString("not-json\n")
		time.Sleep(10 * time.Second)
		return
	}
	os.Exit(m.Run())
}

func TestPortableRuntimeProcessUsesTheCanonicalFixedFDLayout(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	process, err := launchPortableRuntimeProcess(runtimeProcessLaunchOptions{
		context: ctx,
		path:    os.Args[0],
		args:    []string{"-test.run=TestMain"},
		env:     append(os.Environ(), "REDEVPLUGIN_RUNTIMECLIENT_FIXED_FD_HELPER=1"),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = process.Kill()
		_ = process.Wait()
	}()
	assertRuntimeChannelRoundTrip(t, process.ipcIn, process.ipcOut, 'i')
	assertRuntimeChannelRoundTrip(t, process.controlIn, process.controlOut, 'c')
}

func assertRuntimeChannelRoundTrip(t *testing.T, writer io.Writer, reader io.Reader, value byte) {
	t.Helper()
	if _, err := writer.Write([]byte{value}); err != nil {
		t.Fatalf("write runtime channel: %v", err)
	}
	response := []byte{0}
	if _, err := io.ReadFull(reader, response); err != nil {
		t.Fatalf("read runtime channel: %v", err)
	}
	if response[0] != value {
		t.Fatalf("runtime channel response = %q, want %q", response[0], value)
	}
}

func runFixedFDLayoutHelper() {
	if os.Getenv("REDEVPLUGIN_CONTROL_READ_FD") != "" || os.Getenv("REDEVPLUGIN_CONTROL_WRITE_FD") != "" {
		os.Exit(90)
	}
	for _, pair := range [][2]int{{runtimeIPCReadFD, runtimeIPCWriteFD}, {runtimeControlReadFD, runtimeControlWriteFD}} {
		reader := os.NewFile(uintptr(pair[0]), "runtime-fixed-read")
		writer := os.NewFile(uintptr(pair[1]), "runtime-fixed-write")
		if reader == nil || writer == nil {
			os.Exit(91)
		}
		value := []byte{0}
		if _, err := io.ReadFull(reader, value); err != nil {
			os.Exit(92)
		}
		if _, err := writer.Write(value); err != nil {
			os.Exit(93)
		}
	}
	os.Exit(0)
}

func TestRuntimeProcessWaitCleansOwnedStagingOnce(t *testing.T) {
	var cleanups int
	process := &runtimeProcess{
		wait:    func() error { return nil },
		cleanup: func() { cleanups++ },
	}
	if err := process.Wait(); err != nil {
		t.Fatal(err)
	}
	if err := process.Wait(); err != nil {
		t.Fatal(err)
	}
	if cleanups != 1 {
		t.Fatalf("runtime staging cleanup count = %d, want 1", cleanups)
	}
}

func TestRuntimeProcessFailureCodesMapExactExitStatuses(t *testing.T) {
	tests := []struct {
		exitCode int
		want     observability.RuntimeProcessFailureCode
	}{
		{exitCode: 0, want: observability.RuntimeProcessExitUnexpected},
		{exitCode: runtimeProcessExitGeneral, want: observability.RuntimeProcessFailed},
		{exitCode: runtimeProcessExitWriterCapacityOverflow, want: observability.RuntimeProcessWriterCapacityOverflow},
		{exitCode: runtimeProcessExitWriterCapacityLimitExceeded, want: observability.RuntimeProcessWriterCapacityLimitExceeded},
		{exitCode: runtimeProcessExitWriterStartFailed, want: observability.RuntimeProcessWriterStartFailed},
		{exitCode: runtimeProcessExitWriterClosed, want: observability.RuntimeProcessWriterClosed},
		{exitCode: runtimeProcessExitWriterBatchSizeOverflow, want: observability.RuntimeProcessWriterBatchSizeOverflow},
		{exitCode: runtimeProcessExitWriterWriteFailed, want: observability.RuntimeProcessWriterWriteFailed},
		{exitCode: runtimeProcessExitWriterFlushFailed, want: observability.RuntimeProcessWriterFlushFailed},
		{exitCode: runtimeProcessExitWriterPanicked, want: observability.RuntimeProcessWriterPanicked},
		{exitCode: 99, want: observability.RuntimeProcessExitUnrecognized},
	}
	for _, test := range tests {
		cmd := exec.Command(os.Args[0], "-test.run=^$")
		cmd.Env = append(os.Environ(), "REDEVPLUGIN_RUNTIMECLIENT_EXIT_CODE="+strconv.Itoa(test.exitCode))
		cmd.Stdout = io.Discard
		cmd.Stderr = io.Discard
		err := cmd.Run()
		if got := runtimeProcessFailureCodeFromWaitError(err); got != test.want {
			t.Fatalf("exit code %d mapped to %q, want %q", test.exitCode, got, test.want)
		}
	}
}

func TestRuntimeProcessTerminationIntentDoesNotHideWriterFailure(t *testing.T) {
	cmd := exec.Command(os.Args[0], "-test.run=^$")
	cmd.Env = append(os.Environ(), "REDEVPLUGIN_RUNTIMECLIENT_EXIT_CODE="+strconv.Itoa(runtimeProcessExitWriterWriteFailed))
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	err := cmd.Run()
	if got := classifyRuntimeProcessExit(err, runtimeProcessTerminationStop); got != observability.RuntimeProcessWriterWriteFailed {
		t.Fatalf("writer failure with stop intent = %q, want %q", got, observability.RuntimeProcessWriterWriteFailed)
	}
	if got := classifyRuntimeProcessExit(errors.New("unrecognized wait failure"), runtimeProcessTerminationIPCInvalidation); got != observability.RuntimeProcessExitUnrecognized {
		t.Fatalf("unrecognized IPC invalidation exit = %q, want %q", got, observability.RuntimeProcessExitUnrecognized)
	}
	if got := classifyRuntimeProcessExit(nil, runtimeProcessTerminationHandshakeCleanup); got != "" {
		t.Fatalf("expected handshake cleanup exit = %q, want empty", got)
	}
}

func TestRuntimeProcessTerminationIntentPreservesEveryNonzeroExit(t *testing.T) {
	tests := append(RuntimeProcessExitFailures(), RuntimeProcessExitFailure{
		ExitCode: 99,
		Code:     observability.RuntimeProcessExitUnrecognized,
	})
	for _, test := range tests {
		cmd := exec.Command(os.Args[0], "-test.run=^$")
		cmd.Env = append(os.Environ(), "REDEVPLUGIN_RUNTIMECLIENT_EXIT_CODE="+strconv.Itoa(test.ExitCode))
		cmd.Stdout = io.Discard
		cmd.Stderr = io.Discard
		err := cmd.Run()
		for _, intent := range []runtimeProcessTerminationIntent{
			runtimeProcessTerminationStop,
			runtimeProcessTerminationHandshakeCleanup,
			runtimeProcessTerminationIPCInvalidation,
		} {
			if got := classifyRuntimeProcessExit(err, intent); got != test.Code {
				t.Fatalf("exit %d with intent %d = %q, want %q", test.ExitCode, intent, got, test.Code)
			}
		}
	}
}

func TestProcessExitPreservesFirstTerminationIntent(t *testing.T) {
	exit := &processExit{}
	exit.markTerminationIntent(runtimeProcessTerminationStop)
	exit.markTerminationIntent(runtimeProcessTerminationIPCInvalidation)
	if got := exit.terminationIntent(); got != runtimeProcessTerminationStop {
		t.Fatalf("termination intent = %v, want stop", got)
	}
}

func TestReadIPCLoopClassifiesEOFSeparatelyFromActiveIPCFailure(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		intent runtimeProcessTerminationIntent
	}{
		{name: "process exit EOF", input: "", intent: runtimeProcessTerminationNone},
		{name: "active IPC failure", input: "not-json\n", intent: runtimeProcessTerminationIPCInvalidation},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			health := Health{RuntimeGenerationID: "generation_1", Ready: true}
			exit := &processExit{}
			supervisor := &ProcessSupervisor{
				process: &runtimeProcess{},
				exit:    exit,
				health:  health,
				pending: map[string]*pendingIPCRequest{},
			}
			generation := &runtimeGeneration{id: health.RuntimeGenerationID, ctx: context.Background()}
			supervisor.readIPCLoop(bufio.NewReader(strings.NewReader(test.input)), generation, health)
			if got := exit.terminationIntent(); got != test.intent {
				t.Fatalf("termination intent = %v, want %v", got, test.intent)
			}
			if supervisor.health.Ready {
				t.Fatal("runtime remained ready after IPC reader termination")
			}
		})
	}
}

func writeRuntimeHelperStartMarker() {
	if path := os.Getenv("REDEVPLUGIN_RUNTIMECLIENT_START_MARKER"); path != "" {
		_ = os.WriteFile(path, []byte("started"), 0o600)
	}
}

func TestReadBoundedIPCLineRejectsOversizedFrame(t *testing.T) {
	reader := bufio.NewReader(strings.NewReader("123456789\n"))
	_, err := readBoundedIPCLine(reader, 8)
	if err == nil || !strings.Contains(err.Error(), "exceeds 8 bytes") {
		t.Fatalf("readBoundedIPCLine() error = %v, want size limit", err)
	}
}

func readSemanticJSONTestFrame(reader *bufio.Reader) (ipcFrame, error) {
	line, err := readBoundedIPCLine(reader, maxIPCFrameBytes)
	if err != nil {
		return ipcFrame{}, err
	}
	var frame ipcFrame
	if err := decodeStrictJSON(line, &frame); err != nil {
		return ipcFrame{}, err
	}
	return frame, nil
}

func TestReadIPCFrameRejectsNonCanonicalJSON(t *testing.T) {
	tests := []struct {
		name  string
		frame string
	}{
		{name: "unknown field", frame: `{"frame_type":"diagnostic","request_id":"r1","payload":{},"future":true}`},
		{name: "duplicate frame type", frame: `{"frame_type":"diagnostic","frame_type":"heartbeat","request_id":"r1","payload":{}}`},
		{name: "case folded request id", frame: `{"frame_type":"diagnostic","request_id":"r1","REQUEST_ID":"r2","payload":{}}`},
		{name: "case alias only", frame: `{"frame_type":"diagnostic","REQUEST_ID":"r1","payload":{}}`},
		{name: "duplicate nested payload key", frame: `{"frame_type":"diagnostic","request_id":"r1","payload":{"ok":true,"ok":false}}`},
		{name: "trailing JSON", frame: `{"frame_type":"diagnostic","request_id":"r1","payload":{}} {}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := readIPCFrame(bufio.NewReader(strings.NewReader(test.frame + "\n"))); err == nil {
				t.Fatal("readIPCFrame() accepted non-canonical JSON")
			}
		})
	}
}

func TestValidateHelloAckRejectsNonCanonicalPayload(t *testing.T) {
	baseFrame := ipcFrame{
		FrameType:           ipcFrameTypeHelloAck,
		RequestID:           "hello_1",
		RuntimeGenerationID: "g1",
	}
	for _, payload := range []string{
		`{"internal_wire":1,"platform_version":"3.0.3","runtime_artifact_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","connection_nonce":"nonce_1234567890123456","future":true}`,
		`{"internal_wire":1,"platform_version":"3.0.3","platform_version":"3.0.4","runtime_artifact_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","connection_nonce":"nonce_1234567890123456"}`,
		`{"internal_wire":1,"platform_version":"3.0.3","PLATFORM_VERSION":"3.0.4","runtime_artifact_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","connection_nonce":"nonce_1234567890123456"}`,
		`{"internal_wire":1,"PLATFORM_VERSION":"3.0.3","runtime_artifact_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","connection_nonce":"nonce_1234567890123456"}`,
		`{"internal_wire":1,"platform_version":"3.0.3","runtime_artifact_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","connection_nonce":"nonce_1234567890123456"} {}`,
	} {
		frame := baseFrame
		frame.Payload = json.RawMessage(payload)
		if _, err := validateHelloAck(
			"hello_1",
			"g1",
			"nonce_1234567890123456",
			testRuntimeArtifactIdentity(testRuntimeTarget, strings.Repeat("a", 64)),
			DefaultRuntimeLimits(),
			frame,
		); !errors.Is(err, ErrRuntimeHandshake) {
			t.Fatalf("validateHelloAck(%s) error = %v, want ErrRuntimeHandshake", payload, err)
		}
	}
}

func TestValidateHelloAckRequiresExactContainmentEvidence(t *testing.T) {
	descriptor := testRuntimeArtifactIdentity(testRuntimeTarget, strings.Repeat("a", 64))
	validContainment := processContainmentEvidence{
		SchemaVersion:         "redevplugin.process_containment.v1",
		Profile:               runtimeContainmentProfile,
		SeccompPolicySHA256:   runtimeContainmentPolicySHA,
		NoNewPrivileges:       true,
		SeccompTSync:          true,
		ProcessCreationDenied: true,
		ReexecDenied:          true,
		Active:                true,
	}
	validAck := helloAckPayload{
		InternalWire:          InternalWire,
		PlatformVersion:       descriptor.PlatformVersion().String(),
		RuntimeArtifactSHA256: descriptor.BinarySHA256(),
		ConnectionNonce:       "nonce_1234567890123456",
		ActualTarget:          descriptor.Target().String(),
		Limits:                DefaultRuntimeLimits(),
		ProcessContainment:    &validContainment,
	}
	frameFor := func(t *testing.T, ack helloAckPayload) ipcFrame {
		t.Helper()
		payload, err := json.Marshal(ack)
		if err != nil {
			t.Fatal(err)
		}
		return ipcFrame{
			FrameType:           ipcFrameTypeHelloAck,
			RequestID:           "hello_1",
			RuntimeGenerationID: "generation_1",
			Payload:             payload,
		}
	}
	if _, err := validateHelloAck("hello_1", "generation_1", validAck.ConnectionNonce, descriptor, validAck.Limits, frameFor(t, validAck), true); err != nil {
		t.Fatalf("validateHelloAck() valid containment error = %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*helloAckPayload)
	}{
		{name: "missing", mutate: func(ack *helloAckPayload) { ack.ProcessContainment = nil }},
		{name: "wrong schema", mutate: func(ack *helloAckPayload) {
			ack.ProcessContainment.SchemaVersion = "redevplugin.process_containment.v2"
		}},
		{name: "wrong profile", mutate: func(ack *helloAckPayload) { ack.ProcessContainment.Profile = "legacy" }},
		{name: "wrong policy", mutate: func(ack *helloAckPayload) { ack.ProcessContainment.SeccompPolicySHA256 = strings.Repeat("0", 64) }},
		{name: "no new privileges false", mutate: func(ack *helloAckPayload) { ack.ProcessContainment.NoNewPrivileges = false }},
		{name: "tsync false", mutate: func(ack *helloAckPayload) { ack.ProcessContainment.SeccompTSync = false }},
		{name: "process creation allowed", mutate: func(ack *helloAckPayload) { ack.ProcessContainment.ProcessCreationDenied = false }},
		{name: "reexec allowed", mutate: func(ack *helloAckPayload) { ack.ProcessContainment.ReexecDenied = false }},
		{name: "inactive", mutate: func(ack *helloAckPayload) { ack.ProcessContainment.Active = false }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			containment := validContainment
			ack := validAck
			ack.ProcessContainment = &containment
			test.mutate(&ack)
			if _, err := validateHelloAck("hello_1", "generation_1", ack.ConnectionNonce, descriptor, ack.Limits, frameFor(t, ack), true); !errors.Is(err, ErrRuntimeHandshake) {
				t.Fatalf("validateHelloAck() error = %v, want ErrRuntimeHandshake", err)
			}
		})
	}
}

func TestStrictJSONAllowsCaseDistinctDynamicMapKeys(t *testing.T) {
	var payload struct {
		Headers map[string]string `json:"headers"`
	}
	if err := decodeStrictJSON([]byte(`{"headers":{"Key":"first","key":"second"}}`), &payload); err != nil {
		t.Fatalf("decodeStrictJSON() error = %v", err)
	}
	if payload.Headers["Key"] != "first" || payload.Headers["key"] != "second" {
		t.Fatalf("headers = %#v", payload.Headers)
	}
}

func TestProcessSupervisorLifecycleAndDiagnostics(t *testing.T) {
	const maxHeartbeatStaleness = 5 * time.Second
	store := &runtimeDiagnosticSink{}
	supervisor, err := newTestProcessSupervisor(t, ProcessSupervisorOptions{
		Limits:                DefaultRuntimeLimits(),
		HandshakeTimeout:      5 * time.Second,
		HeartbeatInterval:     2 * time.Second,
		MaxHeartbeatStaleness: maxHeartbeatStaleness,
		RuntimePath:           os.Args[0],
		Args:                  []string{"-test.run=TestMain"},
		Env:                   append(os.Environ(), "REDEVPLUGIN_RUNTIMECLIENT_HELPER=1"),
		Diagnostics:           store,
		StreamSink:            &recordingRuntimeStreamSink{},
	})
	if err != nil {
		t.Fatal(err)
	}

	if err := supervisor.Start(context.Background(), testRuntimeTarget); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	health, err := supervisor.Health(context.Background())
	if err != nil {
		t.Fatalf("Health() error = %v", err)
	}
	if !health.Ready ||
		health.RuntimeInstanceID == "" ||
		health.RuntimeGenerationID == "" ||
		health.ArtifactIdentity.PlatformVersion().String() != version.CurrentPlatformVersion() ||
		health.ArtifactIdentity.Target() != testRuntimeTarget {
		t.Fatalf("health mismatch: %#v", health)
	}
	heartbeat, err := supervisor.Heartbeat(context.Background())
	if err != nil {
		t.Fatalf("Heartbeat() error = %v", err)
	}
	if heartbeat.RuntimeGenerationID != health.RuntimeGenerationID ||
		heartbeat.RuntimeUnixNano <= 0 ||
		heartbeat.MaxStalenessMillis != int64(maxHeartbeatStaleness/time.Millisecond) ||
		heartbeat.HostSentUnixNanoEcho <= 0 {
		t.Fatalf("heartbeat mismatch: %#v", heartbeat)
	}
	projected, err := supervisor.Health(context.Background())
	if err != nil {
		t.Fatalf("Health(after heartbeat) error = %v", err)
	}
	if projected.ActiveInvocations != heartbeat.ActiveInvocations || projected.QueuedInvocations != heartbeat.QueuedInvocations || projected.ModuleCache != heartbeat.ModuleCache {
		t.Fatalf("health did not project heartbeat state: health=%#v heartbeat=%#v", projected, heartbeat)
	}
	rawResult, err := supervisor.invokeWorkerForTest(context.Background(), Lease{LeaseID: "lease_1", RuntimeGenerationID: health.RuntimeGenerationID, PluginInstanceID: "plugini_1"}, "worker.echo", workerInvocationFixture())
	if err != nil {
		t.Fatalf("InvokeWorker() error = %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(rawResult, &decoded); err != nil {
		t.Fatalf("decode worker result: %v", err)
	}
	if decoded["data"].(map[string]any)["from_runtime"] != true {
		t.Fatalf("worker result mismatch: %#v", decoded)
	}
	revokeResult, err := supervisor.Revoke(context.Background(), testRevokeRequest("plugini_1", 3))
	if err != nil {
		t.Fatalf("Revoke() error = %v", err)
	}
	if revokeResult.PluginInstanceID != "plugini_1" ||
		revokeResult.RevokeEpoch != 3 ||
		revokeResult.ClosedSocketCount != 2 ||
		revokeResult.ClosedStreamCount != 3 ||
		revokeResult.ClosedStorageHandleCount != 4 {
		t.Fatalf("Revoke() result mismatch: %#v", revokeResult)
	}

	waitForDiagnostic(t, store, "plugin.runtime.process.started")
	waitForDiagnostic(t, store, "plugin.runtime.ipc.handshake")

	stopRuntimeSupervisor(t, supervisor)
	health, err = supervisor.Health(context.Background())
	if err != nil {
		t.Fatalf("Health(after stop) error = %v", err)
	}
	if health.Ready {
		t.Fatalf("health after stop still ready: %#v", health)
	}
	if _, err := supervisor.invokeWorkerForTest(context.Background(), Lease{}, "worker.echo", nil); !errors.Is(err, ErrRuntimeNotReady) {
		t.Fatalf("InvokeWorker(after stop) error = %v, want ErrRuntimeNotReady", err)
	}
}

func TestProcessSupervisorPreservesWriterExitAfterSuccessfulHandshake(t *testing.T) {
	diagnostics := &runtimeDiagnosticSink{}
	supervisor, err := newTestProcessSupervisor(t, ProcessSupervisorOptions{
		Limits:                DefaultRuntimeLimits(),
		HandshakeTimeout:      5 * time.Second,
		HeartbeatInterval:     2 * time.Second,
		MaxHeartbeatStaleness: 5 * time.Second,
		RuntimePath:           os.Args[0],
		Args:                  []string{"-test.run=TestMain"},
		Env: append(
			os.Environ(),
			"REDEVPLUGIN_RUNTIMECLIENT_HELPER=1",
			"REDEVPLUGIN_RUNTIMECLIENT_EXIT_AFTER_ACK="+strconv.Itoa(runtimeProcessExitWriterWriteFailed),
		),
		Diagnostics: diagnostics,
		StreamSink:  &recordingRuntimeStreamSink{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := supervisor.Start(context.Background(), testRuntimeTarget); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	waitForDiagnostic(t, diagnostics, "plugin.runtime.process.exited")
	events := diagnostics.list("plugin.runtime.process.exited")
	if len(events) != 1 || events[0].Severity != observability.DiagnosticSeverityWarning ||
		events[0].Details.RuntimeProcessFailureCode != observability.RuntimeProcessWriterWriteFailed {
		t.Fatalf("runtime process exit diagnostic = %#v", events)
	}
	stopRuntimeSupervisor(t, supervisor)
}

func TestProcessSupervisorRuntimeLeaseReplayStoreRejectsDuplicateBeforeIPC(t *testing.T) {
	diagnostics := &runtimeDiagnosticSink{}
	supervisor, err := newTestProcessSupervisor(t, ProcessSupervisorOptions{
		Limits:                DefaultRuntimeLimits(),
		HandshakeTimeout:      5 * time.Second,
		HeartbeatInterval:     2 * time.Second,
		MaxHeartbeatStaleness: 5 * time.Second,
		RuntimePath:           os.Args[0],
		Args:                  []string{"-test.run=TestMain"},
		Env:                   append(os.Environ(), "REDEVPLUGIN_RUNTIMECLIENT_HELPER=1"),
		Diagnostics:           diagnostics,
		RuntimeLeaseReplays:   NewMemoryRuntimeLeaseReplayStore(),
		StreamSink:            &recordingRuntimeStreamSink{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := supervisor.Start(context.Background(), testRuntimeTarget); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	health, err := supervisor.Health(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	lease := Lease{
		LeaseID:             "rel_replay",
		LeaseNonce:          "nonce_replay_1234567890",
		RuntimeGenerationID: health.RuntimeGenerationID,
		PluginInstanceID:    "plugini_1",
		Method:              "worker.echo",
		PolicyRevision:      11,
		ManagementRevision:  12,
		RevokeEpoch:         13,
		ExpiresAtUnixMillis: time.Now().Add(time.Minute).UnixMilli(),
	}
	if _, err := supervisor.invokeWorkerForTest(context.Background(), lease, "worker.echo", workerInvocationFixture()); err != nil {
		t.Fatalf("InvokeWorker(first) error = %v", err)
	}
	if _, err := supervisor.invokeWorkerForTest(context.Background(), lease, "worker.echo", workerInvocationFixture()); !errors.Is(err, ErrRuntimeLeaseReplay) {
		t.Fatalf("InvokeWorker(replay) error = %v, want %v", err, ErrRuntimeLeaseReplay)
	}
	waitForDiagnostic(t, diagnostics, "plugin.runtime.lease.replayed")
	stopRuntimeSupervisor(t, supervisor)
}

func TestProcessSupervisorMapsRuntimeRequestFailure(t *testing.T) {
	supervisor, err := newTestProcessSupervisor(t, ProcessSupervisorOptions{
		Limits:                DefaultRuntimeLimits(),
		HandshakeTimeout:      5 * time.Second,
		HeartbeatInterval:     2 * time.Second,
		MaxHeartbeatStaleness: 5 * time.Second,
		RuntimePath:           os.Args[0],
		Args:                  []string{"-test.run=TestMain"},
		Env:                   append(os.Environ(), "REDEVPLUGIN_RUNTIMECLIENT_HELPER=1", "REDEVPLUGIN_RUNTIMECLIENT_FAIL_INVOKE=1"),
		StreamSink:            &recordingRuntimeStreamSink{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := supervisor.Start(context.Background(), testRuntimeTarget); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	if _, err := supervisor.invokeWorkerForTest(context.Background(), Lease{LeaseID: "lease_1"}, "worker.echo", workerInvocationFixture()); !errors.Is(err, ErrRuntimeRequestFailed) {
		t.Fatalf("InvokeWorker() error = %v, want ErrRuntimeRequestFailed", err)
	}
	stopRuntimeSupervisor(t, supervisor)
}

func TestWorkerExecutionErrorPreservesStableWorkerFailure(t *testing.T) {
	err := (runtimeResponsePayload{Code: "NOTE_NOT_FOUND", Message: "note was not found", ErrorOrigin: WorkerErrorOriginPlugin}).workerExecutionError()
	var workerErr *WorkerExecutionError
	if !errors.As(err, &workerErr) {
		t.Fatalf("worker execution error type = %T, want *WorkerExecutionError", err)
	}
	if workerErr.Code != "NOTE_NOT_FOUND" || workerErr.Message != "note was not found" || workerErr.Origin != WorkerErrorOriginPlugin {
		t.Fatalf("worker execution error = %#v", workerErr)
	}
	if !errors.Is(err, ErrRuntimeRequestFailed) {
		t.Fatalf("worker execution error must remain a runtime request failure: %v", err)
	}
}

func TestWorkerExecutionErrorRejectsMissingOrUnknownOrigin(t *testing.T) {
	for _, origin := range []WorkerErrorOrigin{"", "worker"} {
		err := (runtimeResponsePayload{Code: "RUNTIME_CAPABILITY_REVOKED", Message: "spoofed", ErrorOrigin: origin}).workerExecutionError()
		var workerErr *WorkerExecutionError
		if errors.As(err, &workerErr) {
			t.Fatalf("origin %q produced trusted worker error %#v", origin, workerErr)
		}
		if !errors.Is(err, ErrRuntimeIPCUnavailable) {
			t.Fatalf("origin %q error = %v, want ErrRuntimeIPCUnavailable", origin, err)
		}
	}
}

func TestDecodeRuntimeResponseRejectsNonCanonicalPayloads(t *testing.T) {
	tests := []struct {
		name    string
		payload string
	}{
		{name: "removed error field", payload: `{"ok":false,"error":"removed","code":"FAILED","message":"failed","error_origin":"runtime"}`},
		{name: "unknown field", payload: `{"ok":true,"result":{},"future":true}`},
		{name: "duplicate ok", payload: `{"ok":true,"ok":false,"result":{}}`},
		{name: "case folded ok", payload: `{"ok":true,"OK":false,"result":{}}`},
		{name: "case alias only", payload: `{"OK":true,"result":{}}`},
		{name: "duplicate code", payload: `{"ok":false,"code":"FAILED","code":"SPOOFED","message":"failed","error_origin":"runtime"}`},
		{name: "trailing JSON", payload: `{"ok":true,"result":{}} {}`},
		{name: "missing ok", payload: `{"result":{}}`},
		{name: "success missing result", payload: `{"ok":true}`},
		{name: "success with code", payload: `{"ok":true,"result":{},"code":"FAILED"}`},
		{name: "success with message", payload: `{"ok":true,"result":{},"message":"failed"}`},
		{name: "success with origin", payload: `{"ok":true,"result":{},"error_origin":"runtime"}`},
		{name: "failure with result", payload: `{"ok":false,"result":{},"code":"FAILED","message":"failed","error_origin":"runtime"}`},
		{name: "failure missing code", payload: `{"ok":false,"message":"failed","error_origin":"runtime"}`},
		{name: "failure empty code", payload: `{"ok":false,"code":" ","message":"failed","error_origin":"runtime"}`},
		{name: "failure missing message", payload: `{"ok":false,"code":"FAILED","error_origin":"runtime"}`},
		{name: "failure empty message", payload: `{"ok":false,"code":"FAILED","message":" ","error_origin":"runtime"}`},
		{name: "failure missing origin", payload: `{"ok":false,"code":"FAILED","message":"failed"}`},
		{name: "failure invalid origin", payload: `{"ok":false,"code":"FAILED","message":"failed","error_origin":"worker"}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := decodeRuntimeResponse(ipcFrame{Payload: json.RawMessage(test.payload)})
			if !errors.Is(err, ErrRuntimeIPCUnavailable) {
				t.Fatalf("decodeRuntimeResponse() error = %v, want ErrRuntimeIPCUnavailable", err)
			}
		})
	}
}

func TestDecodeRuntimeResponseAcceptsClosedSuccessAndFailure(t *testing.T) {
	success, err := decodeRuntimeResponse(ipcFrame{Payload: json.RawMessage(`{"ok":true,"result":{"data":{"ok":true}}}`)})
	if err != nil || !success.OK || string(success.Result) != `{"data":{"ok":true}}` {
		t.Fatalf("success = %#v, error = %v", success, err)
	}
	failure, err := decodeRuntimeResponse(ipcFrame{Payload: json.RawMessage(`{"ok":false,"code":"FAILED","message":"failed","error_origin":"runtime"}`)})
	if err != nil || failure.OK || failure.Code != "FAILED" || failure.Message != "failed" || failure.ErrorOrigin != WorkerErrorOriginRuntime {
		t.Fatalf("failure = %#v, error = %v", failure, err)
	}
}

func TestRuntimeLimitsMustBeExplicitAndValid(t *testing.T) {
	if _, err := newTestProcessSupervisor(t, ProcessSupervisorOptions{RuntimePath: os.Args[0], StreamSink: &recordingRuntimeStreamSink{}}); err == nil {
		t.Fatal("NewProcessSupervisor() accepted zero runtime limits")
	}
	limits := DefaultRuntimeLimits()
	if err := ValidateRuntimeLimits(limits); err != nil {
		t.Fatalf("DefaultRuntimeLimits() error = %v", err)
	}
	if _, err := newTestProcessSupervisor(t, ProcessSupervisorOptions{
		RuntimePath:           os.Args[0],
		Limits:                limits,
		HandshakeTimeout:      5 * time.Second,
		HeartbeatInterval:     2 * time.Second,
		MaxHeartbeatStaleness: 5 * time.Second,
	}); !errors.Is(err, ErrRuntimeHostServicesInvalid) {
		t.Fatalf("NewProcessSupervisor(without host services) error = %v, want %v", err, ErrRuntimeHostServicesInvalid)
	}
	supervisor, err := newTestProcessSupervisor(t, ProcessSupervisorOptions{
		RuntimePath:           os.Args[0],
		Limits:                limits,
		StreamSink:            &recordingRuntimeStreamSink{},
		HandshakeTimeout:      5 * time.Second,
		HeartbeatInterval:     2 * time.Second,
		MaxHeartbeatStaleness: 5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if supervisor.limits != limits {
		t.Fatalf("runtime limits = %#v, want %#v", supervisor.limits, limits)
	}
	maximums := RuntimeLimits{
		WorkerCount:            RuntimeWorkerCountMax,
		QueueCapacity:          RuntimeQueueCapacityMax,
		PerPluginConcurrency:   RuntimePerPluginConcurrencyMax,
		ModuleCacheEntries:     RuntimeModuleCacheEntriesMax,
		ModuleCacheSourceBytes: RuntimeModuleCacheSourceBytesMax,
	}
	if err := ValidateRuntimeLimits(maximums); err != nil {
		t.Fatalf("ValidateRuntimeLimits(maximums) error = %v", err)
	}
	invalid := []RuntimeLimits{
		{},
		{WorkerCount: RuntimeWorkerCountMax + 1, QueueCapacity: 1, PerPluginConcurrency: 1, ModuleCacheEntries: 1, ModuleCacheSourceBytes: 1},
		{WorkerCount: 1, QueueCapacity: RuntimeQueueCapacityMax + 1, PerPluginConcurrency: 1, ModuleCacheEntries: 1, ModuleCacheSourceBytes: 1},
		{WorkerCount: 1, QueueCapacity: 1, PerPluginConcurrency: RuntimePerPluginConcurrencyMax + 1, ModuleCacheEntries: 1, ModuleCacheSourceBytes: 1},
		{WorkerCount: 1, QueueCapacity: 1, PerPluginConcurrency: 2, ModuleCacheEntries: 1, ModuleCacheSourceBytes: 1},
		{WorkerCount: 1, QueueCapacity: 1, PerPluginConcurrency: 1, ModuleCacheEntries: RuntimeModuleCacheEntriesMax + 1, ModuleCacheSourceBytes: 1},
		{WorkerCount: 1, QueueCapacity: 1, PerPluginConcurrency: 1, ModuleCacheEntries: 1, ModuleCacheSourceBytes: RuntimeModuleCacheSourceBytesMax + 1},
	}
	for _, limits := range invalid {
		if err := ValidateRuntimeLimits(limits); !errors.Is(err, ErrRuntimeLimitsInvalid) {
			if err == nil {
				t.Fatalf("ValidateRuntimeLimits(%#v) accepted invalid limits", limits)
			}
			t.Fatalf("ValidateRuntimeLimits(%#v) error = %v, want %v", limits, err, ErrRuntimeLimitsInvalid)
		}
	}
}

func TestProcessSupervisorTimingMustBeExplicitAndValid(t *testing.T) {
	valid := ProcessSupervisorOptions{
		RuntimePath:           os.Args[0],
		Limits:                DefaultRuntimeLimits(),
		StreamSink:            &recordingRuntimeStreamSink{},
		IOBroker:              testRuntimeIOBroker{},
		HandshakeTimeout:      5 * time.Second,
		HeartbeatInterval:     2 * time.Second,
		MaxHeartbeatStaleness: 5 * time.Second,
	}
	tests := []struct {
		name   string
		mutate func(*ProcessSupervisorOptions)
	}{
		{name: "zero handshake timeout", mutate: func(options *ProcessSupervisorOptions) { options.HandshakeTimeout = 0 }},
		{name: "negative handshake timeout", mutate: func(options *ProcessSupervisorOptions) { options.HandshakeTimeout = -time.Second }},
		{name: "zero heartbeat interval", mutate: func(options *ProcessSupervisorOptions) { options.HeartbeatInterval = 0 }},
		{name: "negative heartbeat interval", mutate: func(options *ProcessSupervisorOptions) { options.HeartbeatInterval = -time.Second }},
		{name: "zero heartbeat staleness", mutate: func(options *ProcessSupervisorOptions) { options.MaxHeartbeatStaleness = 0 }},
		{name: "negative heartbeat staleness", mutate: func(options *ProcessSupervisorOptions) { options.MaxHeartbeatStaleness = -time.Second }},
		{name: "staleness below interval", mutate: func(options *ProcessSupervisorOptions) { options.MaxHeartbeatStaleness = time.Second }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			options := valid
			test.mutate(&options)
			if _, err := newTestProcessSupervisor(t, options); err == nil {
				t.Fatal("NewProcessSupervisor() accepted invalid runtime timing")
			}
		})
	}
}

func TestProcessSupervisorRequiresExplicitDescriptor(t *testing.T) {
	_, err := NewProcessSupervisor(ProcessSupervisorOptions{
		RuntimePath:           os.Args[0],
		Limits:                DefaultRuntimeLimits(),
		StreamSink:            &recordingRuntimeStreamSink{},
		HandshakeTimeout:      5 * time.Second,
		HeartbeatInterval:     2 * time.Second,
		MaxHeartbeatStaleness: 5 * time.Second,
	})
	if !errors.Is(err, ErrRuntimeArtifactIdentityInvalid) {
		t.Fatalf("NewProcessSupervisor() error = %v, want ErrRuntimeArtifactIdentityInvalid", err)
	}
}

func TestProcessSupervisorRejectsDigestMismatchBeforeStartingProcess(t *testing.T) {
	markerPath := filepath.Join(t.TempDir(), "runtime-started")
	supervisor, err := NewProcessSupervisor(ProcessSupervisorOptions{
		RuntimePath:           os.Args[0],
		ArtifactIdentity:      testRuntimeArtifactIdentity(testRuntimeTarget, strings.Repeat("0", 64)),
		Args:                  []string{"-test.run=TestMain"},
		Env:                   append(os.Environ(), "REDEVPLUGIN_RUNTIMECLIENT_HELPER=1", "REDEVPLUGIN_RUNTIMECLIENT_START_MARKER="+markerPath),
		Limits:                DefaultRuntimeLimits(),
		StreamSink:            &recordingRuntimeStreamSink{},
		IOBroker:              testRuntimeIOBroker{},
		HandshakeTimeout:      5 * time.Second,
		HeartbeatInterval:     2 * time.Second,
		MaxHeartbeatStaleness: 5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := supervisor.Start(context.Background(), testRuntimeTarget); !errors.Is(err, ErrRuntimeArtifactDigest) {
		t.Fatalf("Start() error = %v, want ErrRuntimeArtifactDigest", err)
	}
	if _, err := os.Stat(markerPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("runtime helper process was started before digest validation: %v", err)
	}
}

func TestProcessSupervisorRejectsHelloDescriptorMismatch(t *testing.T) {
	for _, test := range []struct {
		name               string
		env                string
		descriptorMismatch bool
	}{
		{name: "platform version", env: "REDEVPLUGIN_RUNTIMECLIENT_ACK_PLATFORM_VERSION=99.0.0", descriptorMismatch: true},
		{name: "build metadata", env: "REDEVPLUGIN_RUNTIMECLIENT_ACK_PLATFORM_VERSION=" + version.CurrentPlatformVersion() + "+different-build", descriptorMismatch: true},
		{name: "target", env: "REDEVPLUGIN_RUNTIMECLIENT_ACK_TARGET=linux/arm64", descriptorMismatch: true},
		{name: "internal wire", env: "REDEVPLUGIN_RUNTIMECLIENT_ACK_INTERNAL_WIRE=2"},
		{name: "runtime artifact", env: "REDEVPLUGIN_RUNTIMECLIENT_ACK_ARTIFACT_SHA256=" + strings.Repeat("f", 64), descriptorMismatch: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			supervisor, err := newTestProcessSupervisor(t, ProcessSupervisorOptions{
				RuntimePath:           os.Args[0],
				Args:                  []string{"-test.run=TestMain"},
				Env:                   append(os.Environ(), "REDEVPLUGIN_RUNTIMECLIENT_HELPER=1", test.env),
				Limits:                DefaultRuntimeLimits(),
				StreamSink:            &recordingRuntimeStreamSink{},
				HandshakeTimeout:      5 * time.Second,
				HeartbeatInterval:     2 * time.Second,
				MaxHeartbeatStaleness: 5 * time.Second,
			})
			if err != nil {
				t.Fatal(err)
			}
			err = supervisor.Start(context.Background(), testRuntimeTarget)
			if !errors.Is(err, ErrRuntimeHandshake) || (test.descriptorMismatch && !errors.Is(err, ErrRuntimeArtifactIdentityMismatch)) {
				t.Fatalf("Start() error = %v, want handshake rejection", err)
			}
			health, healthErr := supervisor.Health(context.Background())
			if healthErr != nil {
				t.Fatal(healthErr)
			}
			if health.Ready {
				t.Fatalf("mismatched hello left runtime ready: %#v", health)
			}
		})
	}
}

func TestProcessSupervisorRejectsTypedNilHostStreamSink(t *testing.T) {
	var typedNil *recordingRuntimeStreamSink
	_, err := newTestProcessSupervisor(t, ProcessSupervisorOptions{
		RuntimePath:           os.Args[0],
		Limits:                DefaultRuntimeLimits(),
		HandshakeTimeout:      5 * time.Second,
		HeartbeatInterval:     2 * time.Second,
		MaxHeartbeatStaleness: 5 * time.Second,
		StreamSink:            typedNil,
	})
	if !errors.Is(err, ErrRuntimeHostServicesInvalid) {
		t.Fatalf("NewProcessSupervisor(typed nil stream sink) error = %v, want %v", err, ErrRuntimeHostServicesInvalid)
	}
}

func TestRuntimeAdmissionCancellationDoesNotConsumeCapacity(t *testing.T) {
	controller := newRuntimeAdmissionController(RuntimeLimits{WorkerCount: 1, QueueCapacity: 1, PerPluginConcurrency: 1})
	releaseFirst, err := controller.acquire(context.Background(), "plugini_waiting")
	if err != nil {
		t.Fatal(err)
	}
	releaseSecond, err := controller.acquire(context.Background(), "plugini_waiting")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if _, err := controller.acquire(ctx, "plugini_waiting"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("acquire() error = %v, want %v", err, context.DeadlineExceeded)
	}
	releaseFirst()
	releaseSecond()
	release, err := controller.acquire(context.Background(), "plugini_waiting")
	if err != nil {
		t.Fatalf("acquire() after cancellation error = %v", err)
	}
	release()
}

func TestRuntimeAdmissionPreservesQueueCapacityForOtherPlugins(t *testing.T) {
	controller := newRuntimeAdmissionController(RuntimeLimits{WorkerCount: 8, QueueCapacity: 32, PerPluginConcurrency: 4})
	releases := make([]func(), 0, 9)
	for index := 0; index < 8; index++ {
		release, err := controller.acquire(context.Background(), "plugini_saturated")
		if err != nil {
			t.Fatal(err)
		}
		releases = append(releases, release)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if _, err := controller.acquire(ctx, "plugini_saturated"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("ninth saturated-plugin acquire error = %v, want %v", err, context.DeadlineExceeded)
	}
	releaseOther, err := controller.acquire(context.Background(), "plugini_other")
	if err != nil {
		t.Fatalf("other plugin acquire error = %v", err)
	}
	releases = append(releases, releaseOther)
	for _, release := range releases {
		release()
	}
}

func TestProcessSupervisorMultiplexesSameShardInvocations(t *testing.T) {
	supervisor, err := newTestProcessSupervisor(t, ProcessSupervisorOptions{
		Limits:                RuntimeLimits{WorkerCount: 2, QueueCapacity: 2, PerPluginConcurrency: 2, ModuleCacheEntries: 1, ModuleCacheSourceBytes: 1 << 20},
		HandshakeTimeout:      5 * time.Second,
		HeartbeatInterval:     2 * time.Second,
		MaxHeartbeatStaleness: 5 * time.Second,
		RuntimePath:           os.Args[0],
		Args:                  []string{"-test.run=TestMain"},
		Env:                   append(os.Environ(), "REDEVPLUGIN_RUNTIMECLIENT_HELPER=1", "REDEVPLUGIN_RUNTIMECLIENT_MULTIPLEX=1"),
		StreamSink:            &recordingRuntimeStreamSink{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := supervisor.Start(context.Background(), testRuntimeTarget); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { stopRuntimeSupervisor(t, supervisor) })

	slowDone := make(chan error, 1)
	go func() {
		_, err := supervisor.invokeWorkerForTest(context.Background(), Lease{LeaseID: "lease_multiplex_slow", InvocationID: "invoke_multiplex_slow"}, "worker.echo", workerInvocationFixture())
		slowDone <- err
	}()
	waitForSustainedIPCLock(t, supervisor, 20*time.Millisecond)
	fastDone := make(chan error, 1)
	go func() {
		_, err := supervisor.invokeWorkerForTest(context.Background(), Lease{LeaseID: "lease_multiplex_fast", InvocationID: "invoke_multiplex_fast"}, "worker.echo", workerInvocationFixture())
		fastDone <- err
	}()
	select {
	case err := <-fastDone:
		if err != nil {
			t.Fatalf("fast invocation error = %v", err)
		}
	case err := <-slowDone:
		t.Fatalf("slow invocation completed before fast invocation: %v", err)
	case <-time.After(time.Second):
		t.Fatal("multiplexed invocations did not complete")
	}
	if err := <-slowDone; err != nil {
		t.Fatalf("slow invocation error = %v", err)
	}
}

func TestProcessSupervisorControlIPCRemainsAvailableWhenInvocationAdmissionIsFull(t *testing.T) {
	supervisor, err := newTestProcessSupervisor(t, ProcessSupervisorOptions{
		Limits:                RuntimeLimits{WorkerCount: 1, QueueCapacity: 1, PerPluginConcurrency: 1, ModuleCacheEntries: 1, ModuleCacheSourceBytes: 1 << 20},
		HandshakeTimeout:      5 * time.Second,
		HeartbeatInterval:     2 * time.Second,
		MaxHeartbeatStaleness: 5 * time.Second,
		RuntimePath:           os.Args[0],
		Args:                  []string{"-test.run=TestMain"},
		Env:                   append(os.Environ(), "REDEVPLUGIN_RUNTIMECLIENT_HELPER=1", "REDEVPLUGIN_RUNTIMECLIENT_WAIT_FOR_REVOKE_DURING_INVOKE=1"),
		StreamSink:            &recordingRuntimeStreamSink{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := supervisor.Start(context.Background(), testRuntimeTarget); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	t.Cleanup(func() { stopRuntimeSupervisor(t, supervisor) })

	activeDone := make(chan error, 1)
	go func() {
		_, invokeErr := supervisor.invokeWorkerForTest(context.Background(), Lease{LeaseID: "lease_control_active", InvocationID: "invoke_control_active"}, "worker.echo", workerInvocationFixture())
		activeDone <- invokeErr
	}()
	waitForSustainedIPCLock(t, supervisor, 20*time.Millisecond)
	pendingDone := make(chan error, 1)
	go func() {
		_, invokeErr := supervisor.invokeWorkerForTest(context.Background(), Lease{LeaseID: "lease_control_pending", InvocationID: "invoke_control_pending"}, "worker.echo", workerInvocationFixture())
		pendingDone <- invokeErr
	}()
	waitForInvocationAdmissionCount(t, supervisor, 2)

	controlCtx, cancelControl := context.WithTimeout(context.Background(), time.Second)
	defer cancelControl()
	if _, err := supervisor.Heartbeat(controlCtx); err != nil {
		t.Fatalf("Heartbeat() while invocation admission was full: %v", err)
	}
	if _, err := supervisor.Revoke(controlCtx, testRevokeRequest("plugini_1", 2)); err != nil {
		t.Fatalf("Revoke() while invocation admission was full: %v", err)
	}
	for index, done := range []<-chan error{activeDone, pendingDone} {
		select {
		case invokeErr := <-done:
			if !errors.Is(invokeErr, ErrRuntimeRequestFailed) {
				t.Fatalf("invocation %d error = %v, want %v", index, invokeErr, ErrRuntimeRequestFailed)
			}
		case <-time.After(time.Second):
			t.Fatalf("invocation %d did not exit after revoke", index)
		}
	}
	waitForInvocationAdmissionCount(t, supervisor, 0)
}

func TestProcessSupervisorDrainsCanceledInvocationWithoutInvalidatingRuntime(t *testing.T) {
	store := observability.NewMemoryStore()
	supervisor, err := newTestProcessSupervisor(t, ProcessSupervisorOptions{
		Limits:                DefaultRuntimeLimits(),
		HandshakeTimeout:      5 * time.Second,
		HeartbeatInterval:     2 * time.Second,
		MaxHeartbeatStaleness: 5 * time.Second,
		RuntimePath:           os.Args[0],
		Args:                  []string{"-test.run=TestMain"},
		Env:                   append(os.Environ(), "REDEVPLUGIN_RUNTIMECLIENT_HELPER=1", "REDEVPLUGIN_RUNTIMECLIENT_DELAY_INVOKE_MILLIS=80"),
		Diagnostics:           store,
		StreamSink:            &recordingRuntimeStreamSink{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := supervisor.Start(context.Background(), testRuntimeTarget); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	health, err := supervisor.Health(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if _, err := supervisor.invokeWorkerForTest(ctx, Lease{LeaseID: "lease_1", RuntimeGenerationID: health.RuntimeGenerationID, PluginInstanceID: "plugini_1"}, "worker.echo", workerInvocationFixture()); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("InvokeWorker() canceled error = %v, want %v", err, context.DeadlineExceeded)
	}
	health, err = supervisor.Health(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !health.Ready {
		t.Fatalf("runtime should remain ready after draining a canceled invocation: %#v", health)
	}
	if _, err := supervisor.invokeWorkerForTest(context.Background(), Lease{
		LeaseID:             "lease_2",
		RuntimeGenerationID: health.RuntimeGenerationID,
		PluginInstanceID:    "plugini_1",
	}, "worker.echo", workerInvocationFixture()); err != nil {
		t.Fatalf("InvokeWorker(after canceled invocation) error = %v", err)
	}
	stopRuntimeSupervisor(t, supervisor)
}

func TestProcessSupervisorRevokeUsesIndependentControlChannelDuringInvocation(t *testing.T) {
	store := observability.NewMemoryStore()
	supervisor, err := newTestProcessSupervisor(t, ProcessSupervisorOptions{
		Limits:                DefaultRuntimeLimits(),
		HandshakeTimeout:      5 * time.Second,
		HeartbeatInterval:     2 * time.Second,
		MaxHeartbeatStaleness: 5 * time.Second,
		RuntimePath:           os.Args[0],
		Args:                  []string{"-test.run=TestMain"},
		Env: append(os.Environ(),
			"REDEVPLUGIN_RUNTIMECLIENT_HELPER=1",
			"REDEVPLUGIN_RUNTIMECLIENT_WAIT_FOR_REVOKE_DURING_INVOKE=1",
		),
		Diagnostics: store,
		StreamSink:  &recordingRuntimeStreamSink{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := supervisor.Start(context.Background(), testRuntimeTarget); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	health, err := supervisor.Health(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := supervisor.invokeWorkerForTest(context.Background(), Lease{
			LeaseID:             "lease_busy",
			RuntimeGenerationID: health.RuntimeGenerationID,
			PluginInstanceID:    "plugini_1",
		}, "worker.echo", workerInvocationFixture())
		done <- err
	}()
	waitForSustainedIPCLock(t, supervisor, 20*time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	result, err := supervisor.Revoke(ctx, testRevokeRequest("plugini_1", 4))
	if err != nil {
		t.Fatalf("Revoke(during invocation) error = %v", err)
	}
	if result.PluginInstanceID != "plugini_1" || result.RevokeEpoch != 4 {
		t.Fatalf("Revoke(during invocation) result = %#v", result)
	}
	select {
	case err := <-done:
		if !errors.Is(err, ErrRuntimeRequestFailed) {
			t.Fatalf("InvokeWorker(after revoke) error = %v, want %v", err, ErrRuntimeRequestFailed)
		}
	case <-time.After(time.Second):
		t.Fatal("InvokeWorker did not observe the concurrent revoke")
	}
	health, err = supervisor.Health(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !health.Ready {
		t.Fatalf("runtime should remain ready after a successful concurrent revoke: %#v", health)
	}
	stopRuntimeSupervisor(t, supervisor)
}

func TestProcessSupervisorHeartbeatInvalidatesStaleRuntime(t *testing.T) {
	store := &runtimeDiagnosticSink{}
	supervisor, err := newTestProcessSupervisor(t, ProcessSupervisorOptions{
		Limits:                DefaultRuntimeLimits(),
		HandshakeTimeout:      5 * time.Second,
		RuntimePath:           os.Args[0],
		Args:                  []string{"-test.run=TestMain"},
		Env:                   append(os.Environ(), "REDEVPLUGIN_RUNTIMECLIENT_HELPER=1", "REDEVPLUGIN_RUNTIMECLIENT_BLOCK_HEARTBEAT=1"),
		Diagnostics:           store,
		HeartbeatInterval:     10 * time.Millisecond,
		MaxHeartbeatStaleness: 30 * time.Millisecond,
		StreamSink:            &recordingRuntimeStreamSink{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := supervisor.Start(context.Background(), testRuntimeTarget); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	waitForDiagnostic(t, store, "plugin.runtime.ipc.invalidated")
	health, err := supervisor.Health(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if health.Ready {
		t.Fatalf("runtime should be marked not ready after stale heartbeat: %#v", health)
	}
	stopRuntimeSupervisor(t, supervisor)
}

func TestProcessSupervisorStopWaitsForInvalidatedProcessBeforeRestart(t *testing.T) {
	supervisor, err := newTestProcessSupervisor(t, ProcessSupervisorOptions{
		Limits:                DefaultRuntimeLimits(),
		HandshakeTimeout:      5 * time.Second,
		HeartbeatInterval:     2 * time.Second,
		MaxHeartbeatStaleness: 5 * time.Second,
		RuntimePath:           os.Args[0],
		Args:                  []string{"-test.run=TestMain"},
		Env:                   append(os.Environ(), "REDEVPLUGIN_RUNTIMECLIENT_HELPER=1"),
		StreamSink:            &recordingRuntimeStreamSink{},
	})
	if err != nil {
		t.Fatal(err)
	}

	health := Health{RuntimeGenerationID: "generation_invalidated", Ready: true}
	exit := &processExit{done: make(chan struct{})}
	canceled := make(chan struct{})
	var cancelOnce sync.Once
	supervisor.mu.Lock()
	supervisor.process = &runtimeProcess{}
	supervisor.cancel = func() { cancelOnce.Do(func() { close(canceled) }) }
	supervisor.exit = exit
	supervisor.health = health
	supervisor.mu.Unlock()

	supervisor.invalidateRuntimeAfterIPCFailure(health, errors.New("ipc failed"))
	select {
	case <-canceled:
	case <-time.After(time.Second):
		t.Fatal("runtime invalidation did not cancel the process context")
	}

	stopDone := make(chan error, 1)
	go func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		stopDone <- supervisor.Stop(stopCtx)
	}()
	select {
	case err := <-stopDone:
		t.Fatalf("Stop() returned before invalidated process cleanup: %v", err)
	case <-time.After(20 * time.Millisecond):
	}

	supervisor.mu.Lock()
	supervisor.process = nil
	supervisor.cancel = nil
	supervisor.exit = nil
	supervisor.mu.Unlock()
	close(exit.done)
	if err := <-stopDone; err != nil {
		t.Fatalf("Stop() after invalidated process cleanup error = %v", err)
	}

	if err := supervisor.Start(context.Background(), testRuntimeTarget); err != nil {
		t.Fatalf("Start() after invalidated process cleanup error = %v", err)
	}
	stopRuntimeSupervisor(t, supervisor)
}

func TestProcessSupervisorConcurrentStopWaitersObserveSameExit(t *testing.T) {
	supervisor, err := newTestProcessSupervisor(t, ProcessSupervisorOptions{
		RuntimePath:           os.Args[0],
		Limits:                DefaultRuntimeLimits(),
		StreamSink:            &recordingRuntimeStreamSink{},
		HandshakeTimeout:      5 * time.Second,
		HeartbeatInterval:     2 * time.Second,
		MaxHeartbeatStaleness: 5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	exit := &processExit{done: make(chan struct{})}
	canceled := make(chan struct{})
	var cancelOnce sync.Once
	supervisor.mu.Lock()
	supervisor.process = &runtimeProcess{}
	supervisor.cancel = func() { cancelOnce.Do(func() { close(canceled) }) }
	supervisor.exit = exit
	supervisor.health = Health{RuntimeGenerationID: "generation_concurrent_stop", Ready: true}
	supervisor.mu.Unlock()

	const waiters = 16
	results := make(chan error, waiters)
	for range waiters {
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			results <- supervisor.Stop(ctx)
		}()
	}
	select {
	case <-canceled:
	case <-time.After(time.Second):
		t.Fatal("concurrent Stop() calls did not cancel the process")
	}
	select {
	case err := <-results:
		t.Fatalf("Stop() returned before process exit: %v", err)
	case <-time.After(20 * time.Millisecond):
	}

	supervisor.mu.Lock()
	supervisor.process = nil
	supervisor.cancel = nil
	supervisor.exit = nil
	supervisor.mu.Unlock()
	close(exit.done)
	for index := 0; index < waiters; index++ {
		select {
		case err := <-results:
			if err != nil {
				t.Fatalf("Stop() waiter %d error = %v", index, err)
			}
		case <-time.After(time.Second):
			t.Fatalf("Stop() waiter %d did not observe process exit", index)
		}
	}
}

func TestProcessSupervisorStopMakesGenerationUnavailableBeforeExit(t *testing.T) {
	supervisor, err := newTestProcessSupervisor(t, ProcessSupervisorOptions{
		RuntimePath:           os.Args[0],
		Limits:                DefaultRuntimeLimits(),
		StreamSink:            &recordingRuntimeStreamSink{},
		HandshakeTimeout:      5 * time.Second,
		HeartbeatInterval:     2 * time.Second,
		MaxHeartbeatStaleness: 5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	exit := &processExit{done: make(chan struct{})}
	canceled := make(chan struct{})
	var cancelOnce sync.Once
	supervisor.mu.Lock()
	supervisor.process = &runtimeProcess{}
	supervisor.cancel = func() { cancelOnce.Do(func() { close(canceled) }) }
	supervisor.exit = exit
	supervisor.health = Health{
		RuntimeInstanceID: "runtime_stopping", RuntimeGenerationID: "generation_stopping",
		IPCChannelID: "ipc_stopping", Ready: true,
	}
	supervisor.mu.Unlock()

	stopDone := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		stopDone <- supervisor.Stop(ctx)
	}()
	select {
	case <-canceled:
	case <-time.After(time.Second):
		t.Fatal("Stop() did not cancel the runtime")
	}
	health, err := supervisor.Health(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if health.Ready {
		t.Fatalf("Health() remained ready while Stop() waited for process exit: %#v", health)
	}
	if err := supervisor.Start(context.Background(), testRuntimeTarget); !errors.Is(err, ErrRuntimeNotReady) {
		t.Fatalf("Start() during Stop() error = %v, want %v", err, ErrRuntimeNotReady)
	}
	if _, err := supervisor.InvokeWorker(context.Background(), Lease{}, "worker.echo", workerInvocationFixture()); !errors.Is(err, ErrRuntimeNotReady) {
		t.Fatalf("InvokeWorker() during Stop() error = %v, want %v", err, ErrRuntimeNotReady)
	}
	supervisor.admission.mu.Lock()
	pending := supervisor.admission.active
	supervisor.admission.mu.Unlock()
	if pending != 0 {
		t.Fatalf("Stop-in-progress invocation admission count = %d, want 0", pending)
	}

	supervisor.mu.Lock()
	supervisor.process = nil
	supervisor.cancel = nil
	supervisor.exit = nil
	supervisor.mu.Unlock()
	close(exit.done)
	if err := <-stopDone; err != nil {
		t.Fatal(err)
	}
}

func TestProcessSupervisorHeartbeatContinuesWhileIPCRequestIsInFlight(t *testing.T) {
	store := observability.NewMemoryStore()
	supervisor, err := newTestProcessSupervisor(t, ProcessSupervisorOptions{
		Limits:           DefaultRuntimeLimits(),
		HandshakeTimeout: 5 * time.Second,
		RuntimePath:      os.Args[0],
		Args:             []string{"-test.run=TestMain"},
		Env: append(os.Environ(),
			"REDEVPLUGIN_RUNTIMECLIENT_HELPER=1",
			"REDEVPLUGIN_RUNTIMECLIENT_DELAY_INVOKE_MILLIS=200",
			"REDEVPLUGIN_RUNTIMECLIENT_REQUIRE_HEARTBEAT_DURING_INVOKE=1",
		),
		Diagnostics:           store,
		HeartbeatInterval:     10 * time.Millisecond,
		MaxHeartbeatStaleness: 30 * time.Millisecond,
		StreamSink:            &recordingRuntimeStreamSink{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := supervisor.Start(context.Background(), testRuntimeTarget); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	health, err := supervisor.Health(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	invokeDone := make(chan error, 1)
	go func() {
		_, invokeErr := supervisor.invokeWorkerForTest(context.Background(), Lease{
			LeaseID:             "lease_heartbeat_busy",
			RuntimeGenerationID: health.RuntimeGenerationID,
			PluginInstanceID:    "plugini_1",
		}, "worker.echo", workerInvocationFixture())
		invokeDone <- invokeErr
	}()
	waitForSustainedIPCLock(t, supervisor, 20*time.Millisecond)
	time.Sleep(3 * supervisor.maxHeartbeatStaleness)
	health, err = supervisor.Health(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !health.Ready {
		t.Fatalf("runtime should remain ready while a valid IPC request is in flight: %#v", health)
	}
	select {
	case err := <-invokeDone:
		if err != nil {
			t.Fatalf("InvokeWorker() error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("InvokeWorker() did not finish")
	}
	if _, err := supervisor.Heartbeat(context.Background()); err != nil {
		t.Fatalf("Heartbeat(after in-flight request) error = %v", err)
	}
	stopRuntimeSupervisor(t, supervisor)
}

func TestProcessSupervisorRejectsRevokeWhenRuntimeIsNotReady(t *testing.T) {
	supervisor, err := newTestProcessSupervisor(t, ProcessSupervisorOptions{
		Limits:                DefaultRuntimeLimits(),
		HandshakeTimeout:      5 * time.Second,
		HeartbeatInterval:     2 * time.Second,
		MaxHeartbeatStaleness: 5 * time.Second,
		RuntimePath:           os.Args[0],
		Args:                  []string{"-test.run=TestMain"},
		StreamSink:            &recordingRuntimeStreamSink{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := supervisor.Revoke(context.Background(), testRevokeRequest("plugini_1", 1)); !errors.Is(err, ErrRuntimeNotReady) {
		t.Fatalf("Revoke(not ready) error = %v, want ErrRuntimeNotReady", err)
	}
}

func TestDecodeRevokeResultRequiresStructuredCounters(t *testing.T) {
	request := testRevokeRequest("plugini_1", 3)
	_, err := decodeRevokeResult(json.RawMessage(`{"plugin_instance_id":"plugini_1","revoke_epoch":3}`), request)
	if !errors.Is(err, ErrRuntimeRequestFailed) {
		t.Fatalf("decodeRevokeResult(missing counters) error = %v, want ErrRuntimeRequestFailed", err)
	}
	_, err = decodeRevokeResult(json.RawMessage(`{"resource_scope":{"kind":"environment","owner_env_hash":"env_hash"},"plugin_instance_id":"other","revoke_epoch":3,"closed_socket_count":0,"closed_stream_count":0,"closed_storage_handle_count":0}`), request)
	if !errors.Is(err, ErrRuntimeRequestFailed) {
		t.Fatalf("decodeRevokeResult(plugin mismatch) error = %v, want ErrRuntimeRequestFailed", err)
	}
	if _, err := decodeRevokeResult(json.RawMessage(`{"resource_scope":{"kind":"environment","owner_env_hash":"env_hash"},"plugin_instance_id":"plugini_1","revoke_epoch":3,"closed_socket_count":0,"closed_stream_count":0,"closed_storage_handle_count":0,"extra":true}`), request); err == nil {
		t.Fatal("decodeRevokeResult(extra field) expected fail-closed error")
	}
	result, err := decodeRevokeResult(json.RawMessage(`{"resource_scope":{"kind":"environment","owner_env_hash":"env_hash"},"plugin_instance_id":"plugini_1","revoke_epoch":3,"closed_socket_count":2,"closed_stream_count":3,"closed_storage_handle_count":4}`), request)
	if err != nil {
		t.Fatalf("decodeRevokeResult() error = %v", err)
	}
	if result.ClosedSocketCount != 2 || result.ClosedStreamCount != 3 || result.ClosedStorageHandleCount != 4 {
		t.Fatalf("decodeRevokeResult() result mismatch: %#v", result)
	}
}

func TestDecodeSessionRevokeResultIsClosedAndGenerationBound(t *testing.T) {
	request := SessionRevokeRequest{SessionScope: sessionctx.SessionScope{
		OwnerSessionHash: "session_hash", OwnerUserHash: "user_hash", OwnerEnvHash: "env_hash", SessionChannelIDHash: "channel_hash",
	}, SessionRevokeSequence: 7}
	valid := json.RawMessage(`{"session_revoke_sequence":7,"state":"complete","counts":{"queued_invocations":1,"running_invocations":2,"storage_hostcalls":3,"active_network_requests":4,"sockets":5,"network_streams":6}}`)
	result, err := decodeSessionRevokeResult(valid, "generation_1", request)
	if err != nil {
		t.Fatalf("decodeSessionRevokeResult() error = %v", err)
	}
	if result.RuntimeGenerationID != "generation_1" || result.State != SessionRevokeStateComplete || result.Counts.NetworkStreams != 6 {
		t.Fatalf("decodeSessionRevokeResult() = %#v", result)
	}
	for name, raw := range map[string]json.RawMessage{
		"missing counts":  json.RawMessage(`{"session_revoke_sequence":7,"state":"complete"}`),
		"wrong sequence":  json.RawMessage(`{"session_revoke_sequence":8,"state":"complete","counts":{"queued_invocations":0,"running_invocations":0,"storage_hostcalls":0,"active_network_requests":0,"sockets":0,"network_streams":0}}`),
		"unknown state":   json.RawMessage(`{"session_revoke_sequence":7,"state":"partial","counts":{"queued_invocations":0,"running_invocations":0,"storage_hostcalls":0,"active_network_requests":0,"sockets":0,"network_streams":0}}`),
		"unknown field":   json.RawMessage(`{"session_revoke_sequence":7,"state":"complete","counts":{"queued_invocations":0,"running_invocations":0,"storage_hostcalls":0,"active_network_requests":0,"sockets":0,"network_streams":0},"future":true}`),
		"unsafe counter":  json.RawMessage(`{"session_revoke_sequence":7,"state":"complete","counts":{"queued_invocations":9007199254740992,"running_invocations":0,"storage_hostcalls":0,"active_network_requests":0,"sockets":0,"network_streams":0}}`),
		"unknown counter": json.RawMessage(`{"session_revoke_sequence":7,"state":"complete","counts":{"queued_invocations":0,"running_invocations":0,"storage_hostcalls":0,"active_network_requests":0,"sockets":0,"network_streams":0,"future":0}}`),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeSessionRevokeResult(raw, "generation_1", request); !errors.Is(err, ErrRuntimeRequestFailed) {
				t.Fatalf("decodeSessionRevokeResult() error = %v, want ErrRuntimeRequestFailed", err)
			}
		})
	}
	if _, err := decodeSessionRevokeResult(valid, "", request); !errors.Is(err, ErrRuntimeRequestFailed) {
		t.Fatalf("decodeSessionRevokeResult(missing generation) error = %v", err)
	}
}

func TestDecodeHeartbeatResultRequiresStructuredTiming(t *testing.T) {
	_, err := decodeHeartbeatResult(json.RawMessage(`{"runtime_generation_id":"gen_1","runtime_unix_nano":1}`), "gen_1")
	if !errors.Is(err, ErrRuntimeRequestFailed) {
		t.Fatalf("decodeHeartbeatResult(missing fields) error = %v, want ErrRuntimeRequestFailed", err)
	}
	_, err = decodeHeartbeatResult(json.RawMessage(`{"runtime_generation_id":"other","runtime_unix_nano":1,"max_staleness_ms":5000,"host_sent_unix_nano":1}`), "gen_1")
	if !errors.Is(err, ErrRuntimeRequestFailed) {
		t.Fatalf("decodeHeartbeatResult(generation mismatch) error = %v, want ErrRuntimeRequestFailed", err)
	}
	if _, err := decodeHeartbeatResult(json.RawMessage(`{"runtime_generation_id":"gen_1","runtime_unix_nano":1,"max_staleness_ms":5000,"host_sent_unix_nano":1,"extra":true}`), "gen_1"); err == nil {
		t.Fatal("decodeHeartbeatResult(extra field) expected fail-closed error")
	}
	result, err := decodeHeartbeatResult(json.RawMessage(`{"runtime_generation_id":"gen_1","runtime_unix_nano":2,"max_staleness_ms":5000,"host_sent_unix_nano":1}`), "gen_1")
	if err != nil {
		t.Fatalf("decodeHeartbeatResult() error = %v", err)
	}
	if result.RuntimeGenerationID != "gen_1" || result.RuntimeUnixNano != 2 || result.MaxStalenessMillis != 5000 || result.HostSentUnixNanoEcho != 1 {
		t.Fatalf("decodeHeartbeatResult() result mismatch: %#v", result)
	}
}

func TestIPCGoldenFixtures(t *testing.T) {
	expectedFixtureNames := []string{
		"missing_required.json",
		"replay_frame.json",
		"runtime_generation_mismatch.json",
		"unknown_enum.json",
		"valid_hello_ack.json",
		"valid_invoke_worker_result.json",
		"valid_session_revoke.json",
		"valid_session_revoke_ack.json",
	}
	files, err := filepath.Glob(filepath.Join("..", "..", "testdata", "contracts", "ipc", "*.json"))
	if err != nil {
		t.Fatalf("glob ipc fixtures: %v", err)
	}
	sort.Strings(files)
	if len(files) != len(expectedFixtureNames) {
		t.Fatalf("IPC golden fixture count = %d, want exactly %d current-protocol fixtures", len(files), len(expectedFixtureNames))
	}
	for index, file := range files {
		if got := filepath.Base(file); got != expectedFixtureNames[index] {
			t.Fatalf("IPC golden fixture %d = %q, want %q", index, got, expectedFixtureNames[index])
		}
	}
	for _, file := range files {
		t.Run(filepath.Base(file), func(t *testing.T) {
			raw, err := os.ReadFile(file)
			if err != nil {
				t.Fatalf("read fixture: %v", err)
			}
			if filepath.Base(file) == "valid_session_revoke.json" || filepath.Base(file) == "valid_session_revoke_ack.json" {
				if err := validateSessionRevokeGoldenFixture(filepath.Base(file), raw); err != nil {
					t.Fatalf("fixture error = %v", err)
				}
				return
			}
			var fixture ipcGoldenFixture
			if err := json.Unmarshal(raw, &fixture); err != nil {
				t.Fatalf("decode fixture: %v", err)
			}
			if fixture.Name == "" || fixture.Kind == "" {
				t.Fatalf("fixture missing name/kind: %#v", fixture)
			}
			err = validateIPCGoldenFixture(fixture)
			if fixture.WantError {
				if err == nil {
					t.Fatal("fixture unexpectedly passed")
				}
				if fixture.ErrorContains != "" && !strings.Contains(err.Error(), fixture.ErrorContains) {
					t.Fatalf("fixture error = %v, want substring %q", err, fixture.ErrorContains)
				}
				return
			}
			if err != nil {
				t.Fatalf("fixture error = %v", err)
			}
		})
	}
}

func validateSessionRevokeGoldenFixture(name string, raw []byte) error {
	var frame ipcFrame
	if err := decodeStrictJSON(raw, &frame); err != nil {
		return err
	}
	request := SessionRevokeRequest{SessionScope: sessionctx.SessionScope{
		OwnerSessionHash: "owner_session_fixture_1", OwnerUserHash: "owner_user_fixture_1",
		OwnerEnvHash: "owner_env_fixture_1", SessionChannelIDHash: "session_channel_fixture_1",
	}, SessionRevokeSequence: 1}
	switch name {
	case "valid_session_revoke.json":
		if frame.FrameType != ipcFrameTypeSessionRevoke || frame.RequestID != "session_revoke_1" || frame.RuntimeGenerationID != "runtime_generation_fixture_1" {
			return errors.New("session revoke request frame identity mismatch")
		}
		var payload sessionRevokeRequestPayload
		if err := decodeStrictJSON(frame.Payload, &payload); err != nil {
			return err
		}
		if payload.SessionRevokeSequence != request.SessionRevokeSequence || payload.OwnerSessionHash != request.SessionScope.OwnerSessionHash ||
			payload.OwnerUserHash != request.SessionScope.OwnerUserHash || payload.OwnerEnvHash != request.SessionScope.OwnerEnvHash ||
			payload.SessionChannelIDHash != request.SessionScope.SessionChannelIDHash {
			return errors.New("session revoke request payload mismatch")
		}
		return nil
	case "valid_session_revoke_ack.json":
		if err := validateIPCResponse("session_revoke_1", "runtime_generation_fixture_1", ipcFrameTypeSessionRevokeAck, frame); err != nil {
			return err
		}
		response, err := decodeRuntimeResponse(frame)
		if err != nil {
			return err
		}
		_, err = decodeSessionRevokeResult(response.Result, frame.RuntimeGenerationID, request)
		return err
	default:
		return errors.New("unknown session revoke fixture")
	}
}

type ipcGoldenFixture struct {
	Name                string   `json:"name"`
	Kind                string   `json:"kind"`
	RequestID           string   `json:"request_id"`
	ParentRequestID     string   `json:"parent_request_id,omitempty"`
	RuntimeGenerationID string   `json:"runtime_generation_id"`
	ResponseFrameType   string   `json:"response_frame_type,omitempty"`
	ConnectionNonce     string   `json:"connection_nonce,omitempty"`
	WantError           bool     `json:"want_error"`
	ErrorContains       string   `json:"error_contains,omitempty"`
	Frame               ipcFrame `json:"frame"`
}

func validateIPCGoldenFixture(fixture ipcGoldenFixture) error {
	switch fixture.Kind {
	case "hello_ack":
		var ack helloAckPayload
		if err := json.Unmarshal(fixture.Frame.Payload, &ack); err != nil {
			return err
		}
		runtimeVersion, err := version.ParseSemVer(ack.PlatformVersion)
		if err != nil {
			return err
		}
		target, err := parseRuntimeAdmissionTarget(ack.ActualTarget)
		if err != nil {
			return err
		}
		identity, err := NewRuntimeArtifactIdentity(RuntimeArtifactIdentityOptions{
			PlatformVersion: runtimeVersion, Target: target, BinarySHA256: strings.Repeat("a", 64),
		})
		if err != nil {
			return err
		}
		_, err = validateHelloAck(fixture.RequestID, fixture.RuntimeGenerationID, fixture.ConnectionNonce, identity, ack.Limits, fixture.Frame)
		return err
	case "response":
		if err := validateIPCResponse(fixture.RequestID, fixture.RuntimeGenerationID, fixture.ResponseFrameType, fixture.Frame); err != nil {
			return err
		}
		_, err := decodeRuntimeResponse(fixture.Frame)
		return err
	default:
		return fmt.Errorf("unsupported ipc fixture kind %q", fixture.Kind)
	}
}

func TestWorkerInvocationContextBindsBrokerAccessHash(t *testing.T) {
	payload := workerInvocationFixtureWithAccess(workerBrokerAccess{
		Storage: []workerStorageBrokerAccess{{StoreID: "notes", Scope: "user", Operations: []string{"query"}}},
		Network: []workerNetworkBrokerAccess{{ConnectorID: "forecast", Transport: "http", Scope: "user", Operations: []string{"http"}, HTTPMethods: []string{"GET"}}},
	})
	lease := workerInvocationLeaseFixture()
	invocation, err := workerInvocationContextFromInvocation(lease, payload)
	if err != nil {
		t.Fatalf("workerInvocationContextFromInvocation() error = %v", err)
	}
	if len(invocation.BrokerAccess.Storage) != 1 || invocation.BrokerAccess.Storage[0].StoreID != "notes" ||
		len(invocation.BrokerAccess.Storage[0].Operations) != 1 || invocation.BrokerAccess.Storage[0].Operations[0] != "query" {
		t.Fatalf("storage broker access mismatch: %#v", invocation.BrokerAccess.Storage)
	}
	if len(invocation.BrokerAccess.Network) != 1 || invocation.BrokerAccess.Network[0].ConnectorID != "forecast" ||
		len(invocation.BrokerAccess.Network[0].HTTPMethods) != 1 || invocation.BrokerAccess.Network[0].HTTPMethods[0] != "GET" {
		t.Fatalf("network broker access mismatch: %#v", invocation.BrokerAccess.Network)
	}
	var tampered map[string]any
	if err := json.Unmarshal(payload, &tampered); err != nil {
		t.Fatal(err)
	}
	tampered["broker_access_sha256"] = "sha256:" + strings.Repeat("0", 64)
	rawTampered, err := json.Marshal(tampered)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := workerInvocationContextFromInvocation(lease, rawTampered); !errors.Is(err, ErrRuntimeRequestFailed) || !strings.Contains(err.Error(), "hash mismatch") {
		t.Fatalf("tampered broker access error = %v", err)
	}
}

func TestWorkerInvocationContextRejectsSignedLeaseAudienceMismatch(t *testing.T) {
	lease := workerInvocationLeaseFixture()
	for _, field := range []string{
		"plugin_id",
		"plugin_instance_id",
		"active_fingerprint",
		"runtime_instance_id",
		"runtime_generation_id",
		"method",
		"effect",
		"execution",
		"surface_instance_id",
		"owner_session_hash",
		"owner_user_hash",
		"owner_env_hash",
		"session_channel_id_hash",
		"bridge_channel_id",
		"execution_id",
		"audit_correlation_id",
	} {
		t.Run(field, func(t *testing.T) {
			var invocation map[string]any
			if err := json.Unmarshal(workerInvocationFixture(), &invocation); err != nil {
				t.Fatal(err)
			}
			invocation[field] = "spoofed"
			raw, err := json.Marshal(invocation)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := workerInvocationContextFromInvocation(lease, raw); !errors.Is(err, ErrRuntimeRequestFailed) || !strings.Contains(err.Error(), field) {
				t.Fatalf("audience mismatch error = %v, want %s mismatch", err, field)
			}
		})
	}
}

func TestProcessSupervisorServesBoundArtifactHandle(t *testing.T) {
	provider := &recordingArtifactProvider{
		content: []byte("wasm bytes"),
		sha256:  fixtureArtifactSHA,
	}
	supervisor, err := newTestProcessSupervisor(t, ProcessSupervisorOptions{
		Limits:                DefaultRuntimeLimits(),
		HandshakeTimeout:      5 * time.Second,
		HeartbeatInterval:     2 * time.Second,
		MaxHeartbeatStaleness: 5 * time.Second,
		RuntimePath:           os.Args[0],
		Args:                  []string{"-test.run=TestMain"},
		Env:                   append(os.Environ(), "REDEVPLUGIN_RUNTIMECLIENT_HELPER=1", "REDEVPLUGIN_RUNTIMECLIENT_REQUEST_ARTIFACT=1"),
		Artifacts:             provider,
		StreamSink:            &recordingRuntimeStreamSink{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := supervisor.Start(context.Background(), testRuntimeTarget); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	health, err := supervisor.Health(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	rawResult, err := supervisor.invokeWorkerForTest(context.Background(), Lease{LeaseID: "lease_1", RuntimeGenerationID: health.RuntimeGenerationID, PluginInstanceID: "plugini_1"}, "worker.echo", workerInvocationFixture())
	if err != nil {
		t.Fatalf("InvokeWorker() error = %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(rawResult, &decoded); err != nil {
		t.Fatalf("decode worker result: %v", err)
	}
	artifact, ok := decoded["artifact"].(map[string]any)
	if !ok {
		t.Fatalf("artifact result missing: %#v", decoded)
	}
	if artifact["ok"] != true || artifact["sha256"] != fixtureArtifactSHA || artifact["content_base64"] != base64.StdEncoding.EncodeToString([]byte("wasm bytes")) {
		t.Fatalf("artifact result mismatch: %#v", artifact)
	}
	if provider.calls != 1 || provider.last.PackageHash != fixturePackageHash || provider.last.Artifact != fixtureArtifact || provider.last.ArtifactSHA256 != fixtureArtifactSHA {
		t.Fatalf("artifact provider mismatch: calls=%d last=%#v", provider.calls, provider.last)
	}
	stopRuntimeSupervisor(t, supervisor)
}

func TestProcessSupervisorArtifactHostcallIsInvocationIndependentAndGenerationBound(t *testing.T) {
	provider := &cancelAwareArtifactProvider{
		started:  make(chan time.Time, 1),
		canceled: make(chan error, 1),
	}
	oldWriter := &lockedBuffer{}
	newWriter := &lockedBuffer{}
	generationCtx, cancelGeneration := context.WithCancel(context.Background())
	generation := &runtimeGeneration{id: "generation_old", ctx: generationCtx, stdin: oldWriter}
	_, cancelInvocation := context.WithCancel(context.Background())
	supervisor := &ProcessSupervisor{artifacts: provider, ipcIn: &serializedWriteCloser{WriteCloser: nopWriteCloser{Writer: newWriter}}}
	request := ArtifactRequest{PackageHash: fixturePackageHash, Artifact: fixtureArtifact, ArtifactSHA256: fixtureArtifactSHA}
	flight := &pendingCompileFlight{
		generation: generation, parentRequestID: "invoke_old", artifactRequestID: "invoke_old:artifact",
		artifact: request, registered: true,
	}
	supervisor.dispatchCompileFlightArtifact(generation, Health{RuntimeGenerationID: generation.id}, ipcFrame{
		FrameType: ipcFrameTypeOpenHandle,
		RequestID: flight.artifactRequestID, ParentRequestID: flight.parentRequestID, RuntimeGenerationID: generation.id,
		Payload: mustMarshalRaw(request),
	}, flight)

	calledAt := <-provider.started
	cancelInvocation()
	select {
	case err := <-provider.canceled:
		t.Fatalf("artifact read inherited invocation cancellation: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	cancelGeneration()
	select {
	case err := <-provider.canceled:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("artifact generation cancellation error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("artifact read did not stop with its runtime generation")
	}
	deadline := time.Now().Add(time.Second)
	for oldWriter.Len() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if oldWriter.Len() == 0 {
		t.Fatal("artifact response was not written to the owning generation")
	}
	if newWriter.Len() != 0 {
		t.Fatal("old generation artifact response was written to the current transport")
	}
	frame, err := readSemanticJSONTestFrame(bufio.NewReader(bytes.NewReader(oldWriter.Bytes())))
	if err != nil {
		t.Fatal(err)
	}
	var failure hostcallFailurePayload
	if err := decodeStrictJSON(frame.Payload, &failure); err != nil {
		t.Fatal(err)
	}
	if failure.OK || failure.Code != "ARTIFACT_READ_FAILED" {
		t.Fatalf("artifact cancellation response = %#v", failure)
	}
	if elapsed := time.Since(calledAt); elapsed > time.Second {
		t.Fatalf("artifact generation cancellation took %s", elapsed)
	}
}

func TestProcessSupervisorRoutesLateCompileFlightArtifactAfterInvocationCancellation(t *testing.T) {
	provider := &notifyingArtifactProvider{called: make(chan ArtifactRequest, 1)}
	diagnostics := &runtimeDiagnosticSink{}
	supervisor, err := newTestProcessSupervisor(t, ProcessSupervisorOptions{
		Limits:                DefaultRuntimeLimits(),
		HandshakeTimeout:      5 * time.Second,
		HeartbeatInterval:     2 * time.Second,
		MaxHeartbeatStaleness: 5 * time.Second,
		RuntimePath:           os.Args[0],
		Args:                  []string{"-test.run=TestMain"},
		Env: append(os.Environ(),
			"REDEVPLUGIN_RUNTIMECLIENT_HELPER=1",
			"REDEVPLUGIN_RUNTIMECLIENT_LATE_ARTIFACT_AFTER_CANCEL=1",
		),
		Artifacts:   provider,
		Diagnostics: diagnostics,
		StreamSink:  &recordingRuntimeStreamSink{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := supervisor.Start(context.Background(), testRuntimeTarget); err != nil {
		t.Fatal(err)
	}
	health, err := supervisor.Health(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if _, err := supervisor.invokeWorkerForTest(ctx, Lease{
		LeaseID: "lease_late_artifact", RuntimeGenerationID: health.RuntimeGenerationID, PluginInstanceID: "plugini_1",
	}, "worker.echo", workerInvocationFixture()); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("canceled InvokeWorker() error = %v, want context deadline", err)
	}
	select {
	case request := <-provider.called:
		if request != (ArtifactRequest{PackageHash: fixturePackageHash, Artifact: fixtureArtifact, ArtifactSHA256: fixtureArtifactSHA}) {
			t.Fatalf("late compile flight artifact request = %#v", request)
		}
	case <-time.After(time.Second):
		t.Fatal("late compile flight artifact request was not routed")
	}

	deadline := time.Now().Add(time.Second)
	for {
		supervisor.pendingMu.Lock()
		compileFlights := len(supervisor.compileFlights)
		supervisor.pendingMu.Unlock()
		if compileFlights == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("completed compile flight route was retained: %d", compileFlights)
		}
		time.Sleep(time.Millisecond)
	}
	for {
		health, err = supervisor.Health(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if !health.Ready {
			t.Fatalf("late compile flight invalidated the owning generation: %#v diagnostics=%#v", health, diagnostics.list("plugin.runtime.ipc.invalidated"))
		}
		if _, err := supervisor.invokeWorkerForTest(context.Background(), Lease{
			LeaseID: "lease_after_late_artifact", RuntimeGenerationID: health.RuntimeGenerationID, PluginInstanceID: "plugini_2",
		}, "worker.echo", workerInvocationFixtureForPlugin("plugini_2")); err == nil {
			break
		} else if time.Now().After(deadline) {
			t.Fatalf("independent invocation after late compile flight failed: %v", err)
		}
		time.Sleep(time.Millisecond)
	}
	stopRuntimeSupervisor(t, supervisor)
}

func TestCancelAcknowledgementRemovesOnlyNeverStartedCompileFlightIntent(t *testing.T) {
	generation := &runtimeGeneration{id: "generation_cancel_cleanup", ctx: context.Background()}
	unregistered := &pendingCompileFlight{generation: generation, parentRequestID: "invoke_queued", artifactRequestID: "invoke_queued:artifact"}
	registered := &pendingCompileFlight{generation: generation, parentRequestID: "invoke_running", artifactRequestID: "invoke_running:artifact", registered: true}
	supervisor := &ProcessSupervisor{compileFlights: map[string]*pendingCompileFlight{
		unregistered.artifactRequestID: unregistered,
		registered.artifactRequestID:   registered,
	}}

	supervisor.reconcileCompileFlightAfterCancelAck(generation, "invoke_queued", "queued")
	supervisor.reconcileCompileFlightAfterCancelAck(generation, "invoke_running", "running")

	supervisor.pendingMu.Lock()
	defer supervisor.pendingMu.Unlock()
	if _, exists := supervisor.compileFlights[unregistered.artifactRequestID]; exists {
		t.Fatal("queued invocation retained an unregistered compile flight intent")
	}
	if supervisor.compileFlights[registered.artifactRequestID] != registered {
		t.Fatal("running registered compile flight was removed by cancellation acknowledgement")
	}
}

func TestProcessSupervisorInvalidatesRuntimeForUnknownCompileFlightLifecycle(t *testing.T) {
	for _, frameType := range []string{ipcFrameTypeCompileFlightRegister, ipcFrameTypeCompileFlightComplete} {
		t.Run(frameType, func(t *testing.T) {
			provider := &recordingArtifactProvider{content: []byte("wasm bytes"), sha256: fixtureArtifactSHA}
			supervisor, err := newTestProcessSupervisor(t, ProcessSupervisorOptions{
				Limits:                DefaultRuntimeLimits(),
				HandshakeTimeout:      5 * time.Second,
				HeartbeatInterval:     2 * time.Second,
				MaxHeartbeatStaleness: 5 * time.Second,
				RuntimePath:           os.Args[0],
				Args:                  []string{"-test.run=TestMain"},
				Env: append(os.Environ(),
					"REDEVPLUGIN_RUNTIMECLIENT_HELPER=1",
					"REDEVPLUGIN_RUNTIMECLIENT_REQUEST_ARTIFACT=1",
					"REDEVPLUGIN_RUNTIMECLIENT_UNKNOWN_COMPILE_FLIGHT="+frameType,
				),
				Artifacts:  provider,
				StreamSink: &recordingRuntimeStreamSink{},
			})
			if err != nil {
				t.Fatal(err)
			}
			if err := supervisor.Start(context.Background(), testRuntimeTarget); err != nil {
				t.Fatal(err)
			}
			health, err := supervisor.Health(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := supervisor.invokeWorkerForTest(context.Background(), Lease{
				LeaseID: "lease_unknown_flight", RuntimeGenerationID: health.RuntimeGenerationID, PluginInstanceID: "plugini_1",
			}, "worker.echo", workerInvocationFixture()); !errors.Is(err, ErrRuntimeIPCUnavailable) {
				t.Fatalf("InvokeWorker() error = %v, want %v", err, ErrRuntimeIPCUnavailable)
			}
			wantProviderCalls := 0
			if frameType == ipcFrameTypeCompileFlightComplete {
				wantProviderCalls = 1
			}
			if provider.calls != wantProviderCalls {
				t.Fatalf("artifact provider calls = %d, want %d", provider.calls, wantProviderCalls)
			}
			health, err = supervisor.Health(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if health.Ready {
				t.Fatalf("runtime remained ready after unknown %s: %#v", frameType, health)
			}
			stopRuntimeSupervisor(t, supervisor)
		})
	}
}

func TestProcessSupervisorFailsOnlyPendingRequestsFromOwningGeneration(t *testing.T) {
	oldGeneration := &runtimeGeneration{id: "generation_old", ctx: context.Background()}
	newGeneration := &runtimeGeneration{id: "generation_new", ctx: context.Background()}
	oldPending := &pendingIPCRequest{generation: oldGeneration, result: make(chan ipcCallResult, 1)}
	newPending := &pendingIPCRequest{generation: newGeneration, result: make(chan ipcCallResult, 1)}
	supervisor := &ProcessSupervisor{pending: map[string]*pendingIPCRequest{
		"old": oldPending,
		"new": newPending,
	}}
	want := errors.New("old generation failed")
	supervisor.failPendingGeneration(oldGeneration, want)
	select {
	case result := <-oldPending.result:
		if !errors.Is(result.err, want) {
			t.Fatalf("old generation pending error = %v", result.err)
		}
	default:
		t.Fatal("old generation pending request was not failed")
	}
	select {
	case result := <-newPending.result:
		t.Fatalf("new generation pending request was failed: %v", result.err)
	default:
	}
	supervisor.pendingMu.Lock()
	defer supervisor.pendingMu.Unlock()
	if len(supervisor.pending) != 1 || supervisor.pending["new"] != newPending {
		t.Fatalf("remaining pending requests = %#v", supervisor.pending)
	}
}

func TestProcessSupervisorInvalidatesRuntimeForUnknownHostcallParent(t *testing.T) {
	provider := &recordingArtifactProvider{content: []byte("wasm bytes"), sha256: fixtureArtifactSHA}
	supervisor, err := newTestProcessSupervisor(t, ProcessSupervisorOptions{
		Limits:                DefaultRuntimeLimits(),
		HandshakeTimeout:      5 * time.Second,
		HeartbeatInterval:     2 * time.Second,
		MaxHeartbeatStaleness: 5 * time.Second,
		RuntimePath:           os.Args[0],
		Args:                  []string{"-test.run=TestMain"},
		Env: append(os.Environ(),
			"REDEVPLUGIN_RUNTIMECLIENT_HELPER=1",
			"REDEVPLUGIN_RUNTIMECLIENT_REQUEST_ARTIFACT=1",
			"REDEVPLUGIN_RUNTIMECLIENT_UNKNOWN_HOSTCALL_PARENT=1",
		),
		Artifacts:  provider,
		StreamSink: &recordingRuntimeStreamSink{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := supervisor.Start(context.Background(), testRuntimeTarget); err != nil {
		t.Fatal(err)
	}
	health, err := supervisor.Health(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := supervisor.invokeWorkerForTest(context.Background(), Lease{
		LeaseID: "lease_unknown_parent", RuntimeGenerationID: health.RuntimeGenerationID, PluginInstanceID: "plugini_1",
	}, "worker.echo", workerInvocationFixture()); !errors.Is(err, ErrRuntimeIPCUnavailable) {
		t.Fatalf("InvokeWorker() error = %v, want %v", err, ErrRuntimeIPCUnavailable)
	}
	if provider.calls != 0 {
		t.Fatalf("unknown parent reached artifact provider: %d", provider.calls)
	}
	health, err = supervisor.Health(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if health.Ready {
		t.Fatalf("runtime remained ready after unknown hostcall parent: %#v", health)
	}
	stopRuntimeSupervisor(t, supervisor)
}

func assertRedactedRuntimeError(t *testing.T, err error, code, publicMessage, sensitive string) {
	t.Helper()
	if !errors.Is(err, ErrRuntimeRequestFailed) || !strings.Contains(err.Error(), code) || !strings.Contains(err.Error(), publicMessage) {
		t.Fatalf("runtime error = %v, want %s with fixed public message", err, code)
	}
	for _, secret := range []string{sensitive, "/Users/secret/path", "vault-token-super-secret", "resolver internal", "private-dns"} {
		if secret != "" && strings.Contains(err.Error(), secret) {
			t.Fatalf("runtime error leaked %q: %v", secret, err)
		}
	}
}

func assertHostcallFailureDiagnostic(t *testing.T, store *runtimeDiagnosticSink, hostcall, code, rawError string) {
	t.Helper()
	events := store.list("plugin.runtime.hostcall.failed")
	if len(events) != 1 {
		t.Fatalf("hostcall failure diagnostics = %#v, want exactly one event", events)
	}
	event := events[0]
	if event.Message != "runtime hostcall failed" || event.Details.Hostcall != hostcall || event.Details.Code != code {
		t.Fatalf("hostcall failure diagnostic mismatch: %#v", event)
	}
	failure := event.Failure
	if failure.Code != observability.FailureAction || failure.Component != observability.FailureComponentRuntime || failure.Operation != "runtime.hostcall" || strings.Contains(fmt.Sprint(event), rawError) {
		t.Fatalf("hostcall failure diagnostic retained raw cause: %#v", event)
	}
}

func TestProcessSupervisorRedactsRuntimeProcessOutput(t *testing.T) {
	const sensitive = "vault token sk-live-secret at /Users/secret/path"
	diagnostics := &runtimeDiagnosticSink{}
	supervisor := &ProcessSupervisor{diagnostics: diagnostics, now: func() time.Time {
		return time.Date(2026, 7, 18, 12, 0, 0, 0, time.UTC)
	}}

	exit := &processExit{}
	exit.diagnosticReaders.Add(1)
	supervisor.scanPipe(io.NopCloser(strings.NewReader(sensitive+"\n")), "stderr", &runtimeProcess{}, exit, Health{})
	if events := diagnostics.list("plugin.runtime.process.stderr"); len(events) != 0 {
		t.Fatalf("runtime process output produced per-content diagnostics: %#v", events)
	}
	if strings.Contains(fmt.Sprint(diagnostics.events), sensitive) || strings.Contains(fmt.Sprint(diagnostics.events), "sk-live-secret") || strings.Contains(fmt.Sprint(diagnostics.events), "/Users/secret/path") {
		t.Fatalf("runtime process diagnostics retained output: %#v", diagnostics.events)
	}
}

func TestProcessSupervisorDiagnosticOutputLimitsAndFailureModes(t *testing.T) {
	t.Run("bounded output", func(t *testing.T) {
		diagnostics := &runtimeDiagnosticSink{}
		supervisor := &ProcessSupervisor{diagnostics: diagnostics, now: func() time.Time { return time.Now().UTC() }}
		exit := &processExit{}
		exit.diagnosticReaders.Add(1)
		supervisor.scanPipe(io.NopCloser(strings.NewReader(strings.Repeat("x", 64<<10))), "stdout", &runtimeProcess{}, exit, Health{})
		if exit.diagnosticBytes != 64<<10 || len(diagnostics.list("")) != 0 {
			t.Fatalf("bounded diagnostic state = bytes %d events %#v", exit.diagnosticBytes, diagnostics.list(""))
		}
	})

	t.Run("flood", func(t *testing.T) {
		diagnostics := &runtimeDiagnosticSink{}
		supervisor := &ProcessSupervisor{diagnostics: diagnostics, now: func() time.Time { return time.Now().UTC() }}
		kills := 0
		process := &runtimeProcess{kill: func() error { kills++; return nil }}
		exit := &processExit{}
		exit.diagnosticReaders.Add(1)
		supervisor.scanPipe(io.NopCloser(strings.NewReader(strings.Repeat("x", 6<<20))), "stderr", process, exit, Health{})
		if kills != 1 || len(diagnostics.list("plugin.runtime.process.stderr.limit")) != 1 {
			t.Fatalf("flood teardown = kills %d events %#v", kills, diagnostics.list(""))
		}
	})

	t.Run("premature eof", func(t *testing.T) {
		diagnostics := &runtimeDiagnosticSink{}
		supervisor := &ProcessSupervisor{diagnostics: diagnostics, now: func() time.Time { return time.Now().UTC() }}
		kills := 0
		process := &runtimeProcess{kill: func() error { kills++; return nil }, alive: func() bool { return true }}
		exit := &processExit{}
		exit.diagnosticReaders.Add(1)
		supervisor.scanPipe(io.NopCloser(strings.NewReader("")), "stdout", process, exit, Health{})
		if kills != 1 || len(diagnostics.list("plugin.runtime.process.stdout.premature_eof")) != 1 {
			t.Fatalf("premature EOF teardown = kills %d events %#v", kills, diagnostics.list(""))
		}
	})

	t.Run("read failure", func(t *testing.T) {
		diagnostics := &runtimeDiagnosticSink{}
		supervisor := &ProcessSupervisor{diagnostics: diagnostics, now: func() time.Time { return time.Now().UTC() }}
		kills := 0
		process := &runtimeProcess{kill: func() error { kills++; return nil }}
		exit := &processExit{}
		exit.diagnosticReaders.Add(1)
		supervisor.scanPipe(failingRuntimeDiagnosticReader{}, "stderr", process, exit, Health{})
		if kills != 1 || len(diagnostics.list("plugin.runtime.process.stderr.error")) != 1 {
			t.Fatalf("read failure teardown = kills %d events %#v", kills, diagnostics.list(""))
		}
	})
}

func TestProcessSupervisorDiagnosticEOFTeardownIsRaceSafe(t *testing.T) {
	diagnostics := &runtimeDiagnosticSink{}
	supervisor := &ProcessSupervisor{diagnostics: diagnostics, now: func() time.Time { return time.Now().UTC() }}
	var killMu sync.Mutex
	kills := 0
	process := &runtimeProcess{
		kill: func() error {
			killMu.Lock()
			kills++
			killMu.Unlock()
			return nil
		},
		alive: func() bool { return true },
	}
	exit := &processExit{}
	exit.diagnosticReaders.Add(2)
	go supervisor.scanPipe(io.NopCloser(strings.NewReader("")), "stdout", process, exit, Health{})
	go supervisor.scanPipe(io.NopCloser(strings.NewReader("")), "stderr", process, exit, Health{})
	exit.diagnosticReaders.Wait()
	killMu.Lock()
	defer killMu.Unlock()
	if kills < 1 || kills > 2 {
		t.Fatalf("concurrent EOF teardown kills = %d", kills)
	}
}

type failingRuntimeDiagnosticReader struct{}

func (failingRuntimeDiagnosticReader) Read([]byte) (int, error) {
	return 0, errors.New("sensitive runtime diagnostic read failure")
}

func (failingRuntimeDiagnosticReader) Close() error { return nil }

func TestProcessSupervisorDeniesUnboundArtifactHandle(t *testing.T) {
	provider := &recordingArtifactProvider{
		content: []byte("wasm bytes"),
		sha256:  fixtureArtifactSHA,
	}
	supervisor, err := newTestProcessSupervisor(t, ProcessSupervisorOptions{
		Limits:                DefaultRuntimeLimits(),
		HandshakeTimeout:      5 * time.Second,
		HeartbeatInterval:     2 * time.Second,
		MaxHeartbeatStaleness: 5 * time.Second,
		RuntimePath:           os.Args[0],
		Args:                  []string{"-test.run=TestMain"},
		Env:                   append(os.Environ(), "REDEVPLUGIN_RUNTIMECLIENT_HELPER=1", "REDEVPLUGIN_RUNTIMECLIENT_REQUEST_ARTIFACT=1", "REDEVPLUGIN_RUNTIMECLIENT_REQUEST_WRONG_ARTIFACT=1"),
		Artifacts:             provider,
		StreamSink:            &recordingRuntimeStreamSink{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := supervisor.Start(context.Background(), testRuntimeTarget); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	health, err := supervisor.Health(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := supervisor.invokeWorkerForTest(context.Background(), Lease{LeaseID: "lease_1", RuntimeGenerationID: health.RuntimeGenerationID, PluginInstanceID: "plugini_1"}, "worker.echo", workerInvocationFixture()); !errors.Is(err, ErrRuntimeRequestFailed) {
		t.Fatalf("InvokeWorker() error = %v, want ErrRuntimeRequestFailed", err)
	}
	if provider.calls != 0 {
		t.Fatalf("artifact provider was called for denied request: %d", provider.calls)
	}
	stopRuntimeSupervisor(t, supervisor)
}

func TestProcessSupervisorRequiresWorkerInvocationArtifactIdentity(t *testing.T) {
	supervisor, err := newTestProcessSupervisor(t, ProcessSupervisorOptions{
		Limits:                DefaultRuntimeLimits(),
		HandshakeTimeout:      5 * time.Second,
		HeartbeatInterval:     2 * time.Second,
		MaxHeartbeatStaleness: 5 * time.Second,
		RuntimePath:           os.Args[0],
		Args:                  []string{"-test.run=TestMain"},
		Env:                   append(os.Environ(), "REDEVPLUGIN_RUNTIMECLIENT_HELPER=1"),
		StreamSink:            &recordingRuntimeStreamSink{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := supervisor.Start(context.Background(), testRuntimeTarget); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	if _, err := supervisor.invokeWorkerForTest(context.Background(), Lease{LeaseID: "lease_1"}, "worker.echo", []byte(`{"message":"hello"}`)); !errors.Is(err, ErrRuntimeRequestFailed) {
		t.Fatalf("InvokeWorker() error = %v, want ErrRuntimeRequestFailed", err)
	}
	stopRuntimeSupervisor(t, supervisor)
}

func TestProcessSupervisorRejectsNonWorkerArtifactPath(t *testing.T) {
	supervisor, err := newTestProcessSupervisor(t, ProcessSupervisorOptions{
		Limits:                DefaultRuntimeLimits(),
		HandshakeTimeout:      5 * time.Second,
		HeartbeatInterval:     2 * time.Second,
		MaxHeartbeatStaleness: 5 * time.Second,
		RuntimePath:           os.Args[0],
		Args:                  []string{"-test.run=TestMain"},
		Env:                   append(os.Environ(), "REDEVPLUGIN_RUNTIMECLIENT_HELPER=1"),
		StreamSink:            &recordingRuntimeStreamSink{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := supervisor.Start(context.Background(), testRuntimeTarget); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	payload := []byte(fmt.Sprintf(`{"package_hash":%q,"artifact":"ui/index.html","artifact_sha256":%q,"worker_id":"echo_worker","method":"worker.echo"}`, fixturePackageHash, fixtureArtifactSHA))
	if _, err := supervisor.invokeWorkerForTest(context.Background(), Lease{LeaseID: "lease_1"}, "worker.echo", payload); !errors.Is(err, ErrRuntimeRequestFailed) {
		t.Fatalf("InvokeWorker() error = %v, want ErrRuntimeRequestFailed", err)
	}
	stopRuntimeSupervisor(t, supervisor)
}

func TestProcessSupervisorRejectsMissingPath(t *testing.T) {
	if _, err := NewProcessSupervisor(ProcessSupervisorOptions{StreamSink: &recordingRuntimeStreamSink{}}); !errors.Is(err, ErrRuntimePathRequired) {
		t.Fatalf("NewProcessSupervisor() error = %v, want ErrRuntimePathRequired", err)
	}
}

func TestProcessSupervisorFailsClosedOnBadHandshake(t *testing.T) {
	supervisor, err := newTestProcessSupervisor(t, ProcessSupervisorOptions{
		Limits:                DefaultRuntimeLimits(),
		HeartbeatInterval:     2 * time.Second,
		MaxHeartbeatStaleness: 5 * time.Second,
		RuntimePath:           os.Args[0],
		Args:                  []string{"-test.run=TestMain"},
		Env:                   append(os.Environ(), "REDEVPLUGIN_RUNTIMECLIENT_BAD_HELPER=1"),
		HandshakeTimeout:      200 * time.Millisecond,
		StreamSink:            &recordingRuntimeStreamSink{},
	})
	if err != nil {
		t.Fatal(err)
	}
	err = supervisor.Start(context.Background(), testRuntimeTarget)
	if !errors.Is(err, ErrRuntimeHandshake) {
		t.Fatalf("Start() error = %v, want ErrRuntimeHandshake", err)
	}
	health, err := supervisor.Health(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if health.Ready {
		t.Fatalf("bad handshake left runtime ready: %#v", health)
	}
}

func TestProcessSupervisorFailsClosedOnHandshakeNonceMismatch(t *testing.T) {
	supervisor, err := newTestProcessSupervisor(t, ProcessSupervisorOptions{
		Limits:                DefaultRuntimeLimits(),
		HeartbeatInterval:     2 * time.Second,
		MaxHeartbeatStaleness: 5 * time.Second,
		RuntimePath:           os.Args[0],
		Args:                  []string{"-test.run=TestMain"},
		Env:                   append(os.Environ(), "REDEVPLUGIN_RUNTIMECLIENT_HELPER=1", "REDEVPLUGIN_RUNTIMECLIENT_BAD_NONCE=1"),
		HandshakeTimeout:      200 * time.Millisecond,
		StreamSink:            &recordingRuntimeStreamSink{},
	})
	if err != nil {
		t.Fatal(err)
	}
	err = supervisor.Start(context.Background(), testRuntimeTarget)
	if !errors.Is(err, ErrRuntimeHandshake) {
		t.Fatalf("Start() error = %v, want ErrRuntimeHandshake", err)
	}
	health, err := supervisor.Health(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if health.Ready {
		t.Fatalf("nonce mismatch left runtime ready: %#v", health)
	}
}

func TestRuntimeHostcallContextCapsRequestedTimeout(t *testing.T) {
	start := time.Now()
	ctx, cancel := runtimeHostcallContext(context.Background(), 5*time.Minute)
	defer cancel()
	deadline, ok := ctx.Deadline()
	if !ok {
		t.Fatal("runtimeHostcallContext() missing deadline")
	}
	if remaining := deadline.Sub(start); remaining <= 0 || remaining > maxRuntimeHostcallTimeout+250*time.Millisecond {
		t.Fatalf("runtimeHostcallContext() remaining deadline = %v, want capped by %v", remaining, maxRuntimeHostcallTimeout)
	}
}

func runRuntimeClientHelper() {
	ipcReadFile := os.NewFile(runtimeIPCReadFD, "redevplugin-ipc-read")
	ipcWriteFile := os.NewFile(runtimeIPCWriteFD, "redevplugin-ipc-write")
	controlReadFile := os.NewFile(runtimeControlReadFD, "redevplugin-control-read")
	controlWriteFile := os.NewFile(runtimeControlWriteFD, "redevplugin-control-write")
	if ipcReadFile == nil || ipcWriteFile == nil || controlReadFile == nil || controlWriteFile == nil {
		os.Exit(64)
	}
	reader := bufio.NewReader(&testHostSemanticIPCReader{reader: ipcReadFile})
	runtimeOutput := newRuntimeSemanticIPCWriteCloser(ipcWriteFile)
	encoder := json.NewEncoder(runtimeOutput)
	line, err := reader.ReadBytes('\n')
	if err != nil {
		os.Exit(2)
	}
	var frame ipcFrame
	if err := json.Unmarshal(line, &frame); err != nil {
		os.Exit(3)
	}
	if frame.FrameType != ipcFrameTypeHello || strings.TrimSpace(frame.RequestID) == "" {
		os.Exit(4)
	}
	var hello helloRequestPayload
	if err := json.Unmarshal(frame.Payload, &hello); err != nil {
		os.Exit(5)
	}
	channelNonce := hello.ConnectionNonce
	if strings.TrimSpace(channelNonce) == "" {
		os.Exit(6)
	}
	if os.Getenv("REDEVPLUGIN_RUNTIMECLIENT_REQUIRE_LEASE_PUBLIC_KEY") == "1" {
		if len(hello.RuntimeLeasePublicKeys) != 1 ||
			hello.RuntimeLeasePublicKeys[0].Algorithm != RuntimeLeaseSignatureAlgorithm ||
			!strings.HasPrefix(hello.RuntimeLeasePublicKeys[0].KeyID, "host_ephemeral_") {
			os.Exit(60)
		}
		rawKey, err := base64.StdEncoding.DecodeString(hello.RuntimeLeasePublicKeys[0].PublicKeyBase64)
		if err != nil || len(rawKey) != ed25519.PublicKeySize {
			os.Exit(61)
		}
	}
	if os.Getenv("REDEVPLUGIN_RUNTIMECLIENT_BAD_NONCE") == "1" {
		channelNonce = "wrong_channel_nonce"
	}
	platformVersion := envOrDefault("REDEVPLUGIN_RUNTIMECLIENT_ACK_PLATFORM_VERSION", version.CurrentPlatformVersion())
	actualTarget := envOrDefault("REDEVPLUGIN_RUNTIMECLIENT_ACK_TARGET", hello.Target)
	internalWire := InternalWire
	if os.Getenv("REDEVPLUGIN_RUNTIMECLIENT_ACK_INTERNAL_WIRE") == "2" {
		internalWire = 2
	}
	payload, _ := json.Marshal(helloAckPayload{
		InternalWire:          internalWire,
		PlatformVersion:       platformVersion,
		RuntimeArtifactSHA256: envOrDefault("REDEVPLUGIN_RUNTIMECLIENT_ACK_ARTIFACT_SHA256", hello.RuntimeArtifactSHA256),
		ConnectionNonce:       channelNonce,
		ActualTarget:          actualTarget,
		Limits:                hello.Limits,
	})
	_ = encoder.Encode(ipcFrame{
		FrameType:           ipcFrameTypeHelloAck,
		RequestID:           frame.RequestID,
		RuntimeGenerationID: frame.RuntimeGenerationID,
		Payload:             payload,
	})
	if rawExitCode := os.Getenv("REDEVPLUGIN_RUNTIMECLIENT_EXIT_AFTER_ACK"); rawExitCode != "" {
		exitCode, err := strconv.Atoi(rawExitCode)
		if err != nil {
			os.Exit(67)
		}
		time.Sleep(100 * time.Millisecond)
		os.Exit(exitCode)
	}
	revoked := make(chan struct{})
	var revokeOnce sync.Once
	var heartbeatCount atomic.Int64
	go runRuntimeClientControlHelper(
		bufio.NewReader(&testHostSemanticIPCReader{reader: controlReadFile}),
		json.NewEncoder(newRuntimeSemanticIPCWriteCloser(controlWriteFile)),
		revoked,
		&revokeOnce,
		&heartbeatCount,
		hello.Limits,
	)
	var multiplexInvocations atomic.Int64
	var lateArtifactInvocation *ipcFrame
	var lateArtifactInvocationCount int
	for {
		line, err := reader.ReadBytes('\n')
		if err != nil {
			return
		}
		var request ipcFrame
		if err := json.Unmarshal(line, &request); err != nil {
			os.Exit(5)
		}
		switch request.FrameType {
		case ipcFrameTypeInvokeWorker:
			if os.Getenv("REDEVPLUGIN_RUNTIMECLIENT_LATE_ARTIFACT_AFTER_CANCEL") == "1" {
				lateArtifactInvocationCount++
				if lateArtifactInvocationCount == 1 {
					requestCopy := request
					lateArtifactInvocation = &requestCopy
					writeCompileFlightLifecycleFromHelper(encoder, request, ipcFrameTypeCompileFlightRegister)
					continue
				}
			}
			if os.Getenv("REDEVPLUGIN_RUNTIMECLIENT_MULTIPLEX") == "1" {
				invocationNumber := multiplexInvocations.Add(1)
				go func(request ipcFrame, invocationNumber int64) {
					if invocationNumber == 1 {
						time.Sleep(150 * time.Millisecond)
					}
					raw, _ := json.Marshal(runtimeResponsePayload{OK: true, Result: json.RawMessage(`{"data":{"from_runtime":true}}`)})
					_ = encoder.Encode(ipcFrame{
						FrameType:           ipcFrameTypeInvokeWorkerResult,
						RequestID:           request.RequestID,
						RuntimeGenerationID: request.RuntimeGenerationID,
						Payload:             raw,
					})
				}(request, invocationNumber)
				continue
			}
			if os.Getenv("REDEVPLUGIN_RUNTIMECLIENT_REQUIRE_SIGNED_LEASE") == "1" && !verifySignedLeaseFromHelper(request, hello) {
				os.Exit(62)
			}
			if os.Getenv("REDEVPLUGIN_RUNTIMECLIENT_BLOCK_INVOKE") == "1" {
				time.Sleep(10 * time.Second)
				continue
			}
			if rawDelay := strings.TrimSpace(os.Getenv("REDEVPLUGIN_RUNTIMECLIENT_DELAY_INVOKE_MILLIS")); rawDelay != "" {
				delayMillis, parseErr := strconv.Atoi(rawDelay)
				if parseErr != nil || delayMillis <= 0 {
					os.Exit(63)
				}
				time.Sleep(time.Duration(delayMillis) * time.Millisecond)
			}
			if os.Getenv("REDEVPLUGIN_RUNTIMECLIENT_WAIT_FOR_REVOKE_DURING_INVOKE") == "1" {
				<-revoked
				resultPayload := runtimeResponsePayload{OK: false, Code: "RUNTIME_CAPABILITY_REVOKED", Message: "runtime capability was revoked", ErrorOrigin: WorkerErrorOriginRuntime}
				raw, _ := json.Marshal(resultPayload)
				_ = encoder.Encode(ipcFrame{
					FrameType:           ipcFrameTypeInvokeWorkerResult,
					RequestID:           request.RequestID,
					RuntimeGenerationID: request.RuntimeGenerationID,
					Payload:             raw,
				})
				continue
			}
			if os.Getenv("REDEVPLUGIN_RUNTIMECLIENT_REQUIRE_HEARTBEAT_DURING_INVOKE") == "1" && heartbeatCount.Load() == 0 {
				resultPayload := runtimeResponsePayload{OK: false, Code: "RUNTIME_CONTROL_CHANNEL_STALE", Message: "heartbeat did not run during invocation", ErrorOrigin: WorkerErrorOriginRuntime}
				raw, _ := json.Marshal(resultPayload)
				_ = encoder.Encode(ipcFrame{
					FrameType:           ipcFrameTypeInvokeWorkerResult,
					RequestID:           request.RequestID,
					RuntimeGenerationID: request.RuntimeGenerationID,
					Payload:             raw,
				})
				continue
			}
			if os.Getenv("REDEVPLUGIN_RUNTIMECLIENT_REQUEST_ARTIFACT") == "1" {
				if !requestArtifactFromHelper(reader, encoder, request) {
					continue
				}
			}
			resultPayload := runtimeResponsePayload{OK: true, Result: json.RawMessage(`{"data":{"from_runtime":true}}`)}
			if os.Getenv("REDEVPLUGIN_RUNTIMECLIENT_FAIL_INVOKE") == "1" {
				resultPayload = runtimeResponsePayload{OK: false, Code: "WASM_WORKER_FAILED", Message: "runtime worker execution failed", ErrorOrigin: WorkerErrorOriginRuntime}
			}
			raw, _ := json.Marshal(resultPayload)
			_ = encoder.Encode(ipcFrame{
				FrameType:           ipcFrameTypeInvokeWorkerResult,
				RequestID:           request.RequestID,
				RuntimeGenerationID: request.RuntimeGenerationID,
				Payload:             raw,
			})
		case ipcFrameTypeCancelInvoke:
			var cancelRequest cancelInvokeRequestPayload
			_ = json.Unmarshal(request.Payload, &cancelRequest)
			raw, _ := json.Marshal(runtimeResponsePayload{OK: true, Result: mustMarshalRaw(cancelInvokeAckResultPayload{
				InvocationRequestID: cancelRequest.InvocationRequestID,
				Disposition:         "running",
			})})
			_ = encoder.Encode(ipcFrame{
				FrameType:           ipcFrameTypeCancelInvokeAck,
				RequestID:           request.RequestID,
				RuntimeGenerationID: request.RuntimeGenerationID,
				Payload:             raw,
			})
			if lateArtifactInvocation != nil {
				time.Sleep(25 * time.Millisecond)
				invocation := *lateArtifactInvocation
				artifact := artifactRequestPayloadFromInvoke(invocation)
				_ = encoder.Encode(ipcFrame{
					FrameType:           ipcFrameTypeOpenHandle,
					RequestID:           invocation.RequestID + ":artifact",
					ParentRequestID:     invocation.RequestID,
					RuntimeGenerationID: invocation.RuntimeGenerationID,
					Payload:             mustMarshalRaw(artifact),
				})
			}
		case ipcFrameTypeOpenHandle:
			if lateArtifactInvocation == nil || request.RequestID != lateArtifactInvocation.RequestID+":artifact" {
				os.Exit(69)
			}
			invocation := *lateArtifactInvocation
			artifact := artifactRequestPayloadFromInvoke(invocation)
			_ = encoder.Encode(ipcFrame{
				FrameType:           "compile_flight_complete",
				RequestID:           invocation.RequestID + ":artifact:complete",
				ParentRequestID:     invocation.RequestID,
				RuntimeGenerationID: invocation.RuntimeGenerationID,
				Payload: mustMarshalRaw(map[string]any{
					"artifact_request_id": invocation.RequestID + ":artifact",
					"package_hash":        artifact.PackageHash,
					"artifact":            artifact.Artifact,
					"artifact_sha256":     artifact.ArtifactSHA256,
				}),
			})
			canceledPayload, _ := json.Marshal(runtimeResponsePayload{
				OK: false, Code: "RUNTIME_INVOCATION_CANCELED", Message: "runtime invocation was canceled", ErrorOrigin: WorkerErrorOriginRuntime,
			})
			_ = encoder.Encode(ipcFrame{
				FrameType:           ipcFrameTypeInvokeWorkerResult,
				RequestID:           invocation.RequestID,
				RuntimeGenerationID: invocation.RuntimeGenerationID,
				Payload:             canceledPayload,
			})
			lateArtifactInvocation = nil
		default:
			os.Exit(6)
		}
	}
}

func envOrDefault(key string, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

type notifyingArtifactProvider struct {
	called chan ArtifactRequest
}

func (p *notifyingArtifactProvider) ReadArtifact(_ context.Context, req ArtifactRequest) (ArtifactResult, error) {
	p.called <- req
	return ArtifactResult{Content: []byte("wasm bytes"), SHA256: req.ArtifactSHA256}, nil
}

func runRuntimeClientControlHelper(
	reader *bufio.Reader,
	encoder *json.Encoder,
	revoked chan struct{},
	revokeOnce *sync.Once,
	heartbeatCount *atomic.Int64,
	limits RuntimeLimits,
) {
	for {
		line, err := reader.ReadBytes('\n')
		if err != nil {
			return
		}
		var request ipcFrame
		if err := json.Unmarshal(line, &request); err != nil {
			os.Exit(67)
		}
		switch request.FrameType {
		case ipcFrameTypeHeartbeat:
			if os.Getenv("REDEVPLUGIN_RUNTIMECLIENT_BLOCK_HEARTBEAT") == "1" {
				time.Sleep(10 * time.Second)
				continue
			}
			heartbeatCount.Add(1)
			var heartbeatReq heartbeatRequestPayload
			_ = json.Unmarshal(request.Payload, &heartbeatReq)
			raw, _ := json.Marshal(runtimeResponsePayload{OK: true, Result: mustMarshalRaw(map[string]any{
				"runtime_generation_id": request.RuntimeGenerationID,
				"runtime_unix_nano":     time.Now().UnixNano(),
				"max_staleness_ms":      heartbeatReq.MaxStalenessMillis,
				"host_sent_unix_nano":   heartbeatReq.SentUnixNano,
				"active_invocations":    0,
				"queued_invocations":    0,
				"limits":                limits,
				"module_cache":          ModuleCacheMetrics{},
			})})
			_ = encoder.Encode(ipcFrame{
				FrameType:           ipcFrameTypeHeartbeat,
				RequestID:           request.RequestID,
				RuntimeGenerationID: request.RuntimeGenerationID,
				Payload:             raw,
			})
		case ipcFrameTypeRevokeEpoch:
			var revokeReq revokeEpochRequestPayload
			_ = json.Unmarshal(request.Payload, &revokeReq)
			revokeOnce.Do(func() { close(revoked) })
			raw, _ := json.Marshal(runtimeResponsePayload{OK: true, Result: mustMarshalRaw(map[string]any{
				"resource_scope":              revokeReq.ResourceScope,
				"plugin_instance_id":          revokeReq.PluginInstanceID,
				"revoke_epoch":                revokeReq.RevokeEpoch,
				"closed_socket_count":         2,
				"closed_stream_count":         3,
				"closed_storage_handle_count": 4,
			})})
			_ = encoder.Encode(ipcFrame{
				FrameType:           ipcFrameTypeRevokeEpochAck,
				RequestID:           request.RequestID,
				RuntimeGenerationID: request.RuntimeGenerationID,
				Payload:             raw,
			})
		default:
			os.Exit(68)
		}
	}
}

func waitForSustainedIPCLock(t *testing.T, supervisor *ProcessSupervisor, duration time.Duration) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	var occupiedSince time.Time
	for time.Now().Before(deadline) {
		supervisor.pendingMu.Lock()
		pending := len(supervisor.pending)
		supervisor.pendingMu.Unlock()
		if pending == 0 {
			occupiedSince = time.Time{}
		} else {
			if occupiedSince.IsZero() {
				occupiedSince = time.Now()
			} else if time.Since(occupiedSince) >= duration {
				return
			}
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("IPC lock did not remain occupied by the invocation")
}

func waitForInvocationAdmissionCount(t *testing.T, supervisor *ProcessSupervisor, want int) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		supervisor.admission.mu.Lock()
		got := supervisor.admission.active
		supervisor.admission.mu.Unlock()
		if got == want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	supervisor.admission.mu.Lock()
	got := supervisor.admission.active
	supervisor.admission.mu.Unlock()
	t.Fatalf("invocation admission count = %d, want %d", got, want)
}

func verifySignedLeaseFromHelper(request ipcFrame, hello helloRequestPayload) bool {
	if len(hello.RuntimeLeasePublicKeys) != 1 {
		return false
	}
	var payload invokeWorkerRequestPayload
	if err := json.Unmarshal(request.Payload, &payload); err != nil {
		return false
	}
	publicKey := hello.RuntimeLeasePublicKeys[0]
	rawKey, err := base64.StdEncoding.DecodeString(publicKey.PublicKeyBase64)
	if err != nil || len(rawKey) != ed25519.PublicKeySize || payload.Lease.KeyID != publicKey.KeyID || payload.Lease.Signature == "" {
		return false
	}
	verifier := Ed25519RuntimeLeaseVerifier{
		Keyring: StaticRuntimeLeaseSigningKeyring{Keys: []RuntimeLeaseSigningKey{{
			KeyID: publicKey.KeyID, PublicKey: ed25519.PublicKey(rawKey),
		}}},
		Now: func() time.Time { return time.UnixMilli(payload.Lease.IssuedAtUnixMillis).Add(time.Second) },
	}
	return verifier.VerifyRuntimeLease(context.Background(), RuntimeLeaseVerificationRequest{
		Lease: payload.Lease, Method: payload.Method, Now: time.UnixMilli(payload.Lease.IssuedAtUnixMillis).Add(time.Second),
	}) == nil
}

func requestArtifactFromHelper(reader *bufio.Reader, encoder *json.Encoder, request ipcFrame) bool {
	artifactReq := artifactRequestPayloadFromInvoke(request)
	writeCompileFlightLifecycleFromHelper(encoder, request, ipcFrameTypeCompileFlightRegister)
	if os.Getenv("REDEVPLUGIN_RUNTIMECLIENT_REQUEST_WRONG_ARTIFACT") == "1" {
		artifactReq.Artifact = "workers/other.wasm"
	}
	rawArtifactReq, _ := json.Marshal(artifactReq)
	parentRequestID := request.RequestID
	if os.Getenv("REDEVPLUGIN_RUNTIMECLIENT_UNKNOWN_HOSTCALL_PARENT") == "1" {
		parentRequestID = request.RequestID + ":unknown"
	}
	_ = encoder.Encode(ipcFrame{
		FrameType:           ipcFrameTypeOpenHandle,
		RequestID:           request.RequestID + ":artifact",
		ParentRequestID:     parentRequestID,
		RuntimeGenerationID: request.RuntimeGenerationID,
		Payload:             rawArtifactReq,
	})
	line, err := reader.ReadBytes('\n')
	if err != nil {
		os.Exit(7)
	}
	var response ipcFrame
	if err := json.Unmarshal(line, &response); err != nil {
		os.Exit(8)
	}
	if response.FrameType != ipcFrameTypeOpenHandle || response.RequestID != request.RequestID+":artifact" || response.ParentRequestID != request.RequestID {
		os.Exit(9)
	}
	var artifact artifactHandleResultPayload
	if err := json.Unmarshal(response.Payload, &artifact); err != nil {
		os.Exit(10)
	}
	if !artifact.OK {
		writeCompileFlightLifecycleFromHelper(encoder, request, ipcFrameTypeCompileFlightComplete)
		raw, _ := json.Marshal(runtimeResponsePayload{OK: false, Code: artifact.Code, Message: artifact.Message, ErrorOrigin: artifact.ErrorOrigin})
		_ = encoder.Encode(ipcFrame{
			FrameType:           ipcFrameTypeInvokeWorkerResult,
			RequestID:           request.RequestID,
			RuntimeGenerationID: request.RuntimeGenerationID,
			Payload:             raw,
		})
		return false
	}
	writeCompileFlightLifecycleFromHelper(encoder, request, ipcFrameTypeCompileFlightComplete)
	raw, _ := json.Marshal(runtimeResponsePayload{OK: true, Result: mustMarshalRaw(map[string]any{
		"artifact": map[string]any{
			"ok":             artifact.OK,
			"sha256":         artifact.SHA256,
			"content_base64": artifact.ContentBase64,
		},
	})})
	_ = encoder.Encode(ipcFrame{
		FrameType:           ipcFrameTypeInvokeWorkerResult,
		RequestID:           request.RequestID,
		RuntimeGenerationID: request.RuntimeGenerationID,
		Payload:             raw,
	})
	return false
}

func writeCompileFlightLifecycleFromHelper(encoder *json.Encoder, request ipcFrame, frameType string) {
	artifact := artifactRequestPayloadFromInvoke(request)
	artifactRequestID := request.RequestID + ":artifact"
	if os.Getenv("REDEVPLUGIN_RUNTIMECLIENT_UNKNOWN_COMPILE_FLIGHT") == frameType {
		artifactRequestID += ":unknown"
	}
	suffix := ":register"
	if frameType == ipcFrameTypeCompileFlightComplete {
		suffix = ":complete"
	}
	_ = encoder.Encode(ipcFrame{
		FrameType:           frameType,
		RequestID:           artifactRequestID + suffix,
		ParentRequestID:     request.RequestID,
		RuntimeGenerationID: request.RuntimeGenerationID,
		Payload: mustMarshalRaw(compileFlightLifecyclePayload{
			ArtifactRequestID: artifactRequestID,
			PackageHash:       artifact.PackageHash,
			Artifact:          artifact.Artifact,
			ArtifactSHA256:    artifact.ArtifactSHA256,
		}),
	})
}

func artifactRequestPayloadFromInvoke(request ipcFrame) artifactHandleRequestPayload {
	var payload invokeWorkerRequestPayload
	if err := json.Unmarshal(request.Payload, &payload); err != nil {
		os.Exit(11)
	}
	var invocation ArtifactRequest
	if err := json.Unmarshal(payload.Invocation, &invocation); err != nil {
		os.Exit(12)
	}
	return artifactHandleRequestPayload(invocation)
}

func mustMarshalRaw(value any) json.RawMessage {
	raw, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return raw
}

func waitForDiagnostic(t *testing.T, store *runtimeDiagnosticSink, eventType string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		events := store.list(eventType)
		if len(events) > 0 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	events := store.list("")
	t.Fatalf("timed out waiting for diagnostic %q; events=%#v", eventType, events)
}

type runtimeDiagnosticSink struct {
	mu     sync.Mutex
	events []observability.DiagnosticEvent
}

func (s *runtimeDiagnosticSink) AppendPluginDiagnostic(_ context.Context, event observability.DiagnosticEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, event)
	return nil
}

func (s *runtimeDiagnosticSink) list(eventType string) []observability.DiagnosticEvent {
	s.mu.Lock()
	defer s.mu.Unlock()
	events := make([]observability.DiagnosticEvent, 0, len(s.events))
	for _, event := range s.events {
		if eventType == "" || event.Type == eventType {
			events = append(events, event)
		}
	}
	return events
}

const (
	fixturePackageHash = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	fixtureArtifact    = "workers/echo.wasm"
	fixtureArtifactSHA = "sha256:a81d16f296ff2ebdb2dfe2ee0fbb532ba602da1ef9f797f8b1edb3e987fcf5db"
)

type recordingArtifactProvider struct {
	calls   int
	last    ArtifactRequest
	content []byte
	sha256  string
	err     error
}

type cancelAwareArtifactProvider struct {
	started  chan time.Time
	canceled chan error
}

type lockedBuffer struct {
	mu     sync.Mutex
	buffer bytes.Buffer
}

func (b *lockedBuffer) Write(payload []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buffer.Write(payload)
}

func (b *lockedBuffer) Len() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buffer.Len()
}

func (b *lockedBuffer) Bytes() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]byte(nil), b.buffer.Bytes()...)
}

type nopWriteCloser struct {
	io.Writer
}

func (nopWriteCloser) Close() error { return nil }

func (p *recordingArtifactProvider) ReadArtifact(_ context.Context, req ArtifactRequest) (ArtifactResult, error) {
	p.calls++
	p.last = req
	if p.err != nil {
		return ArtifactResult{}, p.err
	}
	return ArtifactResult{Content: append([]byte(nil), p.content...), SHA256: p.sha256}, nil
}

func (p *cancelAwareArtifactProvider) ReadArtifact(ctx context.Context, _ ArtifactRequest) (ArtifactResult, error) {
	deadline, ok := ctx.Deadline()
	if !ok || time.Until(deadline) <= 0 || time.Until(deadline) > defaultRuntimeHostcallTimeout+250*time.Millisecond {
		return ArtifactResult{}, errors.New("artifact context deadline is not bounded")
	}
	p.started <- time.Now()
	<-ctx.Done()
	p.canceled <- ctx.Err()
	return ArtifactResult{}, ctx.Err()
}

func assertBoundedDeadline(t *testing.T, label string, calledAt time.Time, deadline time.Time, ok bool, max time.Duration) {
	t.Helper()
	if !ok {
		t.Fatalf("%s context missing deadline", label)
	}
	remaining := deadline.Sub(calledAt)
	if remaining <= 0 || remaining > max+250*time.Millisecond {
		t.Fatalf("%s deadline remaining = %v, want >0 and <= %v", label, remaining, max)
	}
}

func workerInvocationFixture() []byte {
	return workerInvocationFixtureWithAccess(workerBrokerAccess{
		Storage: []workerStorageBrokerAccess{
			{StoreID: "workspace", Scope: "user", Operations: []string{"read", "write", "delete", "list"}},
			{StoreID: "settings", Scope: "user", Operations: []string{"get", "put", "delete", "list"}},
			{StoreID: "db", Scope: "user", Operations: []string{"exec", "query"}},
		},
		Network: []workerNetworkBrokerAccess{
			{ConnectorID: "api", Transport: "http", Scope: "user", Operations: []string{"http", "http_stream"}, HTTPMethods: []string{"GET", "POST"}},
			{ConnectorID: "api", Transport: "websocket", Scope: "user", Operations: []string{"websocket_round_trip"}},
			{ConnectorID: "api", Transport: "tcp", Scope: "user", Operations: []string{"tcp_round_trip"}},
			{ConnectorID: "api", Transport: "udp", Scope: "user", Operations: []string{"udp_round_trip"}},
		},
	})
}

func testUserResourceScope() sessionctx.ResourceScope {
	return sessionctx.ResourceScope{Kind: sessionctx.ScopeUser, OwnerEnvHash: "env_hash", OwnerUserHash: "user_hash"}
}

func workerInvocationFixtureForPlugin(pluginInstanceID string) []byte {
	return bytes.ReplaceAll(workerInvocationFixture(), []byte(`"plugin_instance_id":"plugini_1"`), []byte(`"plugin_instance_id":"`+pluginInstanceID+`"`))
}

func workerInvocationLeaseFixture() Lease {
	return Lease{
		PluginID:             "com.example.worker",
		PluginInstanceID:     "plugini_1",
		ActiveFingerprint:    "sha256:active",
		InvocationID:         "invoke_runtime_1",
		ScopeKind:            sessionctx.ScopeUser,
		RuntimeInstanceID:    "runtime_1",
		RuntimeGenerationID:  "runtime_gen_test",
		RuntimeShardID:       "runtime_shard_1",
		Method:               "worker.echo",
		Effect:               "read",
		Execution:            "subscription",
		SurfaceInstanceID:    "surface_runtime",
		OwnerSessionHash:     "session_hash",
		OwnerUserHash:        "user_hash",
		OwnerEnvHash:         "env_hash",
		SessionChannelIDHash: "channel_hash",
		BridgeChannelID:      "bridge_runtime",
		ExecutionID:          "execution_runtime_1",
		AuditCorrelationID:   "audit_runtime_1",
		PolicyRevision:       1,
		ManagementRevision:   2,
		RevokeEpoch:          3,
	}
}

func testRevokeRequest(pluginInstanceID string, revokeEpoch uint64) RevokeRequest {
	return RevokeRequest{
		ResourceScope:    sessionctx.ResourceScope{Kind: sessionctx.ScopeEnvironment, OwnerEnvHash: "env_hash"},
		PluginInstanceID: pluginInstanceID,
		RevokeEpoch:      revokeEpoch,
	}
}

func workerInvocationFixtureWithAccess(access workerBrokerAccess) []byte {
	rawAccess, err := json.Marshal(access)
	if err != nil {
		panic(err)
	}
	accessSum := sha256.Sum256(rawAccess)
	accessHash := "sha256:" + hex.EncodeToString(accessSum[:])
	return []byte(fmt.Sprintf(`{"plugin_id":"com.example.worker","plugin_instance_id":"plugini_1","active_fingerprint":"sha256:active","runtime_instance_id":"runtime_1","runtime_generation_id":"runtime_gen_test","package_hash":%q,"worker_id":"echo_worker","worker_mode":"job","worker_scope":"user","artifact":%q,"artifact_sha256":%q,"method":"worker.echo","effect":"read","execution":"subscription","surface_instance_id":"surface_runtime","owner_session_hash":"session_hash","owner_user_hash":"user_hash","owner_env_hash":"env_hash","session_channel_id_hash":"channel_hash","bridge_channel_id":"bridge_runtime","execution_id":"execution_runtime_1","audit_correlation_id":"audit_runtime_1","broker_access":%s,"broker_access_sha256":%q,"params":{"message":"hello"}}`, fixturePackageHash, fixtureArtifact, fixtureArtifactSHA, rawAccess, accessHash))
}

func (s *ProcessSupervisor) invokeWorkerForTest(ctx context.Context, lease Lease, method string, payload []byte) ([]byte, error) {
	now := time.Now().UTC()
	if s != nil && s.now != nil {
		now = s.now()
	}
	health := s.healthSnapshot()
	if lease.LeaseID == "" {
		lease.LeaseID = "lease_test"
	}
	if lease.LeaseNonce == "" {
		lease.LeaseNonce = "nonce_" + lease.LeaseID + "_1234567890"
	}
	if lease.PluginID == "" {
		lease.PluginID = "com.example.worker"
	}
	if lease.PluginVersion == "" {
		lease.PluginVersion = "1.0.0"
	}
	if lease.ActiveFingerprint == "" {
		lease.ActiveFingerprint = "sha256:active"
	}
	if lease.InvocationID == "" {
		lease.InvocationID = "invoke_runtime_1"
	}
	if lease.ScopeKind == "" {
		lease.ScopeKind = sessionctx.ScopeUser
	}
	if lease.PluginInstanceID == "" {
		lease.PluginInstanceID = "plugini_1"
	}
	if lease.Method == "" {
		lease.Method = method
	}
	if lease.Effect == "" {
		lease.Effect = "read"
	}
	if lease.Execution == "" {
		lease.Execution = "subscription"
	}
	if (lease.Execution == "operation" || lease.Execution == "subscription") && lease.ExecutionID == "" {
		lease.ExecutionID = "execution_runtime_1"
	}
	if lease.AuditCorrelationID == "" {
		lease.AuditCorrelationID = "audit_runtime_1"
	}
	if lease.SurfaceInstanceID == "" {
		lease.SurfaceInstanceID = "surface_runtime"
	}
	if lease.OwnerSessionHash == "" {
		lease.OwnerSessionHash = "session_hash"
	}
	if lease.OwnerUserHash == "" {
		lease.OwnerUserHash = "user_hash"
	}
	if lease.OwnerEnvHash == "" {
		lease.OwnerEnvHash = "env_hash"
	}
	if lease.SessionChannelIDHash == "" {
		lease.SessionChannelIDHash = "channel_hash"
	}
	if lease.BridgeChannelID == "" {
		lease.BridgeChannelID = "bridge_runtime"
	}
	if len(lease.TargetDescriptorHashes) == 0 {
		lease.TargetDescriptorHashes = []string{"invocation:sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
	}
	if lease.Limits.MemoryBytes == 0 {
		lease.Limits.MemoryBytes = 64 * 1024
	}
	if lease.PolicyRevision == 0 {
		lease.PolicyRevision = 1
	}
	if lease.ManagementRevision == 0 {
		lease.ManagementRevision = 1
	}
	if lease.RevokeEpoch == 0 {
		lease.RevokeEpoch = 1
	}
	if lease.RuntimeInstanceID == "" {
		lease.RuntimeInstanceID = health.RuntimeInstanceID
	}
	if lease.RuntimeShardID == "" {
		lease.RuntimeShardID = "runtime_shard_test"
	}
	if lease.RuntimeGenerationID == "" {
		lease.RuntimeGenerationID = health.RuntimeGenerationID
	}
	if lease.IPCChannelID == "" {
		lease.IPCChannelID = health.IPCChannelID
	}
	if lease.ConnectionNonce == "" {
		lease.ConnectionNonce = health.ConnectionNonce
	}
	if lease.TokenID == "" {
		lease.TokenID = lease.LeaseID
	}
	if lease.IssuedAtUnixMillis == 0 {
		lease.IssuedAtUnixMillis = now.Add(-time.Second).UnixMilli()
	}
	if lease.ExpiresAtUnixMillis == 0 {
		lease.ExpiresAtUnixMillis = now.Add(time.Minute).UnixMilli()
	}
	payload = bindWorkerInvocationFixtureToLease(payload, lease)
	return s.InvokeWorker(ctx, lease, method, payload)
}

func bindWorkerInvocationFixtureToLease(payload []byte, lease Lease) []byte {
	var invocation map[string]any
	if json.Unmarshal(payload, &invocation) != nil {
		return payload
	}
	if _, ok := invocation["package_hash"]; !ok {
		return payload
	}
	bindings := map[string]string{
		"plugin_id":               lease.PluginID,
		"plugin_instance_id":      lease.PluginInstanceID,
		"active_fingerprint":      lease.ActiveFingerprint,
		"worker_scope":            string(lease.ScopeKind),
		"runtime_instance_id":     lease.RuntimeInstanceID,
		"runtime_generation_id":   lease.RuntimeGenerationID,
		"method":                  lease.Method,
		"effect":                  lease.Effect,
		"execution":               lease.Execution,
		"surface_instance_id":     lease.SurfaceInstanceID,
		"owner_session_hash":      lease.OwnerSessionHash,
		"owner_user_hash":         lease.OwnerUserHash,
		"owner_env_hash":          lease.OwnerEnvHash,
		"session_channel_id_hash": lease.SessionChannelIDHash,
		"bridge_channel_id":       lease.BridgeChannelID,
		"execution_id":            lease.ExecutionID,
		"audit_correlation_id":    lease.AuditCorrelationID,
	}
	for field, value := range bindings {
		if value == "" {
			delete(invocation, field)
			continue
		}
		invocation[field] = value
	}
	raw, err := json.Marshal(invocation)
	if err != nil {
		panic(err)
	}
	return raw
}

const streamIDForRuntimeNetworkTest = "execution_runtime_1"

type capturedExecutionEvent struct {
	executionID string
	kind        string
	data        []byte
}

type executionEventSink struct {
	mu          sync.Mutex
	executionID string
	events      []capturedExecutionEvent
	closed      bool
	failureCode capability.ExecutionFailureCode
}

func newExecutionEventSink(executionID string) *executionEventSink {
	return &executionEventSink{executionID: executionID}
}

func (s *executionEventSink) AppendRuntimeStream(_ context.Context, executionID, kind string, data []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if executionID != s.executionID || s.closed || s.failureCode != "" {
		return execution.ErrInvalidTransition
	}
	s.events = append(s.events, capturedExecutionEvent{executionID: executionID, kind: kind, data: bytes.Clone(data)})
	return nil
}

func (s *executionEventSink) CloseRuntimeStream(_ context.Context, executionID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if executionID != s.executionID || s.closed || s.failureCode != "" {
		return execution.ErrInvalidTransition
	}
	s.closed = true
	return nil
}

func (s *executionEventSink) FailRuntimeStream(_ context.Context, executionID string, code capability.ExecutionFailureCode, _ error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if executionID != s.executionID || s.closed || s.failureCode != "" {
		return execution.ErrInvalidTransition
	}
	s.failureCode = code
	return nil
}

func (s *executionEventSink) snapshot() ([]capturedExecutionEvent, bool, capability.ExecutionFailureCode) {
	s.mu.Lock()
	defer s.mu.Unlock()
	events := make([]capturedExecutionEvent, len(s.events))
	copy(events, s.events)
	return events, s.closed, s.failureCode
}

func stopRuntimeSupervisor(t *testing.T, supervisor *ProcessSupervisor) {
	t.Helper()
	stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := supervisor.Stop(stopCtx); err != nil {
		t.Fatalf("Stop() error = %v", err)
	}
}
