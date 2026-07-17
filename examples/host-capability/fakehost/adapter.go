package fakehost

import (
	"context"
	"errors"
	"time"

	"github.com/floegence/redevplugin/pkg/capability"
)

type DocumentsAdapter struct{}

func (DocumentsAdapter) ProjectTarget(_ context.Context, req capability.TargetResolutionRequest) (capability.TargetDescriptor, error) {
	fields := map[string]any{}
	for _, name := range []string{"workspace_id", "document_id"} {
		if value, ok := req.TargetInput[name]; ok {
			fields[name] = value
		}
	}
	return capability.TargetDescriptor{Kind: "documents", Fields: fields}, nil
}

func (DocumentsAdapter) Invoke(_ context.Context, req capability.Invocation) (capability.Result, error) {
	switch req.Execution.TargetMethod {
	case "documents.list":
		return capability.Result{Data: map[string]any{
			"documents": []any{map[string]any{"document_id": "doc-1", "title": "Release notes"}},
		}}, nil
	case "documents.archive":
		if req.Execution.Operation == nil {
			return capability.Result{}, errors.New("documents.archive requires a Host-owned operation sink")
		}
		go finishArchive(req.Execution.Operation)
		return capability.Result{Data: map[string]any{"accepted": true}}, nil
	case "documents.watch":
		if req.Execution.Stream == nil {
			return capability.Result{}, errors.New("documents.watch requires a Host-owned stream sink")
		}
		go publishDocumentEvents(req.Execution.Stream)
		return capability.Result{Data: map[string]any{"watching": true}}, nil
	default:
		return capability.Result{}, capability.NewBusinessError("DOCUMENT_NOT_FOUND", "Document not found", map[string]any{"document_id": "unknown"})
	}
}

func (DocumentsAdapter) CancelOperation(context.Context, capability.OperationCancellation) error {
	return nil
}

func finishArchive(operation capability.OperationSink) {
	select {
	case <-operation.CancelRequested():
		_ = operation.Cancel(context.Background(), "archive canceled")
	case <-time.After(10 * time.Millisecond):
		_ = operation.Complete(context.Background())
	}
}

func publishDocumentEvents(stream capability.StreamSink) {
	if err := stream.Append(context.Background(), map[string]any{"document_id": "doc-1", "change": "updated"}); err != nil {
		_ = stream.Fail(context.Background(), capability.ExecutionFailurePlatformFailed, err)
		return
	}
	_ = stream.Close(context.Background())
}
