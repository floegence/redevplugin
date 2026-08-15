package runtimeclient

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/floegence/redevplugin/v2/internal/resourceio"
)

type runtimeIORequestMetadata struct {
	InvocationID string `json:"invocation_id"`
	MaxBytes     uint32 `json:"max_bytes,omitempty"`
	Flags        uint32 `json:"flags,omitempty"`
	Offset       int64  `json:"offset,omitempty"`
	Whence       int    `json:"whence,omitempty"`
}

type runtimeIOControlRequestMetadata struct {
	InvocationID string          `json:"invocation_id"`
	Request      json.RawMessage `json:"request"`
}

type runtimeIOControlResultMetadata struct {
	InvocationID string          `json:"invocation_id"`
	OK           bool            `json:"ok"`
	Response     json.RawMessage `json:"response,omitempty"`
	Code         string          `json:"code,omitempty"`
	Message      string          `json:"message,omitempty"`
	Retryable    bool            `json:"retryable,omitempty"`
}

type runtimeIOResultMetadata struct {
	InvocationID string `json:"invocation_id"`
	OK           bool   `json:"ok"`
	BytesRead    int    `json:"bytes_read,omitempty"`
	BytesWritten int    `json:"bytes_written,omitempty"`
	Flags        uint32 `json:"flags,omitempty"`
	Offset       int64  `json:"offset,omitempty"`
	Code         string `json:"code,omitempty"`
	Message      string `json:"message,omitempty"`
	Retryable    bool   `json:"retryable,omitempty"`
}

func isRuntimeIORequestFrame(frameType IPCFrameType) bool {
	switch frameType {
	case IPCFrameIORead, IPCFrameIOWrite, IPCFrameIOSeek, IPCFrameIOClose:
		return true
	default:
		return false
	}
}

func isRuntimeIOControlRequestFrame(frame IPCFrame) bool {
	if frame.Type != IPCFrameHostcall || frame.Flags != 0 || frame.ResourceID != 0 || len(frame.Body) != 0 {
		return false
	}
	var probe struct {
		InvocationID json.RawMessage `json:"invocation_id"`
	}
	return json.Unmarshal(frame.Metadata, &probe) == nil && len(probe.InvocationID) != 0
}

func runtimeIOResponseFrameType(frameType IPCFrameType) IPCFrameType {
	switch frameType {
	case IPCFrameIORead:
		return IPCFrameIOReadResult
	case IPCFrameIOWrite:
		return IPCFrameIOWriteResult
	case IPCFrameIOSeek:
		return IPCFrameIOSeekResult
	case IPCFrameIOClose:
		return IPCFrameIOCloseResult
	default:
		return 0
	}
}

func (s *ProcessSupervisor) dispatchRuntimeIOFrame(generation *runtimeGeneration, frame IPCFrame) error {
	if s == nil || generation == nil || generation.framedStdin == nil || s.ioBroker == nil || frame.Flags != 0 || (!isRuntimeIORequestFrame(frame.Type) && !isRuntimeIOControlRequestFrame(frame)) {
		return fmt.Errorf("%w: invalid runtime I/O route", ErrIPCProtocolViolation)
	}
	if isRuntimeIOControlRequestFrame(frame) {
		return s.dispatchRuntimeIOControlFrame(generation, frame)
	}
	var metadata runtimeIORequestMetadata
	if err := decodeStrictJSON(frame.Metadata, &metadata); err != nil {
		return fmt.Errorf("%w: invalid runtime I/O metadata", ErrIPCProtocolViolation)
	}
	metadata.InvocationID = strings.TrimSpace(metadata.InvocationID)
	if metadata.InvocationID == "" {
		return fmt.Errorf("%w: runtime I/O invocation_id is required", ErrIPCProtocolViolation)
	}
	if err := validateRuntimeIORequestShape(frame, metadata); err != nil {
		return err
	}
	s.pendingMu.Lock()
	parent := s.pendingInvocations[metadata.InvocationID]
	s.pendingMu.Unlock()
	if parent == nil || parent.generation != generation || parent.invocation == nil || parent.invocation.InvocationID != metadata.InvocationID {
		return fmt.Errorf("%w: runtime I/O invocation is not active", ErrIPCProtocolViolation)
	}
	select {
	case s.ioRouteSlots <- struct{}{}:
	default:
		return fmt.Errorf("%w: runtime I/O route capacity is exhausted", ErrIPCProtocolViolation)
	}
	go func() {
		defer func() { <-s.ioRouteSlots }()
		response := s.executeRuntimeIO(parent.ctx, frame, metadata)
		if err := generation.framedStdin.WriteFrame(response); err != nil {
			s.invalidateRuntimeAfterIPCFailure(s.healthSnapshot(), err)
		}
	}()
	return nil
}

func (s *ProcessSupervisor) dispatchRuntimeIOControlFrame(generation *runtimeGeneration, frame IPCFrame) error {
	var metadata runtimeIOControlRequestMetadata
	if err := decodeStrictJSON(frame.Metadata, &metadata); err != nil {
		return fmt.Errorf("%w: invalid runtime I/O control metadata", ErrIPCProtocolViolation)
	}
	metadata.InvocationID = strings.TrimSpace(metadata.InvocationID)
	if metadata.InvocationID == "" || len(metadata.Request) == 0 || len(metadata.Request) > int(IPCControlMetadataMax) {
		return fmt.Errorf("%w: invalid runtime I/O control request", ErrIPCProtocolViolation)
	}
	s.pendingMu.Lock()
	parent := s.pendingInvocations[metadata.InvocationID]
	s.pendingMu.Unlock()
	if parent == nil || parent.generation != generation || parent.invocation == nil || parent.invocation.InvocationID != metadata.InvocationID {
		return fmt.Errorf("%w: runtime I/O invocation is not active", ErrIPCProtocolViolation)
	}
	select {
	case s.ioRouteSlots <- struct{}{}:
	default:
		return fmt.Errorf("%w: runtime I/O route capacity is exhausted", ErrIPCProtocolViolation)
	}
	go func() {
		defer func() { <-s.ioRouteSlots }()
		response := IPCFrame{Type: IPCFrameHostcallResult, RequestID: frame.RequestID}
		result := runtimeIOControlResultMetadata{InvocationID: metadata.InvocationID, OK: true}
		raw, err := s.ioBroker.Control(parent.ctx, metadata.InvocationID, metadata.Request)
		if err != nil {
			code, retryable := resourceio.StableError(err)
			result = runtimeIOControlResultMetadata{InvocationID: metadata.InvocationID, OK: false, Code: code, Message: strings.ToLower(strings.ReplaceAll(code, "_", " ")), Retryable: retryable}
		} else if len(raw) == 0 || len(raw) > int(IPCControlMetadataMax) || !json.Valid(raw) {
			result = runtimeIOControlResultMetadata{InvocationID: metadata.InvocationID, OK: false, Code: "INTERNAL", Message: "internal", Retryable: false}
		} else {
			result.Response = append(json.RawMessage(nil), raw...)
		}
		response.Metadata, _ = json.Marshal(result)
		if err := generation.framedStdin.WriteFrame(response); err != nil {
			s.invalidateRuntimeAfterIPCFailure(s.healthSnapshot(), err)
		}
	}()
	return nil
}

func validateRuntimeIORequestShape(frame IPCFrame, metadata runtimeIORequestMetadata) error {
	invalid := func() error { return fmt.Errorf("%w: runtime I/O request shape", ErrIPCProtocolViolation) }
	switch frame.Type {
	case IPCFrameIORead:
		if len(frame.Body) != 0 || metadata.MaxBytes == 0 || metadata.MaxBytes > IPCBodyMax || metadata.Flags != 0 || metadata.Offset != 0 || metadata.Whence != 0 {
			return invalid()
		}
	case IPCFrameIOWrite:
		if len(frame.Body) > int(IPCBodyMax) || metadata.MaxBytes != 0 || metadata.Offset != 0 || metadata.Whence != 0 {
			return invalid()
		}
	case IPCFrameIOSeek:
		if len(frame.Body) != 0 || metadata.MaxBytes != 0 || metadata.Flags != 0 || metadata.Whence < 0 || metadata.Whence > 2 {
			return invalid()
		}
	case IPCFrameIOClose:
		if len(frame.Body) != 0 || metadata.MaxBytes != 0 || metadata.Flags != 0 || metadata.Offset != 0 || metadata.Whence != 0 {
			return invalid()
		}
	default:
		return invalid()
	}
	return nil
}

func (s *ProcessSupervisor) executeRuntimeIO(ctx context.Context, request IPCFrame, metadata runtimeIORequestMetadata) IPCFrame {
	response := IPCFrame{
		Type:       runtimeIOResponseFrameType(request.Type),
		RequestID:  request.RequestID,
		ResourceID: request.ResourceID,
	}
	result := runtimeIOResultMetadata{InvocationID: metadata.InvocationID, OK: true}
	var body []byte
	var err error
	switch request.Type {
	case IPCFrameIORead:
		body = make([]byte, metadata.MaxBytes)
		result.BytesRead, result.Flags, err = s.ioBroker.Read(ctx, metadata.InvocationID, request.ResourceID, body)
		if result.BytesRead < 0 || result.BytesRead > len(body) {
			err = fmt.Errorf("runtime I/O broker returned invalid read length")
		} else {
			body = body[:result.BytesRead]
		}
	case IPCFrameIOWrite:
		result.BytesWritten, err = s.ioBroker.Write(ctx, metadata.InvocationID, request.ResourceID, request.Body, metadata.Flags)
		if result.BytesWritten < 0 || result.BytesWritten > len(request.Body) {
			err = fmt.Errorf("runtime I/O broker returned invalid write length")
		}
	case IPCFrameIOSeek:
		result.Offset, err = s.ioBroker.Seek(ctx, metadata.InvocationID, request.ResourceID, metadata.Offset, metadata.Whence)
	case IPCFrameIOClose:
		err = s.ioBroker.Close(ctx, metadata.InvocationID, request.ResourceID)
	}
	if err != nil {
		code, retryable := resourceio.StableError(err)
		result = runtimeIOResultMetadata{
			InvocationID: metadata.InvocationID, OK: false, Code: code, Message: strings.ToLower(strings.ReplaceAll(code, "_", " ")), Retryable: retryable,
		}
		body = nil
	}
	response.Metadata, _ = json.Marshal(result)
	response.Body = body
	return response
}
