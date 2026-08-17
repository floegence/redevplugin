package runtimeclient

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
)

const (
	semanticIPCChunkedFlag uint16 = 1 << 15
	semanticIPCMoreFlag    uint16 = 1 << 14
)

type semanticIPCChunkEnvelope struct {
	Encoding string `json:"encoding"`
	Index    uint32 `json:"index"`
}

// semanticIPCWriteCloser bridges the semantic JSON frame model to the sole
// production byte transport. It
// accepts complete JSON-line writes from json.Encoder and emits framed bytes.
type semanticIPCWriteCloser struct {
	mu      sync.Mutex
	closer  io.WriteCloser
	pending []byte
	mapType func(string) (IPCFrameType, error)
}

func newSemanticIPCWriteCloser(closer io.WriteCloser) *semanticIPCWriteCloser {
	return &semanticIPCWriteCloser{closer: closer, mapType: hostSemanticFrameType}
}

func newRuntimeSemanticIPCWriteCloser(closer io.WriteCloser) *semanticIPCWriteCloser {
	return &semanticIPCWriteCloser{closer: closer, mapType: runtimeSemanticFrameType}
}

func (writer *semanticIPCWriteCloser) Write(payload []byte) (int, error) {
	if writer == nil || writer.closer == nil {
		return 0, io.ErrClosedPipe
	}
	writer.mu.Lock()
	defer writer.mu.Unlock()
	written := len(payload)
	writer.pending = append(writer.pending, payload...)
	for {
		newline := bytes.IndexByte(writer.pending, '\n')
		if newline < 0 {
			if len(writer.pending) > int(IPCFrameMax) {
				return 0, ErrIPCFrameTooLarge
			}
			return written, nil
		}
		line := append([]byte(nil), bytes.TrimSpace(writer.pending[:newline])...)
		writer.pending = append(writer.pending[:0], writer.pending[newline+1:]...)
		if len(line) == 0 {
			continue
		}
		var semantic ipcFrame
		if err := decodeStrictJSON(line, &semantic); err != nil {
			return 0, fmt.Errorf("%w: semantic frame: %v", ErrIPCFrameInvalid, err)
		}
		if writer.mapType == nil {
			return 0, fmt.Errorf("%w: semantic frame direction", ErrIPCProtocolViolation)
		}
		frameType, err := writer.mapType(semantic.FrameType)
		if err != nil {
			return 0, err
		}
		if err := writeSemanticIPCFrame(writer.closer, frameType, semanticIPCRequestID(semantic.RequestID), line); err != nil {
			return 0, err
		}
	}
}

func (writer *semanticIPCWriteCloser) Close() error {
	if writer == nil || writer.closer == nil {
		return nil
	}
	writer.mu.Lock()
	defer writer.mu.Unlock()
	var pendingErr error
	if len(bytes.TrimSpace(writer.pending)) != 0 {
		pendingErr = fmt.Errorf("%w: unterminated semantic frame", ErrIPCFrameInvalid)
	}
	writer.pending = nil
	return errors.Join(pendingErr, writer.closer.Close())
}

func (writer *semanticIPCWriteCloser) WriteFrame(frame IPCFrame) error {
	if writer == nil || writer.closer == nil {
		return io.ErrClosedPipe
	}
	writer.mu.Lock()
	defer writer.mu.Unlock()
	return WriteIPCFrame(writer.closer, frame)
}

func readSemanticIPCFrame(reader io.Reader) (ipcFrame, error) {
	framed, err := ReadIPCFrame(reader)
	if err != nil {
		return ipcFrame{}, err
	}
	return readRuntimeSemanticIPCFrame(reader, framed)
}

func readHostSemanticIPCFrame(reader io.Reader) (ipcFrame, error) {
	return readDirectionalSemanticIPCFrame(reader, hostSemanticFrameType)
}

func readDirectionalSemanticIPCFrame(reader io.Reader, mapType func(string) (IPCFrameType, error)) (ipcFrame, error) {
	framed, err := ReadIPCFrame(reader)
	if err != nil {
		return ipcFrame{}, err
	}
	return readDirectionalSemanticIPCFrameDecoded(reader, framed, mapType)
}

func readRuntimeSemanticIPCFrame(reader io.Reader, framed IPCFrame) (ipcFrame, error) {
	return readDirectionalSemanticIPCFrameDecoded(reader, framed, runtimeSemanticFrameType)
}

func readDirectionalSemanticIPCFrameDecoded(reader io.Reader, framed IPCFrame, mapType func(string) (IPCFrameType, error)) (ipcFrame, error) {
	semanticBytes, err := readSemanticIPCBytes(reader, framed)
	if err != nil {
		return ipcFrame{}, err
	}
	var semantic ipcFrame
	if err := decodeStrictJSON(semanticBytes, &semantic); err != nil {
		return ipcFrame{}, fmt.Errorf("%w: semantic frame: %v", ErrIPCFrameInvalid, err)
	}
	wantType, err := mapType(semantic.FrameType)
	if err != nil {
		return ipcFrame{}, err
	}
	if framed.Type != wantType || framed.RequestID != semanticIPCRequestID(semantic.RequestID) {
		return ipcFrame{}, fmt.Errorf("%w: semantic frame identity mismatch", ErrIPCProtocolViolation)
	}
	return semantic, nil
}

func writeSemanticIPCFrame(writer io.Writer, frameType IPCFrameType, requestID uint64, semantic []byte) error {
	if len(semantic) == 0 || len(semantic) > int(IPCInvokeMetadataMax) {
		return ErrIPCFrameTooLarge
	}
	for index, offset := uint32(0), 0; offset < len(semantic); index++ {
		end := min(offset+int(IPCBodyMax), len(semantic))
		envelope, err := json.Marshal(semanticIPCChunkEnvelope{Encoding: "semantic_json", Index: index})
		if err != nil {
			return err
		}
		flags := semanticIPCChunkedFlag
		if end < len(semantic) {
			flags |= semanticIPCMoreFlag
		}
		if err := WriteIPCFrame(writer, IPCFrame{
			Type: frameType, Flags: flags, RequestID: requestID, Metadata: envelope, Body: semantic[offset:end],
		}); err != nil {
			return err
		}
		offset = end
	}
	return nil
}

func readSemanticIPCBytes(reader io.Reader, first IPCFrame) ([]byte, error) {
	if first.Flags&semanticIPCChunkedFlag == 0 {
		return nil, fmt.Errorf("%w: semantic frame placement", ErrIPCProtocolViolation)
	}
	var result []byte
	frame := first
	for index := uint32(0); ; index++ {
		if frame.Flags & ^(semanticIPCChunkedFlag|semanticIPCMoreFlag) != 0 || len(frame.Body) == 0 {
			return nil, fmt.Errorf("%w: semantic chunk flags", ErrIPCProtocolViolation)
		}
		var envelope semanticIPCChunkEnvelope
		if err := decodeStrictJSON(frame.Metadata, &envelope); err != nil || envelope.Encoding != "semantic_json" || envelope.Index != index {
			return nil, fmt.Errorf("%w: semantic chunk envelope", ErrIPCProtocolViolation)
		}
		if len(result) > int(IPCInvokeMetadataMax)-len(frame.Body) {
			return nil, ErrIPCFrameTooLarge
		}
		result = append(result, frame.Body...)
		if frame.Flags&semanticIPCMoreFlag == 0 {
			return result, nil
		}
		next, err := ReadIPCFrame(reader)
		if err != nil {
			return nil, err
		}
		if next.Type != first.Type || next.RequestID != first.RequestID || next.Flags&semanticIPCChunkedFlag == 0 {
			return nil, fmt.Errorf("%w: semantic chunk identity", ErrIPCProtocolViolation)
		}
		frame = next
	}
}

func semanticIPCRequestID(requestID string) uint64 {
	sum := sha256.Sum256([]byte(requestID))
	value := binary.BigEndian.Uint64(sum[:8])
	if value == 0 {
		return 1
	}
	return value
}

func hostSemanticFrameType(frameType string) (IPCFrameType, error) {
	switch frameType {
	case ipcFrameTypeHello:
		return IPCFrameHello, nil
	case ipcFrameTypeHeartbeat:
		return IPCFrameHeartbeat, nil
	case ipcFrameTypeInvokeWorker:
		return IPCFrameInvoke, nil
	case ipcFrameTypeCancelInvoke:
		return IPCFrameCancelInvoke, nil
	case ipcFrameTypeRevokeEpoch:
		return IPCFrameRevokePlugin, nil
	case ipcFrameTypeSessionRevoke:
		return IPCFrameRevokeSession, nil
	case ipcFrameTypeOpenHandle:
		return IPCFrameHostcallResult, nil
	default:
		return 0, fmt.Errorf("%w: Host semantic frame type %q", ErrIPCProtocolViolation, frameType)
	}
}

func runtimeSemanticFrameType(frameType string) (IPCFrameType, error) {
	switch frameType {
	case ipcFrameTypeHelloAck:
		return IPCFrameHelloAck, nil
	case ipcFrameTypeHeartbeat:
		return IPCFrameHeartbeat, nil
	case ipcFrameTypeInvokeWorkerResult:
		return IPCFrameInvokeResult, nil
	case ipcFrameTypeCancelInvokeAck:
		return IPCFrameCancelAck, nil
	case ipcFrameTypeRevokeEpochAck:
		return IPCFrameRevokePlugin, nil
	case ipcFrameTypeSessionRevokeAck:
		return IPCFrameRevokeSession, nil
	case ipcFrameTypeCompileFlightRegister, ipcFrameTypeCompileFlightComplete, ipcFrameTypeOpenHandle:
		return IPCFrameHostcall, nil
	default:
		return 0, fmt.Errorf("%w: runtime semantic frame type %q", ErrIPCProtocolViolation, frameType)
	}
}
