package runtimeclient

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"unicode/utf8"
)

const (
	IPCProtocolVersionV7  uint8  = 7
	IPCFrameHeaderBytes          = 28
	IPCControlMetadataMax uint32 = 64 << 10
	IPCInvokeMetadataMax  uint32 = 1 << 20
	IPCBodyMax            uint32 = 64 << 10
	IPCFrameMax           uint32 = IPCFrameHeaderBytes + IPCInvokeMetadataMax + IPCBodyMax
)

type IPCFrameType uint8

const (
	IPCFrameHello IPCFrameType = iota + 1
	IPCFrameHelloAck
	IPCFrameHeartbeat
	IPCFrameInvoke
	IPCFrameInvokeResult
	IPCFrameCancelInvoke
	IPCFrameCancelAck
	IPCFrameHostcall
	IPCFrameHostcallResult
	IPCFrameIORead
	IPCFrameIOReadResult
	IPCFrameIOWrite
	IPCFrameIOWriteResult
	IPCFrameIOSeek
	IPCFrameIOSeekResult
	IPCFrameIOClose
	IPCFrameIOCloseResult
	IPCFrameExecutionEvent
	IPCFrameRevokePlugin
	IPCFrameRevokeSession
	IPCFrameDiagnostic
)

var (
	ErrIPCFrameInvalid      = errors.New("invalid rust IPC v7 frame")
	ErrIPCFrameTooLarge     = errors.New("rust IPC v7 frame exceeds limit")
	ErrIPCProtocolViolation = errors.New("rust IPC v7 protocol violation")
)

type IPCFrame struct {
	Type       IPCFrameType
	Flags      uint16
	RequestID  uint64
	ResourceID uint64
	Metadata   []byte
	Body       []byte
}

func (frame IPCFrame) clone() IPCFrame {
	frame.Metadata = append([]byte(nil), frame.Metadata...)
	frame.Body = append([]byte(nil), frame.Body...)
	return frame
}

func validIPCFrameType(frameType IPCFrameType) bool {
	return frameType >= IPCFrameHello && frameType <= IPCFrameDiagnostic
}

func ipcFrameUsesResource(frameType IPCFrameType) bool {
	return frameType >= IPCFrameIORead && frameType <= IPCFrameIOCloseResult
}

func ipcMetadataLimit(frameType IPCFrameType) uint32 {
	if frameType == IPCFrameInvoke || frameType == IPCFrameInvokeResult {
		return IPCInvokeMetadataMax
	}
	return IPCControlMetadataMax
}

func validateIPCFrame(frame IPCFrame) error {
	if !validIPCFrameType(frame.Type) {
		return fmt.Errorf("%w: unknown frame type %d", ErrIPCProtocolViolation, frame.Type)
	}
	if frame.RequestID == 0 {
		return fmt.Errorf("%w: request_id 0 is reserved", ErrIPCProtocolViolation)
	}
	usesResource := ipcFrameUsesResource(frame.Type)
	if usesResource && frame.ResourceID == 0 {
		return fmt.Errorf("%w: I/O frame requires resource_id", ErrIPCProtocolViolation)
	}
	if !usesResource && frame.ResourceID != 0 {
		return fmt.Errorf("%w: non-I/O frame carries resource_id", ErrIPCProtocolViolation)
	}
	if uint64(len(frame.Metadata)) > uint64(ipcMetadataLimit(frame.Type)) || uint64(len(frame.Body)) > uint64(IPCBodyMax) {
		return ErrIPCFrameTooLarge
	}
	if len(frame.Metadata) > 0 {
		if !utf8.Valid(frame.Metadata) {
			return fmt.Errorf("%w: metadata is not UTF-8", ErrIPCFrameInvalid)
		}
		if err := validateIPCMetadata(frame.Metadata); err != nil {
			return fmt.Errorf("%w: metadata JSON: %v", ErrIPCFrameInvalid, err)
		}
	}
	return nil
}

func validateIPCMetadata(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	nodes := 0
	if err := consumeIPCJSONValue(decoder, 0, &nodes); err != nil {
		return err
	}
	if token, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err != nil {
			return err
		}
		return fmt.Errorf("trailing JSON token %v", token)
	}
	return nil
}

func consumeIPCJSONValue(decoder *json.Decoder, depth int, nodes *int) error {
	if depth > 64 || *nodes >= 100_000 {
		return errors.New("JSON structural limit exceeded")
	}
	*nodes++
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	switch value := token.(type) {
	case nil, bool, string:
		return nil
	case json.Number:
		return validateIPCJSONInteger(string(value))
	case json.Delim:
		switch value {
		case '[':
			for decoder.More() {
				if err := consumeIPCJSONValue(decoder, depth+1, nodes); err != nil {
					return err
				}
			}
			end, err := decoder.Token()
			if err != nil || end != json.Delim(']') {
				return errors.New("JSON array is not closed")
			}
			return nil
		case '{':
			keys := make(map[string]struct{})
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return err
				}
				key, ok := keyToken.(string)
				if !ok {
					return errors.New("JSON object key is not a string")
				}
				if _, exists := keys[key]; exists {
					return errors.New("duplicate JSON field")
				}
				keys[key] = struct{}{}
				if err := consumeIPCJSONValue(decoder, depth+1, nodes); err != nil {
					return err
				}
			}
			end, err := decoder.Token()
			if err != nil || end != json.Delim('}') {
				return errors.New("JSON object is not closed")
			}
			return nil
		}
	}
	return errors.New("unsupported JSON value")
}

func validateIPCJSONInteger(value string) error {
	if value == "" || value == "-0" {
		return errors.New("JSON number is not a canonical integer")
	}
	if value[0] == '-' {
		if _, err := strconv.ParseInt(value, 10, 64); err != nil {
			return errors.New("JSON number is not a signed 64-bit integer")
		}
		return nil
	}
	if _, err := strconv.ParseUint(value, 10, 64); err != nil {
		return errors.New("JSON number is not an unsigned 64-bit integer")
	}
	return nil
}

func WriteIPCFrameV7(writer io.Writer, frame IPCFrame) error {
	if writer == nil {
		return fmt.Errorf("%w: writer is required", ErrIPCFrameInvalid)
	}
	if err := validateIPCFrame(frame); err != nil {
		return err
	}
	metadataLength := uint32(len(frame.Metadata))
	bodyLength := uint32(len(frame.Body))
	frameLength := uint32(IPCFrameHeaderBytes) + metadataLength + bodyLength
	var header [4 + IPCFrameHeaderBytes]byte
	binary.BigEndian.PutUint32(header[0:4], frameLength)
	header[4] = IPCProtocolVersionV7
	header[5] = byte(frame.Type)
	binary.BigEndian.PutUint16(header[6:8], frame.Flags)
	binary.BigEndian.PutUint64(header[8:16], frame.RequestID)
	binary.BigEndian.PutUint64(header[16:24], frame.ResourceID)
	binary.BigEndian.PutUint32(header[24:28], metadataLength)
	binary.BigEndian.PutUint32(header[28:32], bodyLength)
	if err := writeIPCBytes(writer, header[:]); err != nil {
		return err
	}
	if err := writeIPCBytes(writer, frame.Metadata); err != nil {
		return err
	}
	if err := writeIPCBytes(writer, frame.Body); err != nil {
		return err
	}
	return nil
}

func ReadIPCFrameV7(reader io.Reader) (IPCFrame, error) {
	if reader == nil {
		return IPCFrame{}, fmt.Errorf("%w: reader is required", ErrIPCFrameInvalid)
	}
	var prefix [4]byte
	if _, err := io.ReadFull(reader, prefix[:]); err != nil {
		return IPCFrame{}, err
	}
	frameLength := binary.BigEndian.Uint32(prefix[:])
	if frameLength < IPCFrameHeaderBytes {
		return IPCFrame{}, fmt.Errorf("%w: frame length %d is shorter than header", ErrIPCFrameInvalid, frameLength)
	}
	if frameLength > IPCFrameMax {
		return IPCFrame{}, ErrIPCFrameTooLarge
	}
	var header [IPCFrameHeaderBytes]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return IPCFrame{}, err
	}
	if header[0] != IPCProtocolVersionV7 {
		return IPCFrame{}, fmt.Errorf("%w: protocol version %d", ErrIPCProtocolViolation, header[0])
	}
	frame := IPCFrame{
		Type:       IPCFrameType(header[1]),
		Flags:      binary.BigEndian.Uint16(header[2:4]),
		RequestID:  binary.BigEndian.Uint64(header[4:12]),
		ResourceID: binary.BigEndian.Uint64(header[12:20]),
	}
	if !validIPCFrameType(frame.Type) {
		return IPCFrame{}, fmt.Errorf("%w: unknown frame type %d", ErrIPCProtocolViolation, frame.Type)
	}
	metadataLength := binary.BigEndian.Uint32(header[20:24])
	bodyLength := binary.BigEndian.Uint32(header[24:28])
	if metadataLength > ipcMetadataLimit(frame.Type) || bodyLength > IPCBodyMax {
		return IPCFrame{}, ErrIPCFrameTooLarge
	}
	if uint64(IPCFrameHeaderBytes)+uint64(metadataLength)+uint64(bodyLength) != uint64(frameLength) {
		return IPCFrame{}, fmt.Errorf("%w: component lengths do not match frame length", ErrIPCFrameInvalid)
	}
	frame.Metadata = make([]byte, metadataLength)
	frame.Body = make([]byte, bodyLength)
	if _, err := io.ReadFull(reader, frame.Metadata); err != nil {
		return IPCFrame{}, err
	}
	if _, err := io.ReadFull(reader, frame.Body); err != nil {
		return IPCFrame{}, err
	}
	if err := validateIPCFrame(frame); err != nil {
		return IPCFrame{}, err
	}
	return frame, nil
}

func writeIPCBytes(writer io.Writer, value []byte) error {
	for len(value) > 0 {
		written, err := writer.Write(value)
		if err != nil {
			return err
		}
		if written <= 0 || written > len(value) {
			return io.ErrShortWrite
		}
		value = value[written:]
	}
	return nil
}

func IPCResponseTypeV7(request IPCFrameType) (IPCFrameType, bool) {
	switch request {
	case IPCFrameHello:
		return IPCFrameHelloAck, true
	case IPCFrameHeartbeat:
		return IPCFrameHeartbeat, true
	case IPCFrameInvoke:
		return IPCFrameInvokeResult, true
	case IPCFrameCancelInvoke:
		return IPCFrameCancelAck, true
	case IPCFrameHostcall:
		return IPCFrameHostcallResult, true
	case IPCFrameIORead:
		return IPCFrameIOReadResult, true
	case IPCFrameIOWrite:
		return IPCFrameIOWriteResult, true
	case IPCFrameIOSeek:
		return IPCFrameIOSeekResult, true
	case IPCFrameIOClose:
		return IPCFrameIOCloseResult, true
	case IPCFrameRevokePlugin:
		return IPCFrameRevokePlugin, true
	case IPCFrameRevokeSession:
		return IPCFrameRevokeSession, true
	default:
		return 0, false
	}
}
