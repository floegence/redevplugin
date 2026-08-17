package runtimeclient

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"testing"
)

func TestIPCFrameRoundTripPreservesRawBody(t *testing.T) {
	body := make([]byte, IPCBodyMax)
	for index := range body {
		body[index] = byte(index % 251)
	}
	want := IPCFrame{Type: IPCFrameIOReadResult, Flags: 5, RequestID: 42, Metadata: []byte(`{"ok":true}`), Body: body}
	var encoded bytes.Buffer
	if err := WriteIPCFrame(&encoded, want); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded.Bytes(), []byte("body_base64")) {
		t.Fatal("raw IPC frame contains a Base64 body envelope")
	}
	got, err := ReadIPCFrame(&encoded)
	if err != nil {
		t.Fatal(err)
	}
	if got.Type != want.Type || got.Flags != want.Flags || got.RequestID != want.RequestID || !bytes.Equal(got.Metadata, want.Metadata) || !bytes.Equal(got.Body, want.Body) {
		t.Fatalf("round trip mismatch: got=%#v want=%#v", got, want)
	}
}

func TestIPCFrameUsesFrameSpecificMetadataLimits(t *testing.T) {
	largeMetadata := append([]byte(`{"value":"`), bytes.Repeat([]byte("a"), 80<<10)...)
	largeMetadata = append(largeMetadata, []byte(`"}`)...)
	invoke := IPCFrame{Type: IPCFrameInvoke, RequestID: 1, Metadata: largeMetadata}
	var encoded bytes.Buffer
	if err := WriteIPCFrame(&encoded, invoke); err != nil {
		t.Fatalf("invoke metadata rejected: %v", err)
	}
	invoke.Type = IPCFrameHostcall
	if err := WriteIPCFrame(io.Discard, invoke); !errors.Is(err, ErrIPCFrameTooLarge) {
		t.Fatalf("hostcall metadata error = %v, want %v", err, ErrIPCFrameTooLarge)
	}
}

func TestIPCFrameRejectsMalformedLengthsBeforeAllocation(t *testing.T) {
	for _, test := range []struct {
		name   string
		header func([]byte)
		want   error
	}{
		{name: "invalid magic", header: func(header []byte) {
			copy(header, []byte("NOPE"))
		}, want: ErrIPCProtocolViolation},
		{name: "oversize payload", header: func(header []byte) {
			copy(header, ipcFrameMagic[:])
			header[4] = byte(IPCFrameHostcall)
			binary.BigEndian.PutUint64(header[7:15], 1)
			binary.BigEndian.PutUint32(header[15:19], IPCFrameMax)
		}, want: ErrIPCFrameTooLarge},
	} {
		t.Run(test.name, func(t *testing.T) {
			header := make([]byte, IPCFrameHeaderBytes)
			test.header(header)
			input := bytes.NewReader(header)
			_, err := ReadIPCFrame(input)
			if !errors.Is(err, test.want) {
				t.Fatalf("ReadIPCFrame() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestIPCFrameRejectsInvalidJSONAndFrameType(t *testing.T) {
	tests := []IPCFrame{
		{Type: IPCFrameHello, RequestID: 1, Metadata: []byte(`{"a":1,"a":2}`)},
		{Type: IPCFrameHello, RequestID: 1, Metadata: []byte(`{"value":1e0}`)},
		{Type: IPCFrameType(255), RequestID: 1, Metadata: []byte(`{}`)},
	}
	for index, frame := range tests {
		if err := WriteIPCFrame(io.Discard, frame); err == nil {
			t.Fatalf("case %d accepted invalid frame: %#v", index, frame)
		}
	}
}

func TestIPCFrameAcceptsSignedSeekOffsetMetadata(t *testing.T) {
	frame := IPCFrame{Type: IPCFrameIOSeek, RequestID: 1, Metadata: []byte(`{"offset":-4096,"whence":2}`)}
	var encoded bytes.Buffer
	if err := WriteIPCFrame(&encoded, frame); err != nil {
		t.Fatal(err)
	}
	decoded, err := ReadIPCFrame(&encoded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded.Metadata, frame.Metadata) {
		t.Fatalf("metadata = %s, want %s", decoded.Metadata, frame.Metadata)
	}
}

func TestIPCFrameMatchesCrossLanguageFixtures(t *testing.T) {
	raw, err := os.ReadFile("../../spec/internal/runtime-wire-fixtures.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixtures struct {
		SchemaKind string `json:"schema_kind"`
		Frames     []struct {
			Name        string `json:"name"`
			EncodedHex  string `json:"encoded_hex"`
			FrameType   uint8  `json:"frame_type"`
			Flags       uint16 `json:"flags"`
			RequestID   uint64 `json:"request_id"`
			MetadataHex string `json:"metadata_hex"`
			BodyHex     string `json:"body_hex"`
		} `json:"frames"`
	}
	if err := json.Unmarshal(raw, &fixtures); err != nil {
		t.Fatal(err)
	}
	if fixtures.SchemaKind != "redevplugin.runtime_wire_fixtures" || len(fixtures.Frames) == 0 {
		t.Fatalf("invalid runtime wire fixture catalog: %#v", fixtures)
	}
	for _, fixture := range fixtures.Frames {
		t.Run(fixture.Name, func(t *testing.T) {
			encoded, err := hex.DecodeString(fixture.EncodedHex)
			if err != nil {
				t.Fatal(err)
			}
			metadata, err := hex.DecodeString(fixture.MetadataHex)
			if err != nil {
				t.Fatal(err)
			}
			body, err := hex.DecodeString(fixture.BodyHex)
			if err != nil {
				t.Fatal(err)
			}
			want := IPCFrame{Type: IPCFrameType(fixture.FrameType), Flags: fixture.Flags, RequestID: fixture.RequestID, Metadata: metadata, Body: body}
			got, err := ReadIPCFrame(bytes.NewReader(encoded))
			if err != nil {
				t.Fatal(err)
			}
			if got.Type != want.Type || got.Flags != want.Flags || got.RequestID != want.RequestID || !bytes.Equal(got.Metadata, want.Metadata) || !bytes.Equal(got.Body, want.Body) {
				t.Fatalf("decoded fixture = %#v, want %#v", got, want)
			}
			var output bytes.Buffer
			if err := WriteIPCFrame(&output, want); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(output.Bytes(), encoded) {
				t.Fatalf("encoded fixture = %x, want %x", output.Bytes(), encoded)
			}
		})
	}
}
