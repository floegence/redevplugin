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

func TestIPCFrameV7RoundTripPreservesRawBody(t *testing.T) {
	body := make([]byte, IPCBodyMax)
	for index := range body {
		body[index] = byte(index % 251)
	}
	want := IPCFrame{Type: IPCFrameIOReadResult, Flags: 5, RequestID: 42, ResourceID: 99, Metadata: []byte(`{"ok":true}`), Body: body}
	var encoded bytes.Buffer
	if err := WriteIPCFrameV7(&encoded, want); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded.Bytes(), []byte("body_base64")) {
		t.Fatal("raw IPC frame contains a Base64 body envelope")
	}
	got, err := ReadIPCFrameV7(&encoded)
	if err != nil {
		t.Fatal(err)
	}
	if got.Type != want.Type || got.Flags != want.Flags || got.RequestID != want.RequestID || got.ResourceID != want.ResourceID || !bytes.Equal(got.Metadata, want.Metadata) || !bytes.Equal(got.Body, want.Body) {
		t.Fatalf("round trip mismatch: got=%#v want=%#v", got, want)
	}
}

func TestIPCFrameV7UsesFrameSpecificMetadataLimits(t *testing.T) {
	largeMetadata := append([]byte(`{"value":"`), bytes.Repeat([]byte("a"), 80<<10)...)
	largeMetadata = append(largeMetadata, []byte(`"}`)...)
	invoke := IPCFrame{Type: IPCFrameInvoke, RequestID: 1, Metadata: largeMetadata}
	var encoded bytes.Buffer
	if err := WriteIPCFrameV7(&encoded, invoke); err != nil {
		t.Fatalf("invoke metadata rejected: %v", err)
	}
	invoke.Type = IPCFrameHostcall
	if err := WriteIPCFrameV7(io.Discard, invoke); !errors.Is(err, ErrIPCFrameTooLarge) {
		t.Fatalf("hostcall metadata error = %v, want %v", err, ErrIPCFrameTooLarge)
	}
}

func TestIPCFrameV7RejectsMalformedLengthsBeforeAllocation(t *testing.T) {
	for _, test := range []struct {
		name   string
		prefix uint32
		header func([]byte)
		want   error
	}{
		{name: "short header", prefix: IPCFrameHeaderBytes - 1, want: ErrIPCFrameInvalid},
		{name: "oversize frame", prefix: IPCFrameMax + 1, want: ErrIPCFrameTooLarge},
		{name: "oversize metadata", prefix: IPCFrameHeaderBytes, header: func(header []byte) {
			header[0], header[1] = IPCProtocolVersionV7, byte(IPCFrameHostcall)
			binary.BigEndian.PutUint64(header[4:12], 1)
			binary.BigEndian.PutUint32(header[20:24], IPCControlMetadataMax+1)
		}, want: ErrIPCFrameTooLarge},
		{name: "length mismatch", prefix: IPCFrameHeaderBytes + 2, header: func(header []byte) {
			header[0], header[1] = IPCProtocolVersionV7, byte(IPCFrameHello)
			binary.BigEndian.PutUint64(header[4:12], 1)
		}, want: ErrIPCFrameInvalid},
	} {
		t.Run(test.name, func(t *testing.T) {
			var input bytes.Buffer
			_ = binary.Write(&input, binary.BigEndian, test.prefix)
			if test.header != nil {
				header := make([]byte, IPCFrameHeaderBytes)
				test.header(header)
				input.Write(header)
			}
			_, err := ReadIPCFrameV7(&input)
			if !errors.Is(err, test.want) {
				t.Fatalf("ReadIPCFrameV7() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestIPCFrameV7RejectsInvalidJSONAndResourcePlacement(t *testing.T) {
	tests := []IPCFrame{
		{Type: IPCFrameHello, RequestID: 1, Metadata: []byte(`{"a":1,"a":2}`)},
		{Type: IPCFrameHello, RequestID: 1, Metadata: []byte(`{"value":1e0}`)},
		{Type: IPCFrameHello, RequestID: 1, ResourceID: 2, Metadata: []byte(`{}`)},
		{Type: IPCFrameIORead, RequestID: 1, Metadata: []byte(`{}`)},
		{Type: IPCFrameType(255), RequestID: 1, Metadata: []byte(`{}`)},
	}
	for index, frame := range tests {
		if err := WriteIPCFrameV7(io.Discard, frame); err == nil {
			t.Fatalf("case %d accepted invalid frame: %#v", index, frame)
		}
	}
}

func TestIPCFrameV7AcceptsSignedSeekOffsetMetadata(t *testing.T) {
	frame := IPCFrame{Type: IPCFrameIOSeek, RequestID: 1, ResourceID: 2, Metadata: []byte(`{"offset":-4096,"whence":2}`)}
	var encoded bytes.Buffer
	if err := WriteIPCFrameV7(&encoded, frame); err != nil {
		t.Fatal(err)
	}
	decoded, err := ReadIPCFrameV7(&encoded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded.Metadata, frame.Metadata) {
		t.Fatalf("metadata = %s, want %s", decoded.Metadata, frame.Metadata)
	}
}

func TestIPCFrameV7MatchesCrossLanguageFixtures(t *testing.T) {
	raw, err := os.ReadFile("../../spec/plugin/ipc-v7-fixtures.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixtures struct {
		SchemaVersion string `json:"schema_version"`
		Frames        []struct {
			Name        string `json:"name"`
			EncodedHex  string `json:"encoded_hex"`
			FrameType   uint8  `json:"frame_type"`
			Flags       uint16 `json:"flags"`
			RequestID   uint64 `json:"request_id"`
			ResourceID  uint64 `json:"resource_id"`
			MetadataHex string `json:"metadata_hex"`
			BodyHex     string `json:"body_hex"`
		} `json:"frames"`
	}
	if err := json.Unmarshal(raw, &fixtures); err != nil {
		t.Fatal(err)
	}
	if fixtures.SchemaVersion != "redevplugin.rust_ipc_v7_fixtures.v1" || len(fixtures.Frames) == 0 {
		t.Fatalf("invalid IPC v7 fixture catalog: %#v", fixtures)
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
			want := IPCFrame{Type: IPCFrameType(fixture.FrameType), Flags: fixture.Flags, RequestID: fixture.RequestID, ResourceID: fixture.ResourceID, Metadata: metadata, Body: body}
			got, err := ReadIPCFrameV7(bytes.NewReader(encoded))
			if err != nil {
				t.Fatal(err)
			}
			if got.Type != want.Type || got.Flags != want.Flags || got.RequestID != want.RequestID || got.ResourceID != want.ResourceID || !bytes.Equal(got.Metadata, want.Metadata) || !bytes.Equal(got.Body, want.Body) {
				t.Fatalf("decoded fixture = %#v, want %#v", got, want)
			}
			var output bytes.Buffer
			if err := WriteIPCFrameV7(&output, want); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(output.Bytes(), encoded) {
				t.Fatalf("encoded fixture = %x, want %x", output.Bytes(), encoded)
			}
		})
	}
}

func FuzzReadIPCFrameV7(f *testing.F) {
	var valid bytes.Buffer
	_ = WriteIPCFrameV7(&valid, IPCFrame{Type: IPCFrameHello, RequestID: 1, Metadata: []byte(`{}`)})
	f.Add(valid.Bytes())
	f.Add([]byte{0, 0, 0, 1, 7})
	f.Fuzz(func(t *testing.T, raw []byte) {
		defer func() {
			if recovered := recover(); recovered != nil {
				t.Fatalf("ReadIPCFrameV7 panicked: %v", recovered)
			}
		}()
		_, _ = ReadIPCFrameV7(bytes.NewReader(raw))
	})
}
