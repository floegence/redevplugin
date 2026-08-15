#![allow(
    dead_code,
    reason = "wired into the runtime process after codec contract tests"
)]

use serde::de::{DeserializeSeed, MapAccess, SeqAccess, Visitor};
use std::collections::HashSet;
use std::fmt;
use std::io::{Read, Write};

pub const PROTOCOL_VERSION: u8 = 7;
pub const HEADER_BYTES: u32 = 28;
pub const CONTROL_METADATA_MAX: u32 = 64 * 1024;
pub const INVOKE_METADATA_MAX: u32 = 1024 * 1024;
pub const BODY_MAX: u32 = 64 * 1024;
pub const FRAME_MAX: u32 = HEADER_BYTES + INVOKE_METADATA_MAX + BODY_MAX;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FrameType {
    Hello = 1,
    HelloAck = 2,
    Heartbeat = 3,
    Invoke = 4,
    InvokeResult = 5,
    CancelInvoke = 6,
    CancelAck = 7,
    Hostcall = 8,
    HostcallResult = 9,
    IoRead = 10,
    IoReadResult = 11,
    IoWrite = 12,
    IoWriteResult = 13,
    IoSeek = 14,
    IoSeekResult = 15,
    IoClose = 16,
    IoCloseResult = 17,
    ExecutionEvent = 18,
    RevokePlugin = 19,
    RevokeSession = 20,
    Diagnostic = 21,
}

impl TryFrom<u8> for FrameType {
    type Error = CodecError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Hello),
            2 => Ok(Self::HelloAck),
            3 => Ok(Self::Heartbeat),
            4 => Ok(Self::Invoke),
            5 => Ok(Self::InvokeResult),
            6 => Ok(Self::CancelInvoke),
            7 => Ok(Self::CancelAck),
            8 => Ok(Self::Hostcall),
            9 => Ok(Self::HostcallResult),
            10 => Ok(Self::IoRead),
            11 => Ok(Self::IoReadResult),
            12 => Ok(Self::IoWrite),
            13 => Ok(Self::IoWriteResult),
            14 => Ok(Self::IoSeek),
            15 => Ok(Self::IoSeekResult),
            16 => Ok(Self::IoClose),
            17 => Ok(Self::IoCloseResult),
            18 => Ok(Self::ExecutionEvent),
            19 => Ok(Self::RevokePlugin),
            20 => Ok(Self::RevokeSession),
            21 => Ok(Self::Diagnostic),
            _ => Err(CodecError::Protocol("unknown frame type")),
        }
    }
}

impl FrameType {
    fn uses_resource(self) -> bool {
        matches!(
            self,
            Self::IoRead
                | Self::IoReadResult
                | Self::IoWrite
                | Self::IoWriteResult
                | Self::IoSeek
                | Self::IoSeekResult
                | Self::IoClose
                | Self::IoCloseResult
        )
    }

    fn metadata_limit(self) -> u32 {
        if matches!(self, Self::Invoke | Self::InvokeResult) {
            INVOKE_METADATA_MAX
        } else {
            CONTROL_METADATA_MAX
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub frame_type: FrameType,
    pub flags: u16,
    pub request_id: u64,
    pub resource_id: u64,
    pub metadata: Vec<u8>,
    pub body: Vec<u8>,
}

#[derive(Debug)]
pub enum CodecError {
    Io(std::io::Error),
    Invalid(&'static str),
    TooLarge,
    Protocol(&'static str),
}

impl fmt::Display for CodecError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "IPC I/O: {error}"),
            Self::Invalid(message) => write!(formatter, "invalid rust IPC v7 frame: {message}"),
            Self::TooLarge => formatter.write_str("rust IPC v7 frame exceeds limit"),
            Self::Protocol(message) => {
                write!(formatter, "rust IPC v7 protocol violation: {message}")
            }
        }
    }
}

impl std::error::Error for CodecError {}

impl From<std::io::Error> for CodecError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

fn validate_frame(frame: &Frame) -> Result<(), CodecError> {
    if frame.request_id == 0 {
        return Err(CodecError::Protocol("request_id 0 is reserved"));
    }
    if frame.frame_type.uses_resource() != (frame.resource_id != 0) {
        return Err(CodecError::Protocol("resource_id placement is invalid"));
    }
    if frame.metadata.len() > frame.frame_type.metadata_limit() as usize
        || frame.body.len() > BODY_MAX as usize
    {
        return Err(CodecError::TooLarge);
    }
    validate_metadata(&frame.metadata)
}

pub fn write_frame(writer: &mut impl Write, frame: &Frame) -> Result<(), CodecError> {
    validate_frame(frame)?;
    let metadata_len = u32::try_from(frame.metadata.len()).map_err(|_| CodecError::TooLarge)?;
    let body_len = u32::try_from(frame.body.len()).map_err(|_| CodecError::TooLarge)?;
    let frame_len = HEADER_BYTES
        .checked_add(metadata_len)
        .and_then(|value| value.checked_add(body_len))
        .ok_or(CodecError::TooLarge)?;
    writer.write_all(&frame_len.to_be_bytes())?;
    writer.write_all(&[PROTOCOL_VERSION, frame.frame_type as u8])?;
    writer.write_all(&frame.flags.to_be_bytes())?;
    writer.write_all(&frame.request_id.to_be_bytes())?;
    writer.write_all(&frame.resource_id.to_be_bytes())?;
    writer.write_all(&metadata_len.to_be_bytes())?;
    writer.write_all(&body_len.to_be_bytes())?;
    writer.write_all(&frame.metadata)?;
    writer.write_all(&frame.body)?;
    Ok(())
}

pub fn read_frame(reader: &mut impl Read) -> Result<Frame, CodecError> {
    let frame_len = read_u32(reader)?;
    if frame_len < HEADER_BYTES {
        return Err(CodecError::Invalid("frame length is shorter than header"));
    }
    if frame_len > FRAME_MAX {
        return Err(CodecError::TooLarge);
    }
    let mut header = [0_u8; HEADER_BYTES as usize];
    reader.read_exact(&mut header)?;
    if header[0] != PROTOCOL_VERSION {
        return Err(CodecError::Protocol("protocol version is unsupported"));
    }
    let frame_type = FrameType::try_from(header[1])?;
    let flags = u16::from_be_bytes(header[2..4].try_into().expect("fixed header range"));
    let request_id = u64::from_be_bytes(header[4..12].try_into().expect("fixed header range"));
    let resource_id = u64::from_be_bytes(header[12..20].try_into().expect("fixed header range"));
    let metadata_len = u32::from_be_bytes(header[20..24].try_into().expect("fixed header range"));
    let body_len = u32::from_be_bytes(header[24..28].try_into().expect("fixed header range"));
    if metadata_len > frame_type.metadata_limit() || body_len > BODY_MAX {
        return Err(CodecError::TooLarge);
    }
    let components = HEADER_BYTES
        .checked_add(metadata_len)
        .and_then(|value| value.checked_add(body_len))
        .ok_or(CodecError::TooLarge)?;
    if components != frame_len {
        return Err(CodecError::Invalid(
            "component lengths do not match frame length",
        ));
    }
    let mut metadata = vec![0; metadata_len as usize];
    let mut body = vec![0; body_len as usize];
    reader.read_exact(&mut metadata)?;
    reader.read_exact(&mut body)?;
    let frame = Frame {
        frame_type,
        flags,
        request_id,
        resource_id,
        metadata,
        body,
    };
    validate_frame(&frame)?;
    Ok(frame)
}

fn read_u32(reader: &mut impl Read) -> Result<u32, CodecError> {
    let mut bytes = [0_u8; 4];
    reader.read_exact(&mut bytes)?;
    Ok(u32::from_be_bytes(bytes))
}

fn validate_metadata(raw: &[u8]) -> Result<(), CodecError> {
    if raw.is_empty() {
        return Ok(());
    }
    let input =
        std::str::from_utf8(raw).map_err(|_| CodecError::Invalid("metadata is not UTF-8"))?;
    let mut deserializer = serde_json::Deserializer::from_str(input);
    StrictJsonSeed { depth: 0, nodes: 0 }
        .deserialize(&mut deserializer)
        .map_err(|_| CodecError::Invalid("metadata JSON is invalid"))?;
    deserializer
        .end()
        .map_err(|_| CodecError::Invalid("metadata JSON has trailing values"))?;
    Ok(())
}

struct StrictJsonSeed {
    depth: usize,
    nodes: usize,
}

impl<'de> DeserializeSeed<'de> for StrictJsonSeed {
    type Value = usize;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        if self.depth > 64 || self.nodes >= 100_000 {
            return Err(serde::de::Error::custom("JSON structural limit exceeded"));
        }
        deserializer.deserialize_any(StrictJsonVisitor {
            depth: self.depth,
            nodes: self.nodes + 1,
        })
    }
}

struct StrictJsonVisitor {
    depth: usize,
    nodes: usize,
}

impl<'de> Visitor<'de> for StrictJsonVisitor {
    type Value = usize;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("canonical JSON")
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(self.nodes)
    }

    fn visit_bool<E>(self, _: bool) -> Result<Self::Value, E> {
        Ok(self.nodes)
    }

    fn visit_u64<E>(self, _: u64) -> Result<Self::Value, E> {
        Ok(self.nodes)
    }

    fn visit_i64<E>(self, _: i64) -> Result<Self::Value, E> {
        Ok(self.nodes)
    }

    fn visit_f64<E>(self, _: f64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Err(E::custom("floating JSON numbers are not canonical"))
    }

    fn visit_str<E>(self, _: &str) -> Result<Self::Value, E> {
        Ok(self.nodes)
    }

    fn visit_string<E>(self, _: String) -> Result<Self::Value, E> {
        Ok(self.nodes)
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(self.nodes)
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        StrictJsonSeed {
            depth: self.depth + 1,
            nodes: self.nodes,
        }
        .deserialize(deserializer)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut nodes = self.nodes;
        while let Some(next) = sequence.next_element_seed(StrictJsonSeed {
            depth: self.depth + 1,
            nodes,
        })? {
            nodes = next;
        }
        Ok(nodes)
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut keys = HashSet::new();
        let mut nodes = self.nodes;
        while let Some(key) = map.next_key::<String>()? {
            if !keys.insert(key) {
                return Err(serde::de::Error::custom("duplicate JSON field"));
            }
            nodes = map.next_value_seed(StrictJsonSeed {
                depth: self.depth + 1,
                nodes,
            })?;
        }
        Ok(nodes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Deserialize)]
    struct FixtureCatalog {
        schema_version: String,
        frames: Vec<FrameFixture>,
    }

    #[derive(Deserialize)]
    struct FrameFixture {
        name: String,
        encoded_hex: String,
        frame_type: u8,
        flags: u16,
        request_id: u64,
        resource_id: u64,
        metadata_hex: String,
        body_hex: String,
    }

    #[test]
    fn frame_round_trip_preserves_raw_body() {
        let body: Vec<u8> = (0..BODY_MAX).map(|index| (index % 251) as u8).collect();
        let want = Frame {
            frame_type: FrameType::IoReadResult,
            flags: 5,
            request_id: 42,
            resource_id: 99,
            metadata: br#"{"ok":true}"#.to_vec(),
            body,
        };
        let mut encoded = Vec::new();
        write_frame(&mut encoded, &want).unwrap();
        assert!(!encoded.windows(11).any(|window| window == b"body_base64"));
        let got = read_frame(&mut encoded.as_slice()).unwrap();
        assert_eq!(got, want);
    }

    #[test]
    fn frame_specific_metadata_limits_are_enforced() {
        let mut metadata = br#"{"value":""#.to_vec();
        metadata.extend(std::iter::repeat_n(b'a', 80 * 1024));
        metadata.extend_from_slice(br#""}"#);
        let mut frame = Frame {
            frame_type: FrameType::Invoke,
            flags: 0,
            request_id: 1,
            resource_id: 0,
            metadata,
            body: Vec::new(),
        };
        write_frame(&mut Vec::new(), &frame).unwrap();
        frame.frame_type = FrameType::Hostcall;
        assert!(matches!(
            write_frame(&mut Vec::new(), &frame),
            Err(CodecError::TooLarge)
        ));
    }

    #[test]
    fn invalid_metadata_and_resource_placement_are_rejected() {
        for metadata in [br#"{"a":1,"a":2}"#.as_slice(), br#"{"value":1e0}"#] {
            let frame = Frame {
                frame_type: FrameType::Hello,
                flags: 0,
                request_id: 1,
                resource_id: 0,
                metadata: metadata.to_vec(),
                body: Vec::new(),
            };
            assert!(write_frame(&mut Vec::new(), &frame).is_err());
        }
        let frame = Frame {
            frame_type: FrameType::IoRead,
            flags: 0,
            request_id: 1,
            resource_id: 0,
            metadata: br#"{}"#.to_vec(),
            body: Vec::new(),
        };
        assert!(write_frame(&mut Vec::new(), &frame).is_err());
    }

    #[test]
    fn signed_seek_offset_metadata_is_accepted() {
        let frame = Frame {
            frame_type: FrameType::IoSeek,
            flags: 0,
            request_id: 1,
            resource_id: 2,
            metadata: br#"{"offset":-4096,"whence":2}"#.to_vec(),
            body: Vec::new(),
        };
        let mut encoded = Vec::new();
        write_frame(&mut encoded, &frame).unwrap();
        assert_eq!(read_frame(&mut encoded.as_slice()).unwrap(), frame);
    }

    #[test]
    fn matches_cross_language_fixtures() {
        let catalog: FixtureCatalog =
            serde_json::from_str(include_str!("../../../spec/plugin/ipc-v7-fixtures.json"))
                .unwrap();
        assert_eq!(
            catalog.schema_version,
            "redevplugin.rust_ipc_v7_fixtures.v1"
        );
        assert!(!catalog.frames.is_empty());
        for fixture in catalog.frames {
            let encoded = decode_hex(&fixture.encoded_hex);
            let expected = Frame {
                frame_type: FrameType::try_from(fixture.frame_type).unwrap(),
                flags: fixture.flags,
                request_id: fixture.request_id,
                resource_id: fixture.resource_id,
                metadata: decode_hex(&fixture.metadata_hex),
                body: decode_hex(&fixture.body_hex),
            };
            let decoded = read_frame(&mut encoded.as_slice())
                .unwrap_or_else(|error| panic!("decode fixture {}: {error}", fixture.name));
            assert_eq!(decoded, expected, "fixture {}", fixture.name);
            let mut output = Vec::new();
            write_frame(&mut output, &expected)
                .unwrap_or_else(|error| panic!("encode fixture {}: {error}", fixture.name));
            assert_eq!(output, encoded, "fixture {}", fixture.name);
        }
    }

    fn decode_hex(value: &str) -> Vec<u8> {
        assert_eq!(value.len() % 2, 0);
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                let text = std::str::from_utf8(pair).unwrap();
                u8::from_str_radix(text, 16).unwrap()
            })
            .collect()
    }

    #[test]
    fn malformed_length_is_rejected_before_payload_allocation() {
        assert!(matches!(
            read_frame(&mut (HEADER_BYTES - 1).to_be_bytes().as_slice()),
            Err(CodecError::Invalid(_))
        ));
        assert!(matches!(
            read_frame(&mut (FRAME_MAX + 1).to_be_bytes().as_slice()),
            Err(CodecError::TooLarge)
        ));
    }
}
