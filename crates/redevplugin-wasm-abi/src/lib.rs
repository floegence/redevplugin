pub const WASM_WORKER_ABI_VERSION: &str = "redevplugin-wasm-worker-v2";
pub const EXPORT_WORKER_INVOKE: &str = "redevplugin_worker_invoke";
pub const REQUIRED_EXPORT_INVOKE: &str = "redevplugin_worker_invoke";
pub const IMPORT_STORAGE: &str = "redevplugin.storage";
pub const IMPORT_NETWORK: &str = "redevplugin.network";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedWorkerModule {
    pub byte_len: usize,
    pub export_name: String,
}

pub fn validate_worker_module(
    bytes: &[u8],
    required_export: &str,
) -> Result<ValidatedWorkerModule, String> {
    wasmparser::Validator::new()
        .validate_all(bytes)
        .map_err(|err| format!("wasm validation failed: {err}"))?;
    if bytes.len() < 8 {
        return Err("wasm module is too small".to_string());
    }
    if &bytes[0..4] != b"\0asm" {
        return Err("wasm magic header is invalid".to_string());
    }
    if bytes[4..8] != [0x01, 0x00, 0x00, 0x00] {
        return Err("wasm version must be 1".to_string());
    }
    let required_export = required_export.trim();
    if required_export.is_empty() {
        return Err("required export is empty".to_string());
    }
    let mut cursor = 8;
    let mut found_export = false;
    while cursor < bytes.len() {
        let section_id = bytes[cursor];
        cursor += 1;
        let section_len = read_u32_leb(bytes, &mut cursor)? as usize;
        let section_end = cursor
            .checked_add(section_len)
            .ok_or_else(|| "wasm section length overflows".to_string())?;
        if section_end > bytes.len() {
            return Err("wasm section length exceeds module size".to_string());
        }
        if section_id == 7 {
            found_export = parse_export_section(&bytes[cursor..section_end], required_export)?;
        }
        cursor = section_end;
    }
    if !found_export {
        return Err(format!(
            "required function export {required_export:?} is missing"
        ));
    }
    Ok(ValidatedWorkerModule {
        byte_len: bytes.len(),
        export_name: required_export.to_string(),
    })
}

fn parse_export_section(section: &[u8], required_export: &str) -> Result<bool, String> {
    let mut cursor = 0;
    let count = read_u32_leb(section, &mut cursor)? as usize;
    let mut found = false;
    for _ in 0..count {
        let name_len = read_u32_leb(section, &mut cursor)? as usize;
        let name_end = cursor
            .checked_add(name_len)
            .ok_or_else(|| "wasm export name length overflows".to_string())?;
        if name_end > section.len() {
            return Err("wasm export name exceeds section size".to_string());
        }
        let name = std::str::from_utf8(&section[cursor..name_end])
            .map_err(|_| "wasm export name is not utf-8".to_string())?;
        cursor = name_end;
        if cursor >= section.len() {
            return Err("wasm export entry is missing kind".to_string());
        }
        let kind = section[cursor];
        cursor += 1;
        let _index = read_u32_leb(section, &mut cursor)?;
        if name == required_export {
            if kind != 0 {
                return Err(format!(
                    "required export {required_export:?} must be a function"
                ));
            }
            found = true;
        }
    }
    if cursor != section.len() {
        return Err("wasm export section has trailing bytes".to_string());
    }
    Ok(found)
}

fn read_u32_leb(bytes: &[u8], cursor: &mut usize) -> Result<u32, String> {
    let mut result: u32 = 0;
    let mut shift = 0;
    for _ in 0..5 {
        if *cursor >= bytes.len() {
            return Err("unexpected end of wasm leb128 value".to_string());
        }
        let byte = bytes[*cursor];
        *cursor += 1;
        result |= ((byte & 0x7f) as u32) << shift;
        if byte & 0x80 == 0 {
            return Ok(result);
        }
        shift += 7;
    }
    Err("wasm leb128 value is too large".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_minimal_worker_module() {
        let module = minimal_worker_wasm(REQUIRED_EXPORT_INVOKE);
        let validated =
            validate_worker_module(&module, REQUIRED_EXPORT_INVOKE).expect("valid worker module");
        assert_eq!(validated.byte_len, module.len());
        assert_eq!(validated.export_name, REQUIRED_EXPORT_INVOKE);
    }

    #[test]
    fn rejects_missing_required_export() {
        let module = minimal_worker_wasm("other_export");
        let err = validate_worker_module(&module, REQUIRED_EXPORT_INVOKE)
            .expect_err("missing required export");
        assert!(err.contains("required function export"));
    }

    #[test]
    fn rejects_non_wasm_bytes() {
        let err =
            validate_worker_module(b"not wasm", REQUIRED_EXPORT_INVOKE).expect_err("invalid magic");
        assert!(err.contains("magic"));
    }

    #[test]
    fn rejects_shared_invalid_opcode_fixture() {
        let module = decode_hex(include_str!(
            "../../../testdata/contracts/wasm/invalid-final-opcode.hex"
        ));
        let err = validate_worker_module(&module, REQUIRED_EXPORT_INVOKE)
            .expect_err("invalid function opcode must fail validation");
        assert!(err.contains("validation"), "{err}");
    }

    fn decode_hex(input: &str) -> Vec<u8> {
        let input = input.trim().as_bytes();
        assert_eq!(input.len() % 2, 0);
        input
            .chunks_exact(2)
            .map(|pair| {
                let text = std::str::from_utf8(pair).expect("hex fixture is UTF-8");
                u8::from_str_radix(text, 16).expect("hex fixture byte")
            })
            .collect()
    }

    fn minimal_worker_wasm(export_name: &str) -> Vec<u8> {
        let export_name_bytes = export_name.as_bytes();
        let mut module = vec![
            0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01, 0x04, 0x01, 0x60, 0x00, 0x00,
            0x03, 0x02, 0x01, 0x00, 0x07,
        ];
        let mut export_payload = vec![0x01, export_name_bytes.len() as u8];
        export_payload.extend_from_slice(export_name_bytes);
        export_payload.extend_from_slice(&[0x00, 0x00]);
        module.push(export_payload.len() as u8);
        module.extend_from_slice(&export_payload);
        module.extend_from_slice(&[0x0a, 0x04, 0x01, 0x02, 0x00, 0x0b]);
        module
    }
}
