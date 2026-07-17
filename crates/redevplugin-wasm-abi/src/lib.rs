use std::collections::HashMap;
use std::fmt;
use wasmparser::{Encoding, ExternalKind, FuncType, Parser, Payload, RefType, TypeRef, ValType};

pub const WASM_WORKER_ABI_VERSION: &str = "redevplugin-wasm-worker-v2";
pub const EXPORT_MEMORY: &str = "memory";
pub const EXPORT_WORKER_ALLOC: &str = "redevplugin_worker_alloc";
pub const EXPORT_WORKER_DEALLOC: &str = "redevplugin_worker_dealloc";
pub const EXPORT_WORKER_INVOKE: &str = "redevplugin_worker_invoke";
pub const REQUIRED_EXPORT_INVOKE: &str = EXPORT_WORKER_INVOKE;
pub const IMPORT_STORAGE: &str = "redevplugin.storage";
pub const IMPORT_NETWORK: &str = "redevplugin.network";
pub const MAX_TABLE_ELEMENTS: u64 = 65_536;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValueType {
    I32,
    I64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FunctionContract {
    pub export_name: String,
    pub params: Vec<ValueType>,
    pub results: Vec<ValueType>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryContract {
    pub initial_pages: u64,
    pub maximum_pages: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostcallImport {
    pub module: String,
    pub name: String,
    pub params: Vec<ValueType>,
    pub results: Vec<ValueType>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedWorkerModule {
    pub byte_len: usize,
    pub memory: MemoryContract,
    pub alloc_export: FunctionContract,
    pub dealloc_export: FunctionContract,
    pub invoke_export: FunctionContract,
    pub imports: Vec<HostcallImport>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationErrorCategory {
    InvalidModule,
    UnsupportedImport,
    InvalidMemory,
    InvalidTable,
    MissingExport,
    InvalidSignature,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationError {
    category: ValidationErrorCategory,
    message: String,
}

impl ValidationError {
    pub fn category(&self) -> ValidationErrorCategory {
        self.category
    }

    fn new(category: ValidationErrorCategory, message: impl Into<String>) -> Self {
        Self {
            category,
            message: message.into(),
        }
    }
}

impl fmt::Display for ValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for ValidationError {}

pub fn validate_worker_module(bytes: &[u8]) -> Result<ValidatedWorkerModule, ValidationError> {
    wasmparser::Validator::new()
        .validate_all(bytes)
        .map_err(|err| invalid_module(format!("wasm validation failed: {err}")))?;

    let mut types = Vec::new();
    let mut function_type_indices = Vec::new();
    let mut imported_function_type_indices = Vec::new();
    let mut imports = Vec::new();
    let mut memories = Vec::new();
    let mut table_count = 0_u32;
    let mut exports = HashMap::new();

    for payload in Parser::new(0).parse_all(bytes) {
        match payload.map_err(|err| invalid_module(format!("parse wasm module: {err}")))? {
            Payload::Version { encoding, .. } if encoding != Encoding::Module => {
                return Err(invalid_module(
                    "worker artifact must be a core WebAssembly module",
                ));
            }
            Payload::TypeSection(reader) => {
                for function_type in reader.into_iter_err_on_gc_types() {
                    types.push(function_type.map_err(|err| {
                        invalid_module(format!("parse wasm function type: {err}"))
                    })?);
                }
            }
            Payload::ImportSection(reader) => {
                for imported in reader {
                    let imported = imported
                        .map_err(|err| invalid_module(format!("parse wasm import: {err}")))?;
                    let TypeRef::Func(type_index) = imported.ty else {
                        return Err(ValidationError::new(
                            ValidationErrorCategory::UnsupportedImport,
                            format!(
                                "worker import {}/{} must be a function",
                                imported.module, imported.name
                            ),
                        ));
                    };
                    let function_type = types.get(type_index as usize).ok_or_else(|| {
                        invalid_module(format!(
                            "worker import {}/{} references missing type {type_index}",
                            imported.module, imported.name
                        ))
                    })?;
                    require_hostcall(imported.module, imported.name, function_type)?;
                    let (params, results) = function_contract_types(function_type)?;
                    imports.push(HostcallImport {
                        module: imported.module.to_string(),
                        name: imported.name.to_string(),
                        params,
                        results,
                    });
                    imported_function_type_indices.push(type_index);
                }
            }
            Payload::FunctionSection(reader) => {
                for type_index in reader {
                    function_type_indices
                        .push(type_index.map_err(|err| {
                            invalid_module(format!("parse wasm function: {err}"))
                        })?);
                }
            }
            Payload::TableSection(reader) => {
                for table in reader {
                    let table =
                        table.map_err(|err| invalid_module(format!("parse wasm table: {err}")))?;
                    table_count += 1;
                    if table_count > 1 {
                        return Err(ValidationError::new(
                            ValidationErrorCategory::InvalidTable,
                            "worker must define at most one table",
                        ));
                    }
                    if table.ty.table64
                        || table.ty.shared
                        || !matches!(table.ty.element_type, RefType::FUNCREF | RefType::EXTERNREF)
                        || table.ty.initial > MAX_TABLE_ELEMENTS
                        || table
                            .ty
                            .maximum
                            .is_some_and(|maximum| maximum > MAX_TABLE_ELEMENTS)
                    {
                        return Err(ValidationError::new(
                            ValidationErrorCategory::InvalidTable,
                            "worker table contract is unsupported",
                        ));
                    }
                }
            }
            Payload::MemorySection(reader) => {
                for memory in reader {
                    let memory = memory
                        .map_err(|err| invalid_module(format!("parse wasm memory: {err}")))?;
                    memories.push(memory);
                }
            }
            Payload::ExportSection(reader) => {
                for exported in reader {
                    let exported = exported
                        .map_err(|err| invalid_module(format!("parse wasm export: {err}")))?;
                    if exports
                        .insert(exported.name.to_string(), (exported.kind, exported.index))
                        .is_some()
                    {
                        return Err(invalid_module(format!(
                            "worker export {:?} is duplicated",
                            exported.name
                        )));
                    }
                }
            }
            _ => {}
        }
    }

    if memories.len() != 1 {
        return Err(ValidationError::new(
            ValidationErrorCategory::InvalidMemory,
            format!(
                "worker must define exactly one linear memory, found {}",
                memories.len()
            ),
        ));
    }
    let memory = memories[0];
    if memory.memory64 || memory.shared || memory.page_size_log2.is_some() {
        return Err(ValidationError::new(
            ValidationErrorCategory::InvalidMemory,
            "worker memory must be an unshared 32-bit memory with standard pages",
        ));
    }
    match exports.get(EXPORT_MEMORY) {
        Some((ExternalKind::Memory, 0)) => {}
        _ => {
            return Err(ValidationError::new(
                ValidationErrorCategory::MissingExport,
                "worker must export its only linear memory as \"memory\"",
            ));
        }
    }

    let alloc_export = require_function_export(
        EXPORT_WORKER_ALLOC,
        &[ValueType::I32],
        &[ValueType::I32],
        &exports,
        &types,
        &imported_function_type_indices,
        &function_type_indices,
    )?;
    let dealloc_export = require_function_export(
        EXPORT_WORKER_DEALLOC,
        &[ValueType::I32, ValueType::I32],
        &[],
        &exports,
        &types,
        &imported_function_type_indices,
        &function_type_indices,
    )?;
    let invoke_export = require_function_export(
        EXPORT_WORKER_INVOKE,
        &[ValueType::I32, ValueType::I32],
        &[ValueType::I64],
        &exports,
        &types,
        &imported_function_type_indices,
        &function_type_indices,
    )?;

    Ok(ValidatedWorkerModule {
        byte_len: bytes.len(),
        memory: MemoryContract {
            initial_pages: memory.initial,
            maximum_pages: memory.maximum,
        },
        alloc_export,
        dealloc_export,
        invoke_export,
        imports,
    })
}

fn require_hostcall(
    module: &str,
    name: &str,
    function_type: &FuncType,
) -> Result<(), ValidationError> {
    let allowed = matches!(
        (module, name),
        (IMPORT_STORAGE, "files" | "kv" | "sqlite") | (IMPORT_NETWORK, "execute")
    );
    if !allowed {
        return Err(ValidationError::new(
            ValidationErrorCategory::UnsupportedImport,
            format!("worker import {module}/{name} is unsupported"),
        ));
    }
    let (params, results) = function_contract_types(function_type)?;
    if params != [ValueType::I32; 4] || results != [ValueType::I32] {
        return Err(ValidationError::new(
            ValidationErrorCategory::InvalidSignature,
            format!("worker import {module}/{name} has an invalid function signature"),
        ));
    }
    Ok(())
}

fn require_function_export(
    name: &str,
    expected_params: &[ValueType],
    expected_results: &[ValueType],
    exports: &HashMap<String, (ExternalKind, u32)>,
    types: &[FuncType],
    imported_function_type_indices: &[u32],
    function_type_indices: &[u32],
) -> Result<FunctionContract, ValidationError> {
    let Some((ExternalKind::Func, function_index)) = exports.get(name).copied() else {
        return Err(ValidationError::new(
            ValidationErrorCategory::MissingExport,
            format!("required function export {name:?} is missing"),
        ));
    };
    let type_index =
        if let Some(type_index) = imported_function_type_indices.get(function_index as usize) {
            *type_index
        } else {
            let defined_index = function_index as usize - imported_function_type_indices.len();
            *function_type_indices.get(defined_index).ok_or_else(|| {
                invalid_module(format!(
                    "function export {name:?} references missing function {function_index}"
                ))
            })?
        };
    let function_type = types.get(type_index as usize).ok_or_else(|| {
        invalid_module(format!(
            "function export {name:?} references missing type {type_index}"
        ))
    })?;
    let (params, results) = function_contract_types(function_type)?;
    if params != expected_params || results != expected_results {
        return Err(ValidationError::new(
            ValidationErrorCategory::InvalidSignature,
            format!("worker export {name:?} has an invalid function signature"),
        ));
    }
    Ok(FunctionContract {
        export_name: name.to_string(),
        params,
        results,
    })
}

fn function_contract_types(
    function_type: &FuncType,
) -> Result<(Vec<ValueType>, Vec<ValueType>), ValidationError> {
    let params = function_type
        .params()
        .iter()
        .map(value_type)
        .collect::<Result<Vec<_>, _>>()?;
    let results = function_type
        .results()
        .iter()
        .map(value_type)
        .collect::<Result<Vec<_>, _>>()?;
    Ok((params, results))
}

fn value_type(value: &ValType) -> Result<ValueType, ValidationError> {
    match value {
        ValType::I32 => Ok(ValueType::I32),
        ValType::I64 => Ok(ValueType::I64),
        _ => Err(ValidationError::new(
            ValidationErrorCategory::InvalidSignature,
            format!("worker ABI function uses unsupported value type {value}"),
        )),
    }
}

fn invalid_module(message: impl Into<String>) -> ValidationError {
    ValidationError::new(ValidationErrorCategory::InvalidModule, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_complete_worker_contract() {
        let module = wat::parse_str(valid_worker_wat()).expect("compile valid worker");
        let validated = validate_worker_module(&module).expect("validate worker module");
        assert_eq!(validated.byte_len, module.len());
        assert_eq!(validated.memory.initial_pages, 1);
        assert_eq!(validated.alloc_export.export_name, EXPORT_WORKER_ALLOC);
        assert_eq!(validated.dealloc_export.export_name, EXPORT_WORKER_DEALLOC);
        assert_eq!(validated.invoke_export.export_name, EXPORT_WORKER_INVOKE);
        assert_eq!(validated.imports.len(), 2);
    }

    #[test]
    fn rejects_missing_memory_export() {
        let module = wat::parse_str(valid_worker_wat().replace("(export \"memory\")", ""))
            .expect("compile worker");
        let error = validate_worker_module(&module).expect_err("missing memory export");
        assert_eq!(error.category(), ValidationErrorCategory::MissingExport);
    }

    #[test]
    fn rejects_invalid_required_export_signatures() {
        for (name, replacement) in [
            (
                "alloc",
                "(func (export \"redevplugin_worker_alloc\") (param i64) (result i32) i32.const 0)",
            ),
            (
                "dealloc",
                "(func (export \"redevplugin_worker_dealloc\") (param i32))",
            ),
            (
                "invoke",
                "(func (export \"redevplugin_worker_invoke\") (param i32 i32) (result i32) i32.const 0)",
            ),
        ] {
            let source = valid_worker_wat();
            let invalid = match name {
                "alloc" => source.replace(
                    "(func (export \"redevplugin_worker_alloc\") (param i32) (result i32) i32.const 0)",
                    replacement,
                ),
                "dealloc" => source.replace(
                    "(func (export \"redevplugin_worker_dealloc\") (param i32 i32))",
                    replacement,
                ),
                _ => source.replace(
                    "(func (export \"redevplugin_worker_invoke\") (param i32 i32) (result i64) i64.const 0)",
                    replacement,
                ),
            };
            let module = wat::parse_str(invalid).expect("compile invalid-signature worker");
            let error = validate_worker_module(&module).expect_err(name);
            assert_eq!(error.category(), ValidationErrorCategory::InvalidSignature);
        }
    }

    #[test]
    fn rejects_unsupported_or_mistyped_imports() {
        for import in [
            "(import \"wasi_snapshot_preview1\" \"fd_write\" (func (param i32 i32 i32 i32) (result i32)))",
            "(import \"redevplugin.storage\" \"files\" (func (param i32) (result i32)))",
            "(import \"redevplugin.storage\" \"memory\" (memory 1))",
        ] {
            let source = valid_worker_wat().replace(
                "(import \"redevplugin.storage\" \"files\" (func (param i32 i32 i32 i32) (result i32)))",
                import,
            );
            let module = wat::parse_str(source).expect("compile worker with invalid import");
            assert!(
                validate_worker_module(&module).is_err(),
                "accepted {import}"
            );
        }
    }

    #[test]
    fn rejects_invalid_memory_and_table_contracts() {
        for replacement in [
            "(memory (export \"memory\") i64 1)",
            "(memory (export \"memory\") 1 2 shared)",
            "(memory (export \"memory\") 1) (memory 1)",
            "(memory (export \"memory\") 1) (table 65537 funcref)",
            "(memory (export \"memory\") 1) (table 1 funcref) (table 1 funcref)",
        ] {
            let source = valid_worker_wat().replace("(memory (export \"memory\") 1)", replacement);
            let module = wat::parse_str(source).expect("compile worker with invalid resources");
            assert!(
                validate_worker_module(&module).is_err(),
                "accepted {replacement}"
            );
        }
    }

    #[test]
    fn rejects_shared_invalid_opcode_fixture() {
        let module = decode_hex(include_str!(
            "../../../testdata/contracts/wasm/invalid-final-opcode.hex"
        ));
        let error = validate_worker_module(&module).expect_err("invalid opcode");
        assert_eq!(error.category(), ValidationErrorCategory::InvalidModule);
    }

    #[test]
    fn rejects_shared_table_maximum_fixture() {
        let module = decode_hex(include_str!(
            "../../../testdata/contracts/wasm/table-maximum-exceeds-limit.hex"
        ));
        let error = validate_worker_module(&module).expect_err("table maximum above limit");
        assert_eq!(error.category(), ValidationErrorCategory::InvalidTable);
    }

    fn valid_worker_wat() -> &'static str {
        r#"(module
            (import "redevplugin.storage" "files" (func (param i32 i32 i32 i32) (result i32)))
            (import "redevplugin.network" "execute" (func (param i32 i32 i32 i32) (result i32)))
            (memory (export "memory") 1)
            (func (export "redevplugin_worker_alloc") (param i32) (result i32) i32.const 0)
            (func (export "redevplugin_worker_dealloc") (param i32 i32))
            (func (export "redevplugin_worker_invoke") (param i32 i32) (result i64) i64.const 0)
        )"#
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
}
