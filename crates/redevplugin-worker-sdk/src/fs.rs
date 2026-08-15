use crate::api;
use crate::error::{Error, ErrorCode, Result};
use crate::resource::{Handle, IO_FLAG_EOF, MAX_IO_CHUNK_BYTES};
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};

static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(1);
const ATOMIC_TEMP_ATTEMPTS: usize = 16;

#[derive(Debug, Clone, Default, Serialize)]
pub struct OpenOptions {
    pub read: bool,
    pub write: bool,
    pub create: bool,
    pub create_new: bool,
    pub truncate: bool,
    pub append: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mode: Option<u32>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct FileStat {
    pub uri: String,
    pub kind: FileKind,
    pub size: u64,
    pub mode: u32,
    pub modified_unix_ms: i64,
    #[serde(default)]
    pub created_unix_ms: Option<i64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileKind {
    File,
    Directory,
    Symlink,
    Other,
    #[serde(other)]
    Unknown,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DirectoryEntry {
    pub name: String,
    pub uri: String,
    pub kind: FileKind,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DirectoryPage {
    #[serde(default)]
    pub entries: Vec<DirectoryEntry>,
    pub eof: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct WatchEvent {
    pub sequence: u64,
    pub kind: WatchKind,
    pub uri: String,
    #[serde(default)]
    pub previous_uri: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WatchKind {
    Create,
    Change,
    Delete,
    Rename,
    Overflow,
    #[serde(other)]
    Unknown,
}

#[derive(Debug, Clone, Deserialize)]
pub struct MountInfo {
    pub id: String,
    pub uri: String,
    pub read_only: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Mounts {
    #[serde(default)]
    pub mounts: Vec<MountInfo>,
}

#[derive(Deserialize)]
struct HandleResult {
    handle: u64,
}

#[derive(Serialize)]
struct URIArguments<'a> {
    uri: &'a str,
}

pub struct File {
    handle: Handle,
}

impl File {
    pub fn open(uri: &str, options: OpenOptions) -> Result<Self> {
        #[derive(Serialize)]
        struct Arguments<'a> {
            uri: &'a str,
            options: OpenOptions,
        }
        let opened: HandleResult = api::call("fs.open", &Arguments { uri, options })?;
        Ok(Self {
            handle: Handle::new(opened.handle)?,
        })
    }

    pub fn read(&mut self, capacity: usize) -> Result<(Vec<u8>, u32)> {
        self.handle.read(capacity)
    }

    pub fn write_all(&mut self, bytes: &[u8]) -> Result<()> {
        for chunk in bytes.chunks(MAX_IO_CHUNK_BYTES) {
            self.handle.write(chunk, 0)?;
        }
        Ok(())
    }

    pub fn seek(&mut self, offset: i64, whence: u32) -> Result<u64> {
        self.handle.seek(offset, whence)
    }

    pub fn sync(&mut self) -> Result<()> {
        #[derive(Serialize)]
        struct Arguments {
            handle: u64,
        }
        let _: serde_json::Value = api::call(
            "fs.sync",
            &Arguments {
                handle: self.handle.id(),
            },
        )?;
        Ok(())
    }

    pub fn close(mut self) -> Result<()> {
        self.handle.close()
    }
}

pub struct Directory {
    handle: Handle,
}

impl Directory {
    pub fn open(uri: &str) -> Result<Self> {
        let opened: HandleResult = api::call("fs.read_dir.open", &URIArguments { uri })?;
        Ok(Self {
            handle: Handle::new(opened.handle)?,
        })
    }

    pub fn next(&mut self, limit: u16) -> Result<DirectoryPage> {
        #[derive(Serialize)]
        struct Arguments {
            handle: u64,
            limit: u16,
        }
        api::call(
            "fs.read_dir.next",
            &Arguments {
                handle: self.handle.id(),
                limit,
            },
        )
    }

    pub fn close(mut self) -> Result<()> {
        self.handle.close()
    }
}

pub struct Watch {
    handle: Handle,
}

impl Watch {
    pub fn open(uri: &str) -> Result<Self> {
        #[derive(Serialize)]
        struct Arguments<'a> {
            uri: &'a str,
            recursive: bool,
        }
        let opened: HandleResult = api::call(
            "fs.watch",
            &Arguments {
                uri,
                recursive: false,
            },
        )?;
        Ok(Self {
            handle: Handle::new(opened.handle)?,
        })
    }

    pub fn next(&mut self, timeout_ms: u32) -> Result<WatchEvent> {
        #[derive(Serialize)]
        struct Arguments {
            handle: u64,
            timeout_ms: u32,
        }
        api::call(
            "fs.watch_next",
            &Arguments {
                handle: self.handle.id(),
                timeout_ms,
            },
        )
    }

    pub fn close(mut self) -> Result<()> {
        self.handle.close()
    }
}

pub fn mounts() -> Result<Mounts> {
    api::call("fs.mounts", &serde_json::json!({}))
}

pub fn stat(uri: &str, follow_symlinks: bool) -> Result<FileStat> {
    #[derive(Serialize)]
    struct Arguments<'a> {
        uri: &'a str,
        follow_symlinks: bool,
    }
    api::call(
        "fs.stat",
        &Arguments {
            uri,
            follow_symlinks,
        },
    )
}

pub fn read_file(uri: &str) -> Result<Vec<u8>> {
    let mut file = File::open(
        uri,
        OpenOptions {
            read: true,
            ..OpenOptions::default()
        },
    )?;
    let mut result = Vec::new();
    loop {
        let (chunk, flags) = file.read(MAX_IO_CHUNK_BYTES)?;
        if chunk.is_empty() && flags & IO_FLAG_EOF == 0 {
            return Err(Error::internal("file read made no progress"));
        }
        result.extend_from_slice(&chunk);
        if flags & IO_FLAG_EOF != 0 {
            file.close()?;
            return Ok(result);
        }
    }
}

pub fn read_text(uri: &str) -> Result<String> {
    String::from_utf8(read_file(uri)?)
        .map_err(|_| Error::internal("file content is not valid UTF-8"))
}

pub fn write_file(uri: &str, bytes: &[u8], atomic: bool) -> Result<()> {
    if !atomic {
        return write_direct(uri, bytes, false);
    }
    for _ in 0..ATOMIC_TEMP_ATTEMPTS {
        let temporary = atomic_temporary_uri(uri)?;
        match write_direct(&temporary, bytes, true) {
            Ok(()) => {
                let result = rename(&temporary, uri, true);
                if result.is_err() {
                    let _ = remove(&temporary, false);
                }
                return result;
            }
            Err(error) if error.code == ErrorCode::AlreadyExists => continue,
            Err(error) => {
                let _ = remove(&temporary, false);
                return Err(error);
            }
        }
    }
    Err(Error::internal(
        "could not allocate a unique same-directory atomic write file",
    ))
}

pub fn write_text(uri: &str, text: &str, atomic: bool) -> Result<()> {
    write_file(uri, text.as_bytes(), atomic)
}

fn write_direct(uri: &str, bytes: &[u8], create_new: bool) -> Result<()> {
    let mut file = File::open(
        uri,
        OpenOptions {
            write: true,
            create: !create_new,
            create_new,
            truncate: !create_new,
            mode: Some(0o600),
            ..OpenOptions::default()
        },
    )?;
    file.write_all(bytes)?;
    file.sync()?;
    file.close()
}

pub fn remove(uri: &str, recursive: bool) -> Result<()> {
    #[derive(Serialize)]
    struct Arguments<'a> {
        uri: &'a str,
        recursive: bool,
    }
    let _: serde_json::Value = api::call("fs.remove", &Arguments { uri, recursive })?;
    Ok(())
}

pub fn mkdir(uri: &str, recursive: bool, mode: u32) -> Result<()> {
    #[derive(Serialize)]
    struct Arguments<'a> {
        uri: &'a str,
        recursive: bool,
        mode: u32,
    }
    let _: serde_json::Value = api::call(
        "fs.mkdir",
        &Arguments {
            uri,
            recursive,
            mode,
        },
    )?;
    Ok(())
}

pub fn rename(from: &str, to: &str, overwrite: bool) -> Result<()> {
    transfer("fs.rename", from, to, overwrite)
}

pub fn copy(from: &str, to: &str, overwrite: bool) -> Result<()> {
    transfer("fs.copy", from, to, overwrite)
}

fn transfer(operation: &str, from: &str, to: &str, overwrite: bool) -> Result<()> {
    #[derive(Serialize)]
    struct Arguments<'a> {
        from: &'a str,
        to: &'a str,
        overwrite: bool,
    }
    let _: serde_json::Value = api::call(
        operation,
        &Arguments {
            from,
            to,
            overwrite,
        },
    )?;
    Ok(())
}

pub fn set_times(uri: &str, accessed_unix_ms: i64, modified_unix_ms: i64) -> Result<()> {
    #[derive(Serialize)]
    struct Arguments<'a> {
        uri: &'a str,
        accessed_unix_ms: i64,
        modified_unix_ms: i64,
    }
    let _: serde_json::Value = api::call(
        "fs.set_times",
        &Arguments {
            uri,
            accessed_unix_ms,
            modified_unix_ms,
        },
    )?;
    Ok(())
}

fn atomic_temporary_uri(uri: &str) -> Result<String> {
    let (directory, name) = uri
        .rsplit_once('/')
        .filter(|(_, name)| !name.is_empty())
        .ok_or_else(|| Error::from_abi_status(-1))?;
    let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    Ok(format!(
        "{directory}/.{name}.redevplugin-{sequence:016x}.tmp"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn atomic_temporary_file_stays_in_the_same_directory() {
        let temporary = atomic_temporary_uri("redevfs://workspace/src/data.bin").unwrap();
        assert!(temporary.starts_with("redevfs://workspace/src/.data.bin.redevplugin-"));
        assert!(temporary.ends_with(".tmp"));
    }
}
