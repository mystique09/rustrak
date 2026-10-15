mod limits;
pub mod processing;
pub mod service;
pub mod symbols;
pub mod worker;

pub use service::NativeService;

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

pub const MAX_DUMP_SIZE: usize = 20 * 1024 * 1024;
pub const MAX_SYMBOL_SIZE: usize = 512 * 1024 * 1024;
pub const MAX_WORKER_OUTPUT: u64 = 32 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymbolObject {
    pub object_index: usize,
    pub debug_id: String,
    pub arch: String,
    pub file_format: String,
    pub code_id: Option<String>,
    pub features: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymbolInput {
    pub directory: PathBuf,
    pub object: SymbolObject,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum WorkerRequest {
    Inspect {
        input: PathBuf,
        output: PathBuf,
    },
    Modules {
        dump: PathBuf,
    },
    Process {
        event: serde_json::Value,
        dump: Option<PathBuf>,
        symbols: Vec<SymbolInput>,
    },
}

pub fn normalize_debug_id(value: &str) -> Option<String> {
    value
        .parse::<symbolic::common::DebugId>()
        .ok()
        .map(|id| id.to_string())
}

pub fn address(value: &serde_json::Value) -> Option<u64> {
    value.as_u64().or_else(|| {
        let text = value.as_str()?;
        if let Some(hex) = text.strip_prefix("0x") {
            u64::from_str_radix(hex, 16).ok()
        } else {
            text.parse().ok()
        }
    })
}

pub fn is_native_image(image: &serde_json::Value) -> bool {
    image["type"]
        .as_str()
        .is_none_or(|kind| matches!(kind, "pe" | "elf" | "macho"))
        && image["debug_id"].as_str().is_some()
}
