use std::{fs, io::Write, path::Path};

use symbolic::{cfi::CfiCache, debuginfo::Archive, symcache::SymCacheConverter};

use crate::native::{SymbolObject, MAX_SYMBOL_SIZE};

pub type NativeResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

pub fn inspect(input: &Path, output: &Path) -> NativeResult<Vec<SymbolObject>> {
    if fs::metadata(input)?.len() > MAX_SYMBOL_SIZE as u64 {
        return Err("debug file exceeds size limit".into());
    }
    let bytes = fs::read(input)?;
    let archive = Archive::parse(&bytes)?;
    if archive.object_count() > 16 {
        return Err("debug archive contains too many objects".into());
    }
    fs::create_dir_all(output)?;
    let mut objects = Vec::new();
    for (index, object) in archive.objects().enumerate() {
        let object = object?;
        let id = object.debug_id();
        if id.is_nil() {
            return Err("debug object has no debug identifier".into());
        }
        let mut features = Vec::new();
        if object.has_debug_info() {
            features.push("debug".to_owned());
        }
        if object.has_symbols() {
            features.push("symtab".to_owned());
        }
        if object.has_unwind_info() {
            features.push("unwind".to_owned());
        }
        if object.has_sources() {
            features.push("sources".to_owned());
        }
        if object.has_debug_info() || object.has_symbols() {
            let mut converter = SymCacheConverter::new();
            converter.process_object(&object)?;
            let mut file = fs::File::create(output.join(format!("{index}.symcache")))?;
            converter.serialize(&mut file)?;
            file.sync_all()?;
        }
        if object.has_unwind_info() {
            let cache = CfiCache::from_object(&object)?;
            let mut file = fs::File::create(output.join(format!("{index}.cfi")))?;
            file.write_all(cache.as_slice())?;
            file.sync_all()?;
        }
        objects.push(SymbolObject {
            object_index: index,
            debug_id: id.to_string(),
            arch: object.arch().to_string(),
            file_format: object.file_format().to_string(),
            code_id: object.code_id().map(|id| id.to_string()),
            features,
        });
    }
    if objects.is_empty() {
        return Err("debug archive contains no objects".into());
    }
    Ok(objects)
}
