use std::{collections::HashMap, fs, path::Path};

use minidump::{Minidump, MinidumpModuleList, MinidumpSystemInfo, Module};
use minidump_unwind::{simple_symbol_supplier, Symbolizer};
use serde_json::{json, Value};
use symbolic::{
    debuginfo::Archive,
    demangle::{Demangle, DemangleOptions},
    symcache::SymCache,
};

use crate::native::{address, normalize_debug_id, symbols::NativeResult, SymbolInput};

pub fn module_ids(path: &Path) -> NativeResult<Vec<String>> {
    let dump = Minidump::read_path(path)?;
    let modules: MinidumpModuleList = dump.get_stream()?;
    Ok(modules
        .iter()
        .filter_map(|m| m.debug_identifier().map(|id| id.to_string()))
        .collect())
}

fn safe_name(value: &str) -> Option<&str> {
    let name = value.rsplit(['/', '\\']).next()?;
    (!name.is_empty() && name != "." && name != ".." && !name.contains(':')).then_some(name)
}

pub async fn stackwalk(path: &Path, symbols: &[SymbolInput]) -> NativeResult<Value> {
    let dump = Minidump::read_path(path)?;
    let modules: MinidumpModuleList = dump.get_stream()?;
    let directory = tempfile::tempdir()?;
    let architecture = dump.get_stream::<MinidumpSystemInfo>()?.cpu.to_string();
    for module in modules.iter() {
        let Some(id) = module.debug_identifier() else {
            continue;
        };
        let Some(debug_file) = module.debug_file() else {
            continue;
        };
        let Some(name) = safe_name(&debug_file) else {
            continue;
        };
        let mut cfi = Vec::new();
        let mut arch = "unknown".to_owned();
        for symbol in symbols
            .iter()
            .filter(|s| s.object.debug_id == id.to_string() && s.object.arch == architecture)
        {
            let path = symbol
                .directory
                .join(format!("{}.cfi", symbol.object.object_index));
            match fs::read(path) {
                Ok(bytes) if !bytes.is_empty() => {
                    cfi = bytes;
                    arch = symbol.object.arch.clone();
                    break;
                }
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e.into()),
            }
        }
        if cfi.is_empty() {
            continue;
        }
        let base = directory.path().join(name).join(id.breakpad().to_string());
        fs::create_dir_all(&base)?;
        let basename = name.strip_suffix(".pdb").unwrap_or(name);
        let mut bytes = format!("MODULE unknown {arch} {} {name}\n", id.breakpad()).into_bytes();
        bytes.extend_from_slice(&cfi);
        fs::write(base.join(format!("{basename}.sym")), bytes)?;
    }
    let provider = Symbolizer::new(simple_symbol_supplier(vec![directory.path().to_path_buf()]));
    let state = minidump_processor::process_minidump(&dump, &provider).await?;
    let mut bytes = Vec::new();
    state.print_json(&mut bytes, false)?;
    Ok(serde_json::from_slice(&bytes)?)
}

pub fn merge_report(event: &mut Value, report: &Value) -> NativeResult<()> {
    if event
        .get("exception")
        .and_then(|e| e.get("values"))
        .and_then(Value::as_array)
        .is_some_and(|v| !v.is_empty())
    {
        return Ok(());
    }
    let modules = report["modules"].as_array().ok_or("missing module list")?;
    let system = report
        .get("system_info")
        .filter(|v| v.is_object())
        .ok_or("missing system info")?;
    let os = match system["os"].as_str().unwrap_or("unknown") {
        "Mac OS X" => "macOS",
        "Windows NT" => "Windows",
        name => name,
    };
    let image_type = match os {
        "macOS" => "macho",
        "Windows" => "pe",
        _ => "elf",
    };
    let images: Vec<Value> = modules
        .iter()
        .map(|m| {
            let base = address(&m["base_addr"]).unwrap_or(0);
            let end = address(&m["end_addr"]).unwrap_or(base);
            json!({"type":image_type,"code_file":m["filename"],"debug_file":m["debug_file"],
            "image_addr":m["base_addr"],"image_size":end.saturating_sub(base),
            "debug_id":m["debug_id"].as_str().and_then(normalize_debug_id),"code_id":m["code_id"],
            "arch":system["cpu_arch"]})
        })
        .collect();
    let crash = &report["crash_info"];
    let threads = report["threads"].as_array().ok_or("missing threads")?;
    let mut result = Vec::new();
    for (index, thread) in threads.iter().take(256).enumerate() {
        let mut frames = Vec::new();
        for frame in thread["frames"]
            .as_array()
            .ok_or("missing frames")?
            .iter()
            .take(256)
            .rev()
        {
            let mut item =
                json!({"instruction_addr":frame["offset"],"trust":frame["trust"],"in_app":false});
            if let Some(addr) = address(&frame["offset"]) {
                for (module_index, module) in modules.iter().enumerate() {
                    let base = address(&module["base_addr"]).unwrap_or(0);
                    let end = address(&module["end_addr"]).unwrap_or(base);
                    if (base..end).contains(&addr) {
                        item["package"] = module["filename"].clone();
                        item["image_addr"] = module["base_addr"].clone();
                        item["in_app"] =
                            json!(Some(module_index as u64) == report["main_module"].as_u64());
                        break;
                    }
                }
            }
            frames.push(item);
        }
        let crashed = crash["crashing_thread"].as_u64() == Some(index as u64);
        if crashed {
            event["exception"] = json!({"values":[{"type":crash["type"],"value":crash["type"],
                "thread_id":thread["thread_id"],"mechanism":{"type":"minidump","handled":false},
                "stacktrace":{"frames":frames}}]});
        }
        result.push(json!({"id":thread["thread_id"].to_string(),"crashed":crashed,"current":crashed,"stacktrace":{"frames":frames}}));
    }
    if !event.get("contexts").is_some_and(Value::is_object) {
        event["contexts"] = json!({});
    }
    for (key, values) in [
        (
            "os",
            json!({"type":"os","name":os,"version":system["os_ver"]}),
        ),
        ("device", json!({"type":"device","arch":system["cpu_arch"]})),
    ] {
        if !event["contexts"].get(key).is_some_and(Value::is_object) {
            event["contexts"][key] = json!({});
        }
        if let (Some(target), Some(source)) =
            (event["contexts"][key].as_object_mut(), values.as_object())
        {
            target.extend(source.clone());
        }
    }
    event["platform"] = json!("native");
    event["level"] = json!("fatal");
    event["threads"] = json!({"values":result});
    event["debug_meta"] = json!({"images":images});
    Ok(())
}

pub fn symbolize(event: &mut Value, symbols: &[SymbolInput]) -> NativeResult<()> {
    let images = event
        .pointer("/debug_meta/images")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut cache_bytes = HashMap::new();
    let mut ranked_symbols: Vec<_> = symbols.iter().collect();
    ranked_symbols.sort_by_key(|symbol| {
        symbol
            .object
            .features
            .iter()
            .any(|feature| feature == "debug")
    });
    for symbol in ranked_symbols {
        let path = symbol
            .directory
            .join(format!("{}.symcache", symbol.object.object_index));
        match fs::read(path) {
            Ok(bytes) => {
                cache_bytes.insert(
                    (symbol.object.debug_id.clone(), symbol.object.arch.clone()),
                    bytes,
                );
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
    }
    let event_arch = event
        .pointer("/contexts/device/arch")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_owned();
    for pointer in ["/exception/values", "/threads/values"] {
        if let Some(items) = event.pointer_mut(pointer).and_then(Value::as_array_mut) {
            for item in items {
                if let Some(frames) = item
                    .pointer_mut("/stacktrace/frames")
                    .and_then(Value::as_array_mut)
                {
                    resolve_frames(frames, &images, &event_arch, &cache_bytes, symbols)?;
                }
            }
        }
    }
    if let Some(frames) = event
        .pointer_mut("/stacktrace/frames")
        .and_then(Value::as_array_mut)
    {
        resolve_frames(frames, &images, &event_arch, &cache_bytes, symbols)?;
    }
    Ok(())
}

fn resolve_frames(
    frames: &mut Vec<Value>,
    images: &[Value],
    event_arch: &str,
    cache_bytes: &HashMap<(String, String), Vec<u8>>,
    symbols: &[SymbolInput],
) -> NativeResult<()> {
    let mut replacements = Vec::new();
    for (index, frame) in frames.iter_mut().enumerate() {
        let Some(pc) = address(&frame["instruction_addr"]) else {
            continue;
        };
        let base_hint = address(&frame["image_addr"]);
        let image = images.iter().find(|image| {
            let Some(base) = address(&image["image_addr"]) else {
                return false;
            };
            if base_hint.is_some_and(|hint| hint != base) {
                return false;
            }
            match address(&image["image_size"]) {
                Some(size) => pc >= base && pc - base < size,
                None => base_hint == Some(base) && pc >= base,
            }
        });
        let Some(image) = image else {
            frame["symbolicator_status"] = json!("unknown_image");
            continue;
        };
        let Some(id) = image["debug_id"].as_str().and_then(normalize_debug_id) else {
            continue;
        };
        let arch = image["arch"].as_str().unwrap_or(event_arch);
        let arch = match arch {
            "amd64" => "x86_64",
            "aarch64" => "arm64",
            other => other,
        };
        let mut matches = cache_bytes.iter().filter(|((debug_id, cache_arch), _)| {
            debug_id == &id && (arch.is_empty() || cache_arch == arch)
        });
        let Some((_, bytes)) = matches.next() else {
            frame["symbolicator_status"] = json!("missing_debug_file");
            continue;
        };
        if matches.next().is_some() {
            continue;
        }
        let cache = SymCache::parse(bytes)?;
        let base = address(&image["image_addr"]).ok_or("invalid module address")?;
        let mut resolved = Vec::new();
        for location in cache.lookup(pc - base).take(32) {
            let mut frame = frame.clone();
            let function = location.function();
            frame["function"] = json!(function
                .name_for_demangling()
                .demangle(DemangleOptions::complete())
                .unwrap_or_else(|| function.name().to_owned()));
            if let Some(file) = location.file() {
                let path = file.full_path();
                frame["filename"] = json!(path);
                if location.line() > 0 {
                    frame["lineno"] = json!(location.line());
                    add_source_context(&mut frame, symbols, &id, &path, location.line())?;
                }
            }
            frame["symbolicator_status"] = json!("symbolicated");
            resolved.push(frame);
        }
        if resolved.is_empty() {
            frame["symbolicator_status"] = json!("unknown_symbol");
        } else {
            resolved.reverse();
            replacements.push((index, resolved));
        }
    }
    for (index, replacement) in replacements.into_iter().rev() {
        frames.splice(index..=index, replacement);
    }
    Ok(())
}

fn add_source_context(
    frame: &mut Value,
    symbols: &[SymbolInput],
    id: &str,
    path: &str,
    line: u32,
) -> NativeResult<()> {
    for symbol in symbols
        .iter()
        .filter(|s| s.object.debug_id == id && s.object.features.iter().any(|f| f == "sources"))
    {
        let bytes = fs::read(symbol.directory.join("raw"))?;
        let archive = Archive::parse(&bytes)?;
        let Some(object) = archive.object_by_index(symbol.object.object_index)? else {
            continue;
        };
        let session = object.debug_session()?;
        let Some(source) = session.source_by_path(path)? else {
            continue;
        };
        let Some(contents) = source.contents() else {
            continue;
        };
        let index = line.saturating_sub(1) as usize;
        let lines: Vec<_> = contents
            .lines()
            .skip(index.saturating_sub(3))
            .take(7)
            .map(|line| line.chars().take(1000).collect::<String>())
            .collect();
        let center = index.min(3);
        if center >= lines.len() {
            continue;
        }
        frame["pre_context"] = json!(&lines[..center]);
        frame["context_line"] = json!(lines[center]);
        frame["post_context"] = json!(&lines[center + 1..]);
        break;
    }
    Ok(())
}
