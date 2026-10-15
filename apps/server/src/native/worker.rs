use std::{fs, io::Write, path::Path};

use serde_json::Value;

use crate::native::{processing, symbols, symbols::NativeResult, WorkerRequest, MAX_WORKER_OUTPUT};

pub async fn run(request: &Path, response: &Path) -> NativeResult<()> {
    let _limits = crate::native::limits::apply()?;
    let bytes = fs::read(request)?;
    if bytes.len() > MAX_WORKER_OUTPUT as usize {
        return Err("native request exceeds limit".into());
    }
    let value = match serde_json::from_slice::<WorkerRequest>(&bytes)? {
        WorkerRequest::Inspect { input, output } => {
            serde_json::to_value(symbols::inspect(&input, &output)?)?
        }
        WorkerRequest::Modules { dump } => serde_json::to_value(processing::module_ids(&dump)?)?,
        WorkerRequest::Process {
            mut event,
            dump,
            symbols,
        } => {
            if let Some(dump) = dump {
                let report = processing::stackwalk(&dump, &symbols).await?;
                processing::merge_report(&mut event, &report)?;
            }
            processing::symbolize(&mut event, &symbols)?;
            event
        }
    };
    let bytes = serde_json::to_vec::<Value>(&value)?;
    let bytes = crate::ingest::parser::strip_nul_escapes(&bytes);
    if bytes.len() > MAX_WORKER_OUTPUT as usize {
        return Err("native response exceeds limit".into());
    }
    let mut file = fs::File::create(response)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    Ok(())
}
