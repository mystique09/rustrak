use std::{collections::BTreeSet, path::PathBuf, process::Stdio, sync::Arc, time::Duration};

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio::{fs, process::Command, sync::Semaphore};

use crate::native::{
    normalize_debug_id, SymbolInput, SymbolObject, WorkerRequest, MAX_SYMBOL_SIZE,
    MAX_WORKER_OUTPUT,
};
use crate::{
    db::DbPool,
    error::{AppError, AppResult},
};

#[derive(Clone)]
pub struct NativeService {
    root: PathBuf,
    executable: PathBuf,
    slots: Arc<Semaphore>,
    work_slots: Arc<Semaphore>,
    timeout: Duration,
}

impl NativeService {
    pub fn new(root: PathBuf, executable: PathBuf) -> Self {
        Self {
            root,
            executable,
            slots: Arc::new(Semaphore::new(2)),
            work_slots: Arc::new(Semaphore::new(2)),
            timeout: Duration::from_secs(60),
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub async fn work_slot(&self) -> AppResult<tokio::sync::OwnedSemaphorePermit> {
        Arc::clone(&self.work_slots)
            .acquire_owned()
            .await
            .map_err(internal)
    }

    pub async fn expire_uploads(pool: &DbPool) -> AppResult<()> {
        let now = chrono::Utc::now().timestamp();
        let mut tx = pool.begin().await?;
        let expired: Vec<String> = sqlx::query_scalar(
            "SELECT DISTINCT checksum FROM native_chunk_owner WHERE expires_at < $1",
        )
        .bind(now)
        .fetch_all(&mut *tx)
        .await?;
        sqlx::query("DELETE FROM native_chunk_owner WHERE expires_at < $1")
            .bind(now)
            .execute(&mut *tx)
            .await?;
        for checksum in expired {
            sqlx::query("DELETE FROM chunk WHERE checksum=$1 AND NOT EXISTS (SELECT 1 FROM native_chunk_owner WHERE checksum=$1) AND NOT EXISTS (SELECT 1 FROM assembly_job_chunks WHERE checksum=$1)")
                .bind(checksum).execute(&mut *tx).await?;
        }
        tx.commit().await?;
        Ok(())
    }

    async fn directory(&self) -> AppResult<tempfile::TempDir> {
        fs::create_dir_all(self.root.join("jobs"))
            .await
            .map_err(internal)?;
        tempfile::tempdir_in(self.root.join("jobs")).map_err(internal)
    }

    async fn run(&self, request: WorkerRequest) -> AppResult<Value> {
        let _slot = self.slots.acquire().await.map_err(internal)?;
        let job = self.directory().await?;
        let input = job.path().join("request.json");
        let output = job.path().join("response.json");
        fs::write(&input, serde_json::to_vec(&request).map_err(internal)?)
            .await
            .map_err(internal)?;
        let mut command = Command::new(&self.executable);
        command
            .arg("--native-worker")
            .arg(&input)
            .arg(&output)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .env_clear();
        command
            .env("TMP", job.path())
            .env("TEMP", job.path())
            .env("TMPDIR", job.path());
        if let Some(system_root) = std::env::var_os("SYSTEMROOT") {
            command.env("SYSTEMROOT", system_root);
        }
        #[cfg(windows)]
        command.creation_flags(0x08000000);
        let mut child = command.spawn().map_err(internal)?;
        match tokio::time::timeout(self.timeout, child.wait()).await {
            Ok(Ok(status)) if status.success() => {}
            Ok(Ok(_)) => {
                return Err(AppError::Validation(
                    "Native processing failed; debug file or crash may be malformed".to_owned(),
                ))
            }
            Ok(Err(e)) => return Err(internal(e)),
            Err(_) => {
                child.kill().await.map_err(internal)?;
                return Err(AppError::Validation(
                    "Native processing timed out".to_owned(),
                ));
            }
        }
        if fs::metadata(&output).await.map_err(internal)?.len() > MAX_WORKER_OUTPUT {
            return Err(AppError::Validation(
                "Native worker response exceeds limit".to_owned(),
            ));
        }
        serde_json::from_slice(&fs::read(output).await.map_err(internal)?).map_err(internal)
    }

    pub async fn import(
        &self,
        pool: &DbPool,
        project_id: i32,
        checksum: &str,
        name: &str,
        bytes: Vec<u8>,
    ) -> AppResult<Vec<Value>> {
        if bytes.len() > MAX_SYMBOL_SIZE {
            return Err(AppError::PayloadTooLarge(
                "Debug file exceeds size limit".to_owned(),
            ));
        }
        let storage_key = hex::encode(Sha256::digest(&bytes));
        let temporary = self.directory().await?;
        let input = temporary.path().join("raw");
        fs::write(&input, &bytes).await.map_err(internal)?;
        drop(bytes);
        let objects: Vec<SymbolObject> = serde_json::from_value(
            self.run(WorkerRequest::Inspect {
                input: input.clone(),
                output: temporary.path().to_path_buf(),
            })
            .await?,
        )
        .map_err(internal)?;
        let destination = self.root.join(project_id.to_string()).join(&storage_key);
        fs::create_dir_all(
            destination
                .parent()
                .ok_or_else(|| internal("invalid symbol directory"))?,
        )
        .await
        .map_err(internal)?;
        let staging = temporary.path().to_path_buf();
        tokio::task::spawn_blocking(move || -> std::io::Result<()> {
            for entry in std::fs::read_dir(staging)? {
                std::fs::OpenOptions::new()
                    .write(true)
                    .open(entry?.path())?
                    .sync_all()?;
            }
            Ok(())
        })
        .await
        .map_err(internal)?
        .map_err(internal)?;
        match fs::rename(temporary.path(), &destination).await {
            Ok(()) => {}
            Err(_)
                if fs::try_exists(destination.join("raw"))
                    .await
                    .map_err(internal)? => {}
            Err(e) => return Err(internal(e)),
        }
        #[cfg(unix)]
        {
            let parent = destination
                .parent()
                .ok_or_else(|| internal("invalid symbol directory"))?
                .to_path_buf();
            tokio::task::spawn_blocking(move || std::fs::File::open(parent)?.sync_all())
                .await
                .map_err(internal)?
                .map_err(internal)?;
        }
        let mut tx = pool.begin().await?;
        for object in &objects {
            sqlx::query("INSERT INTO native_debug_file (project_id, checksum, object_index, debug_id, arch, file_format, storage_key, file_name, metadata) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT (project_id, checksum, object_index) DO NOTHING")
                .bind(project_id).bind(checksum).bind(object.object_index as i32).bind(&object.debug_id)
                .bind(&object.arch).bind(&object.file_format).bind(&storage_key).bind(name)
                .bind(serde_json::to_string(object).map_err(internal)?)
                .execute(&mut *tx).await?;
        }
        tx.commit().await?;
        self.files(pool, project_id, Some(checksum)).await
    }

    pub async fn files(
        &self,
        pool: &DbPool,
        project_id: i32,
        checksum: Option<&str>,
    ) -> AppResult<Vec<Value>> {
        let rows: Vec<(String, String, String)> = sqlx::query_as("SELECT checksum, file_name, metadata FROM native_debug_file WHERE project_id=$1 AND ($2 IS NULL OR checksum=$2) ORDER BY checksum, object_index LIMIT 1000")
            .bind(project_id).bind(checksum).fetch_all(pool).await?;
        rows.into_iter().map(|(checksum, name, metadata)| {
            let object: SymbolObject = serde_json::from_str(&metadata).map_err(internal)?;
            Ok(json!({"id":format!("{}-{}", checksum,object.object_index),"sha1":checksum,"debugId":object.debug_id,
                "codeId":object.code_id,"cpuName":object.arch,"objectName":name,"symbolType":object.file_format,
                "features":object.features,"headers":{}}))
        }).collect()
    }

    async fn symbols(
        &self,
        pool: &DbPool,
        project_id: i32,
        ids: BTreeSet<String>,
    ) -> AppResult<Vec<SymbolInput>> {
        if ids.len() > 2048 {
            return Err(AppError::Validation("Too many native modules".to_owned()));
        }
        let mut result = Vec::new();
        for id in ids {
            let rows: Vec<(String, String)> = sqlx::query_as("SELECT storage_key, metadata FROM native_debug_file WHERE project_id=$1 AND debug_id=$2 ORDER BY object_index LIMIT 32")
                .bind(project_id).bind(id).fetch_all(pool).await?;
            for (key, metadata) in rows {
                if key.len() != 64 || !key.bytes().all(|b| b.is_ascii_hexdigit()) {
                    return Err(internal("invalid symbol storage key"));
                }
                result.push(SymbolInput {
                    directory: self.root.join(project_id.to_string()).join(key),
                    object: serde_json::from_str(&metadata).map_err(internal)?,
                });
            }
        }
        Ok(result)
    }

    pub async fn enrich(
        &self,
        pool: &DbPool,
        project_id: i32,
        event: &mut Value,
        minidump: Option<Vec<u8>>,
    ) -> AppResult<()> {
        let has_exception = event
            .pointer("/exception/values")
            .and_then(Value::as_array)
            .is_some_and(|v| !v.is_empty());
        let native_images = event
            .pointer("/debug_meta/images")
            .and_then(Value::as_array)
            .is_some_and(|images| images.iter().any(crate::native::is_native_image));
        if (minidump.is_none() || has_exception) && !native_images {
            return Ok(());
        }
        let temporary = self.directory().await?;
        let dump = if let Some(bytes) = minidump.filter(|_| !has_exception) {
            if bytes.len() > crate::native::MAX_DUMP_SIZE {
                return Err(AppError::Validation(
                    "Minidump exceeds size limit".to_owned(),
                ));
            }
            let path = temporary.path().join("crash.dmp");
            fs::write(&path, bytes).await.map_err(internal)?;
            Some(path)
        } else {
            None
        };
        let ids: BTreeSet<String> = if let Some(path) = &dump {
            serde_json::from_value(
                self.run(WorkerRequest::Modules { dump: path.clone() })
                    .await?,
            )
            .map_err(internal)?
        } else {
            event
                .pointer("/debug_meta/images")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter(|image| crate::native::is_native_image(image))
                .filter_map(|image| image["debug_id"].as_str().and_then(normalize_debug_id))
                .collect()
        };
        if dump.is_none() && ids.is_empty() {
            return Ok(());
        }
        let symbols = self.symbols(pool, project_id, ids).await?;
        let enriched = self
            .run(WorkerRequest::Process {
                event: event.clone(),
                dump,
                symbols,
            })
            .await?;
        *event = enriched;
        Ok(())
    }
}

fn internal(error: impl std::fmt::Display) -> AppError {
    AppError::Internal(format!("Native processing: {error}"))
}
