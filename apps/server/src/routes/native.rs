use std::{collections::BTreeMap, sync::Arc};

use actix_web::{web, HttpResponse};
use serde::Deserialize;
use serde_json::json;
use sha1::{Digest, Sha1};

use crate::{
    auth::ApiActor,
    db::DbPool,
    error::{AppError, AppResult},
    native::{NativeService, MAX_SYMBOL_SIZE},
    services::access::{self, Action},
};

#[derive(Deserialize)]
pub struct AssembleFile {
    name: String,
    chunks: Vec<String>,
    debug_id: Option<String>,
}

pub fn actor_key(actor: &ApiActor) -> String {
    actor
        .user_id()
        .map(|id| format!("user:{id}"))
        .unwrap_or_else(|| "legacy".to_owned())
}

fn valid_checksum(value: &str) -> bool {
    value.len() == 40 && value.bytes().all(|b| b.is_ascii_hexdigit())
}

async fn project(pool: &DbPool, actor: &ApiActor, slug: &str, action: Action) -> AppResult<i32> {
    let id: Option<i32> = sqlx::query_scalar("SELECT id FROM projects WHERE slug=$1")
        .bind(slug)
        .fetch_optional(pool)
        .await?;
    let id = id.ok_or_else(|| AppError::NotFound("Project not found".to_owned()))?;
    access::require(pool, actor.is_admin(), actor.user_id(), id, action).await?;
    Ok(id)
}

pub async fn assemble(
    path: web::Path<(String, String)>,
    actor: ApiActor,
    pool: web::Data<DbPool>,
    native: web::Data<Arc<NativeService>>,
    body: web::Json<BTreeMap<String, AssembleFile>>,
) -> AppResult<HttpResponse> {
    let project_id = project(pool.get_ref(), &actor, &path.1, Action::UpdateProject).await?;
    let _upload_slot = native.work_slot().await?;
    if body.is_empty() || body.len() > 64 {
        return Err(AppError::Validation(
            "Expected between 1 and 64 debug files".to_owned(),
        ));
    }
    let owner = actor_key(&actor);
    let mut result = BTreeMap::new();
    for (checksum, file) in body.iter() {
        if !valid_checksum(checksum)
            || file.chunks.is_empty()
            || file.chunks.len() > 512
            || file.chunks.iter().any(|hash| !valid_checksum(hash))
        {
            return Err(AppError::Validation(
                "Invalid debug file checksum or chunks".to_owned(),
            ));
        }
        if file
            .debug_id
            .as_deref()
            .is_some_and(|id| crate::native::normalize_debug_id(id).is_none())
        {
            return Err(AppError::Validation("Invalid debug identifier".to_owned()));
        }
        let existing = native
            .files(pool.get_ref(), project_id, Some(checksum))
            .await?;
        if let Some(dif) = existing.first() {
            result.insert(
                checksum.clone(),
                json!({"state":"ok","missingChunks":[],"dif":dif}),
            );
            continue;
        }
        let mut missing = Vec::new();
        let mut bytes = Vec::new();
        for chunk in &file.chunks {
            let data:Option<Vec<u8>>=sqlx::query_scalar("SELECT c.data FROM chunk c JOIN native_chunk_owner o ON o.checksum=c.checksum WHERE c.checksum=$1 AND o.actor=$2")
                .bind(chunk).bind(&owner).fetch_optional(pool.get_ref()).await?;
            match data {
                Some(data) => {
                    if bytes.len().saturating_add(data.len()) > MAX_SYMBOL_SIZE {
                        return Err(AppError::PayloadTooLarge(
                            "Debug file exceeds size limit".to_owned(),
                        ));
                    }
                    bytes.extend_from_slice(&data);
                }
                None => missing.push(chunk),
            }
        }
        if !missing.is_empty() {
            result.insert(
                checksum.clone(),
                json!({"state":"not_found","missingChunks":missing}),
            );
            continue;
        }
        if hex::encode(Sha1::digest(&bytes)) != checksum.to_ascii_lowercase() {
            result.insert(
                checksum.clone(),
                json!({"state":"error","missingChunks":[],"detail":"Debug file checksum mismatch"}),
            );
            continue;
        }
        let name = file.name.rsplit(['/', '\\']).next().unwrap_or("debug-file");
        match native
            .import(pool.get_ref(), project_id, checksum, name, bytes)
            .await
        {
            Ok(files) => {
                result.insert(
                    checksum.clone(),
                    json!({"state":"ok","missingChunks":[],"dif":files.first()}),
                );
            }
            Err(error) if matches!(error.kind(), AppError::Validation(_)) => {
                result.insert(
                    checksum.clone(),
                    json!({"state":"error","missingChunks":[],"detail":error.to_string()}),
                );
            }
            Err(error) => return Err(error),
        }
    }
    Ok(HttpResponse::Ok().json(result))
}

pub async fn list(
    path: web::Path<(String, String)>,
    actor: ApiActor,
    pool: web::Data<DbPool>,
    native: web::Data<Arc<NativeService>>,
) -> AppResult<HttpResponse> {
    let id = project(pool.get_ref(), &actor, &path.1, Action::ViewProject).await?;
    Ok(HttpResponse::Ok().json(native.files(pool.get_ref(), id, None).await?))
}

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.route(
        "/api/0/projects/{org_slug}/{project_slug}/files/difs/assemble/",
        web::post().to(assemble),
    )
    .route(
        "/api/0/projects/{org_slug}/{project_slug}/files/difs/",
        web::get().to(list),
    )
    .route(
        "/api/0/projects/{org_slug}/{project_slug}/files/dsyms/",
        web::get().to(list),
    );
}
