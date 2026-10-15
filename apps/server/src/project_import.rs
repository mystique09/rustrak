use std::collections::HashSet;
use std::path::Path;

use serde::Deserialize;
use tokio::io::AsyncReadExt;
use uuid::Uuid;

use crate::db::{self, DbPool};
use crate::error::{AppError, AppResult};

const MAX_MANIFEST_BYTES: usize = 64 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectManifest {
    version: u32,
    projects: Vec<ImportedProject>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ImportedProject {
    id: i32,
    name: String,
    slug: String,
    sentry_key: Uuid,
}

impl ProjectManifest {
    pub fn parse(bytes: &[u8]) -> AppResult<Self> {
        if bytes.len() > MAX_MANIFEST_BYTES {
            return Err(AppError::Validation(
                "Project manifest exceeds 64 KiB".into(),
            ));
        }
        let manifest: Self = serde_json::from_slice(bytes)
            .map_err(|_| AppError::Validation("Invalid project manifest JSON".into()))?;
        if manifest.version != 1 || manifest.projects.is_empty() || manifest.projects.len() > 100 {
            return Err(AppError::Validation(
                "Project manifest must use version 1 and contain 1 to 100 projects".into(),
            ));
        }
        let mut ids = HashSet::new();
        let mut keys = HashSet::new();
        let mut slugs = HashSet::new();
        let mut names = HashSet::new();
        for project in &manifest.projects {
            if project.id <= 0
                || project.id == i32::MAX
                || project.sentry_key.is_nil()
                || project.name.trim().is_empty()
                || project.name.trim() != project.name
                || project.name.len() > 255
                || project.slug.is_empty()
                || project.slug.len() > 100
                || slug::slugify(&project.slug) != project.slug
            {
                return Err(AppError::Validation(
                    "Invalid imported project identity".into(),
                ));
            }
            if !ids.insert(project.id)
                || !keys.insert(project.sentry_key)
                || !slugs.insert(&project.slug)
                || !names.insert(&project.name)
            {
                return Err(AppError::Validation(
                    "Duplicate imported project identity".into(),
                ));
            }
        }
        Ok(manifest)
    }
}

pub async fn import_file(pool: &DbPool, path: &Path) -> AppResult<usize> {
    let file = tokio::fs::File::open(path)
        .await
        .map_err(|e| AppError::Internal(format!("Cannot open project manifest: {e}")))?;
    let mut bytes = Vec::new();
    file.take((MAX_MANIFEST_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .await
        .map_err(|e| AppError::Internal(format!("Cannot read project manifest: {e}")))?;
    import_projects(pool, &ProjectManifest::parse(&bytes)?).await
}

pub async fn import_projects(pool: &DbPool, manifest: &ProjectManifest) -> AppResult<usize> {
    let mut transaction = db::begin_write(pool).await?;
    #[cfg(feature = "postgres")]
    sqlx::query("LOCK TABLE projects IN SHARE ROW EXCLUSIVE MODE")
        .execute(&mut *transaction)
        .await?;

    let mut inserted = 0;
    for project in &manifest.projects {
        let matches: Vec<(i32, String, Uuid)> = sqlx::query_as(
            "SELECT id, slug, sentry_key FROM projects
             WHERE id = $1 OR slug = $2 OR sentry_key = $3 OR name = $4",
        )
        .bind(project.id)
        .bind(&project.slug)
        .bind(project.sentry_key)
        .bind(&project.name)
        .fetch_all(&mut *transaction)
        .await?;
        if !matches.is_empty() {
            if matches.len() == 1
                && matches[0] == (project.id, project.slug.clone(), project.sentry_key)
            {
                continue;
            }
            return Err(AppError::Conflict(format!(
                "Imported project {} conflicts with an existing project; nothing was imported",
                project.id
            )));
        }
        sqlx::query(
            "INSERT INTO projects (id, name, slug, sentry_key, platform)
             VALUES ($1, $2, $3, $4, 'native')",
        )
        .bind(project.id)
        .bind(&project.name)
        .bind(&project.slug)
        .bind(project.sentry_key)
        .execute(&mut *transaction)
        .await?;
        inserted += 1;
    }
    #[cfg(feature = "postgres")]
    sqlx::query(
        "SELECT setval(pg_get_serial_sequence('projects', 'id'),
         GREATEST((SELECT MAX(id) FROM projects),
                  (SELECT last_value FROM projects_id_seq)), true)",
    )
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok(inserted)
}
