use actix_web::{test as web_test, web, App, HttpResponse};
use rustrak::auth::SentryAuth;
use rustrak::models::CreateProject;
use rustrak::project_import::{import_projects, ProjectManifest};
use rustrak::services::ProjectService;
use serde_json::{json, Value};

mod common;

fn identities() -> Value {
    json!({"version": 1, "projects": [
        {"id": 1, "name": "Encore client", "slug": "idate-encore-client",
         "sentry_key": "168719e89a3d4871b01c2958e71ea683"},
        {"id": 2, "name": "Game server", "slug": "rust",
         "sentry_key": "606cdf2848984d90b9f8989e74366dee"}
    ]})
}

fn parse(value: &Value) -> ProjectManifest {
    ProjectManifest::parse(&serde_json::to_vec(value).unwrap()).unwrap()
}

#[actix_web::test]
async fn existing_dsns_authenticate_and_wrong_keys_are_rejected() {
    let database = common::TestDb::new().await;
    import_projects(&database.pool, &parse(&identities()))
        .await
        .unwrap();
    let app = web_test::init_service(App::new().app_data(web::Data::new(database.pool)).route(
        "/api/{project_id}/envelope/",
        web::post().to(|auth: SentryAuth| async move { HttpResponse::Ok().json(auth.project.id) }),
    ))
    .await;
    for (id, key) in [
        (1, "168719e89a3d4871b01c2958e71ea683"),
        (2, "606cdf2848984d90b9f8989e74366dee"),
    ] {
        let request = web_test::TestRequest::post()
            .uri(&format!("/api/{id}/envelope/"))
            .insert_header((
                "X-Sentry-Auth",
                format!("Sentry sentry_key={key}, sentry_version=7"),
            ))
            .to_request();
        let response: i32 = web_test::call_and_read_body_json(&app, request).await;
        assert_eq!(response, id);
        let request = web_test::TestRequest::post()
            .uri(&format!("/api/{id}/envelope/?sentry_key={key}"))
            .to_request();
        assert!(web_test::call_service(&app, request)
            .await
            .status()
            .is_success());
        let request = web_test::TestRequest::post()
            .uri(&format!("/api/{}/envelope/?sentry_key={key}", 3 - id))
            .to_request();
        assert_eq!(web_test::call_service(&app, request).await.status(), 401);
    }
}

#[tokio::test]
async fn repeated_import_preserves_projects_and_future_ids() {
    let database = common::TestDb::new().await;
    let manifest = parse(&identities());
    assert_eq!(import_projects(&database.pool, &manifest).await.unwrap(), 2);
    sqlx::query("UPDATE projects SET name = 'Renamed by administrator' WHERE id = 1")
        .execute(&database.pool)
        .await
        .unwrap();
    assert_eq!(import_projects(&database.pool, &manifest).await.unwrap(), 0);
    assert_eq!(
        ProjectService::get_by_id(&database.pool, 1)
            .await
            .unwrap()
            .name,
        "Renamed by administrator"
    );
    let next = ProjectService::create(
        &database.pool,
        CreateProject {
            name: "Another project".into(),
            slug: Some("another".into()),
            platform: Some("native".into()),
        },
    )
    .await
    .unwrap();
    assert!(next.id > 2);
    assert_eq!(import_projects(&database.pool, &manifest).await.unwrap(), 0);
    let later = ProjectService::create(
        &database.pool,
        CreateProject {
            name: "Later project".into(),
            slug: None,
            platform: None,
        },
    )
    .await
    .unwrap();
    assert!(later.id > next.id);
}

#[tokio::test]
async fn conflicts_rollback_the_entire_import_and_preserve_keys() {
    let database = common::TestDb::new().await;
    let mut existing = identities();
    existing["projects"].as_array_mut().unwrap().remove(0);
    existing["projects"][0]["sentry_key"] = json!("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    import_projects(&database.pool, &parse(&existing))
        .await
        .unwrap();
    assert!(import_projects(&database.pool, &parse(&identities()))
        .await
        .is_err());
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM projects")
        .fetch_one(&database.pool)
        .await
        .unwrap();
    assert_eq!(count, 1);
    assert_eq!(
        ProjectService::get_by_id(&database.pool, 2)
            .await
            .unwrap()
            .sentry_key
            .simple()
            .to_string(),
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    );
}

#[tokio::test]
async fn identities_cannot_be_mapped_onto_other_projects() {
    let database = common::TestDb::new().await;
    import_projects(&database.pool, &parse(&identities()))
        .await
        .unwrap();
    for field in ["id", "slug", "sentry_key", "name"] {
        let mut collision = json!({"version": 1, "projects": [{
            "id": 10, "name": "Different", "slug": "different",
            "sentry_key": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        }]});
        collision["projects"][0][field] = identities()["projects"][0][field].clone();
        assert!(
            import_projects(&database.pool, &parse(&collision))
                .await
                .is_err(),
            "{field}"
        );
    }
}

#[tokio::test]
async fn concurrent_imports_preserve_a_single_mapping() {
    let database = common::TestDb::new().await;
    let manifest = parse(&identities());
    let (first, second) = tokio::join!(
        import_projects(&database.pool, &manifest),
        import_projects(&database.pool, &manifest)
    );
    assert_eq!(first.unwrap() + second.unwrap(), 2);
}

#[tokio::test]
async fn file_import_is_bounded_and_requires_an_existing_file() {
    let database = common::TestDb::new().await;
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("projects.json");
    assert!(rustrak::project_import::import_file(&database.pool, &path)
        .await
        .is_err());
    std::fs::write(&path, vec![b' '; 65537]).unwrap();
    assert!(rustrak::project_import::import_file(&database.pool, &path)
        .await
        .is_err());
    std::fs::write(&path, serde_json::to_vec(&identities()).unwrap()).unwrap();
    assert_eq!(
        rustrak::project_import::import_file(&database.pool, &path)
            .await
            .unwrap(),
        2
    );
}

#[test]
fn invalid_manifests_are_rejected_before_import() {
    for invalid in [
        json!({}),
        json!({"version": 2, "projects": identities()["projects"]}),
        json!({"version": 1, "projects": []}),
    ] {
        assert!(ProjectManifest::parse(&serde_json::to_vec(&invalid).unwrap()).is_err());
    }
    for (field, value) in [
        ("id", json!(0)),
        ("id", json!(-1)),
        ("id", json!(i32::MAX)),
        ("slug", json!("bad/slug")),
        ("name", json!(" ")),
        ("sentry_key", json!("00000000000000000000000000000000")),
        ("unexpected", json!(true)),
    ] {
        let mut manifest = identities();
        manifest["projects"][0][field] = value;
        assert!(
            ProjectManifest::parse(&serde_json::to_vec(&manifest).unwrap()).is_err(),
            "{field}"
        );
    }
    for field in ["id", "slug", "name", "sentry_key"] {
        let mut manifest = identities();
        manifest["projects"][1][field] = manifest["projects"][0][field].clone();
        assert!(
            ProjectManifest::parse(&serde_json::to_vec(&manifest).unwrap()).is_err(),
            "{field}"
        );
    }
}
