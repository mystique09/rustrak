use rustrak::ingest::{EnvelopeItemKind, EnvelopeParser};

mod common;

#[test]
fn native_attachment_bytes_are_not_json_normalized() {
    let dump = b"MDMP\0binary\\u0000tail\n";
    let mut envelope = format!(
        "{{\"event_id\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"}}\n{{\"type\":\"attachment\",\"attachment_type\":\"event.minidump\",\"length\":{}}}\n",
        dump.len()
    ).into_bytes();
    envelope.extend_from_slice(dump);
    let parsed = EnvelopeParser::new(envelope.into()).parse().unwrap();
    match &parsed.items[0] {
        EnvelopeItemKind::Minidump(payload) => assert_eq!(payload.as_ref(), dump),
        other => panic!("unexpected attachment: {other:?}"),
    }
}

#[tokio::test]
async fn dump_and_metadata_survive_restart_duplicate_delivery_and_project_isolation() {
    use rustrak::ingest::{storage, EventMetadata};
    let directory = tempfile::tempdir().unwrap();
    let id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let metadata = EventMetadata {
        event_id: id.to_owned(),
        project_id: 7,
        ingested_at: chrono::Utc::now(),
        remote_addr: None,
    };
    let event = br#"{"release":"qa","breadcrumbs":[{"message":"before crash"}]}"#;
    let dump = b"MDMP\0binary\\u0000tail\n";
    storage::store_event_with_minidump(directory.path(), id, event, &metadata, Some(dump))
        .await
        .unwrap();
    storage::store_event_with_minidump(directory.path(), id, b"{}", &metadata, Some(b"retry"))
        .await
        .unwrap();
    assert_eq!(
        storage::read_event_for_project(directory.path(), 7, id)
            .await
            .unwrap(),
        event
    );
    assert_eq!(
        storage::read_minidump_for_project(directory.path(), 7, id)
            .await
            .unwrap()
            .unwrap(),
        dump
    );
    assert!(storage::read_minidump_for_project(directory.path(), 8, id)
        .await
        .unwrap()
        .is_none());
    let queued = storage::list_pending_event_metadata(directory.path())
        .await
        .unwrap();
    assert_eq!(queued.len(), 1);
    assert_eq!(queued[0].project_id, 7);
}

#[cfg(feature = "native")]
mod native {
    use rustrak::native::{normalize_debug_id, processing, symbols, NativeService, SymbolInput};
    use serde_json::{json, Value};
    use std::{
        path::{Path, PathBuf},
        sync::Arc,
    };

    fn fixture(name: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/native")
            .join(name)
    }

    fn inspect(name: &str, directory: &Path) -> Vec<SymbolInput> {
        std::fs::copy(fixture(name), directory.join("raw")).unwrap();
        symbols::inspect(&directory.join("raw"), directory)
            .unwrap()
            .into_iter()
            .map(|object| SymbolInput {
                directory: directory.to_path_buf(),
                object,
            })
            .collect()
    }

    #[test]
    fn pdb_age_is_part_of_the_symbol_identity() {
        assert_eq!(
            normalize_debug_id("3249D99D0C4049318610F4E4FB0B69361"),
            Some("3249d99d-0c40-4931-8610-f4e4fb0b6936-1".to_owned())
        );
        assert_ne!(
            normalize_debug_id("3249D99D0C4049318610F4E4FB0B69361"),
            normalize_debug_id("3249D99D0C4049318610F4E4FB0B69362")
        );
    }

    #[test]
    fn native_formats_resolve_main_and_reject_other_modules_and_architectures() {
        for (name, offset) in [
            ("windows.pdb", 0x2910u64),
            ("linux.debug", 0x1c70),
            ("macos.dwarf", 0xdba0),
        ] {
            let directory = tempfile::tempdir().unwrap();
            let symbols = inspect(name, directory.path());
            let symbol = &symbols[0];
            let id = &symbol.object.debug_id;
            let arch = &symbol.object.arch;
            let frame = json!({"instruction_addr":format!("0x{:x}",0x100000+offset),"image_addr":"0x100000"});
            let mut event = json!({"debug_meta":{"images":[{"image_addr":"0x100000","image_size":0x100000,"debug_id":id,"arch":arch}]},"exception":{"values":[{"stacktrace":{"frames":[frame.clone()]}}]}});
            processing::symbolize(&mut event, &symbols).unwrap();
            let resolved = &event["exception"]["values"][0]["stacktrace"]["frames"][0];
            assert!(
                resolved["function"]
                    .as_str()
                    .is_some_and(|name| name.contains("main")),
                "{name}: {resolved}"
            );
            assert!(
                resolved["lineno"].as_u64().is_some_and(|line| line > 0),
                "{name}: {resolved}"
            );
            for (field, value) in [
                ("image_addr", json!("0x200000")),
                ("arch", json!("other")),
                ("debug_id", json!("00000000-0000-0000-0000-000000000000")),
            ] {
                let mut wrong = event.clone();
                wrong["exception"]["values"][0]["stacktrace"]["frames"][0] = frame.clone();
                wrong["debug_meta"]["images"][0][field] = value;
                processing::symbolize(&mut wrong, &symbols).unwrap();
                assert!(
                    wrong["exception"]["values"][0]["stacktrace"]["frames"][0]["function"]
                        .is_null(),
                    "{name} {field}"
                );
            }
        }
    }

    #[tokio::test]
    async fn windows_macos_linux_dumps_preserve_metadata_and_sdk_exceptions() {
        for (os, symbol_file) in [
            ("windows", Some("windows.sym")),
            ("macos", Some("macos.sym")),
            ("linux", None),
        ] {
            let directory = tempfile::tempdir().unwrap();
            let symbols = symbol_file
                .map(|file| inspect(file, directory.path()))
                .unwrap_or_default();
            let report = processing::stackwalk(&fixture(&format!("{os}.dmp")), &symbols)
                .await
                .unwrap();
            let mut event = json!({"event_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","release":"qa@1","tags":{"test":"native"},"breadcrumbs":[{"message":"before crash"}],"contexts":{"device":{"name":"QA"}}});
            let original = event.clone();
            processing::merge_report(&mut event, &report).unwrap();
            processing::symbolize(&mut event, &symbols).unwrap();
            for key in ["event_id", "release", "tags", "breadcrumbs"] {
                assert_eq!(event[key], original[key]);
            }
            assert_eq!(event["contexts"]["device"]["name"], "QA");
            assert_eq!(event["platform"], "native");
            assert_eq!(event["level"], "fatal");
            let frames = event
                .pointer("/exception/values/0/stacktrace/frames")
                .and_then(Value::as_array)
                .unwrap();
            assert!(!frames.is_empty(), "{os}");
            if symbol_file.is_some() {
                assert!(
                    frames.iter().any(|frame| frame["function"].is_string()),
                    "{os}: {frames:?}"
                );
            }
            let enriched = event.clone();
            processing::merge_report(&mut event, &report).unwrap();
            assert_eq!(event, enriched);
        }
    }

    #[test]
    fn uploaded_sources_supply_context_without_reading_host_files() {
        use symbolic::debuginfo::sourcebundle::{SourceBundleWriter, SourceFileInfo};
        let directory = tempfile::tempdir().unwrap();
        let mut symbols = inspect("windows.pdb", directory.path());
        let mut event = json!({"debug_meta":{"images":[{"image_addr":"0x100000","image_size":0x10000,"debug_id":symbols[0].object.debug_id,"arch":"x86"}]},"exception":{"values":[{"stacktrace":{"frames":[{"instruction_addr":"0x102910"}]}}]}});
        processing::symbolize(&mut event, &symbols).unwrap();
        let frame = &event["exception"]["values"][0]["stacktrace"]["frames"][0];
        let path = frame["filename"].as_str().unwrap().to_owned();
        let line = frame["lineno"].as_u64().unwrap() as usize;
        let source_directory = tempfile::tempdir().unwrap();
        let mut writer = SourceBundleWriter::start(
            std::fs::File::create(source_directory.path().join("raw")).unwrap(),
        )
        .unwrap();
        writer.set_attribute("debug_id", symbols[0].object.debug_id.clone());
        writer.set_attribute("arch", "x86");
        let mut info = SourceFileInfo::default();
        info.set_path(path);
        let content = (1..line + 5)
            .map(|i| format!("uploaded line {i}\n"))
            .collect::<String>();
        writer
            .add_file("source.cpp", content.as_bytes(), info)
            .unwrap();
        writer.finish().unwrap();
        for object in symbols::inspect(
            &source_directory.path().join("raw"),
            source_directory.path(),
        )
        .unwrap()
        {
            symbols.push(SymbolInput {
                directory: source_directory.path().to_path_buf(),
                object,
            });
        }
        processing::symbolize(&mut event, &symbols).unwrap();
        let frame = &event["exception"]["values"][0]["stacktrace"]["frames"][0];
        assert_eq!(frame["context_line"], format!("uploaded line {line}"));
        assert_eq!(frame["post_context"].as_array().unwrap().len(), 3);
    }

    #[tokio::test]
    async fn child_worker_import_is_idempotent_and_symbols_are_project_scoped() {
        use rustrak::{models::CreateProject, services::ProjectService};
        use sha1::{Digest, Sha1};
        let db = crate::common::TestDb::new().await;
        let project = ProjectService::create(
            &db.pool,
            CreateProject {
                name: "Native".to_owned(),
                slug: Some("native".to_owned()),
                platform: Some("native".to_owned()),
            },
        )
        .await
        .unwrap();
        let other = ProjectService::create(
            &db.pool,
            CreateProject {
                name: "Other".to_owned(),
                slug: Some("other".to_owned()),
                platform: None,
            },
        )
        .await
        .unwrap();
        let directory = tempfile::tempdir().unwrap();
        let native = Arc::new(NativeService::new(
            directory.path().to_path_buf(),
            PathBuf::from(env!("CARGO_BIN_EXE_rustrak")),
        ));
        let bytes = std::fs::read(fixture("windows.pdb")).unwrap();
        let checksum = hex::encode(Sha1::digest(&bytes));
        let files = native
            .import(&db.pool, project.id, &checksum, "crash.pdb", bytes.clone())
            .await
            .unwrap();
        assert_eq!(files.len(), 1);
        assert_eq!(
            native
                .import(&db.pool, project.id, &checksum, "crash.pdb", bytes)
                .await
                .unwrap(),
            files
        );
        let mut event = json!({"debug_meta":{"images":[{"image_addr":"0x100000","image_size":0x10000,"debug_id":files[0]["debugId"],"arch":"x86"}]},"exception":{"values":[{"stacktrace":{"frames":[{"instruction_addr":"0x102910","image_addr":"0x100000"}]}}]}});
        let mut isolated = event.clone();
        native
            .enrich(&db.pool, project.id, &mut event, None)
            .await
            .unwrap();
        assert!(event
            .pointer("/exception/values/0/stacktrace/frames/0/function")
            .and_then(Value::as_str)
            .is_some_and(|name| name.contains("main")));
        native
            .enrich(&db.pool, other.id, &mut isolated, None)
            .await
            .unwrap();
        assert!(isolated
            .pointer("/exception/values/0/stacktrace/frames/0/function")
            .is_none());
        let mut malformed = json!({"release":"retained", "tags":{"qa":"native"}});
        let original = malformed.clone();
        assert!(native
            .enrich(
                &db.pool,
                project.id,
                &mut malformed,
                Some(b"bad dump".to_vec())
            )
            .await
            .is_err());
        assert_eq!(malformed, original);
    }

    #[actix_web::test]
    async fn upload_auth_checksums_deduplication_and_chunk_ownership() {
        use actix_web::{http::StatusCode, test, web, App};
        use rustrak::{
            config::Config,
            models::{CreateAuthToken, CreateProject, ProjectRole, UserRole},
            routes,
            services::{AuthTokenService, ProjectMemberService, ProjectService, UsersService},
        };
        use sha1::{Digest, Sha1};
        let db = crate::common::TestDb::new().await;
        let project = ProjectService::create(
            &db.pool,
            CreateProject {
                name: "Native".into(),
                slug: Some("native".into()),
                platform: None,
            },
        )
        .await
        .unwrap();
        let mut tokens = Vec::new();
        for (name, role) in [
            ("editor", Some(ProjectRole::Editor)),
            ("other", Some(ProjectRole::Editor)),
            ("viewer", Some(ProjectRole::Viewer)),
            ("outsider", None),
        ] {
            let user = UsersService::create_user_with_password_hash(
                &db.pool,
                &format!("{name}@example.invalid"),
                "not-used",
                UserRole::Member,
            )
            .await
            .unwrap();
            if let Some(role) = role {
                ProjectMemberService::upsert(&db.pool, project.id, user.id, role)
                    .await
                    .unwrap();
            }
            tokens.push(
                AuthTokenService::create_for_user(
                    &db.pool,
                    CreateAuthToken { description: None },
                    Some(user.id),
                )
                .await
                .unwrap()
                .token,
            );
        }
        let directory = tempfile::tempdir().unwrap();
        let service = Arc::new(NativeService::new(
            directory.path().to_path_buf(),
            env!("CARGO_BIN_EXE_rustrak").into(),
        ));
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(db.pool.clone()))
                .app_data(web::Data::new(Config::from_env().unwrap()))
                .app_data(web::Data::new(service.clone()))
                .configure(routes::sourcemaps::configure)
                .configure(routes::native::configure),
        )
        .await;
        let bytes = std::fs::read(fixture("windows.pdb")).unwrap();
        let checksum = hex::encode(Sha1::digest(&bytes));
        let body = json!({checksum.clone():{"name":"../crash.pdb","chunks":[checksum.clone()]}});
        let path = "/api/0/projects/qa/native/files/difs/assemble/";
        for index in [2, 3] {
            let response = test::call_service(
                &app,
                test::TestRequest::post()
                    .uri(path)
                    .insert_header(("Authorization", format!("Bearer {}", tokens[index])))
                    .set_json(&body)
                    .to_request(),
            )
            .await;
            assert!(matches!(
                response.status(),
                StatusCode::FORBIDDEN | StatusCode::NOT_FOUND
            ));
        }
        let mut multipart=b"--native-test\r\nContent-Disposition: form-data; name=\"file\"; filename=\"chunk\"\r\nContent-Type: application/octet-stream\r\n\r\n".to_vec();
        multipart.extend_from_slice(&bytes);
        multipart.extend_from_slice(b"\r\n--native-test--\r\n");
        let response = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/api/0/organizations/qa/chunk-upload/")
                .insert_header(("Authorization", format!("Bearer {}", tokens[0])))
                .insert_header(("Content-Type", "multipart/form-data; boundary=native-test"))
                .set_payload(multipart)
                .to_request(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let response = test::call_service(
            &app,
            test::TestRequest::post()
                .uri(path)
                .insert_header(("Authorization", format!("Bearer {}", tokens[1])))
                .set_json(&body)
                .to_request(),
        )
        .await;
        let result: Value = test::read_body_json(response).await;
        assert_eq!(result[&checksum]["state"], "not_found");
        let bad_checksum = "0000000000000000000000000000000000000000";
        let bad = json!({bad_checksum:{"name":"crash.pdb","chunks":[checksum.clone()]}});
        let response = test::call_service(
            &app,
            test::TestRequest::post()
                .uri(path)
                .insert_header(("Authorization", format!("Bearer {}", tokens[0])))
                .set_json(&bad)
                .to_request(),
        )
        .await;
        let result: Value = test::read_body_json(response).await;
        assert_eq!(result[bad_checksum]["state"], "error");
        for _ in 0..2 {
            let response = test::call_service(
                &app,
                test::TestRequest::post()
                    .uri(path)
                    .insert_header(("Authorization", format!("Bearer {}", tokens[0])))
                    .set_json(&body)
                    .to_request(),
            )
            .await;
            assert_eq!(response.status(), StatusCode::OK);
            let result: Value = test::read_body_json(response).await;
            assert_eq!(result[&checksum]["state"], "ok", "{result}");
            assert_eq!(result[&checksum]["dif"]["objectName"], "crash.pdb");
        }
        assert_eq!(
            service
                .files(&db.pool, project.id, None)
                .await
                .unwrap()
                .len(),
            1
        );
        sqlx::query("UPDATE native_chunk_owner SET expires_at=0")
            .execute(&db.pool)
            .await
            .unwrap();
        NativeService::expire_uploads(&db.pool).await.unwrap();
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM chunk")
            .fetch_one(&db.pool)
            .await
            .unwrap();
        assert_eq!(count, 0);
    }

    #[tokio::test]
    async fn malformed_dumps_keep_metadata_and_infrastructure_failures_keep_the_spool() {
        use rustrak::{
            config::RateLimitConfig,
            digest::processors::{ErrorProcessor, Processor, ProcessorCtx},
            ingest::{storage, EventMetadata},
            models::CreateProject,
            services::{EventService, ProjectService},
        };
        let db = crate::common::TestDb::new().await;
        let project = ProjectService::create(
            &db.pool,
            CreateProject {
                name: "Recovery".into(),
                slug: None,
                platform: None,
            },
        )
        .await
        .unwrap();
        let spool = tempfile::tempdir().unwrap();
        let symbols = tempfile::tempdir().unwrap();
        let rates = RateLimitConfig {
            max_events_per_minute: 1000,
            max_events_per_hour: 10000,
            max_events_per_project_per_minute: 500,
            max_events_per_project_per_hour: 5000,
        };
        for (worker, should_succeed) in [
            (PathBuf::from(env!("CARGO_BIN_EXE_rustrak")), true),
            (symbols.path().join("missing-worker"), false),
        ] {
            let id = uuid::Uuid::new_v4();
            let event = json!({"event_id":id.simple().to_string(),"release":"qa@1","tags":{"test":"recovery"},"breadcrumbs":[{"message":"before crash"}]});
            let metadata = EventMetadata {
                project_id: project.id,
                event_id: id.simple().to_string(),
                ingested_at: chrono::Utc::now(),
                remote_addr: None,
            };
            storage::store_event_with_minidump(
                spool.path(),
                &metadata.event_id,
                &serde_json::to_vec(&event).unwrap(),
                &metadata,
                Some(b"bad dump"),
            )
            .await
            .unwrap();
            let native = Arc::new(NativeService::new(symbols.path().to_path_buf(), worker));
            let processor = ErrorProcessor::new(
                spool.path().to_path_buf(),
                rates.clone(),
                crate::common::null_sourcemap_provider(),
            )
            .with_native(native);
            let ctx = ProcessorCtx {
                pool: db.pool.clone(),
                project_id: project.id,
                event_id: id,
                ingested_at: metadata.ingested_at,
                remote_addr: None,
            };
            let result = processor.process(metadata.clone(), &ctx).await;
            if should_succeed {
                result.unwrap();
                let stored = EventService::get_by_event_id(&db.pool, project.id, id)
                    .await
                    .unwrap();
                assert_eq!(stored.data["release"], event["release"]);
                assert_eq!(stored.data["tags"], event["tags"]);
                assert_eq!(stored.data["breadcrumbs"], event["breadcrumbs"]);
                assert_eq!(stored.data["errors"][0]["type"], "native_processing_error");
            } else {
                assert!(result.is_err());
                assert_eq!(
                    storage::read_minidump_for_project(
                        spool.path(),
                        project.id,
                        &metadata.event_id
                    )
                    .await
                    .unwrap()
                    .unwrap(),
                    b"bad dump"
                );
                assert!(!EventService::exists(&db.pool, project.id, id)
                    .await
                    .unwrap());
            }
        }
    }
}
