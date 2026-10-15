mod common;

use chrono::Utc;
use common::TestDb;
use rustrak::models::{
    AlertRuleChannelInput, AlertType, ChannelType, CreateAlertRule, CreateNotificationChannel,
    CreateProject,
};
use rustrak::services::grouping::get_denormalized_fields;
use rustrak::services::{AlertService, EventService, IssueService, ProjectService};
use serde_json::{json, Value};
use uuid::Uuid;

#[tokio::test]
async fn alert_snapshots_the_triggering_event_without_private_payload_fields() {
    let db = TestDb::new().await;
    let project = ProjectService::create(
        &db.pool,
        CreateProject {
            name: "Alert context".into(),
            slug: None,
            platform: None,
        },
    )
    .await
    .unwrap();
    let channel = AlertService::create_channel(
        &db.pool,
        CreateNotificationChannel {
            name: "Unused sink".into(),
            provider_type: ChannelType::Webhook,
            credentials: json!({"url":"http://127.0.0.1:9/unused"}),
            is_enabled: true,
        },
    )
    .await
    .unwrap();
    let rule = AlertService::create_rule(
        &db.pool,
        project.id,
        CreateAlertRule {
            name: "Context".into(),
            alert_type: AlertType::Regression,
            conditions: json!({}),
            cooldown_minutes: 60,
            channels: vec![AlertRuleChannelInput {
                integration_id: channel.id,
                routing_override: json!({}),
            }],
        },
    )
    .await
    .unwrap();
    sqlx::query("UPDATE alert_rules SET last_triggered_at = $1 WHERE id = $2")
        .bind(Utc::now())
        .bind(rule.id)
        .execute(&db.pool)
        .await
        .unwrap();
    let mut data = json!({
        "release":"encore@1.2.3", "environment":"production", "platform":"native", "level":"fatal",
        "contexts":{"os":{"name":"Windows","version":"11"},"device":{"arch":"x86_64"}},
        "user":{"email":"private@example.invalid"}, "request":{"headers":{"Authorization":"secret-token"}},
        "breadcrumbs":[{"message":"private breadcrumb"}],
        "exception":{"values":[{"type":"AccessViolation","value":"invalid read", "mechanism":{"type":"minidump","handled":false},
            "stacktrace":{"frames":[
                {"function":"os_dispatch", "in_app":false},
                {"function":"room_update", "filename":"C:\\Users\\private-user\\game\\room.rs", "lineno":42, "in_app":true,
                 "symbolicator_status":"symbolicated", "vars":{"secret":"private-local"}, "context_line":"private-source"}
            ]}}]}
    });
    let fields = get_denormalized_fields(&data);
    let issue = IssueService::create(
        &db.pool,
        project.id,
        Utc::now(),
        &fields,
        Some("fatal"),
        Some("native"),
    )
    .await
    .unwrap();
    let grouping: i32 = sqlx::query_scalar("INSERT INTO groupings (project_id, issue_id, grouping_key, grouping_key_hash) VALUES ($1, $2, $3, $4) RETURNING id")
        .bind(project.id).bind(issue.id).bind("alert-context").bind("a".repeat(64)).fetch_one(&db.pool).await.unwrap();
    let event_id = Uuid::new_v4();
    let stored_id = EventService::create(
        &db.pool,
        event_id,
        project.id,
        issue.id,
        grouping,
        &data,
        Utc::now(),
        &fields,
        None,
        Some(AlertType::Regression),
    )
    .await
    .unwrap();
    data["release"] = json!("later-release");
    EventService::create(
        &db.pool,
        Uuid::new_v4(),
        project.id,
        issue.id,
        grouping,
        &data,
        Utc::now(),
        &fields,
        None,
        None,
    )
    .await
    .unwrap();
    AlertService::trigger_event_alert(
        &db.pool,
        &project,
        &issue,
        AlertType::Regression,
        event_id,
        "https://rustrak.example",
    )
    .await
    .unwrap();
    let payload: Value =
        sqlx::query_scalar("SELECT payload FROM alert_history WHERE project_id = $1")
            .bind(project.id)
            .fetch_one(&db.pool)
            .await
            .unwrap();
    assert_eq!(payload["event"]["release"], "encore@1.2.3");
    assert_eq!(payload["event"]["id"], event_id.to_string());
    assert_eq!(
        payload["event"]["url"],
        format!(
            "https://rustrak.example/projects/{}/issues/{}/events/{}",
            project.id, issue.id, stored_id
        )
    );
    assert_eq!(payload["event"]["operating_system"], "Windows 11");
    assert_eq!(payload["event"]["architecture"], "x86_64");
    assert_eq!(
        payload["event"]["exception"],
        "AccessViolation: invalid read"
    );
    assert_eq!(payload["event"]["handled"], false);
    assert_eq!(payload["event"]["mechanism"], "minidump");
    assert!(payload["event"]["stacktrace"]
        .as_str()
        .unwrap()
        .contains("room_update (room.rs:42)"));
    assert!(payload["event"]["symbolication"]
        .as_str()
        .unwrap()
        .contains("1/1"));
    let text = payload.to_string();
    for private in [
        "private@example",
        "secret-token",
        "private breadcrumb",
        "private-user",
        "private-local",
        "private-source",
        "os_dispatch",
        "later-release",
    ] {
        assert!(!text.contains(private), "unexpected data: {private}");
    }

    for (data, expected_stack, expected_symbols) in [
        (json!({}), "", "No stack frames reported"),
        (
            json!({"threads":{"values":[
                {"crashed":false,"stacktrace":{"frames":[{"function":"unrelated_thread"}]}},
                {"crashed":true,"stacktrace":{"frames":[{"instruction_addr":"0x1234", "symbolicator_status":"missing_debug_file"}]}}
            ]}}),
            "0x1234 [missing_debug_file]",
            "0/1 displayed native frames resolved",
        ),
        (
            json!({"stacktrace":{"frames":[{"function":"server_tick"}]}}),
            "server_tick",
            "SDK frames; native symbolication status unavailable",
        ),
    ] {
        let event_id = Uuid::new_v4();
        EventService::create(
            &db.pool,
            event_id,
            project.id,
            issue.id,
            grouping,
            &data,
            Utc::now(),
            &fields,
            None,
            None,
        )
        .await
        .unwrap();
        AlertService::trigger_event_alert(
            &db.pool,
            &project,
            &issue,
            AlertType::Regression,
            event_id,
            "https://rustrak.example",
        )
        .await
        .unwrap();
        let payload: Value =
            sqlx::query_scalar("SELECT payload FROM alert_history WHERE idempotency_key = $1")
                .bind(format!(
                    "event-{}-{}-regression-{}",
                    project.id, event_id, channel.id
                ))
                .fetch_one(&db.pool)
                .await
                .unwrap();
        assert_eq!(payload["event"]["stacktrace"], expected_stack);
        assert_eq!(payload["event"]["symbolication"], expected_symbols);
        assert!(payload["event"]["handled"].is_null());
        assert_eq!(payload["event"]["release"], "");
    }
}
