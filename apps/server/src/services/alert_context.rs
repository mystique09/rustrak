use crate::models::alert::AlertEventInfo;
use crate::models::Event;
use serde_json::Value;

fn bounded(value: &str, limit: usize) -> String {
    if value.encode_utf16().count() <= limit {
        return value.to_string();
    }
    let mut text = String::new();
    let mut units = 0;
    for character in value.chars() {
        units += character.len_utf16();
        if units >= limit {
            break;
        }
        text.push(character);
    }
    text.push('…');
    text
}

fn string(value: &Value) -> &str {
    value.as_str().unwrap_or("")
}

pub(crate) fn summarize(event: &Event, dashboard_url: &str) -> AlertEventInfo {
    let data = &event.data;
    let exception = data["exception"]["values"]
        .as_array()
        .and_then(|values| values.last());
    let frames = exception
        .and_then(|value| value["stacktrace"]["frames"].as_array())
        .filter(|frames| !frames.is_empty())
        .or_else(|| {
            data["threads"]["values"].as_array().and_then(|threads| {
                threads
                    .iter()
                    .find(|thread| thread["crashed"] == true)
                    .and_then(|thread| thread["stacktrace"]["frames"].as_array())
            })
        })
        .or_else(|| data["stacktrace"]["frames"].as_array());
    let mut stack = Vec::new();
    let mut selected = 0;
    let mut resolved = 0;
    let mut native = false;
    if let Some(frames) = frames {
        let has_app = frames.iter().any(|frame| frame["in_app"] == true);
        for frame in frames
            .iter()
            .rev()
            .filter(|frame| !has_app || frame["in_app"] == true)
            .take(5)
        {
            selected += 1;
            let status = string(&frame["symbolicator_status"]);
            native |= !status.is_empty();
            resolved += usize::from(status == "symbolicated");
            let function = ["function", "symbol", "instruction_addr"]
                .iter()
                .map(|key| string(&frame[*key]))
                .find(|value| !value.is_empty())
                .unwrap_or("unknown frame");
            let file = string(&frame["filename"])
                .rsplit(['/', '\\'])
                .next()
                .unwrap_or("");
            let location = match (file.is_empty(), frame["lineno"].as_u64()) {
                (false, Some(line)) => format!(" ({file}:{line})"),
                (false, None) => format!(" ({file})"),
                _ => String::new(),
            };
            let status = if status.is_empty() || status == "symbolicated" {
                String::new()
            } else {
                format!(" [{status}]")
            };
            stack.push(bounded(
                &format!("{function}{location}{status}").replace('`', "'"),
                180,
            ));
        }
    }
    let symbolication = if selected == 0 {
        "No stack frames reported".to_string()
    } else if native {
        format!("{resolved}/{selected} displayed native frames resolved")
    } else {
        "SDK frames; native symbolication status unavailable".to_string()
    };
    let exception_text = exception
        .map(|value| {
            let kind = string(&value["type"]);
            let message = string(&value["value"]);
            match (kind.is_empty(), message.is_empty()) {
                (false, false) => format!("{kind}: {message}"),
                (false, true) => kind.to_string(),
                _ => message.to_string(),
            }
        })
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| event.title());
    let operating_system = [
        string(&data["contexts"]["os"]["name"]),
        string(&data["contexts"]["os"]["version"]),
    ]
    .into_iter()
    .filter(|part| !part.is_empty())
    .collect::<Vec<_>>()
    .join(" ");
    let architecture = string(&data["contexts"]["device"]["arch"]);
    AlertEventInfo {
        id: event.event_id.to_string(),
        url: format!(
            "{}/projects/{}/issues/{}/events/{}",
            dashboard_url.trim_end_matches('/'),
            event.project_id,
            event.issue_id.map(|id| id.to_string()).unwrap_or_default(),
            event.id
        ),
        timestamp: event.timestamp,
        release: bounded(&event.release, 200),
        environment: bounded(&event.environment, 64),
        level: bounded(&event.level, 20),
        platform: bounded(&event.platform, 64),
        operating_system: bounded(&operating_system, 128),
        architecture: bounded(architecture, 64),
        exception: bounded(&exception_text, 1200),
        mechanism: exception
            .map(|value| bounded(string(&value["mechanism"]["type"]), 64))
            .unwrap_or_default(),
        handled: exception.and_then(|value| value["mechanism"]["handled"].as_bool()),
        stacktrace: bounded(&stack.join("\n"), 950),
        symbolication,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summaries_fit_message_limits_without_breaking_unicode() {
        assert_eq!(bounded("abcd", 4), "abcd");
        assert_eq!(bounded("abcdef", 4), "abc…");
        let text = bounded(&"\u{1F980}".repeat(600), 950);
        assert!(text.encode_utf16().count() <= 950);
        assert!(text.ends_with('…'));
    }
}
