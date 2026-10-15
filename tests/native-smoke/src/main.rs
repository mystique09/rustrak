use std::{path::PathBuf, sync::Arc, time::Duration};

use sentry_minidump::MinidumpIntegration;

#[inline(never)]
fn native_crash_leaf() {
    let address = std::hint::black_box(1usize);
    unsafe {
        std::ptr::write_volatile(address as *mut u8, 42);
    }
}

#[inline(never)]
fn native_crash_middle() {
    native_crash_leaf();
    std::hint::black_box(42);
}

fn main() {
    let dsn = std::env::var("SENTRY_DSN").expect("SENTRY_DSN must point to a local QA server");
    assert!(
        dsn.starts_with("http://") && (dsn.contains("@127.0.0.1:") || dsn.contains("@localhost:")),
        "Only loopback QA DSNs are allowed"
    );
    let directory =
        PathBuf::from(std::env::var_os("NATIVE_SMOKE_DIR").expect("NATIVE_SMOKE_DIR is required"));
    let integration = Arc::new(
        MinidumpIntegration::new()
            .crashes_dir(directory)
            .client_connect_timeout(Duration::from_secs(10))
            .flush_timeout(Duration::from_secs(30)),
    );
    let mut options = sentry::ClientOptions::new()
        .dsn(dsn.as_str())
        .release("rustrak-native-smoke@1")
        .environment("native-qa");
    options.integrations.push(integration.clone());
    let _guard = sentry::init(options);
    integration.set_tag("native_smoke".to_owned(), Some("true".to_owned()));
    integration.add_breadcrumb(sentry::Breadcrumb {
        message: Some("before native crash".to_owned()),
        ..Default::default()
    });
    native_crash_middle();
}
