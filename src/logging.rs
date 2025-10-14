//! Logging setup for the application
//!

use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

// Initialize tracing subscriber
pub fn setup_logging() {
    // Initialize tracing subscriber
    let log_level = std::env::var("RUST_LOG").unwrap_or("info".to_string());
    let log_level_sqlx = std::env::var("RUST_LOG_SQLX").unwrap_or("warn".to_string());
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(format!(
            "crabcakes={log_level},scratchstack_aws_signature=debug,tower_http=info,h2=warn,sqlx={log_level_sqlx}",
        )))
        .with(tracing_subscriber::fmt::layer())
        .init();
}

#[cfg(test)]
pub(crate) fn setup_test_logging() {
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;

    let _ = tracing_subscriber::registry()
        .with(
             tracing_subscriber::fmt::layer()
        .with_target(true)
        .with_thread_ids(false)
        .with_test_writer()
        .with_level(true)
        )
        .with(tracing_subscriber::EnvFilter::new("debug,russh::client=info,russh::sshbuffer=info,russh::keys::agent::client=info,russh::keys::agent=info,h2::codec=warn"))
        .try_init();
}
