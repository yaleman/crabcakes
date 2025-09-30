pub mod auth;
pub mod cli;
pub mod credentials;
pub mod error;
pub mod filesystem;
pub mod policy;
pub mod s3_handlers;
pub mod server;
pub mod xml_responses;

#[cfg(test)]
mod tests;

#[cfg(test)]
pub fn setup_test_logging() {
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;

    let _ = tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .with_target(true)
                .with_thread_ids(false)
                .with_test_writer()
                .with_level(true),
        )
        .with(tracing_subscriber::EnvFilter::new("debug,russh::client=info,russh::sshbuffer=info,russh::keys::agent::client=info,russh::keys::agent=info"))
        .try_init();
}
