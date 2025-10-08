use std::sync::LazyLock;

use chrono::Duration;

pub(crate) static MAX_TEMP_CREDS_DURATION: LazyLock<Duration> =
    LazyLock::new(|| Duration::seconds(3600));
