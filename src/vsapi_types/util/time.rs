use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Convert a visa expiration timestamp (seconds since UNIX epoch) to SystemTime.
pub fn visa_expiration_timestamp_to_system_time(timestamp: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(timestamp)
}
