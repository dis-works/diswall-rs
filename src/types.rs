use serde::{Deserialize, Serialize};

/// Statistics representation
#[derive(Default, Serialize, Deserialize, Debug)]
pub struct Stats {
    pub(crate) time: i64,
    pub(crate) banned: u32,
    pub(crate) packets_dropped: u64,
    pub(crate) bytes_dropped: u64,
    pub(crate) packets_accepted: u64,
    pub(crate) bytes_accepted: u64,
}