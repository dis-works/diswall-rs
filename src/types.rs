use serde::{Deserialize, Serialize};

/// Statistics representation
#[derive(Default, Serialize, Deserialize, Debug)]
pub struct Stats {
    pub(crate) time: i64,
    pub(crate) banned: u32,
    #[serde(default)]
    pub(crate) packets_dropped: u64,
    #[serde(default)]
    pub(crate) bytes_dropped: u64,
    #[serde(default)]
    pub(crate) packets_accepted: u64,
    #[serde(default)]
    pub(crate) bytes_accepted: u64,
}

impl Stats {
    pub fn copy_from(&mut self, other: &Self) {
        self.time = other.time;
        self.banned = other.banned;
        self.bytes_dropped = other.bytes_dropped;
        self.bytes_accepted = other.bytes_accepted;
        self.packets_dropped = other.packets_dropped;
        self.packets_accepted = other.packets_accepted;
    }
}