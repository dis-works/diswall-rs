use serde::{Deserialize, Serialize};
use crate::state::Blocked;

#[derive(Debug, PartialEq, Deserialize, Serialize)]
pub enum StateMessage {
    Ping,
    Changed,
    GetBlocked(u32),
    Blocked(Vec<Blocked>)
}