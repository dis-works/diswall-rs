use std::cmp::max;
use std::collections::HashMap;
use std::net::IpAddr;
use std::ops::Add;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime};
use ratatui::style::{Color, Style};
use ratatui::text::{Line, Span};
use serde::{Deserialize, Serialize};

#[allow(dead_code)]
pub struct State {
    pub blocked: Vec<Blocked>,
    pub mean: Vec<Blocked>,
    version: u64,
    mean_version: u64,
    pub logged_in: LoginState
}

#[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize)]
pub enum LoginState {
    Unknown,
    LoggedIn(String),
    Error(String),
    Default
}

#[allow(dead_code)]
impl State {
    pub fn new() -> Self {
        Self { blocked: Vec::new(), mean: Vec::new(), version: 0, mean_version: 0, logged_in: LoginState::Unknown }
    }

    pub fn add(&mut self, ip: IpAddr, port: Option<u16>, seconds: u64) {
        let blocked = Blocked::new(ip, port, seconds);
        self.add_blocked(blocked);
    }

    pub fn add_blocked(&mut self, mut blocked: Blocked) {
        match self.blocked.iter().rposition(|i| i.ip == blocked.ip) {
            None => {},
            Some(index) => {
                let item = self.blocked.remove(index);
                blocked.port = blocked.port.or(item.port);
                blocked.count += item.count;
            }
        }
        self.blocked.push(blocked);
        self.version += 1;
    }

    pub fn get_version(&self) -> u64 {
        self.version
    }

    pub fn get_strings(&self, last: Option<usize>) -> Vec<String> {
        match last {
            None => {
                self.blocked.iter().map(|b| b.to_string()).collect()
            }
            Some(last) => {
                let skip = max(0, self.blocked.len() - last);
                self.blocked.iter().skip(skip).map(|b| b.to_string()).collect()
            }
        }
    }

    pub fn get_blocked(&self, start_id: u64) -> Vec<Blocked> {
        if start_id == 0 {
            return self.blocked.clone();
        }
        let start = start_id + 1;
        match self.blocked.binary_search_by(|s| s.id.cmp(&start)) {
            Ok(index) | Err(index) => self.blocked[index..].to_vec(),
        }
    }

    pub fn compute_mean(&mut self) {
        if self.mean_version == self.version {
            return;
        }
        let mut map: HashMap<IpAddr, Blocked> = HashMap::new();
        for item in self.blocked.iter() {
            // If there already is such IP we merge the data
            if let Some(i) = map.remove(&item.ip) {
                let port = item.port.or(i.port);
                let at = i.at;
                let until = i.until;
                let id = i.id;
                map.insert(i.ip, Blocked { id, at, ip: i.ip, until, port, count: 1 });
            } else {
                map.insert(item.ip, item.clone());
            }
        }
        self.mean = map.into_values().collect();
        self.mean.sort_by(| a, b| a.id.cmp(&b.id));
        self.mean_version = self.version;
    }
}

pub static BLOCKED_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
pub struct Blocked {
    pub id: u64,
    pub at: SystemTime,
    pub ip: IpAddr,
    pub port: Option<u16>,
    pub until: SystemTime,
    #[serde(default)]
    pub count: usize
}

#[allow(dead_code)]
impl Blocked {
    pub fn new(ip: IpAddr, port: Option<u16>, seconds: u64) -> Self {
        let id = BLOCKED_ID.fetch_add(1, Ordering::SeqCst);
        let at = SystemTime::now();
        let until = at.add(Duration::from_secs(seconds));
        Self { id, at, ip, port, until, count: 1 }
    }

    pub fn is_blocked_now(&self, now: &SystemTime) -> bool {
        self.until > *now
    }

    pub fn is_blocked_after(&self, start: &SystemTime) -> bool {
        self.at >= *start
    }

    pub fn is_local(&self) -> bool {
        self.port.is_some()
    }

    pub fn is_found(&self, text: &str) -> bool {
        self.ip.to_string().contains(text)
    }

    pub fn to_line(&self) -> Line {
        let mut buf = Vec::new();
        let text = match &self.port {
            None => String::new(),
            Some(port) => format!(" ({port})")
        };
        let color = match text.is_empty() {
            true => Color::White,
            false => Color::LightYellow
        };
        let span1 = Span::styled(
            format!("{} until {} {}{}", time_to_str(&self.at), time_to_str(&self.until), &self.ip, &text),
            Style::default().fg(color)
        );
        buf.push(span1);

        if self.count > 1 {
            buf.push(Span::styled(format!(" {} times", self.count), Style::default().fg(Color::LightBlue)));
        }
        Line::from(buf)
    }
}

impl ToString for Blocked {
    fn to_string(&self) -> String {
        let mut res = match &self.port {
            None => format!("► {} until {} {}", time_to_str(&self.at), time_to_str(&self.until), &self.ip),
            Some(port) => format!("◄ {} until {} {} ({port})", time_to_str(&self.at), time_to_str(&self.until), &self.ip)
        };
        if self.count > 1 {
            res.push_str(&format!(" {} times", self.count));
        }
        res
    }
}

fn time_to_str(system_time: &SystemTime) -> String {
    let duration_since_epoch = system_time.duration_since(std::time::UNIX_EPOCH).unwrap_or_else(|_| Duration::new(0, 0));
    let format = time::format_description::parse_borrowed::<1>("[year]-[month]-[day] [hour]:[minute]:[second]").unwrap();

    let formatted_time = time::OffsetDateTime::from_unix_timestamp(0).unwrap() + duration_since_epoch;
    formatted_time.format(&format).unwrap()
}