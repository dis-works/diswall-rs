use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv6Addr};
use std::ops::SubAssign;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::AtomicU32;
use std::time::Duration;
use async_nats::Client;
use log::{debug, error, info, warn};
use lru::LruCache;
use time::PrimitiveDateTime;
use tokio::fs::File;
use tokio::io::{AsyncBufReadExt, AsyncSeekExt, BufReader, SeekFrom};
use tokio::sync::RwLock;
use tokio::time::{sleep, Instant};
use crate::config::Config;
use crate::{DEFAULT_BLOCK_TIME_SEC, process_ip};
use crate::state::{Blocked, State};

const WL: &str = include_str!("whitelist.txt");
const BL: &str = include_str!("blacklist.txt");

/// Opens an Nginx error log file, parses it line by line and sends IPs of intruders to the specified pipe
pub async fn process_log_file(config: Config, nats: Option<Client>, banned_count: Arc<AtomicU32>, cache: Arc<RwLock<LruCache<String, bool>>>, state: Arc<RwLock<State>>, file_name: String, log_type: LogType) {
    info!("Opening {file_name} as {:?} log", &log_type);
    
    let mut file = match File::open(&file_name).await {
        Ok(file) => file,
        Err(error) => {
            error!("Error opening file: {}", error);
            return;
        }
    };
    let _ = file.seek(SeekFrom::End(0)).await;
    let mut inode = get_inode(&file).await;

    let wl = WL.lines().collect::<HashSet<_>>();
    let bl = BL.lines().collect::<HashSet<_>>();
    let mut scores: HashMap<String, f32> = HashMap::new();
    let mut times: HashMap<String, (Instant, f32)> = HashMap::new();
    let mut subnets = Subnets::default();

    // Create a buffered reader to read the file line-by-line
    let mut reader = BufReader::new(file);
    let mut buffer = String::new();
    loop {
        match reader.read_line(&mut buffer).await {
            Ok(size) => {
                if size > 0 {
                    if buffer.ends_with('\n') {
                        let mut block_time = DEFAULT_BLOCK_TIME_SEC;
                        let mut gotchas = Vec::new();
                        let mut tag = "http";
                        match log_type {
                            LogType::AccessLog => {
                                process_access_log_line(&buffer, &mut times, &config.ignore_ips);
                                for (client, (time, score)) in &times {
                                    let seconds = time.elapsed().as_secs();
                                    info!("Score: {score}, seconds {seconds}");
                                    let total_score = match subnets.get_subnet_ips_count(client) {
                                        0 => 1.0,
                                        count => count as f32
                                    };
                                    if seconds >= 60 && (*score * total_score) >= seconds as f32 {
                                        info!("=== Score: {}", *score);
                                        gotchas.push(client.to_owned());
                                        subnets.add_ip(client);
                                    }
                                }
                                block_time = 60;
                                tag = "waf";
                            }
                            LogType::ErrorLog => {
                                process_error_log_line(&buffer, &wl, &bl, &mut scores, &config.ignore_ips);
                                for (client, score) in &scores {
                                    if *score >= 0.7 {
                                        gotchas.push(client.to_owned());
                                    }
                                }
                            }
                        }
                        for client in gotchas {
                            match log_type {
                                LogType::AccessLog => {
                                    let (time, score) = times.remove(&client).unwrap();
                                    debug!("Baning http bot for DoS {} -> {:.2} for {}s", &client, score, time.elapsed().as_secs());
                                }
                                LogType::ErrorLog => {
                                    let score = scores.remove(&client).unwrap();
                                    debug!("Baning http bot {} -> {:.2}", &client, score);
                                }
                            }
                            info!("Banning {client}");
                            let ban = format!("{}|{tag}", &client);
                            process_ip(&config, &nats, &banned_count, &cache, &config.ipset_black_list, &ban).await;
                            if let Ok(ip) = client.parse() {
                                let mut state = state.write().await;
                                let blocked = Blocked::new(ip, None, block_time);
                                state.add_blocked(blocked);
                            }
                        }
                        buffer.clear();
                    }
                } else {
                    // Probably we have EOF
                    sleep(Duration::from_millis(100)).await;
                    let mut file = match File::open(&file_name).await {
                        Ok(file) => file,
                        Err(error) => {
                            error!("Error opening file: {}", error);
                            return;
                        }
                    };

                    // Check if this log has been rotated
                    let new_inode = get_inode(&file).await;
                    if new_inode != inode {
                        info!("Log file rotated, reopening new file");
                        let _ = file.seek(SeekFrom::End(0)).await;
                        reader = BufReader::new(file);
                        inode = new_inode;
                    }
                }
            }
            Err(e) => {
                error!("Error reading log: {}", e);
                return;
            }
        }
    }
}

#[allow(unused_variables)]
async fn get_inode(file: &File) -> u64 {
    #[cfg(target_os = "linux")]
    if let Ok(meta) = file.metadata().await {
        use std::os::unix::fs::MetadataExt;
        return meta.ino();
    }
    0u64
}

/// Process the access-log line
fn process_access_log_line(line: &str, scores: &mut HashMap<String, (Instant, f32)>, ignore_ips: &Vec<String>) {
    let client_ip = parse_client_ip(line);
    debug!("Got IP {client_ip}");
    if ignore_ips.contains(&client_ip) {
        debug!("Ignoring {client_ip}");
        return;
    }
    
    let (request_time, backend_response_time) = parse_access_times(line);
    debug!("Request time: {request_time}, backend: {:?}", &backend_response_time);
    if backend_response_time.is_some() && request_time > 0.0 {
        let backend_time = backend_response_time.unwrap();
        if let Some((_time, score)) = scores.get_mut(&client_ip) {
            *score += backend_time;
            info!("{client_ip} got {score}");
        } else {
            let mut start_time = Instant::now();
            start_time.sub_assign(Duration::from_secs(backend_time as u64));
            scores.insert(client_ip, (start_time, backend_time));
        }
    }
}

/// Process the log line
fn process_error_log_line(line: &String, wl: &HashSet<&str>, bl: &HashSet<&str>, scores: &mut HashMap<String, f32>, ignore_ips: &Vec<String>) {
    let line = ErrorLogLine::new(&line);
    match line {
        None => {}
        Some(line) => {
            if ignore_ips.contains(&line.client) {
                debug!("Ignoring IP {}", &line.client);
                return;
            }
            debug!("Line.request: {}, path: {}, client: {}", &line.request, line.get_path(), &line.client);
            let path = line.get_path();
            if wl.contains(&path) {
                if let Some(val) = scores.get_mut(&line.client) {
                    *val -= 0.5;
                } else {
                    scores.insert(line.client.clone(), -0.5);
                }
            }
            if bl.contains(&path) {
                if let Some(val) = scores.get_mut(&line.client) {
                    *val += 1.0;
                } else {
                    scores.insert(line.client.clone(), 1.0);
                }
            }
            if line.server == "_" {
                if let Some(val) = scores.get_mut(&line.client) {
                    *val += 0.3;
                } else {
                    scores.insert(line.client.clone(), 0.3);
                }
            }
            if path.contains("/wp-") && !(path.ends_with(".jpg") || path.ends_with(".jpeg") || path.ends_with(".png")) {
                if let Some(val) = scores.get_mut(&line.client) {
                    *val += 0.3;
                } else {
                    scores.insert(line.client.clone(), 0.3);
                }
            }
            if path.contains("shell") || path.contains("exec") || path.contains("wget") || path.contains(".sql") || path.contains(".db") {
                if let Some(val) = scores.get_mut(&line.client) {
                    *val += 1.0;
                } else {
                    scores.insert(line.client.clone(), 1.0);
                }
            }
            if path.ends_with(".php") {
                if let Some(val) = scores.get_mut(&line.client) {
                    *val += 0.3;
                } else {
                    scores.insert(line.client.clone(), 0.3);
                }
            }
        }
    }
}

struct ErrorLogLine {
    datetime: PrimitiveDateTime,
    #[allow(dead_code)]
    error: String,
    client: String,
    server: String,
    request: String,
    host: String,
    referrer: String
}

impl ErrorLogLine {
    fn new(line: &str) -> Option<ErrorLogLine> {
        let start = if line.contains("open()") {
            line.find("open()").unwrap()
        } else if line.contains("FastCGI") {
            line.find("FastCGI").unwrap()
        } else {
            0
        };

        let time = line[0..line.find("[").unwrap()-1].to_owned();
        let mut log_line = ErrorLogLine::default();

        let format = time::macros::format_description!("[year]/[month]/[day] [hour]:[minute]:[second]");
        if let Ok(date) = PrimitiveDateTime::parse(&time, &format) {
            log_line.datetime = date;
        }

        let parts = line[start..].split(", ").collect::<Vec<_>>();
        for p in parts {
            if p.starts_with("client:") {
                log_line.client = get_val(p);
            } else if p.starts_with("server:") {
                log_line.server = get_val(p).replace("\"", "");
            } else if p.starts_with("host:") {
                log_line.host = get_val(p);
            } else if p.starts_with("request:") {
                log_line.request = get_val(p).replace("\"", "");
            } else if p.starts_with("referrer:") {
                log_line.referrer = get_val(p).replace("\"", "");
            }
        }

        Some(log_line)
    }

    fn get_path(&self) -> &str {
        if self.request.is_empty() {
            return &self.request;
        }
        let pos1 = self.request.find(' ').unwrap_or_default();
        let pos2 = self.request.rfind(' ').unwrap_or(self.request.len()-1);
        &self.request[pos1 + 1..pos2]
    }
}

impl Default for ErrorLogLine {
    fn default() -> Self {
        ErrorLogLine {
            datetime: PrimitiveDateTime::MIN,
            error: String::new(),
            client: String::new(),
            server: String::new(),
            request: String::new(),
            host: String::new(),
            referrer: String::new(),
        }
    }
}

fn get_val(s: &str) -> String {
    match s.find(": ") {
        None => s.to_owned(),
        Some(pos) => {
            s[pos + 2..].to_owned()
        }
    }
}

fn parse_client_ip(log_line: &str) -> String {
    log_line
        .split_whitespace()
        .next()
        .and_then(|ip_str| Some(ip_str.to_owned()))
        .unwrap_or(String::new())
}

/// Gets request_time & upstream_response_time from Nginx's log.
fn parse_access_times(log_line: &str) -> (f32, Option<f32>) {
    let mut parts = log_line.split_whitespace().rev(); // Разбираем строку с конца

    let upstream_time = parts.next().and_then(|s| {
        if s == "-" {
            None
        } else {
            f32::from_str(s).ok()
        }
    });
    
    let request_time = parts
        .next()
        .and_then(|s| f32::from_str(s).ok())
        .unwrap_or(0.0);

    (request_time, upstream_time)
}

#[derive(Debug)]
pub enum LogType {
    AccessLog,
    ErrorLog,
}

#[derive(Default)]
struct Subnets {
    nets: HashMap<String, Vec<u8>>
}

impl Subnets {
    pub fn add_ip(&mut self, ip: &str) {
        match ip.parse::<IpAddr>() {
            Ok(ip) => {
                let (subnet, last_byte) = Self::parse_subnet(ip);
                match self.nets.get_mut(&subnet) {
                    None => {
                        self.nets.insert(subnet, vec![last_byte]);
                    }
                    Some(bytes) => {
                        if !bytes.contains(&last_byte) {
                            bytes.push(last_byte);
                            bytes.sort();
                        }
                    }
                }
            }
            Err(e) => {
                warn!("Couldn't parse IP from '{ip}: {e}'");
            }
        }
    }

    #[allow(dead_code)]
    pub fn found(&self, ip: &str) -> bool {
        match ip.parse::<IpAddr>() {
            Ok(ip) => {
                let (subnet, last_byte) = Self::parse_subnet(ip);
                match self.nets.get(&subnet) {
                    None => {}
                    Some(bytes) => {
                        if bytes.contains(&last_byte) {
                            return true;
                        }
                    }
                }
            }
            Err(e) => {
                warn!("Couldn't parse IP from '{ip}: {e}'");
            }
        }
        false
    }
    
    pub fn get_subnet_ips_count(&self, ip: &str) -> u8 {
        match ip.parse::<IpAddr>() {
            Ok(ip) => {
                let (subnet, _last_byte) = Self::parse_subnet(ip);
                match self.nets.get(&subnet) {
                    None => {}
                    Some(bytes) => {
                        return bytes.len() as u8;
                    }
                }
            }
            Err(e) => {
                warn!("Couldn't parse IP from '{ip}: {e}'");
            }
        }
        0
    }

    fn parse_subnet(ip: IpAddr) -> (String, u8) {
        match ip {
            IpAddr::V4(ip) => {
                let octets = ip.octets();
                (format!("{}.{}.{}.{}", octets[0], octets[1], octets[2], octets[3]), octets[3])
            }
            IpAddr::V6(ip) => {
                let mut octets = ip.octets();
                let last = octets[15];
                octets[15] = 0;
                (Ipv6Addr::from(octets).to_string(), last)
            }
        }
    }
}