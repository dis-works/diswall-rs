use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::sync::{Arc, Mutex};
use std::sync::atomic::AtomicU32;
use std::thread;
use std::time::Duration;
use log::{debug, error, info};
use lru::LruCache;
use nats::Connection;
use time::PrimitiveDateTime;
use crate::config::Config;
use crate::{DEFAULT_BLOCK_TIME_SEC, process_ip};
use crate::state::{Blocked, State};

const WL: &str = include_str!("whitelist.txt");
const BL: &str = include_str!("blacklist.txt");

/// Opens an Nginx error log file, parses it line by line and sends IPs of intruders to the specified pipe
pub fn process_log_file(config: Config, nats: Option<Connection>, banned_count: Arc<AtomicU32>, cache: Arc<Mutex<LruCache<String, bool>>>, state: Arc<Mutex<State>>, file_name: String) {
    let mut file = match File::open(&file_name) {
        Ok(file) => file,
        Err(error) => {
            error!("Error opening file: {}", error);
            return;
        }
    };
    let _ = file.seek(SeekFrom::End(0));
    let mut inode = get_inode(&file);

    let wl = WL.lines().collect::<HashSet<_>>();
    let bl = BL.lines().collect::<HashSet<_>>();
    let mut scores: HashMap<String, f32> = HashMap::new();

    // Create a buffered reader to read the file line-by-line
    let mut reader = BufReader::new(file);
    let mut buffer = String::new();
    loop {
        match reader.read_line(&mut buffer) {
            Ok(size) => {
                if size > 0 {
                    if buffer.ends_with('\n') {
                        process_log_line(&buffer, &wl, &bl, &mut scores, &config.ignore_ips);
                        let mut gotchas = Vec::new();
                        for (client, score) in &scores {
                            if *score >= 0.7 {
                                gotchas.push(client.to_owned());
                            }
                        }
                        for client in gotchas {
                            let score = scores.remove(&client).unwrap();
                            debug!("Baning http bot {} -> {:.2}", &client, score);
                            let ban = format!("{}|http", &client);
                            process_ip(&config, &nats, &banned_count, &cache, &config.ipset_black_list, &ban);
                            if let Ok(mut state) = state.lock() {
                                if let Ok(ip) = client.parse() {
                                    let blocked = Blocked::new(ip, None, DEFAULT_BLOCK_TIME_SEC);
                                    state.add_blocked(blocked);
                                }
                            }
                        }
                    }
                } else {
                    // Probably we have EOF
                    thread::sleep(Duration::from_millis(200));
                    let mut file = match File::open(&file_name) {
                        Ok(file) => file,
                        Err(error) => {
                            error!("Error opening file: {}", error);
                            return;
                        }
                    };

                    let new_inode = get_inode(&file);
                    if new_inode != inode {
                        info!("Log file rotated, reopening new file");
                        let _ = file.seek(SeekFrom::End(0));
                        reader = BufReader::new(file);
                        inode = new_inode;
                    }
                    // Check if this log has been rotated
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
fn get_inode(file: &File) -> u64 {
    #[cfg(target_os = "linux")]
    if let Ok(meta) = file.metadata() {
        use std::os::unix::fs::MetadataExt;
        return meta.ino();
    }
    0u64
}

/// Process the log line
fn process_log_line(line: &String, wl: &HashSet<&str>, bl: &HashSet<&str>, scores: &mut HashMap<String, f32>, ignore_ips: &Vec<String>) {
    let line = LogLine::new(&line);
    match line {
        None => {
            //println!("Line: {}", line.);
        }
        Some(line) => {
            if ignore_ips.contains(&line.client) {
                debug!("Ignoring IP {}", &line.client);
                return;
            }
            //println!("Line.request: {}, path: {}, client: {}", &line.request, line.get_path(), &line.client);
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

struct LogLine {
    datetime: PrimitiveDateTime,
    #[allow(dead_code)]
    error: String,
    client: String,
    server: String,
    request: String,
    host: String,
    referrer: String
}

impl LogLine {
    fn new(line: &str) -> Option<LogLine> {
        let start = if line.contains("open()") {
            line.find("open()").unwrap()
        } else if line.contains("FastCGI") {
            line.find("FastCGI").unwrap()
        } else {
            0
        };

        let time = line[0..line.find("[").unwrap()-1].to_owned();
        let mut log_line = LogLine::default();

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

impl Default for LogLine {
    fn default() -> Self {
        LogLine {
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
    return match s.find(": ") {
        None => s.to_owned(),
        Some(pos) => {
            s[pos + 2..].to_owned()
        }
    }
}