use std::fs::File;
use std::hash::Hasher;
use std::io::{BufRead, BufReader};
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use log::{debug, error, info, trace, warn};
use nats::Connection;
use sqlite::State;
use time::OffsetDateTime;
use ureq::Agent;
use crate::{Config, Stats};
use crate::config::{PREFIX_BL, PREFIX_STATS, PREFIX_WL};

pub const DB_NAME: &str = "diswall.db";
pub const CREATE_DB: &str = include_str!("../data/create_db.sql");
pub const CHECK_DB: &str = "SELECT name FROM sqlite_master WHERE type='table' AND name='data';";
pub const TUNE_DB: &str = "pragma temp_store = memory;\npragma mmap_size = 1073741824;";
pub const GET_LIST: &str = "SELECT ip, until FROM data WHERE client=? AND hostname=? AND blacklist=? AND until>?;";
pub const ADD_TO_LIST: &str = "INSERT INTO data (client, hostname, blacklist, ip, until) VALUES (?, ?, ?, ?, ?);";
pub const COUNT_LIST: &str = "SELECT COUNT(ip) FROM data WHERE client=? AND hostname=? AND blacklist=? AND until>?;";
pub const UPDATE_IN_LIST: &str = "UPDATE data SET until=? WHERE client=? AND blacklist=? AND ip=?;";
pub const GET_COUNT: &str = "SELECT COUNT(ip) FROM data WHERE client=? AND blacklist=? AND ip=?;";
pub const DELETE_FROM_LIST: &str = "DELETE FROM data WHERE client=? AND hostname=? AND blacklist=? AND ip=?;";
const DEFAULT_TIMEOUT: i64 = 86400;

pub fn run_server(config: Config, nats: Option<Connection>) {
    if nats.is_none() {
        error!("Cannot work in server mode without NATS connection");
        return;
    }
    info!("Starting DisWall server...", );

    let db = sqlite::open(DB_NAME).expect("Unable to open sqlite database!");
    create_db_if_needed(&db);
    let db = Arc::new(Mutex::new(db));

    let nats = nats.unwrap();
    if let Ok(sub) = nats.subscribe(&config.nats.wl_init_subject) {
        let db = db.clone();
        sub.with_handler(move |message| {
            let (client, hostname) = get_user_and_host(&message.subject);
            info!("Got wl init request from {}/{}", &client, &hostname);
            let buffer = match db.lock() {
                Ok(db) => get_list(&db, &client, &hostname, false),
                Err(_) => String::new()
            };
            if let Err(e) = message.respond(buffer.as_bytes()) {
                warn!("Error sending {} to {}: {}", &message.subject, &client, e);
            }
            Ok(())
        });
        info!("Subscribed to {}", &config.nats.wl_init_subject);
    }

    if let Ok(sub) = nats.subscribe(&config.nats.bl_init_subject) {
        let db = db.clone();
        sub.with_handler(move |message| {
            let (client, hostname) = get_user_and_host(&message.subject);
            info!("Got bl init request from {}/{}", &client, &hostname);
            let buffer = match db.lock() {
                Ok(db) => {
                    // We get two lists from DB: global list (from honeypots) and individual list from that client/host
                    let global_list = get_list(&db, "", "", true);
                    let my_list = get_list(&db, &client, &hostname, true);
                    format!("{}\n{}", global_list, my_list)
                },
                Err(_) => String::new()
            };
            if let Err(e) = message.respond(buffer.as_bytes()) {
                warn!("Error sending {} to {}: {}", &message.subject, &client, e);
            }
            Ok(())
        });
        info!("Subscribed to {}", &config.nats.bl_init_subject);
    }

    // Subscribe to new IPs for whitelist
    if let Ok(sub) = nats.subscribe(&config.nats.wl_add_subject) {
        let db = db.clone();
        sub.with_handler(move |message| {
            debug!("Got message on {}", &message.subject);
            let (client, hostname) = get_user_and_host(&message.subject);
            if let Ok(string) = String::from_utf8(message.data) {
                if !valid_ip(&string) {
                    warn!("Could not parse IP {} from {}", &string, &client);
                    return Ok(());
                }
                if let Ok(db) = db.lock() {
                    if let Err(e) = add_to_list(&db, &client, &hostname, false, &string, DEFAULT_TIMEOUT) {
                        warn!("Error adding to DB: {}", e);
                    }
                }
            }
            Ok(())
        });
        info!("Subscribed to {}", &config.nats.wl_add_subject);
    }

    let agent = ureq::AgentBuilder::new()
        .user_agent(&format!("DisWall v{}", env!("CARGO_PKG_VERSION")))
        .timeout(Duration::from_secs(3))
        .max_idle_connections_per_host(4)
        .max_idle_connections(16)
        .build();

    // Subscribe for new IPs for blocklist
    if let Ok(sub) = nats.subscribe(&config.nats.bl_add_subject) {
        let db = db.clone();
        let nats = nats.clone();
        let config = config.clone();
        let agent = agent.clone();
        let subject = config.nats.bl_add_subject.clone();
        sub.with_handler(move |message| {
            let (client, hostname) = get_user_and_host(&message.subject);
            debug!("Got message on {} from {:?}", &message.subject, (&client, &hostname));
            if let Ok(ip) = String::from_utf8(message.data) {
                if !valid_ip(&ip) {
                    warn!("Could not parse IP {} from {}", &ip, &client);
                    return Ok(());
                }
                let time = OffsetDateTime::now_utc().unix_timestamp();
                let client_mix = mix_client(format!("{}/{}/{}", &client, &hostname, &config.clickhouse.salt).as_bytes());
                // If this IP was sent by one of our honeypots we add this IP without client and hostname
                let (client, hostname, honeypot) = match config.nats.honeypots.contains(&client) {
                    true => (String::new(), String::new(), true),
                    false => (client, hostname, false)
                };
                if let Ok(db) = db.lock() {
                    if let Err(e) = add_to_list(&db, &client, &hostname, true, &ip, DEFAULT_TIMEOUT) {
                        warn!("Error adding to DB: {}", e);
                    }
                }
                if honeypot {
                    match nats.publish(&config.nats.bl_global_subject, &ip) {
                        Ok(_) => info!("Pushed {} to [{}]", &ip, &config.nats.bl_global_subject),
                        Err(e) => warn!("Error pushing {} to [{}]: {}", &ip, &config.nats.bl_global_subject, e)
                    }
                }
                let request = format!("INSERT INTO scanners VALUES ({}, {}, '{}')", &client_mix, time, &ip);
                send_clickhouse_request(&agent, &config, &request);
                let request = format!("INSERT INTO nats_data (client, hostname, blacklist, ip, until) VALUES ('{}', '{}', {}, '{}', {})", &client, &hostname, 1, &ip, time + 86400);
                send_clickhouse_request(&agent, &config, &request);
            }
            Ok(())
        });
        info!("Subscribed to {}", &subject);
    }

    // Subscribe for IPs to delete from whitelist
    if let Ok(sub) = nats.subscribe(&config.nats.wl_del_subject) {
        let db = db.clone();
        sub.with_handler(move |message| {
            let (client, hostname) = get_user_and_host(&message.subject);
            debug!("Got message on {} from {:?}", &message.subject, (&client, &hostname));
            if let Ok(string) = String::from_utf8(message.data) {
                if !valid_ip(&string) {
                    warn!("Could not parse IP {} from {}", &string, &client);
                    return Ok(());
                }
                if let Ok(db) = db.lock() {
                    if let Err(e) = delete_from_list(&db, &client, &hostname, false, &string) {
                        warn!("Error removing from DB: {}", e);
                    }
                }
            }
            Ok(())
        });
        info!("Subscribed to {}", &config.nats.wl_del_subject);
    }

    // Subscribe for IPs to delete from blocklist
    if let Ok(sub) = nats.subscribe(&config.nats.bl_del_subject) {
        let db = db.clone();
        sub.with_handler(move |message| {
            let (client, hostname) = get_user_and_host(&message.subject);
            debug!("Got message on {} from {:?}", &message.subject, (&client, &hostname));
            if let Ok(string) = String::from_utf8(message.data) {
                if !valid_ip(&string) {
                    warn!("Could not parse IP {} from {}", &string, &client);
                    return Ok(());
                }
                if let Ok(db) = db.lock() {
                    if let Err(e) = delete_from_list(&db, &client, &hostname, true, &string) {
                        warn!("Error removing from DB: {}", e);
                    }
                }
            }
            Ok(())
        });
        info!("Subscribed to {}", &config.nats.bl_del_subject);
    }

    if config.send_statistics && !config.clickhouse.url.is_empty() {
        start_stats_handler(&config, nats.clone(), agent);
    }

    // If there is readable pipe to read we read it in a loop
    if let Ok(f) = File::open(&config.pipe_path) {
        let mut reader = BufReader::new(f);
        info!("Pipe opened, waiting for IPs");

        let mut line = String::new();
        let mut timer = Instant::now();
        let delay = Duration::from_millis(5);
        loop {
            if let Ok(len) = reader.read_line(&mut line) {
                if len > 0 {
                    let ip = line.trim().to_owned();
                    let (ip, timeout) = if ip.contains(" ") {
                        let parts = ip.split(" ").collect::<Vec<_>>();
                        (parts[0].to_owned(), parts[1].parse::<i64>().unwrap_or(DEFAULT_TIMEOUT))
                    } else {
                        (ip, DEFAULT_TIMEOUT)
                    };
                    info!("Got new IP from server pipe: {}", &ip);
                    if let Ok(db) = db.lock() {
                        let _ = add_to_list(&db, "", "", true, &ip, timeout);
                    }
                    let msg = if timeout == DEFAULT_TIMEOUT {
                        ip
                    } else {
                        let timeout = if timeout > 2147483 {
                            2147483
                        } else {
                            timeout
                        };
                        format!("{} timeout {}", &ip, timeout)
                    };
                    match nats.publish(&config.nats.bl_global_subject, &msg) {
                        Ok(_) => info!("Pushed {} to [{}]", &msg, &config.nats.bl_global_subject),
                        Err(e) => warn!("Error pushing {} to [{}]: {}", &msg, &config.nats.bl_global_subject, e)
                    }
                } else {
                    thread::sleep(delay);
                    if timer.elapsed().as_secs() >= 300 {
                        if let Ok(db) = db.lock() {
                            let count = count_list(&db, "", "", true);
                            info!("Currently blocked IP count: {}", count);
                        }
                        timer = Instant::now();
                    }
                }
            }
            line.clear();
        }
    } else {
        // If there is no pipe we just loop here until we die
        let delay = Duration::from_secs(1);
        let mut timer = Instant::now();
        loop {
            thread::sleep(delay);
            if timer.elapsed().as_secs() >= 300 {
                if let Ok(db) = db.lock() {
                    let count = count_list(&db, "", "", true);
                    info!("Currently blocked IP count: {}", count);
                }
                timer = Instant::now();
            }
        }
    }
}

fn start_stats_handler(config: &Config, nats: Connection, agent: Agent) {
    // Subscribe for IPs to delete from blocklist
    if let Ok(sub) = nats.subscribe(&config.nats.stats_subject) {
        let config = config.clone();
        let subject = config.nats.stats_subject.clone();
        sub.with_handler(move |message| {
            let (client, hostname) = get_user_and_host(&message.subject);
            debug!("Got message on {} from {:?}", &message.subject, (&client, &hostname));
            if let Ok(string) = String::from_utf8(message.data) {
                match serde_json::from_str::<Stats>(&string) {
                    Ok(stats) => {
                        let request = format!("INSERT INTO stats VALUES ('{}/{}', {}, {}, {}, {}, {}, {})",
                                              &client, &hostname, stats.time, stats.banned,
                                              stats.packets_dropped, stats.bytes_dropped,
                                              stats.packets_accepted, stats.bytes_accepted);
                        send_clickhouse_request(&agent, &config, &request);
                    }
                    Err(e) => error!("Could not deserialize stats from {}: {}. String: {}", &client, e, &string)
                }
            }
            Ok(())
        });
        info!("Subscribed to {}", &subject);
    }
}

fn send_clickhouse_request(agent: &Agent, config: &Config, request: &str) {
    let response = agent
        .post(&config.clickhouse.url)
        .set("X-ClickHouse-User", &config.clickhouse.login)
        .set("X-ClickHouse-Key", &config.clickhouse.password)
        .set("X-ClickHouse-Database", &config.clickhouse.database)
        .send_bytes(request.as_bytes());
    match response {
        Ok(response) => {
            if response.status() != 200 {
                warn!("Clickhouse response is {:?}", &response);
            }
        }
        Err(e) => warn!("Failed to send stats to clickhouse: {}", e)
    }
}

fn get_list(db: &sqlite::Connection, client: &str, hostname: &str, blacklist: bool) -> String {
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let mut result = String::new();
    let blacklist = match blacklist {
        true => 1,
        false => 0
    };
    match db.prepare(GET_LIST) {
        Ok(mut statement) => {
            statement.bind(1, client).expect("Error in bind");
            statement.bind(2, hostname).expect("Error in bind");
            statement.bind(3, blacklist).expect("Error in bind");
            statement.bind(4, now).expect("Error in bind");
            while statement.next().unwrap() == State::Row {
                if let Ok(mut string) = statement.read::<String>(0) {
                    let until = statement.read::<i64>(1).unwrap_or(0);
                    if !result.is_empty() {
                        result.push('\n');
                    }
                    let mut timeout = until - now;
                    // ipset supports timeouts only until 2147483 :(
                    if timeout > 2147483 {
                        timeout = 2147483;
                    }
                    string = format!("{} timeout {}", &string, timeout);
                    result.push_str(&string);
                }
            }
        }
        Err(e) => {
            info!("No list found. {}", e);
        }
    }
    result
}

fn add_to_list(db: &sqlite::Connection, client: &str, hostname: &str, blacklist: bool, ip: &str, timeout: i64) -> sqlite::Result<State> {
    let until = OffsetDateTime::now_utc().unix_timestamp() + timeout;
    let mut statement = db.prepare(GET_COUNT)?;
    statement.bind(1, client)?;
    statement.bind(2, blacklist as i64)?;
    statement.bind(3, ip)?;
    let count = match statement.next().unwrap() {
        State::Row => match statement.read::<i64>(0) {
            Ok(count) => count,
            Err(..) => 0
        },
        State::Done => 0
    };
    if count > 0 {
        trace!("Updating {} ban time", &ip);
        let mut statement = db.prepare(UPDATE_IN_LIST)?;
        statement.bind(1, until)?;
        statement.bind(2, client)?;
        statement.bind(3, blacklist as i64)?;
        statement.bind(4, ip)?;
        statement.next()
    } else {
        // If we have no record of this IP we add it now
        trace!("Adding {} to list", &ip);
        let mut statement = db.prepare(ADD_TO_LIST)?;
        statement.bind(1, client)?;
        statement.bind(2, hostname)?;
        statement.bind(3, blacklist as i64)?;
        statement.bind(4, ip)?;
        statement.bind(5, until)?;
        statement.next()
    }
}

fn delete_from_list(db: &sqlite::Connection, client: &str, hostname: &str, blacklist: bool, ip: &str) -> sqlite::Result<State> {
    let mut statement = db.prepare(DELETE_FROM_LIST)?;
    statement.bind(1, client)?;
    statement.bind(2, hostname)?;
    statement.bind(3, blacklist as i64)?;
    statement.bind(4, ip)?;
    statement.next()
}

fn count_list(db: &sqlite::Connection, client: &str, hostname: &str, blacklist: bool) -> i64 {
    let until = OffsetDateTime::now_utc().unix_timestamp();
    let blacklist = match blacklist {
        true => 1,
        false => 0
    };
    match db.prepare(COUNT_LIST) {
        Ok(mut statement) => {
            statement.bind(1, client).expect("Error in bind");
            statement.bind(2, hostname).expect("Error in bind");
            statement.bind(3, blacklist).expect("Error in bind");
            statement.bind(4, until).expect("Error in bind");
            while statement.next().unwrap() == State::Row {
                if let Ok(count) = statement.read::<i64>(0) {
                    return count;
                }
            }
        }
        Err(e) => {
            info!("No list found. {}", e);
        }
    }
    0i64
}

fn create_db_if_needed(db: &sqlite::Connection) {
    let mut db_exists = false;
    match db.prepare(CHECK_DB) {
        Ok(mut statement) => {
            while statement.next().unwrap() == State::Row {
                db_exists = true;
            }
        }
        Err(_) => {}
    }
    if !db_exists {
        if let Err(e) = db.execute(CREATE_DB) {
            error!("Error creating main data table: {}", e);
        }
    }
    if let Err(e) = db.execute(TUNE_DB) {
        warn!("Error tuning DB: {}", e);
    }
}

/// Converts any subject string from `diswall.whitelist.client_name.add.host_name` to `("client_name", "host_name")`
pub fn get_user_and_host(subject: &str) -> (String, String) {
    let mut text = subject.to_owned();
    text = text.replace(PREFIX_BL, "");
    text = text.replace(PREFIX_WL, "");
    text = text.replace(PREFIX_STATS, "");
    if text.starts_with(".") {
        text = text[1..].to_owned();
    }
    text = text.replace(".init.", "--");
    text = text.replace(".add.", "--");
    text = text.replace(".del.", "--");

    let split = text.split("--").collect::<Vec<&str>>();
    match split.len() {
        2 => (split[0].to_owned(), split[1].to_owned()),
        _ => (split[0].to_owned(), String::new())
    }
}

pub fn valid_ip(ip: &str) -> bool {
    match ip.parse::<IpAddr>() {
        Ok(_) => true,
        Err(_) => false,
    }
}

pub fn mix_client(data: &[u8]) -> u64 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::Hash;

    let mut hasher = DefaultHasher::new();
    data.hash(&mut hasher);
    hasher.finish()
}

#[test]
pub fn test_mix() {
    let data = b"Some string";
    let mix = mix_client(data);
    assert_eq!(mix, 12313646071179450357);
}