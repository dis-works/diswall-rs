use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use log::{debug, error, info, warn};
use nats::Connection;
use sqlite::State;
use time::OffsetDateTime;
use crate::{Config, Stats};
use crate::config::{PREFIX_BL, PREFIX_WL};

pub const DB_NAME: &str = "diswall.db";
pub const CREATE_DB: &str = include_str!("../data/create_db.sql");
pub const CHECK_DB: &str = "SELECT name FROM sqlite_master WHERE type='table' AND name='data';";
pub const GET_LIST: &str = "SELECT ip FROM data WHERE client=? AND hostname=? AND blacklist=? AND until>?;";
pub const ADD_TO_LIST: &str = "INSERT INTO data (client, hostname, blacklist, ip, until) VALUES (?, ?, ?, ?, ?);";
pub const GET_UNTIL: &str = "SELECT until FROM data WHERE client=? AND hostname=? AND blacklist=? AND ip=?";
pub const DELETE_FROM_LIST: &str = "DELETE FROM data WHERE client=? AND hostname=? AND blacklist=? AND ip=?;";

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
                    if let Err(e) = add_to_list(&db, &client, &hostname, false, &string) {
                        warn!("Error adding to DB: {}", e);
                    }
                }
            }
            Ok(())
        });
        info!("Subscribed to {}", &config.nats.wl_add_subject);
    }

    // Subscribe for new IPs for blocklist
    if let Ok(sub) = nats.subscribe(&config.nats.bl_add_subject) {
        let db = db.clone();
        let nats = nats.clone();
        let config = config.clone();
        sub.with_handler(move |message| {
            let (client, hostname) = get_user_and_host(&message.subject);
            debug!("Got message on {} from {:?}", &message.subject, (&client, &hostname));
            if let Ok(string) = String::from_utf8(message.data) {
                if !valid_ip(&string) {
                    warn!("Could not parse IP {} from {}", &string, &client);
                    return Ok(());
                }
                // If this IP was sent by one of our honeypots we add this IP without client and hostname
                let (client, hostname, honeypot) = match config.nats.honeypots.contains(&client) {
                    true => (String::new(), String::new(), true),
                    false => (client, hostname, false)
                };
                if let Ok(db) = db.lock() {
                    if let Err(e) = add_to_list(&db, &client, &hostname, true, &string) {
                        warn!("Error adding to DB: {}", e);
                    }
                }
                if honeypot {
                    match nats.publish(&config.nats.bl_global_subject, &string) {
                        Ok(_) => info!("Pushed {} to [{}]", &string, &config.nats.bl_global_subject),
                        Err(e) => warn!("Error pushing {} to [{}]: {}", &string, &config.nats.bl_global_subject, e)
                    }
                }
            }
            Ok(())
        });
        info!("Subscribed to {}", &config.nats.bl_add_subject);
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
        start_stats_handler(&config, nats)
    }

    let delay = Duration::from_secs(1);
    // We just loop here until kill
    loop {
        thread::sleep(delay);
    }
}

fn start_stats_handler(config: &Config, nats: Connection) {
    let agent = ureq::AgentBuilder::new()
        .user_agent(&format!("DisWall v{}", env!("CARGO_PKG_VERSION")))
        .timeout(Duration::from_secs(3))
        .max_idle_connections_per_host(10)
        .max_idle_connections(10)
        .build();

    // Subscribe for IPs to delete from blocklist
    if let Ok(sub) = nats.subscribe(&config.nats.stats_subject) {
        let config = config.clone();
        sub.with_handler(move |message| {
            let (client, hostname) = get_user_and_host(&message.subject);
            debug!("Got message on {} from {:?}", &message.subject, (&client, &hostname));
            if let Ok(string) = String::from_utf8(message.data) {
                match serde_json::from_str::<Stats>(&string) {
                    Ok(stats) => {
                        let request = format!("INSERT INTO stats VALUES ({}/{}, {}, {}, {}, {})", &client, &hostname, stats.time, stats.banned, stats.packets_dropped, stats.bytes_dropped);
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
                    Err(e) => error!("Could not deserialize stats from {}: {}. String: {}", &client, e, &string)
                }
            }
            Ok(())
        });
        info!("Subscribed to {}", &config.nats.stats_subject);
    }
}

fn get_list(db: &sqlite::Connection, client: &str, hostname: &str, blacklist: bool) -> String {
    let until = OffsetDateTime::now_utc().unix_timestamp();
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
            statement.bind(4, until).expect("Error in bind");
            while statement.next().unwrap() == State::Row {
                if let Ok(string) = statement.read::<String>(0) {
                    if !result.is_empty() {
                        result.push('\n');
                    }
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

fn add_to_list(db: &sqlite::Connection, client: &str, hostname: &str, blacklist: bool, ip: &str) -> sqlite::Result<State> {
    let until = OffsetDateTime::now_utc().unix_timestamp() + 86400;
    let mut statement = db.prepare(GET_UNTIL)?;
    statement.bind(1, client)?;
    statement.bind(2, hostname)?;
    statement.bind(3, blacklist as i64)?;
    statement.bind(4, ip)?;
    match statement.next().unwrap() {
        State::Row => Ok(State::Done),
        State::Done => {
            // If we have no record of this IP we add it now
            let mut statement = db.prepare(ADD_TO_LIST)?;
            statement.bind(1, client)?;
            statement.bind(2, hostname)?;
            statement.bind(3, blacklist as i64)?;
            statement.bind(4, ip)?;
            statement.bind(5, until)?;
            statement.next()
        }
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
}

/// Converts any subject string from `diswall.whitelist.client_name.add.host_name` to `("client_name", "host_name")`
pub fn get_user_and_host(subject: &str) -> (String, String) {
    let mut text = subject.to_owned();
    text = text.replace(PREFIX_BL, "");
    text = text.replace(PREFIX_WL, "");
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
