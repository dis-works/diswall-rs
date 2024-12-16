use std::{env, fs, io, thread};
use std::cmp::min;
use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, ErrorKind, Read, Seek, SeekFrom};
use std::net::IpAddr;
use std::num::{NonZeroUsize};
use std::process::{Command, exit, Stdio};
use std::sync::{Arc, Mutex, RwLock};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};
use getopts::{Matches, Options};
use lazy_static::lazy_static;
use log::{debug, error, info, LevelFilter, trace, warn};
use nats::Connection;
use simplelog::{ColorChoice, CombinedLogger, ConfigBuilder, format_description, LevelPadding, TerminalMode, TermLogger, WriteLogger};
use time::OffsetDateTime;
use crate::config::{Config, DEFAULT_CLIENT_NAME, FwType};
use crate::server::run_server;
#[cfg(not(windows))]
use crate::install::{install_client, update_client};
use crate::timer::HourlyTimer;
use crate::types::Stats;
use crate::utils::{extract_between_brackets, get_first_part, get_ip_and_tag, get_ip_and_timeout, is_ipv6, reduce_spaces};
use lru::LruCache;
use utils::valid_ip;
use crate::firewall::get_installed_fw_type;
#[cfg(not(windows))]
use crate::install::uninstall_client;
#[cfg(not(windows))]
use crate::install::update_fw_configs_for_ipv6;
use crate::ports::Ports;
use crate::state::{Blocked, LoginState, State};
use crate::state::LoginState::LoggedIn;
#[cfg(not(windows))]
use crate::ui::{
    ui_client::UiClient,
    ui_server::UiServer
};

mod config;
mod firewall;
mod server;
mod timer;
mod types;
mod utils;
mod addons;
#[cfg(not(windows))]
mod install;
mod ports;
mod state;
#[cfg(not(windows))]
mod ui;

#[cfg(not(windows))]
const UI_SOCK_ADDR: &'static str = "/run/diswall.sock";
const DEFAULT_BLOCK_TIME_SEC: u64 = 86400;
lazy_static! {
    pub static ref STATE: Arc<Mutex<State>> = Arc::new(Mutex::new(State::new()));
}

fn main() -> Result<(), i32> {
    let args: Vec<String> = env::args().collect();
    let program = args[0].clone();

    let (options, opt_matches) = get_options(&args);

    if opt_matches.opt_present("h") {
        let brief = format!("Usage: {} [options]", program);
        println!("{}", options.usage(&brief));
        return Ok(());
    }

    if opt_matches.opt_present("v") {
        println!("DisWall v{}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }

    if opt_matches.opt_present("g") {
        println!("{}", include_str!("../config/diswall.toml"));
        return Ok(());
    }

    if opt_matches.opt_present("e") {
        return match get_installed_fw_type() {
            Ok(fw_type) => {
                utils::edit_firewall_config(&fw_type);
                Ok(())
            },
            Err(e) => {
                println!("Could not get current firewall type: {e}");
                Err(1)
            }
        }
    }

    if let Some(ip) = opt_matches.opt_str("k") {
        if kill_connection(&ip) {
            println!("Killed connection with {}", &ip);
        }
        return Ok(())
    }

    #[cfg(not(windows))]
    if opt_matches.opt_present("i") {
        setup_logger(&opt_matches);
        info!("Starting DisWall UI...");
        let client = UiClient::new(UI_SOCK_ADDR.to_string());
        if let Err(e) = client.start() {
            error!("Error running UI: {e}");
        }
        return Ok(());
    }

    let file_name = opt_matches.opt_str("c").unwrap_or_else(|| String::from("/etc/diswall/diswall.conf"));

    // Load or create default config
    let mut config = Config::from_file(&file_name).unwrap_or_else(|| Config::default());

    // Override config options by options from arguments
    config.override_config_from_args(&opt_matches);
    config.init_nats_subjects();
    setup_logger(&opt_matches);
    match get_installed_fw_type() {
        Ok(t) => config.fw_type = t,
        Err(e) => {
            error!("{}", e);
            return Err(103);
        }
    }

    if !opt_matches.opt_present("install") {
        // If we have old configs we update them
        #[cfg(not(windows))]
        if !update_fw_configs_for_ipv6() {
            warn!("Error updating config for IPv6 support. Please, run `sudo diswall` one time to enable IPv6 support.");
            return Ok(());
        }
    }

    if opt_matches.opt_present("after-update") {
        #[cfg(not(windows))]
        if install::update_fw_configs_for_separated_protocols() {
            info!("Firewall config updated");
        }
        #[cfg(not(windows))]
        if install::uninstall_rsyslog_configs() {
            let _ = fs::remove_file("/var/log/diswall/diswall.pipe");
            // We restart service only for old update code in `install::update_client()`.
            // TODO: This code will be removed in next version
            match Command::new("systemctl").arg("restart").arg("diswall").stdout(Stdio::null()).spawn() {
                Ok(mut child) => {
                    if let Ok(r) = child.wait() {
                        if r.success() {
                            info!("Updated successfully, service restarted");
                            return Ok(());
                        }
                    }
                }
                Err(_) => ()
            }
        }
        return Ok(());
    }

    if opt_matches.opt_present("install") {
        #[cfg(windows)]
        {
            error!("Installing DisWall on Windows is not supported!");
            return Err(110);
        }
        #[cfg(not(windows))]
        {
            info!("Installing DisWall v{}", env!("CARGO_PKG_VERSION"));
            if let Err(e) = install_client() {
                error!("Error installing DisWall: {}", &e);
                return Err(100);
            }
            return Ok(());
        }
    }

    if opt_matches.opt_present("update") {
        #[cfg(windows)]
        {
            error!("Updating DisWall on Windows is not supported!");
            return Err(110);
        }
        #[cfg(not(windows))]
        {
            info!("Updating DisWall v{}", env!("CARGO_PKG_VERSION"));
            if let Err(e) = update_client() {
                error!("Error updating DisWall: {}", &e);
                return Err(101);
            }
            return Ok(());
        }
    }

    if opt_matches.opt_present("uninstall") {
        #[cfg(windows)]
        {
            error!("Uninstalling DisWall on Windows is not supported!");
            return Err(110);
        }
        #[cfg(not(windows))]
        {
            info!("Uninstalling DisWall v{}", env!("CARGO_PKG_VERSION"));
            if let Err(e) = uninstall_client() {
                error!("Error uninstalling DisWall: {}", &e);
                return Err(102);
            }
            return Ok(());
        }
    }

    debug!("Loaded config:\n{:#?}", &config);
    let cache = Arc::new(Mutex::new(LruCache::new(NonZeroUsize::new(8).unwrap())));

    #[cfg(not(windows))]
    thread::spawn(|| {
        let server = UiServer::new(UI_SOCK_ADDR.to_string(), Arc::clone(&STATE));
        server.start();
    });

    let start_nats = !config.local_only &&
        !config.nats.server.is_empty() &&
        !config.nats.client_name.is_empty() &&
        !config.nats.client_name.eq("<ENTER YOU CLIENT NAME>");
    let client_name = config.nats.client_name.clone();
    let nats = if start_nats {
        //let hostname = config::get_hostname();
        debug!("Connecting to NATS server...");
        let nats = nats::Options::with_user_pass(&config.nats.client_name, &config.nats.client_pass)
            .with_name("DisWall")
            .error_callback(|error| {
                error!("NATS error: {}", error);
                if let Ok(mut state) = STATE.lock() {
                    state.logged_in = LoginState::Error(error.to_string())
                }
            })
            .retry_on_failed_connect()
            .reconnect_callback(move || {
                info!("Reconnected to NATS server");
                if let Ok(mut state) = STATE.lock() {
                    state.logged_in = LoginState::LoggedIn(client_name.clone())
                }
            })
            .reconnect_buffer_size(32 * 1024 * 1024)
            .max_reconnects(1_000_000)
            .reconnect_delay_callback(reconnect_timer)
            .connect(format!("nats://{}:{}", &config.nats.server, &config.nats.port));
        match nats {
            Err(e) => {
                error!("Error connecting to NATS server: {}", e);
                return Err(1);
            }
            Ok(nats) => {
                let nats_clone = Some(nats.clone());
                if process_ips_from_parameters(&config, &opt_matches, nats_clone) {
                    return Ok(());
                }
                if !config.server_mode {
                    info!("Connected to NATS server, setting up handlers");
                    if let Ok(mut state) = STATE.lock() {
                        if config.nats.client_name == DEFAULT_CLIENT_NAME {
                            state.logged_in = LoginState::Default;
                        } else {
                            state.logged_in = LoggedIn(config.nats.client_name.clone());
                        }
                    }
                    start_nats_handlers(&mut config, &nats, Arc::clone(&cache), Arc::clone(&STATE));
                }
                Some(nats)
            }
        }
    } else {
        debug!("Starting in local only mode...");
        if process_ips_from_parameters(&config, &opt_matches, None) {
            return Ok(());
        }
        None
    };

    // If this binary is executed with 'server' parameter we start only NATS server
    if config.server_mode {
        run_server(config, nats);
        return Ok(());
    }

    let banned_count = Arc::new(AtomicU32::new(0));
    if config.send_statistics && config.nats.client_name.ne(DEFAULT_CLIENT_NAME) {
        if let Some(nats) = nats.clone() {
            let banned_count = banned_count.clone();
            let black_list_name = config.ipset_black_list.clone();
            let white_list_name = config.ipset_white_list.clone();
            let subject = config.nats.stats_subject.clone();
            let fw_type = config.fw_type.clone();
            let prev_stats = Arc::new(RwLock::new(Stats::default()));
            let mut timer = HourlyTimer::new(move || {
                match fw_type {
                    FwType::IpTables => collect_stats_from_iptables(&black_list_name, &subject, &nats, &banned_count, &prev_stats),
                    FwType::NfTables => collect_stats_from_nftables(&black_list_name, &white_list_name, &subject, &nats, &banned_count, &prev_stats)
                }
            });
            let _ = timer.start();
        }
    }

    if !config.nginx.logs.is_empty() {
        // For every log path in config we start new thread that will read that log
        for log in &config.nginx.logs {
            let log = log.clone();
            let state = Arc::clone(&STATE);
            let cache = Arc::clone(&cache);
            let banned_count = banned_count.clone();
            let nats = nats.clone();
            let config = config.clone();
            thread::spawn(move || {
                addons::nginx::process_log_file(config, nats, banned_count, cache, state, log);
            });
        }
    }

    if let Err(e) = lock_on_log_read(config, nats, &banned_count, Arc::clone(&cache), Arc::clone(&STATE)) {
        error!("Error reading journalctl: {}", e);
    }
    Ok(())
}

fn reconnect_timer(c: usize) -> Duration {
    if c < 10 {
        Duration::from_millis(1000 + (rand::random::<u64>() % 200))
    } else {
        Duration::from_millis(5000 + (rand::random::<u64>() % 500))
    }
}

fn process_ips_from_parameters(config: &Config, opt_matches: &Matches, nats: Option<Connection>) -> bool {
    if let Some(ip) = opt_matches.opt_str("wl-add-ip") {
        let comment = match opt_matches.opt_str("wl-add-comm") {
            None => None,
            Some(s) => Some(s)
        };
        return modify_list(&config.fw_type, true, &nats, &config.ipset_white_list, &config.nats.wl_push_subject, &ip, comment);
    }

    if let Some(ip) = opt_matches.opt_str("wl-del-ip") {
        return modify_list(&config.fw_type, false, &nats, &config.ipset_white_list, &config.nats.wl_del_subject, &ip, None);
    }

    if let Some(ip) = opt_matches.opt_str("bl-add-ip") {
        if modify_list(&config.fw_type, true, &nats, &config.ipset_black_list, &config.nats.bl_push_subject, &ip, None) {
            let _ = kill_connection(&ip);
            return true;
        }
    }

    if let Some(ip) = opt_matches.opt_str("bl-del-ip") {
        return modify_list(&config.fw_type, true, &nats, &config.ipset_black_list, &config.nats.bl_del_subject, &ip, None);
    }

    false
}

fn start_nats_handlers(config: &mut Config, nats: &Connection, cache: Arc<Mutex<LruCache<String, bool>>>, state: Arc<Mutex<State>>) {
    let msg = String::new();
    match nats.request(&config.nats.wl_init_subject, &msg) {
        Ok(message) => {
            let string = String::from_utf8(message.data).unwrap_or(String::default());
            let mut buf = String::new();
            for line in string.lines() {
                let ip = get_first_part(line);
                let suffix = match is_ipv6(&ip) {
                    true => "6",
                    false => ""
                };
                match config.fw_type {
                    FwType::IpTables => {
                        // add diswall-wl 1.2.3.4 timeout 1234
                        buf.push_str(&format!("add {}{suffix} {line}\n", &config.ipset_white_list));
                    }
                    FwType::NfTables => {
                        // add element ip filter diswall-wl {1.2.3.4 timeout 1234s}
                        buf.push_str(&format!("add element ip{suffix} filter {}{suffix} {{{line}s}}\n", &config.ipset_white_list));
                    }
                }
                trace!("To whitelist: {}", line);
            }
            match config.fw_type {
                FwType::IpTables => firewall::ipset_restore(&buf),
                FwType::NfTables => firewall::nft_restore(&buf)
            }
        }
        Err(e) => error!("Error requesting WL from NATS server: {}", e)
    }

    // Getting blocklist from server
    match nats.request(&config.nats.bl_init_subject, &msg) {
        Ok(message) => {
            let default_timeout = if config.max_block_time > 0 {
                min(DEFAULT_BLOCK_TIME_SEC, config.max_block_time)
            } else {
                DEFAULT_BLOCK_TIME_SEC
            };
            let string = String::from_utf8(message.data).unwrap_or(String::default());
            let mut buf = String::new();
            for line in string.lines() {
                let (ip, timeout) = get_ip_and_timeout(&line);
                let timeout = timeout.parse::<u64>().unwrap_or_else(|_| DEFAULT_BLOCK_TIME_SEC);
                let timeout = min(timeout, default_timeout);
                let suffix = match is_ipv6(&ip) {
                    true => "6",
                    false => ""
                };
                let line = match config.fw_type {
                    FwType::IpTables => {
                        // add diswall-bl 1.2.3.4 timeout 1234
                        format!("add {}{suffix} {line}\n", &config.ipset_black_list)
                    }
                    FwType::NfTables => {
                        // add element ip filter diswall-bl {1.2.3.4 timeout 1234s}
                        format!("add element ip{suffix} filter {}{suffix} {{{line}s}}\n", &config.ipset_black_list)
                    }
                };
                buf.push_str(&line);
                trace!("To blacklist: {}", &line);
                if let Ok(mut state) = state.lock() {
                    if let Ok(ip) = ip.parse() {
                        info!("Adding IP {}", &ip);
                        let blocked = Blocked::new(ip, None, timeout);
                        state.add_blocked(blocked);
                    } else {
                        error!("Error parsing IP {} from line '{}'", &ip, &line);
                    }
                }
            }
            if let Ok(state) = state.lock() {
                info!("Added {} items to state", &state.blocked.len());
            }
            match config.fw_type {
                FwType::IpTables => firewall::ipset_restore(&buf),
                FwType::NfTables => firewall::nft_restore(&buf)
            }
        }
        Err(e) => error!("Error requesting BL from NATS server: {}", e)
    }

    // Subscribe to new IPs for whitelist
    if let Ok(sub) = nats.subscribe(&config.nats.wl_subscribe_subject) {
        let list_name = config.ipset_white_list.clone();
        let fw_type = config.fw_type.clone();
        sub.with_handler(move |message| {
            if let Ok(string) = String::from_utf8(message.data) {
                let split = string.split("|").collect::<Vec<&str>>();
                let list = match is_ipv6(split[0]) {
                    true => format!("{}6", list_name),
                    false => list_name.to_owned()
                };
                match fw_type {
                    FwType::IpTables => {
                        // If no comment
                        if split.len() == 1 {
                            debug!("Got IP for whitelist: {}", split[0]);
                            firewall::ipset_add_or_del("add", &list, split[0], None)
                        } else {
                            debug!("Got IP for whitelist: {} ({})", split[0], split[1]);
                            firewall::ipset_add_or_del("add", &list, split[0], Some(split[1].to_owned()));
                        }
                    },
                    FwType::NfTables => firewall::nft_add(&list, split[0])
                }
            }
            Ok(())
        });
        info!("Subscribed to {}", &config.nats.wl_subscribe_subject);
    }

    // Subscribe for new IPs for blocklist
    match nats.subscribe(&config.nats.bl_subscribe_subject) {
        Ok(sub) => {
            let list_name = config.ipset_black_list.clone();
            let fw_type = config.fw_type.clone();
            let cache = Arc::clone(&cache);
            let ignore_ips = config.ignore_ips.clone();
            sub.with_handler(move |message| {
                if let Ok(string) = String::from_utf8(message.data) {
                    //trace!("Got ip from my subject: {}", &string);
                    let (ip, tag) = get_ip_and_tag(&string);
                    if !valid_ip(&ip) {
                        warn!("Could not parse IP {} from {}", &ip, &string);
                        return Ok(());
                    }
                    if ignore_ips.contains(&ip) {
                        debug!("Ignoring IP {ip}");
                        return Ok(());
                    }
                    if let Ok(cache) = cache.lock() {
                        if cache.contains(&ip) {
                            return Ok(());
                        }
                    }
                    if tag.len() > 25 {
                        warn!("Too long tag '{}' from {}", &tag, &string);
                        return Ok(());
                    }
                    let list = match is_ipv6(&ip) {
                        true => format!("{}6", list_name),
                        false => list_name.to_owned()
                    };
                    match fw_type {
                        FwType::IpTables => firewall::ipset_add_or_del("add", &list, &ip, None),
                        FwType::NfTables => firewall::nft_add(&list, &ip)
                    }
                    let _ = kill_connection(&ip);
                    if let Ok(mut cache) = cache.lock() {
                        cache.push(ip, true);
                    }
                }
                Ok(())
            });
            info!("Subscribed to {}", &config.nats.bl_subscribe_subject);
        }
        Err(e) => error!("Error subscribing to BL updates from NATS server: {}", e)
    }

    // Subscribe for new IPs for blocklist
    if let Ok(sub) = nats.subscribe(&config.nats.bl_global_subject) {
        let list_name = config.ipset_black_list.clone();
        let fw_type = config.fw_type.clone();
        let max_block_time = config.max_block_time;
        sub.with_handler(move |message| {
            if let Ok(string) = String::from_utf8(message.data) {
                trace!("Got ip from global subject: {}", &string);
                let (ip, tag) = get_ip_and_tag(&string);
                if !valid_ip(&ip) {
                    warn!("Could not parse IP {} from {}", &ip, &string);
                    return Ok(());
                }
                if tag.len() > 25 {
                    warn!("Too long tag '{}' from {}", &tag, &string);
                    return Ok(());
                }
                let (data, timeout) = match tag.parse::<u64>() {
                    Ok(timeout) => {
                        let timeout = if max_block_time > 0 {
                            min(timeout, max_block_time)
                        } else {
                            timeout
                        };
                        (format!("{} timeout {}", &ip, timeout), timeout)
                    },
                    Err(_) => {
                        let timeout = if max_block_time > 0 {
                            min(DEFAULT_BLOCK_TIME_SEC, max_block_time)
                        } else {
                            DEFAULT_BLOCK_TIME_SEC
                        };
                        (ip.clone(), timeout)
                    }
                };
                let list = match is_ipv6(&ip) {
                    true => format!("{}6", list_name),
                    false => list_name.to_owned()
                };
                match fw_type {
                    FwType::IpTables => firewall::ipset_add_or_del("add", &list, &data, None),
                    FwType::NfTables => firewall::nft_add(&list, &data)
                }
                if let Ok(mut state) = state.lock() {
                    if let Ok(ip) = ip.parse() {
                        let blocked = Blocked::new(ip, None, timeout);
                        state.add_blocked(blocked);
                    }
                }
                let _ = kill_connection(&ip);
            }
            Ok(())
        });
        info!("Subscribed to {}", &config.nats.bl_global_subject);
    }

    // Subscribe for IPs to delete from whitelist
    if let Ok(sub) = nats.subscribe(&config.nats.wl_del_subject) {
        let list_name = config.ipset_white_list.clone();
        sub.with_handler(move |message| {
            if let Ok(string) = String::from_utf8(message.data) {
                debug!("Got IP to delete from whitelist: {}", &string);
                firewall::ipset_add_or_del("del", &list_name, &string, None);
            }
            Ok(())
        });
        info!("Subscribed to {}", &config.nats.wl_del_subject);
    }

    // Subscribe for IPs to delete from blocklist
    if let Ok(sub) = nats.subscribe(&config.nats.bl_del_subject) {
        let list_name = config.ipset_black_list.clone();
        sub.with_handler(move |message| {
            if let Ok(string) = String::from_utf8(message.data) {
                debug!("Got IP to delete from blocklist: {}", &string);
                firewall::ipset_add_or_del("del", &list_name, &string, None);
            }
            Ok(())
        });
        info!("Subscribed to {}", &config.nats.bl_del_subject);
    }
}

fn lock_on_log_read(config: Config, nats: Option<Connection>, banned_count: &Arc<AtomicU32>, cache: Arc<Mutex<LruCache<String, bool>>>, state: Arc<Mutex<State>>) -> Result<(), io::Error> {
    match Command::new("journalctl")
        .arg("-f")
        .arg("--since=now")
        .arg("--output=cat")
        .arg("--grep=diswall-log|sshd:auth|authentication failed|diswall-add")
        .stdout(Stdio::piped()).spawn() {
        Ok(mut child) => {
            match child.stdout.take() {
                None => {
                    error!("Error starting journalctl");
                    return Err(io::Error::from(ErrorKind::NotFound));
                }
                Some(out) => {
                    let mut reader = BufReader::new(out);
                    debug!("Journal opened, waiting for IPs");
                    let block_list = config.ipset_black_list.as_str();
                    let mut line = String::new();
                    let delay = Duration::from_millis(2);
                    let mut banned = HashMap::<String, (Instant, i32)>::new();
                    // Usual scanned ports of known services like databases, etc.
                    let service_ports = [1025, 1433, 1434, 1521, 1583, 1830, 2049, 3050, 3306, 3351, 3389, 5432, 5900, 6379, 7210, 8080, 8081, 8443, 9200, 9216, 9300, 11211];
                    const EPHEMERAL_PORT_START: u16 = 49152;
                    let open_ports = Ports::new(60);
                    loop {
                        let len = reader.read_line(&mut line)?;
                        if len > 0 {
                            if line.starts_with("diswall-log") {
                                trace!("Got line from firewall: {}", line.replace("diswall-log ", ""));
                                if line.contains("SRC=0.0.0.0") {
                                    line.clear();
                                    continue;
                                }
                                let mut ip = String::new();
                                let mut protocol = String::new();
                                let mut port = 0u16;
                                let parts = line.trim().split(' ').collect::<Vec<_>>();
                                for part in parts {
                                    if part.starts_with("SRC=") {
                                        ip.push_str(&part[4..]);
                                        continue;
                                    }
                                    if part.starts_with("PROTO=") {
                                        protocol.push_str(&part[6..]);
                                        continue;
                                    }
                                    if part.starts_with("DPT=") {
                                        port = part[4..].parse::<u16>().unwrap_or(0);
                                        break;
                                    }
                                }
                                if open_ports.is_open(port, &protocol) {
                                    trace!("Skipping open port {port}");
                                    line.clear();
                                    continue;
                                }
                                // If the packet is going to sensitive port, we ban it no matter what
                                if port < 1025 || service_ports.contains(&port) {
                                    debug!("{ip} Fast-banning, as scanning port {port}");
                                    process_ip(&config, &nats, banned_count, &cache, &block_list, &ip);
                                    if let Ok(mut state) = state.lock() {
                                        if let Ok(ip) = ip.parse() {
                                            let blocked = Blocked::new(ip, Some(port), DEFAULT_BLOCK_TIME_SEC);
                                            state.add_blocked(blocked);
                                        }
                                    }
                                    banned.remove(&ip);
                                } else {
                                    // Sometimes the kernel looses info about legit connections, and some packets are coming as not related to any connections.
                                    // For these packets we are trying to count those packets, and don't ban on random glitch-packet.
                                    match banned.get_mut(&ip) {
                                        Some((time, count)) => {
                                            // For ephemeral ports we use more relaxed blocking
                                            let max_count = if port >= EPHEMERAL_PORT_START {
                                                3
                                            } else {
                                                1
                                            };
                                            if time.elapsed().as_secs() > 3600 {
                                                *count = 1;
                                                *time = Instant::now();
                                                debug!("{ip} Resetting count to {count}, port {port}");
                                            } else {
                                                *count += 1;
                                                debug!("{ip} Incremented count to {count}, port {port}");
                                                if *count >= max_count {
                                                    debug!("{ip} Banned for {count} port scans, port {port}");
                                                    process_ip(&config, &nats, banned_count, &cache, &block_list, &ip);
                                                    if let Ok(mut state) = state.lock() {
                                                        if let Ok(ip) = ip.parse() {
                                                            let blocked = Blocked::new(ip, Some(port), DEFAULT_BLOCK_TIME_SEC);
                                                            state.add_blocked(blocked);
                                                        }
                                                    }
                                                    banned.remove(&ip);
                                                }
                                            }
                                        }
                                        None => {
                                            if port >= EPHEMERAL_PORT_START {
                                                debug!("{ip} First attempt of port {port} scan, saving");
                                                banned.insert(ip.to_owned(), (Instant::now(), 1));
                                            } else {
                                                debug!("{ip} Banned for first port scan, port {port}");
                                                process_ip(&config, &nats, banned_count, &cache, &block_list, &ip);
                                                if let Ok(mut state) = state.lock() {
                                                    if let Ok(ip) = ip.parse() {
                                                        let blocked = Blocked::new(ip, Some(port), DEFAULT_BLOCK_TIME_SEC);
                                                        state.add_blocked(blocked);
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            } else if line.contains("sshd:auth") && line.contains("authentication failure") {
                                trace!("Got line from sshd: {}", line.replace("sshd", "****"));
                                if let Some(mut pos) = line.find("rhost=") {
                                    pos += 6;
                                    trace!("slicing from {}", &line[pos..]);
                                    let pos2 = match line[pos..].find(' ') {
                                        Some(pos2) => pos+pos2,
                                        None => line.len()
                                    };
                                    let ip = line[pos..pos2].trim().to_string();
                                    let ban = format!("{}|ssh", &ip);
                                    trace!("Banning {ip}");
                                    process_ip(&config, &nats, banned_count, &cache, &block_list, &ban);
                                    if let Ok(mut state) = state.lock() {
                                        if let Ok(ip) = ip.parse() {
                                            let blocked = Blocked::new(ip, None, DEFAULT_BLOCK_TIME_SEC);
                                            state.add_blocked(blocked);
                                        }
                                    }
                                }
                            } else if line.contains("diswall-add") {
                                let line = line.replace("diswall-add ", "");
                                trace!("Got line from addon {}", &line);
                                process_ip(&config, &nats, banned_count, &cache, &block_list, &line);
                                if let Ok(mut state) = state.lock() {
                                    if let Ok(ip) = line.parse() {
                                        let blocked = Blocked::new(ip, None, DEFAULT_BLOCK_TIME_SEC);
                                        state.add_blocked(blocked);
                                    }
                                }
                            } else if line.contains("authentication failed") && line.contains("SASL") {
                                trace!("Got line from SASL");
                                if let Some(ip) = extract_between_brackets(&line) {
                                    let ban = format!("{ip}|smtp");
                                    process_ip(&config, &nats, banned_count, &cache, &block_list, &ban);
                                    if let Ok(mut state) = state.lock() {
                                        if let Ok(ip) = ip.parse() {
                                            let blocked = Blocked::new(ip, None, DEFAULT_BLOCK_TIME_SEC);
                                            state.add_blocked(blocked);
                                        }
                                    }
                                }
                            }
                        } else {
                            thread::sleep(delay);
                        }
                        line.clear();
                    }
                }
            }
        }
        Err(e) => return Err(e)
    }
}

fn process_ip(config: &Config, nats: &Option<Connection>, banned_count: &Arc<AtomicU32>, cache: &Arc<Mutex<LruCache<String, bool>>>, block_list: &str, line: &str) {
    let (ip, tag) = get_ip_and_tag(line.trim());
    if !valid_ip(&ip) {
        warn!("Could not parse IP {} from {}", &ip, &line);
        return;
    }
    if tag.len() > 25 {
        warn!("Too long tag '{}' from {}", &tag, &line);
        return;
    }

    if let Ok(cache) = cache.lock() {
        if cache.contains(&ip) {
            debug!("Already banned {}", &ip);
            return;
        }
    }
    if !tag.is_empty() {
        debug!("Got new IP: {} with tag '{}'", &ip, &tag);
    } else {
        debug!("Got new IP: {}", &ip);
    }

    if modify_list(&config.fw_type, true, &nats, &block_list, &config.nats.bl_push_subject, line.trim(), None) {
        let _ = kill_connection(&ip);
        let _ = banned_count.fetch_add(1u32, Ordering::SeqCst);
        // We push this IP to cache before we push it to NATS to avoid duplication
        if let Ok(mut cache) = cache.lock() {
            cache.push(ip.clone(), true);
        }
    }
}

fn modify_list(fw_type: &FwType, add: bool, nats: &Option<Connection>, list: &str, subject: &str, line: &str, comment: Option<String>) -> bool {
    let action = match add {
        true => "add",
        false => "del"
    };

    let (ip, tag) = if line.contains("|") {
        let parts = line.split("|").collect::<Vec<_>>();
        (parts[0].to_owned(), parts[1].to_owned())
    } else {
        (line.to_owned(), String::new())
    };
    if !valid_ip(&ip) {
        warn!("Could not parse IP {} from {}", &ip, &line);
        return false;
    }
    if tag.len() > 25 {
        warn!("Too long tag '{}' from {}", &tag, &line);
        return false;
    }
    let list = match is_ipv6(&ip) {
        true => format!("{}6", list),
        false => list.to_owned()
    };

    let mut result = false;
    if let Ok(addr) = ip.parse::<IpAddr>() {
        match addr {
            IpAddr::V4(ip) => {
                if !ip.is_private() && !ip.is_loopback() && !ip.is_unspecified() {
                    debug!("{} {} to/from {}", action, line, list);
                    let ip = ip.to_string();
                    match fw_type {
                        FwType::IpTables => firewall::ipset_add_or_del(action, &list, &ip, comment),
                        FwType::NfTables => {
                            match add {
                                true => firewall::nft_add(&list, &ip),
                                false => firewall::nft_del(&list, &ip)
                            }
                        }
                    }
                    if !tag.is_empty() {
                        push_to_nats(&nats, subject, format!("{}|{}", &ip, tag));
                    } else {
                        push_to_nats(&nats, subject, ip);
                    }
                    result = true;
                }
            }
            IpAddr::V6(ip) => {
                if !ip.is_loopback() && !ip.is_unspecified() {
                    debug!("{} {} to/from {}", action, line, list);
                    let ip = ip.to_string();
                    match fw_type {
                        FwType::IpTables => firewall::ipset_add_or_del(action, &list, &ip, comment),
                        FwType::NfTables => {
                            match add {
                                true => firewall::nft_add(&list, &ip),
                                false => firewall::nft_del(&list, &ip)
                            }
                        }
                    }
                    if !tag.is_empty() {
                        push_to_nats(&nats, subject, format!("{}|{}", &ip, tag));
                    } else {
                        push_to_nats(&nats, subject, ip);
                    }
                    result = true;
                }
            }
        }
    }
    result
}

/// Publishes some IP to NATS server with particular subject
fn push_to_nats(nats: &Option<Connection>, subject: &str, data: String) {
    if let Some(nats) = &nats {
        match nats.publish(subject, &data) {
            Ok(_) => info!("Pushed {} to [{}]", &data, subject),
            Err(e) => warn!("Error pushing {} to [{}]: {}", &data, subject, e)
        }
    }
}

/// Creates options struct and parses arguments to a struct
fn get_options(args: &Vec<String>) -> (Options, Matches) {
    let mut opts = Options::new();
    opts.optflag("h", "help", "Print this help menu");
    opts.optflag("v", "version", "Print version and exit");
    opts.optflag("i", "interface", "Run user interface to the service");
    opts.optflag("", "install", "Install DisWall as system service (in client mode)");
    opts.optflag("", "update", "Update DisWall to latest release from GitHub");
    opts.optflag("", "after-update", "Perform additional config updates after updating DisWall");
    opts.optflag("", "uninstall", "Uninstall DisWall from your server");
    opts.optflag("d", "debug", "Show trace messages, more than debug");
    opts.optflag("g", "generate", "Generate fresh configuration file. It is better to redirect contents to file.");
    opts.optflag("e", "edit", "Edit firewall configuration file.");
    opts.optopt("c", "config", "Set configuration file path", "FILE");
    opts.optopt("", "log", "Set log file path", "FILE");

    opts.optopt("s", "nats-server", "NATS server name", "DOMAIN");
    opts.optopt("P", "port", "NATS server port", "PORT");
    opts.optopt("n", "name", "NATS client name (login)", "NAME");
    opts.optopt("p", "pass", "NATS password", "PASSWORD");

    opts.optflag("l", "local-only", "Don't connect to NATS server, work only locally");

    opts.optopt("a", "allow-list", "Allow list name", "");
    opts.optopt("b", "block-list", "Block list name", "");

    opts.optopt("", "wl-add-ip", "Add this IP to allow list", "IP");
    opts.optopt("", "wl-add-comm", "Comment to add with IP to allow list", "COMMENT");
    opts.optopt("", "wl-del-ip", "Remove IP from allow list", "IP");
    opts.optopt("", "bl-add-ip", "Add this IP to block list", "IP");
    opts.optopt("", "bl-del-ip", "Remove IP from block list", "IP");

    opts.optflag("k", "kill", "Kill already established connection using `ss -K`");
    opts.optflag("", "server", "Start diswall NATS server to handle init messages.");

    let opt_matches = match opts.parse(&args[1..]) {
        Ok(m) => m,
        Err(f) => panic!("{}", f.to_string())
    };
    (opts, opt_matches)
}

/// Sets up logger in accordance with command line options
fn setup_logger(opt_matches: &Matches) {
    let mut level = LevelFilter::Info;
    if opt_matches.opt_present("d") || env::var("DISWALL_DEBUG").is_ok() {
        level = LevelFilter::Trace;
    }
    // If the daemon is run by systemd, then we don't need time in the log
    let time_level = if env::var_os("INVOCATION_ID").is_some() {
        LevelFilter::Off
    } else {
        LevelFilter::Error
    };
    let config = ConfigBuilder::new()
        .add_filter_ignore_str("rustls::")
        .add_filter_ignore_str("ureq::")
        .set_thread_level(LevelFilter::Error)
        .set_location_level(LevelFilter::Off)
        .set_target_level(LevelFilter::Error)
        .set_level_padding(LevelPadding::Right)
        .set_time_level(time_level)
        .set_time_format_custom(format_description!("[hour]:[minute]:[second].[subsecond digits:3]"))
        .set_time_offset_to_local()
        .unwrap()
        .build();
    match opt_matches.opt_str("log") {
        None => {
            if let Err(e) = TermLogger::init(level, config, TerminalMode::Stdout, ColorChoice::Auto) {
                println!("Unable to initialize logger!\n{}", e);
            }
        }
        Some(path) => {
            let file = match OpenOptions::new().write(true).create(true).open(&path) {
                Ok(mut file) => {
                    file.seek(SeekFrom::End(0)).unwrap();
                    file
                }
                Err(e) => {
                    println!("Could not open log file '{}' for writing!\n{}", &path, e);
                    exit(1);
                }
            };
            let logger = CombinedLogger::init(vec![
                TermLogger::new(level, config.clone(), TerminalMode::Stdout, ColorChoice::Auto),
                WriteLogger::new(level, config, file),
            ]);
            if let Err(e) = logger {
                println!("Unable to initialize logger!\n{}", e);
            }
        }
    }
}

pub fn kill_connection(ip: &str) -> bool {
    let ip = if ip.contains(" ") {
        let parts = ip.split(" ").collect::<Vec<_>>();
        parts[0]
    } else {
        ip
    };
    if ip.parse::<IpAddr>().is_err() {
        error!("Can not parse IP address from {}", ip);
        return false;
    }
    let ip = match is_ipv6(ip) {
        true => format!("[{}]", ip),
        false => ip.to_owned()
    };

    let command = Command::new("ss")
        .arg("--no-header")
        .arg("--numeric")
        .arg("--kill")
        .arg("dst")
        .arg(ip)
        .stdout(Stdio::null())
        .spawn();
    match command {
        Ok(mut child) => {
            match child.wait() {
                Ok(status) => return status.success(),
                Err(e) => error!("Error running ss: {}", e)
            }
        }
        Err(e) => error!("Error running ss: {}", e)
    }
    false
}

/// Collects statistics about dropped packets and dropped bytes from iptables
fn collect_stats_from_iptables(list_name: &str, subject: &str, nats: &Connection, banned_count: &Arc<AtomicU32>, prev_stats: &RwLock<Stats>) {
    let time = OffsetDateTime::now_utc().unix_timestamp();
    let command = Command::new("iptables")
        .arg("-nxvL")
        .arg("INPUT")
        .stdout(Stdio::piped())
        .spawn();
    match command {
        Ok(mut child) => {
            match child.wait() {
                Ok(status) => {
                    if !status.success() {
                        warn!("Could not get stats from iptables");
                        return;
                    }
                    if let Some(mut out) = child.stdout.take() {
                        let mut buf = String::new();
                        if let Ok(_) = out.read_to_string(&mut buf) {
                            let lines = buf.split("\n").collect::<Vec<&str>>();
                            let banned = banned_count.load(Ordering::SeqCst);
                            // We clear banned count every hour
                            banned_count.store(0u32, Ordering::SeqCst);
                            let mut stats = Stats { time, banned, packets_dropped: 0, bytes_dropped: 0, packets_accepted: 0, bytes_accepted: 0 };
                            for line in lines {
                                let text = reduce_spaces(line);
                                let parts = text.trim().split(" ").collect::<Vec<&str>>();
                                // We don't count local traffic
                                if parts.len() < 5 || parts[5].eq("lo") {
                                    continue;
                                }

                                if parts[2].eq("ACCEPT") {
                                    stats.packets_accepted += parts[0].parse::<u64>().unwrap_or(0u64);
                                    stats.bytes_accepted += parts[1].parse::<u64>().unwrap_or(0u64);
                                } else if line.contains(list_name) {
                                    stats.packets_dropped = parts[0].parse::<u64>().unwrap_or(0u64);
                                    stats.bytes_dropped = parts[1].parse::<u64>().unwrap_or(0u64);
                                }
                            }
                            let mut stats_to_push = stats.clone();
                            {
                                // But the second time we subtract previous stats, to make numbers for this hour only
                                let prev = prev_stats.read().unwrap();
                                stats_to_push.bytes_accepted -= prev.bytes_accepted;
                                stats_to_push.bytes_dropped -= prev.bytes_dropped;
                                stats_to_push.packets_accepted -= prev.packets_accepted;
                                stats_to_push.packets_dropped -= prev.packets_dropped;
                            }
                            info!("Statistics: {:?}", &stats_to_push);
                            let data = serde_json::to_string(&stats_to_push).unwrap_or(String::from("Error serializing stats"));
                            // To distribute somehow requests to NATS server we make a random delay
                            let delay = Duration::from_secs(rand::random::<u64>() % 60);
                            thread::sleep(delay);
                            if let Err(e) = nats.publish(subject, &data) {
                                warn!("Could not send stats to NATS server: {}", e);
                            }
                            prev_stats.write().unwrap().copy_from(&stats);
                        }
                    }
                },
                Err(e) => error!("Error running iptables: {}", e)
            }
        }
        Err(e) => error!("Error running iptables: {}", e)
    }
}

/// Collects statistics about dropped packets and dropped bytes from iptables
fn collect_stats_from_nftables(black_list_name: &str, white_list_name: &str, subject: &str, nats: &Connection, banned_count: &Arc<AtomicU32>, prev_stats: &RwLock<Stats>) {
    let time = OffsetDateTime::now_utc().unix_timestamp();
    let command = Command::new("nft")
        .arg("-j")
        .arg("list")
        .arg("counters")
        .stdout(Stdio::piped())
        .spawn();
    match command {
        Ok(mut child) => {
            match child.wait() {
                Ok(status) => {
                    if !status.success() {
                        warn!("Could not get stats from iptables");
                        return;
                    }
                    if let Some(mut out) = child.stdout.take() {
                        let mut buf = String::new();
                        if let Ok(_) = out.read_to_string(&mut buf) {
                            let banned = banned_count.load(Ordering::SeqCst);
                            // We clear banned count every hour
                            banned_count.store(0u32, Ordering::SeqCst);
                            let mut stats = Stats { time, banned, packets_dropped: 0, bytes_dropped: 0, packets_accepted: 0, bytes_accepted: 0 };
                            match json::parse(&buf) {
                                Ok(json) => {
                                    for item in json["nftables"].members() {
                                        for (name, value) in item.entries() {
                                            if !name.eq("counter") {
                                                continue;
                                            }
                                            if value["name"] == white_list_name {
                                                stats.packets_accepted += value["packets"].as_u64().unwrap_or(0u64);
                                                stats.bytes_accepted += value["bytes"].as_u64().unwrap_or(0u64);
                                            }
                                            if value["name"] == black_list_name {
                                                stats.packets_dropped += value["packets"].as_u64().unwrap_or(0u64);
                                                stats.bytes_dropped += value["bytes"].as_u64().unwrap_or(0u64);
                                            }
                                        }
                                    }
                                }
                                Err(e) => error!("Error parsing stats from nft: {}", e)
                            }
                            let mut stats_to_push = stats.clone();
                            {
                                // But the second time we subtract previous stats, to make numbers for this hour only
                                let prev = prev_stats.read().unwrap();
                                stats_to_push.bytes_accepted -= prev.bytes_accepted;
                                stats_to_push.bytes_dropped -= prev.bytes_dropped;
                                stats_to_push.packets_accepted -= prev.packets_accepted;
                                stats_to_push.packets_dropped -= prev.packets_dropped;
                            }
                            info!("Statistics: {:?}", &stats_to_push);
                            let data = serde_json::to_string(&stats_to_push).unwrap_or(String::from("Error serializing stats"));
                            // To distribute somehow requests to NATS server we make a random delay
                            let delay = Duration::from_secs(rand::random::<u64>() % 60);
                            thread::sleep(delay);
                            if let Err(e) = nats.publish(subject, &data) {
                                warn!("Could not send stats to NATS server: {}", e);
                            }
                            prev_stats.write().unwrap().copy_from(&stats);
                        }
                    }
                },
                Err(e) => error!("Error running iptables: {}", e)
            }
        }
        Err(e) => error!("Error running iptables: {}", e)
    }
}