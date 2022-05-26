use std::convert::Infallible;
use std::{env, io, thread};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom};
use std::net::{IpAddr};
use std::process::{Command, exit, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;
use getopts::{Matches, Options};
use log::{debug, error, info, LevelFilter, warn};
use nats::Connection;
use simplelog::{ColorChoice, CombinedLogger, ConfigBuilder, format_description, LevelPadding, TerminalMode, TermLogger, WriteLogger};
use time::OffsetDateTime;
use crate::config::Config;
#[cfg(not(windows))]
use crate::ipset::{ipset_list_create_bl, ipset_list_create_wl, ipset_list_exists};
use crate::server::run_server;
#[cfg(not(windows))]
use crate::install::install_client;
use crate::timer::HourlyTimer;
use crate::types::Stats;

mod config;
mod ipset;
mod server;
mod timer;
mod types;
#[cfg(not(windows))]
mod install;

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

    if let Some(ip) = opt_matches.opt_str("k") {
        if kill_connection(&ip) {
            println!("Killed connection with {}", &ip);
        }
        return Ok(())
    }

    let file_name = match opt_matches.opt_str("c") {
        None => String::from("/etc/diswall/diswall.conf"),
        Some(name) => name
    };
    // Load or create default config
    let mut config = match Config::from_file(&file_name) {
        None => Config::default(),
        Some(config) => config
    };

    // Override config options by options from arguments
    config.override_config_from_args(&opt_matches);
    config.init_nats_subjects();
    setup_logger(&opt_matches);

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

    debug!("Loaded config:\n{:#?}", &config);

    let nats = if !config.local_only && !config.nats.server.is_empty() {
        //let hostname = config::get_hostname();
        debug!("Connecting to NATS server...");
        let nats = nats::Options::with_user_pass(&config.nats.client_name, &config.nats.client_pass)
            .with_name("DisWall")
            .error_callback(|error| error!("NATS error: {}", error))
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
                    start_nats_handlers(&mut config, &nats);
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

    #[cfg(not(windows))]
    {
        if !ipset_list_exists(&config.ipset_black_list) {
            info!("ipset list {} does not exist, creating", &config.ipset_black_list);
            if !ipset_list_create_bl(&config.ipset_black_list) {
                error!("Error creating ipset list {}", &config.ipset_black_list);
                return Err(2);
            }
        }

        if !ipset_list_exists(&config.ipset_white_list) {
            info!("ipset list {} does not exist, creating", &config.ipset_white_list);
            if !ipset_list_create_wl(&config.ipset_white_list) {
                error!("Error creating ipset list {}", &config.ipset_white_list);
                return Err(3);
            }
        }
    }

    let banned_count = Arc::new(AtomicU32::new(0));
    if config.send_statistics {
        if let Some(nats) = nats.clone() {
            let banned_count = banned_count.clone();
            let list_name = config.ipset_black_list.clone();
            let subject = config.nats.stats_subject.clone();
            let mut timer = HourlyTimer::new(move || {
                collect_stats(&list_name, &subject, &nats, &banned_count);
            });
            let _ = timer.start();
        }
    }

    if let Err(e) = lock_on_pipe(config, nats, &banned_count) {
        error!("Error reading pipe: {}", e);
    }
    Ok(())
}

fn process_ips_from_parameters(config: &Config, opt_matches: &Matches, nats: Option<Connection>) -> bool {
    if let Some(ip) = opt_matches.opt_str("wl-add-ip") {
        let comment = match opt_matches.opt_str("wl-add-comm") {
            None => None,
            Some(s) => Some(s)
        };
        modify_list(true, &nats, &config.ipset_white_list, &config.nats.wl_add_subject, &ip, comment);
        return true;
    }

    if let Some(ip) = opt_matches.opt_str("wl-del-ip") {
        modify_list(false, &nats, &config.ipset_white_list, &config.nats.wl_del_subject, &ip, None);
        return true;
    }

    if let Some(ip) = opt_matches.opt_str("bl-add-ip") {
        modify_list(true, &nats, &config.ipset_black_list, &config.nats.bl_add_subject, &ip, None);
        let _ = kill_connection(&ip);
        return true;
    }

    if let Some(ip) = opt_matches.opt_str("bl-del-ip") {
        modify_list(true, &nats, &config.ipset_black_list, &config.nats.bl_del_subject, &ip, None);
        return true;
    }

    false
}

fn start_nats_handlers(config: &mut Config, nats: &Connection) {
    let msg = String::new();
    if let Ok(message) = nats.request(&config.nats.wl_init_subject, &msg) {
        let string = String::from_utf8(message.data).unwrap_or(String::default());
        let mut buf = format!("create -exist {} hash:net comment", &config.ipset_white_list);
        for line in string.lines() {
            buf.push('\n');
            buf.push_str(&format!("add {} {}", &config.ipset_white_list, line));
            // TODO remove print in production
            debug!("To whitelist: {}", line);
        }
        ipset::run_ipset("restore", "", &buf, None);
    }

    // Getting blocklist from server
    if let Ok(message) = nats.request(&config.nats.bl_init_subject, &msg) {
        let string = String::from_utf8(message.data).unwrap_or(String::default());
        let mut buf = format!("create -exist {} hash:ip hashsize 32768 maxelem 1000000 timeout 86400", &config.ipset_black_list);
        for line in string.lines() {
            buf.push('\n');
            buf.push_str(&format!("add {} {}", &config.ipset_black_list, line));
            // TODO remove print in production
            debug!("To blacklist: {}", line);
        }
        ipset::run_ipset("restore", "", &buf, None);
    }

    // Subscribe to new IPs for whitelist
    if let Ok(sub) = nats.subscribe(&config.nats.wl_add_subject) {
        let list_name = config.ipset_white_list.clone();
        sub.with_handler(move |message| {
            if let Ok(string) = String::from_utf8(message.data) {
                let split = string.split("|").collect::<Vec<&str>>();
                // If no comment
                if split.len() == 1 {
                    debug!("Got IP for whitelist: {}", split[0]);
                    ipset::run_ipset("add", &list_name, split[0], None);
                } else {
                    debug!("Got IP for whitelist: {} ({})", split[0], split[1]);
                    ipset::run_ipset("add", &list_name, split[0], Some(split[1].to_owned()));
                }
            }
            Ok(())
        });
        info!("Subscribed to {}", &config.nats.wl_add_subject);
    }

    // Subscribe for new IPs for blocklist
    if let Ok(sub) = nats.subscribe(&config.nats.bl_add_subject) {
        let list_name = config.ipset_black_list.clone();
        sub.with_handler(move |message| {
            if let Ok(string) = String::from_utf8(message.data) {
                ipset::run_ipset("add", &list_name, &string, None);
                let _ = kill_connection(&string);
            }
            Ok(())
        });
        info!("Subscribed to {}", &config.nats.bl_add_subject);
    }

    // Subscribe for new IPs for blocklist
    if let Ok(sub) = nats.subscribe(&config.nats.bl_global_subject) {
        let list_name = config.ipset_black_list.clone();
        sub.with_handler(move |message| {
            if let Ok(string) = String::from_utf8(message.data) {
                ipset::run_ipset("add", &list_name, &string, None);
                let _ = kill_connection(&string);
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
                ipset::run_ipset("del", &list_name, &string, None);
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
                ipset::run_ipset("del", &list_name, &string, None);
            }
            Ok(())
        });
        info!("Subscribed to {}", &config.nats.bl_del_subject);
    }
}

/// The main function, that reads iptables log and works with IPs
fn lock_on_pipe(config: Config, nats: Option<Connection>, banned_count: &Arc<AtomicU32>) -> Result<Infallible, io::Error> {
    let f = File::open(&config.pipe_path)?;
    let mut reader = BufReader::new(f);

    debug!("Pipe opened, waiting for IPs");
    let block_list = config.ipset_black_list.as_str();
    let mut line = String::new();
    let delay = Duration::from_millis(15);
    loop {
        let len = reader.read_line(&mut line)?;
        if len > 0 {
            debug!("Got new IP: {}", line.trim());
            modify_list(true, &nats, &block_list, &config.nats.bl_add_subject, line.trim(), None);
            let _ = banned_count.fetch_add(1u32, Ordering::SeqCst);
            line.clear();
        } else {
            thread::sleep(delay);
        }
    }
}

fn modify_list(add: bool, nats: &Option<Connection>, list: &str, subject: &str, line: &str, comment: Option<String>) {
    let action = match add {
        true => "add",
        false => "del"
    };
    if let Ok(addr) = line.parse::<IpAddr>() {
        match addr {
            IpAddr::V4(ip) => {
                if !ip.is_private() && !ip.is_loopback() && !ip.is_unspecified() {
                    debug!("{} {} to/from {}", action, line, list);
                    ipset::run_ipset(action, &list, line, comment);
                    push_to_nats(&nats, subject, ip.to_string());
                }
            }
            IpAddr::V6(ip) => {
                if !ip.is_loopback() && !ip.is_unspecified() {
                    debug!("{} {} to/from {}", action, line, list);
                    ipset::run_ipset(action, &list, line, comment);
                    push_to_nats(&nats, subject, ip.to_string());
                }
            }
        }
    }
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
    opts.optflag("", "install", "Install DisWall as system service (in client mode)");
    opts.optflag("d", "debug", "Show trace messages, more than debug");
    opts.optflag("g", "generate", "Generate fresh configuration file. It is better to redirect contents to file.");
    opts.optopt("c", "config", "Set configuration file path", "FILE");
    opts.optopt("", "log", "Set log file path", "FILE");

    opts.optopt("f", "pipe-file", "Named pipe from which to fetch IPs", "FILE");

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
    // TODO
    //opts.optopt("", "creds", "Use credentials file", "FILE");

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
    let config = ConfigBuilder::new()
        .add_filter_ignore_str("rustls::")
        .set_thread_level(LevelFilter::Error)
        .set_location_level(LevelFilter::Off)
        .set_target_level(LevelFilter::Error)
        .set_level_padding(LevelPadding::Right)
        .set_time_level(LevelFilter::Error)
        .set_time_format_custom(format_description!("[hour]:[minute]:[second].[subsecond]"))
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
    if ip.parse::<IpAddr>().is_err() {
        error!("Can not parse IP address from {}", ip);
        return false;
    }

    let command = Command::new("ss")
        .arg("-K")
        .arg("dst")
        .arg(ip)
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
fn collect_stats(list_name: &str, subject: &str, nats: &Connection, banned_count: &Arc<AtomicU32>) {
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
                            for line in lines {
                                if !line.contains(list_name) {
                                    warn!("Could not get stats from iptables");
                                    return;
                                }
                                let text = line.replace("  ", " ");
                                let parts = text.trim().split(" ").collect::<Vec<&str>>();
                                let packets_dropped = parts[0].parse::<u64>().unwrap_or(0u64);
                                let bytes_dropped = parts[1].parse::<u64>().unwrap_or(0u64);
                                let time = OffsetDateTime::now_utc().unix_timestamp();
                                let banned = banned_count.load(Ordering::SeqCst);
                                let stats = Stats { time, banned, packets_dropped, bytes_dropped };
                                info!("Statistics: {:?}", &stats);
                                let data = serde_json::to_string(&stats).unwrap_or(String::from("Error serializing stats"));
                                // We clear banned count every hour
                                banned_count.store(0u32, Ordering::SeqCst);
                                // To distribute somehow requests to NATS server we make a random delay
                                let delay = Duration::from_secs(rand::random::<u64>() % 60);
                                thread::sleep(delay);
                                if let Err(e) = nats.publish(subject, &data) {
                                    warn!("Could not send stats to NATS server: {}", e);
                                }
                            }
                        }
                    }
                },
                Err(e) => error!("Error running iptables: {}", e)
            }
        }
        Err(e) => error!("Error running iptables: {}", e)
    }
}