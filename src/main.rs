use std::convert::Infallible;
use std::{env, io, thread};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::net::IpAddr;
use std::process::exit;
use std::time::Duration;
use getopts::{Matches, Options};
use log::{debug, error, info, LevelFilter, warn};
use nats::Connection;
use simplelog::{ColorChoice, CombinedLogger, ConfigBuilder, LevelPadding, TerminalMode, TermLogger, WriteLogger};
use ipset::ipset_list_exists;
use crate::config::{Config, get_hostname};
use crate::server::run_server;

mod config;
mod ipset;
mod server;

fn main() {
    let args: Vec<String> = env::args().collect();
    let program = args[0].clone();

    let (options, opt_matches) = get_options(&args);

    if opt_matches.opt_present("h") {
        let brief = format!("Usage: {} [options]", program);
        println!("{}", options.usage(&brief));
        exit(0);
    }

    if opt_matches.opt_present("v") {
        println!("DisWall v{}", env!("CARGO_PKG_VERSION"));
        exit(0);
    }

    if opt_matches.opt_present("g") {
        println!("{}", include_str!("../config/diswall.toml"));
        exit(0);
    }

    let file_name = match opt_matches.opt_str("c") {
        None => String::from("diswall.toml"),
        Some(name) => name
    };
    // Load or create default config
    let mut config = match Config::from_file(&file_name) {
        None => Config::default(),
        Some(config) => config
    };

    // Override config options by options from arguments
    override_config_from_args(&opt_matches, &mut config);
    setup_logger(&opt_matches);
    debug!("Loaded config:\n{:#?}", &config);

    let run_as_server = opt_matches.opt_present("server");

    let nats = if !config.local_only && !config.nats.server.is_empty() {
        //let hostname = config::get_hostname();
        debug!("Connecting to NATS server...");
        let nats = nats::Options::with_user_pass(&config.nats.client_name, &config.nats.client_pass)
            .with_name("DisWall")
            .error_callback(|error| error!("NATS connection error: {}", error))
            .connect(format!("nats://{}:{}", &config.nats.server, &config.nats.port));
        match nats {
            Err(e) => {
                error!("Error connecting to NATS server: {}", e);
                exit(1);
            }
            Ok(nats) => {
                if !run_as_server {
                    info!("Connected to NATS server, setting up handlers");
                    start_nats_handlers(&mut config, &nats);
                }
                Some(nats)
            }
        }
    } else {
        None
    };

    // If this binary is executed with 'server' parameter we start only NATS server
    if run_as_server {
        run_server(config, nats);
        return;
    }

    check_ipset_list_exists(&config.ipset_black_list);
    check_ipset_list_exists(&config.ipset_white_list);

    if let Err(e) = lock_on_pipe(config, nats) {
        error!("Error reading pipe: {}", e);
    }
}

fn check_ipset_list_exists(list_name: &String) {
    if !ipset_list_exists(list_name) {
        error!("ipset list {} does not exist!", list_name);
        exit(1);
    }
}

fn start_nats_handlers(config: &mut Config, nats: &Connection) {
    // Getting whitelist for this client/host
    let hostname = get_hostname();
    let msg = format!("{}.{}", config.nats.client_name, hostname);
    if let Ok(message) = nats.request(&config.nats.wl_init_subject, &msg) {
        let string = String::from_utf8(message.data).unwrap_or(String::default());
        // Changing from individual name to common name
        let s1 = format!(" {}-{} ", &config.ipset_white_list, &config.nats.client_name);
        let s2 = format!(" {} ", &config.ipset_white_list);
        let string = string.replace(&s1, &s2);
        for line in string.lines() {
            debug!("To whitelist: {}", line);
        }
        ipset::run_ipset("restore", &string, &vec![]);
    }

    // Getting blocklist from server
    if let Ok(message) = nats.request(&config.nats.bl_init_subject, &msg) {
        let string = String::from_utf8(message.data).unwrap_or(String::default());
        // Changing from individual name to common name
        // TODO remove print in production
        for line in string.lines() {
            debug!("To blacklist: {}", line);
        }
        ipset::run_ipset("restore", &string, &vec![]);
    }

    // Subscribe to new IPs for whitelist
    if let Ok(sub) = nats.subscribe(&config.nats.wl_add_subject) {
        let list = config.ipset_white_list.clone();
        sub.with_handler(move |message| {
            if let Ok(string) = String::from_utf8(message.data) {
                let split = string.split("|").collect::<Vec<&str>>();
                // If no comment
                if split.len() == 1 {
                    debug!("Got IP for whitelist: {}", split[0]);
                    ipset::run_ipset("add", split[0], &vec![list.as_str()]);
                } else {
                    debug!("Got IP for whitelist: {} ({})", split[0], split[1]);
                    ipset::run_ipset("add", split[0], &vec![list.as_str(), split[1]]);
                }
            }
            Ok(())
        });
        info!("Subscribed to whitelist additions");
    }

    // Subscribe for new IPs for blocklist
    if let Ok(sub) = nats.subscribe(&config.nats.bl_add_subject) {
        let list = config.ipset_black_list.clone();
        sub.with_handler(move |message| {
            if let Ok(string) = String::from_utf8(message.data) {
                let split = string.split("|").collect::<Vec<&str>>();
                // If no comment
                if split.len() == 1 {
                    debug!("Got IP for blocklist: {}", split[0]);
                } else {
                    debug!("Got IP for blocklist {} from {}", split[0], split[1]);
                }
                ipset::run_ipset("add", split[0], &vec![list.as_str()]); // Don't add comment to ipset
            }
            Ok(())
        });
        debug!("Subscribed to blocklist additions");
    }

    // Subscribe for IPs to delete from whitelist
    if let Ok(sub) = nats.subscribe(&config.nats.wl_del_subject) {
        let list = config.ipset_white_list.clone();
        sub.with_handler(move |message| {
            if let Ok(string) = String::from_utf8(message.data) {
                debug!("Got IP to delete from whitelist: {}", &string);
                ipset::run_ipset("del", &string, &vec![list.as_str()]);
            }
            Ok(())
        });
        info!("Subscribed to whitelist removals");
    }

    // Subscribe for IPs to delete from blocklist
    if let Ok(sub) = nats.subscribe(&config.nats.bl_del_subject) {
        let list = config.ipset_black_list.clone();
        sub.with_handler(move |message| {
            if let Ok(string) = String::from_utf8(message.data) {
                debug!("Got IP to delete from blocklist: {}", &string);
                ipset::run_ipset("del", &string, &vec![list.as_str()]);
            }
            Ok(())
        });
        info!("Subscribed to blocklist removals");
    }
}

/// The main function, that reads iptables log and works with IPs
fn lock_on_pipe(config: Config, nats: Option<Connection>) -> Result<Infallible, io::Error> {
    let f = File::open(&config.pipe_path)?;
    let mut reader = BufReader::new(f);

    debug!("Pipe opened, waiting for IPs");
    let block_list = [config.ipset_black_list.as_str()];
    let mut line = String::new();
    let delay = Duration::from_millis(15);
    loop {
        let len = reader.read_line(&mut line)?;
        if len > 0 {
            debug!("Got new IP: {}", line.trim());
            if let Ok(addr) = line.trim().parse::<IpAddr>() {
                match addr {
                    IpAddr::V4(ip) => {
                        if !ip.is_private() && !ip.is_loopback() && !ip.is_unspecified() {
                            debug!("Adding {} to {}", &line.trim(), config.ipset_black_list.as_str());
                            ipset::run_ipset("add", line.trim(), &block_list);
                            push_to_nats(&nats, &config.nats.bl_add_subject, ip.to_string(), &config.nats.hostname);
                        }
                    }
                    IpAddr::V6(ip) => {
                        if !ip.is_loopback() && !ip.is_unspecified() {
                            debug!("Adding {} to {}", &line.trim(), config.ipset_black_list.as_str());
                            ipset::run_ipset("add", line.trim(), &block_list);
                            push_to_nats(&nats, &config.nats.bl_add_subject, ip.to_string(), &config.nats.hostname);
                        }
                    }
                }
            }
            line.clear();
        } else {
            thread::sleep(delay);
        }
    }
}

/// Publishes some IP to NATS server with particular subject
fn push_to_nats(nats: &Option<Connection>, subject: &str, ip: String, comment: &String) {
    if let Some(nats) = &nats {
        let data = format!("{}|{}", ip, &comment);
        match nats.publish(subject, &data) {
            Ok(_) => info!("Pushed {} to [{}]", &data, subject),
            Err(e) => warn!("Error pushing {} to [{}]: {}", &data, subject, e)
        }
    }
}

fn override_config_from_args(opt_matches: &Matches, config: &mut Config) {
    if let Some(name) = opt_matches.opt_str("f") {
        config.pipe_path = name;
    }
    if let Some(server) = opt_matches.opt_str("s") {
        config.nats.server = server;
    }
    if let Ok(port) = opt_matches.opt_get::<u16>("P") {
        config.nats.port = port.unwrap_or(4222);
    }
    if let Some(name) = opt_matches.opt_str("n") {
        config.nats.client_name = name;
    }
    if let Some(pass) = opt_matches.opt_str("p") {
        config.nats.client_pass = pass;
    }
    if opt_matches.opt_present("l") {
        config.local_only = true;
    }
    if let Some(list) = opt_matches.opt_str("allow-list") {
        config.ipset_white_list = list;
    }
    if let Some(list) = opt_matches.opt_str("block-list") {
        config.ipset_black_list = list;
    }
}

/// Creates options struct and parses arguments to a struct
fn get_options(args: &Vec<String>) -> (Options, Matches) {
    let mut opts = Options::new();
    opts.optflag("h", "help", "Print this help menu");
    opts.optflag("v", "version", "Print version and exit");
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
        .set_time_level(LevelFilter::Error)
        .set_time_format_str("%F %T%.3f")
        .set_time_to_local(true)
        .set_level_padding(LevelPadding::Right)
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