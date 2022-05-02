use std::convert::Infallible;
use std::{env, io, thread};
use std::collections::HashSet;
use std::fs::{File, OpenOptions, Permissions, set_permissions};
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::net::{IpAddr, SocketAddrV4};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, exit, Stdio};
use std::str::FromStr;
use std::time::Duration;
use getopts::{Matches, Options};
use log::{debug, error, info, LevelFilter, warn};
use nats::Connection;
use nix::unistd::mkfifo;
use simplelog::{ColorChoice, CombinedLogger, ConfigBuilder, LevelPadding, TerminalMode, TermLogger, WriteLogger};
use ipset::ipset_list_exists;
use crate::config::Config;
use crate::ipset::{ipset_list_create_bl, ipset_list_create_wl};
use crate::server::run_server;

mod config;
mod ipset;
mod server;

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
    config.override_config_from_args(&opt_matches);
    config.init_nats_subjects();
    setup_logger(&opt_matches);

    if opt_matches.opt_present("install") {
        info!("Installing DisWall v{}", env!("CARGO_PKG_VERSION"));
        if let Err(e) = install_client() {
            error!("Error installing DisWall: {}", &e);
            return Err(100);
        }
        return Ok(());
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
                if !config.server_mode {
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
    if config.server_mode {
        run_server(config, nats);
        return Ok(());
    }

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

    if let Err(e) = lock_on_pipe(config, nats) {
        error!("Error reading pipe: {}", e);
    }
    Ok(())
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
                    ipset::run_ipset("add", &list_name, split[0], Some(split[1]));
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
fn lock_on_pipe(config: Config, nats: Option<Connection>) -> Result<Infallible, io::Error> {
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
            if let Ok(addr) = line.trim().parse::<IpAddr>() {
                match addr {
                    IpAddr::V4(ip) => {
                        if !ip.is_private() && !ip.is_loopback() && !ip.is_unspecified() {
                            debug!("Adding {} to {}", &line.trim(), config.ipset_black_list.as_str());
                            ipset::run_ipset("add", &block_list, line.trim(), None);
                            push_to_nats(&nats, &config.nats.bl_add_subject, ip.to_string());
                        }
                    }
                    IpAddr::V6(ip) => {
                        if !ip.is_loopback() && !ip.is_unspecified() {
                            debug!("Adding {} to {}", &line.trim(), config.ipset_black_list.as_str());
                            ipset::run_ipset("add", &block_list, line.trim(), None);
                            push_to_nats(&nats, &config.nats.bl_add_subject, ip.to_string());
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

fn install_client() -> io::Result<()> {
    use std::fs;
    use nix::sys::stat;

    // Configuring rsyslog
    fs::create_dir_all("/etc/rsyslog.d/")?;
    fs::write("/etc/rsyslog.d/10-diswall.conf", include_bytes!("../scripts/10-diswall.conf"))?;
    info!("Created rsyslogd config file: /etc/rsyslog.d/10-diswall.conf");
    // Adding systemd service for diswall
    fs::write("/etc/systemd/system/diswall.service", include_bytes!("../scripts/diswall.service"))?;
    info!("Created systemd service file: /etc/systemd/system/diswall.service");
    // Adding systemd service for firewall initialization
    fs::write("/etc/systemd/system/diswall-fw-init.service", include_bytes!("../scripts/diswall-fw-init.service"))?;
    info!("Created systemd service file: /etc/systemd/system/diswall-fw-init.service");
    // Creating rsyslog->diswall pipe
    fs::create_dir_all("/var/log/diswall")?;
    mkfifo("/var/log/diswall/diswall.pipe", stat::Mode::S_IRWXU)?;
    info!("Created firewall pipe: /var/log/diswall/diswall.pipe");
    // Creating a config for diswall
    fs::create_dir_all("/etc/diswall/")?;
    fs::write("/etc/diswall/diswall.conf", include_bytes!("../config/diswall.toml"))?;
    info!("Created config file: /etc/diswall/diswall.conf");

    // Copying this binary to /usr/bin
    let exe_path = std::env::current_exe()?;
    fs::copy(exe_path, "/usr/bin/diswall")?;

    let services = get_listening_services();
    let mut buffer = String::new();
    for service in services {
        if service.dst_addr.ip().is_loopback() {
            continue;
        }
        if !buffer.is_empty() {
            buffer.push('\n');
        }
        let s = if service.src_addr.ip().is_unspecified() {
            format!("iptables -A INPUT -p {} --dport {} -m comment --comment \"{}\" -j ACCEPT", &service.protocol, service.dst_addr.port(), &service.name)
        } else {
            format!("iptables -A INPUT -s {} -p {} --dport {} -m comment --comment \"{}\" -j ACCEPT", &service.src_addr.ip(), &service.protocol, service.dst_addr.port(), &service.name)
        };
        buffer.push_str(&s);
    }
    let script_content = include_str!("../scripts/diswall_init.sh").replace("#diswall_init_rules", &buffer);

    let path = Path::new("/usr/bin/diswall_init.sh");
    match File::create(&path) {
        Ok(mut f) => {
            f.write_all(script_content.as_bytes()).expect("Error saving script to /usr/bin/diswall_init.sh");
            set_permissions(&path, Permissions::from_mode(0700))?;
        }
        Err(e) => error!("Error saving script to /usr/bin/diswall_init.sh: {}", e)
    }

    info!("Installation complete!");
    info!("Please, read and correct firewall init script at /usr/bin/diswall_init.sh, it will run at system start.");
    info!("Also, check DisWall config at /etc/diswall/diswall.conf, and enter client credentials.");
    info!("And then you need to enable & start diswall service by running '(sudo) systemctl enable --now diswall.service'.");

    Ok(())
}

fn get_listening_services() -> HashSet<Service> {
    let mut result = HashSet::new();

    match Command::new("ss").arg("-4nlptuH").stdout(Stdio::piped()).spawn() {
        Ok(mut child) => {
            let mut buffer = String::new();
            let mut io = child.stdout.take().unwrap();
            match io.read_to_string(&mut buffer) {
                Ok(size) => {
                    if size == 0 {
                        warn!("Result of 'ss -4nlptuH' is zero!");
                        return result;
                    }
                    let buffer = reduce_spaces(&buffer)
                        .trim()
                        .replace("\n\n", "\n")
                        .replace(" \n", "\n")
                        .replace("%lo:", ":");
                    for line in buffer.split("\n") {
                        let parts = line.split(" ").collect::<Vec<_>>();
                        if parts.len() < 6 {
                            warn!("Error parsing 'ss -4nlptuH' output!");
                            return result;
                        }

                        let protocol = String::from(parts[0]);
                        let dst_addr = match SocketAddrV4::from_str(parts[4]) {
                            Ok(addr) => addr,
                            Err(e) => {
                                warn!("Cannot parse address '{}': {}", parts[4], e);
                                continue;
                            }
                        };
                        // Change the port from * to 0 to parse address successfully
                        let src_addr = parts[5].replace(":*", ":0");
                        let src_addr = match SocketAddrV4::from_str(&src_addr) {
                            Ok(addr) => addr,
                            Err(e) => {
                                warn!("Cannot parse address '{}': {}", &src_addr, e);
                                continue;
                            }
                        };

                        // Most of the sockets have 7 parts, the last of them has users part.
                        // But sometimes, for example with WireGuard, socket is created by kernel, and there is no 7th part.
                        let name = if parts.len() == 6 {
                            String::from("kernel")
                        } else {
                            if let Some(start) = parts[6].find('\"') {
                                let s = parts[6][start + 1..].to_owned();
                                if let Some(end) = s.find('\"') {
                                    s[..end].to_owned()
                                } else {
                                    String::from("unknown")
                                }
                            } else {
                                String::from("unknown")
                            }
                        };
                        result.insert(Service { name, protocol, src_addr, dst_addr });
                    }
                }
                Err(e) => warn!("Error reading pipe: {}", e)
            }
        }
        Err(e) => warn!("Cannot run 'ss -4nlptuH': {}", e)
    }

    result
}

fn reduce_spaces(string: &str) -> String {
    let mut s = string.to_owned();
    let mut len = string.len();
    loop {
        s = s.replace("  ", " ");
        if len == s.len() {
            return s;
        }
        len = s.len();
    }
}

#[derive(Debug, Eq, Hash, PartialEq)]
struct Service {
    name: String,
    protocol: String,
    src_addr: SocketAddrV4,
    dst_addr: SocketAddrV4,
}