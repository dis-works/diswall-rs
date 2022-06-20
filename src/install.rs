use std::io;
use std::collections::HashSet;
use std::process::{Command, Stdio};
use std::net::SocketAddr;
use std::io::Read;
use std::str::FromStr;
#[cfg(not(windows))]
use std::os::unix::fs::PermissionsExt;
use std::fs::{File, Permissions, set_permissions};
use serde::Deserialize;
use log::{error, info, warn};
#[cfg(not(windows))]
use nix::unistd::mkfifo;
use crate::utils;

const RELEASE_URL: &str = "https://api.github.com/repos/dis-works/diswall-rs/releases/latest";

const BIN_PATH: &str = "/usr/bin/diswall";
const LOG_PATH: &str = "/etc/rsyslog.d/10-diswall.conf";
const UNIT_PATH: &str = "/etc/systemd/system/diswall.service";
const UNIT_FW_PATH: &str = "/etc/systemd/system/diswall-fw-init.service";
const PIPE_PATH: &str = "/var/log/diswall/diswall.pipe";
const CONFIG_PATH: &str = "/etc/diswall/diswall.conf";
const INIT_PATH: &str = "/usr/bin/diswall_init.sh";

const MAX_BIN_SIZE: usize = 10_000_000;

#[cfg(not(windows))]
pub(crate) fn install_client() -> io::Result<()> {
    use std::fs;
    use nix::sys::stat;
    use std::path::Path;
    use std::io::Write;

    // Configuring rsyslog
    if Path::new(LOG_PATH).exists() {
        info!("Not rewriting rsyslogd config file at: {}", LOG_PATH);
    } else {
        fs::create_dir_all("/etc/rsyslog.d/")?;
        fs::write(LOG_PATH, include_bytes!("../scripts/10-diswall.conf"))?;
        info!("Created rsyslogd config file: {}", LOG_PATH);
        match Command::new("systemctl")
            .arg("restart")
            .arg("rsyslog")
            .stdout(Stdio::null()).spawn() {
            Ok(mut child) => {
                if let Ok(r) = child.wait() {
                    if r.success() {
                        info!("Rsyslogd restarted successfully");
                    }
                }
            }
            Err(e) => return Err(e)
        }
    }
    // Adding systemd service for diswall
    if Path::new(UNIT_PATH).exists() {
        info!("Not rewriting service file: {}", UNIT_PATH);
    } else {
        fs::write(UNIT_PATH, include_bytes!("../scripts/diswall.service"))?;
        info!("Created systemd service file: {}", UNIT_PATH);
    }
    // Adding systemd service for firewall initialization
    if Path::new(UNIT_FW_PATH).exists() {
        info!("Not rewriting service file: {}", UNIT_FW_PATH);
    } else {
        fs::write(UNIT_FW_PATH, include_bytes!("../scripts/diswall-fw-init.service"))?;
        info!("Created systemd service file: {}", UNIT_FW_PATH);
    }
    // Creating rsyslog->diswall pipe
    if Path::new(PIPE_PATH).exists() {
        info!("Not rewriting pipe at: {}", PIPE_PATH);
    } else {
        fs::create_dir_all("/var/log/diswall")?;
        mkfifo(PIPE_PATH, stat::Mode::S_IRWXU)?;
        info!("Created firewall pipe: {}", PIPE_PATH);
    }
    // Creating a config for diswall
    if Path::new(CONFIG_PATH).exists() {
        info!("Not rewriting config file: {}", CONFIG_PATH);
    } else {
        fs::create_dir_all("/etc/diswall/")?;
        fs::write(CONFIG_PATH, include_bytes!("../config/diswall.toml"))?;
        info!("Created config file: {}", CONFIG_PATH);
    }

    // Copying this binary to /usr/bin
    let exe_path = std::env::current_exe()?;
    if !exe_path.eq(Path::new(BIN_PATH)) {
        fs::copy(exe_path, BIN_PATH)?;
    }

    if Path::new(INIT_PATH).exists() {
        info!("Not rewriting firewall init script: {}", INIT_PATH);
    } else {
        let services = get_listening_services();
        let mut buffer = String::new();
        for service in services {
            if service.dst_addr.ip().is_loopback() {
                continue;
            }
            let s = if service.src_addr.ip().is_unspecified() {
                format!("iptables -A INPUT -p {} --dport {} -m comment --comment \"{}\" -j ACCEPT", &service.protocol, service.dst_addr.port(), &service.name)
            } else if service.src_addr.ip().is_ipv4() {
                // We work with IPv4 only for now
                format!("iptables -A INPUT -s {} -p {} --dport {} -m comment --comment \"{}\" -j ACCEPT", &service.src_addr.ip(), &service.protocol, service.dst_addr.port(), &service.name)
            } else {
                continue;
            };
            if !buffer.is_empty() {
                buffer.push('\n');
            }
            buffer.push_str(&s);
        }

        let path = Path::new(INIT_PATH);
        match File::create(&path) {
            Ok(mut f) => {
                let script_content = include_str!("../scripts/diswall_init.sh").replace("#diswall_init_rules", &buffer);
                f.write_all(script_content.as_bytes()).expect(&format!("Error saving script to {}", INIT_PATH));
                set_permissions(&path, Permissions::from_mode(0o700))?;
            }
            Err(e) => error!("Error saving script to {}: {}", INIT_PATH, e)
        }
    }

    info!("Installation complete!");
    info!("Please, read and correct firewall init script at {}, it will run at system start.", INIT_PATH);
    info!("Also, check DisWall config at {}, and enter client credentials.", CONFIG_PATH);
    info!("And then you need to enable & start diswall service by running '(sudo) systemctl enable --now diswall.service'.");

    Ok(())
}

#[cfg(not(windows))]
pub(crate) fn update_client() -> io::Result<()> {
    use std::fs;

    let update = get_last_release();
    match update {
        Ok(update) => {
            info!("Latest release on GitHub is {}", &update.name);
            let current_tag = format!("v{}", env!("CARGO_PKG_VERSION"));
            if update.tag_name == current_tag {
                info!("Current version {} is the last version, you don't need to upgrade.", env!("CARGO_PKG_VERSION"));
                return Ok(());
            }

            let arch = env!("BUILD_ARCH");
            let url = update.assets.iter()
                .map(|asset| &asset.browser_download_url)
                .find(|url| url.ends_with(arch));
            let url = match url {
                None => {
                    warn!("Didn't find release build for architecture {}, aborting update", arch);
                    return Err(io::Error::from(io::ErrorKind::Other));
                }
                Some(url) => url
            };

            info!("Downloading new binary from {}", &url);
            match ureq::get(&url).call() {
                Err(e) => warn!("Error getting release build from {}: {}", &url, e),
                Ok(response) => {
                    let mut bytes: Vec<u8> = Vec::with_capacity(MAX_BIN_SIZE);
                    response.into_reader()
                        .take(MAX_BIN_SIZE as u64)
                        .read_to_end(&mut bytes)?;

                    info!("Downloaded binary ({} bytes)", bytes.len());
                    let old_path = format!("{}.old", BIN_PATH);
                    fs::rename(BIN_PATH, &old_path)?;
                    info!("Renamed old binary to {}", &old_path);

                    fs::write(BIN_PATH, &bytes)?;
                    info!("Saved new binary to {}", BIN_PATH);
                    set_permissions(BIN_PATH, Permissions::from_mode(0o755))?;
                    info!("Permissions set successfully");
                    // Restarting service
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
                    warn!("Error restarting diswall service, please do this by yourself");
                }
            }
        }
        Err(s) => error!("{}", s)
    }
    Ok(())
}

#[cfg(not(windows))]
pub(crate) fn uninstall_client() -> io::Result<()> {
    use std::fs;

    // Stopping service
    match Command::new("systemctl")
        .arg("disable")
        .arg("--now")
        .arg("diswall")
        .stdout(Stdio::null()).spawn() {
        Ok(mut child) => {
            if let Ok(r) = child.wait() {
                if r.success() {
                    info!("Service stopped and disabled");
                }
            }
        }
        Err(e) => return Err(e)
    }

    match Command::new("iptables")
        .arg("-F")
        .arg("INPUT")
        .stdout(Stdio::null()).spawn() {
        Ok(mut child) => {
            if let Ok(r) = child.wait() {
                if r.success() {
                    info!("Iptables INPUT table flushed successfully");
                }
            }
        }
        Err(e) => return Err(e)
    }

    fs::remove_file(LOG_PATH)?;
    match Command::new("systemctl")
        .arg("restart")
        .arg("rsyslog")
        .stdout(Stdio::null()).spawn() {
        Ok(mut child) => {
            if let Ok(r) = child.wait() {
                if r.success() {
                    info!("Rsyslogd restarted successfully");
                }
            }
        }
        Err(e) => return Err(e)
    }

    let _ = fs::remove_file(UNIT_PATH);
    let _ = fs::remove_file(UNIT_FW_PATH);
    let _ = fs::remove_file(CONFIG_PATH);
    let _ = fs::remove_file(INIT_PATH);
    let _ = fs::remove_file(PIPE_PATH);
    let _ = fs::remove_file(format!("{}.old", BIN_PATH));
    let _ = fs::remove_file(BIN_PATH);
    info!("Removed all DisWall files");

    Ok(())
}

fn get_listening_services() -> HashSet<Service> {
    let mut result = HashSet::new();

    match Command::new("ss").arg("-nlptuH").stdout(Stdio::piped()).spawn() {
        Ok(mut child) => {
            let mut buffer = String::new();
            let mut io = child.stdout.take().unwrap();
            match io.read_to_string(&mut buffer) {
                Ok(size) => {
                    if size == 0 {
                        warn!("Result of 'ss -nlptuH' is zero!");
                        return result;
                    }
                    let buffer = utils::reduce_spaces(&buffer)
                        .trim()
                        .replace("\n\n", "\n")
                        .replace(" \n", "\n")
                        .replace("%lo:", ":");
                    for line in buffer.split("\n") {
                        let parts = line.split(" ").collect::<Vec<_>>();
                        if parts.len() < 6 {
                            warn!("Error parsing 'ss -nlptuH' output!");
                            return result;
                        }

                        let protocol = String::from(parts[0]);
                        let dst_addr = parts[4].replace("*:", "0.0.0.0:");
                        let dst_addr = match SocketAddr::from_str(&dst_addr) {
                            Ok(addr) => addr,
                            Err(e) => {
                                warn!("Cannot parse dst address '{}': {}", dst_addr, e);
                                continue;
                            }
                        };
                        // Change the port from * to 0 to parse address successfully
                        let src_addr = parts[5].replace(":*", ":0").replace("*:0", "0.0.0.0:0");
                        let src_addr = match SocketAddr::from_str(&src_addr) {
                            Ok(addr) => addr,
                            Err(e) => {
                                warn!("Cannot parse src address '{}': {}", &src_addr, e);
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
        Err(e) => warn!("Cannot run 'ss -nlptuH': {}", e)
    }

    result
}

fn get_last_release() -> Result<Update, String> {
    match ureq::get(RELEASE_URL).call() {
        Ok(response) => {
            let string = response.into_string().unwrap();
            match serde_json::from_str(&string) {
                Ok(update) => Ok(update),
                Err(e) => Err(e.to_string())
            }
        },
        Err(e) => Err(e.to_string())
    }
}

#[derive(Debug, Eq, Hash, PartialEq)]
struct Service {
    name: String,
    protocol: String,
    src_addr: SocketAddr,
    dst_addr: SocketAddr,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct Update {
    html_url: String,
    name: String,
    tag_name: String,
    draft: bool,
    prerelease: bool,
    assets: Vec<Asset>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct Asset {
    name: String,
    browser_download_url: String,
}

#[test]
pub fn test1() {
    let update = get_last_release();
    println!("Release: {:?}", &update);
    assert!(update.is_ok());
}