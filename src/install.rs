use std::io;
use std::collections::HashSet;
use std::process::{Command, Stdio};
use std::net::SocketAddr;
use std::io::{Error, Read};
use std::str::FromStr;
#[cfg(not(windows))]
use std::os::unix::fs::PermissionsExt;
use std::fs::{File, Permissions, set_permissions};
use serde::Deserialize;
use log::{error, info, warn};
#[cfg(not(windows))]
use nix::unistd::mkfifo;
use crate::firewall::get_installed_fw_type;
use crate::utils::replace_string_in_file;
use crate::{FwType, utils};

const RELEASE_URL: &str = "https://api.github.com/repos/dis-works/diswall-rs/releases/latest";

const BIN_PATH: &str = "/usr/bin/diswall";
const LOG_PATH: &str = "/etc/rsyslog.d/10-diswall.conf";
const UNIT_PATH: &str = "/etc/systemd/system/diswall.service";
const UNIT_IPT_INIT_PATH: &str = "/etc/systemd/system/diswall-fw-init.service";
const PIPE_PATH: &str = "/var/log/diswall/diswall.pipe";
const CONFIG_PATH: &str = "/etc/diswall/diswall.conf";
const IPT_INIT_PATH: &str = "/usr/bin/diswall_init.sh";
const NFT_CONF_PATH: &str = "/etc/nftables.conf";

const MAX_BIN_SIZE: usize = 10_000_000;

#[cfg(not(windows))]
pub(crate) fn install_client() -> io::Result<()> {
    use std::fs;
    use nix::sys::stat;
    use std::path::Path;

    let fw_type = match get_installed_fw_type() {
        Ok(fw_type) => fw_type,
        Err(e) => {
            error!("{}", e);
            return Err(io::Error::from(io::ErrorKind::Other));
        }
    };

    // Configuring rsyslog
    if Path::new(LOG_PATH).exists() {
        info!("Not rewriting rsyslogd config file at: {}", LOG_PATH);
    } else {
        install_rsyslog_config()?;
    }
    // Adding systemd service for diswall
    if Path::new(UNIT_PATH).exists() {
        info!("Not rewriting service file: {}", UNIT_PATH);
    } else {
        fs::write(UNIT_PATH, include_bytes!("../scripts/diswall.service"))?;
        info!("Created systemd service file: {}", UNIT_PATH);
    }
    // Creating rsyslog->diswall pipe
    if Path::new(PIPE_PATH).exists() {
        info!("Not rewriting pipe at: {}", PIPE_PATH);
    } else {
        fs::create_dir_all("/var/log/diswall")?;
        mkfifo(PIPE_PATH, stat::Mode::S_IRWXU & stat::Mode::S_IRWXG)?;
        if let Err(e) = change_group_ownership(PIPE_PATH, "syslog") {
            warn!("Error changing group ownership of {}: {e}", PIPE_PATH);
        }
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

    match fw_type {
        FwType::IpTables => install_ipt_part()?,
        FwType::NfTables => install_nft_part()?
    }

    info!("Installation complete!");
    warn!("IMPORTANT: Read and edit firewall init script by using 'diswall -e', it will run at system start.");
    warn!("Also, check DisWall config at {}, and enter client credentials.", CONFIG_PATH);
    info!("And then you need to enable & start diswall service by running '(sudo) systemctl enable --now diswall.service'.");

    Ok(())
}

fn install_rsyslog_config() -> io::Result<()> {
    use std::fs;

    fs::create_dir_all("/etc/rsyslog.d/")?;
    fs::write(LOG_PATH, include_bytes!("../scripts/10-diswall.conf"))?;
    info!("Created rsyslogd config file: {}", LOG_PATH);
    restart_rsyslog()
}

fn restart_rsyslog() -> Result<(), Error> {
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
    Ok(())
}

pub fn update_rsyslog_config() -> io::Result<()> {
    use std::fs;

    fs::create_dir_all("/etc/rsyslog.d/")?;
    if let Ok(text) = fs::read_to_string(LOG_PATH) {
        if text.contains("PROTO=([A-Za-z0-9]+)") {
            return Ok(());
        }
    }
    fs::write(LOG_PATH, include_bytes!("../scripts/10-diswall.conf"))?;
    info!("Updated rsyslogd config file: {}", LOG_PATH);
    restart_rsyslog()
}

fn install_ipt_part() -> io::Result<()> {
    use std::fs;
    use std::path::Path;
    use std::io::Write;

    // Adding systemd service for firewall initialization
    if Path::new(UNIT_IPT_INIT_PATH).exists() {
        info!("Not rewriting service file: {}", UNIT_IPT_INIT_PATH);
    } else {
        fs::write(UNIT_IPT_INIT_PATH, include_bytes!("../scripts/diswall-fw-init.service"))?;
        info!("Created systemd service file: {}", UNIT_IPT_INIT_PATH);
    }
    if Path::new(IPT_INIT_PATH).exists() {
        info!("Not rewriting iptables init script: {}", IPT_INIT_PATH);
    } else {
        let services = get_listening_services();
        let mut buffer = String::new();
        let mut added_ports = HashSet::new();
        for service in services {
            if service.dst_addr.ip().is_loopback() {
                continue;
            }
            let s = if service.src_addr.ip().is_unspecified() {
                // We don't want duplicates
                if added_ports.contains(&service.dst_addr.port()) {
                    continue;
                }
                added_ports.insert(service.dst_addr.port());
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

        let path = Path::new(IPT_INIT_PATH);
        match File::create(&path) {
            Ok(mut f) => {
                let mut script_content = include_str!("../scripts/diswall_init.sh").replace("#diswall_init_rules", &buffer);
                let ip6_buffer = buffer.replace("iptables", "ip6tables");
                script_content = script_content.replace("#diswall_init6_rules", &ip6_buffer);
                f.write_all(script_content.as_bytes()).expect(&format!("Error saving script to {}", IPT_INIT_PATH));
                set_permissions(&path, Permissions::from_mode(0o700))?;
            }
            Err(e) => error!("Error creating script {}: {}", IPT_INIT_PATH, e)
        }
    }
    Ok(())
}

fn install_nft_part() -> io::Result<()> {
    use std::path::Path;
    use std::io::Write;

    let current_config = match File::open(NFT_CONF_PATH) {
        Ok(mut f) => {
            let mut buf = String::new();
            f.read_to_string(&mut buf)?;
            buf
        }
        Err(_) => {
            //TODO  check that it is problem with permissions
            String::new()
        }
    };

    let config_is_ours = current_config.contains("#diswall ruleset");
    if !config_is_ours {
        let mut buf = String::new();
        // Commenting out all current config lines
        for line in current_config.lines() {
            if line.starts_with("#") {
                buf.push_str(line);
                buf.push('\n');
            } else {
                buf.push_str(&format!("#{}\n", &line));
            }
        }

        // We allow current listening services to accept connections
        let services = get_listening_services();
        let mut lines = Vec::new();
        let mut added_ports = HashSet::new();
        for service in services {
            if service.dst_addr.ip().is_loopback() {
                continue;
            }
            let line = if service.src_addr.ip().is_unspecified() {
                // We don't want duplicates
                if added_ports.contains(&service.dst_addr.port()) {
                    continue;
                }
                added_ports.insert(service.dst_addr.port());
                format!("    {} dport {} accept", &service.protocol, service.dst_addr.port())
            } else if service.src_addr.ip().is_ipv4() {
                // We work with IPv4 only for now
                format!("    {} saddr {} dport {} accept", &service.protocol, &service.src_addr.ip(), service.dst_addr.port())
            } else {
                continue;
            };
            lines.push(line);
        }
        lines.sort();
        lines.dedup();
        let buffer = lines.join("\n");

        let path = Path::new(NFT_CONF_PATH);
        match File::create(&path) {
            Ok(mut f) => {
                let script_content = include_str!("../scripts/nftables.conf")
                    .replace("#diswall_init_rules", &buffer)
                    .replace("#diswall_init6_rules", &buffer);
                buf.push_str(&script_content);
                f.write_all(buf.as_bytes()).expect(&format!("Error saving config to {}", NFT_CONF_PATH));
                set_permissions(&path, Permissions::from_mode(0o755))?;
            }
            Err(e) => error!("Error saving config to {}: {}", NFT_CONF_PATH, e)
        }
    } else {
        info!("Not rewriting nftables config: {}", NFT_CONF_PATH);
    }
    // Start or restart nftables service (It is installed but not enabled on Debian for some reason)
    start_or_restart_nft()?;

    Ok(())
}

fn start_or_restart_nft() -> io::Result<()> {
    let mut need_restart = false;
    match Command::new("systemctl")
        .arg("status")
        .arg("nftables")
        .stdout(Stdio::piped()).spawn() {
        Ok(mut child) => {
            if let Ok(r) = child.wait() {
                if r.success() {
                    if let Some(mut stdout) = child.stdout.take() {
                        let mut buf = String::new();
                        let _ = stdout.read_to_string(&mut buf);
                        if buf.contains("active (exited)") {
                            need_restart = true;
                        }
                    }
                }
            }
        }
        Err(e) => return Err(e)
    }

    if need_restart {
        match Command::new("systemctl")
            .arg("restart")
            .arg("nftables")
            .stdout(Stdio::null()).spawn() {
            Ok(mut child) => {
                if let Ok(r) = child.wait() {
                    if r.success() {
                        info!("Nftables restarted successfully");
                    }
                }
            }
            Err(e) => return Err(e)
        }
    } else {
        match Command::new("systemctl")
            .arg("enable")
            .arg("--now")
            .arg("nftables")
            .stdout(Stdio::null()).spawn() {
            Ok(mut child) => {
                if let Ok(r) = child.wait() {
                    if r.success() {
                        info!("Nftables enabled successfully");
                    }
                }
            }
            Err(e) => return Err(e)
        }
    }

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

                    match Command::new("diswall").arg("--after-update").stdout(Stdio::null()).spawn() {
                        Ok(mut child) => {
                            if let Ok(r) = child.wait() {
                                if r.success() {
                                    info!("After update processed successfully");
                                    return Ok(());
                                }
                            }
                        }
                        Err(_) => ()
                    }

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
pub(crate) fn update_fw_configs_for_ipv6() -> bool {
    let fw_type = match get_installed_fw_type() {
        Ok(fw_type) => fw_type,
        Err(e) => {
            error!("{}", e);
            return false;
        }
    };

    use std::path::Path;
    use std::io::Write;
    use std::fs::OpenOptions;
    use std::fs;

    match fw_type {
        FwType::IpTables => {
            let path = Path::new(IPT_INIT_PATH);
            let contents = fs::read_to_string(path).unwrap_or_default();
            if contents.contains("ip6tables -A INPUT") {
                info!("Update of {} is not needed", IPT_INIT_PATH);
                return true;
            }
            match OpenOptions::new().append(true).open(&path) {
                Ok(mut f) => {
                    info!("Updating config file {}", IPT_INIT_PATH);
                    let script_content = include_str!("../scripts/diswall_init6.sh");
                    f.write_all(script_content.as_bytes()).expect(&format!("Error saving script to {}", IPT_INIT_PATH));
                }
                Err(e) => {
                    error!("Error saving script to {}: {}", IPT_INIT_PATH, e);
                    return false;
                }
            }
        },
        FwType::NfTables => {
            let path = Path::new(NFT_CONF_PATH);
            let contents = fs::read_to_string(path).unwrap_or_default();
            if contents.contains("ip6 saddr @diswall-bl6") {
                info!("Update of {} is not needed", NFT_CONF_PATH);
                return true;
            }
            match OpenOptions::new().append(true).open(&path) {
                Ok(mut f) => {
                    info!("Updating config file {}", NFT_CONF_PATH);
                    let script_content = include_str!("../scripts/nftables6.conf");
                    f.write_all(script_content.as_bytes()).expect(&format!("Error saving config to {}", NFT_CONF_PATH));
                }
                Err(e) => {
                    error!("Error saving config to {}: {}", NFT_CONF_PATH, e);
                    return false;
                }
            }
        }
    }
    if install_rsyslog_config().is_err() {
        return false;
    }
    true
}

/// Change single log directive to two separate directives
pub(crate) fn update_fw_configs_for_separated_protocols() -> bool {
    let fw_type = match get_installed_fw_type() {
        Ok(fw_type) => fw_type,
        Err(e) => {
            error!("{}", e);
            return false;
        }
    };

    let (updated, path) = match fw_type {
        FwType::IpTables => {
            let old = "iptables -A INPUT -j LOG --log-prefix \"diswall-log: \"";
            let new = "iptables -A INPUT -p udp -j LOG --log-prefix \"diswall-log: \"\niptables -A INPUT -p tcp -j LOG --log-prefix \"diswall-log: \"";
            let updated = replace_string_in_file(IPT_INIT_PATH, old, new);
            let old = "ip6tables -A INPUT -j LOG --log-prefix \"diswall-log: \"";
            let new = "ip6tables -A INPUT -p udp -j LOG --log-prefix \"diswall-log: \"\nip6tables -A INPUT -p tcp -j LOG --log-prefix \"diswall-log: \"";
            let updated = updated && replace_string_in_file(IPT_INIT_PATH, old, new);
            (updated, IPT_INIT_PATH)
        },
        FwType::NfTables => {
            let old = "    log prefix \"diswall-log: \"";
            let new = "    tcp dport 1-65535 log prefix \"diswall-log: \" drop\n    udp dport 1-65535 log prefix \"diswall-log: \" drop";
            (replace_string_in_file(NFT_CONF_PATH, old, new), NFT_CONF_PATH)
        }
    };
    if updated {
        if let Err(e) = crate::firewall::apply_fw_config(path) {
            error!("Error applying firewall config: {}", e);
            return false;
        }
    }
    true
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
    let _ = restart_rsyslog();

    let _ = fs::remove_file(UNIT_PATH);
    let _ = fs::remove_file(UNIT_IPT_INIT_PATH);
    let _ = fs::remove_file(CONFIG_PATH);
    let _ = fs::remove_file(IPT_INIT_PATH);
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

fn change_group_ownership(file_path: &str, group_name: &str) -> Result<(), String> {
    Command::new("chown")
        .args(&[format!(":{}", group_name), file_path.to_string()]) // ":group_name" sets the group ownership
        .output()
        .map_err(|e| format!("Failed to execute chown command: {}", e))
        .and_then(|output| {
            if output.status.success() {
                Ok(())
            } else {
                Err(format!("Error executing chown command: {}", String::from_utf8_lossy(&output.stderr)))
            }
        })
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