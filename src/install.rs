use std::io;
use std::collections::HashSet;
use std::process::{Command, Stdio};
use std::net::SocketAddr;
use std::io::Read;
use std::str::FromStr;
use std::os::unix::fs::PermissionsExt;
use std::fs::{File, Permissions, set_permissions};
use log::{error, info, warn};
use nix::unistd::mkfifo;

#[cfg(not(windows))]
pub(crate) fn install_client() -> io::Result<()> {
    use std::fs;
    use nix::sys::stat;
    use std::path::Path;
    use std::io::Write;

    // Configuring rsyslog
    if !Path::new("/etc/rsyslog.d/10-diswall.conf").exists() {
        fs::create_dir_all("/etc/rsyslog.d/")?;
        fs::write("/etc/rsyslog.d/10-diswall.conf", include_bytes!("../scripts/10-diswall.conf"))?;
        info!("Created rsyslogd config file: /etc/rsyslog.d/10-diswall.conf");
    } else {
        info!("Not rewriting rsyslogd config file at: /etc/rsyslog.d/10-diswall.conf");
    }
    // Adding systemd service for diswall
    if !Path::new("/etc/systemd/system/diswall.service").exists() {
        fs::write("/etc/systemd/system/diswall.service", include_bytes!("../scripts/diswall.service"))?;
        info!("Created systemd service file: /etc/systemd/system/diswall.service");
    } else {
        info!("Not rewriting service file: /etc/systemd/system/diswall.service");
    }
    // Adding systemd service for firewall initialization
    if !Path::new("/etc/systemd/system/diswall-fw-init.service").exists() {
        fs::write("/etc/systemd/system/diswall-fw-init.service", include_bytes!("../scripts/diswall-fw-init.service"))?;
        info!("Created systemd service file: /etc/systemd/system/diswall-fw-init.service");
    } else {
        info!("Not rewriting service file: /etc/systemd/system/diswall-fw-init.service");
    }
    // Creating rsyslog->diswall pipe
    if !Path::new("/var/log/diswall/diswall.pipe").exists() {
        fs::create_dir_all("/var/log/diswall")?;
        mkfifo("/var/log/diswall/diswall.pipe", stat::Mode::S_IRWXU)?;
        info!("Created firewall pipe: /var/log/diswall/diswall.pipe");
    } else {
        info!("Not rewriting pipe at: /var/log/diswall/diswall.pipe");
    }
    // Creating a config for diswall
    if !Path::new("/etc/diswall/diswall.conf").exists() {
        fs::create_dir_all("/etc/diswall/")?;
        fs::write("/etc/diswall/diswall.conf", include_bytes!("../config/diswall.toml"))?;
        info!("Created config file: /etc/diswall/diswall.conf");
    } else {
        info!("Not rewriting config file: /etc/diswall/diswall.conf");
    }

    // Copying this binary to /usr/bin
    let exe_path = std::env::current_exe()?;
    if !exe_path.eq(Path::new("/usr/bin/diswall")) {
        fs::copy(exe_path, "/usr/bin/diswall")?;
    }

    if !Path::new("/usr/bin/diswall_init.sh").exists() {
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
        let script_content = include_str!("../scripts/diswall_init.sh").replace("#diswall_init_rules", &buffer);

        let path = Path::new("/usr/bin/diswall_init.sh");
        match File::create(&path) {
            Ok(mut f) => {
                f.write_all(script_content.as_bytes()).expect("Error saving script to /usr/bin/diswall_init.sh");
                set_permissions(&path, Permissions::from_mode(0700))?;
            }
            Err(e) => error!("Error saving script to /usr/bin/diswall_init.sh: {}", e)
        }
    } else {
        info!("Not rewriting firewall init script: /usr/bin/diswall_init.sh");
    }

    info!("Installation complete!");
    info!("Please, read and correct firewall init script at /usr/bin/diswall_init.sh, it will run at system start.");
    info!("Also, check DisWall config at /etc/diswall/diswall.conf, and enter client credentials.");
    info!("And then you need to enable & start diswall service by running '(sudo) systemctl enable --now diswall.service'.");

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
                    let buffer = reduce_spaces(&buffer)
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
    src_addr: SocketAddr,
    dst_addr: SocketAddr,
}
