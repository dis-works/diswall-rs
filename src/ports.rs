use std::cell::RefCell;
use std::collections::HashMap;
use std::time::Instant;
#[cfg(target_os = "linux")]
use netstat2::{AddressFamilyFlags, get_sockets_info, ProtocolFlags, ProtocolSocketInfo, TcpState::Listen};

/// A helper to determine what ports we have open, with cache
#[allow(dead_code)]
pub struct Ports {
    ports: RefCell<HashMap<u16, Instant>>,
    timeout: u64
}

impl Ports {
    pub fn new(timeout: u64) -> Self {
        Self { ports: RefCell::new(HashMap::new()), timeout }
    }

    #[cfg(target_os = "linux")]
    pub fn is_open(&self, port: u16, _protocol: &str) -> bool {
        if self.is_in_cache(&port) {
            return true;
        }

        let af_flags = AddressFamilyFlags::IPV4 | AddressFamilyFlags::IPV6;
        let proto_flags = ProtocolFlags::TCP | ProtocolFlags::UDP;
        let sockets_info = match get_sockets_info(af_flags, proto_flags) {
            Ok(info) => info,
            Err(e) => {
                println!("Error getting sockets info: {e}");
                return false;
            }
        };

        let mut listening = false;
        for si in sockets_info {
            listening = match si.protocol_socket_info {
                ProtocolSocketInfo::Tcp(tcp_si) => tcp_si.local_port == port && tcp_si.state == Listen,
                ProtocolSocketInfo::Udp(udp_si) => udp_si.local_port == port,
            };
            if listening {
                break;
            }
        };
        if listening {
            self.ports.borrow_mut().insert(port, Instant::now());
        }
        listening
    }

    #[allow(dead_code)]
    fn is_in_cache(&self, port: &u16) -> bool {
        if let Some(instant) = self.ports.borrow().get(&port) {
            if instant.elapsed().as_secs() < self.timeout {
                return true;
            }
        }
        false
    }

    #[cfg(target_os = "freebsd")]
    pub fn is_open(&self, port: u16, protocol: &str) -> bool {
        use std::io::ErrorKind;

        if self.is_in_cache(&port) {
            return true;
        }

        match protocol {
            "TCP" => {
                // Attempt to create a TCP listener
                let tcp_listener = std::net::TcpListener::bind(("0.0.0.0", port));
                if let Err(e) = tcp_listener {
                    if e.kind() == ErrorKind::AddrInUse {
                        self.ports.borrow_mut().insert(port, Instant::now());
                        return true;
                    }
                }
            }
            "UDP" => {
                // Attempt to create a UDP socket
                let udp_socket = std::net::UdpSocket::bind(("0.0.0.0", port));
                if let Err(e) = udp_socket {
                    if e.kind() == ErrorKind::AddrInUse {
                        self.ports.borrow_mut().insert(port, Instant::now());
                        return true;
                    }
                }
            }
            _ => {}
        }
        false
    }

    #[cfg(not(any(target_os = "freebsd", target_os = "linux")))]
    pub fn is_open(&self, _port: u16, _protocol: &str) -> bool {
        false
    }
}