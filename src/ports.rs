use std::cell::RefCell;
use std::collections::HashMap;
use std::time::Instant;
use netstat2::{AddressFamilyFlags, get_sockets_info, ProtocolFlags, ProtocolSocketInfo};
use netstat2::TcpState::Listen;

/// A helper to determine what ports we have open, with cache
pub struct Ports {
    ports: RefCell<HashMap<u16, Instant>>,
    timeout: u64
}

impl Ports {
    pub fn new(timeout: u64) -> Self {
        Self { ports: RefCell::new(HashMap::new()), timeout }
    }

    pub fn is_open(&self, port: u16) -> bool {
        if let Some(instant) = self.ports.borrow().get(&port) {
            if instant.elapsed().as_secs() < self.timeout {
                return true;
            }
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
}