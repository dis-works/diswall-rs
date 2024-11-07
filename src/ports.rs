use std::cell::RefCell;
use std::collections::HashMap;
use std::time::Instant;
use netsock::family::AddressFamilyFlags;
use netsock::get_sockets;
use netsock::protocol::ProtocolFlags;
use netsock::socket::ProtocolSocketInfo;
use netsock::state::TcpState;

/// A helper to determine what ports we have open, with cache
#[allow(dead_code)]
pub struct Ports {
    ports: RefCell<HashMap<(u16, u8), Instant>>,
    timeout: u64
}

impl Ports {
    pub fn new(timeout: u64) -> Self {
        Self { ports: RefCell::new(HashMap::new()), timeout }
    }

    fn is_in_cache(&self, port: u16, protocol: u8) -> bool {
        if let Some(instant) = self.ports.borrow().get(&(port, protocol)) {
            if instant.elapsed().as_secs() < self.timeout {
                return true;
            }
        }
        false
    }

    pub fn is_open(&self, port: u16, protocol: &str) -> bool {
        // Combine IPv4 and IPv6 address family flags to search for sockets across both families.
        let af_flags = AddressFamilyFlags::IPV4 | AddressFamilyFlags::IPV6;

        // Combine TCP and UDP protocol flags to search for both types of sockets.
        let proto_flags = match protocol {
            "TCP" => ProtocolFlags::TCP,
            "UDP" => ProtocolFlags::UDP,
            _ => return false
        };
        let proto_bits = proto_flags.bits();
        if self.is_in_cache(port, proto_bits) {
            return true;
        }

        // Call get_sockets with the specified address family and protocol flags.
        // This function returns a Result, which we match on to handle both the Ok and Err cases.
        match get_sockets(af_flags, proto_flags) {
            Ok(sockets) => {
                // If successful, iterate over the returned sockets and print their information.
                for socket in sockets {
                    // Print the socket and process information
                    return match socket.protocol_socket_info {
                        ProtocolSocketInfo::Tcp(tcp_socket) => {
                            if tcp_socket.local_port != port { continue; }
                            // If we listen on local address only we don't count it
                            if tcp_socket.local_addr.is_loopback() { continue; };
                            if tcp_socket.state != TcpState::Listen { continue; }
                            self.ports.borrow_mut().insert((port, proto_bits), Instant::now());
                            true
                        },
                        ProtocolSocketInfo::Udp(udp_socket) => {
                            if udp_socket.local_port != port { continue; }
                            // If we listen on local address only we don't count it
                            if udp_socket.local_addr.is_loopback() { continue; };
                            self.ports.borrow_mut().insert((port, proto_bits), Instant::now());
                            true
                        },
                    }
                }
            }
            Err(e) => {
                // If an error occurs, print the error message.
                eprintln!("Error: {}", e);
            }
        }
        false
    }
}