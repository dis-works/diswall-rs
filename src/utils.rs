use std::net::{IpAddr, Ipv6Addr};

/// Reduces all series of spaces to one space
pub fn reduce_spaces(string: &str) -> String {
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

pub fn get_first_part(data: &str) -> String {
    if data.contains(" ") {
        let parts = data.split(" ").collect::<Vec<_>>();
        return parts[0].to_owned();
    }
    return data.to_owned();
}

/// If the string has "|", then it returns first part as IP, and second as Tag.
/// Otherwise it returns whole string as IP, and empty string as Tag.
pub fn get_ip_and_tag(data: &str) -> (String, String) {
    if data.contains("|") {
        let parts = data.split("|").collect::<Vec<_>>();
        let ip = clean_ip(parts[0]);
        (ip, String::from(parts[1]))
    } else {
        (clean_ip(data), String::new())
    }
}

fn clean_ip(addr: &str) -> String {
    match addr.parse::<IpAddr>() {
        Ok(ip) => {
            if let IpAddr::V6(ipv6) = ip {
                if let Some(ipv4) = ipv6.to_ipv4() {
                    IpAddr::V4(ipv4).to_string()
                } else {
                    ipv6.to_string()
                }
            } else {
                ip.to_string()
            }
        },
        Err(_) => String::new(),
    }
}

pub fn is_ipv6(addr: &str) -> bool {
    match addr.parse::<Ipv6Addr>() {
        Ok(_) => true,
        Err(_) => false
    }
}

/// Checks if IP in this string is valid
pub fn valid_ip(ip: &str) -> bool {
    match ip.parse::<IpAddr>() {
        Ok(_) => true,
        Err(_) => false,
    }
}
