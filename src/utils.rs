use std::net::IpAddr;

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

/// If the string has "|", then it returns first part as IP, and second as Tag.
/// Otherwise it returns whole string as IP, and empty string as Tag.
pub fn get_ip_and_tag(data: &str) -> (String, String) {
    if data.contains("|") {
        let parts = data.split("|").collect::<Vec<_>>();
        (String::from(parts[0]), String::from(parts[1]))
    } else {
        (String::from(data), String::new())
    }
}

/// Checks if IP in this string is valid
pub fn valid_ip(ip: &str) -> bool {
    match ip.parse::<IpAddr>() {
        Ok(_) => true,
        Err(_) => false,
    }
}
