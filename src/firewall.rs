use std::process::{Command, Stdio};
use std::io::Write;
#[allow(unused_imports)]
use log::{debug, error, info, warn};
use crate::config::FwType;

pub fn ipset_add_or_del(action: &str, list_name: &str, data: &str, comment: Option<String>) {
    let data = data.trim();
    let mut command = Command::new("ipset");
    let mut args = vec!["-exist", action, list_name];
    if data.contains(" ") {
        let mut parts = data.split(" ").collect::<Vec<_>>();
        args.append(&mut parts);
    } else {
        args.push(&data);
    }
    let mut buf = String::new();
    if let Some(comment) = comment {
        buf.push_str(&comment);
        args.push("comment");
        args.push(&buf);
    }
    command.args(&args);
    match command.stdout(Stdio::null()).spawn() {
        Err(e) => {
            match action {
                "add" => error!("Error adding {} to ipset: {}", data, e),
                "del" => error!("Error removing {} from ipset: {}", data, e),
                &_ => error!("Error ipset command: {}", e)
            }
        }
        Ok(mut child) => {
            let _ = child.wait();
        }
    }
}

pub fn ipset_restore(data: &str) {
    let data = data.trim();
    let command = Command::new("ipset")
        .arg("-exist")
        .arg("restore")
        .stdin(Stdio::piped())
        .spawn();
    if let Ok(mut command) = command {
        let mut stdin = command.stdin.take().unwrap();
        if let Err(e) = stdin.write_all(data.as_bytes()) {
            error!("Error restoring ipset rules {}", e);
            return;
        }
    }
}

/// nft add element ip filter block {192.168.44.77 timeout 3600s}
pub fn nft_add_or_del(action: &str, list_name: &str, data: &str) {
    let data = data.trim();
    let mut command = Command::new("nft");
    let data = match data.contains("timeout") {
        true => format!("{{{}s}}", data),
        false => format!("{{{} timeout 1h}}", data)
    };
    let ip = match data.contains('.') {
        true => String::from("ip"),
        false => String::from("ip6")
    };
    command.args([action, "element", &ip, "filter", list_name, &data]);
    match command.stdout(Stdio::null()).stderr(Stdio::null()).spawn() {
        Err(e) => {
            match action {
                "add" => error!("Error adding {} to nft set: {}", data, e),
                "del" => error!("Error removing {} from nft set: {}", data, e),
                &_ => error!("Error ipset command: {}", e)
            }
        }
        Ok(mut child) => {
            let _ = child.wait();
        }
    }
}

pub fn nft_restore(data: &str) {
    let data = data.trim();
    let command = Command::new("nft")
        .arg("-f")
        .arg("-")
        .stdin(Stdio::piped())
        .spawn();
    if let Ok(mut command) = command {
        let mut stdin = command.stdin.take().unwrap();
        if let Err(e) = stdin.write_all(data.as_bytes()) {
            error!("Error restoring ipset rules {}", e);
            return;
        }
    }
}

pub fn get_installed_fw_type() -> Result<FwType, String> {
    let command = Command::new("ipset")
        .arg("-v")
        .stdout(Stdio::piped())
        .spawn();
    match command {
        Ok(mut child) => {
            if let Ok(_) = child.wait() {
                return Ok(FwType::IpTables)
            }
        }
        Err(_) => {}
    }

    let command = Command::new("nft")
        .arg("-v")
        .stdout(Stdio::piped())
        .spawn();
    match command {
        Ok(mut child) => {
            if let Ok(_) = child.wait() {
                return Ok(FwType::NfTables)
            }
        }
        Err(_) => {}
    }
    Err(String::from("Could not determine installed firewall type."))
}
