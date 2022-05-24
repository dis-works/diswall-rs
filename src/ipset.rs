use std::process::{Command, Stdio};
use std::io::Write;
#[allow(unused_imports)]
use log::{debug, error, info, warn};

pub fn run_ipset(action: &str, list_name: &str, data: &str, comment: Option<String>) {
    let data = data.trim();
    if action == "restore" {
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
    } else {
        let mut command = Command::new("ipset");
        let command = match comment {
            Some(comment) => command.args(vec!["-exist", action, list_name, data, "comment", &comment]),
            None => command.args(vec!["-exist", action, list_name, data])
        };
        match command.spawn() {
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
}

#[allow(dead_code)]
pub fn ipset_list_exists(list_name: &str) -> bool {
    let command = Command::new("ipset")
        .arg("list")
        .arg("-name")
        .arg(list_name)
        .stdout(Stdio::piped())
        .spawn();
    match command {
        Ok(mut child) => {
            match child.wait() {
                Ok(status) => return status.success(),
                Err(e) => error!("Error running ipset: {}", e)
            }
        }
        Err(e) => error!("Error running ipset: {}", e)
    }
    false
}

/// Runs command `ipset create -exist diswall-wl hash:net comment`
#[allow(dead_code)]
pub fn ipset_list_create_wl(list_name: &str) -> bool {
    let command = Command::new("ipset")
        .arg("create")
        .arg("-exist")
        .arg(list_name)
        .arg("hash:net")
        .arg("comment")
        .spawn();
    match command {
        Ok(mut child) => {
            match child.wait() {
                Ok(status) => return status.success(),
                Err(e) => error!("Error running ipset: {}", e)
            }
        }
        Err(e) => error!("Error running ipset: {}", e)
    }
    false
}

/// Runs command `ipset create -exist diswall-bl hash:ip hashsize 32768 maxelem 1000000 timeout 86400`
#[allow(dead_code)]
pub fn ipset_list_create_bl(list_name: &str) -> bool {
    let command = Command::new("ipset")
        .arg("create")
        .arg("-exist")
        .arg(list_name)
        .arg("hash:ip")
        .arg("hashsize")
        .arg("32768")
        .arg("maxelem")
        .arg("1000000")
        .arg("timeout")
        .arg("86400")
        .spawn();
    match command {
        Ok(mut child) => {
            match child.wait() {
                Ok(status) => return status.success(),
                Err(e) => error!("Error running ipset: {}", e)
            }
        }
        Err(e) => error!("Error running ipset: {}", e)
    }
    false
}