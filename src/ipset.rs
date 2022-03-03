use std::process::{Command, Stdio};
use std::io::{Read, Write};
use log::{debug, error, info, warn};

pub fn run_ipset(action: &str, data: &str, optional: &[&str]) {
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
        let command = match optional.len() {
            2 => command.args(vec!["-exist", action, optional[0], data, "comment", optional[1]]),
            _ => command.args(vec!["-exist", action, optional[0], data])
        };
        if let Err(e) = command.spawn() {
            match action {
                "add" => error!("Error adding {} to ipset: {}", data, e),
                "del" => error!("Error removing {} from ipset: {}", data, e),
                &_ => error!("Error ipset command: {}", e)
            }
        }
    }
}

pub fn get_ipset_list(list_name: &str, user_name: &str) -> String {
    let mut buffer = String::new();
    let command = Command::new("ipset")
        .arg("list")
        .arg("-name")
        .arg(format!("{}-{}", list_name, user_name))
        .spawn();
    match command {
        Ok(_) => {
            let command = Command::new("ipset")
                .arg("save")
                .arg(format!("{}-{}", list_name, user_name))
                .stdout(Stdio::piped())
                .spawn();
            if let Ok(mut command) = command {
                let mut io = command.stdout.take().unwrap();
                if let Ok(size) = io.read_to_string(&mut buffer) {
                    debug!("Got {} for {}, {} bytes long", list_name, user_name, size);
                }
            } else {
                warn!("Error getting {} for {}", list_name, user_name);
            }
        }
        Err(..) => {
            info!("No {} for {}", list_name, user_name);
        }
    }
    buffer
}

pub fn ipset_list_exists(list_name: &str) -> bool {
    let command = Command::new("ipset")
        .arg("list")
        .arg("-name")
        .arg(list_name)
        .spawn();
    info!("List: {:?}", &command);
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
