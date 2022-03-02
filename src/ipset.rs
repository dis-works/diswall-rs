use std::process::{Command, Stdio};
use std::io::Write;
use log::{error};

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
