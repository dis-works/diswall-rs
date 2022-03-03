use std::thread;
use std::time::Duration;
use log::{error, info, warn};
use nats::Connection;
use crate::{Config, ipset};

pub fn run_server(config: Config, nats: Option<Connection>) {
    if nats.is_none() {
        error!("Cannot work in server mode without NATS connection");
        return;
    }
    info!("Starting DisWall server...", );

    let nats = nats.unwrap();
    if let Ok(sub) = nats.subscribe(&config.nats.wl_init_subject) {
        sub.with_handler(move |message| {
            if let Ok(data) = String::from_utf8(message.data.clone()) {
                info!("Got wl init request from {}", &data);
                let list_name = "diswall-wl";
                let split = data.split("/").collect::<Vec<&str>>();
                let buffer = ipset::get_ipset_list(list_name, split[0]);
                if let Err(e) = message.respond(buffer.as_bytes()) {
                    warn!("Error sending {} to {}: {}", list_name, split[0], e);
                }
            }
            Ok(())
        });
        info!("Subscribed to {}", &config.nats.wl_init_subject);
    }

    if let Ok(sub) = nats.subscribe(&config.nats.bl_init_subject) {
        sub.with_handler(|message| {
            if let Ok(data) = String::from_utf8(message.data.clone()) {
                info!("Got bl init request from {}", &data);
                let list_name = "diswall-bl";
                let split = data.split("/").collect::<Vec<&str>>();
                let buffer = ipset::get_ipset_list(list_name, split[0]);
                if let Err(e) = message.respond(buffer.as_bytes()) {
                    warn!("Error sending {} to {}: {}", list_name, split[0], e);
                }
            }
            Ok(())
        });
        info!("Subscribed to {}", &config.nats.bl_init_subject);
    }

    let delay = Duration::from_secs(1);
    // We just loop here until kill
    loop {
        thread::sleep(delay);
    }
}