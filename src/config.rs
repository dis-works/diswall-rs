use std::fs::File;
use std::io::Read;
use log::{error, warn};
use serde::{Deserialize, Serialize};

const DEFAULT_CLIENT_NAME: &'static str = "<ENTER YOU CLIENT NAME>";
const DEFAULT_CLIENT_PASS: &'static str = "<ENTER YOUR PASSWORD>";

/// The main configuration structure, loaded from TOML config file
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    #[serde(default = "default_pipe")]
    pub pipe_path: String,
    #[serde(default)]
    pub nats: NatsConfig,
    #[serde(default)]
    pub local_only: bool,
    #[serde(default = "default_ipset_black_list")]
    pub ipset_black_list: String,
    #[serde(default = "default_ipset_white_list")]
    pub ipset_white_list: String
}

impl Config {
    pub fn from_file(file_name: &str) -> Option<Self> {
        match File::open(file_name) {
            Ok(mut file) => {
                let mut text = String::new();
                file.read_to_string(&mut text).unwrap();
                if let Ok(mut config) = toml::from_str::<Config>(&text) {
                    if !config.local_only && config.nats.client_name.ne(DEFAULT_CLIENT_NAME) {
                        config.nats.wl_init_subject = format!("diswall.whitelist.{}.init.{}", &config.nats.client_name, &config.nats.hostname);
                        config.nats.bl_init_subject = format!("diswall.blacklist.{}.init.{}", &config.nats.client_name, &config.nats.hostname);
                        config.nats.wl_add_subject = format!("diswall.whitelist.{}.add.{}", &config.nats.client_name, &config.nats.hostname);
                        config.nats.wl_del_subject = format!("diswall.whitelist.{}.del.{}", &config.nats.client_name, &config.nats.hostname);
                        config.nats.bl_add_subject = format!("diswall.blacklist.{}.add.{}", &config.nats.client_name, &config.nats.hostname);
                        config.nats.bl_del_subject = format!("diswall.blacklist.{}.del.{}", &config.nats.client_name, &config.nats.hostname);
                    }
                    return Some(config);
                }
                None
            }
            Err(e) => {
                error!("Error loading configuration from {}: {}", file_name, e);
                None
            }
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        let nats = NatsConfig::default();
        Config {
            pipe_path: default_pipe(),
            nats,
            local_only: true,
            ipset_black_list: default_ipset_black_list(),
            ipset_white_list: default_ipset_white_list(),
        }
    }
}

/// NATS client configuration, a part of main config structure, is loaded from same TOML
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NatsConfig {
    pub server: String,
    pub port: u16,
    pub client_name: String,
    pub client_pass: String,
    #[serde(default = "default_hostname")]
    pub hostname: String,
    #[serde(default = "default_bl_init_subject")]
    pub bl_init_subject: String,
    #[serde(default = "default_wl_init_subject")]
    pub wl_init_subject: String,
    #[serde(default = "default_bl_add_subject")]
    pub bl_add_subject: String,
    #[serde(default = "default_bl_del_subject")]
    pub bl_del_subject: String,
    #[serde(default = "default_wl_add_subject")]
    pub wl_add_subject: String,
    #[serde(default = "default_wl_del_subject")]
    pub wl_del_subject: String
}

impl Default for NatsConfig {
    fn default() -> Self {
        NatsConfig {
            server: String::from("diswall.stream"),
            port: 4222,
            client_name: String::from(DEFAULT_CLIENT_NAME),
            client_pass: String::from(DEFAULT_CLIENT_PASS),
            hostname: default_hostname(),
            bl_init_subject: default_bl_init_subject(),
            wl_init_subject: default_wl_init_subject(),
            bl_add_subject: default_bl_add_subject(),
            wl_add_subject: default_wl_add_subject(),
            bl_del_subject: default_bl_del_subject(),
            wl_del_subject: default_wl_del_subject()
        }
    }
}

pub fn get_hostname() -> String {
    let unknown = String::from("unknown");
    match hostname::get() {
        Ok(hostname) => hostname.into_string().unwrap_or(unknown),
        Err(e) => {
            warn!("Error getting hostname: {}", e);
            unknown
        }
    }
}

fn default_pipe() -> String {
    String::from("/var/log/diswall/diswall.pipe")
}

fn default_hostname() -> String {
    get_hostname()
}

fn default_ipset_black_list() -> String {
    String::from("diswall-bl")
}

fn default_ipset_white_list() -> String {
    String::from("diswall-al")
}

fn default_bl_init_subject() -> String {
    String::from("diswall.blacklist.unknown.init")
}

fn default_wl_init_subject() -> String {
    String::from("diswall.whitelist.unknown.init")
}

fn default_bl_add_subject() -> String {
    String::from("diswall.blacklist.unknown.add")
}

fn default_bl_del_subject() -> String {
    String::from("diswall.blacklist.unknown.del")
}

fn default_wl_add_subject() -> String {
    String::from("diswall.whitelist.unknown.add")
}

fn default_wl_del_subject() -> String {
    String::from("diswall.whitelist.unknown.del")
}