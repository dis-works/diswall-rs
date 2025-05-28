use std::fs::File;
use std::io::Read;
use getopts::Matches;
use log::{error, warn};
use serde::{Deserialize, Serialize};

pub const DEFAULT_CLIENT_NAME: &'static str = "default";
const DEFAULT_CLIENT_PASS: &'static str = "default";
pub(crate) const PREFIX_WL: &'static str = "diswall.whitelist";
pub(crate) const PREFIX_BL: &'static str = "diswall.blacklist";
pub(crate) const PREFIX_STATS: &'static str = "diswall.stats";

/// The main configuration structure, loaded from TOML config file
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub nginx: Nginx,
    #[serde(default)]
    pub nats: NatsConfig,
    #[serde(skip)]
    pub fw_type: FwType,
    #[serde(default)]
    pub clickhouse: ClickHouseConfig,
    #[serde(default)]
    pub local_only: bool,
    #[serde(default)]
    pub server_mode: bool,
    #[serde(default = "default_send_statistics")]
    pub send_statistics: bool,
    #[serde(default = "default_ipset_black_list")]
    pub ipset_black_list: String,
    #[serde(default = "default_ipset_white_list")]
    pub ipset_white_list: String,
    #[serde(default)]
    pub ignore_ips: Vec<String>,
    #[serde(default)]
    pub max_block_time: u64
}

impl Config {
    pub fn from_file(file_name: &str) -> Option<Self> {
        match File::open(file_name) {
            Ok(mut file) => {
                let mut text = String::new();
                file.read_to_string(&mut text).unwrap();
                if let Ok(config) = toml::from_str::<Config>(&text) {
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

    pub fn override_config_from_args(&mut self, opt_matches: &Matches) {
        if let Some(server) = opt_matches.opt_str("s") {
            self.nats.server = server;
        }
        if let Ok(port) = opt_matches.opt_get::<u16>("P") {
            self.nats.port = port.unwrap_or(4222);
        }
        if let Some(name) = opt_matches.opt_str("n") {
            self.nats.client_name = name;
        }
        if let Some(pass) = opt_matches.opt_str("p") {
            self.nats.client_pass = pass;
        }
        if opt_matches.opt_present("l") {
            self.local_only = true;
        }
        if opt_matches.opt_present("server") {
            self.server_mode = true;
        }
        if let Some(list) = opt_matches.opt_str("allow-list") {
            self.ipset_white_list = list;
        }
        if let Some(list) = opt_matches.opt_str("block-list") {
            self.ipset_black_list = list;
        }
    }

    pub fn init_nats_subjects(&mut self) {
        if !self.local_only {
            let (client, host) = match self.server_mode {
                true => ("*", "*"),
                false => (self.nats.client_name.as_str(), self.nats.hostname.as_str())
            };

            self.nats.wl_init_subject = format!("{}.{}.init.{}", PREFIX_WL, client, host);
            self.nats.wl_push_subject = format!("{}.{}.add.{}", PREFIX_WL, client, host);
            self.nats.wl_subscribe_subject = format!("{}.{}.add.*", PREFIX_WL, client);
            self.nats.wl_del_subject = format!("{}.{}.del.{}", PREFIX_WL, client, host);

            self.nats.bl_init_subject = format!("{}.{}.init.{}", PREFIX_BL, client, host);
            self.nats.bl_push_subject = format!("{}.{}.add.{}", PREFIX_BL, client, host);
            self.nats.bl_subscribe_subject = format!("{}.{}.add.*", PREFIX_BL, client);
            self.nats.bl_del_subject = format!("{}.{}.del.{}", PREFIX_BL, client, host);

            self.nats.stats_subject = format!("{}.{}.add.{}", PREFIX_STATS, client, host);
        }
        if self.nats.client_name == DEFAULT_CLIENT_NAME {
            self.nats.bl_global_subject = format!("{}.default", PREFIX_BL);
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        let nats = NatsConfig::default();
        let clickhouse = ClickHouseConfig::default();
        Config {
            nginx: Nginx::default(),
            nats,
            fw_type: FwType::IpTables,
            clickhouse,
            local_only: true,
            server_mode: false,
            send_statistics: true,
            ipset_black_list: default_ipset_black_list(),
            ipset_white_list: default_ipset_white_list(),
            ignore_ips: Vec::new(),
            max_block_time: 0u64
        }
    }
}

/// Nginx error logs configuration, a part of main config structure, is loaded from same TOML
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Nginx {
    #[serde(default)]
    pub(crate) logs: Vec<String>,
    #[serde(default)]
    pub(crate) access: Vec<String>
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
    #[serde(default)]
    pub bl_push_subject: String,
    #[serde(default = "default_bl_add_subject")]
    pub bl_subscribe_subject: String,
    #[serde(default = "default_bl_del_subject")]
    pub bl_del_subject: String,
    #[serde(default)]
    pub wl_push_subject: String,
    #[serde(default = "default_wl_add_subject")]
    pub wl_subscribe_subject: String,
    #[serde(default = "default_wl_del_subject")]
    pub wl_del_subject: String,
    #[serde(default = "default_bl_global_subject")]
    pub bl_global_subject: String,
    #[serde(default = "default_stats_subject")]
    pub stats_subject: String,
    #[serde(default)]
    pub honeypots: Vec<String>
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
            bl_push_subject: String::new(),
            bl_subscribe_subject: default_bl_add_subject(),
            wl_push_subject: String::new(),
            wl_subscribe_subject: default_wl_add_subject(),
            bl_del_subject: default_bl_del_subject(),
            wl_del_subject: default_wl_del_subject(),
            bl_global_subject: default_bl_global_subject(),
            stats_subject: default_stats_subject(),
            honeypots: Vec::new()
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ClickHouseConfig {
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub login: String,
    #[serde(default)]
    pub password: String,
    #[serde(default)]
    pub database: String,
    #[serde(default)]
    pub salt: String,
}

#[derive(Clone, Copy, Debug, Default)]
pub enum FwType {
    #[default]
    IpTables,
    NfTables
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

fn default_hostname() -> String {
    get_hostname().replace(".", "_")
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

fn default_bl_global_subject() -> String {
    String::from("diswall.blacklist.new")
}

fn default_stats_subject() -> String {
    String::from("diswall.stats.unknown.add")
}

fn default_send_statistics() -> bool {
    true
}