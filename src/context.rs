use std::num::NonZeroUsize;
use std::sync::Arc;
use async_nats::Client;
use lru::LruCache;
use tokio::sync::RwLock;
use log::{error, info};
use std::collections::HashSet;
use std::sync::atomic::AtomicU32;
use futures::StreamExt;
use crate::config::{Config, FwType};
use crate::{firewall, DEFAULT_BLOCK_TIME_SEC};
use crate::state::{Blocked, State};
use crate::utils::{get_first_part, get_ip_and_tag, get_ip_and_timeout, is_ipv6, valid_ip};

#[derive(Clone)]
pub struct Context {
    pub config: Config,
    pub nats: Option<Client>,
    pub cache: Arc<RwLock<LruCache<String, bool>>>,
    pub state: Arc<RwLock<State>>,
    pub banned_count: Arc<AtomicU32>,
}

impl Context {
    pub fn new(config: Config, nats: Option<Client>, state: Arc<RwLock<State>>) -> Self {
        let cache = Arc::new(RwLock::new(LruCache::new(NonZeroUsize::new(8).unwrap())));
        let banned_count = Arc::new(AtomicU32::new(0));
        Self { config, nats, cache, state, banned_count }
    }
    
    pub async fn start_handlers(&mut self) {
        if self.nats.is_some() {
            Self::start_nats_handlers(self).await;
        }
    }

    pub async fn start_nats_handlers(context: &mut Context) {

        async fn process_list(config: &Config, nats: &Client, subject: &str, is_blocklist: bool) -> Option<Vec<Blocked>> {
            info!("Requesting {subject}");
            match nats.request(subject.to_string(), "empty".into()).await {
                Ok(message) => {
                    info!("Got response on {subject}, {} bytes", &message.payload.len());
                    let data = String::from_utf8_lossy(&message.payload);
                    let mut buf = String::new();

                    let mut blocked = Vec::new();
                    let mut lines = 0;
                    for line in data.lines() {
                        let (ip, timeout) = if is_blocklist {
                            get_ip_and_timeout(line)
                        } else {
                            (get_first_part(line), String::new())
                        };

                        let suffix = if is_ipv6(&ip) { "6" } else { "" };
                        let rule = match config.fw_type {
                            FwType::IpTables => format!("add {}{suffix} {line}\n", config.ipset_black_list),
                            FwType::NfTables => format!("add element ip{suffix} filter {}{suffix} {{{line}s}}\n", config.ipset_black_list),
                        };
                        buf.push_str(&rule);
                        lines += 1;

                        if is_blocklist {
                            if let Ok(parsed_ip) = ip.parse() {
                                blocked.push(Blocked::new(parsed_ip, None, timeout.parse().unwrap_or(DEFAULT_BLOCK_TIME_SEC)));

                            }
                        }
                    }
                    info!("Parsed {} lines for the list", lines);

                    let fw_type = config.fw_type.clone();
                    tokio::spawn(async move {
                        match fw_type {
                            FwType::IpTables => firewall::ipset_restore(&buf),
                            FwType::NfTables => firewall::nft_restore(&buf),
                        }
                    });
                    Some(blocked)
                }
                Err(e) => {
                    error!("Error requesting {} from NATS server: {}", subject, e);
                    None
                },
            }
        }

        // Process whitelist and blocklist
        if let Some(nats) = &context.nats {
            let config_clone = context.config.clone();
            let nats_clone = nats.clone();
            tokio::spawn(async move {
                let _ = process_list(&config_clone, &nats_clone, &config_clone.nats.wl_init_subject, false).await;
            });

            let config_clone = context.config.clone();
            let nats_clone = nats.clone();
            let state = Arc::clone(&context.state);
            tokio::spawn(async move {
                let blocked = process_list(&config_clone, &nats_clone, &config_clone.nats.bl_init_subject, true).await;
                if let Some(blocked) = blocked {
                    for b in blocked {
                        state.write().await.add_blocked(b);
                    }
                }
            });
        }

        // Subscribe handlers
        async fn subscribe_and_process(nats: &Client, subject: String, list_name: String, fw_type: FwType, cache: Option<Arc<RwLock<LruCache<String, bool>>>>, ignore_ips: Option<HashSet<String>>, state: Option<Arc<RwLock<State>>>) {
            if let Ok(mut sub) = nats.subscribe(subject.clone()).await {
                info!("Subscribed to {}", &subject);
                while let Some(message) = sub.next().await {
                    if let Ok(data) = String::from_utf8(message.payload.to_vec()) {
                        let (ip, _tag) = get_ip_and_tag(&data);

                        if !valid_ip(&ip) {
                            continue;
                        }
                        if let Some(ignore_ips) = &ignore_ips {
                            if ignore_ips.contains(&ip) {
                                continue;
                            }
                        }

                        if let Some(ref cache) = cache {
                            let cache = cache.read().await;
                            if cache.contains(&ip) {
                                continue;
                            }
                        }

                        let list = if is_ipv6(&ip) {
                            format!("{}6", list_name)
                        } else {
                            list_name.clone()
                        };

                        match fw_type {
                            FwType::IpTables => firewall::ipset_add_or_del("add", &list, &ip, None),
                            FwType::NfTables => firewall::nft_add(&list, &ip),
                        }

                        if let Some(ref cache) = cache {
                            let mut cache = cache.write().await;
                            cache.push(ip.clone(), true);
                        }

                        let _ = crate::kill_connection(&ip);

                        if let Some(ref state) = state {
                            if let Ok(parsed_ip) = ip.parse() {
                                let mut state = state.write().await;
                                state.add_blocked(Blocked::new(parsed_ip, None, DEFAULT_BLOCK_TIME_SEC));
                            }
                        }
                    }
                }
            }
        }

        if let Some(nats) = &context.nats {
            let config_clone = context.config.clone();
            let nats_clone = nats.clone();
            let cache_clone = context.cache.clone();
            let ignore_ips_clone = context.config.ignore_ips.iter().map(|s| s.to_owned()).collect::<HashSet<String>>();
            let state_clone = Arc::clone(&context.state);
            tokio::spawn(async move {
                subscribe_and_process(&nats_clone, config_clone.nats.bl_subscribe_subject.clone(), config_clone.ipset_black_list.clone(), config_clone.fw_type.clone(), Some(cache_clone), Some(ignore_ips_clone), Some(state_clone)).await;
            });

            let config_clone = context.config.clone();
            let nats_clone = nats.clone();
            tokio::spawn(async move {
                subscribe_and_process(&nats_clone, config_clone.nats.wl_subscribe_subject.clone(), config_clone.ipset_white_list.clone(), config_clone.fw_type.clone(), None, None, None, ).await;
            });

            // Remove from lists
            let nats_clone = nats.clone();
            let list_name_clone = context.config.ipset_white_list.clone();
            let subject = context.config.nats.wl_del_subject.clone();
            let fw_type = context.config.fw_type.clone();
            tokio::spawn(async move {
                subscribe_and_process(&nats_clone, subject, list_name_clone, fw_type, None, None, None).await;
            });

            let nats_clone = nats.clone();
            let list_name_clone = context.config.ipset_black_list.clone();
            let subject = context.config.nats.bl_del_subject.clone();
            tokio::spawn(async move {
                subscribe_and_process(&nats_clone, subject, list_name_clone, fw_type, None, None, None).await;
            });
        }
    }
}