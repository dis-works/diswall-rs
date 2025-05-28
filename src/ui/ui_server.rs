use tokio::sync::RwLock;
#[cfg(not(windows))]
use tokio::net::{UnixListener, UnixStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::sync::Arc;
use std::fs;
use log::{debug, error, info};
use tokio::time::timeout;
use crate::state::{LoginState, State};
use crate::ui::messages::StateMessage;

pub struct UiServer {
    socket_path: String,
    state: Arc<RwLock<State>>
}

impl UiServer {
    pub fn new(socket_path: String, state: Arc<RwLock<State>>) -> Self {
        Self { socket_path, state }
    }

    pub async fn start(&self) {
        let _ = fs::remove_file(&self.socket_path);
        let listener = match UnixListener::bind(&self.socket_path) {
            Ok(listener) => listener,
            Err(e) => {
                error!("Unable to open unix-socket: {e}");
                return;
            }
        };

        info!("UI server activated");
        loop {
            if let Ok((stream, _)) = listener.accept().await {
                let state = Arc::clone(&self.state);
                tokio::spawn(async move {
                    handle_client(stream, state).await;
                });
            }
        }
    }
}

impl Drop for UiServer {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.socket_path);
    }
}

async fn handle_client(mut stream: tokio::net::UnixStream, state: Arc<RwLock<State>>) {
    let mut buffer = [0; 512];

    info!("UI client connected");
    let mut last_item = 0;
    let mut last_time = std::time::Instant::now();
    let mut last_login_state = LoginState::Unknown;
    loop {
        let message_size = match timeout(tokio::time::Duration::from_millis(50), stream.read_u64()).await {
            Ok(Ok(size)) => size, // The read was successful within the timeout
            Ok(Err(_)) => 0,
            Err(_) => 0
        };
        if message_size > 0 {
            match stream.read(&mut buffer[0..message_size as usize]).await {
                Ok(n) if n == 0 => break, // Connection closed
                Ok(n) => {
                    // TODO check message size == n
                    let message = match rmp_serde::decode::from_slice::<StateMessage>(&buffer[..n]) {
                        Ok(message) => message,
                        Err(e) => {
                            error!("Unable to decode UI message: {e}");
                            break;
                        }
                    };
                    debug!("Received: {:?}", message);

                    match &message {
                        StateMessage::Ping => {}
                        StateMessage::Changed => {}
                        StateMessage::GetBlocked(_num) => {
                            let state = state.read().await;
                            let lines = state.get_blocked(last_item);
                            let response = StateMessage::Blocked(lines);
                            let buf = rmp_serde::encode::to_vec_named(&response).unwrap();
                            if let Err(_) = send_message(&mut stream, &buf).await {
                                break;
                            }
                        }
                        StateMessage::Blocked(_) => {}
                        StateMessage::LogStatus(_) => {}
                    }
                }
                Err(e) => {
                    error!("Error reading from socket: {}", e);
                    break;
                }
            }
        }

        let blocked = {
            let state = state.read().await;
            let blocked = state.get_blocked(last_item);
            if !blocked.is_empty() {
                Some(blocked)
            } else {
                None
            }
        };
        if let Some(blocked) = blocked {
            debug!("Found {} log items, sending", &blocked.len());
            let last = blocked.last().unwrap().id;
            let response = StateMessage::Blocked(blocked);
            let buf = rmp_serde::encode::to_vec_named(&response).unwrap();
            if let Err(e) = send_message(&mut stream, &buf).await {
                error!("Error sending log lines to UI: {e}");
                break;
            }
            last_item = last;
            last_time = std::time::Instant::now();
        } else if last_time.elapsed().as_secs() > 4 {
            let response = StateMessage::Ping;
            let buf = rmp_serde::encode::to_vec_named(&response).unwrap();
            if let Err(e) = send_message(&mut stream, &buf).await {
                error!("Error sending ping to UI: {e}");
                break;
            }
            last_time = std::time::Instant::now();
        }
        {
            let state = state.read().await;
            if last_login_state != state.logged_in {
                let message = StateMessage::LogStatus(state.logged_in.clone());
                let buf = rmp_serde::encode::to_vec_named(&message).unwrap();
                if let Err(e) = send_message(&mut stream, &buf).await {
                    error!("Error sending status to UI: {e}");
                    break;
                }
                last_login_state = state.logged_in.clone();
            }
        }
    }
    info!("UI client disconnected");
}

async fn send_message(stream: &mut UnixStream, buf: &Vec<u8>) -> Result<(), std::io::Error> {
    stream.write_u64(buf.len() as u64).await?;
    stream.write_all(&buf).await?;
    stream.flush().await
}