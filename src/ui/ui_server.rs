use std::io::{Read, Write};
#[cfg(not(windows))]
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::{Arc, Mutex};
use std::{fs, thread};
use std::time::Duration;
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use log::{debug, error, info};
use crate::state::State;
use crate::ui::messages::StateMessage;

pub struct UiServer {
    socket_path: String,
    state: Arc<Mutex<State>>
}

impl UiServer {
    pub fn new(socket_path: String, state: Arc<Mutex<State>>) -> Self {
        Self { socket_path, state }
    }

    pub fn start(&self) {
        let listener = match UnixListener::bind(&self.socket_path) {
            Ok(listener) => listener,
            Err(e) => {
                error!("Unable to open unix-socket: {e}");
                return;
            }
        };

        info!("UI server activated");
        for stream in listener.incoming() {
            match stream {
                Ok(stream) => {
                    let state = Arc::clone(&self.state);
                    // Spawn a new thread for each incoming connection
                    thread::spawn(|| {
                        handle_client(stream, state);
                    });
                }
                Err(e) => {
                    eprintln!("Error accepting connection: {}", e);
                    break;
                }
            }
        }
    }
}

impl Drop for UiServer {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.socket_path);
    }
}

fn handle_client(mut stream: UnixStream, state: Arc<Mutex<State>>) {
    let mut buffer = [0; 512];

    info!("UI client connected");
    let _ = stream.set_read_timeout(Some(Duration::from_millis(100)));
    let mut last_item = 0;
    let mut last_time = std::time::Instant::now();
    loop {
        //TODO read message size
        let message_size = match stream.read_u64::<BigEndian>() {
            Ok(size) => size,
            Err(e) => {
                debug!("Unable to read UI message size: {e}");
                0
            }
        };
        if message_size > 0 {
            match stream.read(&mut buffer[0..message_size as usize]) {
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
                            if let Ok(state) = state.lock() {
                                let lines = state.get_blocked(last_item);
                                let response = StateMessage::Blocked(lines);
                                let buf = rmp_serde::encode::to_vec_named(&response).unwrap();
                                stream.write_u64::<BigEndian>(buf.len() as u64).expect("Error sending response");
                                stream.write_all(&buf).expect("Error sending response");
                            }
                        }
                        StateMessage::Blocked(_) => {}
                    }
                }
                Err(e) => {
                    error!("Error reading from socket: {}", e);
                    break;
                }
            }
        }

        let blocked = if let Ok(state) = state.lock() {
            let blocked = state.get_blocked(last_item);
            if !blocked.is_empty() {
                Some(blocked)
            } else {
                None
            }
        } else {
            None
        };
        if let Some(blocked) = blocked {
            info!("Found {} log items, sending", &blocked.len());
            let last = blocked.last().unwrap().id;
            let response = StateMessage::Blocked(blocked);
            let buf = rmp_serde::encode::to_vec_named(&response).unwrap();
            stream.write_u64::<BigEndian>(buf.len() as u64).expect("Error sending response");
            stream.write_all(&buf).expect("Error sending response");
            if let Err(e) = stream.flush() {
                error!("Error flushing socket {e}");
                break;
            }
            last_item = last;
            last_time = std::time::Instant::now();
        } else if last_time.elapsed().as_secs() > 4 {
            let response = StateMessage::Ping;
            let buf = rmp_serde::encode::to_vec_named(&response).unwrap();
            stream.write_u64::<BigEndian>(buf.len() as u64).expect("Error sending response");
            stream.write_all(&buf).expect("Error sending response");
            last_time = std::time::Instant::now();
            if let Err(e) = stream.flush() {
                error!("Error flushing socket {e}");
                break;
            }
        }
    }
    info!("UI client disconnected");
}