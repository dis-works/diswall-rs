use std::io::{Error, ErrorKind, Read, stdout, Stdout};
use std::ops::Sub;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::mpsc::{channel, Sender};
use std::thread;
use std::time::{Duration, SystemTime};
use byteorder::{BigEndian, ReadBytesExt};
use crossterm::event::{KeyCode, KeyModifiers};
use crossterm::ExecutableCommand;
use crossterm::terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen};
use log::{debug, error, info, trace};
use ratatui::layout::Alignment;
use ratatui::prelude::{Color, Constraint, CrosstermBackend, Direction, Layout, Rect, Style, Stylize};
use ratatui::Terminal;
use ratatui::widgets::{Block, Borders, BorderType, Paragraph};
use ratatui::widgets::block::{Position, Title};
use crate::state::{Blocked, State};
use crate::ui::help::Popup;
use crate::ui::messages::StateMessage;
use crate::ui::search::Search;
use crate::ui::ui_client::StateTime::{Day, Full, Hour, Minute};

pub struct UiClient {
    path: String
}

impl UiClient {
    pub fn new(path: String) -> Self {
        Self { path }
    }

    pub fn start(&self) -> std::io::Result<()> {
        let stream = match Path::new(&self.path).exists() {
            true => {
                let mut stream = None;
                for _ in 0..5 {
                    info!("Trying to connect to service socket '{}'...", &self.path);
                    match UnixStream::connect(&self.path) {
                        Ok(s) => {
                            info!("Connected!");
                            stream = Some(s);
                            break;
                        },
                        Err(_) => {
                            info!("Could not connect to socket, let's wait a bit...");
                            thread::sleep(Duration::from_secs(3));
                        }
                    }
                }
                if stream.is_none() {
                    error!("Could not connect to socket at '{}'. Is diswall service alive?", &self.path);
                    return Err(Error::from(ErrorKind::NotConnected));
                }
                stream
            }
            false => {
                error!("Socket '{}' does not exist. Is diswall service alive?", &self.path);
                return Err(Error::from(ErrorKind::NotConnected));
            }
        };

        let stream = stream.unwrap();
        let (sender, receiver) = channel();

        thread::spawn(|| {
            if let Err(e) = read_stream(stream, sender) {
                error!("Error reading socket {e}");
            }
        });

        stdout().execute(EnterAlternateScreen)?;
        enable_raw_mode()?;
        let mut terminal = Terminal::new(CrosstermBackend::new(stdout()))?;
        terminal.clear()?;

        let mut state = State::new();
        let mut state_time = StateTime::Full;
        let mut origin = Origin::All;
        let mut redraw = true;

        let help = Popup::new(" Help ", "Hotkeys:\n\nLeft/Right to change time intervals (All time, last hour, last minute)\n\
        G/L/A to show only global (from NATS), local (banned here) or all items\n\
        Use 'f' to find some IP address\n\
        \n\
        Use 'q' to quit.");
        let mut show_help = false;
        let mut search = Search::new();
        let mut found: Option<String> = None;

        loop {
            let version = state.get_version();
            let start = std::time::Instant::now();
            while let Ok(item) = receiver.try_recv() {
                state.add_blocked(item);
                if start.elapsed().as_millis() >= 500 {
                    break;
                }
            }

            if redraw || version != state.get_version() {
                Self::redraw(&mut terminal, &state, &state_time, &origin, help.clone(), show_help, &search, &found)?;
                redraw = false;
            }

            // Check for user input every 50 milliseconds
            if crossterm::event::poll(std::time::Duration::from_millis(50))? {
                // If a key event occurs, handle it
                if let crossterm::event::Event::Key(key) = crossterm::event::read()? {
                    if key.kind == crossterm::event::KeyEventKind::Press {
                        if search.visible() && search.process_event(key) {
                            redraw = true;
                            if let Some(term) = search.take_search_term() {
                                found = Some(term);
                                search.hide();
                            }
                        } else {
                            match key.code {
                                KeyCode::Left => {
                                    state_time = state_time.up();
                                    redraw = true;
                                }
                                KeyCode::Right => {
                                    state_time = state_time.down();
                                    redraw = true;
                                }
                                KeyCode::Char('l') => {
                                    origin = Origin::Local;
                                    redraw = true;
                                },
                                KeyCode::Char('g') => {
                                    origin = Origin::Global;
                                    redraw = true;
                                },
                                KeyCode::Char('a') => {
                                    origin = Origin::All;
                                    redraw = true;
                                },
                                KeyCode::Char('h') => {
                                    show_help = !show_help;
                                    redraw = true;
                                },
                                KeyCode::Char('f') => {
                                    search.show();
                                    redraw = true;
                                },
                                KeyCode::Esc => {
                                    show_help = false;
                                    found = None;
                                    redraw = true;
                                },
                                KeyCode::Char('q') => {
                                    if show_help {
                                        show_help = false;
                                        redraw = true;
                                    } else {
                                        break;
                                    }
                                },
                                KeyCode::Char('c') if key.modifiers == KeyModifiers::CONTROL => {
                                    break;
                                },
                                _ => {},
                            }
                        }
                    }
                }
            }
        }
        stdout().execute(LeaveAlternateScreen)?;
        disable_raw_mode()?;
        Ok(())
    }

    fn redraw(terminal: &mut Terminal<CrosstermBackend<Stdout>>, state: &State, state_time: &StateTime, origin: &Origin, help: Popup, show_help: bool, search: &Search, find: &Option<String>) -> std::io::Result<()> {
        terminal.draw(|frame| {
            let layout = Layout::default()
                .direction(Direction::Vertical)
                .constraints(vec![
                    Constraint::Max(4),
                    Constraint::Min(4),
                ])
                .split(frame.area());

            let b = Block::default()
                .title(format!(" DisWall v{} ", env!("CARGO_PKG_VERSION")))
                .border_style(Style::default().fg(Color::Magenta))
                .border_type(BorderType::Rounded)
                .borders(Borders::ALL);

            let text = get_stats_text(&state, state_time);

            frame.render_widget(
                Paragraph::new(text)
                    .white()
                    .on_black()
                    .block(b),
                layout[0],
            );

            let refs = match find {
                None => {
                    state.blocked.iter()
                        .filter(|item| *origin == Origin::All || (*origin == Origin::Local && item.is_local()) || (*origin == Origin::Global && !item.is_local()))
                        .collect::<Vec<_>>()
                }
                Some(term) => {
                    state.blocked.iter()
                        .filter(|item| item.is_found(term))
                        .collect::<Vec<_>>()
                }
            };

            let height = layout[1].height as usize;
            let skip = if height >= refs.len() {
                0
            } else {
                refs.len() - height
            };

            let items = refs.iter()
                .skip(skip)
                .map(|i| i.to_line())
                .collect::<Vec<_>>();
            let bottom = format!(" Total lines in log {} (Use 'h' to open help) ", state.blocked.len());
            let title = match find {
                None => String::from(" Log of blocked IPs "),
                Some(term) => format!(" Log of IPs found by pattern '{}' (hit Esc to see all)", term)
            };
            frame.render_widget(
                Paragraph::new(items)
                    .white()
                    .on_black()
                    .block(
                        Block::default()
                            .title(title)
                            .border_style(Style::default().fg(Color::Magenta))
                            .border_type(BorderType::Rounded)
                            .borders(Borders::ALL)
                            .title(Title::from(bottom).position(Position::Bottom).alignment(Alignment::Center))
                    ),
                layout[1],
            );
            if show_help {
                let popup_area = Rect {
                    x: frame.area().width / 4,
                    y: frame.area().height / 3,
                    width: frame.area().width / 2,
                    height: frame.area().height / 3,
                };
                frame.render_widget(help, popup_area);
            }
            if search.visible() {
                search.draw(frame);
            }
        })?;
        Ok(())
    }
}

fn read_stream(mut stream: UnixStream, sender: Sender<Blocked>) -> std::io::Result<()> {
    loop {
        //TODO read message size
        let message_size = match stream.read_u64::<BigEndian>() {
            Ok(size) => size as usize,
            Err(e) => {
                error!("Unable to read UI message size: {e}");
                break;
            }
        };
        trace!("Reading message of {} bytes", &message_size);
        let mut buffer = vec![0u8; message_size];
        let mut read_bytes = 0;
        loop {
            match stream.read(&mut buffer[read_bytes..message_size as usize]) {
                Ok(n) if n == 0 => break, // Connection closed
                Ok(n) => {
                    read_bytes += n;
                    if read_bytes == message_size {
                        break;
                    }
                }
                Err(e) => {
                    stdout().execute(LeaveAlternateScreen)?;
                    disable_raw_mode()?;
                    error!("Error reading from socket: {}", e);
                    break;
                }
            }
        }
        if read_bytes == message_size {
            // TODO check message size == n
            let message = match rmp_serde::decode::from_slice::<StateMessage>(&buffer[..]) {
                Ok(message) => message,
                Err(e) => {
                    stdout().execute(LeaveAlternateScreen)?;
                    disable_raw_mode()?;
                    error!("Unable to decode UI message: {e}");
                    break;
                }
            };
            debug!("Received: {:?}", message);

            match &message {
                StateMessage::Ping => {
                    trace!("Got ping");
                }
                StateMessage::Changed => {}
                StateMessage::GetBlocked(_num) => {}
                StateMessage::Blocked(items) => {
                    for item in items {
                        //info!("{}", &item.to_string());
                        if let Err(_) = sender.send(item.clone()) {
                            break;
                        }
                    }
                }
            }
        }
    }
    trace!("Stream reading finished");
    Ok(())
}

fn get_stats_text(state: &State, state_time: &StateTime) -> String {
    let mut blocked_now = 0;
    let mut local = 0;
    let mut from_nats = 0;
    let mut last_interval = 0;
    let now = SystemTime::now();
    let start = match state_time {
        Full => SystemTime::UNIX_EPOCH,
        Day => now.sub(Duration::from_secs(86400)),
        Hour => now.sub(Duration::from_secs(3600)),
        Minute => now.sub(Duration::from_secs(60))
    };

    state.blocked.iter().for_each(|item| {
        if item.is_blocked_now(&now) {
            blocked_now += 1;
            match item.port {
                None => from_nats += 1,
                Some(_) => local += 1
            }
        }
        if item.is_blocked_after(&start) {
            last_interval += 1;
        }
    });
    format!("Blocked now: {}, from honeypots: {}, local: {}\n{}: {}", blocked_now, from_nats, local, &state_time.to_string(), last_interval)
}

enum StateTime {
    Full,
    Day,
    Hour,
    Minute
}

impl StateTime {
    pub fn up(&self) -> Self {
        match self {
            Full => Full,
            Day => Full,
            Hour => Day,
            Minute => Hour
        }
    }

    pub fn down(&self) -> Self {
        match self {
            Full => Day,
            Day => Hour,
            Hour => Minute,
            Minute => Minute
        }
    }
}

impl ToString for StateTime {
    fn to_string(&self) -> String {
        match self {
            Full => String::from("All time"),
            Day => String::from("Last 24 hours"),
            Hour => String::from("Last 60 minutes"),
            Minute => String::from("Last minute"),
        }
    }
}

#[derive(PartialEq)]
pub enum Origin {
    All,
    Global,
    Local
}