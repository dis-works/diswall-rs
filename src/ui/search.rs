use crossterm::event::{KeyCode, KeyEvent};
use ratatui::Frame;
use ratatui::prelude::{Color, Rect, Style};
use ratatui::widgets::{Block, Borders, BorderType, Clear, Paragraph};


const MAX_CHARS: usize = 30;

pub struct Search {
    input: String,
    cursor_pos: usize,
    visible: bool,
    search_term: Option<String>,
}

impl Search {
    pub fn new() -> Self {
        Self { input: String::new(), cursor_pos: 0, visible: false, search_term: None }
    }

    pub fn process_event(&mut self, event: KeyEvent) -> bool {
        if !self.visible && event.code == KeyCode::Char('f') {
            self.visible = true;
            true
        } else if self.visible {
            if event.code == KeyCode::Esc {
                self.visible = false;
                return true;
            }

            match event.code {
                KeyCode::Enter => self.submit_message(),
                KeyCode::Char(to_insert) => {
                    self.enter_char(to_insert);
                }
                KeyCode::Backspace => {
                    self.delete_char();
                }
                KeyCode::Left => {
                    self.move_cursor_left();
                }
                KeyCode::Right => {
                    self.move_cursor_right();
                }
                _ => {}
            }
            true
        } else {
            false
        }
    }

    pub fn take_search_term(&mut self) -> Option<String> {
        self.search_term.take()
    }

    pub fn draw(&self, frame: &mut Frame) {
        let width = frame.size().width / 4;
        let popup_area = Rect {
            x: frame.size().width / 2 - width / 2,
            y: 7,
            width,
            height: 3,
        };

        frame.render_widget(Clear, popup_area);
        let input = Paragraph::new(self.input.as_str())
            .style(Style::default())
            .block(Block::default().borders(Borders::ALL).border_style(Style::default().fg(Color::Magenta)).border_type(BorderType::Rounded).title(" Find "));
        frame.render_widget(input, popup_area);
        frame.set_cursor(
            // Draw the cursor at the current position in the input field.
            // This position is controlled via the left and right arrow keys
            popup_area.x + self.cursor_pos as u16 + 1,
            // Move one line down, from the border to the input line
            popup_area.y + 1,
        )
    }

    pub fn visible(&self) -> bool {
        self.visible
    }

    pub fn hide(&mut self) {
        self.visible = false;
    }

    pub fn show(&mut self) {
        self.visible = true;
    }

    fn move_cursor_left(&mut self) {
        let cursor_moved_left = self.cursor_pos.saturating_sub(1);
        self.cursor_pos = self.clamp_cursor(cursor_moved_left);
    }

    fn move_cursor_right(&mut self) {
        let cursor_moved_right = self.cursor_pos.saturating_add(1);
        self.cursor_pos = self.clamp_cursor(cursor_moved_right);
    }

    fn enter_char(&mut self, new_char: char) {
        if self.input.chars().count() >= MAX_CHARS {
            return;
        }
        self.input.insert(self.cursor_pos, new_char);

        self.move_cursor_right();
    }

    fn delete_char(&mut self) {
        let is_not_cursor_leftmost = self.cursor_pos != 0;
        if is_not_cursor_leftmost {
            // Method "remove" is not used on the saved text for deleting the selected char.
            // Reason: Using remove on String works on bytes instead of the chars.
            // Using remove would require special care because of char boundaries.

            let current_index = self.cursor_pos;
            let from_left_to_current_index = current_index - 1;

            // Getting all characters before the selected character.
            let before_char_to_delete = self.input.chars().take(from_left_to_current_index);
            // Getting all characters after selected character.
            let after_char_to_delete = self.input.chars().skip(current_index);

            // Put all characters together except the selected one.
            // By leaving the selected one out, it is forgotten and therefore deleted.
            self.input = before_char_to_delete.chain(after_char_to_delete).collect();
            self.move_cursor_left();
        }
    }

    fn clamp_cursor(&self, new_cursor_pos: usize) -> usize {
        new_cursor_pos.clamp(0, self.input.len())
    }

    fn reset_cursor(&mut self) {
        self.cursor_pos = 0;
    }

    fn submit_message(&mut self) {
        if !self.input.is_empty() {
            self.search_term = Some(self.input.clone());
            self.input.clear();
            self.reset_cursor();
        }
    }
}