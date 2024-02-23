use ratatui::prelude::*;
use ratatui::widgets::{Block, Borders, BorderType, Clear, Paragraph, Widget, Wrap};
use ratatui::widgets::block::Title;

#[derive(Debug, Default, Clone)]
pub struct Popup<'a> {
    title: Title<'a>,
    content: Text<'a>,
    border_style: Style,
    title_style: Style,
    style: Style,
}

impl<'a> Popup<'a> {
    pub fn new(title: &'a str, text: &'a str) -> Popup<'a> {
        let title = Title::from(title);
        let content = Text::from(text);
        let border_style = Style::new().magenta();
        let title_style = Style::new().magenta();
        let style = Style::new().white();
        Popup {
            title,
            content,
            border_style,
            title_style,
            style,
        }
    }
}

impl Widget for Popup<'_> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        // ensure that all cells under the popup are cleared to avoid leaking content
        Clear.render(area, buf);
        let block = Block::new()
            .title(self.title)
            .title_style(self.title_style)
            .borders(Borders::ALL)
            .border_style(self.border_style)
            .border_type(BorderType::Rounded);
        Paragraph::new(self.content)
            .wrap(Wrap { trim: true })
            .style(self.style)
            .block(block)
            .render(area, buf);
    }
}