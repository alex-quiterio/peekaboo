//! Terminal styling: ANSI colour only when stdout is a terminal and NO_COLOR is not set.
use crate::domain::model::Severity;
use std::io::IsTerminal;

#[derive(Debug, Clone, Copy)]
pub struct Style {
    color: bool,
}

impl Style {
    #[cfg(test)]
    pub fn plain() -> Self {
        Style { color: false }
    }

    /// Colour for an interactive terminal; plain text when piped or when NO_COLOR is set.
    pub fn detect() -> Self {
        Style { color: std::io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none() }
    }

    fn paint(self, code: &str, text: &str) -> String {
        if self.color { format!("\x1b[{code}m{text}\x1b[0m") } else { text.to_string() }
    }

    pub fn bold(self, text: &str) -> String {
        self.paint("1", text)
    }
    pub fn dim(self, text: &str) -> String {
        self.paint("2", text)
    }
    pub fn red(self, text: &str) -> String {
        self.paint("31", text)
    }
    pub fn green(self, text: &str) -> String {
        self.paint("32", text)
    }
    pub fn yellow(self, text: &str) -> String {
        self.paint("33", text)
    }
    pub fn cyan(self, text: &str) -> String {
        self.paint("36", text)
    }

    pub fn severity(self, severity: Severity, text: &str) -> String {
        match severity {
            Severity::High => self.paint("1;31", text),
            Severity::Medium => self.paint("33", text),
            Severity::Low => self.paint("36", text),
            Severity::Info => self.paint("2", text),
        }
    }

    /// A section heading with a rule under the width of the page.
    pub fn heading(self, title: &str) -> String {
        format!("{}\n{}", self.bold(&self.cyan(title)), self.dim(&"─".repeat(WIDTH)))
    }

    /// A bar like `████████░░░░` for a 0–100 value, coloured by how good it is.
    pub fn meter(self, percent: u32, width: usize) -> String {
        let filled = (percent.min(100) as usize * width + 50) / 100;
        let bar = format!("{}{}", "█".repeat(filled), "░".repeat(width - filled));
        match percent {
            80.. => self.green(&bar),
            50..=79 => self.yellow(&bar),
            _ => self.red(&bar),
        }
    }
}

/// Width of the rules and of wrapped text.
pub const WIDTH: usize = 64;

/// Wraps `text` to `width` columns, indenting continuation lines by `indent` spaces.
pub fn wrap(text: &str, width: usize, indent: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut line = String::new();
    for word in text.split_whitespace() {
        let used = if lines.is_empty() { 0 } else { indent };
        if !line.is_empty() && used + line.chars().count() + 1 + word.chars().count() > width {
            lines.push(std::mem::take(&mut line));
        }
        if !line.is_empty() {
            line.push(' ');
        }
        line.push_str(word);
    }
    if !line.is_empty() || lines.is_empty() {
        lines.push(line);
    }
    let pad = " ".repeat(indent);
    lines.into_iter().enumerate().map(|(i, l)| if i == 0 { l } else { format!("{pad}{l}") }).collect()
}
