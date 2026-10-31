//! Text clipboard state supplied by the host application.

use alloc::string::String;

/// A local view of the system clipboard. The host publishes local changes
/// and calls `receive` when the compositor reports new contents.
#[derive(Clone, Debug, Default)]
pub struct Clipboard {
    text: Option<String>,
    changed: bool,
}

impl Clipboard {
    pub fn text(&self) -> Option<&str> {
        self.text.as_deref()
    }

    pub fn set(&mut self, text: &str) {
        self.text = Some(String::from(text));
        self.changed = true;
    }

    pub fn receive(&mut self, text: Option<String>) {
        self.text = text;
        self.changed = false;
    }

    pub fn take_changed(&mut self) -> Option<&str> {
        if !core::mem::take(&mut self.changed) {
            return None;
        }
        self.text.as_deref()
    }
}
