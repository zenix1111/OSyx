//! "Open with": which program opens a file.
//!
//! Installed applications (`/system/share/applications/*.app`) say which
//! files they handle with a `Handles=` line of extensions and kind names
//! (`Handles=mp4,mkv,video`). The user's choices per extension or kind live
//! in `~/.config/osyx/openwith.conf` as `mp4=/opt/player` lines. Files shows
//! images, text and source itself or through the default browser, unpacks
//! archives itself, and hands everything else to a registered application.

use crate::kind::{extension, Kind};
use alloc::string::String;
use alloc::vec::Vec;

/// Things Files does by itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Builtin {
    /// The text viewer (a hex dump for binary data).
    Viewer,
    Hex,
    /// The default browser through `/bin/open` (images, web pages).
    Browser,
    /// Unpack an archive next to itself.
    Extract,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Target {
    Builtin(Builtin),
    /// A program (an absolute path), started with the file as its argument.
    Exec(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Handler {
    pub name: String,
    pub exec: String,
    /// Lower-case extensions and kind names this application handles.
    pub handles: Vec<String>,
}

impl Handler {
    /// From the text of a `.app` file; `None` without name, `Exec` or `Handles`.
    pub fn parse(text: &str) -> Option<Handler> {
        let (mut name, mut exec, mut handles) = (String::new(), String::new(), Vec::new());
        for line in text.lines() {
            let Some((k, v)) = line.split_once('=') else { continue };
            match k.trim() {
                "Name" => name = String::from(v.trim()),
                "Exec" => exec = String::from(v.trim()),
                "Handles" => {
                    handles = v.split(',').map(|s| s.trim().trim_start_matches('.').to_ascii_lowercase()).filter(|s| !s.is_empty()).collect()
                }
                _ => {}
            }
        }
        (!name.is_empty() && exec.starts_with('/') && !handles.is_empty()).then_some(Handler { name, exec, handles })
    }

    fn handles(&self, ext: Option<&str>, kind: Kind) -> bool {
        self.handles.iter().any(|h| Some(h.as_str()) == ext || h == kind_name(kind))
    }
}

/// The name of a kind in `Handles=` and in the user's choices.
pub fn kind_name(kind: Kind) -> &'static str {
    match kind {
        Kind::Text => "text",
        Kind::Source => "source",
        Kind::Html => "html",
        Kind::Image => "image",
        Kind::Audio => "audio",
        Kind::Video => "video",
        Kind::Pdf => "pdf",
        Kind::Archive(_) => "archive",
        Kind::Program => "program",
        Kind::Other => "other",
    }
}

/// The user's choices: (extension or kind name, target).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Choices(pub Vec<(String, Target)>);

fn builtin_by_name(s: &str) -> Option<Builtin> {
    Some(match s {
        "builtin:viewer" => Builtin::Viewer,
        "builtin:hex" => Builtin::Hex,
        "builtin:browser" => Builtin::Browser,
        "builtin:extract" => Builtin::Extract,
        _ => return None,
    })
}

fn builtin_name(b: Builtin) -> &'static str {
    match b {
        Builtin::Viewer => "builtin:viewer",
        Builtin::Hex => "builtin:hex",
        Builtin::Browser => "builtin:browser",
        Builtin::Extract => "builtin:extract",
    }
}

impl Choices {
    pub fn parse(text: &str) -> Choices {
        let mut out = Vec::new();
        for line in text.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')) {
            let Some((k, v)) = line.split_once('=') else { continue };
            let key = k.trim().trim_start_matches('.').to_ascii_lowercase();
            let v = v.trim();
            let target = match builtin_by_name(v) {
                Some(b) => Target::Builtin(b),
                None if v.starts_with('/') => Target::Exec(String::from(v)),
                None => continue,
            };
            if !key.is_empty() {
                out.push((key, target));
            }
        }
        Choices(out)
    }

    pub fn render(&self) -> String {
        let mut s = String::new();
        for (k, t) in &self.0 {
            let v = match t {
                Target::Builtin(b) => builtin_name(*b),
                Target::Exec(e) => e.as_str(),
            };
            s += &alloc::format!("{k}={v}\n");
        }
        s
    }

    /// Remembers `target` for files with this extension (or, without one,
    /// for the kind).
    pub fn set(&mut self, name: &str, kind: Kind, target: Target) {
        let key = extension(name).unwrap_or_else(|| String::from(kind_name(kind)));
        self.0.retain(|(k, _)| *k != key);
        self.0.push((key, target));
    }

    fn get(&self, ext: Option<&str>, kind: Kind) -> Option<&Target> {
        let by = |key: &str| self.0.iter().find(|(k, _)| k == key).map(|(_, t)| t);
        ext.and_then(by).or_else(|| by(kind_name(kind)))
    }
}

/// One entry of the "Open with" menu.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Candidate {
    pub label: String,
    pub target: Target,
}

/// Everything that can open a file called `name` of kind `kind`.
/// `browser`: a default browser is installed.
pub fn candidates(name: &str, kind: Kind, handlers: &[Handler], browser: bool) -> Vec<Candidate> {
    let ext = extension(name);
    let mut out: Vec<Candidate> = Vec::new();
    let mut add = |label: &str, target: Target| out.push(Candidate { label: String::from(label), target });
    match kind {
        Kind::Text | Kind::Source | Kind::Other => {
            add("Text viewer", Target::Builtin(Builtin::Viewer));
            add("Hex viewer", Target::Builtin(Builtin::Hex));
        }
        Kind::Html | Kind::Image => {
            if browser {
                add("Web browser", Target::Builtin(Builtin::Browser));
            }
            add("Hex viewer", Target::Builtin(Builtin::Hex));
        }
        Kind::Archive(_) => add("Extract here", Target::Builtin(Builtin::Extract)),
        Kind::Audio | Kind::Video | Kind::Pdf => add("Hex viewer", Target::Builtin(Builtin::Hex)),
        Kind::Program => {}
    }
    for h in handlers.iter().filter(|h| h.handles(ext.as_deref(), kind)) {
        out.push(Candidate { label: h.name.clone(), target: Target::Exec(h.exec.clone()) });
    }
    out
}

/// What a double click does: the user's choice if it is still possible,
/// else a registered application for the exact extension, then for the
/// kind, else the first built-in way. `None`: nothing can open it.
pub fn default_target(name: &str, kind: Kind, handlers: &[Handler], choices: &Choices, browser: bool) -> Option<Target> {
    let list = candidates(name, kind, handlers, browser);
    let ext = extension(name);
    if let Some(t) = choices.get(ext.as_deref(), kind) {
        if list.iter().any(|c| &c.target == t) {
            return Some(t.clone());
        }
    }
    // Media Files cannot show: a registered application, else nothing
    // (the hex viewer is an explicit choice, not a default).
    let app = handlers.iter().find(|h| h.handles(ext.as_deref(), kind)).map(|h| Target::Exec(h.exec.clone()));
    match kind {
        Kind::Audio | Kind::Video | Kind::Pdf => app,
        _ => list.into_iter().next().map(|c| c.target),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kind::classify;

    fn player() -> Handler {
        Handler::parse("Name=Player\nExec=/opt/player\nHandles=mp4, .MKV, audio\n").unwrap()
    }

    #[test]
    fn parsing_handlers() {
        let h = player();
        assert_eq!(h.handles, ["mp4", "mkv", "audio"]);
        assert!(Handler::parse("Name=X\nExec=/x\n").is_none(), "no Handles line");
        assert!(Handler::parse("Name=X\nExec=x\nHandles=txt\n").is_none(), "relative Exec");
    }

    #[test]
    fn media_needs_a_registered_application() {
        let handlers = [player()];
        let choices = Choices::default();
        let video = classify("clip.mp4");
        assert_eq!(default_target("clip.mp4", video, &handlers, &choices, true), Some(Target::Exec("/opt/player".into())));
        assert_eq!(default_target("song.mp3", classify("song.mp3"), &handlers, &choices, true), Some(Target::Exec("/opt/player".into())), "by kind");
        assert_eq!(default_target("movie.avi", classify("movie.avi"), &handlers, &choices, true), None, "nothing handles avi");
        assert_eq!(default_target("a.pdf", Kind::Pdf, &[], &choices, true), None);
        // Still openable as hex through the menu.
        let list = candidates("a.pdf", Kind::Pdf, &[], true);
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].target, Target::Builtin(Builtin::Hex));
    }

    #[test]
    fn built_in_defaults() {
        let none = Choices::default();
        assert_eq!(default_target("a.txt", Kind::Text, &[], &none, false), Some(Target::Builtin(Builtin::Viewer)));
        assert_eq!(default_target("a.png", Kind::Image, &[], &none, true), Some(Target::Builtin(Builtin::Browser)));
        assert_eq!(default_target("a.png", Kind::Image, &[], &none, false), Some(Target::Builtin(Builtin::Hex)), "no browser: hex is all there is");
        let z = classify("a.zip");
        assert_eq!(default_target("a.zip", z, &[], &none, false), Some(Target::Builtin(Builtin::Extract)));
    }

    #[test]
    fn user_choices_win_when_possible() {
        let handlers = [Handler::parse("Name=Editor\nExec=/opt/edit\nHandles=txt,md\n").unwrap()];
        let mut choices = Choices::default();
        choices.set("notes.txt", Kind::Text, Target::Exec("/opt/edit".into()));
        assert_eq!(default_target("x.txt", Kind::Text, &handlers, &choices, false), Some(Target::Exec("/opt/edit".into())));
        // Another text extension is not affected.
        assert_eq!(default_target("x.log", Kind::Text, &handlers, &choices, false), Some(Target::Builtin(Builtin::Viewer)));
        // The program was uninstalled: back to the default.
        assert_eq!(default_target("x.txt", Kind::Text, &[], &choices, false), Some(Target::Builtin(Builtin::Viewer)));
    }

    #[test]
    fn choices_round_trip() {
        let text = "# comment\nmp4=/opt/player\n.TXT=builtin:hex\nbad=relative\nmovie=\n";
        let c = Choices::parse(text);
        assert_eq!(c.0.len(), 2);
        assert_eq!(Choices::parse(&c.render()), c);
    }
}
