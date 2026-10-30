//! What a file is, judged by its name.

use alloc::string::String;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArchiveKind {
    Tar,
    /// `.tar.gz` and `.tgz`.
    TarGz,
    /// A single compressed file (`.gz`).
    Gz,
    Zip,
    SevenZ,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Text,
    Source,
    Html,
    Image,
    Audio,
    Video,
    Pdf,
    Archive(ArchiveKind),
    Program,
    Other,
}

const TEXT: &[&str] = &["txt", "md", "log", "conf", "cfg", "ini", "csv", "json", "xml", "yaml", "yml", "toml", "app", "rtf", "srt"];
const SOURCE: &[&str] = &["rs", "c", "h", "cc", "cpp", "hpp", "py", "sh", "js", "ts", "ax", "java", "go", "asm", "s", "css", "lua", "php", "cs", "rb"];
const HTML: &[&str] = &["html", "htm", "xhtml"];
const IMAGE: &[&str] = &["png", "jpg", "jpeg", "gif", "webp", "bmp", "osxi", "ico", "svg", "tif", "tiff"];
const AUDIO: &[&str] = &["mp3", "wav", "flac", "ogg", "oga", "opus", "m4a", "aac", "wma", "mid"];
const VIDEO: &[&str] = &["mp4", "mkv", "webm", "avi", "mov", "wmv", "flv", "m4v", "mpg", "mpeg", "ogv"];

/// The lower-case extension after the last dot (`None` for no dot, a
/// leading dot only, or a trailing dot).
pub fn extension(name: &str) -> Option<String> {
    let (stem, ext) = name.rsplit_once('.')?;
    (!stem.is_empty() && !ext.is_empty()).then(|| ext.to_ascii_lowercase())
}

/// The kind of a file named `name` (directories are not classified here).
pub fn classify(name: &str) -> Kind {
    let lower = name.to_ascii_lowercase();
    if lower.ends_with(".tar.gz") || lower.ends_with(".tgz") {
        return Kind::Archive(ArchiveKind::TarGz);
    }
    let Some(ext) = extension(&lower) else {
        // Files without an extension are mostly scripts, READMEs, Makefiles.
        return Kind::Text;
    };
    let ext = ext.as_str();
    if ext == "exe" {
        return Kind::Program;
    }
    if TEXT.contains(&ext) {
        Kind::Text
    } else if SOURCE.contains(&ext) {
        Kind::Source
    } else if HTML.contains(&ext) {
        Kind::Html
    } else if IMAGE.contains(&ext) {
        Kind::Image
    } else if AUDIO.contains(&ext) {
        Kind::Audio
    } else if VIDEO.contains(&ext) {
        Kind::Video
    } else if ext == "pdf" {
        Kind::Pdf
    } else if ext == "gz" {
        Kind::Archive(ArchiveKind::Gz)
    } else if ext == "tar" {
        Kind::Archive(ArchiveKind::Tar)
    } else if ext == "zip" {
        Kind::Archive(ArchiveKind::Zip)
    } else if ext == "7z" {
        Kind::Archive(ArchiveKind::SevenZ)
    } else {
        Kind::Other
    }
}

impl Kind {
    /// Name shown in the Type column.
    pub fn label(self) -> &'static str {
        match self {
            Kind::Text => "Text document",
            Kind::Source => "Source code",
            Kind::Html => "Web page",
            Kind::Image => "Image",
            Kind::Audio => "Audio",
            Kind::Video => "Video",
            Kind::Pdf => "PDF document",
            Kind::Archive(_) => "Archive",
            Kind::Program => "Program",
            Kind::Other => "File",
        }
    }

    /// Kinds Files can show itself (as text, or a hex dump when binary).
    pub fn viewable(self) -> bool {
        matches!(self, Kind::Text | Kind::Source | Kind::Other)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kinds_by_name() {
        assert_eq!(classify("notes.TXT"), Kind::Text);
        assert_eq!(classify("main.rs"), Kind::Source);
        assert_eq!(classify("index.html"), Kind::Html);
        assert_eq!(classify("Photo.JPG"), Kind::Image);
        assert_eq!(classify("song.flac"), Kind::Audio);
        assert_eq!(classify("clip.MKV"), Kind::Video);
        assert_eq!(classify("paper.pdf"), Kind::Pdf);
        assert_eq!(classify("a.tar"), Kind::Archive(ArchiveKind::Tar));
        assert_eq!(classify("a.tar.gz"), Kind::Archive(ArchiveKind::TarGz));
        assert_eq!(classify("a.TGZ"), Kind::Archive(ArchiveKind::TarGz));
        assert_eq!(classify("log.gz"), Kind::Archive(ArchiveKind::Gz));
        assert_eq!(classify("a.zip"), Kind::Archive(ArchiveKind::Zip));
        assert_eq!(classify("a.7z"), Kind::Archive(ArchiveKind::SevenZ));
        assert_eq!(classify("setup.exe"), Kind::Program);
        assert_eq!(classify("README"), Kind::Text);
        assert_eq!(classify("data.bin"), Kind::Other);
        assert_eq!(classify(".bashrc"), Kind::Text, "a leading dot is not an extension");
    }

    #[test]
    fn extensions() {
        assert_eq!(extension("a.b.C").as_deref(), Some("c"));
        assert_eq!(extension("noext"), None);
        assert_eq!(extension(".hidden"), None);
        assert_eq!(extension("trailing."), None);
    }
}
