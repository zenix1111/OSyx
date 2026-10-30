//! Blocks of AXIS scripts: `if cond { ... } else { ... }` and
//! `for NAME in WORDS { ... }`.
//!
//! One line holds the header or the closing brace; an `else` shares its line
//! with the closing brace of the `then` part (`} else {`). Indices, quoting
//! and `$` expansion stay with the shell: the parser keeps command lines and
//! conditions verbatim.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

/// One statement of a script.
#[derive(Debug, PartialEq, Eq)]
pub enum Stmt {
    /// A complete line the shell runs as a command.
    Command(String),
    If { cond: String, then: Vec<Stmt>, alt: Vec<Stmt> },
    For { name: String, words: String, body: Vec<Stmt> },
}

/// How many block levels a chunk of lines opens (`{` minus `}`, outside
/// quotes and comments). The shell reads more lines while it is positive.
pub fn depth(lines: &[&str]) -> Result<i32, String> {
    let mut d = 0;
    for line in lines {
        d += braces(code(line))?;
    }
    Ok(d)
}

/// Parses complete lines into statements.
pub fn parse_script(lines: &[&str]) -> Result<Vec<Stmt>, String> {
    let mut i = 0;
    let stmts = statements(lines, &mut i, false)?;
    if i < lines.len() {
        return Err(String::from("unexpected `}`"));
    }
    Ok(stmts)
}

fn statements(lines: &[&str], i: &mut usize, in_block: bool) -> Result<Vec<Stmt>, String> {
    let mut out = Vec::new();
    while *i < lines.len() {
        if let Some(q) = unterminated(code(lines[*i])) {
            return Err(alloc::format!("unterminated quote `{q}`"));
        }
        let line = code(lines[*i]).trim();
        if line.is_empty() {
            *i += 1;
            continue;
        }
        if line == "}" || line == "} else {" {
            if !in_block {
                return Err(String::from("`}` without a block"));
            }
            return Ok(out);
        }
        if let Some(rest) = line.strip_prefix("if ").and_then(|r| r.strip_suffix('{')) {
            let cond = rest.trim();
            if cond.is_empty() {
                return Err(String::from("`if` needs a condition"));
            }
            *i += 1;
            let then = statements(lines, i, true)?;
            let alt = if close(lines, i)? {
                let alt = statements(lines, i, true)?;
                expect_close(lines, i)?;
                alt
            } else {
                Vec::new()
            };
            out.push(Stmt::If { cond: cond.to_string(), then, alt });
            continue;
        }
        if let Some(rest) = line.strip_prefix("for ").and_then(|r| r.strip_suffix('{')) {
            let (name, words) = rest.split_once(" in ").ok_or("`for` needs `NAME in WORDS`")?;
            let name = name.trim();
            if !name.starts_with(|c: char| c.is_alphabetic() || c == '_')
                || !name.chars().all(|c| c.is_alphanumeric() || c == '_')
            {
                return Err(String::from("`for` needs a variable name"));
            }
            *i += 1;
            let body = statements(lines, i, true)?;
            expect_close(lines, i)?;
            out.push(Stmt::For { name: name.to_string(), words: words.trim().to_string(), body });
            continue;
        }
        if line.ends_with('{') {
            return Err(String::from("only `if` and `for` open a block"));
        }
        out.push(Stmt::Command(line.to_string()));
        *i += 1;
    }
    if in_block {
        return Err(String::from("missing `}`"));
    }
    Ok(out)
}

/// Consumes the closing line; `true` when it opens an `else` part.
fn close(lines: &[&str], i: &mut usize) -> Result<bool, String> {
    match lines.get(*i).map(|l| code(l).trim()) {
        Some("} else {") => {
            *i += 1;
            Ok(true)
        }
        Some("}") => {
            *i += 1;
            Ok(false)
        }
        Some(_) => Err(String::from("expected `}`")),
        None => Err(String::from("missing `}`")),
    }
}

fn expect_close(lines: &[&str], i: &mut usize) -> Result<(), String> {
    match lines.get(*i).map(|l| code(l).trim()) {
        Some("}") => {
            *i += 1;
            Ok(())
        }
        _ => Err(String::from("expected `}`")),
    }
}

/// The line without a trailing comment.
fn code(line: &str) -> &str {
    let mut quote = None;
    for (o, ch) in line.char_indices() {
        match (quote, ch) {
            (Some(q), c) if c == q => quote = None,
            (Some(_), _) => {}
            (None, '"') | (None, '\'') => quote = Some(ch),
            (None, '#') => return &line[..o],
            _ => {}
        }
    }
    line
}

/// Block depth change of one line, ignoring quoted braces.
fn braces(line: &str) -> Result<i32, String> {
    let mut d = 0;
    let mut quote = None;
    for ch in line.chars() {
        match (quote, ch) {
            (Some(q), c) if c == q => quote = None,
            (Some(_), _) => {}
            (None, '"') | (None, '\'') => quote = Some(ch),
            (None, '{') => d += 1,
            (None, '}') => d -= 1,
            _ => {}
        }
    }
    match quote {
        Some(q) => Err(alloc::format!("unterminated quote `{q}`")),
        None => Ok(d),
    }
}

/// The quote character a line leaves open, if any.
fn unterminated(line: &str) -> Option<char> {
    let mut quote = None;
    for ch in line.chars() {
        match (quote, ch) {
            (Some(q), c) if c == q => quote = None,
            (Some(_), _) => {}
            (None, '"') | (None, '\'') => quote = Some(ch),
            _ => {}
        }
    }
    quote
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(text: &str) -> Result<Vec<Stmt>, String> {
        let lines: Vec<&str> = text.lines().collect();
        parse_script(&lines)
    }

    #[test]
    fn commands_and_comments() {
        let s = run("echo one\n# note\n\necho two # trailing").unwrap();
        assert_eq!(s, [Stmt::Command(String::from("echo one")), Stmt::Command(String::from("echo two"))]);
    }

    #[test]
    fn if_else_nests() {
        let s = run("if 1 == 1 {\n  echo yes\n} else {\n  echo no\n}\necho after").unwrap();
        assert_eq!(s.len(), 2);
        match &s[0] {
            Stmt::If { cond, then, alt } => {
                assert_eq!(cond, "1 == 1");
                assert_eq!(then, &[Stmt::Command(String::from("echo yes"))]);
                assert_eq!(alt, &[Stmt::Command(String::from("echo no"))]);
            }
            other => panic!("not an if: {other:?}"),
        }
        assert_eq!(s[1], Stmt::Command(String::from("echo after")));
    }

    #[test]
    fn for_loop_body_and_nesting() {
        let s = run("for x in a b c {\n if 1 {\n  echo $x\n }\n}").unwrap();
        match &s[0] {
            Stmt::For { name, words, body } => {
                assert_eq!(name, "x");
                assert_eq!(words, "a b c");
                assert_eq!(body.len(), 1);
                assert!(matches!(body[0], Stmt::If { .. }));
            }
            other => panic!("not a for: {other:?}"),
        }
    }

    #[test]
    fn depth_guides_line_collection() {
        assert_eq!(depth(&["if 1 {"]).unwrap(), 1);
        assert_eq!(depth(&["if 1 {", "for x in a {", "}", "}"]).unwrap(), 0);
        assert_eq!(depth(&["}"]).unwrap(), -1);
        assert_eq!(depth(&["echo '{'"]).unwrap(), 0);
        assert_eq!(depth(&["# { {"]).unwrap(), 0);
        assert_eq!(depth(&["echo \"{#\""]).unwrap(), 0);
    }

    #[test]
    fn malformed_blocks_are_rejected() {
        assert!(run("if 1 {\n echo x").is_err());
        assert!(run("echo x\n}").is_err());
        assert!(run("while 1 {\n}").is_err());
        assert!(run("if {\n}").is_err());
        assert!(run("for x a b {\n}").is_err());
        assert!(run("for 1 in a {\n}").is_err());
        assert!(run("if 1 {\n} else {\n echo x").is_err());
    }
}
