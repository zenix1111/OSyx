//! Command-line parsing for AXIS, the OSyx shell.
//!
//! Splits a line into pipeline [`Stage`]s and finds the redirections of each
//! stage. Quoting, `$` expansion and word splitting stay with the shell: the
//! pieces returned here keep quotes and `$` in place, so the shell applies
//! the same rules to commands and redirection targets. Host-tested.

#![no_std]

extern crate alloc;

pub mod block;

use alloc::string::String;
use alloc::vec::Vec;

/// One command of a pipeline.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Stage {
    /// The command with quoting and `$` left in place.
    pub command: String,
    /// The `<` target with quoting and `$` left in place.
    pub stdin: Option<String>,
    /// The `>` or `>>` target.
    pub stdout: Option<Redirect>,
}

/// A target of `>` (`append` false) or `>>` (`append` true).
#[derive(Debug, PartialEq, Eq)]
pub struct Redirect {
    pub path: String,
    pub append: bool,
}

/// Splits `line` into pipeline stages. An empty or whitespace-only line has
/// no stages.
///
/// `|`, `<` and `>` separate words outside quotes; an operator may touch its
/// neighbour (`a|b`, `ls>out`). Quoted operators are ordinary characters.
pub fn parse(line: &str) -> Result<Vec<Stage>, String> {
    let mut stages = Vec::new();
    let mut words: Vec<String> = Vec::new();
    let mut stdin = None;
    let mut stdout = None;
    let tokens = tokens(line)?;
    if tokens.is_empty() {
        return Ok(stages);
    }
    let mut toks = tokens.into_iter();
    while let Some(tok) = toks.next() {
        match tok {
            Tok::Word(w) => words.push(w),
            Tok::Pipe => stages.push(stage(&mut words, &mut stdin, &mut stdout)?),
            Tok::In => {
                let target = target(&mut toks, "<")?;
                if stdin.replace(target).is_some() {
                    return Err(String::from("standard input redirected twice"));
                }
            }
            Tok::Out { append } => {
                let target = target(&mut toks, if append { ">>" } else { ">" })?;
                if stdout.replace(Redirect { path: target, append }).is_some() {
                    return Err(String::from("standard output redirected twice"));
                }
            }
        }
    }
    stages.push(stage(&mut words, &mut stdin, &mut stdout)?);
    Ok(stages)
}

fn stage(words: &mut Vec<String>, stdin: &mut Option<String>, stdout: &mut Option<Redirect>) -> Result<Stage, String> {
    if words.is_empty() {
        return Err(String::from("missing command"));
    }
    Ok(Stage { command: words.drain(..).collect::<Vec<_>>().join(" "), stdin: stdin.take(), stdout: stdout.take() })
}

fn target(toks: &mut alloc::vec::IntoIter<Tok>, op: &str) -> Result<String, String> {
    match toks.next() {
        Some(Tok::Word(w)) => Ok(w),
        _ => Err(alloc::format!("`{op}` needs a file name")),
    }
}

enum Tok {
    Word(String),
    Pipe,
    In,
    Out { append: bool },
}

fn tokens(line: &str) -> Result<Vec<Tok>, String> {
    let mut out = Vec::new();
    let mut chars = line.chars().peekable();
    loop {
        while chars.peek().is_some_and(|c| c.is_whitespace()) {
            chars.next();
        }
        let Some(&c) = chars.peek() else { break };
        match c {
            '|' => {
                chars.next();
                out.push(Tok::Pipe);
            }
            '<' => {
                chars.next();
                out.push(Tok::In);
            }
            '>' => {
                chars.next();
                let append = chars.peek() == Some(&'>');
                if append {
                    chars.next();
                }
                out.push(Tok::Out { append });
            }
            _ => out.push(Tok::Word(word(&mut chars)?)),
        }
    }
    Ok(out)
}

/// One word up to an unquoted whitespace or operator, quotes included.
fn word(chars: &mut core::iter::Peekable<core::str::Chars>) -> Result<String, String> {
    let mut w = String::new();
    while let Some(&c) = chars.peek() {
        if c.is_whitespace() || matches!(c, '|' | '<' | '>') {
            break;
        }
        chars.next();
        w.push(c);
        if c == '"' || c == '\'' {
            loop {
                let Some(q) = chars.next() else {
                    return Err(String::from("unterminated quote"));
                };
                w.push(q);
                if q == c {
                    break;
                }
            }
        }
    }
    Ok(w)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn one(line: &str) -> Stage {
        let stages = parse(line).unwrap();
        assert_eq!(stages.len(), 1);
        stages.into_iter().next().unwrap()
    }

    #[test]
    fn plain_commands_have_no_redirections() {
        let s = one("ls -l /osyx-seed");
        assert_eq!(s.command, "ls -l /osyx-seed");
        assert_eq!(s.stdin, None);
        assert_eq!(s.stdout, None);
    }

    #[test]
    fn empty_lines_have_no_stages() {
        assert!(parse("").unwrap().is_empty());
        assert!(parse("   ").unwrap().is_empty());
    }

    #[test]
    fn pipes_split_stages() {
        let stages = parse("ls | cat | cat").unwrap();
        let commands: Vec<&str> = stages.iter().map(|s| s.command.as_str()).collect();
        assert_eq!(commands, ["ls", "cat", "cat"]);
    }

    #[test]
    fn operators_need_no_spaces() {
        let stages = parse("cat</osyx-seed/a|cat>/tmp/out").unwrap();
        assert_eq!(stages.len(), 2);
        assert_eq!(stages[0].command, "cat");
        assert_eq!(stages[0].stdin.as_deref(), Some("/osyx-seed/a"));
        assert_eq!(stages[1].command, "cat");
        assert_eq!(stages[1].stdout, Some(Redirect { path: String::from("/tmp/out"), append: false }));
    }

    #[test]
    fn append_and_quoted_targets() {
        let s = one("cat a >> \"my file\"");
        assert_eq!(s.command, "cat a");
        assert_eq!(s.stdout, Some(Redirect { path: String::from("\"my file\""), append: true }));
    }

    #[test]
    fn quoted_operators_are_text() {
        let s = one("echo 'a | b > c'");
        assert_eq!(s.command, "echo 'a | b > c'");
        assert_eq!(s.stdout, None);
    }

    #[test]
    fn variables_reach_the_shell_unexpanded() {
        let s = one("cat $file > $out");
        assert_eq!(s.command, "cat $file");
        assert_eq!(s.stdout, Some(Redirect { path: String::from("$out"), append: false }));
    }

    #[test]
    fn malformed_lines_are_rejected() {
        assert!(parse("cat a |").is_err());
        assert!(parse("| cat").is_err());
        assert!(parse("cat >").is_err());
        assert!(parse("cat > a > b").is_err());
        assert!(parse("cat < a < b").is_err());
        assert!(parse("echo \"open").is_err());
        assert!(parse("> out").is_err());
    }
}
