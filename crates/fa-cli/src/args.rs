//! A small argument parser with the agent-ergonomics rules baked in: every
//! unknown verb or flag is answered with the nearest known one (edit
//! distance ≤ 2), `--flag=value` and `--flag value` both work, and `--json`
//! may appear anywhere.

use std::collections::BTreeMap;

#[derive(Clone, Debug, Default)]
pub struct Args {
    pub positional: Vec<String>,
    pub flags: BTreeMap<String, Vec<String>>,
    pub switches: Vec<String>,
}

/// Flags that take a value; everything else starting with `--` is a switch.
pub const VALUE_FLAGS: &[&str] = &[
    "--book",
    "--keys",
    "--name",
    "--base-unit",
    "--calendar",
    "--year-start-month",
    "--adjustment-periods",
    "--fiscal-year",
    "--period",
    "--intent",
    "--as",
    "--grant",
    "--reason",
    "--key",
    "--to",
    "--date",
];
pub const SWITCHES: &[&str] = &["--json", "--yes", "--help", "--version", "--no-color"];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UsageError {
    pub message: String,
    pub fix: String,
}

pub fn parse(argv: &[String]) -> Result<Args, UsageError> {
    let mut args = Args::default();
    let mut i = 0;
    while i < argv.len() {
        let a = &argv[i];
        if a == "--" {
            args.positional.extend(argv[i + 1..].iter().cloned());
            break;
        }
        if let Some(body) = a.strip_prefix("--") {
            let (name, inline) = match body.split_once('=') {
                Some((n, v)) => (format!("--{n}"), Some(v.to_string())),
                None => (a.clone(), None),
            };
            if VALUE_FLAGS.contains(&name.as_str()) {
                let value = match inline {
                    Some(v) => v,
                    None => {
                        i += 1;
                        argv.get(i).cloned().ok_or_else(|| UsageError {
                            message: format!("{name} needs a value"),
                            fix: format!("{name} <value>"),
                        })?
                    }
                };
                args.flags.entry(name).or_default().push(value);
            } else if SWITCHES.contains(&name.as_str()) {
                if inline.is_some() {
                    return Err(UsageError {
                        message: format!("{name} takes no value"),
                        fix: name.clone(),
                    });
                }
                args.switches.push(name);
            } else {
                let known: Vec<&str> = VALUE_FLAGS.iter().chain(SWITCHES.iter()).copied().collect();
                let fix = match nearest(&name, &known) {
                    Some(n) => format!("did you mean {n}?"),
                    None => "run `fa --help` for the flag list".to_string(),
                };
                return Err(UsageError {
                    message: format!("unknown flag {name}"),
                    fix,
                });
            }
        } else {
            args.positional.push(a.clone());
        }
        i += 1;
    }
    Ok(args)
}

impl Args {
    pub fn flag(&self, name: &str) -> Option<&str> {
        self.flags
            .get(name)
            .and_then(|v| v.last())
            .map(String::as_str)
    }

    pub fn flag_all(&self, name: &str) -> Vec<&str> {
        self.flags
            .get(name)
            .map(|v| v.iter().map(String::as_str).collect())
            .unwrap_or_default()
    }

    pub fn switch(&self, name: &str) -> bool {
        self.switches.iter().any(|s| s == name)
    }

    pub fn require(&self, name: &str, example: &str) -> Result<&str, UsageError> {
        self.flag(name).ok_or_else(|| UsageError {
            message: format!("{name} is required"),
            fix: format!("{name} {example}"),
        })
    }
}

/// Edit distance ≤ 2 nearest candidate, if any.
pub fn nearest<'a>(word: &str, candidates: &[&'a str]) -> Option<&'a str> {
    candidates
        .iter()
        .copied()
        .map(|c| (levenshtein(word, c), c))
        .filter(|(d, _)| *d <= 2)
        .min_by_key(|(d, c)| (*d, c.len()))
        .map(|(_, c)| c)
}

pub fn levenshtein(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    for (i, ca) in a.iter().enumerate() {
        let mut cur = vec![i + 1];
        for (j, cb) in b.iter().enumerate() {
            let cost = usize::from(ca != cb);
            cur.push((prev[j] + cost).min(prev[j + 1] + 1).min(cur[j] + 1));
        }
        prev = cur;
    }
    prev[b.len()]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(s: &str) -> Vec<String> {
        s.split_whitespace().map(String::from).collect()
    }

    #[test]
    fn parses_flags_switches_and_positionals() {
        let a = parse(&argv(
            "post --intent x.json --json --grant post_closed --grant close --book=/tmp/b",
        ))
        .unwrap();
        assert_eq!(a.positional, vec!["post"]);
        assert_eq!(a.flag("--intent"), Some("x.json"));
        assert_eq!(a.flag("--book"), Some("/tmp/b"));
        assert_eq!(a.flag_all("--grant"), vec!["post_closed", "close"]);
        assert!(a.switch("--json"));
        assert!(!a.switch("--yes"));
    }

    #[test]
    fn typos_get_a_suggestion_and_missing_values_are_named() {
        let e = parse(&argv("tb --jsno")).unwrap_err();
        assert!(e.fix.contains("--json"), "{e:?}");
        let e = parse(&argv("tb --period")).unwrap_err();
        assert!(e.message.contains("--period needs a value"));
        assert_eq!(
            nearest("perod", &["period", "post", "book"]),
            Some("period")
        );
        assert_eq!(nearest("zzzzzz", &["period"]), None);
        assert_eq!(levenshtein("kitten", "sitting"), 3);
    }
}
