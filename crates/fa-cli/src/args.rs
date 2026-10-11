//! A small argument parser with the agent-ergonomics rules baked in: every
//! unknown verb or flag is answered with the nearest known one (edit
//! distance ≤ 2), `--flag=value` and `--flag value` both work, and `--json`
//! may appear anywhere. The known flags come from the verb registry
//! (`registries/verbs.toml`): `value_flags` take a value, `switches` do not.

use std::collections::BTreeMap;

#[derive(Clone, Debug, Default)]
pub struct Args {
    pub positional: Vec<String>,
    pub flags: BTreeMap<String, Vec<String>>,
    pub switches: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UsageError {
    pub message: String,
    pub fix: String,
}

pub fn parse(argv: &[String], value_flags: &[&str], switches: &[&str]) -> Result<Args, UsageError> {
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
            if value_flags.contains(&name.as_str()) {
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
            } else if switches.contains(&name.as_str()) {
                if inline.is_some() {
                    return Err(UsageError {
                        message: format!("{name} takes no value"),
                        fix: name.clone(),
                    });
                }
                args.switches.push(name);
            } else {
                let known: Vec<&str> = value_flags.iter().chain(switches).copied().collect();
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

/// The nearest candidate within the registry's correction distance
/// (verbs.toml `[global] correction_distance`), shortest first on a tie.
/// An unreadable registry corrects nothing.
pub fn nearest<'a>(word: &str, candidates: &[&'a str]) -> Option<&'a str> {
    let within = crate::verbs::registry().ok()?.global.correction_distance;
    nearest_within(word, candidates, within)
}

/// The nearest candidate at most `within` edits from `word`.
pub fn nearest_within<'a>(word: &str, candidates: &[&'a str], within: usize) -> Option<&'a str> {
    candidates
        .iter()
        .copied()
        .map(|c| (edit_distance(word, c), c))
        .filter(|(d, _)| *d <= within)
        .min_by_key(|(d, c)| (*d, c.len()))
        .map(|(_, c)| c)
}

/// Levenshtein distance with an adjacent transposition counted as one edit
/// (the optimal-string-alignment form of Damerau–Levenshtein), so `--jsno`
/// is one edit from `--json`, as plan Appendix D's own example has it.
pub fn edit_distance(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    // d[i][j]: the distance between a[..i] and b[..j].
    let mut d = vec![vec![0usize; b.len() + 1]; a.len() + 1];
    for (i, row) in d.iter_mut().enumerate() {
        row[0] = i;
    }
    for (j, cell) in d[0].iter_mut().enumerate() {
        *cell = j;
    }
    for i in 1..=a.len() {
        for j in 1..=b.len() {
            let cost = usize::from(a[i - 1] != b[j - 1]);
            let mut best = (d[i - 1][j] + 1)
                .min(d[i][j - 1] + 1)
                .min(d[i - 1][j - 1] + cost);
            if i > 1 && j > 1 && a[i - 1] == b[j - 2] && a[i - 2] == b[j - 1] {
                best = best.min(d[i - 2][j - 2] + 1);
            }
            d[i][j] = best;
        }
    }
    d[a.len()][b.len()]
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALUE: &[&str] = &["--intent", "--grant", "--book", "--period"];
    const SWITCH: &[&str] = &["--json", "--yes"];

    fn argv(s: &str) -> Vec<String> {
        s.split_whitespace().map(String::from).collect()
    }

    #[test]
    fn parses_flags_switches_and_positionals() {
        let a = parse(
            &argv("post --intent x.json --json --grant post_closed --grant close --book=/tmp/b"),
            VALUE,
            SWITCH,
        )
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
        let e = parse(&argv("tb --jsno"), VALUE, SWITCH).unwrap_err();
        assert!(e.fix.contains("--json"), "{e:?}");
        let e = parse(&argv("tb --period"), VALUE, SWITCH).unwrap_err();
        assert!(e.message.contains("--period needs a value"));
        assert_eq!(
            nearest("perod", &["period", "post", "book"]),
            Some("period")
        );
        assert_eq!(nearest("zzzzzz", &["period"]), None);
        assert_eq!(edit_distance("kitten", "sitting"), 3);
    }

    /// The registry's correction distance is 1: one insertion, deletion,
    /// substitution or adjacent transposition is corrected; two edits are
    /// not (the boundary), whatever the candidate.
    #[test]
    fn correction_spans_exactly_the_registry_distance() {
        let registry = crate::verbs::registry().expect("verbs.toml");
        assert_eq!(registry.global.correction_distance, 1);
        for (typo, meant) in [
            ("pst", "post"),
            ("posts", "post"),
            ("psot", "post"),
            ("pist", "post"),
            ("--jsno", "--json"),
        ] {
            assert_eq!(edit_distance(typo, meant), 1, "{typo}");
            assert_eq!(nearest(typo, &[meant, "tb"]), Some(meant), "{typo}");
        }
        for typo in ["pzzt", "ps", "opsst", "--jxno"] {
            assert_eq!(
                edit_distance(typo, "post").min(edit_distance(typo, "--json")),
                2,
                "{typo}"
            );
            assert_eq!(nearest(typo, &["post", "--json"]), None, "{typo}");
        }
        // The same words within a wider distance would be corrected: the
        // boundary is the registry's, not the candidates'.
        assert_eq!(nearest_within("pzzt", &["post"], 2), Some("post"));
    }
}
