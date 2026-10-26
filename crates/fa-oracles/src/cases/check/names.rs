//! K-NAMES (§2.8, §3.6; bead fa-yugf.9, A3c): no free-text field a case
//! renders or journals carries a token whose `fa:case-name-token:v1` hash is
//! in `roles.toml`'s deny list. Real people appear only as role labels.
//!
//! The fields read: role labels and descriptions; each variant's principal
//! labels, `[[party]]` ids, labels and relation tokens, intent memos and
//! `[[case]]` fields, and the fact ids a generated manual-assertion
//! statement carries; `case.toml`'s `[[decision]]` reasons. A failure line
//! names the field and the hash, never the matched text, so a gate log
//! cannot leak a name.

use super::super::names::denied;
use super::super::{CASE_FILE, ROLES_FILE};
use super::{CheckReport, Context};

/// One scanned field: where it is, the row, the field's name, its text.
struct Field {
    file: String,
    line: Option<usize>,
    row: String,
    name: &'static str,
    text: String,
}

/// Every scanned field. A row label that itself carries a deny-listed
/// token (a principal or party named after a person) is replaced by its
/// position, so neither a FAIL line nor the examined list prints it.
fn fields(cx: &Context<'_>, deny: &[String]) -> Vec<Field> {
    let case = cx.case;
    let mut out: Vec<Field> = Vec::new();
    let mut push = |file: &str, line, row: &str, name, text: &str| {
        let row = if denied(row, deny).is_empty() {
            row.to_string()
        } else {
            format!("{name} #{}", out.len() + 1)
        };
        out.push(Field {
            file: file.to_string(),
            line,
            row,
            name,
            text: text.to_string(),
        });
    };
    for role in &case.roles.roles {
        push(ROLES_FILE, role.line, &role.label, "label", &role.label);
        push(
            ROLES_FILE,
            role.line,
            &role.label,
            "description",
            &role.description,
        );
    }
    for d in &case.header.decisions {
        push(CASE_FILE, d.line, &d.id, "reason", &d.reason);
    }
    for book in case.books.values() {
        let file = format!("books/{}.toml", book.stem);
        for p in &book.principals {
            push(&file, p.line, &p.label, "principal", &p.label);
        }
        for p in &book.parties {
            push(&file, p.line, &p.id, "party id", &p.id);
            push(&file, p.line, &p.id, "party label", &p.label);
            for token in p.relations_raw.iter().flatten() {
                push(&file, p.line, &p.id, "party relation", token);
            }
        }
        for it in &book.intents {
            if let Some(memo) = &it.memo {
                push(&file, it.line, &it.id, "memo", memo);
            }
            // A generated assertion statement is fixed text plus the fact
            // id it describes (A7a).
            if it
                .evidence
                .as_deref()
                .is_some_and(|e| e.starts_with("manual_assertion:"))
            {
                push(&file, it.line, &it.id, "assertion statement", &it.fact);
            }
        }
        for c in &book.cases {
            let text = [
                c.id.as_str(),
                c.kind.as_str(),
                c.determined_on.as_str(),
                c.authority.as_str(),
                c.disclosure.as_str(),
                c.poster.as_str(),
            ]
            .into_iter()
            .chain(c.approvers.iter().map(String::as_str))
            .chain(c.periods.iter().map(String::as_str))
            .collect::<Vec<_>>()
            .join(" ");
            push(&file, c.line, &c.id, "case", &text);
        }
    }
    out
}

#[must_use]
pub fn check(cx: &Context<'_>) -> CheckReport {
    let deny = cx.case.roles.deny_hashes.clone().unwrap_or_default();
    let fields = fields(cx, &deny);
    let mut r = CheckReport::new("K-NAMES", fields.len());
    for f in &fields {
        r.examined(format!("{}:{}", f.row, f.name));
        for hash in denied(&f.text, &deny) {
            r.fail(
                &f.file,
                f.line,
                &f.row,
                format!("field {} holds a deny-listed token (sha256 {hash})", f.name),
            );
        }
    }
    r.finish()
}

#[cfg(test)]
mod tests {
    use super::super::super::names::deny_hash;
    use super::super::super::tests::pilot_planted;
    use super::super::Verdict;
    use super::*;

    /// The pilot's deny list with `deny_hash("testname")` added; the test
    /// never commits a real name.
    fn deny_testname() -> (&'static str, &'static str, String) {
        let old = "hashes = [\"9936228e243e1ba6060617f1fc1cdf574887f045b8b5e873e66d45a476492759\"]";
        let new = format!(
            "hashes = [\"9936228e243e1ba6060617f1fc1cdf574887f045b8b5e873e66d45a476492759\", \"{}\"]",
            deny_hash("testname")
        );
        (ROLES_FILE, old, new)
    }

    #[test]
    fn pilot_carries_no_deny_listed_token() {
        let case = pilot_planted(&[]);
        let r = check(&Context::new(&case));
        assert_eq!(r.verdict, Verdict::Pass, "{}", r.render(None));
    }

    #[test]
    fn principal_with_a_deny_listed_token_fails_k_names() {
        let (file, old, new) = deny_testname();
        let case = pilot_planted(&[
            (file, old, new.as_str()),
            (
                ROLES_FILE,
                "",
                "\n[[role]]\nlabel = \"testname-1\"\nkind = \"harness\"\ndescription = \"a planted principal\"\n",
            ),
            (
                "books/native.toml",
                "",
                "\n[[principal]]\nlabel = \"testname-1\"\nprofile = \"Human\"\ngrants = [\"read\"]\n",
            ),
        ]);
        let r = check(&Context::new(&case));
        let text = r.render(None);
        assert_eq!(r.verdict, Verdict::Fail, "{text}");
        let hash = deny_hash("testname");
        let line = case.books["native"]
            .principals
            .iter()
            .find(|p| p.label == "testname-1")
            .and_then(|p| p.line)
            .expect("the planted principal's line");
        assert!(
            text.lines().any(|l| l.starts_with(&format!(
                "FAIL K-NAMES books/native.toml:{line} principal #"
            )) && l.ends_with(&format!(
                ": field principal holds a deny-listed token (sha256 {hash})"
            ))),
            "{text}"
        );
        assert!(
            text.lines()
                .any(|l| l.starts_with("FAIL K-NAMES roles.toml:")
                    && l.ends_with(&format!(
                        ": field label holds a deny-listed token (sha256 {hash})"
                    ))),
            "{text}"
        );
        assert!(
            !text.to_lowercase().contains("testname"),
            "a name leaked:\n{text}"
        );
    }

    #[test]
    fn decision_reason_with_a_deny_listed_token_fails_k_names() {
        let (file, old, new) = deny_testname();
        let case = pilot_planted(&[
            (file, old, new.as_str()),
            (
                CASE_FILE,
                "",
                "\n[[decision]]\nid = \"D-1\"\noutcome = \"kept\"\nfacts = [\"F4\"]\nsources = [\"SRC-WC-001\"]\nreason = \"as TestName's memo describes\"\n",
            ),
        ]);
        let r = check(&Context::new(&case));
        let text = r.render(None);
        assert_eq!(r.verdict, Verdict::Fail, "{text}");
        let line = case.header.decisions[0].line.expect("the decision's line");
        let want = format!(
            "FAIL K-NAMES case.toml:{line} D-1: field reason holds a deny-listed token (sha256 {})",
            deny_hash("testname")
        );
        assert!(text.lines().any(|l| l == want), "{want}\n{text}");
        assert!(
            !text.to_lowercase().contains("testname"),
            "a name leaked:\n{text}"
        );
    }
}
