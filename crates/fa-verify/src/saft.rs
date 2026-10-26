//! `fa-verify saft`: an OECD SAF-T 2.00 general-ledger extract (`fa export
//! saft --with-proofs`) checked offline against the complete-prefix bundle
//! produced with it (plan §13.1, §16.3; bead fa-2q91).
//!
//! The SAF-T file states the coordinate the ADS certificate states
//! (`SelectionEndDate`, `KnownAtSeq`, `NumberOfEntries`), its transactions
//! (one per proven entry, lines in leg order), its balance assertions (the
//! refold of those lines) and its chart (`GeneralLedgerAccounts`). They are
//! read here by an independent reader of exactly the profile `fa export saft`
//! writes, never by fa-formats, and judged by the law `fa-verify ads`
//! applies ([`crate::ads`]): the transactions are exactly the proven entries
//! the export selects, the assertions exactly their refold, and the chart
//! exactly the one the proven entries declare. Descriptions and memos are not
//! judged, as in ADS. Anything outside the profile (an unknown element, an
//! entity other than the five XML ones, a comment, mixed content) is refused,
//! never skipped.

use crate::ads::{self, AdsReport, Extracted, Parts, Row, Stated, StatedAccount, StatedBalance};
use crate::bundle::BundleError;

/// The XML declaration `fa export saft` writes.
const DECLARATION: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>";
/// The SAF-T 2.00 namespace of the root `AuditFile`.
pub const NAMESPACE: &str = "urn:OECD:StandardAuditFile-Taxation/2.00";
/// The profile nests five levels; anything deeper is not it.
const MAX_DEPTH: usize = 8;

const PARTS: Parts = Parts {
    format: "SAF-T",
    coordinate: "the SAF-T header",
    entries: "GeneralLedgerEntries",
    entry: "SAF-T transaction",
    balances: "BalanceAssertions",
    chart: "GeneralLedgerAccounts",
};

/// One element: its name, attributes, child elements and text.
#[derive(Debug, PartialEq, Eq)]
struct Node {
    name: String,
    attributes: Vec<(String, String)>,
    children: Vec<Node>,
    text: String,
}

impl Node {
    /// The one child named `name`.
    fn child(&self, name: &str) -> Result<&Node, String> {
        let mut found = self.children.iter().filter(|c| c.name == name);
        match (found.next(), found.next()) {
            (Some(one), None) => Ok(one),
            (None, _) => Err(format!("<{}> has no <{name}>", self.name)),
            (Some(_), Some(_)) => Err(format!("<{}> has more than one <{name}>", self.name)),
        }
    }

    /// The child named `name`, if any (never two).
    fn optional(&self, name: &str) -> Result<Option<&Node>, String> {
        match self.children.iter().filter(|c| c.name == name).count() {
            0 => Ok(None),
            1 => self.child(name).map(Some),
            _ => Err(format!("<{}> has more than one <{name}>", self.name)),
        }
    }

    fn all<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a Node> + 'a {
        self.children.iter().filter(move |c| c.name == name)
    }

    /// The text of the one child named `name`, which holds no elements.
    fn text_of(&self, name: &str) -> Result<&str, String> {
        leaf(self.child(name)?)
    }

    /// Refuse any child the profile does not name here.
    fn only(&self, allowed: &[&str]) -> Result<&Self, String> {
        match self
            .children
            .iter()
            .find(|c| !allowed.contains(&c.name.as_str()))
        {
            Some(c) => Err(format!(
                "<{}> holds <{}>, which the SAF-T profile does not",
                self.name, c.name
            )),
            None => Ok(self),
        }
    }
}

fn leaf(node: &Node) -> Result<&str, String> {
    if node.children.is_empty() {
        Ok(&node.text)
    } else {
        Err(format!("<{}> holds elements, not text", node.name))
    }
}

/// The five XML entities, and nothing else.
fn unescape(s: &str) -> Result<String, String> {
    const ENTITIES: [(&str, char); 5] = [
        ("&amp;", '&'),
        ("&lt;", '<'),
        ("&gt;", '>'),
        ("&quot;", '"'),
        ("&apos;", '\''),
    ];
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(i) = rest.find('&') {
        out.push_str(&rest[..i]);
        rest = &rest[i..];
        let (entity, c) = ENTITIES
            .iter()
            .find(|(entity, _)| rest.starts_with(entity))
            .ok_or("an XML entity outside the SAF-T profile")?;
        out.push(*c);
        rest = &rest[entity.len()..];
    }
    out.push_str(rest);
    Ok(out)
}

struct Parser<'a> {
    s: &'a str,
    i: usize,
}

impl Parser<'_> {
    fn rest(&self) -> &str {
        &self.s[self.i..]
    }

    fn skip_ws(&mut self) {
        let n = self
            .rest()
            .bytes()
            .take_while(u8::is_ascii_whitespace)
            .count();
        self.i += n;
    }

    fn eat(&mut self, literal: &str) -> bool {
        let found = self.rest().starts_with(literal);
        if found {
            self.i += literal.len();
        }
        found
    }

    fn name(&mut self) -> Result<String, String> {
        let n = self
            .rest()
            .bytes()
            .take_while(|b| b.is_ascii_alphanumeric() || matches!(*b, b'_' | b'-'))
            .count();
        if n == 0 {
            return Err("an element or attribute name outside the SAF-T profile".into());
        }
        let name = self.rest()[..n].to_string();
        self.i += n;
        Ok(name)
    }

    fn element(&mut self, depth: usize) -> Result<Node, String> {
        if depth > MAX_DEPTH {
            return Err("SAF-T elements nest deeper than the profile".into());
        }
        if !self.eat("<") {
            return Err("expected an element".into());
        }
        let name = self.name()?;
        let mut attributes = Vec::new();
        loop {
            self.skip_ws();
            if self.eat(">") {
                break;
            }
            let key = self.name()?;
            if !self.eat("=\"") {
                return Err(format!("<{name}>: attribute {key} is not `=\"…\"`"));
            }
            let end = self
                .rest()
                .find('"')
                .ok_or_else(|| format!("<{name}>: attribute {key} is not closed"))?;
            let value = unescape(&self.rest()[..end])?;
            self.i += end + 1;
            attributes.push((key, value));
        }
        let mut children = Vec::new();
        let mut text = String::new();
        loop {
            if self.eat("</") {
                let close = self.name()?;
                if close != name || !self.eat(">") {
                    return Err(format!("<{name}> is closed by </{close}>"));
                }
                break;
            }
            if self.rest().starts_with('<') {
                children.push(self.element(depth + 1)?);
                continue;
            }
            let end = self
                .rest()
                .find('<')
                .ok_or_else(|| format!("<{name}> is not closed"))?;
            text.push_str(&self.rest()[..end]);
            self.i += end;
        }
        if children.is_empty() {
            text = unescape(&text)?;
        } else if text.bytes().all(|b| b.is_ascii_whitespace()) {
            text.clear();
        } else {
            return Err(format!("<{name}> mixes text and elements"));
        }
        Ok(Node {
            name,
            attributes,
            children,
            text,
        })
    }
}

/// The `AuditFile` of exactly the profile `fa export saft` writes.
fn read(xml: &str) -> Result<Node, String> {
    let body = xml
        .strip_prefix(DECLARATION)
        .ok_or("the file does not start with the SAF-T XML declaration")?;
    let mut p = Parser { s: body, i: 0 };
    p.skip_ws();
    let root = p.element(0)?;
    p.skip_ws();
    if p.i != body.len() {
        return Err("content follows </AuditFile>".into());
    }
    if root.name != "AuditFile" || root.attributes != [("xmlns".to_string(), NAMESPACE.to_string())]
    {
        return Err(format!(
            "the root is not a SAF-T 2.00 AuditFile in {NAMESPACE}"
        ));
    }
    root.only(&["Header", "MasterFiles", "GeneralLedgerEntries"])?;
    Ok(root)
}

/// An unsigned decimal: digits only.
fn number<T: std::str::FromStr>(node: &Node, name: &str) -> Result<T, String> {
    let text = node.text_of(name)?;
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return Err(format!("<{name}> `{text}` is not an unsigned decimal"));
    }
    text.parse()
        .map_err(|_| format!("<{name}> `{text}` is out of range"))
}

fn side(node: &Node, name: &str) -> Result<&'static str, String> {
    match node.text_of(name)? {
        "Debit" => Ok("D"),
        "Credit" => Ok("C"),
        other => Err(format!("<{name}> `{other}` is neither Debit nor Credit")),
    }
}

fn transactions(entries: &Node) -> Result<Vec<Extracted>, String> {
    entries
        .all("Transaction")
        .map(|t| {
            t.only(&[
                "TransactionID",
                "TransactionDate",
                "RecordedSeq",
                "EntryClass",
                "Description",
                "MigratedFrom",
                "Line",
            ])?;
            let id = t.text_of("TransactionID")?.to_string();
            let date = t.text_of("TransactionDate")?.to_string();
            let seq: u64 = number(t, "RecordedSeq")?;
            let class: u16 = number(t, "EntryClass")?;
            let mut rows = Vec::new();
            for (i, line) in t.all("Line").enumerate() {
                line.only(&[
                    "RecordID",
                    "AccountID",
                    "DebitAmount",
                    "CreditAmount",
                    "CurrencyCode",
                    "Memo",
                ])?;
                let record: u32 = number(line, "RecordID")?;
                if usize::try_from(record).ok() != i.checked_add(1) {
                    return Err(format!(
                        "SAF-T transaction {id}: its lines are not numbered 1.. in order"
                    ));
                }
                let (debit, amount) = match (
                    line.optional("DebitAmount")?,
                    line.optional("CreditAmount")?,
                ) {
                    (Some(d), None) => (true, leaf(d)?),
                    (None, Some(c)) => (false, leaf(c)?),
                    _ => {
                        return Err(format!(
                            "SAF-T transaction {id} line {record} states not exactly one of DebitAmount and CreditAmount"
                        ));
                    }
                };
                let scale = amount
                    .split_once('.')
                    .map_or(0, |(_, fraction)| u32::try_from(fraction.len()).unwrap_or(u32::MAX));
                let mantissa = ads::exact(amount, scale).ok_or_else(|| {
                    format!("SAF-T transaction {id} line {record}: `{amount}` is not an exact amount")
                })?;
                rows.push(Row {
                    journal_id: id.clone(),
                    line: record,
                    date: date.clone(),
                    seq,
                    class,
                    account: line.text_of("AccountID")?.to_string(),
                    debit,
                    mantissa,
                    unit: line.text_of("CurrencyCode")?.to_string(),
                    scale,
                });
            }
            Ok(Extracted {
                journal_id: id,
                seq,
                date,
                class,
                rows,
            })
        })
        .collect()
}

fn assertions(balances: &Node) -> Result<Vec<StatedBalance>, String> {
    balances.only(&["Assertion"])?;
    balances
        .all("Assertion")
        .map(|a| {
            a.only(&["AccountID", "AsOfDate", "Side", "Amount", "CurrencyCode"])?;
            let (account, as_of, side, amount, unit) = (
                a.text_of("AccountID")?,
                a.text_of("AsOfDate")?,
                side(a, "Side")?,
                a.text_of("Amount")?,
                a.text_of("CurrencyCode")?,
            );
            Ok(StatedBalance {
                line: format!("{account}|{as_of}|{side}|{amount}|{unit}"),
                account: account.to_string(),
                as_of: as_of.to_string(),
                side: side.to_string(),
                amount: amount.to_string(),
                unit: unit.to_string(),
                scale: None,
            })
        })
        .collect()
}

fn accounts(chart: &Node) -> Result<Vec<StatedAccount>, String> {
    chart.only(&["Account"])?;
    chart
        .all("Account")
        .map(|a| {
            a.only(&[
                "AccountID",
                "AccountDescription",
                "AccountType",
                "NormalSide",
            ])?;
            let (code, name, account_type, normal) = (
                a.text_of("AccountID")?,
                a.text_of("AccountDescription")?,
                a.text_of("AccountType")?,
                side(a, "NormalSide")?,
            );
            Ok(StatedAccount {
                line: format!("{code}|{name}|{account_type}|{normal}"),
                code: code.to_string(),
                name: name.to_string(),
                account_type: account_type.to_string(),
                side: normal.to_string(),
            })
        })
        .collect()
}

/// What the file states, from its header, entries and master files.
fn stated(doc: &Node) -> Result<Stated, String> {
    let header = doc.child("Header")?.only(&[
        "AuditFileVersion",
        "CompanyName",
        "DefaultCurrencyCode",
        "DefaultCurrencyScale",
        "SelectionEndDate",
        "KnownAtSeq",
        "ContentDigest",
        "CertificateDigest",
    ])?;
    if header.text_of("AuditFileVersion")? != "2.00" {
        return Err("the SAF-T header's AuditFileVersion is not 2.00".into());
    }
    let entries = doc
        .child("GeneralLedgerEntries")?
        .only(&["NumberOfEntries", "Transaction"])?;
    let masters = doc
        .child("MasterFiles")?
        .only(&["GeneralLedgerAccounts", "BalanceAssertions"])?;
    Ok(Stated {
        effective_through: header.text_of("SelectionEndDate")?.to_string(),
        known_at_seq: number(header, "KnownAtSeq").ok(),
        entry_count: number(entries, "NumberOfEntries").ok(),
        account_scope: None,
        entries: transactions(entries),
        balances: masters.child("BalanceAssertions").and_then(assertions),
        chart: masters.child("GeneralLedgerAccounts").and_then(accounts),
    })
}

/// Verify the bundle, then the SAF-T file against the entries it proves.
/// The bundle's own failure is reported, never masked; the file is judged
/// only against a verified complete-prefix bundle.
pub fn verify_saft(
    xml: &str,
    bundle: &[u8],
    trusted_keys: &[[u8; 32]],
    receipt: Option<&[u8]>,
) -> Result<AdsReport, BundleError> {
    let (report, records) = ads::prove(bundle, trusted_keys, receipt)?;
    let doc = read(xml);
    let header = doc.as_ref().ok().and_then(|d| d.child("Header").ok());
    let header_text = |name: &str| {
        header
            .and_then(|h| h.text_of(name).ok())
            .unwrap_or_default()
            .to_string()
    };
    let mut out = AdsReport::new(
        report,
        header_text("SelectionEndDate"),
        header.and_then(|h| number(h, "KnownAtSeq").ok()),
    );
    if !out.bundle.verified() {
        out.failures
            .push("the bundle did not verify, so the SAF-T file was not judged against it".into());
        return Ok(out);
    }
    match doc.and_then(|doc| stated(&doc)) {
        Ok(stated) => Ok(ads::judge(out, records, stated, &PARTS)),
        Err(why) => {
            out.failures.push(why);
            Ok(out)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LINE: &str = "<Line><RecordID>1</RecordID><AccountID>1000</AccountID><DebitAmount>12.34</DebitAmount><CurrencyCode>USD</CurrencyCode></Line>";

    fn file(lines: &str) -> String {
        format!(
            "{DECLARATION}\n<AuditFile xmlns=\"{NAMESPACE}\">\n  <Header>\n    <AuditFileVersion>2.00</AuditFileVersion>\n    <SelectionEndDate>2026-03-31</SelectionEndDate>\n    <KnownAtSeq>9</KnownAtSeq>\n  </Header>\n  <MasterFiles>\n    <GeneralLedgerAccounts>\n      <Account><AccountID>1000</AccountID><AccountDescription>Cash &amp; equivalents</AccountDescription><AccountType>Asset</AccountType><NormalSide>Debit</NormalSide></Account>\n    </GeneralLedgerAccounts>\n    <BalanceAssertions>\n      <Assertion><AccountID>1000</AccountID><AsOfDate>2026-03-31</AsOfDate><Side>Debit</Side><Amount>12.34</Amount><CurrencyCode>USD</CurrencyCode></Assertion>\n    </BalanceAssertions>\n  </MasterFiles>\n  <GeneralLedgerEntries>\n    <NumberOfEntries>1</NumberOfEntries>\n    <Transaction><TransactionID>t1</TransactionID><TransactionDate>2026-03-10</TransactionDate><RecordedSeq>7</RecordedSeq><EntryClass>1</EntryClass><Description>a &lt;b&gt;</Description>{lines}</Transaction>\n  </GeneralLedgerEntries>\n</AuditFile>\n"
        )
    }

    #[test]
    fn the_profile_reads_without_fa_formats() {
        let doc = read(&file(LINE)).unwrap();
        let stated = stated(&doc).unwrap();
        assert_eq!(stated.effective_through, "2026-03-31");
        assert_eq!(
            (stated.known_at_seq, stated.entry_count),
            (Some(9), Some(1))
        );
        let entries = stated.entries.unwrap();
        assert_eq!(entries.len(), 1);
        let row = &entries[0].rows[0];
        assert_eq!(
            (row.account.as_str(), row.debit, row.mantissa, row.scale),
            ("1000", true, 1234, 2)
        );
        let chart = stated.chart.unwrap();
        assert_eq!(chart[0].name, "Cash & equivalents");
        assert_eq!(chart[0].side, "D");
        let balances = stated.balances.unwrap();
        assert_eq!((balances[0].side.as_str(), balances[0].scale), ("D", None));
    }

    #[test]
    fn anything_outside_the_profile_is_refused() {
        let good = file(LINE);
        for bad in [
            good.replacen(DECLARATION, "<?xml version=\"1.1\"?>", 1),
            good.replace(NAMESPACE, "urn:other"),
            good.replace("<Memo>", "<Note>").replace(
                "<CurrencyCode>USD</CurrencyCode></Line>",
                "<CurrencyCode>USD</CurrencyCode><Note>x</Note></Line>",
            ),
            good.replace("Cash &amp; equivalents", "Cash &nbsp; equivalents"),
            good.replace("<Header>", "<Header><!-- c -->"),
            good.replace("</AuditFile>\n", "</AuditFile>\n<Extra/>"),
            good.replace("<RecordID>1</RecordID>", "<RecordID>2</RecordID>"),
            good.replace(
                "<DebitAmount>12.34</DebitAmount>",
                "<DebitAmount>12.34</DebitAmount><CreditAmount>1.00</CreditAmount>",
            ),
            good.replace("<DebitAmount>12.34", "<DebitAmount>12.3e1"),
            good.replace("<Side>Debit</Side>", "<Side>D</Side>"),
            good.replace("<KnownAtSeq>9", "<KnownAtSeq>+9"),
        ] {
            let read = read(&bad).and_then(|doc| {
                let stated = stated(&doc)?;
                stated.known_at_seq.ok_or("no KnownAtSeq")?;
                stated.entries?;
                stated.balances?;
                stated.chart?;
                Ok(())
            });
            assert!(read.is_err(), "{bad}");
        }
        let mut deep = String::from(DECLARATION);
        for _ in 0..=MAX_DEPTH + 1 {
            deep.push_str("<A>");
        }
        assert!(read(&deep).is_err(), "nesting is bounded");
    }
}
