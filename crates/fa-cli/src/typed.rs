//! Typed posting verbs over `fa post` (plan §15.3, Appendix B; bead
//! fa-i7e): `fa invoice` and `fa bill` build an ordinary Original entry
//! intent from their flags and post it through the same path, so
//! `--dry-run`, `--plan-out`, `--draft` and `--evidence` behave exactly as
//! they do for `fa post`.
//!
//! There is no posting rule (Canon) yet, so nothing is inferred: the caller
//! names the control account (receivable or payable) and each line's
//! account, there is no implicit tax, and a line that asks for tax is
//! refused. A line's total is its quantity times its unit price, computed
//! exactly in the price's own decimal places; the kernel then checks that
//! amount against the unit's registered scale. The control leg names the
//! party, so the customer or vendor carries the subledger.
//!
//! `fa receipt` and `fa payment` settle them: cash against the receivable
//! (or payable) for the party, the control leg applying itself to the open
//! items `--applies` names (the kernel bounds each application by what is
//! open). The cash leg's memo is the number, which `fa bank match`
//! compares with a bank line's reference.
//!
//! A document's default key names whoever assigned its number: the book
//! numbers its invoices and payments, a vendor its bills and a customer its
//! payment references, so a bill's or receipt's key also names the party
//! (`bill:[<entity>:]<party>:<number>`), and every key names the legal
//! entity when one is given. Keys are per principal (the kernel's
//! idempotency law), so a retry by the same principal is the recorded entry.

use crate::args::Args;
use crate::cli::{Ctx, Fail, post_document, usage};
use crate::json::{Json, obj, s};

#[derive(Clone, Copy)]
enum Kind {
    Invoice,
    Bill,
}

impl Kind {
    /// A bill's number is the vendor's, unique only to that vendor; an
    /// invoice's number is the book's own.
    const fn party_numbered(self) -> bool {
        matches!(self, Self::Bill)
    }

    const fn verb(self) -> &'static str {
        match self {
            Self::Invoice => "invoice",
            Self::Bill => "bill",
        }
    }

    /// The flag naming the control account the party's balance sits in.
    const fn control_flag(self) -> &'static str {
        match self {
            Self::Invoice => "--receivable",
            Self::Bill => "--payable",
        }
    }

    /// The flag naming the default account of every line.
    const fn line_flag(self) -> &'static str {
        match self {
            Self::Invoice => "--revenue",
            Self::Bill => "--expense",
        }
    }

    /// The control leg's side; every line takes the other side.
    const fn control_side(self) -> &'static str {
        match self {
            Self::Invoice => "debit",
            Self::Bill => "credit",
        }
    }

    const fn line_side(self) -> &'static str {
        match self {
            Self::Invoice => "credit",
            Self::Bill => "debit",
        }
    }

    fn example(self) -> String {
        format!(
            "fa {} --party <code> --number <document number> --date YYYY-MM-DD {} <code> {} <code> --line 'qty=10 unit_price=\"125.00 USD\" item=SKU-9' [--line ...] [--evidence <oid>] [--dry-run] --json",
            self.verb(),
            self.control_flag(),
            self.line_flag()
        )
    }
}

pub(crate) fn invoice_cmd(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    typed(ctx, args, Kind::Invoice)
}

pub(crate) fn bill_cmd(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    typed(ctx, args, Kind::Bill)
}

pub(crate) fn receipt_cmd(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    settle(ctx, args, Settle::Receipt)
}

pub(crate) fn payment_cmd(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    settle(ctx, args, Settle::Payment)
}

#[derive(Clone, Copy)]
enum Settle {
    Receipt,
    Payment,
}

impl Settle {
    /// A receipt's reference is the customer's (its cheque or wire
    /// reference), unique only to that customer; a payment's is the
    /// book's own.
    const fn party_numbered(self) -> bool {
        matches!(self, Self::Receipt)
    }

    const fn verb(self) -> &'static str {
        match self {
            Self::Receipt => "receipt",
            Self::Payment => "payment",
        }
    }

    const fn control_flag(self) -> &'static str {
        match self {
            Self::Receipt => "--receivable",
            Self::Payment => "--payable",
        }
    }

    /// Cash comes in on a receipt (debit) and goes out on a payment.
    const fn cash_side(self) -> &'static str {
        match self {
            Self::Receipt => "debit",
            Self::Payment => "credit",
        }
    }

    const fn control_side(self) -> &'static str {
        match self {
            Self::Receipt => "credit",
            Self::Payment => "debit",
        }
    }

    fn example(self) -> String {
        format!(
            "fa {} --party <code> --number <reference> --date YYYY-MM-DD --cash <code> {} <code> --amount \"1290.00 USD\" [--applies <entry vid>[:<leg>][=<amount>]]... [--evidence <oid>] [--dry-run] --json",
            self.verb(),
            self.control_flag()
        )
    }
}

/// The party (required) and legal entity (optional) codes, each non-empty.
fn party_and_entity<'a>(args: &'a Args, example: &str) -> Result<(&'a str, Option<&'a str>), Fail> {
    let party = args.require("--party", "<party code> (fa party list)")?;
    if party.is_empty() {
        return Err(usage("--party needs a party code", example.to_string()));
    }
    let entity = args.flag("--entity");
    if entity.is_some_and(str::is_empty) {
        return Err(usage(
            "--entity needs a legal entity code",
            "fa entity list names them",
        ));
    }
    Ok((party, entity))
}

/// One leg of a typed document's intent.
fn leg_json(
    side: &str,
    account: &str,
    amount: &str,
    memo: Option<String>,
    entity: Option<&str>,
    party: Option<&str>,
    settles: Option<Json>,
) -> Json {
    let mut fields = vec![
        ("side", s(side)),
        ("account", s(account)),
        ("amount", s(amount)),
    ];
    if let Some(memo) = memo {
        fields.push(("memo", s(memo)));
    }
    if let Some(entity) = entity {
        fields.push(("entity", s(entity)));
    }
    if let Some(party) = party {
        fields.push(("party", s(party)));
    }
    if let Some(settles) = settles {
        fields.push(("settles", settles));
    }
    obj(fields)
}

/// `--applies <entry vid>[:<leg ordinal>][=<amount>]`: one open item this
/// document settles. The amount defaults to the whole document when it
/// applies to exactly one item.
fn applications(args: &Args, total: &str, example: &str) -> Result<Option<Json>, Fail> {
    let raw = args.flag_all("--applies");
    if raw.is_empty() {
        return Ok(None);
    }
    let mut items = Vec::with_capacity(raw.len());
    for one in &raw {
        let (target, amount) = match one.split_once('=') {
            Some((target, amount)) => (target, amount.to_string()),
            None if raw.len() == 1 => (*one, total.to_string()),
            None => {
                return Err(usage(
                    format!("--applies {one}: name the amount when several items are applied"),
                    example.to_string(),
                ));
            }
        };
        let amount = sum(std::slice::from_ref(&amount))
            .map_err(|e| usage(format!("--applies {one}: {e}"), example.to_string()))?;
        if is_zero(&amount) {
            return Err(usage(
                format!("--applies {one}: a zero application settles nothing"),
                example.to_string(),
            ));
        }
        let (entry, ordinal) = match target.split_once(':') {
            Some((entry, ordinal)) => (
                entry,
                ordinal.parse::<u16>().map_err(|_| {
                    usage(
                        format!("--applies {one}: the leg ordinal is a small whole number"),
                        example.to_string(),
                    )
                })?,
            ),
            None => (target, 0),
        };
        items.push(obj(vec![
            ("entry", s(entry)),
            ("ordinal", Json::Int(i128::from(ordinal))),
            ("amount", s(amount)),
        ]));
    }
    Ok(Some(Json::Arr(items)))
}

fn settle(ctx: &mut Ctx<'_>, args: &Args, kind: Settle) -> Result<(), Fail> {
    let example = kind.example();
    if args.positional.len() != 1 {
        return Err(usage(
            format!("{} takes no positional argument", kind.verb()),
            example,
        ));
    }
    for flag in [
        "--party",
        "--number",
        "--date",
        "--key",
        "--description",
        "--entity",
        "--cash",
        "--amount",
        kind.control_flag(),
    ] {
        if args.flag_all(flag).len() > 1 {
            return Err(usage(
                format!("{} takes only one {flag}", kind.verb()),
                example,
            ));
        }
    }
    let (party, entity) = party_and_entity(args, &example)?;
    let date = args.require("--date", "YYYY-MM-DD")?;
    fa_time::DateDay::parse(date)
        .map_err(|e| usage(format!("--date: {e}"), "--date YYYY-MM-DD"))?;
    let cash = args.require("--cash", "<cash account code>")?;
    let control = args.require(kind.control_flag(), "<account code>")?;
    let amount = args.require("--amount", "\"<amount> <UNIT>\"")?;
    let amount =
        sum(&[amount.to_string()]).map_err(|e| usage(format!("--amount: {e}"), example.clone()))?;
    if is_zero(&amount) {
        return Err(usage(
            "--amount must be positive: a zero receipt or payment moves nothing",
            example,
        ));
    }
    let number = args.flag("--number");
    let key = match (args.flag("--key"), number) {
        (Some(key), _) => key.to_string(),
        (None, Some(number)) => default_key(
            kind.verb(),
            entity,
            kind.party_numbered().then_some(party),
            number,
        ),
        (None, None) => {
            return Err(usage(
                format!(
                    "{} needs its reference (--number) or an idempotency key (--key): a retry must find the recorded entry",
                    kind.verb()
                ),
                example,
            ));
        }
    };
    let settles = applications(args, &amount, &example)?;
    let legs = vec![
        leg_json(
            kind.cash_side(),
            cash,
            &amount,
            number.map(str::to_string),
            entity,
            None,
            None,
        ),
        leg_json(
            kind.control_side(),
            control,
            &amount,
            None,
            entity,
            Some(party),
            settles,
        ),
    ];
    let description = args.flag("--description").map_or_else(
        || match number {
            Some(number) => format!("{} {number}, {party}", capitalized(kind.verb())),
            None => format!("{} {party}", capitalized(kind.verb())),
        },
        str::to_string,
    );
    let doc = obj(vec![
        ("effective_date", s(date)),
        ("description", s(description)),
        ("idempotency_key", s(key)),
        ("legs", Json::Arr(legs)),
    ]);
    post_document(ctx, args, None, doc)
}

/// One `--line`: `key=value` words, a value double-quoted when it has
/// spaces.
fn line_words(raw: &str) -> Result<Vec<(String, String)>, String> {
    let mut words = Vec::new();
    let mut rest = raw.trim_start();
    while !rest.is_empty() {
        let (key, after) = rest
            .split_once('=')
            .ok_or_else(|| format!("`{rest}` is not key=value"))?;
        if key.is_empty() || key.contains(char::is_whitespace) {
            return Err(format!("`{key}` is not a field name"));
        }
        let (value, tail) = match after.strip_prefix('"') {
            Some(quoted) => {
                let end = quoted
                    .find('"')
                    .ok_or_else(|| format!("the value of {key} has no closing quote"))?;
                (&quoted[..end], &quoted[end + 1..])
            }
            None => after.split_at(after.find(char::is_whitespace).unwrap_or(after.len())),
        };
        if value.is_empty() {
            return Err(format!("the value of {key} is empty"));
        }
        if words.iter().any(|(k, _)| k == key) {
            return Err(format!("{key} is given twice"));
        }
        words.push((key.to_string(), value.to_string()));
        rest = tail.trim_start();
    }
    Ok(words)
}

/// An exact decimal amount as its text names it, `"<digits>[.<decimals>]
/// <UNIT>"`: no sign, exponent or float.
struct Exact<'a> {
    digits: i128,
    scale: usize,
    unit: &'a str,
}

fn exact<'a>(text: &'a str, what: &str) -> Result<Exact<'a>, String> {
    let (number, unit) = text
        .split_once(' ')
        .filter(|(_, unit)| !unit.is_empty() && !unit.contains(char::is_whitespace))
        .ok_or_else(|| format!("{what} `{text}` is not \"<amount> <UNIT>\""))?;
    let (whole, frac) = number.split_once('.').unwrap_or((number, ""));
    if (whole.is_empty() && frac.is_empty())
        || !whole.bytes().all(|b| b.is_ascii_digit())
        || !frac.bytes().all(|b| b.is_ascii_digit())
    {
        return Err(format!(
            "{what} `{number}` is not an exact non-negative decimal (no sign, exponent or float)"
        ));
    }
    let digits = format!("{whole}{frac}")
        .parse::<i128>()
        .map_err(|_| format!("{what} `{number}` is out of range"))?;
    Ok(Exact {
        digits,
        scale: frac.len(),
        unit,
    })
}

/// `digits` at `scale` decimal places, without trailing fractional zeros:
/// the kernel pads an amount to its unit's scale and refuses any digit
/// beyond it, so `8 × "0.125 USD"` is exactly `"1 USD"`, never a refusal.
fn render(digits: i128, scale: usize, unit: &str) -> String {
    let text = digits.to_string();
    if scale == 0 {
        return format!("{text} {unit}");
    }
    let padded = format!("{text:0>width$}", width = scale + 1);
    let (int, dec) = padded.split_at(padded.len() - scale);
    match dec.trim_end_matches('0') {
        "" => format!("{int} {unit}"),
        dec => format!("{int}.{dec} {unit}"),
    }
}

/// `quantity × "<decimal> <UNIT>"` exactly.
fn extend(qty: &str, price: &str) -> Result<String, String> {
    let qty: i128 = qty
        .parse()
        .ok()
        .filter(|q| *q > 0)
        .ok_or_else(|| format!("qty `{qty}` is not a positive whole number"))?;
    let price = exact(price, "unit_price")?;
    let total = price
        .digits
        .checked_mul(qty)
        .ok_or_else(|| format!("qty {qty} × the unit price is out of range"))?;
    Ok(render(total, price.scale, price.unit))
}

/// Sum `"<decimal> <UNIT>"` amounts of one unit exactly, as text. Amounts
/// may name different numbers of decimal places; they are aligned exactly.
fn sum(amounts: &[String]) -> Result<String, String> {
    let parsed = amounts
        .iter()
        .map(|a| exact(a, "amount"))
        .collect::<Result<Vec<_>, _>>()?;
    let Some(first) = parsed.first() else {
        return Err("no lines".into());
    };
    if let Some(other) = parsed.iter().find(|e| e.unit != first.unit) {
        return Err(format!(
            "lines are in {} and {}: one document is in one unit",
            first.unit, other.unit
        ));
    }
    let scale = parsed.iter().map(|e| e.scale).max().unwrap_or(0);
    let mut total: i128 = 0;
    for e in &parsed {
        let aligned = u32::try_from(scale - e.scale)
            .ok()
            .and_then(|places| 10_i128.checked_pow(places))
            .and_then(|factor| e.digits.checked_mul(factor))
            .ok_or_else(|| "the document total is out of range".to_string())?;
        total = total
            .checked_add(aligned)
            .ok_or_else(|| "the document total is out of range".to_string())?;
    }
    Ok(render(total, scale, first.unit))
}

/// Whether a normalized amount is zero: a zero leg posts nothing, and the
/// kernel refuses one (plan §4.4), so it is refused where it was typed.
fn is_zero(amount: &str) -> bool {
    exact(amount, "amount").is_ok_and(|e| e.digits == 0)
}

/// The default idempotency key of a typed document: its kind, the legal
/// entity when given, the party when the number is the party's own (a
/// vendor's bill number, a customer's payment reference, unique only to
/// that party), and the number.
fn default_key(verb: &str, entity: Option<&str>, party: Option<&str>, number: &str) -> String {
    let mut key = verb.to_string();
    for part in [entity, party, Some(number)].into_iter().flatten() {
        key.push(':');
        key.push_str(part);
    }
    key
}

fn typed(ctx: &mut Ctx<'_>, args: &Args, kind: Kind) -> Result<(), Fail> {
    let example = kind.example();
    if args.positional.len() != 1 {
        return Err(usage(
            format!("{} takes no positional argument", kind.verb()),
            example,
        ));
    }
    for flag in [
        "--party",
        "--number",
        "--date",
        "--key",
        "--description",
        "--entity",
        kind.control_flag(),
        kind.line_flag(),
    ] {
        if args.flag_all(flag).len() > 1 {
            return Err(usage(
                format!("{} takes only one {flag}", kind.verb()),
                example,
            ));
        }
    }
    let (party, entity) = party_and_entity(args, &example)?;
    let date = args.require("--date", "YYYY-MM-DD")?;
    fa_time::DateDay::parse(date)
        .map_err(|e| usage(format!("--date: {e}"), "--date YYYY-MM-DD"))?;
    let control = args.require(kind.control_flag(), "<account code>")?;
    let default_account = args.flag(kind.line_flag());
    let number = args.flag("--number");
    let key = match (args.flag("--key"), number) {
        (Some(key), _) => key.to_string(),
        (None, Some(number)) => default_key(
            kind.verb(),
            entity,
            kind.party_numbered().then_some(party),
            number,
        ),
        (None, None) => {
            return Err(usage(
                format!(
                    "{} needs its document number (--number) or an idempotency key (--key): a retry must find the recorded entry",
                    kind.verb()
                ),
                example,
            ));
        }
    };
    let raw_lines = args.flag_all("--line");
    if raw_lines.is_empty() {
        return Err(usage(
            format!("{} needs at least one --line", kind.verb()),
            example,
        ));
    }
    let mut line_legs = Vec::with_capacity(raw_lines.len());
    let mut amounts = Vec::with_capacity(raw_lines.len());
    for (i, raw) in raw_lines.iter().enumerate() {
        let what = format!("--line {}", i + 1);
        let words = line_words(raw).map_err(|e| usage(format!("{what}: {e}"), example.clone()))?;
        let field = |name: &str| {
            words
                .iter()
                .find(|(k, _)| k == name)
                .map(|(_, v)| v.as_str())
        };
        const FIELDS: [&str; 7] = [
            "qty",
            "unit_price",
            "amount",
            "account",
            "item",
            "product",
            "description",
        ];
        if field("tax").is_some() {
            return Err(usage(
                format!("{what}: tax is not computed without a tax law (bead fa-c34)"),
                "post the tax leg explicitly with fa post, or omit tax",
            ));
        }
        if let Some((name, _)) = words.iter().find(|(k, _)| !FIELDS.contains(&k.as_str())) {
            return Err(usage(
                format!("{what}: unknown field `{name}`"),
                format!("fields: {}", FIELDS.join(", ")),
            ));
        }
        let amount = match (field("amount"), field("qty"), field("unit_price")) {
            (Some(amount), None, None) => sum(&[amount.to_string()])
                .map_err(|e| usage(format!("{what}: {e}"), example.clone()))?,
            (None, Some(qty), Some(price)) => {
                extend(qty, price).map_err(|e| usage(format!("{what}: {e}"), example.clone()))?
            }
            _ => {
                return Err(usage(
                    format!("{what}: give amount, or qty with unit_price"),
                    "--line 'qty=10 unit_price=\"125.00 USD\"' or --line 'amount=\"1250.00 USD\"'",
                ));
            }
        };
        if is_zero(&amount) {
            return Err(usage(
                format!("{what}: a zero line posts nothing (every leg moves a positive amount)"),
                "drop the line, or describe it in another line's memo (description=...)",
            ));
        }
        let account = field("account").or(default_account).ok_or_else(|| {
            usage(
                format!(
                    "{what}: no account: name it on the line (account=<code>) or with {}",
                    kind.line_flag()
                ),
                example.clone(),
            )
        })?;
        let mut memo: Vec<&str> = ["item", "product", "description"]
            .into_iter()
            .filter_map(field)
            .collect();
        let pricing;
        if let (Some(qty), Some(price)) = (field("qty"), field("unit_price")) {
            pricing = format!("{qty} x {price}");
            memo.push(&pricing);
        }
        let memo = (!memo.is_empty()).then(|| memo.join(" "));
        line_legs.push(leg_json(
            kind.line_side(),
            account,
            &amount,
            memo,
            entity,
            None,
            None,
        ));
        amounts.push(amount);
    }
    let total = sum(&amounts).map_err(|e| usage(e, example.clone()))?;
    let mut legs = vec![leg_json(
        kind.control_side(),
        control,
        &total,
        None,
        entity,
        Some(party),
        None,
    )];
    legs.extend(line_legs);
    let description = args.flag("--description").map_or_else(
        || match number {
            Some(number) => format!("{} {number}, {party}", capitalized(kind.verb())),
            None => format!("{} {party}", capitalized(kind.verb())),
        },
        str::to_string,
    );
    let doc = obj(vec![
        ("effective_date", s(date)),
        ("description", s(description)),
        ("idempotency_key", s(key)),
        ("legs", Json::Arr(legs)),
    ]);
    post_document(ctx, args, None, doc)
}

fn capitalized(word: &str) -> String {
    let mut chars = word.chars();
    chars.next().map_or_else(String::new, |first| {
        first.to_uppercase().chain(chars).collect()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lines_extend_and_sum_exactly_or_refuse() {
        // Exact, with trailing fractional zeros dropped: the kernel pads an
        // amount to its unit's scale and refuses any digit beyond it.
        assert_eq!(extend("10", "125.00 USD").unwrap(), "1250 USD");
        assert_eq!(extend("3", "0.05 USD").unwrap(), "0.15 USD");
        assert_eq!(extend("7", "100 JPY").unwrap(), "700 JPY");
        assert_eq!(extend("2", "0.125 KWD").unwrap(), "0.25 KWD");
        assert_eq!(
            extend("8", "0.125 USD").unwrap(),
            "1 USD",
            "an exact product within the unit's scale is never refused"
        );
        assert_eq!(extend("3", "0.125 USD").unwrap(), "0.375 USD");
        for (qty, price) in [
            ("0", "1.00 USD"),
            ("-1", "1.00 USD"),
            ("1.5", "1.00 USD"),
            ("2", "1.5e2 USD"),
            ("2", "-1.00 USD"),
            ("2", "1.00"),
            ("2", "1.00 "),
            ("2", ". USD"),
        ] {
            assert!(extend(qty, price).is_err(), "{qty} x {price}");
        }
        assert_eq!(
            sum(&["1250.00 USD".into(), "0.15 USD".into()]).unwrap(),
            "1250.15 USD"
        );
        assert_eq!(
            sum(&["31.5 USD".into(), "2.25 USD".into()]).unwrap(),
            "33.75 USD",
            "lines with different decimal places are aligned exactly"
        );
        assert_eq!(
            sum(&["1.00 USD".into(), "1.0 USD".into()]).unwrap(),
            "2 USD"
        );
        assert!(sum(&["1.00 USD".into(), "1.00 EUR".into()]).is_err());
        assert!(sum(&[]).is_err());
        assert!(sum(&[format!("{} USD", i128::MAX), "1 USD".into()]).is_err());
        assert!(is_zero("0 USD") && is_zero("0.00 USD") && !is_zero("0.01 USD"));
        assert_eq!(
            line_words(r#"qty=10 unit_price="125.00 USD" item=SKU-9 product=Widgets"#).unwrap(),
            vec![
                ("qty".to_string(), "10".to_string()),
                ("unit_price".to_string(), "125.00 USD".to_string()),
                ("item".to_string(), "SKU-9".to_string()),
                ("product".to_string(), "Widgets".to_string()),
            ]
        );
        assert!(line_words("qty=1 qty=2").is_err());
        assert!(line_words(r#"unit_price="1.00 USD"#).is_err());
        assert!(line_words("lonely").is_err());
        assert!(line_words("account= amount=1").is_err(), "an empty value");
        assert!(line_words(r#"item="""#).is_err(), "an empty quoted value");
    }

    #[test]
    fn default_keys_scope_a_number_to_whoever_assigned_it() {
        // The book numbers its invoices and payments; a vendor numbers its
        // bills and a customer its payment references.
        assert_eq!(default_key("invoice", None, None, "10442"), "invoice:10442");
        assert_eq!(
            default_key("bill", None, Some("V-17"), "B-77"),
            "bill:V-17:B-77"
        );
        assert_ne!(
            default_key("bill", None, Some("V-17"), "B-77"),
            default_key("bill", None, Some("V-18"), "B-77"),
            "two vendors' bill B-77 are two documents"
        );
        assert_eq!(
            default_key("receipt", Some("ACME-DE"), Some("C-17"), "W-1"),
            "receipt:ACME-DE:C-17:W-1"
        );
        assert_ne!(
            default_key("invoice", Some("ACME-US"), None, "1"),
            default_key("invoice", Some("ACME-DE"), None, "1"),
            "each legal entity numbers its own invoices"
        );
        assert_ne!(
            default_key("invoice", None, None, "1"),
            default_key("payment", None, None, "1")
        );
    }
}

/// `fa accrue` and `fa defer` (plan §15.3, Appendix B `Accrue`/`Defer`:
/// effective_date, legs, auto_reverse_on?): an Adjusting entry, with its
/// scheduled reversal when `--reverse-on` (or `reverse_on` in the intent)
/// names one. Both are the same entry under the plan's two names; the verb
/// is the operator's account of why it is posted.
pub(crate) fn accrue_cmd(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    adjusting(ctx, args, "accrue")
}

pub(crate) fn defer_cmd(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    adjusting(ctx, args, "defer")
}

/// The two forms of an Adjusting posting: `--intent <file|->` (any legs;
/// `class` may be omitted and anything but Adjusting is refused), or the
/// two-leg flags `--date --debit --credit --amount`. Either way it posts
/// through `fa post`'s own path, so `--dry-run`, `--plan-out`, `--draft`,
/// `--scenario`, `--evidence` and `--reverse-on` behave exactly as there.
fn adjusting(ctx: &mut Ctx<'_>, args: &Args, verb: &str) -> Result<(), Fail> {
    let example = format!(
        "fa {verb} --date 2026-03-31 --debit 6100 --credit 2100 --amount \"1500.00 USD\" [--reverse-on 2026-04-01] [--description <text>] [--key K] --evidence <oid> [--dry-run] --json, or fa {verb} --intent <entry.json|-> [--reverse-on YYYY-MM-DD]"
    );
    if args.positional.len() != 1 {
        return Err(usage(
            format!("{verb} takes no positional argument"),
            example,
        ));
    }
    const LEG_FLAGS: [&str; 6] = [
        "--date",
        "--debit",
        "--credit",
        "--amount",
        "--description",
        "--key",
    ];
    for flag in LEG_FLAGS
        .iter()
        .copied()
        .chain(["--intent", "--reverse-on"])
    {
        if args.flag_all(flag).len() > 1 {
            return Err(usage(format!("{verb} takes only one {flag}"), example));
        }
    }
    let class = fa_model::EntryClass::ADJUSTING;
    if let Some(path) = args.flag("--intent") {
        if let Some(flag) = LEG_FLAGS.iter().find(|flag| args.flag(flag).is_some()) {
            return Err(usage(
                format!(
                    "{verb} --intent carries its own legs and date; {flag} applies only without --intent"
                ),
                example,
            ));
        }
        let text = ctx.files.read_text(path)?;
        let doc = crate::cli::parse_json(path, &text)?;
        if doc.get("intents").is_some() {
            return Err(usage(
                format!("{verb} posts one Adjusting entry, not a batch"),
                "post a batch with fa batch --intent <batch.json>",
            ));
        }
        return post_document(ctx, args, Some(class), doc);
    }
    let need = |flag: &str, what: &str| {
        args.flag(flag)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| usage(format!("{verb} needs {flag} {what}"), example.clone()))
    };
    let date = need("--date", "YYYY-MM-DD")?;
    fa_time::DateDay::parse(date)
        .map_err(|e| usage(format!("--date: {e}"), "--date YYYY-MM-DD"))?;
    let debit = need("--debit", "<account code>")?;
    let credit = need("--credit", "<account code>")?;
    let amount = need("--amount", "\"<amount> <UNIT>\"")?;
    if debit == credit {
        return Err(usage(
            format!(
                "{verb} --debit and --credit name the same account {debit}: the entry would move nothing"
            ),
            example,
        ));
    }
    let key = args.flag("--key").map_or_else(
        || format!("{verb}:{date}:{debit}:{credit}:{amount}"),
        str::to_string,
    );
    let mut fields = vec![
        ("effective_date", s(date)),
        ("idempotency_key", s(key)),
        (
            "legs",
            Json::Arr(vec![
                obj(vec![
                    ("side", s("debit")),
                    ("account", s(debit)),
                    ("amount", s(amount)),
                ]),
                obj(vec![
                    ("side", s("credit")),
                    ("account", s(credit)),
                    ("amount", s(amount)),
                ]),
            ]),
        ),
    ];
    if let Some(description) = args.flag("--description") {
        fields.push(("description", s(description)));
    }
    post_document(ctx, args, Some(class), obj(fields))
}

/// `fa batch --intent <batch.json|->` (plan §15.3, §5.8): a PostBatch,
/// `{"idempotency_key": K, "intents": [<entry intent>, ...]}`, committed
/// atomically and in order through `fa post`'s batch path. A single entry
/// intent is refused rather than posted alone.
pub(crate) fn batch_cmd(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    const EXAMPLE: &str = "fa batch --intent <batch.json|-> [--dry-run] --json, where the batch is {\"idempotency_key\": \"...\", \"intents\": [<entry intent>, ...]}";
    if args.positional.len() != 1 {
        return Err(usage("batch takes no positional argument", EXAMPLE));
    }
    let path = args.require("--intent", "<batch.json|->")?;
    let text = ctx.files.read_text(path)?;
    let doc = crate::cli::parse_json(path, &text)?;
    if doc.get("intents").is_none() {
        return Err(usage(
            "fa batch posts a PostBatch with an intents array; this is a single entry intent",
            "post one entry with fa post --intent, or wrap it: {\"idempotency_key\": \"...\", \"intents\": [<entry intent>]}",
        ));
    }
    post_document(ctx, args, None, doc)
}
