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
//! open). Their key is receipt:<number> or payment:<number>, and the cash
//! leg's memo is the number, which `fa bank match` compares with a bank
//! line's reference.

use crate::args::Args;
use crate::cli::{Ctx, Fail, post_document, usage};
use crate::json::{Json, obj, s};

#[derive(Clone, Copy)]
enum Kind {
    Invoice,
    Bill,
}

impl Kind {
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
        sum(std::slice::from_ref(&amount))
            .map_err(|e| usage(format!("--applies {one}: {e}"), example.to_string()))?;
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
    let party = args.require("--party", "<party code> (fa party list)")?;
    let date = args.require("--date", "YYYY-MM-DD")?;
    fa_time::DateDay::parse(date)
        .map_err(|e| usage(format!("--date: {e}"), "--date YYYY-MM-DD"))?;
    let cash = args.require("--cash", "<cash account code>")?;
    let control = args.require(kind.control_flag(), "<account code>")?;
    let amount = args.require("--amount", "\"<amount> <UNIT>\"")?;
    let amount =
        sum(&[amount.to_string()]).map_err(|e| usage(format!("--amount: {e}"), example.clone()))?;
    let number = args.flag("--number");
    let key = match (args.flag("--key"), number) {
        (Some(key), _) => key.to_string(),
        (None, Some(number)) => format!("{}:{number}", kind.verb()),
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
    let entity = args.flag("--entity");
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
        if words.iter().any(|(k, _)| k == key) {
            return Err(format!("{key} is given twice"));
        }
        words.push((key.to_string(), value.to_string()));
        rest = tail.trim_start();
    }
    Ok(words)
}

/// `quantity × "<decimal> <UNIT>"` exactly, in the price's decimal places.
fn extend(qty: &str, price: &str) -> Result<String, String> {
    let qty: i128 = qty
        .parse()
        .ok()
        .filter(|q| *q > 0)
        .ok_or_else(|| format!("qty `{qty}` is not a positive whole number"))?;
    let (number, unit) = price
        .split_once(' ')
        .ok_or_else(|| format!("unit_price `{price}` is not \"<amount> <UNIT>\""))?;
    let (whole, frac) = number.split_once('.').unwrap_or((number, ""));
    if whole.is_empty()
        || !whole.bytes().all(|b| b.is_ascii_digit())
        || !frac.bytes().all(|b| b.is_ascii_digit())
    {
        return Err(format!(
            "unit_price `{number}` is not an exact non-negative decimal (no sign, exponent or float)"
        ));
    }
    let digits: i128 = format!("{whole}{frac}")
        .parse()
        .map_err(|_| format!("unit_price `{number}` is out of range"))?;
    let total = digits
        .checked_mul(qty)
        .ok_or_else(|| format!("qty {qty} × {number} is out of range"))?
        .to_string();
    let scale = frac.len();
    let rendered = if scale == 0 {
        total
    } else {
        let padded = format!("{total:0>width$}", width = scale + 1);
        let (int, dec) = padded.split_at(padded.len() - scale);
        format!("{int}.{dec}")
    };
    Ok(format!("{rendered} {unit}"))
}

/// Sum `"<decimal> <UNIT>"` amounts of one unit exactly, as text.
fn sum(amounts: &[String]) -> Result<String, String> {
    let mut unit: Option<&str> = None;
    let mut scale: Option<usize> = None;
    let mut total: i128 = 0;
    for amount in amounts {
        let (number, u) = amount
            .split_once(' ')
            .ok_or_else(|| format!("`{amount}` is not \"<amount> <UNIT>\""))?;
        match unit {
            Some(seen) if seen != u => {
                return Err(format!(
                    "lines are in {seen} and {u}: one document is in one unit"
                ));
            }
            _ => unit = Some(u),
        }
        let (whole, frac) = number.split_once('.').unwrap_or((number, ""));
        if !whole.bytes().all(|b| b.is_ascii_digit()) || !frac.bytes().all(|b| b.is_ascii_digit()) {
            return Err(format!(
                "amount `{number}` is not an exact non-negative decimal"
            ));
        }
        match scale {
            Some(seen) if seen != frac.len() => {
                return Err(format!(
                    "amount `{number}` has {} decimal places where another line has {seen}",
                    frac.len()
                ));
            }
            _ => scale = Some(frac.len()),
        }
        let digits: i128 = format!("{whole}{frac}")
            .parse()
            .map_err(|_| format!("amount `{number}` is out of range"))?;
        total = total
            .checked_add(digits)
            .ok_or_else(|| "the document total is out of range".to_string())?;
    }
    let (Some(unit), Some(scale)) = (unit, scale) else {
        return Err("no lines".into());
    };
    let total = total.to_string();
    let rendered = if scale == 0 {
        total
    } else {
        let padded = format!("{total:0>width$}", width = scale + 1);
        let (int, dec) = padded.split_at(padded.len() - scale);
        format!("{int}.{dec}")
    };
    Ok(format!("{rendered} {unit}"))
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
    let party = args.require("--party", "<party code> (fa party list)")?;
    let date = args.require("--date", "YYYY-MM-DD")?;
    fa_time::DateDay::parse(date)
        .map_err(|e| usage(format!("--date: {e}"), "--date YYYY-MM-DD"))?;
    let control = args.require(kind.control_flag(), "<account code>")?;
    let default_account = args.flag(kind.line_flag());
    let number = args.flag("--number");
    let key = match (args.flag("--key"), number) {
        (Some(key), _) => key.to_string(),
        (None, Some(number)) => format!("{}:{number}", kind.verb()),
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
    let entity = args.flag("--entity");
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
            (Some(amount), None, None) => amount.to_string(),
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
        assert_eq!(extend("10", "125.00 USD").unwrap(), "1250.00 USD");
        assert_eq!(extend("3", "0.05 USD").unwrap(), "0.15 USD");
        assert_eq!(extend("7", "100 JPY").unwrap(), "700 JPY");
        assert_eq!(extend("2", "0.125 KWD").unwrap(), "0.250 KWD");
        for (qty, price) in [
            ("0", "1.00 USD"),
            ("-1", "1.00 USD"),
            ("1.5", "1.00 USD"),
            ("2", "1.5e2 USD"),
            ("2", "-1.00 USD"),
            ("2", "1.00"),
        ] {
            assert!(extend(qty, price).is_err(), "{qty} x {price}");
        }
        assert_eq!(
            sum(&["1250.00 USD".into(), "0.15 USD".into()]).unwrap(),
            "1250.15 USD"
        );
        assert!(sum(&["1.00 USD".into(), "1.00 EUR".into()]).is_err());
        assert!(sum(&["1.00 USD".into(), "1.0 USD".into()]).is_err());
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
    }
}
