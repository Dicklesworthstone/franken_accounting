//! Canon posting rules, naively (plan §10.3, §16.1; bead fa-c34): an
//! independent reading of the rule language for the differential against
//! `fa-canon`. It shares no code with the engine: its own tokenizer and
//! recursive-descent parser over the source text, its own unbounded
//! arithmetic ([`Int`]), and its own reading of each rounding law from the
//! definitions in `rounding_laws.toml`.
//!
//! It assumes a rule `fa-canon` compiled (names, unit types, registered laws
//! and the balance proof were checked there) and computes what that rule
//! derives from an event and its inputs, in the engine's order of checks:
//! the event kind, the inputs (an undeclared one first, then each declared
//! one in order), every `let` in order, every leg in order, the effective
//! date, then the reversal date. Intermediates are unbounded; only a let's or
//! a leg's value must fit `i128`.

use std::cmp::Ordering;
use std::collections::BTreeMap;

use crate::Int;

/// A recorded event, as the rule reads it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Event {
    /// The kind's name, in any case (`Sale`, `sale`).
    pub kind: String,
    /// Days since 1970-01-01.
    pub occurred_on: i32,
    /// `(label, unit code, mantissa)`.
    pub resources: Vec<(String, String, i128)>,
}

/// A supplied input value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Input {
    /// Days since 1970-01-01.
    Date(i32),
    /// `(unit code, mantissa)`.
    Amount(String, i128),
}

/// One derived leg: dimension tags sorted by dimension name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Leg {
    pub debit: bool,
    pub account: String,
    pub unit: String,
    pub mantissa: i128,
    pub dims: Vec<(String, String)>,
}

/// What a rule derives: the class it produces, the effective date, the
/// reversal date if it schedules one, and its non-zero legs in order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Derivation {
    pub produces: String,
    pub effective: i32,
    pub reverse_on: Option<i32>,
    pub legs: Vec<Leg>,
}

/// Why a derivation fails, as the class the differential compares.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Failure {
    WrongEventKind,
    UndeclaredInput,
    MissingInput,
    InputType,
    MissingResource,
    AmbiguousResource,
    ResourceUnit,
    NegativeLeg,
    OutOfRange,
    ReversalNotAfter,
    /// The source is not a rule this reader understands.
    Syntax(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Tok {
    Ident(String),
    Str(String),
    Int(u128),
    Sym(char),
}

fn tokens(source: &str) -> Result<Vec<Tok>, Failure> {
    let chars: Vec<char> = source.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c.is_whitespace() {
            i += 1;
        } else if c == '#' || (c == '/' && chars.get(i + 1) == Some(&'/')) {
            while i < chars.len() && chars[i] != '\n' {
                i += 1;
            }
        } else if c.is_ascii_alphabetic() || c == '_' {
            let start = i;
            while i < chars.len() && (chars[i].is_ascii_alphanumeric() || chars[i] == '_') {
                i += 1;
            }
            out.push(Tok::Ident(chars[start..i].iter().collect()));
        } else if c.is_ascii_digit() {
            let mut value: u128 = 0;
            while i < chars.len() && chars[i].is_ascii_digit() {
                let digit = u128::from(chars[i].to_digit(10).unwrap_or_default());
                value = value
                    .checked_mul(10)
                    .and_then(|v| v.checked_add(digit))
                    .ok_or_else(|| Failure::Syntax("integer too large".into()))?;
                i += 1;
            }
            out.push(Tok::Int(value));
        } else if c == '"' {
            i += 1;
            let mut text = String::new();
            loop {
                match chars.get(i) {
                    None => return Err(Failure::Syntax("unterminated string".into())),
                    Some('"') => break,
                    Some('\\') => {
                        text.push(
                            *chars
                                .get(i + 1)
                                .ok_or_else(|| Failure::Syntax("unterminated escape".into()))?,
                        );
                        i += 2;
                    }
                    Some(&other) => {
                        text.push(other);
                        i += 1;
                    }
                }
            }
            i += 1;
            out.push(Tok::Str(text));
        } else {
            out.push(Tok::Sym(c));
            i += 1;
        }
    }
    Ok(out)
}

#[derive(Clone, Debug)]
enum Expr {
    /// `(unit, mantissa)`.
    Literal(String, i128),
    Name(String),
    /// `(label, unit)`.
    Resource(String, String),
    Add(Box<Expr>, Box<Expr>),
    Sub(Box<Expr>, Box<Expr>),
    /// `operand × num ÷ den`, rounded once under `law` when inexact.
    Scaled {
        operand: Box<Expr>,
        num: u128,
        den: u128,
        law: Option<String>,
    },
}

#[derive(Clone, Debug)]
enum DateRef {
    Occurred,
    Input(String),
}

#[derive(Clone, Debug)]
enum Stmt {
    Let(String, Expr),
    Leg {
        debit: bool,
        account: String,
        amount: Expr,
        dims: Vec<(String, String)>,
    },
    Effective(DateRef),
    Reverses(DateRef),
}

#[derive(Clone, Debug)]
enum InputType {
    Date,
    Amount(String),
}

struct Rule {
    kind: String,
    produces: String,
    inputs: Vec<(String, InputType)>,
    stmts: Vec<Stmt>,
}

struct Parser<'a> {
    toks: Vec<Tok>,
    at: usize,
    scales: &'a BTreeMap<String, u32>,
}

fn syntax(what: &str) -> Failure {
    Failure::Syntax(what.to_string())
}

impl Parser<'_> {
    fn next(&mut self) -> Result<Tok, Failure> {
        let tok = self
            .toks
            .get(self.at)
            .cloned()
            .ok_or_else(|| syntax("the rule ended early"))?;
        self.at += 1;
        Ok(tok)
    }

    fn peek_ident(&self, word: &str) -> bool {
        matches!(self.toks.get(self.at), Some(Tok::Ident(w)) if w == word)
    }

    fn peek_sym(&self, c: char) -> bool {
        self.toks.get(self.at) == Some(&Tok::Sym(c))
    }

    fn ident(&mut self) -> Result<String, Failure> {
        match self.next()? {
            Tok::Ident(word) => Ok(word),
            other => Err(Failure::Syntax(format!("expected a name, found {other:?}"))),
        }
    }

    fn word(&mut self, word: &str) -> Result<(), Failure> {
        if self.ident()? == word {
            Ok(())
        } else {
            Err(Failure::Syntax(format!("expected `{word}`")))
        }
    }

    fn sym(&mut self, c: char) -> Result<(), Failure> {
        if self.next()? == Tok::Sym(c) {
            Ok(())
        } else {
            Err(Failure::Syntax(format!("expected `{c}`")))
        }
    }

    fn string(&mut self) -> Result<String, Failure> {
        match self.next()? {
            Tok::Str(text) => Ok(text),
            other => Err(Failure::Syntax(format!(
                "expected a string, found {other:?}"
            ))),
        }
    }

    fn int(&mut self) -> Result<u128, Failure> {
        match self.next()? {
            Tok::Int(value) => Ok(value),
            other => Err(Failure::Syntax(format!(
                "expected an integer, found {other:?}"
            ))),
        }
    }

    fn rule(&mut self) -> Result<Rule, Failure> {
        self.word("rule")?;
        self.ident()?;
        self.ident()?; // vN
        self.word("for")?;
        self.word("event")?;
        let kind = self.ident()?;
        let produces = if self.peek_ident("produces") {
            self.at += 1;
            self.ident()?
        } else {
            "Original".to_string()
        };
        self.sym('{')?;
        let mut inputs = Vec::new();
        if self.peek_ident("inputs") {
            self.at += 1;
            self.sym('{')?;
            while !self.peek_sym('}') {
                let name = self.ident()?;
                self.sym(':')?;
                let ty = match self.ident()?.as_str() {
                    "date" => InputType::Date,
                    "amount" => {
                        self.sym('(')?;
                        let unit = self.string()?;
                        self.sym(')')?;
                        InputType::Amount(unit)
                    }
                    other => return Err(Failure::Syntax(format!("unknown type {other}"))),
                };
                inputs.push((name, ty));
                if self.peek_sym(',') {
                    self.at += 1;
                }
            }
            self.sym('}')?;
        }
        let mut stmts = Vec::new();
        while !self.peek_sym('}') {
            stmts.push(self.stmt()?);
        }
        self.sym('}')?;
        if self.at != self.toks.len() {
            return Err(syntax("text after the rule"));
        }
        Ok(Rule {
            kind,
            produces,
            inputs,
            stmts,
        })
    }

    fn date(&mut self) -> Result<DateRef, Failure> {
        if self.peek_ident("event") {
            self.at += 1;
            self.sym('.')?;
            self.word("occurred_on")?;
            Ok(DateRef::Occurred)
        } else {
            Ok(DateRef::Input(self.ident()?))
        }
    }

    fn stmt(&mut self) -> Result<Stmt, Failure> {
        match self.ident()?.as_str() {
            "let" => {
                let name = self.ident()?;
                self.sym('=')?;
                Ok(Stmt::Let(name, self.expr()?))
            }
            side @ ("debit" | "credit") => {
                let debit = side == "debit";
                let account = self.string()?;
                let amount = self.expr()?;
                let mut dims = Vec::new();
                if self.peek_ident("dims") {
                    self.at += 1;
                    self.sym('{')?;
                    while !self.peek_sym('}') {
                        let dimension = self.ident()?;
                        self.sym('=')?;
                        dims.push((dimension, self.string()?));
                        if self.peek_sym(',') {
                            self.at += 1;
                        }
                    }
                    self.sym('}')?;
                }
                dims.sort();
                Ok(Stmt::Leg {
                    debit,
                    account,
                    amount,
                    dims,
                })
            }
            "effective" => Ok(Stmt::Effective(self.date()?)),
            "reverses" => Ok(Stmt::Reverses(self.date()?)),
            other => Err(Failure::Syntax(format!("unknown statement `{other}`"))),
        }
    }

    fn expr(&mut self) -> Result<Expr, Failure> {
        let mut left = self.term()?;
        loop {
            if self.peek_sym('+') {
                self.at += 1;
                left = Expr::Add(Box::new(left), Box::new(self.term()?));
            } else if self.peek_sym('-') {
                self.at += 1;
                left = Expr::Sub(Box::new(left), Box::new(self.term()?));
            } else {
                return Ok(left);
            }
        }
    }

    fn term(&mut self) -> Result<Expr, Failure> {
        let operand = self.factor()?;
        let (mut num, mut den, mut scaled) = (1u128, 1u128, false);
        loop {
            if self.peek_sym('*') {
                self.at += 1;
                num = num
                    .checked_mul(self.int()?)
                    .ok_or_else(|| syntax("a multiplier overflows"))?;
                scaled = true;
            } else if self.peek_sym('/') {
                self.at += 1;
                den = den
                    .checked_mul(self.int()?)
                    .ok_or_else(|| syntax("a divisor overflows"))?;
                scaled = true;
            } else {
                break;
            }
        }
        let law = if self.peek_ident("round") {
            self.at += 1;
            Some(self.ident()?)
        } else {
            None
        };
        if !scaled && law.is_none() {
            return Ok(operand);
        }
        Ok(Expr::Scaled {
            operand: Box::new(operand),
            num,
            den,
            law,
        })
    }

    fn factor(&mut self) -> Result<Expr, Failure> {
        match self.next()? {
            Tok::Sym('(') => {
                let inner = self.expr()?;
                self.sym(')')?;
                Ok(inner)
            }
            Tok::Str(text) => self.literal(&text),
            Tok::Ident(word) if word == "event" => {
                self.sym('.')?;
                self.word("resource")?;
                self.sym('(')?;
                let label = self.string()?;
                self.sym(',')?;
                let unit = self.string()?;
                self.sym(')')?;
                Ok(Expr::Resource(label, unit))
            }
            Tok::Ident(name) => Ok(Expr::Name(name)),
            other => Err(Failure::Syntax(format!("unexpected {other:?}"))),
        }
    }

    /// `"12.50 USD"`: digits at most to the unit's scale, padded to it.
    fn literal(&self, text: &str) -> Result<Expr, Failure> {
        let (number, unit) = text
            .trim()
            .rsplit_once(' ')
            .ok_or_else(|| syntax("an amount literal is `<number> <UNIT>`"))?;
        let scale = *self
            .scales
            .get(unit.trim())
            .ok_or_else(|| Failure::Syntax(format!("unit {unit} has no scale")))?;
        let number = number.trim().replace('_', "");
        let (negative, body) = match number.strip_prefix('-') {
            Some(body) => (true, body.to_string()),
            None => (false, number.trim_start_matches('+').to_string()),
        };
        let (whole, fraction) = body.split_once('.').unwrap_or((&body, ""));
        if fraction.len() > scale as usize {
            return Err(syntax("more decimals than the unit's scale"));
        }
        let mut magnitude = Int::zero();
        let ten = Int::from_u128(10);
        for c in whole.chars().chain(fraction.chars()) {
            let digit = c
                .to_digit(10)
                .ok_or_else(|| syntax("an amount literal holds a non-digit"))?;
            magnitude = magnitude.mul(&ten).add(&Int::from_u128(u128::from(digit)));
        }
        for _ in fraction.len()..scale as usize {
            magnitude = magnitude.mul(&ten);
        }
        let value = if negative {
            magnitude.negated()
        } else {
            magnitude
        };
        let mantissa = value
            .to_i128()
            .ok_or_else(|| syntax("an amount literal overflows"))?;
        Ok(Expr::Literal(unit.trim().to_string(), mantissa))
    }
}

/// `value × num ÷ den` under `law` (rounding_laws.toml's definitions), for
/// `den > 0`. An exact quotient needs no law.
fn scale(value: &Int, num: u128, den: u128, law: Option<&str>) -> Result<Int, Failure> {
    let product = value.mul(&Int::from_u128(num));
    let den = Int::from_u128(den);
    let (quotient, remainder) = product
        .div_rem(&den)
        .ok_or_else(|| syntax("division by zero"))?;
    if remainder.is_zero() {
        return Ok(quotient);
    }
    let Some(law) = law else {
        return Err(syntax("an inexact division names no rounding law"));
    };
    // `quotient` is truncated toward zero; the fraction left is
    // |remainder| / den, compared with one half.
    let negative = product.is_negative();
    let half = remainder.abs().mul(&Int::from_u128(2)).cmp(&den);
    let odd = || {
        quotient
            .div_rem(&Int::from_u128(2))
            .is_some_and(|(_, bit)| !bit.is_zero())
    };
    let away_from_zero = match law {
        "TowardZero" => false,
        "AwayFromZero" => true,
        // Toward positive infinity: away from zero for a positive value.
        "Ceiling" => !negative,
        "Floor" => negative,
        "HalfAwayFromZero" => half != Ordering::Less,
        "HalfTowardZero" => half == Ordering::Greater,
        // Ties toward positive infinity, which is away from zero only for a
        // positive value; toward negative infinity, only for a negative one.
        "HalfUp" => half == Ordering::Greater || (half == Ordering::Equal && !negative),
        "HalfDown" => half == Ordering::Greater || (half == Ordering::Equal && negative),
        "HalfEven" => half == Ordering::Greater || (half == Ordering::Equal && odd()),
        other => return Err(Failure::Syntax(format!("unknown rounding law {other}"))),
    };
    let one = Int::from_u128(1);
    Ok(match (away_from_zero, negative) {
        (false, _) => quotient,
        (true, false) => quotient.add(&one),
        (true, true) => quotient.sub(&one),
    })
}

struct Frame<'a> {
    event: &'a Event,
    inputs: &'a BTreeMap<String, Input>,
    lets: BTreeMap<String, (String, Int)>,
}

/// A value that must be an i128 mantissa at this point of the evaluation.
fn in_range(value: Int) -> Result<Int, Failure> {
    if value.to_i128().is_some() {
        Ok(value)
    } else {
        Err(Failure::OutOfRange)
    }
}

impl Frame<'_> {
    /// An expression's unit and exact value.
    fn value(&self, expr: &Expr) -> Result<(String, Int), Failure> {
        match expr {
            Expr::Literal(unit, mantissa) => Ok((unit.clone(), Int::from_i128(*mantissa))),
            Expr::Name(name) => {
                if let Some(bound) = self.lets.get(name) {
                    return Ok(bound.clone());
                }
                match self.inputs.get(name) {
                    Some(Input::Amount(unit, mantissa)) => {
                        Ok((unit.clone(), Int::from_i128(*mantissa)))
                    }
                    Some(Input::Date(_)) => Err(Failure::InputType),
                    None => Err(Failure::MissingInput),
                }
            }
            Expr::Resource(label, unit) => {
                let found: Vec<&(String, String, i128)> = self
                    .event
                    .resources
                    .iter()
                    .filter(|(l, _, _)| l == label)
                    .collect();
                match found.as_slice() {
                    [] => Err(Failure::MissingResource),
                    [(_, u, mantissa)] if u == unit => {
                        Ok((unit.clone(), Int::from_i128(*mantissa)))
                    }
                    [_] => Err(Failure::ResourceUnit),
                    _ => Err(Failure::AmbiguousResource),
                }
            }
            // Plan §6.1: a sum or difference is a checked i128 operation, so
            // one that leaves i128 is refused where it happens.
            Expr::Add(a, b) => {
                let (unit, a) = self.value(a)?;
                let (_, b) = self.value(b)?;
                Ok((unit, in_range(a.add(&b))?))
            }
            Expr::Sub(a, b) => {
                let (unit, a) = self.value(a)?;
                let (_, b) = self.value(b)?;
                Ok((unit, in_range(a.sub(&b))?))
            }
            // The product and quotient stay wide; the term's rounded result
            // is narrowed.
            Expr::Scaled {
                operand,
                num,
                den,
                law,
            } => {
                let (unit, value) = self.value(operand)?;
                Ok((unit, in_range(scale(&value, *num, *den, law.as_deref())?)?))
            }
        }
    }

    fn date(&self, date: &DateRef) -> Result<i32, Failure> {
        match date {
            DateRef::Occurred => Ok(self.event.occurred_on),
            DateRef::Input(name) => match self.inputs.get(name) {
                Some(Input::Date(day)) => Ok(*day),
                Some(Input::Amount(..)) => Err(Failure::InputType),
                None => Err(Failure::MissingInput),
            },
        }
    }
}

/// What the rule `source` derives from `event` with `inputs`. `scales`
/// names each unit code's registered scale (for amount literals).
pub fn evaluate(
    source: &str,
    scales: &BTreeMap<String, u32>,
    event: &Event,
    inputs: &BTreeMap<String, Input>,
) -> Result<Derivation, Failure> {
    let mut parser = Parser {
        toks: tokens(source)?,
        at: 0,
        scales,
    };
    let rule = parser.rule()?;
    // Event kinds are named without regard to case (`Sale`, `sale`).
    if !rule.kind.eq_ignore_ascii_case(&event.kind) {
        return Err(Failure::WrongEventKind);
    }
    if inputs
        .keys()
        .any(|name| !rule.inputs.iter().any(|(declared, _)| declared == name))
    {
        return Err(Failure::UndeclaredInput);
    }
    for (name, ty) in &rule.inputs {
        match (ty, inputs.get(name)) {
            (_, None) => return Err(Failure::MissingInput),
            (InputType::Date, Some(Input::Date(_))) => {}
            (InputType::Amount(unit), Some(Input::Amount(given, _))) if unit == given => {}
            _ => return Err(Failure::InputType),
        }
    }
    let mut frame = Frame {
        event,
        inputs,
        lets: BTreeMap::new(),
    };
    for stmt in &rule.stmts {
        if let Stmt::Let(name, expr) = stmt {
            let (unit, value) = frame.value(expr)?;
            if value.to_i128().is_none() {
                return Err(Failure::OutOfRange);
            }
            frame.lets.insert(name.clone(), (unit, value));
        }
    }
    let mut legs = Vec::new();
    for stmt in &rule.stmts {
        if let Stmt::Leg {
            debit,
            account,
            amount,
            dims,
        } = stmt
        {
            let (unit, value) = frame.value(amount)?;
            let mantissa = value.to_i128().ok_or(Failure::OutOfRange)?;
            if mantissa < 0 {
                return Err(Failure::NegativeLeg);
            }
            if mantissa == 0 {
                continue;
            }
            legs.push(Leg {
                debit: *debit,
                account: account.clone(),
                unit,
                mantissa,
                dims: dims.clone(),
            });
        }
    }
    let mut effective = event.occurred_on;
    let mut reverse_on = None;
    for stmt in &rule.stmts {
        match stmt {
            Stmt::Effective(date) => effective = frame.date(date)?,
            Stmt::Reverses(date) => reverse_on = Some(frame.date(date)?),
            _ => {}
        }
    }
    if reverse_on.is_some_and(|day| day <= effective) {
        return Err(Failure::ReversalNotAfter);
    }
    Ok(Derivation {
        produces: rule.produces,
        effective,
        reverse_on,
        legs,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn usd() -> BTreeMap<String, u32> {
        BTreeMap::from([("USD".to_string(), 2)])
    }

    fn rounded(mantissa: i128, num: u128, den: u128, law: &str) -> i128 {
        scale(&Int::from_i128(mantissa), num, den, Some(law))
            .unwrap()
            .to_i128()
            .unwrap()
    }

    /// Each law at a tie, above and below it, on both signs, read from its
    /// registered definition.
    #[test]
    fn every_registered_law_rounds_as_its_definition_says() {
        // (law, 2.5, -2.5, 3.5, -3.5, 2.4, -2.6)
        let cases: [(&str, [i128; 6]); 9] = [
            ("HalfUp", [3, -2, 4, -3, 2, -3]),
            ("HalfDown", [2, -3, 3, -4, 2, -3]),
            ("HalfEven", [2, -2, 4, -4, 2, -3]),
            ("HalfAwayFromZero", [3, -3, 4, -4, 2, -3]),
            ("HalfTowardZero", [2, -2, 3, -3, 2, -3]),
            ("Ceiling", [3, -2, 4, -3, 3, -2]),
            ("Floor", [2, -3, 3, -4, 2, -3]),
            ("TowardZero", [2, -2, 3, -3, 2, -2]),
            ("AwayFromZero", [3, -3, 4, -4, 3, -3]),
        ];
        for (law, expected) in cases {
            let got = [
                rounded(25, 1, 10, law),
                rounded(-25, 1, 10, law),
                rounded(35, 1, 10, law),
                rounded(-35, 1, 10, law),
                rounded(24, 1, 10, law),
                rounded(-26, 1, 10, law),
            ];
            assert_eq!(got, expected, "{law}");
        }
        // Exact quotients need no law.
        assert_eq!(
            scale(&Int::from_i128(30), 1, 10, None).unwrap().to_i128(),
            Some(3)
        );
        assert!(scale(&Int::from_i128(31), 1, 10, None).is_err());
    }

    #[test]
    fn a_rule_derives_its_legs_dates_and_failures() {
        let source = r#"rule sale v1 for event Sale produces Adjusting {
  inputs { back: date } # a comment
  let net = event.resource("net", "USD")
  let tax = net * 7 / 100 round HalfEven
  debit "1200" net + tax dims { region = "EU", cost_center = "CC1" }
  credit "4000" net
  credit "2300" tax // zero for small nets
  reverses back
}"#;
        let event = Event {
            kind: "Sale".into(),
            occurred_on: 100,
            resources: vec![("net".into(), "USD".into(), 1050)],
        };
        let inputs = BTreeMap::from([("back".to_string(), Input::Date(101))]);
        let derived = evaluate(source, &usd(), &event, &inputs).unwrap();
        assert_eq!(derived.produces, "Adjusting");
        assert_eq!((derived.effective, derived.reverse_on), (100, Some(101)));
        // 7% of 10.50 is 0.735, 74 cents under HalfEven.
        let legs: Vec<(bool, &str, i128)> = derived
            .legs
            .iter()
            .map(|leg| (leg.debit, leg.account.as_str(), leg.mantissa))
            .collect();
        assert_eq!(
            legs,
            vec![
                (true, "1200", 1124),
                (false, "4000", 1050),
                (false, "2300", 74)
            ]
        );
        assert_eq!(
            derived.legs[0].dims,
            vec![
                ("cost_center".to_string(), "CC1".to_string()),
                ("region".to_string(), "EU".to_string())
            ]
        );
        let at = |inputs: BTreeMap<String, Input>, event: &Event| {
            evaluate(source, &usd(), event, &inputs).unwrap_err()
        };
        assert_eq!(
            at(
                BTreeMap::from([("back".to_string(), Input::Date(100))]),
                &event
            ),
            Failure::ReversalNotAfter
        );
        assert_eq!(at(BTreeMap::new(), &event), Failure::MissingInput);
        let mut wrong = event.clone();
        wrong.kind = "Purchase".into();
        assert_eq!(at(inputs.clone(), &wrong), Failure::WrongEventKind);
        let mut none = event.clone();
        none.resources.clear();
        assert_eq!(at(inputs.clone(), &none), Failure::MissingResource);
        let mut twice = event.clone();
        twice.resources.push(("net".into(), "USD".into(), 1));
        assert_eq!(at(inputs.clone(), &twice), Failure::AmbiguousResource);
        let mut euro = event;
        euro.resources[0].1 = "EUR".into();
        assert_eq!(at(inputs, &euro), Failure::ResourceUnit);
    }
}
