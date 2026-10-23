//! The rule grammar (plan §10.3), parsed into an untyped syntax tree:
//!
//! ```text
//! rule    := 'rule' NAME 'v'N 'for' 'event' KIND '{' [inputs] stmt* '}'
//! inputs  := 'inputs' '{' NAME ':' type (',' NAME ':' type)* [','] '}'
//! type    := 'date' | 'amount' '(' "UNIT" ')'
//! stmt    := 'let' NAME '=' expr
//!          | ('debit' | 'credit') "ACCOUNT" expr ['dims' '{' DIM '=' "CODE" (',' …)* [','] '}']
//!          | 'effective' ('event' '.' 'occurred_on' | NAME)
//! expr    := term (('+' | '-') term)*
//! term    := factor (('*' | '/') INT)* ['round' LAW]
//! factor  := '(' expr ')' | "AMOUNT UNIT" | NAME | 'event' '.' 'resource' '(' "LABEL" ',' "UNIT" ')'
//! ```

use crate::CanonError;
use crate::lex::{Spanned, Token, tokens};
use fa_money::Side;

/// How deep one expression may nest, counting parentheses and each `+`/`-`
/// of a chain (which builds a left-deep tree); deeper is refused, so the
/// checker and evaluator never recurse past it.
const MAX_DEPTH: u32 = 64;
/// Statements and inputs one rule may hold.
const MAX_STATEMENTS: usize = 512;
const MAX_INPUTS: usize = 64;

/// Words a name may not be. `date`, `amount`, `occurred_on` and `resource`
/// mean something only where the grammar expects them (a type, or after
/// `event.`), so they stay free for lets and inputs.
const KEYWORDS: [&str; 10] = [
    "rule",
    "for",
    "event",
    "inputs",
    "let",
    "debit",
    "credit",
    "dims",
    "effective",
    "round",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Pos {
    pub line: u32,
    pub column: u32,
}

impl Pos {
    pub(crate) fn error(self, message: impl Into<String>) -> CanonError {
        CanonError::new(self.line, self.column, message)
    }
}

#[derive(Debug)]
pub(crate) struct SourceRule {
    pub name: String,
    pub version: u32,
    pub event: (String, Pos),
    /// `produces <Class>`, when the rule names its entry class.
    pub produces: Option<(String, Pos)>,
    pub inputs: Vec<SourceInput>,
    pub stmts: Vec<Stmt>,
}

#[derive(Debug)]
pub(crate) struct SourceInput {
    pub name: String,
    pub ty: SourceType,
    pub pos: Pos,
}

#[derive(Debug)]
pub(crate) enum SourceType {
    Date,
    Amount(String, Pos),
}

#[derive(Debug)]
pub(crate) enum Stmt {
    Let {
        name: String,
        expr: Expr,
        pos: Pos,
    },
    Leg {
        side: Side,
        account: String,
        amount: Expr,
        dims: Vec<(String, String, Pos)>,
        pos: Pos,
    },
    Effective {
        date: DateRef,
        pos: Pos,
    },
}

#[derive(Debug)]
pub(crate) enum DateRef {
    Occurred,
    Name(String),
}

#[derive(Debug)]
pub(crate) enum Expr {
    Literal(String, Pos),
    Name(String, Pos),
    Resource {
        label: String,
        unit: String,
        pos: Pos,
    },
    Add(Box<Expr>, Box<Expr>),
    Sub(Box<Expr>, Box<Expr>),
    /// `operand (* N | / N)* [round LAW]`; `true` marks a multiplication.
    Scale {
        operand: Box<Expr>,
        factors: Vec<(bool, u64)>,
        law: Option<(String, Pos)>,
        pos: Pos,
    },
}

pub(crate) fn parse(source: &str) -> Result<SourceRule, CanonError> {
    let toks = tokens(source)?;
    let mut parser = Parser { toks, at: 0 };
    let rule = parser.rule()?;
    if let Some(extra) = parser.toks.get(parser.at) {
        return Err(CanonError::new(
            extra.line,
            extra.column,
            "text after the rule's closing `}`",
        ));
    }
    Ok(rule)
}

struct Parser {
    toks: Vec<Spanned>,
    at: usize,
}

impl Parser {
    fn pos(&self) -> Pos {
        match self.toks.get(self.at).or_else(|| self.toks.last()) {
            Some(t) => Pos {
                line: t.line,
                column: t.column,
            },
            None => Pos { line: 1, column: 1 },
        }
    }

    fn peek(&self) -> Option<&Token> {
        self.toks.get(self.at).map(|t| &t.token)
    }

    fn peek_ident(&self, word: &str) -> bool {
        matches!(self.peek(), Some(Token::Ident(w)) if w == word)
    }

    fn peek_symbol(&self, c: char) -> bool {
        self.peek() == Some(&Token::Symbol(c))
    }

    fn next(&mut self, expected: &str) -> Result<(Token, Pos), CanonError> {
        let pos = self.pos();
        match self.toks.get(self.at) {
            Some(t) => {
                self.at = self.at.saturating_add(1);
                Ok((t.token.clone(), pos))
            }
            None => Err(pos.error(format!("the rule ended where {expected} was expected"))),
        }
    }

    fn keyword(&mut self, word: &str) -> Result<Pos, CanonError> {
        match self.next(&format!("`{word}`"))? {
            (Token::Ident(w), pos) if w == word => Ok(pos),
            (_, pos) => Err(pos.error(format!("expected `{word}`"))),
        }
    }

    fn symbol(&mut self, c: char) -> Result<Pos, CanonError> {
        match self.next(&format!("`{c}`"))? {
            (Token::Symbol(s), pos) if s == c => Ok(pos),
            (_, pos) => Err(pos.error(format!("expected `{c}`"))),
        }
    }

    fn string(&mut self, what: &str) -> Result<(String, Pos), CanonError> {
        match self.next(what)? {
            (Token::Str(s), pos) => Ok((s, pos)),
            (_, pos) => Err(pos.error(format!("expected {what} as a quoted string"))),
        }
    }

    /// A name the rule binds or reads: an identifier that is not a keyword.
    fn name(&mut self, what: &str) -> Result<(String, Pos), CanonError> {
        match self.next(what)? {
            (Token::Ident(w), pos) if KEYWORDS.contains(&w.as_str()) => {
                Err(pos.error(format!("`{w}` is a keyword, not {what}")))
            }
            (Token::Ident(w), pos) => Ok((w, pos)),
            (_, pos) => Err(pos.error(format!("expected {what}"))),
        }
    }

    fn rule(&mut self) -> Result<SourceRule, CanonError> {
        self.keyword("rule")?;
        let (name, _) = self.name("the rule's name")?;
        let version = match self.next("the rule's version `vN`")? {
            (Token::Ident(v), pos) => v
                .strip_prefix('v')
                .filter(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
                .and_then(|n| n.parse::<u32>().ok())
                .filter(|n| *n >= 1)
                .ok_or_else(|| pos.error("a rule version is `v1`, `v2`, …"))?,
            (_, pos) => return Err(pos.error("expected the rule's version `vN`")),
        };
        self.keyword("for")?;
        self.keyword("event")?;
        let event = match self.next("the event kind")? {
            (Token::Ident(kind), pos) => (kind, pos),
            (_, pos) => return Err(pos.error("expected the event kind, such as `Sale`")),
        };
        let produces = if self.peek_ident("produces") {
            self.keyword("produces")?;
            match self.next("the entry class the rule produces")? {
                (Token::Ident(class), pos) => Some((class, pos)),
                (_, pos) => {
                    return Err(pos
                        .error("expected the entry class the rule produces, such as `Adjusting`"));
                }
            }
        } else {
            None
        };
        self.symbol('{')?;
        let inputs = if self.peek_ident("inputs") {
            self.inputs()?
        } else {
            Vec::new()
        };
        let mut stmts = Vec::new();
        while !self.peek_symbol('}') {
            if stmts.len() >= MAX_STATEMENTS {
                return Err(self
                    .pos()
                    .error(format!("a rule holds at most {MAX_STATEMENTS} statements")));
            }
            stmts.push(self.stmt()?);
        }
        self.symbol('}')?;
        Ok(SourceRule {
            name,
            version,
            event,
            produces,
            inputs,
            stmts,
        })
    }

    fn inputs(&mut self) -> Result<Vec<SourceInput>, CanonError> {
        self.keyword("inputs")?;
        self.symbol('{')?;
        let mut out = Vec::new();
        while !self.peek_symbol('}') {
            if out.len() >= MAX_INPUTS {
                return Err(self
                    .pos()
                    .error(format!("a rule declares at most {MAX_INPUTS} inputs")));
            }
            let (name, pos) = self.name("an input's name")?;
            self.symbol(':')?;
            let ty = match self.next("an input type, `date` or `amount(\"UNIT\")`")? {
                (Token::Ident(t), _) if t == "date" => SourceType::Date,
                (Token::Ident(t), _) if t == "amount" => {
                    self.symbol('(')?;
                    let (unit, unit_pos) = self.string("the amount's unit")?;
                    self.symbol(')')?;
                    SourceType::Amount(unit, unit_pos)
                }
                (_, pos) => {
                    return Err(pos.error("an input is `date` or `amount(\"UNIT\")`"));
                }
            };
            out.push(SourceInput { name, ty, pos });
            if !self.peek_symbol('}') {
                self.symbol(',')?;
            }
        }
        self.symbol('}')?;
        Ok(out)
    }

    fn stmt(&mut self) -> Result<Stmt, CanonError> {
        let pos = self.pos();
        match self.peek() {
            Some(Token::Ident(w)) if w == "let" => {
                self.at = self.at.saturating_add(1);
                let (name, _) = self.name("the let's name")?;
                self.symbol('=')?;
                let expr = self.expr(0)?;
                Ok(Stmt::Let { name, expr, pos })
            }
            Some(Token::Ident(w)) if w == "debit" || w == "credit" => {
                let side = if w == "debit" {
                    Side::Debit
                } else {
                    Side::Credit
                };
                self.at = self.at.saturating_add(1);
                let (account, _) = self.string("the leg's account code")?;
                let amount = self.expr(0)?;
                let dims = if self.peek_ident("dims") {
                    self.dims()?
                } else {
                    Vec::new()
                };
                Ok(Stmt::Leg {
                    side,
                    account,
                    amount,
                    dims,
                    pos,
                })
            }
            Some(Token::Ident(w)) if w == "effective" => {
                self.at = self.at.saturating_add(1);
                let date = if self.peek_ident("event") {
                    self.at = self.at.saturating_add(1);
                    self.symbol('.')?;
                    self.keyword("occurred_on")?;
                    DateRef::Occurred
                } else {
                    DateRef::Name(self.name("a declared date input")?.0)
                };
                Ok(Stmt::Effective { date, pos })
            }
            None => Err(pos.error("the rule ended before its closing `}`")),
            _ => Err(pos.error("expected `let`, `debit`, `credit`, `effective` or `}`")),
        }
    }

    fn dims(&mut self) -> Result<Vec<(String, String, Pos)>, CanonError> {
        self.keyword("dims")?;
        self.symbol('{')?;
        let mut out = Vec::new();
        while !self.peek_symbol('}') {
            let (dimension, pos) = match self.next("a dimension")? {
                (Token::Ident(d), pos) => (d, pos),
                (_, pos) => return Err(pos.error("expected a dimension, such as `cost_center`")),
            };
            self.symbol('=')?;
            let (code, _) = self.string("the dimension value's code")?;
            out.push((dimension, code, pos));
            if !self.peek_symbol('}') {
                self.symbol(',')?;
            }
        }
        self.symbol('}')?;
        Ok(out)
    }

    fn expr(&mut self, depth: u32) -> Result<Expr, CanonError> {
        let mut left = self.term(depth)?;
        let mut chain = depth;
        loop {
            let add = self.peek_symbol('+');
            if !add && !self.peek_symbol('-') {
                return Ok(left);
            }
            chain = chain.saturating_add(1);
            if chain >= MAX_DEPTH {
                return Err(self.pos().error(format!(
                    "an expression nests at most {MAX_DEPTH} deep; name a part with `let`"
                )));
            }
            self.at = self.at.saturating_add(1);
            let right = Box::new(self.term(chain)?);
            left = if add {
                Expr::Add(Box::new(left), right)
            } else {
                Expr::Sub(Box::new(left), right)
            };
        }
    }

    fn term(&mut self, depth: u32) -> Result<Expr, CanonError> {
        let pos = self.pos();
        let operand = self.factor(depth)?;
        let mut factors = Vec::new();
        while self.peek_symbol('*') || self.peek_symbol('/') {
            let multiply = self.peek_symbol('*');
            self.at = self.at.saturating_add(1);
            match self.next("an integer factor")? {
                (Token::Int(n), _) => factors.push((multiply, n)),
                (_, pos) => {
                    return Err(pos.error(
                        "an amount scales only by an integer; a ratio is `* N / D round LAW`",
                    ));
                }
            }
        }
        let law = if self.peek_ident("round") {
            self.at = self.at.saturating_add(1);
            match self.next("a rounding law")? {
                (Token::Ident(law), pos) => Some((law, pos)),
                (_, pos) => return Err(pos.error("expected a rounding law, such as `HalfEven`")),
            }
        } else {
            None
        };
        if factors.is_empty() && law.is_none() {
            return Ok(operand);
        }
        Ok(Expr::Scale {
            operand: Box::new(operand),
            factors,
            law,
            pos,
        })
    }

    fn factor(&mut self, depth: u32) -> Result<Expr, CanonError> {
        let (token, pos) = self.next("an amount")?;
        match token {
            Token::Symbol('(') => {
                if depth >= MAX_DEPTH {
                    return Err(pos.error(format!(
                        "an expression nests at most {MAX_DEPTH} deep; name a part with `let`"
                    )));
                }
                let inner = self.expr(depth.saturating_add(1))?;
                self.symbol(')')?;
                Ok(inner)
            }
            Token::Str(text) => Ok(Expr::Literal(text, pos)),
            Token::Ident(w) if w == "event" => {
                self.symbol('.')?;
                match self.next("an event field")? {
                    (Token::Ident(f), _) if f == "resource" => {
                        self.symbol('(')?;
                        let (label, _) = self.string("the resource label")?;
                        self.symbol(',')?;
                        let (unit, _) = self.string("the resource unit")?;
                        self.symbol(')')?;
                        Ok(Expr::Resource { label, unit, pos })
                    }
                    (Token::Ident(f), field_pos) if f == "occurred_on" => Err(field_pos.error(
                        "`event.occurred_on` is a date; an amount reads `event.resource(\"LABEL\", \"UNIT\")`",
                    )),
                    (_, field_pos) => Err(field_pos.error(
                        "an event exposes `resource(\"LABEL\", \"UNIT\")` and `occurred_on`",
                    )),
                }
            }
            Token::Ident(w) if KEYWORDS.contains(&w.as_str()) => {
                Err(pos.error(format!("`{w}` is a keyword, not an amount")))
            }
            Token::Ident(w) => Ok(Expr::Name(w, pos)),
            Token::Int(_) => Err(pos.error(
                "a bare number has no unit; write an amount literal such as \"12.50 USD\", or scale with `* N`",
            )),
            Token::Symbol(c) => Err(pos.error(format!("expected an amount, found `{c}`"))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SALE: &str = r#"
        rule sale_with_tax v3 for event Sale {
          inputs { as_of: date, fee: amount("USD") }
          let net = event.resource("net", "USD")
          let tax = net * 7 / 100 round HalfEven
          debit "1200" net + tax dims { cost_center = "CC1" }
          credit "4000" net
          credit "2300" tax
          effective as_of
        }
    "#;

    #[test]
    fn a_rule_parses_into_its_inputs_and_statements() {
        let rule = parse(SALE).unwrap();
        assert_eq!((rule.name.as_str(), rule.version), ("sale_with_tax", 3));
        assert_eq!(rule.event.0, "Sale");
        assert_eq!(rule.inputs.len(), 2);
        assert!(matches!(rule.inputs[1].ty, SourceType::Amount(ref u, _) if u == "USD"));
        assert_eq!(rule.stmts.len(), 6);
        let Stmt::Let { expr, .. } = &rule.stmts[1] else {
            panic!("second statement is the tax let");
        };
        assert!(
            matches!(expr, Expr::Scale { factors, law: Some((law, _)), .. }
            if factors == &[(true, 7), (false, 100)] && law == "HalfEven")
        );
        let Stmt::Leg { side, dims, .. } = &rule.stmts[2] else {
            panic!("third statement is the receivable leg");
        };
        assert_eq!(*side, Side::Debit);
        assert_eq!(dims[0].0, "cost_center");
        assert!(
            matches!(rule.stmts[5], Stmt::Effective { date: DateRef::Name(ref n), .. } if n == "as_of")
        );
    }

    #[test]
    fn malformed_rules_are_refused_where_they_go_wrong() {
        for (source, line, column, needle) in [
            ("rule r v0 for event Sale {}", 1, 8, "version"),
            ("rule let v1 for event Sale {}", 1, 6, "keyword"),
            (
                "rule r v1 for event Sale { debit \"1\" 5 }",
                1,
                38,
                "bare number",
            ),
            (
                "rule r v1 for event Sale { debit \"1\" x * y }",
                1,
                42,
                "integer",
            ),
            (
                "rule r v1 for event Sale { post \"1\" x }",
                1,
                28,
                "expected `let`",
            ),
            ("rule r v1 for event Sale { debit \"1\" x", 1, 38, "ended"),
            (
                "rule r v1 for event Sale { } extra",
                1,
                30,
                "after the rule",
            ),
            (
                "rule r v1 for event Sale { debit \"1\" event.occurred_on }",
                1,
                44,
                "is a date",
            ),
        ] {
            let error = parse(source).unwrap_err();
            assert_eq!(
                (error.line, error.column),
                (line, column),
                "{source}: {error}"
            );
            assert!(error.message.contains(needle), "{source}: {error}");
        }
    }

    #[test]
    fn nesting_beyond_the_bound_is_refused_not_recursed() {
        let parens = format!(
            "rule r v1 for event Sale {{ debit \"1\" {}x{} }}",
            "(".repeat(70),
            ")".repeat(70)
        );
        let chain = format!(
            "rule r v1 for event Sale {{ debit \"1\" x{} }}",
            " + x".repeat(70)
        );
        for source in [parens, chain] {
            let error = parse(&source).unwrap_err();
            assert!(error.message.contains("nests at most"), "{error}");
        }
        let within = format!(
            "rule r v1 for event Sale {{ debit \"1\" x{} }}",
            " + x".repeat(60)
        );
        assert!(parse(&within).is_ok());
        let many = format!(
            "rule r v1 for event Sale {{ {} }}",
            "let a = x ".repeat(MAX_STATEMENTS + 1)
        );
        assert!(
            parse(&many)
                .unwrap_err()
                .message
                .contains("at most 512 statements")
        );
    }
}
