//! Load errors: every problem in a case's files, with its file and line.
//!
//! A load never stops at the first error. Every error is collected and the
//! list is sorted by (file, line), so an author sees all of a file's
//! problems in one run.

use core::fmt;

/// What is wrong.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LoadErrorKind {
    /// The TOML subset refused the text (fa-registry's parser, its line).
    Toml,
    /// A required field is absent.
    MissingField,
    /// A field no schema of this row declares (a misspelling is never
    /// silently ignored).
    UnknownField,
    /// A field has the wrong type or does not parse under its grammar.
    WrongType,
    /// A value outside its closed set.
    UnknownValue,
    /// A fact row carries fields of two provenance kinds (plan §2.1).
    TwoProvenanceKinds,
    /// A foreign key names nothing.
    DanglingKey,
    /// A field that must be 64 lower-case hex characters is not.
    NotSha256Hex,
    /// A receipt disagrees with the fact or source it binds.
    ReceiptMismatch,
    /// Two rows share an id (or a key that must be unique).
    DuplicateId,
    /// An intent's declared legs do not balance per unit (A1b).
    Unbalanced,
    /// An intent or step names a period the variant does not declare, or a
    /// date no declared period contains.
    UnknownPeriod,
    /// A label that keys a runner map (a period code, a checkpoint, an
    /// entity) is declared twice.
    DuplicateLabel,
    /// A reversing, restating, revising or reclassifying intent without its
    /// `target` and `target_kind`.
    TargetRequired,
    /// A text longer than its registered limit (`registries/limits.toml`).
    TooLong,
    /// A book file whose stem is not `<kind>[-<suffix>]`, or whose
    /// `[book] variant` differs from its stem (plan §3.2b).
    BadStem,
    /// An intent id that breaks the naming rules of plan §3.2b.
    BadId,
    /// An authored id of a form the runner generates (`<case>-SELF-<variant>`,
    /// `<case>-CASE-<case id>`, `<case>-N-90`; A1c).
    ReservedId,
    /// An expected value on a field the verdict projection always excludes
    /// (plan §5.4).
    ExcludedField,
    /// A `[[note]]` that names a verdict field (plan §5.1: a note has no
    /// verdict).
    NoteWithVerdict,
    /// A P row that states its exit: the exit is the refusal catalog's
    /// (plan §5.2).
    ExitIsCatalogs,
    /// A D or P row every component of which is X: it can neither pass nor
    /// fail, so it is a `[[note]]`.
    AllComponentsX,
    /// A claimed expectation with a pending cell (plan §5.1).
    PendingClaimed,
    /// T or R read fields on both the expectation and its targets.
    ReadFieldsTwice,
}

impl fmt::Display for LoadErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

/// One problem: `<file>:<line>: <kind>: <detail>`, with the row id when the
/// row has one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LoadError {
    pub file: String,
    pub line: Option<usize>,
    pub kind: LoadErrorKind,
    pub row: Option<String>,
    pub detail: String,
}

impl fmt::Display for LoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.line {
            Some(line) => write!(f, "{}:{line}: {}: ", self.file, self.kind)?,
            None => write!(f, "{}: {}: ", self.file, self.kind)?,
        }
        if let Some(row) = &self.row {
            write!(f, "row `{row}`: ")?;
        }
        f.write_str(&self.detail)
    }
}

impl core::error::Error for LoadError {}

/// Sorts errors by (file, line, kind, detail), the order they are reported in.
pub fn sort(errors: &mut [LoadError]) {
    errors.sort_by(|a, b| {
        (&a.file, a.line, a.kind, &a.detail).cmp(&(&b.file, b.line, b.kind, &b.detail))
    });
}
