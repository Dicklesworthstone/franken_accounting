//! `fa document add` and the intent's evidence citations (plan §9.1–§9.2,
//! bead fa-lp6): the CLI half of Docket intake.
//!
//! A document is recorded once, content-addressed; the `document` event
//! prints the citation an intent carries. An intent cites documents in its
//! `evidence` list — an oid string, or `{document_oid, doc_commit?, role?}` —
//! and `--evidence <oid>` (repeatable) appends citations. The kernel, not the
//! CLI, decides whether a citation names a held document under its exact
//! commitment and whether the class's minimum is met.
//!
//! `fa attest review` (plan §9.3, beads fa-g21/fa-12x) records a reviewer's
//! `Reviewed` attestation over a held document: a self-sourced upload then
//! counts toward the evidence minimum of entries posted after it. `fa attest
//! manual` records the preparer's `ManualAssertion` (plan §9.2) over a
//! planned proposal (`fa post --plan-out`): no document exists, for a
//! registered reason; posting that plan then meets the minimum where the
//! class admits an assertion.

use crate::json::{Json, obj, s};
use fa_journal::evidence::{Document, self_sourced};
use fa_model::{EvidenceRef, Oid};
use fa_policy::{Capability, Op};
use fa_registry::evidence_policy::EvidencePolicy;
use fa_registry::reason_codes::ReasonCodes;

use crate::args::{Args, nearest};
use crate::cli::{Ctx, Fail, hex, principal, read_entry_plan, unhandled, usage};

const ADD_EXAMPLE: &str = "fa document add invoice.pdf --kind Invoice --mime application/pdf --grade HumanUpload --book <dir> --json";
const EVIDENCE_EXAMPLE: &str = r#""evidence": ["<document oid hex>"] or [{"document_oid": "<hex>", "doc_commit": "<hex>", "role": "Source"}], or --evidence <oid>"#;
/// The role a bare oid citation takes.
const DEFAULT_ROLE: &str = "Source";

fn policy() -> Result<EvidencePolicy, Fail> {
    EvidencePolicy::embedded()
        .map_err(|e| Fail::Internal(format!("the embedded evidence policy: {e}")))
}

fn hex32(text: &str, what: &str) -> Result<[u8; 32], Fail> {
    let bad = || {
        usage(
            format!("{what}: `{text}` is not 64 hex digits"),
            "copy the value `fa document add --json` printed",
        )
    };
    if text.len() != 64 || !text.is_ascii() {
        return Err(bad());
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[2 * i..2 * i + 2], 16).map_err(|_| bad())?;
    }
    Ok(out)
}

/// A citation's role as written: a registered name, or its integer tag.
enum Role {
    Name(String),
    Tag(i128),
}

fn role_list(policy: &EvidencePolicy) -> String {
    let roles: Vec<String> = policy
        .roles
        .iter()
        .map(|r| format!("{} ({})", r.name, r.tag))
        .collect();
    format!("role: one of {}", roles.join(", "))
}

fn named(what: &str, given: &str, names: &[&str]) -> Fail {
    usage(
        format!("unknown {what} `{given}`"),
        match nearest(given, names) {
            Some(n) => format!("did you mean `{n}`? ({})", names.join(", ")),
            None => format!("one of: {}", names.join(", ")),
        },
    )
}

/// `fa document add <file|-> [--kind K] [--mime M] [--grade G]`.
pub(crate) fn document_cmd(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    // Dispatch has already refused a subcommand verbs.toml does not register.
    match args.positional.get(1).map(String::as_str) {
        Some("add") => add(ctx, args),
        None => Err(usage("`fa document` needs a subcommand", ADD_EXAMPLE)),
        other => Err(unhandled("document", other)),
    }
}

const REVIEW_EXAMPLE: &str =
    "fa attest review <document oid> --grant approve --as <reviewer> --book <dir> --json";
const MANUAL_EXAMPLE: &str = "fa attest manual --plan <file> --reason NoDocumentIssued --statement \"<who, what, when, why there is no document>\" --book <dir> --json";
/// The reason-code scope of a ManualAssertion (reason_codes.toml).
const MANUAL_SCOPE: &str = "manual_assertion";

/// `fa attest review <document oid> [--against <oid>]...`, or `fa attest
/// manual --plan <file> --reason <code|name> --statement <text>`.
pub(crate) fn attest_cmd(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    // Dispatch has already refused a subcommand verbs.toml does not register.
    match args.positional.get(1).map(String::as_str) {
        Some("review") => review(ctx, args),
        Some("manual") => manual(ctx, args),
        None => Err(usage("`fa attest` needs a subcommand", REVIEW_EXAMPLE)),
        other => Err(unhandled("attest", other)),
    }
}

/// The reviewer's `Reviewed` attestation (plan §9.3). Authority is explicit,
/// like `fa checkpoint create`: the reviewer self-issues `approve` with
/// `--grant approve`, admitted before the book is opened; the kernel then
/// refuses a reviewer who uploaded the document (FA-REF-111) or a document
/// the book does not hold (FA-REF-110). `--against` names the documents the
/// review compared, as a set.
fn review(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    let out = &ctx.out;
    let subject = args.positional.get(2).ok_or_else(|| {
        usage(
            "`fa attest review` needs the document's oid",
            REVIEW_EXAMPLE,
        )
    })?;
    if let Some(extra) = args.positional.get(3) {
        return Err(usage(
            format!("unexpected argument `{extra}`"),
            REVIEW_EXAMPLE,
        ));
    }
    let document = Oid(hex32(subject, "document oid")?);
    let mut against = args
        .flag_all("--against")
        .into_iter()
        .map(|a| hex32(a, "--against").map(Oid))
        .collect::<Result<Vec<Oid>, Fail>>()?;
    against.sort();
    against.dedup();
    let reviewer = principal(args);
    let capability = Capability::embedded(reviewer, &args.flag_all("--grant"))
        .map_err(|e| usage(e.to_string(), REVIEW_EXAMPLE))?;
    // The book is not open yet, so its id (the `books` caveat's subject) is
    // unknown here; a self-issued embedded capability is Human, the
    // reviewer's, and carries no `books` caveat, so admission before the
    // open reduces to the op check. The kernel judges the whole intent.
    fa_policy::require(&capability, Op::Approve, "reviewing a document (`approve`)")
        .map_err(|denial| Fail::Refusal(fa_journal::policy::refusal(&denial)))?;
    let mut book = ctx.books.open(args)?;
    let attested = book.record_review(&capability, &document, against.clone())??;
    out.at_book(&book)?;
    let subject_hex = hex(&document.0);
    out.next(
        format!("fa post --intent <entry.json> --evidence {subject_hex} --json"),
        "an entry citing the reviewed document now counts it toward the evidence minimum",
    );
    out.event(
        "attested",
        vec![
            ("kind", s("Reviewed")),
            ("vid", s(format!("{:032x}", attested.vid.0))),
            ("subject", s(&subject_hex)),
            (
                "against",
                Json::Arr(against.iter().map(|o| s(hex(&o.0))).collect()),
            ),
            ("signed_digest", s(hex(&attested.signed_digest))),
            (
                "recorded_at",
                Json::Int(i128::from(attested.recorded_at.0)),
            ),
            ("already_recorded", Json::Bool(attested.already_recorded)),
        ],
        &if attested.already_recorded {
            format!(
                "document {subject_hex} was already reviewed (attestation {:032x}); nothing new was written",
                attested.vid.0
            )
        } else {
            format!(
                "reviewed document {subject_hex}: attestation {:032x}, recorded at {}; entries citing it now count it toward the evidence minimum",
                attested.vid.0, attested.recorded_at.0
            )
        },
    );
    Ok(())
}

/// The preparer's `ManualAssertion` (plan §9.2) over the proposal a plan
/// file carries: no document exists, for a registered reason (`--reason`, a
/// code or a name from reason_codes.toml), with the particulars in
/// `--statement` (sealed under the book key). The preparer acts under
/// `post`, the capability that will post the proposal; the kernel refuses
/// an unregistered reason (FA-REF-112), a class that admits no assertion,
/// and a principal other than the proposal's.
fn manual(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    let out = &ctx.out;
    if let Some(extra) = args.positional.get(2) {
        return Err(usage(
            format!("unexpected argument `{extra}`"),
            MANUAL_EXAMPLE,
        ));
    }
    let path = args.require("--plan", MANUAL_EXAMPLE)?;
    let reason = args.require("--reason", MANUAL_EXAMPLE)?;
    let statement = args.require("--statement", MANUAL_EXAMPLE)?;
    let reasons = ReasonCodes::embedded()
        .map_err(|e| Fail::Internal(format!("the embedded reason codes: {e}")))?;
    // A number goes to the kernel as given (it refuses an unregistered
    // one); a name must be registered.
    let reason_code = match reason.parse::<u16>() {
        Ok(code) => code,
        Err(_) => {
            let names: Vec<&str> = reasons
                .rows
                .iter()
                .filter(|r| r.scope == MANUAL_SCOPE)
                .map(|r| r.name.as_str())
                .collect();
            reasons
                .rows
                .iter()
                .find(|r| r.scope == MANUAL_SCOPE && r.name == reason)
                .map(|r| r.code)
                .ok_or_else(|| named("reason", reason, &names))?
        }
    };
    let proposal = read_entry_plan(&ctx.files, path)?;
    let digest = proposal
        .proposal_digest()
        .map_err(|e| usage(format!("{path}: {e}"), MANUAL_EXAMPLE))?;
    let mut ops = vec!["post"];
    ops.extend(args.flag_all("--grant"));
    let capability = Capability::embedded(principal(args), &ops)
        .map_err(|e| usage(e.to_string(), MANUAL_EXAMPLE))?;
    let mut book = ctx.books.open(args)?;
    let attested =
        book.record_manual_assertion(&capability, &proposal, reason_code, statement)??;
    out.at_book(&book)?;
    let subject_hex = hex(&digest);
    out.next(
        format!("fa post --plan {path} --json"),
        "posting exactly this proposal now meets its class's evidence minimum",
    );
    let name = reasons
        .get(MANUAL_SCOPE, reason_code)
        .map_or_else(|| reason_code.to_string(), |r| r.name.clone());
    out.event(
        "attested",
        vec![
            ("kind", s("ManualAssertion")),
            ("vid", s(format!("{:032x}", attested.vid.0))),
            ("subject", s(&subject_hex)),
            ("against", Json::Arr(Vec::new())),
            ("signed_digest", s(hex(&attested.signed_digest))),
            (
                "recorded_at",
                Json::Int(i128::from(attested.recorded_at.0)),
            ),
            ("already_recorded", Json::Bool(attested.already_recorded)),
        ],
        &if attested.already_recorded {
            format!(
                "proposal {subject_hex} already carries its ManualAssertion (attestation {:032x}); nothing new was written",
                attested.vid.0
            )
        } else {
            format!(
                "asserted ({name}) that no document exists for proposal {subject_hex}: attestation {:032x}, recorded at {}; post it with `fa post --plan {path}`",
                attested.vid.0, attested.recorded_at.0
            )
        },
    );
    Ok(())
}

fn add(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    let out = &ctx.out;
    let path = args.positional.get(2).ok_or_else(|| {
        usage(
            "`fa document add` needs a file (or - for stdin)",
            ADD_EXAMPLE,
        )
    })?;
    let policy = policy()?;
    let kind_name = args.flag("--kind").unwrap_or("Other");
    let kind = policy.kind_by_name(kind_name).ok_or_else(|| {
        let names: Vec<&str> = policy.kinds.iter().map(|k| k.name.as_str()).collect();
        named("document kind", kind_name, &names)
    })?;
    // An agent is the primary operator: absent a declaration, the honest
    // default is the self-sourced grade, never a human's.
    let grade_name = args.flag("--grade").unwrap_or("AgentUpload");
    let grade = policy.grade_by_name(grade_name).ok_or_else(|| {
        let names: Vec<&str> = policy.grades.iter().map(|g| g.name.as_str()).collect();
        named("provenance grade", grade_name, &names)
    })?;
    let mime = args.flag("--mime").unwrap_or("application/octet-stream");
    let bytes = ctx.files.read_bytes(path)?;
    let mut book = ctx.books.open(args)?;
    let doc = Document {
        book_id: book.context().book_id,
        kind: kind.tag,
        mime: mime.to_string(),
        grade: grade.tag,
        retrieved_by: principal(args),
        bytes,
    };
    let added = book.add_document(&doc)??;
    out.at_book(&book)?;
    // On a repeat intake the book's record stands: report its kind and grade.
    let kind_out = policy
        .kind_by_tag(added.kind)
        .map_or_else(|| added.kind.to_string(), |k| k.name.clone());
    let grade_out = policy
        .grade_by_tag(added.grade)
        .map_or_else(|| added.grade.to_string(), |g| g.name.clone());
    let oid = hex(&added.oid.0);
    let commit = hex(&added.doc_commit);
    let self_sourced = self_sourced(&policy, added.grade);
    out.event(
        "document",
        vec![
            ("oid", s(&oid)),
            ("doc_commit", s(&commit)),
            ("kind", s(&kind_out)),
            ("grade", s(&grade_out)),
            ("self_sourced", Json::Bool(self_sourced)),
            ("size", Json::Int(i128::from(added.size))),
            ("recorded_at", Json::Int(i128::from(added.recorded_at.0))),
            ("already_recorded", Json::Bool(added.already_recorded)),
            (
                "evidence",
                obj(vec![
                    ("document_oid", s(&oid)),
                    ("doc_commit", s(&commit)),
                    ("role", s(DEFAULT_ROLE)),
                ]),
            ),
        ],
        &format!(
            "{} document {oid} ({kind_out}, {grade_out}{}, {} bytes) at {}; cite it with --evidence {oid}",
            if added.already_recorded {
                "already recorded:"
            } else {
                "recorded"
            },
            if self_sourced { ", self-sourced" } else { "" },
            added.size,
            added.recorded_at.0
        ),
    );
    Ok(())
}

/// The intent's `evidence` list plus every `--evidence <oid>`, as the sorted,
/// duplicate-free citations the payload requires. A citation without
/// `doc_commit` (absent or null) takes the commitment of the document the
/// book holds at that oid; an oid the book does not hold is passed through
/// for the kernel to refuse with its own code. A `role` is a registered
/// role name or its integer tag (the form `fa explain` prints), so a copied
/// citation keeps its role; any other value is a usage error, never a
/// silent substitution (review D3).
pub(crate) fn parse_evidence(
    intent: &Json,
    args: &Args,
    book: &fa::book::Book,
) -> Result<Vec<EvidenceRef>, Fail> {
    let policy = policy()?;
    let mut cited: Vec<(String, Option<String>, Role)> = Vec::new();
    if let Some(list) = intent.get("evidence") {
        let items = list
            .as_arr()
            .ok_or_else(|| usage("`evidence` must be a list", EVIDENCE_EXAMPLE))?;
        for (i, item) in items.iter().enumerate() {
            match item {
                Json::Str(oid) => cited.push((oid.clone(), None, Role::Name(DEFAULT_ROLE.into()))),
                Json::Obj(_) => {
                    let oid = item
                        .get("document_oid")
                        .and_then(Json::as_str)
                        .ok_or_else(|| {
                            usage(
                                format!("evidence[{i}]: `document_oid` must be a string"),
                                EVIDENCE_EXAMPLE,
                            )
                        })?;
                    let commit = match item.get("doc_commit") {
                        None | Some(Json::Null) => None,
                        Some(Json::Str(h)) => Some(h.clone()),
                        Some(_) => {
                            return Err(usage(
                                format!("evidence[{i}]: `doc_commit` must be a hex string"),
                                EVIDENCE_EXAMPLE,
                            ));
                        }
                    };
                    let role = match item.get("role") {
                        None | Some(Json::Null) => Role::Name(DEFAULT_ROLE.into()),
                        Some(Json::Str(name)) => Role::Name(name.clone()),
                        Some(Json::Int(tag)) => Role::Tag(*tag),
                        Some(_) => {
                            return Err(usage(
                                format!("evidence[{i}]: `role` must be a role name or its tag"),
                                role_list(&policy),
                            ));
                        }
                    };
                    cited.push((oid.to_string(), commit, role));
                }
                _ => {
                    return Err(usage(
                        format!("evidence[{i}] is neither an oid string nor a citation object"),
                        EVIDENCE_EXAMPLE,
                    ));
                }
            }
        }
    }
    for oid in args.flag_all("--evidence") {
        cited.push((oid.to_string(), None, Role::Name(DEFAULT_ROLE.into())));
    }
    let mut refs = Vec::with_capacity(cited.len());
    for (oid_hex, commit_hex, role) in cited {
        let oid = Oid(hex32(&oid_hex, "evidence document_oid")?);
        let role = match role {
            Role::Name(name) => policy.role_by_name(&name).ok_or_else(|| {
                let names: Vec<&str> = policy.roles.iter().map(|r| r.name.as_str()).collect();
                named("evidence role", &name, &names)
            })?,
            Role::Tag(tag) => u8::try_from(tag)
                .ok()
                .and_then(|t| policy.role_by_tag(t))
                .ok_or_else(|| {
                    usage(
                        format!("evidence role tag {tag} is not registered"),
                        role_list(&policy),
                    )
                })?,
        };
        let doc_commit = match commit_hex {
            Some(h) => hex32(&h, "evidence doc_commit")?,
            None => book
                .read_document(&oid)?
                .map_or([0u8; 32], |d| d.doc_commit()),
        };
        refs.push(EvidenceRef {
            document_oid: oid,
            doc_commit,
            role: role.tag,
        });
    }
    refs.sort_unstable();
    if refs.windows(2).any(|w| w[0] == w[1]) {
        return Err(usage(
            "the same document is cited twice in the same role",
            "cite each document once per role",
        ));
    }
    Ok(refs)
}
