//! Render an exactly replayed analytic in the existing procedure_run schema.
use crate::cli::{Out, hex};
use crate::json::{Json, obj, s};
use fa_lantern::{Cite, ProcedureRun};

fn cite(value: &Cite) -> Json {
    let mut fields = vec![
        ("entry", Json::Null), ("ordinal", Json::Null), ("account", Json::Null),
        ("period", Json::Null), ("document", Json::Null), ("principal", Json::Null),
        ("approval", Json::Null),
    ];
    let (kind, key, value, ordinal) = match value {
        Cite::Entry(v) => ("entry", "entry", s(format!("{:032x}", v.0)), None),
        Cite::Leg { entry, ordinal } => ("leg", "entry", s(format!("{:032x}", entry.0)), Some(*ordinal)),
        Cite::Account(v) => ("account", "account", s(format!("{:032x}", v.0)), None),
        Cite::Period(p) => ("period", "period", s(p), None),
        Cite::Document(v) => ("document", "document", s(hex(&v.0)), None),
        Cite::Principal(v) => ("principal", "principal", s(format!("{:032x}", v.0)), None),
        Cite::Approval(v) => ("approval", "approval", s(format!("{:032x}", v.0)), None),
    };
    for (name, slot) in &mut fields {
        if *name == key { *slot = value.clone(); }
    }
    if let Some(ordinal) = ordinal { fields[1].1 = Json::Int(i128::from(ordinal)); }
    fields.push(("kind", s(kind)));
    obj(fields)
}

pub(super) fn render(out: &Out, run: &ProcedureRun, digest: &str) {
    out.known_at(run.coordinate.known_at);
    out.effective(run.coordinate.effective_through.map_or_else(
        || "all".into(), |d| format!("through:{}", d.render()),
    ));
    let findings = run.findings.iter().map(|f| obj(vec![
        ("severity", s(f.severity.name())),
        ("statistic", obj(vec![
            ("name", s(&f.statistic.name)), ("value", Json::Int(f.statistic.value)),
            ("scale", Json::Int(i128::from(f.statistic.scale))),
            ("population", Json::Int(i128::from(f.statistic.population))),
        ])),
        ("cites", Json::Arr(f.cites.iter().map(cite).collect())),
        ("narrative", s(&f.narrative)),
    ])).collect();
    let human = run.findings.iter().map(|f| format!(
        "{} {} {}={} {}", f.severity.name(), run.procedure,
        f.statistic.name, f.statistic.value, f.narrative,
    )).collect::<Vec<_>>().join("\n");
    out.event_with_certificate("procedure_run", vec![
        ("procedure", s(&run.procedure)), ("version", Json::Int(i128::from(run.version))),
        ("claim", s(run.claim.name())), ("evidence", s(&run.evidence)),
        ("known_at", Json::Int(i128::from(run.coordinate.known_at.0))),
        ("effective_through", run.coordinate.effective_through.map_or(Json::Null, |d| s(d.render()))),
        ("parameters", Json::Arr(run.parameters.iter().map(|(k,v)| obj(vec![("name", s(k)), ("value", Json::Int(*v))])).collect())),
        ("inputs", Json::Arr(run.inputs.iter().map(|(k,v)| obj(vec![("name", s(k)), ("value", s(v))])).collect())),
        ("parameters_digest", s(hex(&run.parameters_digest))),
        ("inputs_digest", s(hex(&run.inputs_digest))),
        ("population", Json::Int(i128::from(run.population))),
        ("work", obj(vec![
            ("entries", Json::Int(i128::from(run.work.entries))),
            ("legs", Json::Int(i128::from(run.work.legs))),
            ("comparisons", Json::Int(i128::from(run.work.comparisons))),
        ])),
        ("findings", Json::Arr(findings)),
        ("finding_count", Json::Int(run.findings.len() as i128)),
        ("findings_digest", s(hex(&run.findings_digest))),
    ], &format!(
        "Replayed {} at sequence {}: {} finding(s)\n{human}",
        run.procedure, run.coordinate.known_at.0, run.findings.len(),
    ), Some(digest));
}
