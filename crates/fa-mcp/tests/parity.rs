//! The MCP parity gate (plan §15.4, AGENTS.md "one verb registry drives
//! CLI, daemon and MCP; a parity gate fails CI when they diverge"; bead
//! fa-xex): every `[[verb]]` and every subcommand the CLI serves is a tool in
//! exactly one cluster, or a registered exclusion with a reason — never
//! neither, never both; no cluster has more than seven tools; every tool
//! names a verb the CLI dispatches; authority and dangerous confirmation
//! stay outside call schemas and normalization. Dangerous operations retain
//! their annotations and planning guidance. Planted defects show the gate fails.
//!
//! The mapping table is printed so a reviewer can read it from the log.

use std::collections::{BTreeMap, BTreeSet};

use fa_cli::verbs::{Registry, registry};
use fa_mcp::registry::{FORBIDDEN_ARGUMENTS, McpRegistry, SOURCE, ToolSpec};
use fastmcp_rust::{JsonValue, json};

fn embedded() -> (McpRegistry, &'static Registry) {
    let reg = registry().expect("verbs.toml");
    (McpRegistry::embedded().expect("verbs.toml [mcp]"), reg)
}

#[test]
fn every_verb_and_subcommand_is_one_tool_or_a_registered_exclusion() {
    let (mcp, reg) = embedded();
    let handled: BTreeSet<&str> = fa_cli::cli::handled_verbs().into_iter().collect();
    let excluded: BTreeSet<(String, Option<String>)> = mcp
        .excluded
        .iter()
        .map(|e| (e.verb.clone(), e.subcommand.clone()))
        .collect();
    let mut table: Vec<String> = Vec::new();
    for v in &reg.verbs {
        assert!(
            handled.contains(v.name.as_str()),
            "the CLI does not dispatch `{}`",
            v.name
        );
        let units: Vec<Option<&str>> = if v.subcommands.is_empty() {
            vec![None]
        } else {
            v.subcommands.iter().map(|s| Some(s.as_str())).collect()
        };
        for sub in units {
            let spelled = sub.map_or_else(|| v.name.clone(), |s| format!("{} {s}", v.name));
            let tools: Vec<&ToolSpec> = mcp
                .tools
                .iter()
                .filter(|t| {
                    t.verb == v.name
                        && match sub {
                            None => t.subcommands.is_empty(),
                            Some(s) => t.subcommands.iter().any(|x| x == s),
                        }
                })
                .collect();
            let is_excluded = excluded.contains(&(v.name.clone(), sub.map(str::to_string)));
            assert!(
                tools.len() == 1 || (tools.is_empty() && is_excluded),
                "`{spelled}`: {} tools, excluded = {is_excluded} (exactly one tool, or one registered exclusion)",
                tools.len()
            );
            assert!(
                !(is_excluded && !tools.is_empty()),
                "`{spelled}` is both a tool and an exclusion"
            );
            table.push(match tools.first() {
                Some(t) => format!("{spelled:<28} -> {}", t.wire_name()),
                None => format!("{spelled:<28} -> (excluded)"),
            });
        }
    }
    // Exclusions are the plan §15.4 host-only families: `fad serve|status|stop`,
    // `fa demo init` (which writes outside a book), and `fa capability revoke`
    // (which requires `--grant issue_capability` and `--yes` on the host).
    // Every exclusion names the reason.
    for e in &mcp.excluded {
        let is_allowed_host_only = e.verb == reg.daemon.binary
            || (e.verb == "demo" && e.subcommand.as_deref() == Some("init"))
            || (e.verb == "capability"
                && matches!(
                    e.subcommand.as_deref(),
                    Some("revoke" | "issue" | "list" | "show")
                ))
            // fa-s7x: promotion needs a principal holding approve who is not
            // the draft's owner, and --yes; no bound session holds either.
            || (e.verb == "draft" && e.subcommand.as_deref() == Some("promote"));
        assert!(
            is_allowed_host_only,
            "only plan §15.4 registered host-only verbs are excluded: {e:?}"
        );
        assert!(e.reason.contains("host-only"), "{e:?}");
        table.push(format!(
            "{} {:<24} -> (excluded: {})",
            e.verb,
            e.subcommand.clone().unwrap_or_default(),
            e.reason
        ));
    }
    for d in &reg.daemon.verbs {
        assert!(
            excluded.contains(&(reg.daemon.binary.clone(), Some(d.clone()))),
            "fad {d} is neither a tool nor excluded"
        );
    }
    println!(
        "fa-mcp parity: {} verbs, {} tools in {} clusters, {} exclusions",
        reg.verbs.len(),
        mcp.tools.len(),
        mcp.clusters.len(),
        mcp.excluded.len()
    );
    for row in &table {
        println!("  {row}");
    }
}

#[test]
fn no_cluster_has_more_than_seven_tools_and_the_limit_is_seven() {
    let (mcp, _) = embedded();
    assert_eq!(
        mcp.max_tools_per_cluster, 7,
        "plan §15.4: clusters of at most seven tools"
    );
    let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
    for t in &mcp.tools {
        *counts.entry(t.cluster.as_str()).or_default() += 1;
    }
    for (c, n) in &counts {
        assert!(*n <= 7, "cluster {c} has {n} tools");
        assert!(mcp.cluster(c).is_some(), "tool cluster {c} is not declared");
    }
    for c in &mcp.clusters {
        assert!(
            counts.contains_key(c.name.as_str()),
            "cluster {} has no tools",
            c.name
        );
    }
    // Plan §15.4: at most 40 tools are exposed by default; an on-demand
    // cluster (`fa-mcp --cluster <name>`) is outside the default surface.
    let total: usize = counts
        .iter()
        .filter(|(c, _)| mcp.cluster(c).is_some_and(|c| !c.on_demand))
        .map(|(_, n)| *n)
        .sum();
    assert_eq!(total, mcp.exposed(&[]).count());
    assert!(
        total <= 40,
        "plan §15.4: at most 40 tools by default, got {total}"
    );
    println!("fa-mcp parity: clusters {counts:?}");
}

#[test]
fn tool_names_and_schemas_are_host_safe_and_registry_derived() {
    let (mcp, reg) = embedded();
    let mut names = BTreeSet::new();
    for t in &mcp.tools {
        let name = t.wire_name();
        assert!(
            !name.is_empty()
                && name.len() <= 64
                && name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-'),
            "{name}"
        );
        assert!(names.insert(name.clone()), "duplicate {name}");
        assert!(name.starts_with(&format!("{}_", t.cluster.replace('.', "_"))));
        let schema = t.input_schema(&mcp, reg);
        assert_eq!(schema["type"], JsonValue::String("object".into()));
        // Was `additionalProperties == false` (fa-23r): `ToolSpec::invocation`,
        // not a closed schema, refuses undeclared keys (proved over stdio).
        assert!(
            schema.get("additionalProperties").is_none(),
            "{name}: a closed schema pre-empts the server's structured refusal"
        );
        let props = schema["properties"].as_object().expect("properties");
        for hidden in &mcp.hidden_flags {
            let prop = fa_mcp::registry::property(hidden);
            assert!(
                !props.contains_key(&prop),
                "{name} exposes the host-only flag {hidden}"
            );
        }
        for property in FORBIDDEN_ARGUMENTS {
            assert!(
                !props.contains_key(*property),
                "{name} exposes `{property}`"
            );
            for value in [JsonValue::Null, json!(false), json!("operator")] {
                let mut arguments = json!({});
                arguments[*property] = value;
                let error = t
                    .invocation(&mcp, reg, &arguments)
                    .expect_err("forbidden authority must precede ordinary argument validation");
                assert!(
                    error.message.contains("forbidden argument"),
                    "{name}: {error:?}"
                );
            }
        }
        let verb = reg.verb(&t.verb).expect("verb");
        for f in &t.flags {
            assert!(
                verb.flags.contains(f),
                "{name}: {f} is not a flag of {}",
                t.verb
            );
            // The flag that is the stdin route's `via` is carried by the stdin
            // property; its `<flag>_file` host-path property is deliberately
            // absent from the schema. A host-path flag (`--plan-out`,
            // `--certificate-out`) has no property at all, by design, and is
            // refused before any observation. Every other flag has its own
            // property.
            let carried_by = match &t.stdin {
                Some(stdin) if &stdin.via == f => stdin.property.clone(),
                _ => t.flag_property(f),
            };
            if t.is_host_path_property(&carried_by) {
                assert!(
                    !props.contains_key(&carried_by),
                    "{name}: exposes the host path {carried_by}"
                );
                continue;
            }
            assert!(
                props.contains_key(&carried_by),
                "{name}: {f} has no property"
            );
        }
        for f in &t.switches {
            assert!(verb.switches.contains(f));
            assert_eq!(
                props[&fa_mcp::registry::property(f)]["type"],
                JsonValue::String("boolean".into())
            );
        }
        for r in schema["required"].as_array().expect("required") {
            let r = r.as_str().expect("a name");
            assert!(
                props.contains_key(r),
                "{name}: required `{r}` is not a property"
            );
        }
        let doc = t.description(&mcp, reg);
        for section in [
            "Do:",
            "Don't:",
            "Discovery:",
            "Examples:",
            "Common mistakes:",
            "Exits:",
            "Returns:",
        ] {
            assert!(doc.contains(section), "{name}: {section} missing");
        }
        assert!(
            doc.contains(&verb.summary) || doc.contains(&format!("`fa {}", t.verb)),
            "{name}: the verb's summary"
        );
    }
    assert_eq!(names.len(), mcp.tools.len());
}

#[test]
fn dangerous_tools_keep_annotations_and_safe_guidance_without_caller_confirmation() {
    let (mcp, reg) = embedded();
    for d in &reg.dangerous {
        if mcp
            .excluded
            .iter()
            .any(|e| e.verb == d.verb && e.subcommand == d.subcommand)
        {
            assert!(mcp.tool_for(&d.verb, d.subcommand.as_deref()).is_none());
            continue;
        }
        let tool = mcp
            .tool_for(&d.verb, d.subcommand.as_deref())
            .unwrap_or_else(|| panic!("no tool covers dangerous {} {:?}", d.verb, d.subcommand));
        assert!(tool.is_dangerous(reg), "{}", tool.wire_name());
        let schema = tool.input_schema(&mcp, reg);
        assert!(
            schema["properties"].get("yes").is_none(),
            "{} exposes confirmation",
            tool.wire_name()
        );
        let doc = tool.description(&mcp, reg);
        assert!(
            doc.contains(&d.safe),
            "{}: Don't names the safe alternative",
            tool.wire_name()
        );
        assert!(
            doc.contains("dangerous confirmation is unavailable"),
            "{doc}"
        );
        assert!(doc.contains("A plan is not confirmation"), "{doc}");
    }
    // Confirmation is absent universally, including ordinary write tools.
    for t in &mcp.tools {
        assert!(
            t.input_schema(&mcp, reg)["properties"].get("yes").is_none(),
            "{}",
            t.wire_name()
        );
    }
}

/// The gate is shown able to fail: planted registries, each with exactly
/// the defect named, are refused with a message naming it.
#[test]
fn the_gate_fails_on_planted_defects() {
    fn plant(edit: impl Fn(&str) -> String) -> Result<McpRegistry, String> {
        let text = edit(SOURCE);
        assert_ne!(text, SOURCE, "the planted edit changed nothing");
        let reg = Registry::parse(&text)?;
        McpRegistry::parse(&text, &reg)
    }
    let read_cluster_row = "[[mcp.cluster]]\nname = \"fa.read\"\ndoc = \"Certified reads over the journal: trial balance, financial statements, an explained balance, open items, one entry.\"\n";
    assert!(
        SOURCE.contains(read_cluster_row),
        "the fa.read cluster row as this test spells it"
    );
    let open_items_header =
        "[[mcp.tool]]\ncluster = \"fa.read\"\nname = \"open_items\"\nverb = \"open-items\"\n";
    let open_items_start = SOURCE
        .find(open_items_header)
        .expect("open-items tool header");
    let open_items_end = open_items_start
        + SOURCE[open_items_start..]
            .find("\n\n")
            .expect("end of open-items tool row")
        + 2;
    let open_items_row = &SOURCE[open_items_start..open_items_end];
    assert_eq!(SOURCE.matches(open_items_row).count(), 1);
    let hidden_line = SOURCE
        .lines()
        .find(|line| line.starts_with("hidden_flags = "))
        .expect("hidden flags");
    let exposed_identity = hidden_line.replace(", \"--as\"", "");
    assert_ne!(hidden_line, exposed_identity);
    // The post tool's own flags line, read from the registry (it grows as
    // posting gains flags), and the same line with a caller grant exposed.
    let post_tool_head = "name = \"post\"\nverb = \"post\"\nsubcommands = []\npositionals = []\n";
    let post_flags = {
        let start = SOURCE.find(post_tool_head).expect("post tool row") + post_tool_head.len();
        let end = start + SOURCE[start..].find('\n').expect("end of post flags line");
        &SOURCE[start..end]
    };
    assert!(post_flags.starts_with("flags = [") && post_flags.ends_with(']'));
    let post_row = format!("{post_tool_head}{post_flags}");
    let granted_row = format!(
        "{post_tool_head}{}, \"--grant\"]",
        &post_flags[..post_flags.len() - 1]
    );
    let cases: Vec<(&str, &str, Result<McpRegistry, String>)> = vec![
        (
            "a verb that is neither a tool nor an exclusion",
            "neither a tool nor",
            plant(|s| s.replacen(open_items_row, "", 1)),
        ),
        (
            "a verb that is both a tool and an exclusion",
            "both a tool and an exclusion",
            plant(|s| {
                s.replace(
                    "[[mcp.excluded]]\nverb = \"fad\"\nsubcommand = \"stop\"",
                    "[[mcp.excluded]]\nverb = \"tb\"",
                )
            }),
        ),
        (
            "a cluster with more than seven tools",
            "at most 7",
            plant(|s| {
                s.replace(read_cluster_row, "")
                    .replace("cluster = \"fa.read\"", "cluster = \"fa.book\"")
            }),
        ),
        (
            "a tool naming a verb the registry lacks",
            "unknown verb",
            plant(|s| s.replace("verb = \"open-items\"", "verb = \"open-item\"")),
        ),
        (
            "a verb covered by two tools",
            "covered by 2 tools",
            plant(|s| {
                s.replace("name = \"period_status\"\nverb = \"period\"\nsubcommands = [\"list\"]", "name = \"period_status\"\nverb = \"period\"\nsubcommands = [\"list\", \"create\"]\nselector = \"which\"")
            }),
        ),
        (
            "authority removed from the hidden flag set",
            "authority flag --as must be hidden",
            plant(|s| s.replacen(hidden_line, &exposed_identity, 1)),
        ),
        (
            "a tool explicitly exposing caller grants",
            "hidden flag --grant cannot be exposed",
            plant(|s| s.replacen(&post_row, &granted_row, 1)),
        ),
    ];
    for (what, expect, result) in cases {
        match result {
            Ok(_) => panic!("{what} was accepted"),
            Err(e) => {
                println!("fa-mcp parity negative: {what}: {e}");
                assert!(e.contains(expect), "{what}: `{e}` does not name `{expect}`");
            }
        }
    }
}
