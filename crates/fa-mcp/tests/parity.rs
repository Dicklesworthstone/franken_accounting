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
use fa_mcp::registry::{FORBIDDEN_ARGUMENTS, MACROS, McpRegistry, SOURCE, ToolSpec};
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
            || (e.verb == "draft" && e.subcommand.as_deref() == Some("promote"))
            // fa-lzrn: replacing a party's bank identifiers is the plan
            // §14.4 business-email-compromise vector; a Human operator does
            // it on the host, never a launch-bound session.
            || (e.verb == "party" && e.subcommand.as_deref() == Some("identifiers"))
            // The reviewed closing map and intrinsic close need schema_change
            // or close, outside both launch templates and issued-token ceilings.
            || (e.verb == "close"
                && matches!(e.subcommand.as_deref(), Some("map" | "year-end")))
            // Releasing a bank claim requires explicit Human host confirmation.
            || (e.verb == "bank" && e.subcommand.as_deref() == Some("unmatch"))
            // fa-lzrn: a fetch runs the host's `fwc` connector subprocess with
            // the host's connector credentials; MCP imports a saved payload
            // inline through fa_bank_import (bank_format plaid-sync).
            || (e.verb == "bank" && e.subcommand.as_deref() == Some("fetch"))
            // Attesting a statement close needs an independently authorized
            // Human, full-source authority and --yes (8e7ee49); sessions read
            // verified closes through fa_bank_reconciliation.
            || (e.verb == "bank" && e.subcommand.as_deref() == Some("reconcile"))
            // Leg-projection and outcome-namespace recovery (fa-nl7) need
            // schema_change on trunk, outside both launch templates and
            // issued-token ceilings, and --yes.
            || (e.verb == "recover"
                && matches!(e.subcommand.as_deref(), Some("projections" | "outcomes")))
            // fa-qtfd: a witness cosigns with its own key file on the host
            // (and witness-key writes a new secret key file there); no
            // launch template or issued-token ceiling holds witness.
            || (e.verb == "checkpoint"
                && matches!(e.subcommand.as_deref(), Some("witness" | "witness-key")))
            // fa-6l9: a production writes its volume (load files and
            // natives) into a new host directory, like `fa demo init`; MCP
            // output is inline only. Its profiles stay MCP tools.
            || (e.verb == "produce" && e.subcommand.is_none())
            // fa-75j4: a restatement case's writes need restate, outside
            // both launch templates and issued-token ceilings; sessions
            // read cases through fa_case_read.
            || (e.verb == "case"
                && matches!(
                    e.subcommand.as_deref(),
                    Some("open" | "determine" | "rehearse" | "approve" | "post" | "disclose" | "close")
                ))
            // fa-k07b: the receiver's fork needs receivership, Human
            // authority outside both launch templates and issued-token
            // ceilings (plan §14.4); sessions read the branch as a scenario.
            || (e.verb == "book" && e.subcommand.as_deref() == Some("fork"))
            // fa-lzrn: verifying an export reads a file or ADS directory on
            // the host; MCP exports are inline, never host files.
            || (e.verb == "verify" && e.subcommand.as_deref() == Some("export"))
            // fa-i7e: a void releases a hold for good and needs --yes, which
            // no MCP session carries; fa_post_resolve is the safe path.
            || (e.verb == "void-reserve" && e.subcommand.is_none())
            // fa-c34: a rule's golden corpus is a host directory of case
            // files (like an export verify, fa-lzrn); MCP evaluates a rule
            // over a recorded event inline through fa_rules_rule.
            || (e.verb == "rule" && e.subcommand.as_deref() == Some("test"));
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
        total + MACROS.len() <= 40,
        "plan §15.4: at most 40 tools by default, including {} macros, got {}",
        MACROS.len(),
        total + MACROS.len(),
    );
    for cluster in ["fa.evidence", "fa.forensics", "fa.proof"] {
        assert!(mcp.cluster(cluster).unwrap().on_demand);
        assert!(mcp.exposed(&[]).all(|tool| tool.cluster != cluster));
        assert_eq!(
            mcp.exposed(&[cluster.into()]).count(),
            total + mcp.tools_of(cluster).count(),
            "the entire {cluster} surface remains available on demand",
        );
    }
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

#[test]
fn closing_reads_lower_to_exact_history_and_mutations_remain_host_only() {
    let (mcp, reg) = embedded();
    assert!(mcp.cluster("fa.close").unwrap().on_demand);
    // routes, verify, the draft review (5082454) and the consolidation
    // (fa-76hy) are the closing reads.
    assert_eq!(mcp.tools_of("fa.close").count(), 4);
    assert_eq!(
        mcp.tool_for("close", Some("dry-run")).unwrap().wire_name(),
        "fa_close_dry_run"
    );
    let routes = mcp.tool_for("close", Some("routes")).unwrap();
    assert_eq!(routes.wire_name(), "fa_close_routes");
    let route_args = json!({"as_of": "2026-12-31", "as_known_at": "17"});
    let route_call = routes.invocation(&mcp, reg, &route_args).unwrap();
    assert_eq!(
        route_call.argv,
        vec![
            "close",
            "routes",
            "--as-of",
            "2026-12-31",
            "--as-known-at",
            "17",
            "--json"
        ]
    );
    assert!(route_call.stdin.is_none());
    assert!(routes.invocation(&mcp, reg, &json!({})).is_err());
    let translated = mcp
        .command_to_call(
            reg,
            "fa close routes --as-of 2026-12-31 --as-known-at 17 --json",
        )
        .unwrap();
    assert_eq!(translated.tool, "fa_close_routes");
    assert_eq!(translated.arguments, route_args);

    let verify = mcp.tool_for("verify", Some("close")).unwrap();
    assert_eq!(verify.wire_name(), "fa_close_verify");
    let verify_args = json!({"fiscal_year": "FY2026", "as_known_at": "17"});
    let verification = verify.invocation(&mcp, reg, &verify_args).unwrap();
    assert_eq!(
        verification.argv,
        vec!["verify", "close", "FY2026", "--as-known-at", "17", "--json"]
    );
    assert!(verification.stdin.is_none());
    let schema = verify.input_schema(&mcp, reg);
    assert_eq!(schema["properties"]["fiscal_year"]["type"], json!("string"));
    assert!(schema["properties"].get("period").is_none());
    assert!(verify.invocation(&mcp, reg, &json!({})).is_err());
    let translated = mcp
        .command_to_call(reg, "fa verify close FY2026 --as-known-at 17 --json")
        .unwrap();
    assert_eq!(translated.tool, "fa_close_verify");
    assert_eq!(translated.arguments, verify_args);

    let consolidate = mcp.tool_for("consolidate", None).unwrap();
    assert_eq!(consolidate.wire_name(), "fa_close_consolidate");
    let consolidate_args = json!({"period": "FY2026-P03", "as_known_at": "17"});
    let consolidation = consolidate
        .invocation(&mcp, reg, &consolidate_args)
        .unwrap();
    assert_eq!(
        consolidation.argv,
        vec![
            "consolidate",
            "--period",
            "FY2026-P03",
            "--as-known-at",
            "17",
            "--json"
        ]
    );
    assert!(consolidation.stdin.is_none());
    assert!(consolidate.invocation(&mcp, reg, &json!({})).is_err());

    for (call, operations) in [
        (&route_call, &["read"][..]),
        (&verification, &["read", "verify"][..]),
        (&consolidation, &["read"][..]),
    ] {
        let parsed = fa_cli::args::parse(&call.argv, &reg.value_flags(), &reg.switches()).unwrap();
        let admitted = fa_cli::cli::bound_command_ops(&call.argv[0], &parsed).unwrap();
        assert_eq!(
            admitted.iter().map(|op| op.name()).collect::<Vec<_>>(),
            operations
        );
    }
    for subcommand in ["map", "year-end"] {
        assert!(mcp.tool_for("close", Some(subcommand)).is_none());
        assert!(mcp.excluded.iter().any(|excluded| {
            excluded.verb == "close"
                && excluded.subcommand.as_deref() == Some(subcommand)
                && excluded.reason.contains("host-only")
        }));
    }
    for profile in [
        fa_cli::authority::LaunchProfile::Agent,
        fa_cli::authority::LaunchProfile::Preparer,
    ] {
        for operation in ["schema_change", "close", "approve"] {
            assert!(!profile.ceiling().iter().any(|op| op.name() == operation));
        }
    }
}

#[test]
fn fx_routes_lower_repeated_typed_destinations_and_preserve_operation_authority() {
    let (mcp, reg) = embedded();
    assert!(mcp.cluster("fa.fx").unwrap().on_demand);
    let names: BTreeSet<_> = mcp.tools_of("fa.fx").map(ToolSpec::wire_name).collect();
    assert_eq!(
        names,
        BTreeSet::from([
            "fa_fx_rate".to_string(),
            "fa_fx_routes".to_string(),
            "fa_fx_revalue".to_string(),
        ])
    );
    assert!(mcp.exposed(&[]).all(|tool| tool.cluster != "fa.fx"));
    assert_eq!(
        mcp.exposed(&["fa.fx".into()]).count(),
        mcp.exposed(&[]).count() + 3,
    );

    let routes = mcp.tool_for("fx", Some("routes")).unwrap();
    let arguments = json!({
        "action": "set", "route": ["1200:1290:4900", "2200:2290:6900"],
        "effective_from": "2026-01-01", "key": "fx-routing-v1",
    });
    let invocation = routes.invocation(&mcp, reg, &arguments).unwrap();
    assert!(invocation.stdin.is_none());
    let parsed =
        fa_cli::args::parse(&invocation.argv, &reg.value_flags(), &reg.switches()).unwrap();
    assert_eq!(parsed.positional, vec!["fx", "routes", "set"]);
    assert_eq!(
        parsed.flag_all("--route"),
        vec!["1200:1290:4900", "2200:2290:6900"]
    );
    assert_eq!(parsed.flag("--effective-from"), Some("2026-01-01"));
    assert_eq!(parsed.flag("--key"), Some("fx-routing-v1"));
    assert_eq!(
        fa_cli::cli::bound_command_ops("fx", &parsed)
            .unwrap()
            .iter()
            .map(|op| op.name())
            .collect::<Vec<_>>(),
        vec!["read", "schema_change"]
    );
    let authority = fa_cli::authority::LaunchAuthority::new(
        std::path::PathBuf::from("/unused-fx-book"),
        None,
        "fx-agent",
        fa_cli::authority::LaunchProfile::Agent,
        &[],
    )
    .unwrap();
    let denied = fa_cli::cli::bound_command_admissible(reg, "fx", &parsed, &authority)
        .expect_err("a route array must not confer schema_change authority");
    assert!(denied.contains("schema_change"), "{denied}");
    let translated = mcp
        .command_to_call(
            reg,
            "fa fx routes set --route 1200:1290:4900 --route 2200:2290:6900 --effective-from 2026-01-01 --key fx-routing-v1 --json",
        )
        .unwrap();
    assert_eq!(translated.tool, "fa_fx_routes");
    assert_eq!(translated.arguments, arguments);

    let schema = routes.input_schema(&mcp, reg);
    assert_eq!(
        schema["properties"]["route"]["type"],
        json!(["string", "array"])
    );
    assert_eq!(
        schema["properties"]["route"]["items"]["type"],
        json!("string")
    );
    for route in [json!(["1200:1290:4900", 2]), json!(12), json!([null])] {
        assert!(
            routes
                .invocation(&mcp, reg, &json!({"action": "set", "route": route}))
                .is_err()
        );
    }
    let show_args = json!({"action": "show", "as_of": "2026-03-31", "as_known_at": "17"});
    let show = routes.invocation(&mcp, reg, &show_args).unwrap();
    let parsed = fa_cli::args::parse(&show.argv, &reg.value_flags(), &reg.switches()).unwrap();
    assert_eq!(parsed.positional, vec!["fx", "routes", "show"]);
    assert_eq!(parsed.flag("--as-known-at"), Some("17"));
    assert_eq!(
        fa_cli::cli::bound_command_admissible(reg, "fx", &parsed, &authority)
            .unwrap()
            .iter()
            .map(|op| op.name())
            .collect::<Vec<_>>(),
        vec!["read"]
    );
}

#[test]
fn fx_revaluation_previews_are_typed_and_do_not_supply_host_paths_or_commit_confirmation() {
    let (mcp, reg) = embedded();
    let revalue = mcp.tool_for("fx", Some("revalue")).unwrap();
    assert_eq!(revalue.wire_name(), "fa_fx_revalue");
    let schema = revalue.input_schema(&mcp, reg);
    for property in ["review_only", "dry_run"] {
        assert_eq!(schema["properties"][property]["type"], json!("boolean"));
    }
    assert_eq!(schema["properties"]["review"]["type"], json!("string"));
    let authority = fa_cli::authority::LaunchAuthority::new(
        std::path::PathBuf::from("/unused-fx-book"),
        None,
        "fx-agent",
        fa_cli::authority::LaunchProfile::Agent,
        &[],
    )
    .unwrap();
    let selectors = json!({
        "period": "FY2026-P03", "account": "1200",
        "rate": format!("D:{}", "ab".repeat(32)), "key": "review-fx",
    });
    for preview in ["review_only", "dry_run"] {
        let mut arguments = selectors.clone();
        arguments[preview] = json!(true);
        let invocation = revalue.invocation(&mcp, reg, &arguments).unwrap();
        assert!(invocation.stdin.is_none());
        let parsed =
            fa_cli::args::parse(&invocation.argv, &reg.value_flags(), &reg.switches()).unwrap();
        assert_eq!(parsed.positional, vec!["fx", "revalue"]);
        assert_eq!(parsed.flag("--period"), Some("FY2026-P03"));
        assert!(parsed.switch(&format!("--{}", preview.replace('_', "-"))));
        assert!(!parsed.switch("--yes"));
        assert_eq!(
            fa_cli::cli::bound_command_admissible(reg, "fx", &parsed, &authority)
                .unwrap()
                .iter()
                .map(|op| op.name())
                .collect::<Vec<_>>(),
            vec!["read", "post"]
        );
        arguments[preview] = json!("true");
        assert!(revalue.invocation(&mcp, reg, &arguments).is_err());
    }

    let invocation = revalue.invocation(&mcp, reg, &selectors).unwrap();
    let parsed =
        fa_cli::args::parse(&invocation.argv, &reg.value_flags(), &reg.switches()).unwrap();
    let denied = fa_cli::cli::bound_command_admissible(reg, "fx", &parsed, &authority)
        .expect_err("selecting a rate does not independently confirm a commit");
    assert!(denied.contains("FA-REF-007"), "{denied}");
    for property in ["review_out", "plan_out"] {
        assert!(schema["properties"].get(property).is_none());
        for value in [json!("/outside-launch-root/fx-review"), JsonValue::Null] {
            let mut arguments = selectors.clone();
            arguments["review_only"] = json!(true);
            arguments[property] = value;
            let refused = revalue.invocation(&mcp, reg, &arguments).unwrap_err();
            assert!(
                refused.message.contains("host filesystem argument"),
                "{refused:?}"
            );
            assert!(refused.message.contains(property), "{refused:?}");
        }
    }
    assert!(schema["properties"].get("yes").is_none());
    assert!(
        mcp.command_to_call(
            reg,
            "fa fx revalue --review-out /private/review --review-only"
        )
        .is_none()
    );
    assert!(
        mcp.command_to_call(reg, "fa fx revalue --dry-run --plan-out /private/plan")
            .is_none()
    );
}

#[test]
fn bank_history_preserves_existing_tools_and_keeps_unmatch_host_only() {
    let (mcp, reg) = embedded();
    assert!(mcp.cluster("fa.bank").unwrap().on_demand);
    let history = mcp.tool_for("bank", Some("history")).unwrap();
    assert_eq!(history.wire_name(), "fa_bank_history");
    assert!(!history.is_dangerous(reg));
    let manifest = "ab".repeat(32);
    let arguments = json!({
        "account": "1000", "import": manifest, "as_known_at": "17",
    });
    let invocation = history.invocation(&mcp, reg, &arguments).unwrap();
    assert!(invocation.stdin.is_none());
    let parsed =
        fa_cli::args::parse(&invocation.argv, &reg.value_flags(), &reg.switches()).unwrap();
    assert_eq!(parsed.positional, vec!["bank", "history"]);
    assert_eq!(parsed.flag("--account"), Some("1000"));
    assert_eq!(parsed.flag("--import"), Some(manifest.as_str()));
    assert_eq!(parsed.flag("--as-known-at"), Some("17"));
    assert_eq!(
        fa_cli::cli::bound_command_ops("bank", &parsed)
            .map(|ops| ops.iter().map(|op| op.name()).collect::<Vec<_>>()),
        Some(vec!["read", "reconcile"]),
    );
    let translated = mcp
        .command_to_call(
            reg,
            &format!("fa bank history --account 1000 --import {manifest} --as-known-at 17 --json"),
        )
        .unwrap();
    assert_eq!(translated.tool, "fa_bank_history");
    assert_eq!(translated.arguments, arguments);

    let schema = history.input_schema(&mcp, reg);
    for property in ["account", "import", "as_known_at"] {
        assert_eq!(schema["properties"][property]["type"], json!("string"));
    }
    for property in ["file", "text", "yes", "grant", "principal", "profile"] {
        assert!(schema["properties"].get(property).is_none(), "{property}");
    }
    for forbidden in [
        json!({"grant": ["privileged"]}),
        json!({"yes": true}),
        json!({"text": "governed source bytes"}),
        json!({"file": "/outside-launch-root/bank.csv"}),
    ] {
        assert!(history.invocation(&mcp, reg, &forbidden).is_err());
    }

    for (subcommand, wire) in [("confirm", "fa_bank_confirm"), ("status", "fa_bank_status")] {
        let tool = mcp.tool_for("bank", Some(subcommand)).unwrap();
        assert_eq!(tool.wire_name(), wire);
        assert!(!tool.is_dangerous(reg));
        assert!(!mcp.excluded.iter().any(|excluded| {
            excluded.verb == "bank" && excluded.subcommand.as_deref() == Some(subcommand)
        }));
    }
    assert!(mcp.tool_for("bank", Some("unmatch")).is_none());
    assert!(mcp.excluded.iter().any(|excluded| {
        excluded.verb == "bank"
            && excluded.subcommand.as_deref() == Some("unmatch")
            && excluded.reason.contains("host-only")
    }));
    assert!(reg.dangerous.iter().any(|dangerous| {
        dangerous.verb == "bank" && dangerous.subcommand.as_deref() == Some("unmatch")
    }));
}

/// Advertised setup tools that no `[[bound]]` rule names yet. They are
/// refused on every launch, Human included; whether each gets a rule or a
/// registered exclusion is fa-mg2j's open acceptance ("each advertised tool
/// is usable under at least one launch profile or is a registered
/// exclusion"). This list only shrinks.
const UNNAMED_BY_A_BOUND_RULE: &[(&str, &str)] = &[
    ("book", "create"),
    ("chart", "import"),
    ("period", "create"),
];

/// A tool no `[[bound]]` rule names is refused on every launch-bound session
/// ("not admitted by the launch-bound MCP command surface"): it is dead.
/// `sample` (fa-kaf7) shipped that way, after the seven dead tools of the
/// 2026-10-14 audit. Every advertised tool's verb and subcommand is named by
/// at least one rule; the rule's flag conditions may still narrow it.
#[test]
fn every_advertised_tool_is_named_by_a_bound_rule() {
    let (mcp, reg) = embedded();
    let mut unnamed = Vec::new();
    for tool in &mcp.tools {
        let subcommands: Vec<Option<&str>> = if tool.subcommands.is_empty() {
            vec![None]
        } else {
            tool.subcommands.iter().map(|s| Some(s.as_str())).collect()
        };
        for sub in subcommands {
            let named = reg.bound.iter().any(|rule| {
                rule.verbs.contains(&tool.verb)
                    && (rule.subcommands.is_empty()
                        || sub.is_some_and(|s| rule.subcommands.iter().any(|r| r == s)))
            });
            if !named {
                unnamed.push((tool.verb.clone(), sub.unwrap_or_default().to_string()));
            }
        }
    }
    let known: Vec<(String, String)> = UNNAMED_BY_A_BOUND_RULE
        .iter()
        .map(|(verb, sub)| ((*verb).to_string(), (*sub).to_string()))
        .collect();
    assert_eq!(
        unnamed, known,
        "advertised tools no [[bound]] rule names: give each a rule, or register an [[mcp.excluded]] row"
    );
}

#[test]
fn functional_statement_mcp_preserves_basis_comparatives_and_certificate_authority() {
    let (mcp, reg) = embedded();
    let tool = mcp.tool_for("statement", None).unwrap();
    assert_eq!(tool.wire_name(), "fa_read_statement");
    let schema = tool.input_schema(&mcp, reg);
    assert_eq!(schema["properties"]["functional"]["type"], json!("boolean"));
    assert!(schema["properties"].get("certificate_out").is_none());
    let args = json!({
        "name": "balance-sheet", "functional": true, "for": "FY2026-P02",
        "compare": "FY2026-P01", "as_known_at": "17", "certify": true,
    });
    let invocation = tool.invocation(&mcp, reg, &args).unwrap();
    let parsed =
        fa_cli::args::parse(&invocation.argv, &reg.value_flags(), &reg.switches()).unwrap();
    assert!(parsed.switch("--functional"));
    assert!(parsed.switch("--certify"));
    assert_eq!(parsed.flag("--compare"), Some("FY2026-P01"));
    assert_eq!(parsed.flag("--as-known-at"), Some("17"));
    let required = fa_cli::cli::bound_command_ops("statement", &parsed).unwrap();
    assert_eq!(
        required.iter().map(|op| op.name()).collect::<Vec<_>>(),
        ["read", "produce"]
    );
    let translated = mcp.command_to_call(reg,
        "fa statement balance-sheet --functional --for FY2026-P02 --compare FY2026-P01 --as-known-at 17 --certify --json").unwrap();
    assert_eq!(translated.tool, tool.wire_name());
    assert_eq!(translated.arguments, args);
    let plain = tool
        .invocation(
            &mcp,
            reg,
            &json!({"name": "income-statement", "for": "FY2026-P02", "functional": true}),
        )
        .unwrap();
    let parsed = fa_cli::args::parse(&plain.argv, &reg.value_flags(), &reg.switches()).unwrap();
    assert_eq!(
        fa_cli::cli::bound_command_ops("statement", &parsed)
            .unwrap()
            .iter()
            .map(|op| op.name())
            .collect::<Vec<_>>(),
        ["read"]
    );
}
