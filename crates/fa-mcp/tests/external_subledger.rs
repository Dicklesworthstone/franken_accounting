//! External feed transports preserve inline sources and launch-bound authority.

#![forbid(unsafe_code)]

use fa_mcp::registry::McpRegistry;
use fastmcp_rust::json;

#[test]
fn external_detail_is_forwarded_as_an_inline_object_without_host_paths() {
    let registry = fa_cli::verbs::registry().expect("verb registry");
    let mcp = McpRegistry::embedded().expect("MCP registry");
    let tool = mcp.tool_for("subledger", Some("detail")).unwrap();
    assert_eq!(tool.wire_name(), "fa_subledger_detail");
    let detail = json!({
        "feed": "vendor-ap", "batch_key": "march-001", "effective_date": "2026-03-15",
        "rows": [
            {"source_digest": "01".repeat(32), "account": "6000", "side": "debit", "amount": "100.00 USD"},
            {"source_digest": "02".repeat(32), "account": "2000", "side": "credit", "amount": "100.00 USD", "party": "V-1"}
        ]
    });
    let call = tool
        .invocation(&mcp, registry, &json!({"detail": detail.clone()}))
        .unwrap();
    assert_eq!(call.argv, ["subledger", "detail", "--input", "-", "--json"]);
    assert_eq!(call.stdin.as_deref(), Some(detail.to_string().as_bytes()));
    let parsed =
        fa_cli::args::parse(&call.argv, &registry.value_flags(), &registry.switches()).unwrap();
    assert_eq!(
        fa_cli::cli::bound_command_ops("subledger", &parsed)
            .unwrap()
            .iter()
            .map(|op| op.name())
            .collect::<Vec<_>>(),
        ["read"]
    );
    let schema = tool.input_schema(&mcp, registry);
    assert_eq!(schema["properties"]["detail"]["type"], json!("object"));
    for forbidden in ["input_file", "out", "as", "grant"] {
        assert!(schema["properties"].get(forbidden).is_none());
        let mut arguments = json!({"detail": detail.clone()});
        arguments[forbidden] = json!("/private/source");
        assert!(tool.invocation(&mcp, registry, &arguments).is_err());
    }
    for arguments in [json!({}), json!({"detail": "/private/source.json"})] {
        assert!(tool.invocation(&mcp, registry, &arguments).is_err());
    }
}

#[test]
fn external_feed_requires_read_and_post_while_reconciliation_requires_read() {
    let registry = fa_cli::verbs::registry().expect("verb registry");
    let mcp = McpRegistry::embedded().expect("MCP registry");
    let feed = mcp.tool_for("subledger", Some("feed")).unwrap();
    let document = format!("D:{}", "ab".repeat(32));
    let call = feed
        .invocation(
            &mcp,
            registry,
            &json!({
                "document": document, "date": "2026-03-15", "key": "external-001",
                "description": "March vendor batch", "dry_run": true
            }),
        )
        .unwrap();
    assert_eq!(feed.wire_name(), "fa_subledger_feed");
    assert!(call.stdin.is_none());
    let parsed =
        fa_cli::args::parse(&call.argv, &registry.value_flags(), &registry.switches()).unwrap();
    assert_eq!(parsed.positional, ["subledger", "feed"]);
    assert_eq!(parsed.flag("--document"), Some(document.as_str()));
    assert_eq!(parsed.flag("--date"), Some("2026-03-15"));
    assert_eq!(parsed.flag("--key"), Some("external-001"));
    assert_eq!(parsed.flag("--description"), Some("March vendor batch"));
    assert!(parsed.switch("--dry-run"));
    assert_eq!(
        fa_cli::cli::bound_command_ops("subledger", &parsed)
            .unwrap()
            .iter()
            .map(|op| op.name())
            .collect::<Vec<_>>(),
        ["read", "post"]
    );
    assert!(
        feed.invocation(
            &mcp,
            registry,
            &json!({"document": document, "date": "2026-03-15"})
        )
        .is_err(),
        "a stable idempotency key is required"
    );

    let verify = mcp.tool_for("subledger", Some("verify-feed")).unwrap();
    let entry = "01".repeat(16);
    let call = verify
        .invocation(
            &mcp,
            registry,
            &json!({"entry": entry, "as_known_at": "17"}),
        )
        .unwrap();
    assert_eq!(verify.wire_name(), "fa_subledger_verify_feed");
    assert_eq!(
        call.argv,
        [
            "subledger",
            "verify-feed",
            &entry,
            "--as-known-at",
            "17",
            "--json"
        ]
    );
    assert!(call.stdin.is_none());
    let parsed =
        fa_cli::args::parse(&call.argv, &registry.value_flags(), &registry.switches()).unwrap();
    assert_eq!(
        fa_cli::cli::bound_command_ops("subledger", &parsed)
            .unwrap()
            .iter()
            .map(|op| op.name())
            .collect::<Vec<_>>(),
        ["read"]
    );
}

#[test]
fn aggregate_feed_reconciliation_keeps_fixed_scope_and_conditional_certification_authority() {
    let registry = fa_cli::verbs::registry().expect("verb registry");
    let mcp = McpRegistry::embedded().expect("MCP registry");
    let tool = mcp.tool_for("subledger", Some("reconcile-feed")).unwrap();
    assert_eq!(tool.wire_name(), "fa_audit_external_feed");
    for certify in [false, true] {
        let arguments = json!({
            "feed": "vendor-ap", "control": "2000", "as_of": "2026-03-31",
            "as_known_at": "17", "certify": certify
        });
        let call = tool.invocation(&mcp, registry, &arguments).unwrap();
        let parsed =
            fa_cli::args::parse(&call.argv, &registry.value_flags(), &registry.switches()).unwrap();
        assert_eq!(
            parsed.positional,
            ["subledger", "reconcile-feed", "vendor-ap"]
        );
        assert_eq!(parsed.flag("--control"), Some("2000"));
        assert_eq!(parsed.flag("--as-of"), Some("2026-03-31"));
        assert_eq!(parsed.flag("--as-known-at"), Some("17"));
        assert_eq!(parsed.switch("--certify"), certify);
        let ops: Vec<_> = fa_cli::cli::bound_command_ops("subledger", &parsed)
            .unwrap()
            .iter()
            .map(|op| op.name())
            .collect();
        assert_eq!(
            ops,
            if certify {
                vec!["read", "produce"]
            } else {
                vec!["read"]
            }
        );
        assert!(call.stdin.is_none());
    }
    let schema = tool.input_schema(&mcp, registry);
    for forbidden in ["certificate_out", "as", "grant", "input_file"] {
        assert!(schema["properties"].get(forbidden).is_none());
    }
    for arguments in [
        json!({"feed":"vendor-ap", "control":"2000"}),
        json!({"feed":"vendor-ap", "as_of":"2026-03-31"}),
        json!({"control":"2000", "as_of":"2026-03-31"}),
    ] {
        assert!(tool.invocation(&mcp, registry, &arguments).is_err());
    }
}
