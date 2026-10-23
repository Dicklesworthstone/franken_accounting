//! The optional certificate selects portable report production without
//! exposing caller paths or changing ordinary evidence-bundle invocations.

#![forbid(unsafe_code)]

use fa_mcp::registry::McpRegistry;
use fastmcp_rust::json;

#[test]
fn a_report_certificate_is_forwarded_inline_under_read_and_produce_authority() {
    let registry = fa_cli::verbs::registry().expect("verb registry");
    let mcp = McpRegistry::embedded().expect("MCP registry");
    let tool = mcp.tool_for("bundle", Some("produce")).unwrap();
    let certificate = format!("C:{}", "ab".repeat(32));
    let call = tool
        .invocation(&mcp, registry, &json!({"certificate": certificate}))
        .unwrap();
    assert_eq!(
        call.argv,
        ["bundle", "produce", "--certificate", "-", "--json"]
    );
    assert_eq!(call.stdin.as_deref(), Some(certificate.as_bytes()));
    let parsed =
        fa_cli::args::parse(&call.argv, &registry.value_flags(), &registry.switches()).unwrap();
    assert_eq!(
        fa_cli::cli::bound_command_ops("bundle", &parsed)
            .unwrap()
            .iter()
            .map(|op| op.name())
            .collect::<Vec<_>>(),
        ["read", "produce"]
    );
    let schema = tool.input_schema(&mcp, registry);
    assert_eq!(schema["properties"]["certificate"]["type"], json!("string"));
    assert!(schema["properties"].get("certificate_file").is_none());
    for arguments in [
        json!({"certificate_file": "/private/report.cert"}),
        json!({"certificate_file": null}),
        json!({"certificate": certificate, "grant": "produce"}),
    ] {
        assert!(tool.invocation(&mcp, registry, &arguments).is_err());
    }
    let ordinary = tool.invocation(&mcp, registry, &json!({})).unwrap();
    assert_eq!(ordinary.argv, ["bundle", "produce", "--json"]);
    assert!(ordinary.stdin.is_none());
}
