//! End to end over stdio (beads fa-xex/fa-23r): the real `fa-mcp` binary is started
//! on a temp book and spoken to as an MCP host would — newline-delimited
//! JSON-RPC on its stdin/stdout — through `server/discover`, `tools/list`,
//! `tools/call` and `resources/read`. Every tool result's first content
//! block must equal, byte for byte, the `data` payload the CLI's own front
//! door (`fa_cli::entry::fa`, the function the `fa` binary's `main` calls)
//! prints for an operation admitted by the launch authority. Agent trunk
//! posting and caller-selected authority must be refused without publication.
//!
//! Every request and response is printed with the prefix `fa-mcp-e2e:` so a
//! reader can grep the transcript; the last line is the verdict.

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use fa_cli::json::Json;
use fastmcp_rust::{JsonValue, json};

const PROTOCOL: &str = "2026-07-28";
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(180);

fn log(line: impl AsRef<str>) {
    println!("fa-mcp-e2e: {}", line.as_ref());
}

fn tmp(name: &str) -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    loop {
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let d = std::env::temp_dir().join(format!("fa-mcp-{}-{name}-{n}", std::process::id()));
        match std::fs::create_dir(&d) {
            Ok(()) => return d,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => panic!("create {}: {e}", d.display()),
        }
    }
}

/// The CLI's front door, captured: exit code and stdout. A non-zero exit
/// logs its one `error` line so a fixture refusal is readable in the log.
fn cli(args: &[&str]) -> (u8, String) {
    let argv: Vec<String> = args.iter().map(|a| (*a).to_string()).collect();
    let (code, out) = fa_cli::entry::fa(&argv, true);
    log(format!("cli  $ fa {} -> exit {code}", args.join(" ")));
    if code != 0 {
        log(format!(
            "cli    {}",
            out.stdout.lines().last().unwrap_or("")
        ));
    }
    (code, out.stdout)
}

/// Record a source document and return its oid: the evidence an Original
/// entry must cite (`evidence_policy.toml`: `min_documents = 1`).
fn source_document(dir: &Path, book: &str) -> String {
    let file = dir.join("source.txt");
    std::fs::write(&file, "INVOICE (fa-mcp e2e source document)").unwrap();
    let data = cli_data(&[
        "document",
        "add",
        &file.display().to_string(),
        "--kind",
        "Invoice",
        "--grade",
        "HumanUpload",
        "--book",
        book,
        "--json",
    ]);
    let doc = fa_cli::json::parse(&data).expect("document data");
    let oid = doc
        .get("oid")
        .and_then(Json::as_str)
        .expect("oid")
        .to_string();
    assert_eq!(oid.len(), 64, "{data}");
    oid
}

/// The `data` payload of the CLI's one robot line, canonical.
fn cli_data(args: &[&str]) -> String {
    let (code, stdout) = cli(args);
    assert_eq!(code, 0, "fa {}:\n{stdout}", args.join(" "));
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(lines.len(), 1, "one robot line:\n{stdout}");
    let line = fa_cli::json::parse(lines[0]).expect("a robot line");
    line.get("data").expect("data").render()
}

struct Mcp {
    child: Child,
    stdin: Option<ChildStdin>,
    rx: mpsc::Receiver<String>,
    next_id: u64,
}

impl Mcp {
    fn start(book: &Path) -> Self {
        Self::start_with(book, &[])
    }

    fn start_with(book: &Path, launch: &[&str]) -> Self {
        log(format!(
            "spawn {} --book {} {}",
            env!("CARGO_BIN_EXE_fa-mcp"),
            book.display(),
            launch.join(" "),
        ));
        let mut child = Command::new(env!("CARGO_BIN_EXE_fa-mcp"))
            .args(["--book", &book.display().to_string()])
            .args(launch)
            .env_remove("FA_BOOK")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("spawn fa-mcp");
        let stdin = child.stdin.take().expect("piped stdin");
        let stdout = child.stdout.take().expect("piped stdout");
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                match line {
                    Ok(l) => {
                        if tx.send(l).is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        });
        Self {
            child,
            stdin: Some(stdin),
            rx,
            next_id: 0,
        }
    }

    fn discover(&mut self) -> JsonValue {
        let discovery = self.result("server/discover", json!({}));
        assert_eq!(discovery["supportedVersions"], json!([PROTOCOL]));
        assert_eq!(
            discovery["_meta"]["io.modelcontextprotocol/serverInfo"]["name"],
            json!("fa-mcp"),
            "{discovery}"
        );
        discovery
    }

    fn send(&mut self, message: &JsonValue) {
        let text = message.to_string();
        log(format!("->   {text}"));
        let stdin = self.stdin.as_mut().expect("stdin open");
        stdin.write_all(text.as_bytes()).expect("write");
        stdin.write_all(b"\n").expect("write");
        stdin.flush().expect("flush");
    }

    /// Send one request and wait for its response (notifications are logged
    /// and skipped). Returns the whole response object.
    fn request(&mut self, method: &str, mut params: JsonValue) -> JsonValue {
        params["_meta"] = json!({
            "io.modelcontextprotocol/protocolVersion": PROTOCOL,
            "io.modelcontextprotocol/clientCapabilities": {},
        });
        self.request_raw(method, params)
    }

    fn request_raw(&mut self, method: &str, params: JsonValue) -> JsonValue {
        self.next_id += 1;
        let id = self.next_id;
        self.send(&json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}));
        let started = Instant::now();
        loop {
            let remaining = RESPONSE_TIMEOUT
                .checked_sub(started.elapsed())
                .unwrap_or_default();
            let line = self.rx.recv_timeout(remaining).unwrap_or_else(|e| {
                panic!("no response to {method} (id {id}) within {RESPONSE_TIMEOUT:?}: {e}")
            });
            let shown = if line.len() > 600 {
                let mut end = 600;
                while !line.is_char_boundary(end) {
                    end -= 1;
                }
                format!("{}… ({} bytes)", &line[..end], line.len())
            } else {
                line.clone()
            };
            log(format!("<-   {shown}"));
            let v: JsonValue = fastmcp_rust::serde_json::from_str(&line)
                .unwrap_or_else(|e| panic!("not JSON ({e}): {line}"));
            if v.get("id") == Some(&json!(id)) {
                return v;
            }
        }
    }

    fn result(&mut self, method: &str, params: JsonValue) -> JsonValue {
        let response = self.request(method, params);
        assert!(
            response.get("error").is_none(),
            "{method} failed: {response}"
        );
        assert_eq!(response["result"]["resultType"], "complete", "{response}");
        if method == "resources/read" {
            assert_eq!(response["result"]["ttlMs"], 0, "{response}");
            assert_eq!(response["result"]["cacheScope"], "private", "{response}");
        }
        response["result"].clone()
    }

    /// Close stdin and wait for the process to end; its exit code.
    fn finish(mut self) -> i32 {
        drop(self.stdin.take());
        let started = Instant::now();
        loop {
            if let Some(status) = self.child.try_wait().expect("try_wait") {
                return status.code().unwrap_or(-1);
            }
            if started.elapsed() > Duration::from_secs(30) {
                let _ = self.child.kill();
                let _ = self.child.wait();
                panic!("fa-mcp did not exit within 30 s of stdin closing");
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

impl Drop for Mcp {
    fn drop(&mut self) {
        // A failed assertion must not leave this test's server running.
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

/// A tool call's outcome: the first content block's text and `isError`.
fn call_tool(mcp: &mut Mcp, name: &str, arguments: JsonValue) -> (bool, String, JsonValue) {
    let result = mcp.result("tools/call", json!({"name": name, "arguments": arguments}));
    let is_error = result
        .get("isError")
        .and_then(JsonValue::as_bool)
        .unwrap_or(false);
    let content = result["content"].as_array().expect("content");
    assert!(!content.is_empty(), "{name}: empty content: {result}");
    assert_eq!(content[0]["type"], json!("text"), "{result}");
    let text = content[0]["text"].as_str().expect("text").to_string();
    (is_error, text, result)
}

fn structured_error(text: &str) -> JsonValue {
    let v: JsonValue = fastmcp_rust::serde_json::from_str(text)
        .unwrap_or_else(|e| panic!("not a structured error ({e}): {text}"));
    for key in [
        "type",
        "message",
        "recoverable",
        "fix_hint",
        "suggested_tool_calls",
        "exit",
        "refusal_id",
        "cite",
        "detail",
        "authority",
    ] {
        assert!(
            v.get(key).is_some(),
            "structured error lacks `{key}`: {text}"
        );
    }
    v
}

#[test]
fn financial_statements_and_retained_replay_use_the_same_agent_bound_surface() {
    let dir = tmp("statements");
    let book = dir.join("book");
    let b = book.display().to_string();
    cli_data(&[
        "book",
        "create",
        "--book",
        &b,
        "--name",
        "Statement MCP",
        "--json",
    ]);
    let chart = dir.join("chart.json");
    std::fs::write(&chart, r#"{"accounts":[{"code":"1000","name":"Cash","type":"Asset","unit":"USD"},{"code":"6000","name":"Rent","type":"Expense","unit":"USD"}]}"#).unwrap();
    cli_data(&[
        "chart",
        "import",
        chart.to_str().unwrap(),
        "--book",
        &b,
        "--json",
    ]);
    cli_data(&[
        "period",
        "create",
        "--fiscal-year",
        "2026",
        "--book",
        &b,
        "--json",
    ]);
    cli_data(&["period", "open", "FY2026-P03", "--book", &b, "--json"]);
    let oid = source_document(&dir, &b);
    let intent = dir.join("rent.json");
    std::fs::write(&intent, r#"{"idempotency_key":"statement-rent","effective_date":"2026-03-15","legs":[{"side":"debit","account":"6000","amount":"10.00 USD"},{"side":"credit","account":"1000","amount":"10.00 USD"}]}"#).unwrap();
    cli_data(&[
        "post",
        "--intent",
        intent.to_str().unwrap(),
        "--evidence",
        &oid,
        "--book",
        &b,
        "--json",
    ]);
    let expected = cli_data(&[
        "statement",
        "income-statement",
        "--for",
        "FY2026-P03",
        "--compare",
        "FY2026-P02",
        "--book",
        &b,
        "--json",
    ]);
    let mut mcp = Mcp::start(&book);
    mcp.discover();
    let (error, output, metadata) = call_tool(
        &mut mcp,
        "fa_read_statement",
        json!({
            "name": "income-statement", "for": "FY2026-P03", "compare": "FY2026-P02",
        }),
    );
    assert!(!error, "{output}");
    assert_eq!(output, expected);
    let envelope: JsonValue =
        fastmcp_rust::serde_json::from_str(metadata["content"][1]["text"].as_str().unwrap())
            .unwrap();
    assert_eq!(envelope["events"], json!(["statement"]));
    assert_eq!(envelope["authority"]["profile"], json!("agent"));
    let (error, output, _) = call_tool(
        &mut mcp,
        "fa_read_statement",
        json!({
            "name": "balance-sheet", "for": "FY2026-P03", "compare": "FY2026-P02", "certify": true,
        }),
    );
    assert!(!error, "{output}");
    let certified: JsonValue = fastmcp_rust::serde_json::from_str(&output).unwrap();
    assert_eq!(certified.as_array().unwrap().len(), 2);
    assert_eq!(certified[0]["columns"].as_array().unwrap().len(), 2);
    assert_eq!(certified[1]["file"], JsonValue::Null);
    let replay_oid = format!("C:{}", certified[1]["oid"].as_str().unwrap());
    for certificate in [
        replay_oid,
        certified[1]["bytes"].as_str().unwrap().to_string(),
    ] {
        let (error, replay, _) = call_tool(
            &mut mcp,
            "fa_read_replay",
            json!({"certificate": certificate}),
        );
        assert!(!error, "{replay}");
        assert_eq!(replay, certified[0].to_string());
    }
    let (error, output, _) = call_tool(
        &mut mcp,
        "fa_read_statement",
        json!({
            "name": "balance-sheet", "for": "FY2026-P03", "certificate_out": null,
        }),
    );
    assert!(error, "{output}");
    let denied = structured_error(&output);
    assert_eq!(denied["type"], json!("forbidden_path"));
    assert_eq!(denied["authority"]["profile"], json!("agent"));
    // The default reader cannot acquire produce authority from a certify flag.
    for (tool, args) in [
        (
            "fa_read_trial_balance",
            json!({"period": "FY2026-P03", "summary": true, "certify": true}),
        ),
        (
            "fa_proof_gl",
            json!({"view": "roll-forward", "account": "1000", "from": "2026-03-01", "to": "2026-03-31", "certify": true}),
        ),
        (
            "fa_proof_gl",
            json!({"view": "aging", "as_of": "2026-03-31", "certify": true}),
        ),
    ] {
        let (error, output, _) = call_tool(&mut mcp, tool, args);
        assert!(error, "{output}");
        let refused = structured_error(&output);
        assert_eq!(refused["refusal_id"], json!("FA-REF-011"));
        assert!(output.contains("produce"), "{output}");
    }
    assert_eq!(mcp.finish(), 0);

    let mut producer = Mcp::start_with(&book, &["--grant", "read", "--grant", "produce"]);
    producer.discover();
    for (tool, family, event_name, args) in [
        (
            "fa_read_trial_balance",
            "summary",
            "summary_trial_balance",
            json!({"period": "FY2026-P03", "summary": true, "root": ["1000"], "certify": true}),
        ),
        (
            "fa_proof_gl",
            "roll-forward",
            "roll_forward",
            json!({"view": "roll-forward", "account": "1000", "from": "2026-03-01", "to": "2026-03-31", "certify": true}),
        ),
        (
            "fa_proof_gl",
            "roll-forward",
            "general_ledger",
            json!({"view": "detail", "account": "1000", "unit": "USD", "from": "2026-03-01", "to": "2026-03-31", "label": "MCP March detail", "certify": true}),
        ),
        (
            "fa_proof_gl",
            "effective-date-aging",
            "aging",
            json!({"view": "aging", "account": "1000", "as_of": "2026-03-31", "bucket": ["0", "30", "60"], "certify": true}),
        ),
    ] {
        let (error, output, metadata) = call_tool(&mut producer, tool, args);
        assert!(!error, "{family}: {output}");
        let certified: JsonValue = fastmcp_rust::serde_json::from_str(&output).unwrap();
        assert_eq!(certified.as_array().unwrap().len(), 2);
        assert_eq!(certified[1]["file"], JsonValue::Null);
        let envelope: JsonValue =
            fastmcp_rust::serde_json::from_str(metadata["content"][1]["text"].as_str().unwrap())
                .unwrap();
        assert_eq!(
            envelope["events"],
            json!([event_name, "report_certificate"])
        );
        assert_eq!(envelope["certificate"], certified[1]["oid"]);
        for certificate in [
            format!("C:{}", certified[1]["oid"].as_str().unwrap()),
            certified[1]["bytes"].as_str().unwrap().to_string(),
        ] {
            let mut replay_args = if event_name == "general_ledger" {
                json!({
                    "certificate": certificate,
                    "view": "detail",
                    "account": "1000",
                    "unit": "USD",
                    "from": "2026-03-01",
                    "to": "2026-03-31",
                    "label": "MCP March detail",
                    "as_known_at": certified[0]["known_at"].to_string(),
                })
            } else {
                json!({"certificate": certificate})
            };
            let (error, output, metadata) =
                call_tool(&mut producer, "fa_read_replay", replay_args.clone());
            assert!(!error, "{family}: {output}");
            let replayed: JsonValue = fastmcp_rust::serde_json::from_str(&output).unwrap();
            assert_eq!(replayed[0], certified[0]);
            assert_eq!(replayed[1]["family"], json!(family));
            assert_eq!(replayed[1]["output_digest"], certified[1]["output_digest"]);
            let envelope: JsonValue = fastmcp_rust::serde_json::from_str(
                metadata["content"][1]["text"].as_str().unwrap(),
            )
            .unwrap();
            assert_eq!(envelope["events"], json!([event_name, "report_replayed"]));
            if event_name == "general_ledger" {
                let mut conflicting = replay_args.clone();
                conflicting["expect"] = json!("{}");
                let (error, output, metadata) =
                    call_tool(&mut producer, "fa_read_replay", conflicting);
                assert!(error, "conflicting detail request: {output}");
                assert!(output.contains("separate request formats"), "{output}");
                assert_eq!(metadata["content"].as_array().unwrap().len(), 1);
                replay_args["account"] = json!("6000");
                let (error, output, metadata) =
                    call_tool(&mut producer, "fa_read_replay", replay_args);
                assert!(error, "changed detail scope: {output}");
                assert_eq!(structured_error(&output)["refusal_id"], json!("FA-REF-150"));
                assert_eq!(metadata["content"].as_array().unwrap().len(), 1);
            }
        }
    }
    assert_eq!(producer.finish(), 0);
}

#[test]
fn the_server_over_stdio_matches_the_cli_byte_for_byte_on_data() {
    let dir = tmp("e2e");
    let book = dir.join("book");
    let b = book.display().to_string();
    // A real book with a chart, a fiscal year, an open period and one entry,
    // all through the CLI's front door.
    assert_eq!(
        cli(&[
            "book", "create", "--book", &b, "--name", "MCP E2E", "--json"
        ])
        .0,
        0
    );
    let chart = dir.join("chart.json");
    std::fs::write(
        &chart,
        r#"{"accounts":[{"code":"1000","name":"Cash","type":"Asset","leaf":true,"unit":"USD"},{"code":"6000","name":"Rent","type":"Expense","leaf":true,"unit":"USD"}]}"#,
    )
    .unwrap();
    assert_eq!(
        cli(&[
            "chart",
            "import",
            &chart.display().to_string(),
            "--book",
            &b,
            "--json"
        ])
        .0,
        0
    );
    assert_eq!(
        cli(&[
            "period",
            "create",
            "--fiscal-year",
            "2026",
            "--book",
            &b,
            "--json"
        ])
        .0,
        0
    );
    assert_eq!(
        cli(&["period", "open", "FY2026-P03", "--book", &b, "--json"]).0,
        0
    );
    let entry = dir.join("entry.json");
    std::fs::write(
        &entry,
        r#"{"class":"Original","effective_date":"2026-03-15","description":"March rent","idempotency_key":"inv-1001","legs":[{"side":"debit","account":"6000","amount":"1500.00 USD"},{"side":"credit","account":"1000","amount":"1500.00 USD"}]}"#,
    )
    .unwrap();
    let oid = source_document(&dir, &b);
    assert_eq!(
        cli(&[
            "post",
            "--intent",
            &entry.display().to_string(),
            "--evidence",
            &oid,
            "--book",
            &b,
            "--json"
        ])
        .0,
        0
    );

    // This parity test deliberately uses the trusted Preparer template;
    // default Agent behavior is exercised separately below.
    let mut mcp = Mcp::start_with(&book, &["--profile", "preparer", "--principal", "operator"]);
    mcp.discover();

    // tools/list: exactly the registry's default-surface wire names (plan
    // §15.4: on-demand clusters need `--cluster`), each with an object schema.
    let registry = fa_mcp::registry::McpRegistry::embedded().expect("[mcp]");
    let expected: std::collections::BTreeSet<String> = registry
        .exposed(&[])
        .map(fa_mcp::registry::ToolSpec::wire_name)
        .chain(
            fa_mcp::registry::MACROS
                .iter()
                .map(fa_mcp::registry::MacroSpec::wire_name),
        )
        .collect();
    let mut listed = std::collections::BTreeSet::new();
    let mut cursor: Option<String> = None;
    loop {
        let params = cursor
            .as_ref()
            .map_or_else(|| json!({}), |c| json!({"cursor": c}));
        let page = mcp.result("tools/list", params);
        for tool in page["tools"].as_array().expect("tools") {
            let name = tool["name"].as_str().expect("name").to_string();
            assert_eq!(tool["inputSchema"]["type"], json!("object"), "{name}");
            if name == "fa_post_reverse" {
                assert!(
                    tool["inputSchema"]["required"]
                        .as_array()
                        .unwrap()
                        .contains(&json!("reason")),
                    "reversals require the registered reason: {tool}"
                );
            }
            for argument in fa_mcp::registry::FORBIDDEN_ARGUMENTS {
                assert!(
                    tool["inputSchema"]["properties"].get(*argument).is_none(),
                    "{name} exposes {argument}"
                );
            }
            assert!(
                tool["description"]
                    .as_str()
                    .is_some_and(|d| d.contains("Do:")),
                "{name}"
            );
            if matches!(
                name.as_str(),
                "fa_read_trial_balance" | "fa_read_explain_balance" | "fa_read_open_items"
            ) {
                assert_eq!(
                    tool["inputSchema"]["properties"]["certify"]["type"],
                    json!("boolean")
                );
                assert!(
                    tool["inputSchema"]["properties"]
                        .get("certificate_out")
                        .is_none(),
                    "MCP report certificates are returned inline"
                );
            }
            listed.insert(name);
        }
        match page.get("nextCursor").and_then(JsonValue::as_str) {
            Some(c) => cursor = Some(c.to_string()),
            None => break,
        }
    }
    assert_eq!(listed, expected, "tools/list differs from the registry");
    log(format!(
        "tools/list: {} tools, all registry wire names",
        listed.len()
    ));

    // Discovery shares the catalogue while declaring the actual binding.
    let (is_error, text, _) = call_tool(&mut mcp, "fa_orient_capabilities", json!({}));
    assert!(!is_error, "{text}");
    let mut actual: JsonValue = fastmcp_rust::serde_json::from_str(&text).unwrap();
    let mut expected: JsonValue =
        fastmcp_rust::serde_json::from_str(&cli_data(&["capabilities", "--json"])).unwrap();
    assert_eq!(
        actual["capability"]["binding"]["posture"],
        "mcp-launch-config"
    );
    assert_eq!(actual["capability"]["binding"]["flags"], json!([]));
    assert_eq!(
        expected["capability"]["binding"]["posture"],
        "embedded-owner"
    );
    actual["capability"]["binding"] = JsonValue::Null;
    expected["capability"]["binding"] = JsonValue::Null;
    assert_eq!(
        actual, expected,
        "capability catalogue differs beyond launch binding"
    );
    log("fa_orient_capabilities: same catalogue, actual launch-bound authority");

    // fa.read: the trial balance of the open period — equals the CLI's data.
    let (is_error, text, result) = call_tool(
        &mut mcp,
        "fa_read_trial_balance",
        json!({"period": "FY2026-P03"}),
    );
    assert!(!is_error, "{text}");
    let expected = cli_data(&["tb", "--period", "FY2026-P03", "--book", &b, "--json"]);
    assert_eq!(
        text, expected,
        "fa_read_trial_balance != fa tb --json (data)"
    );
    assert!(
        text.contains("\"1500.00 USD\""),
        "the posted entry is in the trial balance: {text}"
    );
    let envelope: JsonValue = fastmcp_rust::serde_json::from_str(
        result["content"][1]["text"].as_str().expect("envelope"),
    )
    .expect("envelope JSON");
    assert_eq!(envelope["events"], json!(["trial_balance"]));
    assert_eq!(
        envelope["authority"],
        json!({
            "posture": "mcp-launch-config", "principal": "operator", "profile": "preparer",
            "ops": ["read", "post", "verify"],
        })
    );
    assert!(envelope["coordinate"]["known_at"].is_number(), "{envelope}");
    assert_eq!(
        envelope["coordinate"]["effective"],
        json!("period:FY2026-P03"),
        "{envelope}"
    );
    log("fa_read_trial_balance == fa tb --period FY2026-P03 --json: byte-identical data");

    // The real MCP transport reaches the same incremental maintainer as
    // the CLI. A subsequent no-op has byte-identical data on both surfaces.
    let (is_error, text, result) = call_tool(
        &mut mcp,
        "fa_book_advance_registers",
        json!({"period": "FY2026-P03"}),
    );
    assert!(!is_error, "{text}");
    let advanced: JsonValue = fastmcp_rust::serde_json::from_str(&text).unwrap();
    assert_eq!(advanced["entries"], json!(1));
    assert_eq!(advanced["cells"], json!(2));
    assert_eq!(advanced["wrote"], json!(true));
    assert_eq!(advanced["rebuilt"], json!(false));
    let envelope: JsonValue =
        fastmcp_rust::serde_json::from_str(result["content"][1]["text"].as_str().unwrap()).unwrap();
    assert_eq!(envelope["events"], json!(["registers_advanced"]));
    let (is_error, no_op, _) = call_tool(
        &mut mcp,
        "fa_book_advance_registers",
        json!({"period": "FY2026-P03"}),
    );
    assert!(!is_error, "{no_op}");
    let data: JsonValue = fastmcp_rust::serde_json::from_str(&no_op).unwrap();
    assert_eq!(data["wrote"], json!(false));
    assert_eq!(data["recorded_at"], JsonValue::Null);
    assert_eq!(data["entries_decoded"], json!(0));
    assert_eq!(
        no_op,
        cli_data(&[
            "registers",
            "advance",
            "--period",
            "FY2026-P03",
            "--book",
            &b,
            "--json"
        ])
    );
    let (is_error, verified, _) = call_tool(
        &mut mcp,
        "fa_book_verify",
        json!({"target": "registers", "period": "FY2026-P03"}),
    );
    assert!(!is_error, "{verified}");
    log(
        "fa_book_advance_registers: maintained, independently verified, then byte-identical CLI no-op",
    );

    // A write through the server: the entry is recorded (same key: `recorded`).
    let intent: JsonValue =
        fastmcp_rust::serde_json::from_str(&std::fs::read_to_string(&entry).unwrap()).unwrap();
    let (is_error, text, _) = call_tool(
        &mut mcp,
        "fa_post_post",
        json!({"intent": intent, "evidence": [oid]}),
    );
    assert!(!is_error, "{text}");
    let recorded: JsonValue = fastmcp_rust::serde_json::from_str(&text).unwrap();
    let vid = recorded["vid"].as_str().expect("vid").to_string();
    let (is_error, text, _) = call_tool(&mut mcp, "fa_read_show_entry", json!({"vid": vid}));
    assert!(!is_error, "{text}");
    assert_eq!(
        text,
        cli_data(&["entry", "show", &vid, "--book", &b, "--json"])
    );
    log(
        "fa_post_post (same idempotency key) -> recorded; fa_read_show_entry == fa entry show --json",
    );

    // Retain a real certified report through the MCP transport. Inline bytes
    // satisfy replay's input without creating a host file or looking up an oid.
    let (is_error, text, result) = call_tool(
        &mut mcp,
        "fa_read_trial_balance",
        json!({"period": "FY2026-P03", "certify": true}),
    );
    assert!(!is_error, "{text}");
    let certified: JsonValue = fastmcp_rust::serde_json::from_str(&text).unwrap();
    assert_eq!(
        certified.as_array().unwrap().len(),
        2,
        "report and certificate"
    );
    let certified_report = certified[0].to_string();
    assert_eq!(
        certified_report,
        cli_data(&[
            "tb",
            "--period",
            "FY2026-P03",
            "--as-known-at",
            &certified[1]["known_at"].to_string(),
            "--book",
            &b,
            "--json",
        ])
    );
    let certificate_hex = certified[1]["bytes"].as_str().unwrap().to_string();
    let certificate_oid = certified[1]["oid"].as_str().unwrap().to_string();
    assert_eq!(certificate_oid.len(), 64);
    assert_eq!(certified[1]["file"], JsonValue::Null);
    assert_eq!(certified[1]["replay_scope"], json!("fa-fold-over-prefix"));
    assert_eq!(certified[1]["authority"], json!("embedded-owner"));
    assert!(certified[1]["recorded_at"].as_u64() > certified[1]["known_at"].as_u64());
    let envelope: JsonValue =
        fastmcp_rust::serde_json::from_str(result["content"][1]["text"].as_str().unwrap()).unwrap();
    assert_eq!(
        envelope["events"],
        json!(["trial_balance", "report_certificate"])
    );
    assert_eq!(envelope["certificate"], json!(certificate_oid));
    let (is_error, replayed, result) = call_tool(
        &mut mcp,
        "fa_read_replay",
        json!({"certificate": certificate_hex}),
    );
    assert!(!is_error, "{replayed}");
    assert_eq!(replayed, certified_report);
    let replay_envelope: JsonValue =
        fastmcp_rust::serde_json::from_str(result["content"][1]["text"].as_str().unwrap()).unwrap();
    assert_eq!(replay_envelope["events"], json!(["trial_balance"]));
    assert_eq!(replay_envelope["certificate"], json!(certificate_oid));
    assert_eq!(replay_envelope["coordinate"], envelope["coordinate"]);
    for digest in [&certificate_oid, &format!("C:{certificate_oid}")] {
        let (is_error, replayed, _) =
            call_tool(&mut mcp, "fa_read_replay", json!({"certificate": digest}));
        assert!(!is_error, "{replayed}");
        assert_eq!(replayed, certified_report);
    }
    let (is_error, status, _) = call_tool(
        &mut mcp,
        "fa_read_certificate_status",
        json!({"certificate": certificate_oid}),
    );
    assert!(!is_error, "{status}");
    let current: JsonValue = fastmcp_rust::serde_json::from_str(&status).unwrap();
    assert_eq!(current["status"], json!("Current"));
    assert_eq!(current["later_entries"], json!([]));

    // The other report families use the same retained-object transport and
    // retain their original account/period snapshot across subsequent writes.
    let original_known_at = certified[1]["known_at"].to_string();
    let mut generic_certificates = Vec::new();
    for (wire, arguments, command, event, output_format) in [
        (
            "fa_read_explain_balance",
            json!({"account": "1000", "period": "FY2026-P03", "as_known_at": original_known_at, "certify": true}),
            vec!["explain", "balance", "1000", "--period", "FY2026-P03"],
            "balance_explained",
            "fa:balance-explanation:v1",
        ),
        (
            "fa_read_open_items",
            json!({"account": "1000", "as_known_at": original_known_at, "certify": true}),
            vec!["open-items", "--account", "1000"],
            "open_items",
            "fa:open-items:v1",
        ),
    ] {
        let (is_error, text, result) = call_tool(&mut mcp, wire, arguments);
        assert!(!is_error, "{wire}: {text}");
        let data: JsonValue = fastmcp_rust::serde_json::from_str(&text).unwrap();
        assert_eq!(data.as_array().unwrap().len(), 2);
        let oid = data[1]["oid"].as_str().unwrap().to_string();
        assert_eq!(data[1]["output_format"], json!(output_format));
        assert_eq!(data[1]["known_at"], certified[1]["known_at"]);
        assert_eq!(data[1]["file"], JsonValue::Null);
        let report_text = data[0].to_string();
        let mut comparable = data[0].clone();
        if event == "balance_explained" {
            assert_eq!(comparable["certificate"], json!(oid));
            comparable["certificate"] = JsonValue::Null;
        }
        let mut plain = command;
        plain.extend([
            "--as-known-at",
            original_known_at.as_str(),
            "--book",
            b.as_str(),
            "--json",
        ]);
        let expected: JsonValue = fastmcp_rust::serde_json::from_str(&cli_data(&plain)).unwrap();
        assert_eq!(comparable, expected, "{wire}: original report parity");
        let envelope: JsonValue =
            fastmcp_rust::serde_json::from_str(result["content"][1]["text"].as_str().unwrap())
                .unwrap();
        assert_eq!(envelope["events"], json!([event, "report_certificate"]));
        assert_eq!(envelope["certificate"], json!(oid));
        for certificate in [oid.clone(), data[1]["bytes"].as_str().unwrap().to_string()] {
            let (is_error, replayed, result) = call_tool(
                &mut mcp,
                "fa_read_replay",
                json!({"certificate": certificate}),
            );
            assert!(!is_error, "{replayed}");
            assert_eq!(replayed, report_text);
            let replay_envelope: JsonValue =
                fastmcp_rust::serde_json::from_str(result["content"][1]["text"].as_str().unwrap())
                    .unwrap();
            assert_eq!(replay_envelope["events"], json!([event]));
            assert_eq!(replay_envelope["coordinate"], envelope["coordinate"]);
        }
        let (is_error, status, _) = call_tool(
            &mut mcp,
            "fa_read_certificate_status",
            json!({"certificate": oid}),
        );
        assert!(!is_error, "{status}");
        let status: JsonValue = fastmcp_rust::serde_json::from_str(&status).unwrap();
        assert_eq!(status["status"], json!("Current"));
        assert_eq!(status["later_entries"], json!([]));
        generic_certificates.push((oid, report_text, envelope["coordinate"].clone()));
    }
    for (wire, arguments) in [
        (
            "fa_read_explain_balance",
            json!({"account": "9999", "period": "FY2026-P03", "certify": true}),
        ),
        (
            "fa_read_open_items",
            json!({"account": "9999", "certify": true}),
        ),
    ] {
        let (is_error, text, _) = call_tool(&mut mcp, wire, arguments);
        assert!(
            is_error,
            "{wire}: unknown account cannot become an empty certified report"
        );
        assert_eq!(structured_error(&text)["exit"], json!(2), "{text}");
    }

    // The typed reversal is the same law-enforced correction as the CLI:
    // missing and unknown reasons cannot post, and the persisted lineage
    // records the exact registered name/code the caller selected.
    // The final protocol returns a tool error for schema validation. The
    // advertised schema above requires reason; rejection must not post.
    let before_missing = cli_data(&["book", "info", "--book", &b, "--json"]);
    let (is_error, text, _) = call_tool(&mut mcp, "fa_post_reverse", json!({"vid": vid}));
    assert!(
        is_error,
        "missing reason must be refused before dispatch: {text}"
    );
    assert_eq!(
        text,
        "Tool arguments do not match the declared input schema."
    );
    assert_eq!(
        cli_data(&["book", "info", "--book", &b, "--json"]),
        before_missing
    );
    let (is_error, text, _) = call_tool(
        &mut mcp,
        "fa_post_reverse",
        json!({"vid": vid, "reason": "WrongAcount"}),
    );
    assert!(is_error, "unregistered reason: {text}");
    let e = structured_error(&text);
    assert_eq!(e["refusal_id"], json!("FA-REF-054"), "{e}");
    assert!(
        e["fix_hint"].as_str().unwrap().contains("WrongAccount"),
        "{e}"
    );
    let (is_error, text, _) = call_tool(
        &mut mcp,
        "fa_post_reverse",
        json!({"vid": vid, "reason": "WrongAccount"}),
    );
    assert!(!is_error, "{text}");
    let reversed: JsonValue = fastmcp_rust::serde_json::from_str(&text).unwrap();
    assert_eq!(reversed["target"], json!(vid), "{reversed}");
    assert_eq!(reversed["reason_code"], json!(2), "{reversed}");
    assert_eq!(reversed["reason"], json!("WrongAccount"), "{reversed}");
    let reversal_vid = reversed["vid"].as_str().unwrap();
    let (is_error, text, _) =
        call_tool(&mut mcp, "fa_read_show_entry", json!({"vid": reversal_vid}));
    assert!(!is_error, "{text}");
    assert_eq!(
        text,
        cli_data(&["entry", "show", reversal_vid, "--book", &b, "--json"])
    );
    let shown: JsonValue = fastmcp_rust::serde_json::from_str(&text).unwrap();
    assert_eq!(shown["supersedes"][0]["reason"], json!("WrongAccount"));
    assert_eq!(shown["supersedes"][0]["reason_code"], json!(2));
    let (is_error, text, _) = call_tool(
        &mut mcp,
        "fa_post_reverse",
        json!({"vid": vid, "reason": "WrongAccount"}),
    );
    assert!(!is_error, "retry: {text}");
    let retried: JsonValue = fastmcp_rust::serde_json::from_str(&text).unwrap();
    assert_eq!(retried["vid"], reversed["vid"]);
    assert_eq!(retried["entry_digest"], reversed["entry_digest"]);
    log("fa_post_reverse: reason refusals, exact retry and persisted lineage agree with the CLI");

    let (is_error, status, _) = call_tool(
        &mut mcp,
        "fa_read_certificate_status",
        json!({"certificate": certificate_hex}),
    );
    assert!(!is_error, "{status}");
    let later: JsonValue = fastmcp_rust::serde_json::from_str(&status).unwrap();
    assert_eq!(later["status"], json!("SupersededBy"));
    assert_eq!(later["later_entries"], json!([reversal_vid]));
    assert_eq!(later["known_at"], current["known_at"]);
    let (is_error, replayed, _) = call_tool(
        &mut mcp,
        "fa_read_replay",
        json!({"certificate": certificate_hex}),
    );
    assert!(!is_error, "{replayed}");
    assert_eq!(
        replayed, certified_report,
        "later reversal leaves original report replayable"
    );
    for (oid, original, coordinate) in generic_certificates {
        let (is_error, status, _) = call_tool(
            &mut mcp,
            "fa_read_certificate_status",
            json!({"certificate": oid}),
        );
        assert!(!is_error, "{status}");
        let status: JsonValue = fastmcp_rust::serde_json::from_str(&status).unwrap();
        assert_eq!(status["status"], json!("SupersededBy"));
        assert_eq!(status["later_entries"], json!([reversal_vid]));
        assert_eq!(status["known_at"], certified[1]["known_at"]);
        let (is_error, replayed, result) =
            call_tool(&mut mcp, "fa_read_replay", json!({"certificate": oid}));
        assert!(!is_error, "{replayed}");
        assert_eq!(replayed, original, "historical report survives reversal");
        let envelope: JsonValue =
            fastmcp_rust::serde_json::from_str(result["content"][1]["text"].as_str().unwrap())
                .unwrap();
        assert_eq!(envelope["coordinate"], coordinate);
    }
    let retained_hex = dir.join("report.hex");
    std::fs::write(&retained_hex, &certificate_hex).unwrap();
    assert_eq!(
        replayed,
        cli_data(&[
            "replay",
            &retained_hex.display().to_string(),
            "--book",
            &b,
            "--json"
        ])
    );
    let mut damaged = certificate_hex.clone();
    let last = damaged.pop().unwrap();
    damaged.push(if last == '0' { '1' } else { '0' });
    let (is_error, text, _) =
        call_tool(&mut mcp, "fa_read_replay", json!({"certificate": damaged}));
    assert!(is_error, "tampered certificate must refuse");
    let error = structured_error(&text);
    assert_eq!(error["exit"], json!(8), "{error}");
    assert_eq!(error["refusal_id"], json!("FA-REF-150"), "{error}");
    log(
        "certified report: inline replay matches the CLI, later reversal supersedes status, tamper refuses",
    );

    // A refusal from the dispatcher: structured, with the CLI's fix verbatim.
    let (is_error, text, _) = call_tool(
        &mut mcp,
        "fa_read_trial_balance",
        json!({"period": "FY2026-P99"}),
    );
    assert!(is_error, "an unknown period is refused: {text}");
    let e = structured_error(&text);
    let (code, stdout) = cli(&["tb", "--period", "FY2026-P99", "--book", &b, "--json"]);
    assert_ne!(code, 0);
    let cli_err = fa_cli::json::parse(stdout.lines().last().unwrap()).unwrap();
    let cli_err = cli_err.get("data").unwrap();
    assert_eq!(e["exit"], json!(code), "{e}");
    assert_eq!(
        e["type"].as_str(),
        cli_err.get("class").and_then(Json::as_str),
        "{e}"
    );
    assert_eq!(
        e["message"].as_str(),
        cli_err.get("message").and_then(Json::as_str),
        "{e}"
    );
    assert_eq!(
        e["fix_hint"].as_str(),
        cli_err.get("fix").and_then(Json::as_str),
        "fix verbatim: {e}"
    );
    log(format!(
        "refusal mapped: type={} exit={} fix_hint={}",
        e["type"], e["exit"], e["fix_hint"]
    ));

    // A mistake caught before dispatch: a float in an amount.
    let mut bad = intent.clone();
    bad["idempotency_key"] = json!("inv-float");
    bad["legs"][0]["amount"] = json!(1500.5);
    let (is_error, text, _) = call_tool(&mut mcp, "fa_post_post", json!({"intent": bad}));
    assert!(is_error, "{text}");
    let e = structured_error(&text);
    assert_eq!(e["detector"], json!("float_amount"), "{e}");
    assert_eq!(e["type"], json!("usage"));
    log("detector float_amount refused a JSON number before dispatch");

    // Dangerous commits cannot be confirmed by this MCP session.
    let (is_error, text, _) = call_tool(
        &mut mcp,
        "fa_time_period_transition",
        json!({"transition": "close", "code": "FY2026-P03"}),
    );
    assert!(is_error, "{text}");
    let e = structured_error(&text);
    assert_eq!(e["refusal_id"], json!("FA-REF-007"), "{e}");
    assert!(
        e["suggested_tool_calls"]
            .as_array()
            .unwrap()
            .iter()
            .any(|call| {
                call["tool"] == "fa_time_period_transition"
                    && call["arguments"]["transition"] == "close"
                    && call["arguments"]["dry_run"] == json!(true)
            }),
        "safe planning alternative: {e}"
    );
    assert!(!e["fix_hint"].as_str().unwrap().contains("--yes"));
    log("FA-REF-007 mapped with planning for independent operator review");

    // Resources: the exit codes and the served book's periods equal the CLI's data.
    let read = mcp.result("resources/read", json!({"uri": "resource://fa/exit-codes"}));
    let text = read["contents"][0]["text"].as_str().expect("text");
    let caps = fa_cli::json::parse(&cli_data(&["capabilities", "--json"])).unwrap();
    assert_eq!(text, caps.get("exit_codes").unwrap().render());
    let read = mcp.result(
        "resources/read",
        json!({"uri": "resource://fa/periods/default"}),
    );
    let text = read["contents"][0]["text"].as_str().expect("text");
    assert_eq!(text, cli_data(&["period", "list", "--book", &b, "--json"]));
    let read = mcp.result("resources/read", json!({"uri": "resource://fa/book"}));
    let text = read["contents"][0]["text"].as_str().expect("text");
    assert_eq!(text, cli_data(&["book", "info", "--book", &b, "--json"]));
    let resource_envelope: JsonValue = fastmcp_rust::serde_json::from_str(
        read["contents"][1]["text"]
            .as_str()
            .expect("resource authority"),
    )
    .unwrap();
    assert_eq!(resource_envelope["authority"]["profile"], "preparer");
    assert_eq!(resource_envelope["authority"]["principal"], "operator");
    let read = mcp.result(
        "resources/read",
        json!({"uri": "resource://fa/open-items/default/all"}),
    );
    let text = read["contents"][0]["text"]
        .as_str()
        .expect("open-items all");
    assert_eq!(text, cli_data(&["open-items", "--book", &b, "--json"]));
    let read = mcp.result(
        "resources/read",
        json!({"uri": "resource://fa/open-items/default/1000"}),
    );
    let text = read["contents"][0]["text"]
        .as_str()
        .expect("open-items 1000");
    assert_eq!(
        text,
        cli_data(&["open-items", "--account", "1000", "--book", &b, "--json"])
    );
    let read = mcp.result(
        "resources/read",
        json!({"uri": "resource://fa/findings/default"}),
    );
    let findings_res: JsonValue =
        fastmcp_rust::serde_json::from_str(read["contents"][0]["text"].as_str().unwrap()).unwrap();
    assert!(findings_res["procedures"]["procedures"].is_array());
    assert_eq!(findings_res["findings"]["evidence"], json!("FA-EVID-L01"));
    assert_eq!(findings_res["findings"]["claim"], json!("statistical"));
    let read = mcp.result(
        "resources/read",
        json!({"uri": "resource://fa/cases/default"}),
    );
    let cases_res: JsonValue =
        fastmcp_rust::serde_json::from_str(read["contents"][0]["text"].as_str().unwrap()).unwrap();
    assert!(cases_res["periods"]["periods"].is_array());
    assert_eq!(cases_res["cases"], json!([]));
    let read = mcp.result(
        "resources/read",
        json!({"uri": "resource://fa/drafts/default"}),
    );
    let drafts_res: JsonValue =
        fastmcp_rust::serde_json::from_str(read["contents"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(
        drafts_res["portable_planning"]["commit_tool"],
        json!("fa_post_commit_plan")
    );
    let read = mcp.result(
        "resources/read",
        json!({"uri": format!("resource://fa/certificates/{certificate_oid}")}),
    );
    let cert_res: JsonValue =
        fastmcp_rust::serde_json::from_str(read["contents"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(cert_res["oid"], json!(certificate_oid));
    assert_eq!(cert_res["status"], json!("SupersededBy"));
    let read = mcp.result(
        "resources/read",
        json!({"uri": "resource://fa/bundles/bundle-1"}),
    );
    let bundle_res: JsonValue =
        fastmcp_rust::serde_json::from_str(read["contents"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(bundle_res["bundle_id"], json!("bundle-1"));
    assert_eq!(bundle_res["accumulator"]["status"], json!("no_checkpoints"));

    // Workflow macros (§15.4): deterministic step-by-step execution and provenance.
    let (is_error, text, _) = call_tool(
        &mut mcp,
        "fa_macro_prepare_close",
        json!({"period": "FY2026-P03"}),
    );
    assert!(!is_error, "fa_macro_prepare_close: {text}");
    let prep_close: JsonValue = fastmcp_rust::serde_json::from_str(&text).unwrap();
    assert_eq!(prep_close["macro"], json!("fa.macro.prepare_close"));
    assert_eq!(prep_close["step_count"], json!(4));
    assert_eq!(prep_close["steps"][3]["step"], json!("close_plan"));
    assert_eq!(
        prep_close["steps"][3]["data"]["scope"],
        json!("period-transition-proposal")
    );
    let (is_error, text, _) = call_tool(
        &mut mcp,
        "fa_macro_record_and_match_cash",
        json!({"account": "1000", "period": "FY2026-P03"}),
    );
    assert!(!is_error, "fa_macro_record_and_match_cash: {text}");
    let cash_macro: JsonValue = fastmcp_rust::serde_json::from_str(&text).unwrap();
    assert_eq!(cash_macro["macro"], json!("fa.macro.record_and_match_cash"));
    assert_eq!(cash_macro["step_count"], json!(3));
    let (is_error, text, _) = call_tool(
        &mut mcp,
        "fa_macro_investigate_account",
        json!({"account": "1000", "period": "FY2026-P03"}),
    );
    assert!(!is_error, "fa_macro_investigate_account: {text}");
    let inv_macro: JsonValue = fastmcp_rust::serde_json::from_str(&text).unwrap();
    assert_eq!(inv_macro["macro"], json!("fa.macro.investigate_account"));
    assert_eq!(inv_macro["step_count"], json!(3));
    assert_eq!(inv_macro["certificates"].as_array().unwrap().len(), 1);
    let (is_error, text, _) = call_tool(
        &mut mcp,
        "fa_macro_produce_audit_package",
        json!({"period": "FY2026-P03"}),
    );
    assert!(!is_error, "fa_macro_produce_audit_package: {text}");
    let pkg_macro: JsonValue = fastmcp_rust::serde_json::from_str(&text).unwrap();
    assert_eq!(pkg_macro["macro"], json!("fa.macro.produce_audit_package"));
    assert_eq!(pkg_macro["step_count"], json!(4));
    assert_eq!(pkg_macro["certificates"].as_array().unwrap().len(), 3);
    log("all 12 resources and 4 workflow macros verified over stdio");

    // A portable plan runs under the actual launch capability. Rejected
    // overrides and other launch authorities cannot publish its effects.
    let before_plan = cli_data(&["book", "info", "--book", &b, "--json"]);
    let mut planned_intent = intent.clone();
    planned_intent["idempotency_key"] = json!("mcp-portable-plan");
    let (is_error, text, result) = call_tool(
        &mut mcp,
        "fa_post_post",
        json!({"intent": planned_intent, "evidence": [oid], "dry_run": true}),
    );
    assert!(!is_error, "{text}");
    let planned: JsonValue = fastmcp_rust::serde_json::from_str(&text).unwrap();
    assert_eq!(planned["scope"], json!("same-snapshot-post"));
    assert_eq!(planned["authority"], json!("mcp-launch-config"));
    assert_eq!(planned["file"], JsonValue::Null);
    let envelope: JsonValue = fastmcp_rust::serde_json::from_str(
        result["content"][1]["text"]
            .as_str()
            .expect("plan envelope"),
    )
    .unwrap();
    assert_eq!(envelope["events"], json!(["plan"]));
    assert_eq!(envelope["certificate"], JsonValue::Null);
    assert_eq!(envelope["authority"], resource_envelope["authority"]);
    assert_eq!(
        cli_data(&["book", "info", "--book", &b, "--json"]),
        before_plan
    );
    let encoded = planned["bytes"]
        .as_str()
        .expect("canonical plan hex")
        .to_string();
    for argument in fa_mcp::registry::FORBIDDEN_ARGUMENTS {
        let mut arguments = json!({"plan": encoded});
        arguments[*argument] = JsonValue::Null;
        let (is_error, text, _) = call_tool(&mut mcp, "fa_post_commit_plan", arguments);
        assert!(is_error, "{argument}: {text}");
        let refused = structured_error(&text);
        assert_eq!(refused["type"], "forbidden_argument");
        assert_eq!(refused["data"]["argument"], *argument);
        assert_eq!(refused["authority"], resource_envelope["authority"]);
    }
    let mut damaged = encoded.clone();
    let last = damaged.pop().unwrap();
    damaged.push(if last == '0' { '1' } else { '0' });
    let (is_error, text, _) = call_tool(&mut mcp, "fa_post_commit_plan", json!({"plan": damaged}));
    assert!(is_error, "tampered plan: {text}");
    let refused = structured_error(&text);
    assert_eq!(refused["refusal_id"], "FA-REF-034");
    assert_eq!(refused["exit"], 6);

    for (launch, expected_refusal) in [
        (
            vec!["--profile", "preparer", "--principal", "another-preparer"],
            "FA-REF-011",
        ),
        (vec!["--principal", "operator"], "FA-REF-013"),
        (
            vec![
                "--profile",
                "preparer",
                "--principal",
                "operator",
                "--grant",
                "read",
            ],
            "FA-REF-011",
        ),
    ] {
        let mut other = Mcp::start_with(&book, &launch);
        other.discover();
        let (is_error, text, _) =
            call_tool(&mut other, "fa_post_commit_plan", json!({"plan": encoded}));
        assert!(is_error, "{launch:?}: {text}");
        let refused = structured_error(&text);
        assert_eq!(
            refused["refusal_id"], expected_refusal,
            "{launch:?}: {refused}"
        );
        assert_eq!(refused["exit"], 7);
        assert_eq!(other.finish(), 0);
    }
    let (is_error, text, _) = call_tool(
        &mut mcp,
        "fa_time_approve",
        json!({"proposal": planned["proposal_digest"]}),
    );
    assert!(is_error, "{text}");
    assert_eq!(structured_error(&text)["detector"], json!("self_approval"));
    assert_eq!(
        cli_data(&["book", "info", "--book", &b, "--json"]),
        before_plan
    );

    // fa-1nx: an Agent session certifying a trial balance between a Preparer's
    // dry-run plan and commit advances raw known_at without moving the
    // accounting frontier, so the Preparer's plan still commits cleanly.
    let mut agent_certifier = Mcp::start(&book);
    agent_certifier.discover();
    let (is_error, cert_text, _) = call_tool(
        &mut agent_certifier,
        "fa_read_trial_balance",
        json!({"period": "FY2026-P03", "activity": true, "certify": true}),
    );
    assert!(!is_error, "Agent TB certification: {cert_text}");
    assert_eq!(agent_certifier.finish(), 0);
    let cert_events: JsonValue = fastmcp_rust::serde_json::from_str(&cert_text).unwrap();
    assert_eq!(cert_events[1]["known_at"], planned["snapshot_seq"]);
    assert_eq!(
        cert_events[1]["recorded_at"],
        json!(planned["snapshot_seq"].as_u64().unwrap() + 1)
    );

    let (is_error, text, result) =
        call_tool(&mut mcp, "fa_post_commit_plan", json!({"plan": encoded}));
    assert!(!is_error, "{text}");
    let committed: JsonValue = fastmcp_rust::serde_json::from_str(&text).unwrap();
    assert_eq!(committed["already_recorded"], json!(false));
    assert_eq!(committed["plan_digest"], planned["plan_digest"]);
    assert_eq!(
        committed["certificate_digest"],
        planned["certificate_digest"]
    );
    let envelope: JsonValue = fastmcp_rust::serde_json::from_str(
        result["content"][1]["text"]
            .as_str()
            .expect("commit envelope"),
    )
    .unwrap();
    assert_eq!(envelope["events"], json!(["plan_committed"]));
    assert_eq!(envelope["authority"], resource_envelope["authority"]);
    let (is_error, retry, _) = call_tool(&mut mcp, "fa_post_commit_plan", json!({"plan": encoded}));
    assert!(!is_error, "{retry}");
    let retried: JsonValue = fastmcp_rust::serde_json::from_str(&retry).unwrap();
    assert_eq!(retried["already_recorded"], json!(true));
    assert_eq!(retried["vid"], committed["vid"]);
    assert_eq!(retried["recorded_at"], committed["recorded_at"]);

    // Conversely, a real accounting posting between plan and commit invalidates
    // the plan with FA-REF-034 (exit 6).
    let stale_intent = json!({
        "effective_date": "2026-03-15", "idempotency_key": "mcp-plan-stale",
        "legs": [
            {"side": "debit", "account": "6000", "amount": "11.00 USD"},
            {"side": "credit", "account": "1000", "amount": "11.00 USD"},
        ],
    });
    let (is_error, stale_plan_text, _) = call_tool(
        &mut mcp,
        "fa_post_post",
        json!({"intent": stale_intent, "evidence": [oid], "dry_run": true}),
    );
    assert!(!is_error, "{stale_plan_text}");
    let stale_planned: JsonValue = fastmcp_rust::serde_json::from_str(&stale_plan_text).unwrap();
    let intervening_intent = json!({
        "effective_date": "2026-03-15", "idempotency_key": "mcp-plan-intervening",
        "legs": [
            {"side": "debit", "account": "6000", "amount": "1.00 USD"},
            {"side": "credit", "account": "1000", "amount": "1.00 USD"},
        ],
    });
    let (is_error, intervening_text, _) = call_tool(
        &mut mcp,
        "fa_post_post",
        json!({"intent": intervening_intent, "evidence": [oid]}),
    );
    assert!(!is_error, "{intervening_text}");
    let (is_error, stale_commit_text, _) = call_tool(
        &mut mcp,
        "fa_post_commit_plan",
        json!({"plan": stale_planned["bytes"]}),
    );
    assert!(
        is_error,
        "accounting write must invalidate plan: {stale_commit_text}"
    );
    let stale_refused = structured_error(&stale_commit_text);
    assert_eq!(stale_refused["refusal_id"], "FA-REF-034", "{stale_refused}");
    assert_eq!(stale_refused["exit"], 6, "{stale_refused}");

    // A reviewable void plan grants no dangerous confirmation to this
    // bounded Preparer. Its hold remains pending after the commit refusal.
    let hold_intent = json!({
        "effective_date": "2026-03-15", "idempotency_key": "mcp-plan-hold",
        "legs": [
            {"side": "debit", "account": "6000", "amount": "20.00 USD"},
            {"side": "credit", "account": "1000", "amount": "20.00 USD"},
        ],
    });
    let (is_error, text, _) = call_tool(
        &mut mcp,
        "fa_post_reserve",
        json!({"intent": hold_intent, "evidence": [oid]}),
    );
    assert!(!is_error, "{text}");
    let hold: JsonValue = fastmcp_rust::serde_json::from_str(&text).unwrap();
    let before_void = cli_data(&["book", "info", "--book", &b, "--json"]);
    let pending = cli_data(&["tb", "--period", "FY2026-P03", "--book", &b, "--json"]);
    let (is_error, text, _) = call_tool(
        &mut mcp,
        "fa_post_resolve",
        json!({"intent": {
            "resolves": hold["vid"], "disposition": "voids",
            "effective_date": "2026-03-15", "idempotency_key": "mcp-plan-void",
        }, "dry_run": true}),
    );
    assert!(!is_error, "void rehearsal: {text}");
    let void_plan: JsonValue = fastmcp_rust::serde_json::from_str(&text).unwrap();
    assert_eq!(void_plan["authority"], "mcp-launch-config");
    let (is_error, text, _) = call_tool(
        &mut mcp,
        "fa_post_commit_plan",
        json!({"plan": void_plan["bytes"]}),
    );
    assert!(is_error, "a void plan cannot confirm an MCP commit: {text}");
    let refused = structured_error(&text);
    assert_eq!(refused["refusal_id"], "FA-REF-007");
    assert_eq!(refused["authority"], resource_envelope["authority"]);
    assert_eq!(
        cli_data(&["book", "info", "--book", &b, "--json"]),
        before_void
    );
    assert_eq!(
        cli_data(&["tb", "--period", "FY2026-P03", "--book", &b, "--json"]),
        pending
    );
    log(
        "portable plans: zero-write rehearsal, fixed-authority commit and retry, tamper and foreign authority refused, dangerous void remains pending",
    );

    let code = mcp.finish();
    log(format!("fa-mcp exited {code} after stdin closed"));
    assert_eq!(code, 0);
    let plan_file = dir.join("mcp.plan.hex");
    std::fs::write(&plan_file, &encoded).unwrap();
    let mut reopened =
        Mcp::start_with(&book, &["--profile", "preparer", "--principal", "operator"]);
    reopened.discover();
    let before_retry = cli_data(&["book", "info", "--book", &b, "--json"]);
    for arguments in [
        json!({"plan_file": plan_file.display().to_string()}),
        json!({"plan": encoded, "plan_file": plan_file.display().to_string()}),
    ] {
        let (is_error, text, _) = call_tool(&mut reopened, "fa_post_commit_plan", arguments);
        assert!(is_error, "host plan_file must be refused: {text}");
        assert_eq!(structured_error(&text)["type"], "forbidden_path");
        assert_eq!(std::fs::read_to_string(&plan_file).unwrap(), encoded);
    }
    let (is_error, text, _) = call_tool(
        &mut reopened,
        "fa_post_commit_plan",
        json!({"plan": encoded}),
    );
    assert!(!is_error, "fresh-session exact retry: {text}");
    assert_eq!(
        text, retry,
        "same bound launch and exact bytes preserve the original outcome across processes"
    );
    assert_eq!(
        cli_data(&["book", "info", "--book", &b, "--json"]),
        before_retry
    );
    assert_eq!(reopened.finish(), 0);
    log(
        "VERDICT PASS: registry tools, bound authority, report and read parity, portable planning and exact cross-process retry, authority and dangerous-commit refusals",
    );
}

#[test]
fn default_agent_authority_survives_stdio_and_cannot_be_changed_by_a_call() {
    let dir = tmp("agent-authority");
    let book = dir.join("book");
    let b = book.display().to_string();
    cli_data(&[
        "book",
        "create",
        "--book",
        &b,
        "--name",
        "Agent boundary",
        "--json",
    ]);
    let chart = dir.join("chart.json");
    std::fs::write(
        &chart,
        r#"{"accounts":[{"code":"1000","name":"Cash","type":"Asset","leaf":true,"unit":"USD"},{"code":"6000","name":"Rent","type":"Expense","leaf":true,"unit":"USD"}]}"#,
    ).unwrap();
    cli_data(&[
        "chart",
        "import",
        &chart.display().to_string(),
        "--book",
        &b,
        "--json",
    ]);
    cli_data(&[
        "period",
        "create",
        "--fiscal-year",
        "2026",
        "--book",
        &b,
        "--json",
    ]);
    cli_data(&["period", "open", "FY2026-P03", "--book", &b, "--json"]);
    let oid = source_document(&dir, &b);
    let intent = json!({
        "class": "Original", "effective_date": "2026-03-15",
        "description": "Agent boundary rent", "idempotency_key": "agent-rent",
        "legs": [
            {"side": "debit", "account": "6000", "amount": "10.00 USD"},
            {"side": "credit", "account": "1000", "amount": "10.00 USD"},
        ],
    });
    let authority = json!({
        "posture": "mcp-launch-config", "principal": "mcp-agent", "profile": "agent",
        "ops": ["read", "post", "verify"],
    });
    // A legacy initialize cannot silently select a different error contract.
    // The operator gets a protocol refusal before the book is observed.
    let before_legacy = cli_data(&["book", "info", "--book", &b, "--json"]);
    let mut legacy = Mcp::start(&book);
    let refused = legacy.request_raw(
        "initialize",
        json!({"protocolVersion": "2024-11-05", "capabilities": {},
            "clientInfo": {"name": "fa-mcp-legacy-negative", "version": fa_mcp::VERSION}}),
    );
    assert!(refused.get("result").is_none(), "{refused}");
    assert_eq!(refused["error"]["code"], -32601, "{refused}");
    legacy.discover();
    assert_eq!(legacy.finish(), 0);
    assert_eq!(
        cli_data(&["book", "info", "--book", &b, "--json"]),
        before_legacy
    );
    let mut mcp = Mcp::start(&book);
    let init = mcp.discover();
    assert!(init["instructions"].as_str().unwrap().contains("mcp-agent"));

    // Real Agent reads and immutable report retention remain usable.
    let (error, text, result) = call_tool(
        &mut mcp,
        "fa_read_trial_balance",
        json!({"period": "FY2026-P03", "certify": true}),
    );
    assert!(!error, "{text}");
    let certified: JsonValue = fastmcp_rust::serde_json::from_str(&text).unwrap();
    let envelope: JsonValue =
        fastmcp_rust::serde_json::from_str(result["content"][1]["text"].as_str().unwrap()).unwrap();
    assert_eq!(envelope["authority"], authority);
    let (error, replayed, result) = call_tool(
        &mut mcp,
        "fa_read_replay",
        json!({"certificate": certified[1]["oid"]}),
    );
    assert!(!error, "{replayed}");
    assert_eq!(replayed, certified[0].to_string());
    let envelope: JsonValue =
        fastmcp_rust::serde_json::from_str(result["content"][1]["text"].as_str().unwrap()).unwrap();
    assert_eq!(envelope["authority"], authority);
    let before = cli_data(&["book", "info", "--book", &b, "--json"]);

    // Valid accounting/evidence reaches Profile::Agent in the kernel; this
    // must not be replaced by a blanket adapter write ban or an owner call.
    let (error, text, _) = call_tool(
        &mut mcp,
        "fa_post_post",
        json!({"intent": intent, "evidence": [oid], "dry_run": false}),
    );
    assert!(error, "an Agent must not post to trunk: {text}");
    let refused = structured_error(&text);
    assert_eq!(refused["refusal_id"], "FA-REF-013", "{refused}");
    assert_eq!(refused["exit"], 7);
    assert_eq!(refused["authority"], authority);
    // Plan §15.3: the Agent may rehearse the same post. The kernel runs every
    // posting law, the plan binds the Agent's capability (so it commits for
    // no one), and the book is unchanged (checked against `before` below).
    let (error, text, result) = call_tool(
        &mut mcp,
        "fa_post_post",
        json!({"intent": intent, "evidence": [oid], "dry_run": true}),
    );
    assert!(!error, "an Agent rehearses a trunk post: {text}");
    eprintln!("agent rehearsal over MCP: {text}");
    let envelope: JsonValue =
        fastmcp_rust::serde_json::from_str(result["content"][1]["text"].as_str().unwrap()).unwrap();
    assert_eq!(envelope["authority"], authority);
    assert!(text.contains("plan_digest"), "{text}");
    assert_eq!(cli_data(&["book", "info", "--book", &b, "--json"]), before);

    // Presence is refused even for null/false and before float detection.
    for argument in fa_mcp::registry::FORBIDDEN_ARGUMENTS {
        for value in [JsonValue::Null, json!(false), json!("operator")] {
            for wire in ["fa_post_post", "fa_post_commit_plan"] {
                let mut arguments = json!({"intent": {"amount": 1.25}});
                arguments[*argument] = value.clone();
                if wire == "fa_post_commit_plan" {
                    // Missing required inline plan forces framework schema
                    // refusal. Authority still precedes a forbidden path.
                    arguments["plan_file"] = JsonValue::Null;
                }
                let (error, text, _) = call_tool(&mut mcp, wire, arguments);
                assert!(error, "forbidden {argument}: {text}");
                let refused = structured_error(&text);
                assert_eq!(refused["type"], "forbidden_argument");
                assert_eq!(refused["data"]["argument"], *argument);
                assert_eq!(refused["authority"], authority);
                assert!(refused.get("detector").is_none());
                assert_eq!(refused["suggested_tool_calls"], json!([]));
            }
        }
    }
    // An ordinary undeclared key reaches the server too (no schema closes
    // itself, so fastmcp no longer answers it with a bare -32602) and is the
    // normalizer's usage error with a spelling hint, before any dispatch
    // (fa-23r).
    let (error, text, _) = call_tool(
        &mut mcp,
        "fa_read_trial_balance",
        json!({"perod": "FY2026-P03"}),
    );
    assert!(error, "a misspelled key is refused: {text}");
    let refused = structured_error(&text);
    assert_eq!(refused["type"], "usage", "{refused}");
    assert_eq!(refused["exit"], 2, "{refused}");
    assert_eq!(refused["detector"], "arguments", "{refused}");
    assert!(
        refused["message"]
            .as_str()
            .is_some_and(|m| m.contains("unknown argument `perod`")),
        "{refused}"
    );
    assert!(
        refused["fix_hint"]
            .as_str()
            .is_some_and(|f| f.contains("`period`")),
        "{refused}"
    );
    assert_eq!(refused["authority"], authority);
    let (error, text, _) = call_tool(
        &mut mcp,
        "fa_read_show_entry",
        json!({"vid": "--as=operator"}),
    );
    assert!(error, "a positional cannot inject an authority flag");
    assert_eq!(structured_error(&text)["detector"], "arguments");

    // A real owner-produced plan cannot become implicit MCP confirmation.
    let plan = dir.join("close.plan");
    cli_data(&[
        "period",
        "close",
        "FY2026-P03",
        "--plan-out",
        &plan.display().to_string(),
        "--book",
        &b,
        "--json",
    ]);
    let plan_bytes: String = std::fs::read(&plan)
        .unwrap()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    for arguments in [
        json!({"transition": "close", "code": "FY2026-P03"}),
        json!({"transition": "close", "code": "FY2026-P03", "plan": plan_bytes}),
    ] {
        let (error, text, _) = call_tool(&mut mcp, "fa_time_period_transition", arguments);
        assert!(error, "dangerous commit: {text}");
        let refused = structured_error(&text);
        assert_eq!(refused["refusal_id"], "FA-REF-007", "{refused}");
        assert_eq!(refused["authority"], authority);
    }

    let resource = mcp.result("resources/read", json!({"uri": "resource://fa/book"}));
    let resource_authority: JsonValue =
        fastmcp_rust::serde_json::from_str(resource["contents"][1]["text"].as_str().unwrap())
            .unwrap();
    assert_eq!(resource_authority["authority"], authority);
    let alien = mcp.request(
        "resources/read",
        json!({"uri": "resource://fa/chart/%2Fanother%2Fbook"}),
    );
    assert_eq!(
        alien["error"]["data"]["type"], "forbidden_argument",
        "{alien}"
    );
    assert_eq!(alien["error"]["data"]["authority"], authority);
    assert_eq!(cli_data(&["book", "info", "--book", &b, "--json"]), before);
    assert_eq!(mcp.finish(), 0);

    // Trusted launch grants attenuate the whole set: read is not silently
    // supplemented with the Preparer template's default post permission.
    let mut read_only = Mcp::start_with(
        &book,
        &[
            "--principal",
            "reader",
            "--profile",
            "preparer",
            "--grant",
            "read",
        ],
    );
    read_only.discover();
    let (error, text, result) = call_tool(&mut read_only, "fa_book_info", json!({}));
    assert!(!error, "{text}");
    let envelope: JsonValue =
        fastmcp_rust::serde_json::from_str(result["content"][1]["text"].as_str().unwrap()).unwrap();
    assert_eq!(envelope["authority"]["ops"], json!(["read"]));
    assert_eq!(envelope["authority"]["principal"], "reader");
    for dry_run in [false, true] {
        let (error, text, _) = call_tool(
            &mut read_only,
            "fa_post_post",
            json!({"intent": intent, "evidence": [oid], "dry_run": dry_run}),
        );
        assert!(error, "read-only Preparer cannot acquire Post: {text}");
        assert_eq!(structured_error(&text)["exit"], 7);
        assert_eq!(structured_error(&text)["refusal_id"], "FA-REF-011");
    }
    assert_eq!(cli_data(&["book", "info", "--book", &b, "--json"]), before);
    assert_eq!(read_only.finish(), 0);
}

#[test]
fn read_only_period_planning_is_inline_and_paths_cannot_touch_host_files() {
    let dir = tmp("filesystem-containment");
    let book = dir.join("book");
    let b = book.display().to_string();
    cli_data(&[
        "book",
        "create",
        "--name",
        "Inline plans",
        "--book",
        &b,
        "--json",
    ]);
    cli_data(&[
        "period",
        "create",
        "--fiscal-year",
        "2026",
        "--book",
        &b,
        "--json",
    ]);
    cli_data(&["period", "open", "FY2026-P03", "--book", &b, "--json"]);
    let victim = dir.join("preserve.txt");
    std::fs::write(&victim, "host file must remain unchanged").unwrap();
    let paths = vec![victim.display().to_string(), "../preserve.txt".to_string()];
    #[cfg(unix)]
    let paths = {
        let mut paths = paths;
        let link = dir.join("escape-link");
        std::os::unix::fs::symlink(&victim, &link).unwrap();
        paths.push(link.display().to_string());
        paths
    };
    let before = cli(&["book", "info", "--book", &b, "--json"]);
    assert_eq!(before.0, 0);
    let mut mcp = Mcp::start_with(&book, &["--principal", "reader", "--grant", "read"]);
    mcp.discover();
    for path in paths {
        for (wire, argument, mut input) in [
            (
                "fa_time_period_transition",
                "plan_out",
                json!({"transition": "close", "code": "FY2026-P03"}),
            ),
            ("fa_post_post", "intent_file", json!({})),
            ("fa_post_commit_plan", "plan_file", json!({})),
            ("fa_read_replay", "file", json!({})),
            ("fa_read_certificate_status", "file", json!({})),
            // Both schema-invalid and schema-valid inputs retain the same
            // host-path refusal; neither route may inspect a host file.
            ("fa_post_commit_plan", "plan_file", json!({"plan": "00"})),
            ("fa_read_replay", "file", json!({"certificate": "00"})),
            (
                "fa_read_certificate_status",
                "file",
                json!({"certificate": "00"}),
            ),
            ("fa_chart_import_chart", "file", json!({})),
            ("fa_evidence_import_document", "file", json!({})),
            ("fa_read_trial_balance", "certificate_out", json!({})),
        ] {
            for value in [json!(path), JsonValue::Null, json!(false)] {
                input[argument] = value;
                let (error, text, _) = call_tool(&mut mcp, wire, input.clone());
                assert!(error, "{wire} must refuse a host path: {text}");
                let refused = structured_error(&text);
                assert_eq!(refused["type"], "forbidden_path", "{refused}");
                assert_eq!(refused["data"]["argument"], argument);
                assert_eq!(refused["authority"]["ops"], json!(["read"]));
                assert!(refused.get("detector").is_none());
                assert_eq!(
                    std::fs::read_to_string(&victim).unwrap(),
                    "host file must remain unchanged"
                );
            }
        }
    }
    // Ordinary missing required inputs retain the framework's schema error;
    // response enrichment cannot admit them or dispatch a tool.
    for wire in [
        "fa_post_commit_plan",
        "fa_read_replay",
        "fa_read_certificate_status",
    ] {
        let (error, text, _) = call_tool(&mut mcp, wire, json!({}));
        assert!(error, "{wire} must still require its inline content");
        assert_eq!(
            text,
            "Tool arguments do not match the declared input schema."
        );
    }
    let (error, text, result) = call_tool(
        &mut mcp,
        "fa_time_period_transition",
        json!({"transition": "close", "code": "FY2026-P03", "dry_run": true}),
    );
    assert!(!error, "read-authorized inline preparation: {text}");
    let planned: JsonValue = fastmcp_rust::serde_json::from_str(&text).unwrap();
    assert_eq!(planned["scope"], "period-transition-proposal");
    assert_eq!(planned["from"], "Open");
    assert_eq!(planned["to"], "Closed");
    assert!(
        planned["bytes"]
            .as_str()
            .unwrap()
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    );
    let envelope: JsonValue =
        fastmcp_rust::serde_json::from_str(result["content"][1]["text"].as_str().unwrap()).unwrap();
    assert_eq!(envelope["events"], json!(["period_plan"]));
    assert_eq!(envelope["certificate"], JsonValue::Null);
    assert_eq!(envelope["authority"]["principal"], "reader");
    let (error, text, _) = call_tool(
        &mut mcp,
        "fa_time_approve",
        json!({"proposal": planned["proposal_digest"]}),
    );
    assert!(
        error,
        "the inline proposal remains subject to segregation of duties"
    );
    assert_eq!(structured_error(&text)["detector"], "self_approval");
    let (error, text, _) = call_tool(
        &mut mcp,
        "fa_time_period_transition",
        json!({"transition": "close", "code": "FY2026-P03", "plan": planned["bytes"]}),
    );
    assert!(error, "inline bytes never authorize a dangerous MCP commit");
    assert_eq!(structured_error(&text)["refusal_id"], "FA-REF-007");
    assert_eq!(
        cli(&["book", "info", "--book", &b, "--json"]),
        before,
        "the recorded frontier must not move"
    );
    assert_eq!(
        std::fs::read_to_string(&victim).unwrap(),
        "host file must remain unchanged"
    );
    assert_eq!(mcp.finish(), 0);
}

#[test]
fn launch_rejects_unbounded_grants_before_serving_stdio() {
    let dir = tmp("launch-refusal");
    for profile in ["agent", "preparer"] {
        for grant in [
            "approve",
            "close",
            "post_closed",
            "migrate",
            "witness",
            "issue_capability",
        ] {
            let output = Command::new(env!("CARGO_BIN_EXE_fa-mcp"))
                .args([
                    "--book",
                    &dir.display().to_string(),
                    "--profile",
                    profile,
                    "--grant",
                    grant,
                ])
                .env_remove("FA_BOOK")
                .stdin(Stdio::null())
                .output()
                .expect("launch fa-mcp");
            assert_eq!(
                output.status.code(),
                Some(7),
                "{profile} {grant}: {output:?}"
            );
            assert!(
                output.stdout.is_empty(),
                "a refused launch must not start the protocol"
            );
            assert!(String::from_utf8_lossy(&output.stderr).contains("cannot hold"));
        }
    }
    let missing = Command::new(env!("CARGO_BIN_EXE_fa-mcp"))
        .env_remove("FA_BOOK")
        .stdin(Stdio::null())
        .output()
        .expect("launch without book");
    assert_eq!(missing.status.code(), Some(2));
    assert!(missing.stdout.is_empty());
}

/// Never silent on a panic (fa-y9z): stdout is the JSON-RPC transport, so a
/// panicking `fa-mcp` writes nothing there, reports FA-REF-153 on stderr and
/// exits 5, never Rust's 101. The panic is the debug build's `FA_TEST_PANIC`
/// trigger; a release build compiles it out.
#[test]
fn a_panicking_server_reports_fa_ref_153_on_stderr_with_exit_5() {
    let panicked = Command::new(env!("CARGO_BIN_EXE_fa-mcp"))
        .args(["--book", "/nonexistent/fa-mcp-panic-book"])
        .env_remove("FA_BOOK")
        .env("FA_TEST_PANIC", "1")
        .stdin(Stdio::null())
        .output()
        .expect("launch with the panic trigger");
    let stderr = String::from_utf8_lossy(&panicked.stderr);
    assert_eq!(panicked.status.code(), Some(5), "{stderr}");
    assert!(panicked.stdout.is_empty(), "the transport stays clean");
    assert!(stderr.contains("fa-mcp: internal error"), "{stderr}");
    assert!(stderr.contains("FA-REF-153"), "{stderr}");
    assert!(stderr.contains("FA_TEST_PANIC"), "{stderr}");
}

/// fa-v62: an operator issues a holder-bound Agent token with the CLI and
/// launches fa-mcp with it. The session's authority is the token's (posture
/// issued-token, its principal, its journaled ops); a rehearsal runs
/// under it. A tampered token file is refused at launch, before serving.
/// Once the operator revokes the grant, the kernel refuses the same
/// rehearsal (FA-REF-023): the session cannot outlive its grant.
#[test]
fn an_issued_token_binds_the_session_and_its_revocation_is_enforced() {
    let dir = tmp("issued-token");
    let book = dir.join("book");
    let b = book.display().to_string();
    cli_data(&[
        "book", "create", "--book", &b, "--name", "Token Co", "--json",
    ]);
    let chart = dir.join("chart.json");
    std::fs::write(
        &chart,
        r#"{"accounts":[{"code":"1000","name":"Cash","type":"Asset","leaf":true,"unit":"USD"},{"code":"6000","name":"Rent","type":"Expense","leaf":true,"unit":"USD"}]}"#,
    )
    .unwrap();
    cli_data(&[
        "chart",
        "import",
        &chart.display().to_string(),
        "--book",
        &b,
        "--json",
    ]);
    cli_data(&[
        "period",
        "create",
        "--fiscal-year",
        "2026",
        "--book",
        &b,
        "--json",
    ]);
    cli_data(&["period", "open", "FY2026-P03", "--book", &b, "--json"]);
    let oid = source_document(&dir, &b);
    let token = dir.join("agent-7.token");
    let t = token.display().to_string();
    let issued = cli_data(&[
        "capability",
        "issue",
        "--book",
        &b,
        "--holder",
        "agent-7",
        "--profile",
        "agent",
        "--op",
        "read",
        "--op",
        "post",
        "--op",
        "verify",
        "--out",
        &t,
        "--grant",
        "issue_capability",
        "--grant",
        "read",
        "--grant",
        "post",
        "--grant",
        "verify",
        "--json",
    ]);
    log(format!("issued: {issued}"));
    let issued = fa_cli::json::parse(&issued).expect("issued data");
    let commitment = issued
        .get("commitment")
        .and_then(Json::as_str)
        .expect("commitment")
        .to_string();
    let listed = cli_data(&["capability", "list", "--book", &b, "--json"]);
    assert!(listed.contains(&commitment), "{listed}");

    // A tampered token never serves.
    let mut tampered = std::fs::read(&token).unwrap();
    let last = tampered.len() - 1;
    tampered[last] ^= 1;
    let bad = dir.join("tampered.token");
    std::fs::write(&bad, &tampered).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_fa-mcp"))
        .args(["--book", &b, "--token", &bad.display().to_string()])
        .env_remove("FA_BOOK")
        .stdin(Stdio::null())
        .output()
        .expect("run fa-mcp");
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    assert!(String::from_utf8_lossy(&output.stderr).contains("--token"));

    let intent = json!({
        "class": "Original", "effective_date": "2026-03-15",
        "description": "issued-token rent", "idempotency_key": "token-rent",
        "legs": [
            {"side": "debit", "account": "6000", "amount": "10.00 USD"},
            {"side": "credit", "account": "1000", "amount": "10.00 USD"},
        ],
    });
    let authority = json!({
        "posture": "issued-token", "principal": "agent-7", "profile": "agent",
        "ops": ["read", "post", "verify"],
    });
    let mut mcp = Mcp::start_with(&book, &["--token", &t]);
    mcp.discover();
    let (error, text, result) = call_tool(
        &mut mcp,
        "fa_post_post",
        json!({"intent": intent, "evidence": [oid], "dry_run": true}),
    );
    assert!(!error, "the issued Agent token rehearses: {text}");
    let envelope: JsonValue =
        fastmcp_rust::serde_json::from_str(result["content"][1]["text"].as_str().unwrap()).unwrap();
    assert_eq!(envelope["authority"], authority);

    // The operator revokes the grant; the bound session is refused at once.
    cli_data(&[
        "capability",
        "revoke",
        "--book",
        &b,
        "--commitment",
        &commitment,
        "--grant",
        "issue_capability",
        "--yes",
        "--json",
    ]);
    let (error, text, _) = call_tool(
        &mut mcp,
        "fa_post_post",
        json!({"intent": intent, "evidence": [oid], "dry_run": true}),
    );
    assert!(error, "a revoked grant reaches nothing: {text}");
    let refused = structured_error(&text);
    assert_eq!(refused["refusal_id"], "FA-REF-023", "{refused}");
    assert_eq!(mcp.finish(), 0);
}

/// fa-s7x: the default Agent session works on a draft. It opens one and
/// plans a post into it (rehearsed under every posting law, journaled, not
/// on trunk); it cannot promote it over MCP. A Human controller promotes it
/// on the host, and the Agent's planned entry is then on trunk with the
/// Agent as its principal.
#[test]
fn an_agent_plans_into_a_draft_and_a_host_controller_promotes_it() {
    let dir = tmp("agent-draft");
    let book = dir.join("book");
    let b = book.display().to_string();
    cli_data(&[
        "book", "create", "--book", &b, "--name", "Draft Co", "--json",
    ]);
    let chart = dir.join("chart.json");
    std::fs::write(
        &chart,
        r#"{"accounts":[{"code":"1000","name":"Cash","type":"Asset","leaf":true,"unit":"USD"},{"code":"6000","name":"Rent","type":"Expense","leaf":true,"unit":"USD"}]}"#,
    )
    .unwrap();
    cli_data(&[
        "chart",
        "import",
        &chart.display().to_string(),
        "--book",
        &b,
        "--json",
    ]);
    cli_data(&[
        "period",
        "create",
        "--fiscal-year",
        "2026",
        "--book",
        &b,
        "--json",
    ]);
    cli_data(&["period", "open", "FY2026-P03", "--book", &b, "--json"]);
    let oid = source_document(&dir, &b);
    let intent = json!({
        "class": "Original", "effective_date": "2026-03-15",
        "description": "Agent draft rent", "idempotency_key": "agent-draft-rent",
        "legs": [
            {"side": "debit", "account": "6000", "amount": "42.00 USD"},
            {"side": "credit", "account": "1000", "amount": "42.00 USD"},
        ],
    });
    // fa.draft is an on-demand cluster (plan §15.4).
    let mut mcp = Mcp::start_with(&book, &["--cluster", "fa.draft"]);
    mcp.discover();
    let (error, text, _) = call_tool(
        &mut mcp,
        "fa_draft_manage",
        json!({"action": "new", "name": "agent-close"}),
    );
    assert!(!error, "the Agent opens its draft: {text}");
    let (error, text, _) = call_tool(
        &mut mcp,
        "fa_post_post",
        json!({"intent": intent, "evidence": [oid], "draft": "agent-close"}),
    );
    assert!(!error, "the Agent plans into its draft: {text}");
    let planned: JsonValue = fastmcp_rust::serde_json::from_str(&text).unwrap();
    let entry = planned["entry"]
        .as_str()
        .expect("the entry promotion creates")
        .to_string();
    let (error, text, _) = call_tool(
        &mut mcp,
        "fa_draft_manage",
        json!({"action": "show", "name": "agent-close"}),
    );
    assert!(!error, "{text}");
    assert!(text.contains(&entry), "{text}");
    let (error, text, _) = call_tool(
        &mut mcp,
        "fa_draft_manage",
        json!({"action": "promote", "name": "agent-close"}),
    );
    assert!(error, "promotion is host-only: {text}");
    let (code, shown) = cli(&["entry", "show", &entry, "--book", &b, "--json"]);
    assert_eq!(code, 0, "{shown}");
    assert!(
        shown.contains("\"found\":false"),
        "a planned intent is not on trunk: {shown}"
    );

    let promoted = cli_data(&[
        "draft",
        "promote",
        "agent-close",
        "--as",
        "controller",
        "--yes",
        "--book",
        &b,
        "--json",
    ]);
    log(format!("promoted: {promoted}"));
    assert!(promoted.contains(&entry), "{promoted}");
    let (error, text, _) = call_tool(&mut mcp, "fa_read_show_entry", json!({"vid": entry}));
    assert!(!error, "{text}");
    assert!(
        text.contains("\"found\":true"),
        "the promoted entry is on trunk: {text}"
    );
    assert_eq!(mcp.finish(), 0);
}
