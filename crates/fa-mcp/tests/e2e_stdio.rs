//! End to end over stdio (bead fa-xex): the real `fa-mcp` binary is started
//! on a temp book and spoken to as an MCP host would — newline-delimited
//! JSON-RPC on its stdin/stdout — through `initialize`, `tools/list`,
//! `tools/call` and `resources/read`. Every tool result's first content
//! block must equal, byte for byte, the `data` payload the CLI's own front
//! door (`fa_cli::entry::fa`, the function the `fa` binary's `main` calls)
//! prints for the same verb with `--json`.
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
        log(format!(
            "spawn {} --book {}",
            env!("CARGO_BIN_EXE_fa-mcp"),
            book.display()
        ));
        let mut child = Command::new(env!("CARGO_BIN_EXE_fa-mcp"))
            .args(["--book", &book.display().to_string()])
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

    fn send(&mut self, message: &JsonValue) {
        let text = message.to_string();
        log(format!("->   {text}"));
        let stdin = self.stdin.as_mut().expect("stdin open");
        stdin.write_all(text.as_bytes()).expect("write");
        stdin.write_all(b"\n").expect("write");
        stdin.flush().expect("flush");
    }

    fn notify(&mut self, method: &str, params: JsonValue) {
        self.send(&json!({"jsonrpc": "2.0", "method": method, "params": params}));
    }

    /// Send one request and wait for its response (notifications are logged
    /// and skipped). Returns the whole response object.
    fn request(&mut self, method: &str, params: JsonValue) -> JsonValue {
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
    ] {
        assert!(
            v.get(key).is_some(),
            "structured error lacks `{key}`: {text}"
        );
    }
    v
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

    let mut mcp = Mcp::start(&book);
    let init = mcp.result(
        "initialize",
        json!({"protocolVersion": PROTOCOL, "capabilities": {}, "clientInfo": {"name": "fa-mcp-e2e", "version": fa_mcp::VERSION}}),
    );
    assert!(init["protocolVersion"].is_string(), "{init}");
    assert_eq!(init["serverInfo"]["name"], json!("fa-mcp"), "{init}");
    mcp.notify("notifications/initialized", json!({}));

    // tools/list: exactly the registry's wire names, each with an object schema.
    let registry = fa_mcp::registry::McpRegistry::embedded().expect("[mcp]");
    let expected: std::collections::BTreeSet<String> = registry
        .tools
        .iter()
        .map(fa_mcp::registry::ToolSpec::wire_name)
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
            assert!(
                tool["description"]
                    .as_str()
                    .is_some_and(|d| d.contains("Do:")),
                "{name}"
            );
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

    // fa.orient: capabilities — equals the CLI's data byte for byte.
    let (is_error, text, _) = call_tool(&mut mcp, "fa_orient_capabilities", json!({}));
    assert!(!is_error, "{text}");
    let expected = cli_data(&["capabilities", "--json"]);
    assert_eq!(
        text, expected,
        "fa_orient_capabilities != fa capabilities --json (data)"
    );
    log("fa_orient_capabilities == fa capabilities --json: byte-identical data");

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

    // A dangerous operation without `yes`: FA-REF-007 with the safe alternative as a tool call.
    let (is_error, text, _) = call_tool(
        &mut mcp,
        "fa_time_period_transition",
        json!({"transition": "close", "code": "FY2026-P03"}),
    );
    assert!(is_error, "{text}");
    let e = structured_error(&text);
    assert_eq!(e["refusal_id"], json!("FA-REF-007"), "{e}");
    assert_eq!(
        e["suggested_tool_calls"][0]["tool"],
        json!("fa_time_period_transition"),
        "{e}"
    );
    assert_eq!(
        e["suggested_tool_calls"][0]["arguments"]["transition"],
        json!("soft-close"),
        "{e}"
    );
    log("FA-REF-007 mapped with the safe alternative as a suggested tool call");

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
    log("resources exit-codes, periods/{book}, book == the CLI's data");

    let code = mcp.finish();
    log(format!("fa-mcp exited {code} after stdin closed"));
    assert_eq!(code, 0);
    log(
        "VERDICT PASS: tools/list == registry; capabilities, tb, entry show, exit-codes, periods, book byte-identical to the CLI; refusal, detector and FA-REF-007 structured",
    );
}
