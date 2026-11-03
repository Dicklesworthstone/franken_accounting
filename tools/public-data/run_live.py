#!/usr/bin/env python3
"""Exercise a complete pinned public expenditure extract through the real fa CLI.

This is an execution harness, not an alternative accounting engine. The native
migration laws, approvals, activation, folds, exports, certificates and independent
fa-verify binary supply the results. Python supplies source-derived expectations.
All generated books are explicitly scoped models of published expenditure.
"""
from __future__ import annotations

import argparse
from collections import Counter
import csv
from datetime import date
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time
from typing import Any

import public_spend


class CheckError(RuntimeError):
    """An observed native result or retained input broke the test contract."""


def require(condition: bool, detail: str) -> None:
    if not condition:
        raise CheckError(detail)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def json_bytes(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode()


def write_new(path: Path, value: bytes) -> None:
    with path.open("xb") as stream:
        stream.write(value)


def body(event: dict[str, Any]) -> dict[str, Any]:
    value = event.get("data", event)
    require(isinstance(value, dict), "native event has no object body")
    return value


def event_named(events: list[dict[str, Any]], name: str) -> dict[str, Any]:
    found = [event for event in events if event.get("event") == name]
    require(len(found) == 1, f"expected exactly one {name} event, received {len(found)}")
    return found[0]


def money(text: str, *, unit: bool = True) -> int:
    """Read the CLI's fixed two-place GBP representation without floating point."""
    require(isinstance(text, str), "native amount is not an exact decimal string")
    match = re.fullmatch(r"(-?)([0-9]+)\.([0-9]{2})" + (r" GBP" if unit else ""), text)
    require(match is not None, f"unexpected exact GBP amount: {text!r}")
    assert match is not None
    value = int(match[2]) * 100 + int(match[3])
    return -value if match[1] else value


def decimal(value: int) -> str:
    return f"{'-' if value < 0 else ''}{abs(value) // 100}.{abs(value) % 100:02}"


def verify_prepared(directory: Path, dataset: str) -> tuple[dict[str, Any], dict[str, Any]]:
    """Rebuild every expected output from independently pinned original bytes.

    Rehashing a modified manifest is insufficient: the pinned source catalogue and
    deterministic transformation must agree before the first native write.
    """
    sources = public_spend.load_sources()
    require(dataset in sources, f"unknown pinned dataset {dataset!r}")
    expected_files = public_spend.build_bundle(sources[dataset], (directory / "raw.csv").read_bytes())
    for name, expected in expected_files.items():
        actual = (directory / name).read_bytes()
        require(actual == expected, f"prepared {name} differs from its pinned source transformation")
    expected_tb = json.loads(expected_files["expected_tb.json"])
    return sources[dataset], expected_tb


def expected_cells(expected: dict[str, Any]) -> dict[str, tuple[int, int, int]]:
    cells: dict[str, tuple[int, int, int]] = {}
    for account in expected["accounts"]:
        code = account["account"]
        require(code not in cells, f"duplicate source expectation for account {code}")
        debit, credit, net = (int(account[name]) for name in ("debit_minor", "credit_minor", "signed_minor"))
        require(debit >= 0 and credit >= 0 and debit - credit == net, f"inconsistent source totals for {code}")
        if debit or credit:
            cells[code] = debit, credit, net
    require(sum(value[2] for value in cells.values()) == 0, "declared expenditure model is unbalanced")
    return cells


def check_tb(event: dict[str, Any], expected: dict[str, Any], *, invisible: bool = False) -> None:
    rows = body(event).get("rows")
    require(isinstance(rows, list), "trial balance has no rows array")
    actual: dict[str, tuple[int, int, int]] = {}
    for row in rows:
        code = row["code"]
        require(code not in actual, f"duplicate native GBP trial-balance row for {code}")
        values = tuple(money(row[key]) for key in ("debits", "credits", "net"))
        require(values[0] - values[1] == values[2], f"native net does not equal debit minus credit for {code}")
        for pending in ("debits_pending", "credits_pending"):
            if pending in row:
                require(money(row[pending]) == 0, f"unexpected pending amount for {code}")
        if any(values):
            actual[code] = values
    target = {} if invisible else expected_cells(expected)
    require(actual == target, f"native trial balance differs from source by account: {actual!r} != {target!r}")


def check_staged_group(event: dict[str, Any], chunks: list[dict[str, Any]], *,
                       start: int, total: int, package: str, run_vid: str,
                       already_recorded: bool = False) -> list[dict[str, Any]]:
    """Bind every returned receipt to the independently checked prepared chunk.

    A group commits its members separately. Neither a success count nor a
    balanced final fold can replace checking the exact approved identities.
    """
    require(event.get("event") == "migration_import_group_staged", "native emitted no group staging result")
    result = body(event)
    require(result.get("package_oid") == package.removeprefix("D:")
            and result.get("run_vid") == run_vid, "native staged a different package or migration run")
    require(result.get("atomic") is False, "native grouped staging misstates its publication boundary")
    require(result.get("selected_count") == result.get("completed_count") == len(chunks),
            "native group omitted a selected chunk")
    require(result.get("recorded_count") == start + len(chunks) and result.get("chunk_count") == total,
            "native grouped staging returned the wrong chunk census")
    require(result.get("run_state") == "Open"
            and result.get("ready_to_finalize") is (start + len(chunks) == total),
            "native grouped staging returned the wrong activation readiness")
    receipts = result.get("chunks")
    require(isinstance(receipts, list) and len(receipts) == len(chunks), "native group has an incomplete receipt list")
    sequences = set()
    for offset, (chunk, receipt) in enumerate(zip(chunks, receipts, strict=True)):
        require(isinstance(receipt, dict), "native group receipt is not an object")
        require(receipt.get("chunk_index") == start + offset
                and receipt.get("entry_vid") == chunk["entry_vid"]
                and receipt.get("proposal_digest") == chunk["proposal_digest"],
                "native staged a different chunk than the approved source proposal")
        sequence = receipt.get("recorded_at")
        require(type(sequence) is int and sequence > 0 and sequence not in sequences,
                "native group has an invalid or repeated publication sequence")
        sequences.add(sequence)
        require(receipt.get("already_recorded") is already_recorded, "native group returned the wrong retry status")
    return receipts


def check_export(path: Path, prepared: Path, expected: dict[str, Any]) -> dict[str, int]:
    """Compare every exported native leg, including its source identity and memo.

    A zero grand total alone would admit omissions, duplicate payments and paired
    sign changes. This multiset check independently compares the complete dated
    source-model leg population, retaining repeated original rows.
    """
    with (prepared / "legacy.csv").open(encoding="utf-8", newline="") as stream:
        source = list(csv.DictReader(stream, strict=True))
    source_legs: Counter[tuple[Any, ...]] = Counter()
    source_ordinals: Counter[str] = Counter()
    for row in source:
        side = row["side"].lower()
        side = {"d": "debit", "c": "credit"}.get(side, side)
        source_id = expected["source_system"] + ":" + row["entry_id"]
        source_ordinals[source_id] += 1
        source_legs[(source_id, source_ordinals[source_id], row["effective_date"], row["account_code"], side,
                     money(row["amount"], unit=False), row["description"], row["memo"])] += 1
    # Native CSV has a comment preamble; remove only that initial metadata,
    # never physical lines inside a quoted memo beginning with '#'.
    with path.open(encoding="utf-8", newline="") as stream:
        text = stream.read()
    lines = text.splitlines(keepends=True)
    start = 0
    while start < len(lines) and lines[start].startswith("#"):
        start += 1
    reader = csv.DictReader(io.StringIO("".join(lines[start:]), newline=""), strict=True)
    actual_legs: Counter[tuple[Any, ...]] = Counter()
    entries: dict[str, str] = {}
    for row in reader:
        require(row["currency"] == "GBP" and row["unit_scale"] == "2", "export changed source currency or scale")
        require(row["entry_class"] == "12", "exported source entry is not native Migration class")
        require(row["side"] in ("D", "C"), "export has an unknown posting side")
        side = "debit" if row["side"] == "D" else "credit"
        actual_legs[(row["migrated_from"], int(row["line_no"]), row["effective_date"], row["account_code"], side,
                     money(row["amount"], unit=False), row["description"], row["memo"])] += 1
        prior = entries.setdefault(row["entry_id"], row["migrated_from"])
        require(prior == row["migrated_from"], "native entry combines different source journals")
    require(actual_legs == source_legs, "native export lost, duplicated or changed dated source legs/memos")
    require(sum(actual_legs.values()) == expected["leg_count"], "native export leg census differs from source")
    require(len(entries) == expected["entry_count"], "native export journal census differs from source")
    require(len(set(entries.values())) == len(entries), "source journal was split across multiple native entries")
    return {"entries": len(entries), "legs": sum(actual_legs.values())}


class Native:
    def __init__(self, fa: Path, verifier: Path, out: Path, timeout: int, fad: Path | None = None,
                 stage_group_size: int = 64):
        self.fa, self.verifier, self.out, self.timeout = fa, verifier, out, timeout
        require(1 <= stage_group_size <= 4096, "stage group size must be between 1 and 4096")
        self.stage_group_size = stage_group_size
        self.fad = fad
        self.book = out / "book"
        self.calls = 0
        self.daemon: subprocess.Popen[bytes] | None = None
        self.daemon_streams: list[Any] = []
        self.daemon_record: dict[str, Any] | None = None
        self.reviewer_tokens: list[Path] = []
        self.env = {key: value for key, value in os.environ.items() if not key.startswith("FA_")}
        self.env.update(NO_COLOR="1", TERM="dumb")
        (out / "transcript").mkdir()

    def execute(self, args: list[str], *, verifier: bool = False,
                expected_exit: int = 0, token: Path | None = None,
                daemon_control: bool = False, request_bytes: bytes | None = None) -> list[dict[str, Any]]:
        self.calls += 1
        if daemon_control:
            require(self.fad is not None and token is None and not verifier, "invalid daemon control request")
            command = [str(self.fad), *args, "--book", str(self.book), "--json"]
        elif verifier:
            require(token is None, "standalone verifier cannot receive a book token")
            command = [str(self.verifier), *args, "--json"]
        else:
            command = [str(self.fa), "--book", str(self.book)]
            if self.daemon is not None:
                require(self.daemon.poll() is None, "native daemon exited during the bulk import")
                command += ["--via", "fad"]
            if token is not None:
                command += ["--token", str(token)]
            command += args + ["--json"]
        stem = f"{self.calls:05d}"
        started = time.monotonic()
        with (self.out / "commands.jsonl").open("a", encoding="utf-8") as log:
            request = {"call": self.calls, "argv": command, "state": "started"}
            if request_bytes is not None:
                request.update(stdin_sha256=digest(request_bytes), stdin_bytes=len(request_bytes))
            log.write(json.dumps(request) + "\n")
        try:
            completed = subprocess.run(command, input=request_bytes, capture_output=True,
                                       env=self.env, timeout=self.timeout, check=False)
        except subprocess.TimeoutExpired as error:
            write_new(self.out / "transcript" / f"{stem}.stdout.jsonl", error.stdout or b"")
            write_new(self.out / "transcript" / f"{stem}.stderr.txt", error.stderr or b"")
            raise CheckError(f"native command timed out after {self.timeout}s: {args}") from error
        write_new(self.out / "transcript" / f"{stem}.stdout.jsonl", completed.stdout)
        write_new(self.out / "transcript" / f"{stem}.stderr.txt", completed.stderr)
        with (self.out / "commands.jsonl").open("a", encoding="utf-8") as log:
            log.write(json.dumps({"call": self.calls, "state": "completed", "exit": completed.returncode,
                                  "seconds": round(time.monotonic() - started, 3),
                                  "stdout_sha256": digest(completed.stdout),
                                  "stderr_sha256": digest(completed.stderr)}) + "\n")
        require(completed.returncode == expected_exit,
                f"native command {args} exited {completed.returncode}, expected {expected_exit}: "
                + completed.stdout.decode(errors="replace")[-3000:]
                + completed.stderr.decode(errors="replace")[-1000:])
        try:
            events = [json.loads(line) for line in completed.stdout.decode("utf-8").splitlines()]
        except (UnicodeError, json.JSONDecodeError) as error:
            raise CheckError(f"native command did not emit valid JSONL: {args}") from error
        require(bool(events) and all(isinstance(event, dict) for event in events), "native command emitted no event objects")
        if expected_exit == 0:
            require(all(event.get("event") != "error" for event in events), "native success includes an error event")
        return events

    def one(self, args: list[str], *, expected_exit: int = 0, token: Path | None = None,
            request_bytes: bytes | None = None) -> dict[str, Any]:
        events = self.execute(args, expected_exit=expected_exit, token=token, request_bytes=request_bytes)
        require(len(events) == 1, f"expected one native event for {args}, received {len(events)}")
        return events[0]

    def head(self) -> int:
        return self.one(["book", "info"])["coordinate"]["known_at"]

    def document(self, path: Path, kind: str, mime: str) -> str:
        # The native upload records the actual launch posture's custody. The
        # harness never relabels its uploads as human or third-party evidence.
        oid = body(self.one(["document", "add", str(path), "--kind", kind, "--mime", mime]))["oid"]
        # A separate fixture principal exercises the actual native review law.
        # This is automated test-role separation, not independent human review;
        # the original AgentUpload/Generated custody remains unchanged.
        self.one(["document", "attest", "review", "--document", oid,
                  "--as", "public-data-fixture-reviewer-a", "--grant", "approve"])
        return oid

    def approvals(self, proposal: str) -> list[str]:
        # Fixture role separation only: this is NOT independent human review.
        if self.reviewer_tokens:
            return [body(self.one(["approve", "--proposal", proposal], token=token))["approval_vid"]
                    for token in self.reviewer_tokens]
        return [body(self.one(["approve", "--proposal", proposal, "--as", who]))["approval_vid"]
                for who in ("public-data-fixture-reviewer-a", "public-data-fixture-reviewer-b")]

    def start_bulk(self) -> None:
        """Optionally hold the same native book through its existing daemon.

        Every approval still names an issued principal and every stage still
        enters the ordinary native migration admission path. Only the thousands
        of redundant file-store reopens inside the bulk loop are amortized.
        """
        if self.fad is None:
            return
        require(self.daemon is None, "native daemon is already running")
        for who in ("public-data-fixture-reviewer-a", "public-data-fixture-reviewer-b"):
            token = self.out / f"{who}.token"
            self.one(["capability", "issue", "--holder", who, "--profile", "human",
                      "--op", "read", "--op", "approve", "--out", str(token),
                      "--grant", "issue_capability", "--grant", "read", "--grant", "approve"])
            self.reviewer_tokens.append(token)
        self.calls += 1
        stem = f"{self.calls:05d}"
        stdout = self.out / "transcript" / f"{stem}.stdout.jsonl"
        stderr = self.out / "transcript" / f"{stem}.stderr.txt"
        command = [str(self.fad), "serve", "--book", str(self.book), "--json"]
        with (self.out / "commands.jsonl").open("a", encoding="utf-8") as log:
            log.write(json.dumps({"call": self.calls, "argv": command, "state": "started"}) + "\n")
        self.daemon_streams = [stdout.open("xb"), stderr.open("xb")]
        self.daemon_record = {"call": self.calls, "started": time.monotonic(), "stdout": stdout, "stderr": stderr}
        try:
            self.daemon = subprocess.Popen(command, stdout=self.daemon_streams[0], stderr=self.daemon_streams[1], env=self.env)
        except OSError:
            for stream in self.daemon_streams:
                stream.close()
            self.daemon_streams = []
            self.daemon_record = None
            raise
        deadline = time.monotonic() + self.timeout
        while time.monotonic() < deadline:
            require(self.daemon.poll() is None, "native daemon exited before readiness: " + stderr.read_text(errors="replace")[-2000:])
            for line in stdout.read_bytes().splitlines():
                try:
                    event = json.loads(line)
                except (UnicodeError, json.JSONDecodeError):
                    continue  # A concurrently written final line can be incomplete.
                if isinstance(event, dict) and event.get("event") == "fad_serving":
                    return
            time.sleep(0.1)
        raise CheckError(f"native daemon did not become ready within {self.timeout}s")

    def stop_bulk(self) -> None:
        if self.daemon is None:
            return
        process = self.daemon
        try:
            require(process.poll() is None, "native daemon exited before its explicit stop")
            self.execute(["stop"], daemon_control=True)
            try:
                code = process.wait(timeout=self.timeout)
            except subprocess.TimeoutExpired as error:
                raise CheckError("native daemon did not exit after its stop request") from error
            require(code == 0, f"native daemon exited {code}")
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
            for stream in self.daemon_streams:
                stream.close()
            record = self.daemon_record
            assert record is not None
            with (self.out / "commands.jsonl").open("a", encoding="utf-8") as log:
                log.write(json.dumps({"call": record["call"], "state": "completed", "exit": process.returncode,
                                      "seconds": round(time.monotonic() - record["started"], 3),
                                      "stdout_sha256": digest(record["stdout"].read_bytes()),
                                      "stderr_sha256": digest(record["stderr"].read_bytes())}) + "\n")
            self.daemon = None
            self.daemon_streams = []
            self.daemon_record = None

    @staticmethod
    def with_approvals(args: list[str], approvals: list[str]) -> list[str]:
        return args + [item for approval in approvals for item in ("--approval", approval)]


def run(native: Native, prepared: Path, dataset: str, expected: dict[str, Any]) -> dict[str, Any]:
    start = date.fromisoformat(expected["period_start"])
    period = f"FY{start.year}-P{start.month:02}"
    go_live = f"{start.year + 1}-01-01"
    native.one(["book", "create", "--name", f"Published expenditure model: {dataset}",
                "--base-unit", "GBP", "--opening-date", go_live])
    native.one(["chart", "import", str(prepared / "chart.json")])
    native.one(["period", "create", "--fiscal-year", str(start.year)])
    docs = {}
    for name, kind, mime in [("raw.csv", "Spreadsheet", "text/csv;charset=windows-1252"),
                             ("legacy.csv", "Spreadsheet", "text/csv;charset=utf-8"),
                             ("receipt.json", "Workpaper", "application/json"),
                             ("provenance.jsonl", "Workpaper", "application/x-ndjson"),
                             ("records.jsonl", "Workpaper", "application/x-ndjson"),
                             ("expected_tb.json", "Workpaper", "application/json")]:
        docs[name] = native.document(prepared / name, kind, mime)
    readback = native.out / "document-readback"
    readback.mkdir()
    for name, oid in docs.items():
        destination = readback / name
        observed = body(native.one(["document", "read", oid, "--out", str(destination)]))
        require(observed["view"] == "full" and destination.read_bytes() == (prepared / name).read_bytes(),
                f"retained document {name} differs from its source bytes after reopen")
    lines = [{"account": account, "unit": "GBP", "net": decimal(net)}
             for account, (_, _, net) in expected_cells(expected).items() if net]
    empty_tb = native.out / "scope-opening.json"
    write_new(empty_tb, json_bytes({"scope": "constructed published-expenditure model; no departmental opening stock asserted",
                                    "lines": []}))
    opening_doc = native.document(empty_tb, "Spreadsheet", "application/json")
    periods = []
    # The native historical span must run to go-live. Later empty months carry
    # this model's sole source month forward; no assertion about missing public
    # activity or actual departmental closing balances is made.
    for month in range(start.month, 13):
        code = f"FY{start.year}-P{month:02}"
        tb_path = native.out / f"source-control-{code}.json"
        write_new(tb_path, json_bytes({"period": code,
                                      "scope": "computed from the pinned published month only; not an audited trial balance",
                                      "source_sha256": digest((prepared / "raw.csv").read_bytes()), "lines": lines}))
        periods.append({"period": code, "trial_balance": native.document(tb_path, "Spreadsheet", "application/json"),
                        "lines": lines})
    run_path = native.out / "migration-run.json"
    write_new(run_path, json_bytes({"run_key": "public-expenditure-v1", "source_system": expected["source_system"],
                                   "mode": "FullDetail", "trial_balance": opening_doc, "opening_date": go_live,
                                   "lines": [], "periods": periods, "detail_base": [], "sole_opening_source": True}))
    run_vid = body(native.one(["migrate", "open", "--intent", str(run_path)]))["run_vid"]
    intent_path = native.out / "import.json"
    entry_periods = {entry["entry_id"]: period for entry in expected["entries"]}
    write_new(intent_path, json_bytes({"run": "MR:" + run_vid, "source": "D:" + docs["legacy.csv"], "format": "csv",
                                      "default_unit": "GBP", "account_map": json.loads((prepared / "account_map.json").read_bytes()),
                                      "column_map": (prepared / "columns.toml").read_text(), "entry_periods": entry_periods}))
    preparation = body(native.one(["migrate", "import", "--action", "prepare", "--intent", str(intent_path)]))
    require(preparation["mode"] == "FullDetail" and preparation["sole_opening_source"] is True, "native changed migration mode")
    chunks = preparation["chunks"]
    require(len(chunks) == expected["entry_count"] > 0, "native chunk count differs from complete source")
    require(sum(chunk["leg_count"] for chunk in chunks) == expected["leg_count"], "native preparation changed source leg count")
    package = preparation["package_oid"]
    before = native.head()
    again = body(native.one(["migrate", "import", "--action", "prepare", "--intent", str(intent_path)]))
    require(again["package_oid"] == package and again["already_recorded"] is True,
            "import prepare retry did not return its original retained package")
    require(native.head() == before, "import prepare retry published new state")
    check_tb(native.one(["tb", "--period", period]), expected, invisible=True)
    first_approvals: list[str] = []
    native.start_bulk()
    stage_requests = 0
    for start in range(0, len(chunks), native.stage_group_size):
        selected = chunks[start:start + native.stage_group_size]
        selection = []
        for offset, chunk in enumerate(selected):
            approvals = native.approvals(chunk["proposal_digest"])
            selection.append({"index": start + offset, "approvals": approvals})
            if start + offset == 0:
                first_approvals = approvals
        selection_path = native.out / f"stage-{start:05d}.json"
        request_bytes = json_bytes({"chunks": selection})
        write_new(selection_path, request_bytes)
        # The daemon accepts inline request bytes without a filesystem grant.
        # Retain the same bytes locally for reproducibility, but do not ask fad
        # to read an unrestricted host path on the operator's behalf.
        args = ["migrate", "import", "--action", "stage", "--package", package, "--intent", "-"]
        receipts = check_staged_group(native.one(args, request_bytes=request_bytes), selected, start=start, total=len(chunks),
                                      package=package, run_vid=run_vid)
        stage_requests += 1
        for staged in receipts:
            native.one(["document", "attach", staged["entry_vid"], "--evidence", docs["raw.csv"],
                        "--evidence", docs["receipt.json"], "--evidence", docs["provenance.jsonl"],
                        "--evidence", docs["records.jsonl"]])
        if start == 0:
            before = native.head()
            retry = check_staged_group(native.one(args, request_bytes=request_bytes), selected, start=start, total=len(chunks),
                                       package=package, run_vid=run_vid, already_recorded=True)
            require([row["recorded_at"] for row in retry] == [row["recorded_at"] for row in receipts],
                    "staged group retry changed its native publication identities")
            require(native.head() == before, "staged group retry published a duplicate")
            check_tb(native.one(["tb", "--period", period]), expected, invisible=True)
        print(f"{dataset}: staged {start + len(selected)}/{len(chunks)} chunks; source rows preserved",
              file=sys.stderr, flush=True)
    bulk_head = native.head()
    native.stop_bulk()
    require(native.head() == bulk_head, "native daemon stop/reopen changed the recorded frontier")
    shown = body(native.one(["migrate", "import", "--action", "show", "--package", package]))
    require(shown["ties_out"] is True and shown["run_state"] == "Open", "fully staged source does not tie out natively")
    check_tb(native.one(["tb", "--period", period]), expected, invisible=True)
    pre_finalize = native.head()
    plan = native.out / "finalize.plan"
    planned = body(native.one(["migrate", "finalize", run_vid, "--plan-out", str(plan)]))
    approvals = native.approvals(planned["proposal_digest"])
    before_commit = native.head()
    final = body(native.one(native.with_approvals(["migrate", "finalize", run_vid, "--plan", str(plan)], approvals)))
    require(final["to"] == "Finalized", "native run was not finalized")
    require(final["recorded_at"] == before_commit + 1 and native.head() == final["recorded_at"],
            "native finalization did not publish the complete run in exactly one commit")
    check_tb(native.one(["tb", "--period", period]), expected)
    check_tb(native.one(["tb", "--period", period, "--as-known-at", str(pre_finalize)]), expected, invisible=True)
    native.one(["registers", "advance", "--period", period])
    native.one(["verify", "registers", "--period", period])
    before = native.head()
    again = body(native.one(native.with_approvals(["migrate", "import", "--action", "stage", "--package", package,
                                                  "--chunk", "0"], first_approvals)))
    require(again["already_recorded"] is True and native.head() == before, "post-finalization retry duplicated source data")
    export = native.out / "native.csv"
    native.one(["export", "csv-gl", "--period", period, "--out", str(export)])
    native.one(["verify", "export", "csv-gl", str(export)])
    census = check_export(export, prepared, expected)
    certified_events = native.execute(["tb", "--period", period, "--certify"])
    certificate_event = event_named(certified_events, "report_certificate")
    report_events = [event for event in certified_events if event.get("event") != "report_certificate"]
    require(len(report_events) == 1, "certification did not emit one native trial balance")
    check_tb(report_events[0], expected)
    certificate = body(certificate_event)
    locator = "C:" + certificate["oid"]
    replay = native.execute(["replay", locator, "--output", str(native.out / "replayed.report")])
    # The retained canonical output digest is the report's native replay promise.
    check_tb(event_named(replay, "trial_balance"), expected)
    replay_body = body(event_named(replay, "report_replayed"))
    require(replay_body.get("output_digest") == certificate["output_digest"], "native replay did not reproduce the certified output digest")
    state = body(native.one(["checkpoint", "create", "--grant", "witness"]))
    signed = body(native.one(["proof", "signed-checkpoint", "--state", state["oid"]]))
    checkpoint_path = native.out / "report.checkpoint"
    write_new(checkpoint_path, bytes.fromhex(signed["bytes"]))
    bundle_path, receipt_path = native.out / "trial-balance.fab", native.out / "trial-balance.receipt"
    native.one(["bundle", "produce", "--certificate", locator, "--state", state["oid"],
                "--out", str(bundle_path), "--receipt-out", str(receipt_path)])
    verify_args = ["report", str(bundle_path), "--key", signed["checkpoint_public_key"],
                   "--checkpoint", str(checkpoint_path), "--receipt", str(receipt_path), "--expect", certificate["oid"]]
    verified = native.execute(verify_args, verifier=True)
    require(any(event.get("verdict") == "verified" for event in verified), "independent verifier returned no verified verdict")
    bad_path = native.out / "tampered-trial-balance.fab"
    tampered = bytearray(bundle_path.read_bytes())
    require(bool(tampered), "native produced an empty report bundle")
    tampered[len(tampered) // 2] ^= 1
    write_new(bad_path, bytes(tampered))
    bad_args = verify_args.copy()
    bad_args[1] = str(bad_path)
    negative = native.execute(bad_args, verifier=True, expected_exit=8)
    require(not any(event.get("verdict") == "verified" for event in negative), "tampered bundle was labeled verified")
    return {"status": "PASS", "dataset": dataset, "source_sha256": digest((prepared / "raw.csv").read_bytes()),
            "source_stats": expected["source_stats"], "native_export": census, "native_calls": native.calls,
            "stage_group_size": native.stage_group_size, "stage_requests": stage_requests,
            "period": period, "migration_run": run_vid, "package_oid": package, "documents": docs,
            "certificate_digest": certificate["oid"], "output_digest": certificate["output_digest"],
            "checkpoint_public_key": signed["checkpoint_public_key"], "bundle_sha256": digest(bundle_path.read_bytes()),
            "checks": ["pinned_original_bytes", "deterministic_source_transform", "all_source_documents_durable_byte_identity",
                       "complete_chunk_and_leg_census", "group_receipts_bind_every_approved_chunk",
                       "prepare_retry_without_publication", "chunk_retry_without_publication", "staged_invisibility",
                       "native_full_detail_tieout", "atomic_finalization", "historical_invisibility",
                       "exact_gross_and_net_by_account", "registers_equal_fold", "finalized_retry_without_publication",
                       "native_csv_export_verification", "every_dated_exported_leg_and_memo", "native_certificate_replay",
                       "independent_fa_verify_report", "tampered_bundle_refused"],
            "boundary": "Complete published monthly expenditure extract under a declared offset-account model; not a complete original GL, independent human review, fraud finding, or audited trial balance."}


def binary(value: str) -> Path:
    found = shutil.which(value)
    path = Path(found if found else value).resolve()
    if not path.is_file() or not os.access(path, os.X_OK):
        raise argparse.ArgumentTypeError(f"executable not found: {value}")
    return path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prepared", type=Path, required=True, help="complete public_spend.py output directory")
    parser.add_argument("--dataset", required=True, help="pinned sources.toml dataset id")
    parser.add_argument("--out", type=Path, required=True, help="new retained execution directory; existing paths are refused")
    parser.add_argument("--fa", type=binary, default="fa")
    parser.add_argument("--fa-verify", type=binary, default="fa-verify")
    parser.add_argument("--fad", type=binary, help="optional native fad executable for the bulk staging loop")
    parser.add_argument("--timeout", type=int, default=300, help="per-native-command timeout in seconds")
    parser.add_argument("--stage-group-size", type=int, default=64,
                        help="independently approved chunks per source-authenticated request (1..4096; default 64)")
    args = parser.parse_args()
    if args.timeout < 1:
        parser.error("--timeout must be positive")
    if not 1 <= args.stage_group_size <= 4096:
        parser.error("--stage-group-size must be between 1 and 4096")
    prepared, out = args.prepared.resolve(), args.out.resolve()
    try:
        _, expected = verify_prepared(prepared, args.dataset)
        out.mkdir(parents=True, exist_ok=False)
    except (OSError, ValueError, CheckError) as error:
        print(f"public-data preflight refused: {error}", file=sys.stderr)
        return 2
    native = Native(args.fa, args.fa_verify, out, args.timeout, args.fad, args.stage_group_size)
    started = time.monotonic()
    result = {"status": "FAIL", "dataset": args.dataset,
              "boundary": "Only completed commands in commands.jsonl ran. No unexecuted native check passed."}
    code = 1
    try:
        result = run(native, prepared, args.dataset, expected)
        code = 0
    except KeyboardInterrupt:
        result["error"] = "interrupted before all required native observations completed"
        code = 130
    except Exception as error:
        result["error"] = f"{type(error).__name__}: {error}"
    finally:
        # An interrupted or unexpectedly failed run must not leave its daemon
        # holding the book's writer lease. Preserve the primary failure too.
        try:
            native.stop_bulk()
        except Exception as error:
            result["status"] = "FAIL"
            result["daemon_shutdown_error"] = f"{type(error).__name__}: {error}"
            if code == 0:
                code = 1
    result["native_calls"] = native.calls
    result["elapsed_seconds"] = round(time.monotonic() - started, 3)
    result["fa_sha256"] = digest(args.fa.read_bytes())
    result["fa_verify_sha256"] = digest(args.fa_verify.read_bytes())
    result["bulk_transport"] = "native_fad" if args.fad is not None else "direct_cli"
    if args.fad is not None:
        result["fad_sha256"] = digest(args.fad.read_bytes())
    write_new(out / "result.json", json_bytes(result))
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
