#!/usr/bin/env python3
"""Local, read-only presentation companion to fa's versioned robot API.

The book engine, authority checks and accounting folds remain in fa/fad. This
stdlib-only development/desktop server is intentionally not a deployment server.
"""
from __future__ import annotations

import argparse
import hmac
import json
from pathlib import Path
import re
import secrets
import shutil
import socket
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import subprocess
import sys
import threading
from typing import Any
from urllib.parse import parse_qs, urlsplit
import webbrowser

import reports

ROOT = Path(__file__).resolve().parent
MAX_OUTPUT = 16 * 1024 * 1024
MAX_STDERR = 64 * 1024
STATIC = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/app.js": ("app.js", "text/javascript; charset=utf-8"),
    "/amounts.mjs": ("amounts.mjs", "text/javascript; charset=utf-8"),
    "/styles.css": ("styles.css", "text/css; charset=utf-8"),
}
CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; "
       "connect-src 'self'; img-src 'self' data:; font-src 'self'; "
       "base-uri 'none'; object-src 'none'; frame-ancestors 'none'; form-action 'none'")


class DashboardError(Exception):
    def __init__(self, message: str, status: int = 502, detail: Any = None):
        super().__init__(message)
        self.status = status
        self.detail = detail


def text(value: str | None, name: str) -> str:
    # argv, never a shell; still reject option-shaped operands and control chars.
    if not value or len(value) > 128 or value.startswith("-") or any(ord(c) < 32 for c in value):
        raise DashboardError(f"Invalid {name}.", 400)
    return value


def sequence(value: str) -> str:
    if value == "HEAD":
        return value
    if not re.fullmatch(r"0|[1-9][0-9]{0,19}", value) or int(value) > 2**64 - 1:
        raise DashboardError("known_at must be HEAD or an unsigned 64-bit commit sequence.", 400)
    return value


def entry_id(value: str) -> str:
    value = value.removeprefix("E:")
    if not re.fullmatch(r"[0-9a-fA-F]{32}", value):
        raise DashboardError("An entry handle must contain exactly 32 hexadecimal digits.", 400)
    return value.lower()


def exact_transport(value: Any) -> Any:
    """JSON integers travel as decimal strings: JS must not round i128 or u64."""
    if isinstance(value, bool) or value is None:
        return value
    if isinstance(value, int):
        return str(value)
    if isinstance(value, list):
        return [exact_transport(v) for v in value]
    if isinstance(value, dict):
        return {k: exact_transport(v) for k, v in value.items()}
    return value


def reject_float(_: str) -> None:
    raise DashboardError("fa returned a non-integer JSON number; refusing lossy data.")


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise DashboardError("fa returned duplicate JSON fields.")
        result[key] = value
    return result


def run_bounded(argv: list[str], timeout: float) -> tuple[int, bytes, bytes]:
    """Bound both pipes while they are being drained, not after capture_output."""
    buffers = [bytearray(), bytearray()]
    oversized = threading.Event()
    try:
        child = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, shell=False)
    except OSError as error:
        raise DashboardError("Cannot start fa. Check the launch-time --fa executable.", 503) from error

    def drain(pipe: Any, index: int, limit: int) -> None:
        try:
            while block := pipe.read(65536):
                if len(buffers[index]) + len(block) > limit:
                    oversized.set()
                    child.kill()
                    break
                buffers[index].extend(block)
        finally:
            pipe.close()

    readers = [threading.Thread(target=drain, args=(child.stdout, 0, MAX_OUTPUT), daemon=True),
               threading.Thread(target=drain, args=(child.stderr, 1, MAX_STDERR), daemon=True)]
    for reader in readers:
        reader.start()
    try:
        child.wait(timeout=timeout)
    except subprocess.TimeoutExpired as error:
        child.kill()
        child.wait()
        raise DashboardError("The native read timed out. Narrow the selection or increase --timeout.", 504) from error
    finally:
        for reader in readers:
            reader.join(timeout=1)
    if oversized.is_set():
        raise DashboardError("The native response exceeds the local display bound; narrow the selection.", 413)
    if any(reader.is_alive() for reader in readers):
        raise DashboardError("The native process did not close its output streams.")
    return child.returncode, bytes(buffers[0]), bytes(buffers[1])


class NativeSource:
    mode = "live"

    def __init__(self, binary: str, book: Path, principal: str, keys: Path | None, timeout: float):
        self.base = [binary, "--book", str(book), "--as", principal, "--json", "--no-color"]
        if keys:
            self.base.extend(["--keys", str(keys)])
        self.timeout = timeout
        self.book_id: str | None = None

    def call(self, argv: list[str], event: str, *, verification: bool = False) -> dict[str, Any]:
        code, stdout, _stderr = run_bounded(self.base + argv, self.timeout)
        try:
            events = [json.loads(line, parse_float=reject_float, parse_constant=reject_float,
                                 object_pairs_hook=unique_object)
                      for line in stdout.decode("utf-8").splitlines() if line.strip()]
        except (UnicodeError, ValueError) as error:
            raise DashboardError("fa did not return valid UTF-8 robot-mode JSON.") from error
        if not events or any(not isinstance(e, dict) or type(e.get("v")) is not int or e.get("v") != 1 or
                             not isinstance(e.get("data"), dict) for e in events):
            raise DashboardError("Unsupported or missing fa robot envelope; this dashboard needs v1.")
        failures = [e for e in events if e.get("event") == "error"]
        matches = [e for e in events if e.get("event") == event]
        if code != 0 or failures:
            if verification and code == 8 and len(failures) == 1:
                # Preserve a native red result; never substitute an empty green check.
                return {"event": event, "failed": True, "error": failures[0]["data"],
                        "coordinate": failures[0].get("coordinate"),
                        "data": matches[0]["data"] if len(matches) == 1 else None}
            detail = failures[0]["data"] if failures else {"exit": code}
            raise DashboardError("The native read was refused or failed.", 502, detail)
        if len(matches) != 1:
            raise DashboardError(f"Expected exactly one {event} event from fa.")
        answer = matches[0]
        coordinate = answer.get("coordinate")
        if not isinstance(coordinate, dict) or coordinate.get("branch") != "trunk":
            raise DashboardError("A native read did not identify the trunk coordinate.")
        at = coordinate.get("known_at")
        if isinstance(at, bool) or not isinstance(at, int) or not 0 <= at < 2**64:
            raise DashboardError("A native read did not identify an exact commit sequence.")
        book_id = answer.get("book")
        if not isinstance(book_id, str) or not re.fullmatch(r"[0-9a-f]{32}", book_id):
            raise DashboardError("A native read did not identify its book.")
        if self.book_id is not None and book_id != self.book_id:
            raise DashboardError("The book changed during this session. Restart the dashboard.", 409)
        self.book_id = book_id
        return answer

    @staticmethod
    def pin(event: dict[str, Any], known_at: str) -> str:
        coordinate = event["coordinate"]["known_at"]
        declared = event["data"].get("known_at", coordinate)
        if declared != coordinate or (known_at != "HEAD" and str(coordinate) != known_at):
            raise DashboardError("Native report coordinates disagree; refusing a mixed snapshot.", 409)
        return str(coordinate)

    def bootstrap(self) -> dict[str, Any]:
        return {"book": self.call(["book", "info"], "book"),
                "periods": self.call(["period", "list"], "periods")}

    def overview(self, period: str, known_at: str) -> dict[str, Any]:
        stock = self.call(["tb", "--period", period, "--as-known-at", known_at], "trial_balance")
        at = self.pin(stock, known_at)
        activity = self.call(["tb", "--period", period, "--activity", "--as-known-at", at], "trial_balance")
        self.pin(activity, at)
        if stock["data"].get("activity") is not False or activity["data"].get("activity") is not True:
            raise DashboardError("The native response did not honor stock/activity selection.")
        return {"known_at": at, "stock": stock, "activity": activity}

    def account(self, account: str, period: str, known_at: str) -> dict[str, Any]:
        answer = self.call(["explain", "balance", account, "--period", period,
                            "--as-known-at", known_at], "balance_explained")
        self.pin(answer, known_at)
        return {"report": answer}

    def entry(self, vid: str) -> dict[str, Any]:
        # These verbs have no historical selector. Keep each current coordinate;
        # the UI must not present later reviews or supersession as historical.
        return {"entry": self.call(["explain", "entry", vid], "entry_explained"),
                "evidence": self.call(["explain", "evidence", vid], "evidence_explained")}

    def health(self) -> dict[str, Any]:
        return {"report": self.call(["triage"], "book_triage")}

    def projections(self) -> dict[str, Any]:
        return {"report": self.call(["verify", "projections"], "projections_verified", verification=True)}


class DashboardServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = False

    def __init__(self, source: Any, title: str, port: int):
        self.source, self.title = source, title
        self.token = secrets.token_urlsafe(32)
        self.native_lock = threading.Lock()
        self.connections = threading.BoundedSemaphore(8)
        # Never expose a configurable interface. No wildcard or LAN binding.
        super().__init__(("127.0.0.1", port), Handler)
        self.origin = f"http://127.0.0.1:{self.server_port}"

    def get_request(self) -> tuple[socket.socket, Any]:
        sock, address = super().get_request()
        sock.settimeout(5)
        return sock, address

    def process_request(self, request: socket.socket, client_address: Any) -> None:
        if not self.connections.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self.connections.release()
            raise

    def process_request_thread(self, request: socket.socket, client_address: Any) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.connections.release()


class Handler(BaseHTTPRequestHandler):
    server: DashboardServer
    server_version = "FrankenAccounting-Local/1"
    sys_version = ""

    def log_message(self, _format: str, *args: Any) -> None:
        # Do not log tokens, entry IDs, account selectors or native diagnostics.
        pass

    def send_bytes(self, status: int, content: bytes, mime: str) -> None:
        self.send_response(status)
        for key, value in {"Content-Type": mime, "Content-Length": str(len(content)),
                           "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff",
                           "Content-Security-Policy": CSP, "Referrer-Policy": "no-referrer",
                           "X-Frame-Options": "DENY", "Connection": "close",
                           "Permissions-Policy": "camera=(), microphone=(), geolocation=()"}.items():
            self.send_header(key, value)
        self.end_headers()
        self.close_connection = True
        self.wfile.write(content)

    def send_json(self, status: int, value: Any) -> None:
        self.send_bytes(status, json.dumps(exact_transport(value), ensure_ascii=True,
                                          allow_nan=False, separators=(",", ":")).encode(),
                        "application/json; charset=utf-8")

    def admit(self) -> None:
        expected = self.server.origin.removeprefix("http://")
        if self.headers.get_all("Host", []) != [expected]:
            raise DashboardError("Only the launch URL's loopback Host is accepted.", 403)
        origin = self.headers.get_all("Origin", [])
        if origin and origin != [self.server.origin]:
            raise DashboardError("Cross-origin requests are not allowed.", 403)
        if self.headers.get("Sec-Fetch-Site") not in (None, "none", "same-origin"):
            raise DashboardError("Cross-site requests are not allowed.", 403)
        if self.headers.get("Transfer-Encoding") or self.headers.get("Content-Length", "0") != "0":
            raise DashboardError("Requests must not contain a body.", 400)
        if len(self.path) > 2048:
            raise DashboardError("Request target is too long.", 414)

    def do_GET(self) -> None:
        try:
            self.admit()
            target = urlsplit(self.path)
            if target.scheme or target.netloc or target.fragment:
                raise DashboardError("Use an origin-relative request target.", 400)
            if target.path in STATIC:
                if target.query:
                    raise DashboardError("Static assets do not accept parameters.", 400)
                name, mime = STATIC[target.path]
                self.send_bytes(200, (ROOT / "web" / name).read_bytes(), mime)
                return
            if not target.path.startswith("/api/"):
                raise DashboardError("Not found.", 404)
            credentials = self.headers.get_all("Authorization", [])
            if len(credentials) != 1 or not hmac.compare_digest(
                credentials[0].encode("utf-8"), ("Bearer " + self.server.token).encode("utf-8")
            ):
                raise DashboardError("Open the private launch URL from your terminal to connect.", 401)
            try:
                values = parse_qs(target.query, keep_blank_values=True, strict_parsing=True,
                                  max_num_fields=8)
            except ValueError as error:
                raise DashboardError("Invalid query parameters.", 400) from error
            if any(len(v) != 1 for v in values.values()):
                raise DashboardError("Duplicate parameters are not allowed.", 400)
            params = {key: val[0] for key, val in values.items()}
            allowed = {"/api/bootstrap": set(), "/api/overview": {"period", "known_at"},
                       "/api/account": {"account", "period", "known_at"}, "/api/entry": {"vid"},
                       "/api/health": set(), "/api/projections": set(), **reports.ROUTES}
            if target.path not in allowed:
                raise DashboardError("Not found.", 404)
            if set(params) - allowed[target.path]:
                raise DashboardError("Unknown parameters are not accepted.", 400)
            if not self.server.native_lock.acquire(blocking=False):
                raise DashboardError("Another native read is running. Try again after it completes.", 429)
            try:
                source = self.server.source
                if target.path in reports.ROUTES:
                    result = reports.dispatch(source, target.path, params, DashboardError)
                elif target.path == "/api/bootstrap":
                    result = source.bootstrap()
                elif target.path == "/api/overview":
                    result = source.overview(text(params.get("period"), "period"),
                                             sequence(params.get("known_at", "HEAD")))
                elif target.path == "/api/account":
                    result = source.account(text(params.get("account"), "account"),
                                            text(params.get("period"), "period"),
                                            sequence(params.get("known_at", "HEAD")))
                elif target.path == "/api/entry":
                    result = source.entry(entry_id(params.get("vid", "")))
                elif target.path == "/api/projections":
                    result = source.projections()
                else:
                    result = source.health()
            finally:
                self.server.native_lock.release()
            self.send_json(200, {"schema": "fa-dashboard/v1", "mode": source.mode,
                                 "read_only": True, "title": self.server.title, **result})
        except DashboardError as error:
            self.send_json(error.status, {"error": str(error), "detail": error.detail})
        except (BrokenPipeError, ConnectionResetError, TimeoutError):
            self.close_connection = True
        except Exception:
            self.send_json(500, {"error": "The local dashboard could not complete this read. No write was requested."})

    def do_POST(self) -> None:
        self.send_json(405, {"error": "This dashboard has no write endpoints."})

    do_PUT = do_PATCH = do_DELETE = do_POST
    do_OPTIONS = do_HEAD = do_POST


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("--book", type=Path, help="one existing local book; never browser-selectable")
    target.add_argument("--demo", action="store_true", help="explicit synthetic design preview; never reads a book")
    parser.add_argument("--fa", default="fa", help="trusted local fa executable")
    parser.add_argument("--keys", type=Path, help="optional launch-time native key-file path")
    parser.add_argument("--as", dest="principal", default="operator", help="native owner-CLI principal claim")
    parser.add_argument("--title", help="display name, not a journaled book name")
    parser.add_argument("--port", type=int, default=0, help="loopback port; 0 chooses an unused port")
    parser.add_argument("--timeout", type=float, default=30, help="per-native-read seconds (1..120)")
    parser.add_argument("--open", action="store_true", help="open the private launch URL in your default browser")
    args = parser.parse_args()
    if not 0 <= args.port <= 65535 or not 1 <= args.timeout <= 120:
        parser.error("port must be 0..65535 and timeout 1..120")
    if args.demo:
        if args.keys:
            parser.error("--keys is not used in demo mode")
        from demo import DemoSource
        source: Any = DemoSource(DashboardError)
        title = args.title or "Northstar Studio · sample book"
    else:
        book = args.book.expanduser().resolve()
        if not book.is_dir():
            parser.error("--book must name an existing book directory")
        binary = shutil.which(args.fa)
        if not binary:
            parser.error("fa is not installed or not on PATH; supply --fa /path/to/fa")
        if not args.principal or args.principal.startswith("-"):
            parser.error("invalid --as principal")
        source = NativeSource(str(Path(binary).resolve()), book, args.principal,
                              args.keys.expanduser().resolve() if args.keys else None, args.timeout)
        title = args.title or book.name
    try:
        server = DashboardServer(source, title, args.port)
    except OSError as error:
        print(f"Cannot bind the loopback dashboard: {error}", file=sys.stderr)
        return 4
    url = f"{server.origin}/#token={server.token}"
    print(f"FrankenAccounting · {'SYNTHETIC DEMO' if args.demo else 'local owner read-only view'}\n{url}\n"
          "Keep this URL private. Ctrl-C stops the dashboard. No posting or remote access endpoints.", flush=True)
    if args.open:
        webbrowser.open(url, new=2)
    try:
        server.serve_forever(poll_interval=0.25)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
