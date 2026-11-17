"""Run: python3 test_dashboard_rest.py   (starts a fake Dashboard REST server on localhost; no mcp package needed)"""
import asyncio, base64, contextlib, csv, io, json, sys, tempfile, threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs

import dashboard_rest as dr
import gatekeeper_validate as g

FAILS, REQUESTS = [], []
D = "AAD"


def violation(n, comp, with_findings=True):
    v = {"component": {"href": f"{D}/components/{n}/snapshots/6", "name": comp,
                       "sourceCodes": {"href": f"{D}/components/{n}/snapshots/6/source-codes", "name": "Source Codes"}},
         "rulePattern": {"href": f"{D}/rule-patterns/7544"}}
    if with_findings:
        v["diagnosis"] = {"findings": {"href": f"{D}/components/{n}/snapshots/6/findings/7544"}}
    return v


# rule 7544: 3 violations (paging test uses nbRows=2); rule 1020060: 1 violation without findings; rule 7520: none
VIOLATIONS = {"7544": [violation(1, "ZPROG"), violation(2, "ZPROG2"), violation(3, "ZPROG3")],
              "1020060": [violation(4, "main.js", with_findings=False)], "7520": []}
ABAP_SRC = "SELECT SINGLE * FROM mara INTO ls WHERE matnr = p.\nSELECT * FROM mara INTO ls.\n  WRITE ls.\nENDSELECT.\n"
JS_SRC = 'var a = 1;\nconsole.log(1);\n'
FILES = {"D:\\deploy\\APP\\abap\\zprog.abap": (f"{D}/local-sites/9/file-contents/100", ABAP_SRC),
         "D:\\deploy\\APP\\web\\main.js": (f"{D}/local-sites/9/file-contents/101", JS_SRC)}
ABAP_F = {"name": "D:\\deploy\\APP\\abap\\zprog.abap", "href": f"{D}/local-sites/9/file-contents/100"}   # Windows path, like the real server
JS_F = {"name": "D:\\deploy\\APP\\web\\main.js", "href": f"{D}/local-sites/9/file-contents/101"}
FINDINGS = {  # real shape: bookmarks = list of lists of {component, codeFragment{file, startLine}}
    1: {"name": "Number of violation occurrences", "type": "integer", "values": [1], "bookmarks": [[
        {"component": {"name": "ZPROG"}, "codeFragment": {"file": ABAP_F, "startLine": 1, "endLine": 1}}]]},
    2: {"name": "Diagnosis Findings", "bookmarks": [[{"codeFragment": {"file": ABAP_F, "startLine": 2}}],
                                                    [{"codeFragment": {"file": ABAP_F, "startLine": 2}}]]},
    3: {"name": "Diagnosis Findings", "values": []},          # no location in the findings -> falls back to source-codes
}
SOURCES = {3: [{"file": ABAP_F, "startLine": 2, "endLine": 4}],
           4: [{"file": JS_F, "startLine": 2}]}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def reply(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code); self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)

    def do_GET(self):
        u = urlparse(self.path); q = {k: v[0] for k, v in parse_qs(u.query).items()}
        REQUESTS.append((u.path, q))
        basic = "Basic " + base64.b64encode(b"bob:pw").decode()
        ok = self.headers.get("Authorization") == basic or (
            self.headers.get("X-API-KEY") == "k3y" and self.headers.get("X-API-USER") == "bob")
        sent = self.headers.get("Authorization") or self.headers.get("X-API-KEY")
        if not u.path.startswith("/rest/"):                      # not the REST root at all
            return self.reply(404, {"message": "not found"})
        if not ok:
            if not sent:                                         # like the real server: 401 without credentials...
                return self.reply(401, {"message": "unauthorized"})
            body = b"<!doctype html><html><head><title>HTTP Status 404 - Not Found</title></head></html>"
            self.send_response(404); self.send_header("Content-Type", "text/html")      # ...but 404 for WRONG credentials
            self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
            return
        p = u.path
        if p == "/rest/login":
            return self.reply(200, True)
        if p == f"/rest/{D}/applications":
            return self.reply(200, [{"href": f"{D}/applications/3", "name": "MyApp", "snapshots": {"href": f"{D}/applications/3/snapshots"}},
                                    {"href": f"{D}/applications/4", "name": "Other"}])
        if p == f"/rest/{D}/applications/3/snapshots":
            return self.reply(200, [{"href": f"{D}/applications/3/snapshots/5", "number": 1, "annotation": {"date": {"time": 1000}}},
                                    {"href": f"{D}/applications/3/snapshots/6", "number": 2, "annotation": {"date": {"time": 2000}}}])
        if p == f"/rest/{D}/applications/3/snapshots/6/violations":
            allv = VIOLATIONS.get(q.get("rule-pattern"), [])
            s, n = int(q.get("startRow", 1)), int(q.get("nbRows", 10))
            return self.reply(200, allv[s - 1:s - 1 + n])
        for name, (href, text) in FILES.items():
            if p == "/rest/" + href:
                body = text.encode()
                self.send_response(200); self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
                return
        parts = p.split("/")                       # /rest/AAD/components/<id>/snapshots/6/<findings/7544|source-codes>
        if len(parts) > 5 and parts[3] == "components":
            cid = int(parts[4])
            if parts[-1] == "source-codes":
                return self.reply(200, SOURCES.get(cid, []))
            if "findings" in parts:
                return self.reply(200, FINDINGS.get(cid, {}))
        return self.reply(404, {"message": "not found"})


def check(name, cond, detail=""):
    if not cond:
        FAILS.append(name); print(f"FAIL {name} {detail}")


def run(argv):
    out, code, old = io.StringIO(), 0, sys.argv
    sys.argv = ["gatekeeper_validate.py", *argv]
    try:
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            asyncio.run(g.main())
    except SystemExit as e:
        code = e.code if isinstance(e.code, int) else 1
        if isinstance(e.code, str):
            out.write(e.code)
    finally:
        sys.argv = old
    return out.getvalue(), code


def main():
    srv = HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_port}/rest"
    tmp = Path(tempfile.mkdtemp()); src = tmp / "src"
    (src / "abap").mkdir(parents=True); (src / "web").mkdir()
    (src / "abap" / "zprog.abap").write_text(
        "SELECT SINGLE * FROM mara INTO ls WHERE matnr = p.\nSELECT * FROM mara INTO ls.\n  WRITE ls.\nENDSELECT.\n")
    (src / "web" / "main.js").write_text('var a = 1;\nconsole.log(1);\n')

    # --- client
    c = dr.DashboardClient(base, D, user="bob", password="pw")
    app = c.find_application("myapp")
    check("application by name, case-insensitive", app["href"] == f"{D}/applications/3")
    check("latest snapshot by date", c.find_snapshot(app)["number"] == 2)
    check("snapshot by number", c.find_snapshot(app, "1")["number"] == 1)
    snap = c.find_snapshot(app)
    REQUESTS.clear()
    got = list(c.iter_violations(snap, "7544", page=2))
    check("paging returns all violations", len(got) == 3, len(got))
    check("paging uses startRow/nbRows", [(q["startRow"], q["nbRows"]) for p, q in REQUESTS] == [("1", "2"), ("3", "2")], REQUESTS)
    check("rule-pattern parameter sent", all(q["rule-pattern"] == "7544" for p, q in REQUESTS))
    check("limit respected", len(list(c.iter_violations(snap, "7544", limit=1))) == 1)
    f100 = f"{D}/local-sites/9/file-contents/100"
    p = "D:\\deploy\\APP\\abap\\zprog.abap"
    check("locations from findings, deduplicated", c.locations(got[1]) == [(p, 2, f100)], c.locations(got[1]))
    check("fallback to source-codes", c.locations(got[2]) == [(p, 2, f100)], c.locations(got[2]))
    d = c.download(f100, p)
    check("download keeps the extension and content", d.endswith(".abap") and open(d).read() == ABAP_SRC, d)
    check("download is cached", c.download(f100, p) == d)
    check("no location -> empty", c.locations(violation(9, "none", with_findings=False)) == [])
    k = dr.DashboardClient(base, D, api_key="k3y", api_user="bob")
    check("api-key authentication", k.find_application("MyApp")["name"] == "MyApp")

    for name, fn, frag in [
        ("unknown application lists the available ones", lambda: c.find_application("Nope"), "Available: MyApp, Other"),
        ("wrong password (server answers 404) -> rejected credentials", lambda: dr.DashboardClient(base, D, user="bob", password="x").find_application("MyApp"), "rejected the credentials for user 'bob'"),
        ("wrong user -> rejected credentials", lambda: dr.DashboardClient(base, D, user="nobody", password="pw").find_application("MyApp"), "rejected the credentials"),
        ("password with a trailing space -> rejected credentials", lambda: dr.DashboardClient(base, D, user="bob", password="pw ").find_application("MyApp"), "stray space"),
        ("wrong api key -> rejected credentials", lambda: dr.DashboardClient(base, D, api_key="bad", api_user="bob").find_application("MyApp"), "rejected the credentials"),
        ("wrong domain, good credentials -> check --domain", lambda: dr.DashboardClient(base, "NOPE", user="bob", password="pw").find_application("MyApp"), "credentials are accepted"),
        ("wrong rest url -> not the REST root", lambda: dr.DashboardClient(base + "x", D, user="bob", password="pw").find_application("MyApp"), "REST root"),
        ("unreachable", lambda: dr.DashboardClient("http://127.0.0.1:9/rest", D, user="bob", password="pw").find_application("MyApp"), "Cannot reach"),
        ("api key without user", lambda: dr.DashboardClient(base, D, api_key="k3y"), "--api-user"),
        ("no credentials", lambda: dr.DashboardClient(base, D), "No credentials")]:
        try:
            fn(); check(name, False, "no error")
        except dr.RestError as e:
            check(name, frag in str(e), str(e))

    # --- end to end through the CLI
    out = tmp / "report.csv"
    common = ["--rest-url", base, "--domain", D, "--user", "bob", "--password", "pw", "--app", "MyApp",
              "--out", str(out)]                     # no --source-root: the source comes from the server
    text, code = run(common + ["--rule-ids", "7544,1020060,7520"])
    rows = list(csv.DictReader(open(out, encoding="utf-8-sig")))
    got = sorted((r["rule"], r["line"], r["verdict"], r["object"]) for r in rows)
    check("exit ok", code == 0, text)
    check("verdicts from REST data", got == [("1020060", "2", "TRUE_POSITIVE", "main.js"),
                                             ("7544", "1", "FALSE_POSITIVE", "ZPROG"),
                                             ("7544", "2", "TRUE_POSITIVE", "ZPROG2"),
                                             ("7544", "2", "TRUE_POSITIVE", "ZPROG3")], got)
    check("snapshot announced", "snapshot 2" in text, text)
    check("justification present for the false positive", any(r["justification"] for r in rows if r["verdict"] == "FALSE_POSITIVE"))

    text, _ = run(common + ["--rule-ids", "7544", "--limit", "2"])
    check("--limit applies to locations", len(list(csv.DictReader(open(out, encoding="utf-8-sig")))) == 2, text)
    text, _ = run(common + ["--rule-ids", "7544,1020060", "--no-true-positives"])
    rows = list(csv.DictReader(open(out, encoding="utf-8-sig")))
    check("REST mode --no-true-positives: only the false positive is written",
          [r["verdict"] for r in rows] == ["FALSE_POSITIVE"] and "TRUE_POSITIVE row(s) not written" in text, (rows, text))
    text, _ = run(common + ["--rule-ids", "7544", "--snapshot", "1"])
    check("--snapshot number", "snapshot 1" in text, text)

    saved = dict(FILES); FILES.clear()                    # server stops serving files -> local --source-root is the fallback
    text, _ = run(common + ["--rule-ids", "1020060", "--source-root", str(src)])
    rows = list(csv.DictReader(open(out, encoding="utf-8-sig")))
    check("fallback to --source-root when the download fails", [r["verdict"] for r in rows] == ["TRUE_POSITIVE"], (rows, text))
    text, _ = run(common + ["--rule-ids", "1020060"])
    rows = list(csv.DictReader(open(out, encoding="utf-8-sig")))
    check("no download and no --source-root -> REVIEW", [r["verdict"] for r in rows] == ["REVIEW"] and "not available" in rows[0]["reason"], (rows, text))
    FILES.update(saved)

    text, code = run(common + ["--rule-ids", "7544", "--dump"])
    check("--dump prints the violation, findings and source-codes", '"violation"' in text and '"findings"' in text and "7544" in text, text)

    for argv, frag, name in [
        (["--rest-url", base, "--domain", D, "--user", "bob", "--password", "pw", "--app", "Nope"], "Available: MyApp", "unknown app"),
        (["--rest-url", base, "--domain", D, "--user", "bob", "--password", "bad", "--app", "MyApp"], "rejected the credentials", "bad password"),
        (["--rest-url", base, "--domain", "NOPE", "--user", "bob", "--password", "pw", "--app", "MyApp"], "credentials are accepted", "bad domain"),
    ]:
        text, code = run(argv)
        check(f"CLI error: {name}", code != 0 and frag in text and "Traceback" not in text, text)
    text, code = run(["--rest-url", base, "--user", "bob", "--app", "MyApp"])
    check("--domain required", code == 2)
    text, code = run(common + ["--apply-exclusions"])
    check("--apply-exclusions refused in REST mode", code == 2)
    text, code = run(common + ["--input", "x.csv"])
    check("--input and --rest-url exclusive", code == 2)

    srv.shutdown()
    print("all passed" if not FAILS else f"{len(FAILS)} failed: {', '.join(FAILS)}")
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())
