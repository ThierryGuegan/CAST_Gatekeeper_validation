#!/usr/bin/env python3
"""
gatekeeper_validate - triage CAST Imaging Gatekeeper violations as true / false positives.

For every selected quality rule the tool
  1. gets the violations from the Gatekeeper MCP server (tool get_violations, needs Imaging >= 3.6.4),
     from the CAST Dashboard REST API (--rest-url) or from an exported CSV/JSON file (--input),
  2. reads the source file at the reported line from a local checkout,
  3. runs the rule's checker and classifies the violation
       TRUE_POSITIVE | FALSE_POSITIVE | REVIEW   (REVIEW = cannot be decided from the source),
  4. writes a CSV report with the reason, the evidence (code) and a ready-to-use justification,
  5. optionally creates the exclusions in Imaging for the false positives.

Rule families (one checker module each):
  abap    abap_checkers.py     ABAP (technology group TG001, extension com.castsoftware.sap)
  sapui5  sapui5_checkers.py   SAPUI5 extension rules 10206xx
  web     web_checkers.py      TG004: HTML5/JavaScript, TypeScript, Node.js, jQuery, AngularJS/Angular,
                               React, Vue, CSS
  sql     sql_checkers.py      SQL Analyzer: PL/SQL, T-SQL, COBOL embedded SQL (rules 11010xx)

Input (one of):  --url/--api-key/--app          Gatekeeper MCP server (Imaging >= 3.6.4)
                 --rest-url/--domain/--app     CAST Dashboard REST API (Imaging before 3.6.4), see dashboard_rest.py;
                                               the analysed source is downloaded from the server (--source-root optional)
                 --input violations.csv        CSV/JSON export, no server needed
Rule selection:  --rule-ids auto | abap | sapui5 | web | sql | all | 7520,1020600,...
                 auto = every rule that has a real checker (default)
                 all  = auto + rules that can only get a REVIEW verdict
Limits:          --limit N (overall), --per-rule-limit N (per rule); both count the violations checked,
                 true positives included
Report:          --no-true-positives writes only FALSE_POSITIVE and REVIEW rows to the CSV
Safety:          dry-run by default; --apply-exclusions needs the EXCLUSION_MANAGER role
First run:       --dump prints the raw get_violations payload so FIELD_MAP can be checked
Information:     --list-rules prints every supported rule (no server needed)
                 --coverage   (with --rest-url or --input) counts the violations per rule and lists the rules this
                              tool has no checker for; writes <out>_coverage.csv

Rule ids that exist in two languages (e.g. 1101018 GROUP BY in ABAP and in SQL) are routed by
file extension: .sql/.pkb/.cbl/... -> SQL checker, anything else -> ABAP checker.

Setup: pip install mcp        (see README.md)
"""
import argparse, asyncio, contextlib, csv, io, json, os, re, sys
from collections import Counter
from pathlib import Path

import abap_checkers as ac
import dashboard_rest as dr
import sapui5_checkers as ui
import sql_checkers as sq
import web_checkers as wc

TP, FP, RV = ac.TP, ac.FP, ac.RV

# Field names in the get_violations payload. Adjust after a --dump run if needed.
FIELD_MAP = {
    "file": ["filePath", "file_path", "path", "file"],
    "line": ["startLine", "line", "line_number", "lineNumber"],
    "object": ["objectFullName", "object_fullname", "fullName", "name"],
    "component_href": ["component_href", "componentHref"],
    "rule_href": ["rule_pattern_href", "rulePatternHref"],
}

FAMILIES = {"abap": ac.RULES, "sapui5": ui.RULES, "web": wc.RULES, "sql": sq.RULES}
MANUAL = [ac.MANUAL_BY_ID, sq.MANUAL_BY_ID, wc.MANUAL_BY_ID]
MANUAL_GROUPS = [("ABAP", ac.MANUAL), ("SQL", sq.MANUAL), ("WEB", wc.MANUAL)]


def pick(d, key, default=None):
    for k in FIELD_MAP[key]:
        if isinstance(d, dict) and k in d:
            return d[k]
    return default


def find_violations(node):
    if isinstance(node, dict):
        if pick(node, "file") is not None or pick(node, "component_href") is not None:
            yield node
        else:
            for v in node.values():
                yield from find_violations(v)
    elif isinstance(node, list):
        for v in node:
            yield from find_violations(v)


def text_of(result):
    return "".join(c.text for c in result.content if getattr(c, "text", None))


def locate_source(root, rel):
    rel = (rel or "").replace("\\", "/").lstrip("/")
    if not rel or root is None:
        return None
    if (root / rel).is_file():
        return root / rel
    parts, best, score = Path(rel).parts[::-1], None, -1
    for cand in root.rglob(Path(rel).name):
        if cand.is_file():
            k = 0
            for a, b in zip(parts, cand.parts[::-1]):
                if a != b:
                    break
                k += 1
            if k > score:
                best, score = cand, k
    return best


def resolve_rules(spec):
    auto = []
    for fam in ("abap", "sapui5", "web", "sql"):
        auto += [r for r in FAMILIES[fam] if r not in auto]
    if spec in FAMILIES:
        return list(FAMILIES[spec])
    if spec == "auto":
        return auto
    if spec == "all":
        manual = [r for m in MANUAL for r in m if r not in auto]
        return auto + sorted(set(manual), key=int)
    return [x.strip() for x in spec.split(",") if x.strip()]


def rule_name(rid):
    for fam in ("sapui5", "web", "abap", "sql"):
        if rid in FAMILIES[fam]:
            return FAMILIES[fam][rid][0]
    return "(manual-review rule)" if any(rid in m for m in MANUAL) else None


def coverage_rows(counts):
    """counts: {rule id: {"name", "count"}} -> rows (rule, name, violations, status, detail), most violations first.
    status: CHECKED (a checker decides), REVIEW_ONLY (always a manual review), NO_CHECKER (not covered)."""
    rows = []
    for rid, e in counts.items():
        fam, chk = pick_checker(rid, None)
        if fam is None:
            status, detail = "NO_CHECKER", ""
        elif fam == "manual":
            status, detail = "REVIEW_ONLY", chk if isinstance(chk, str) else ""
        else:
            status, detail = "CHECKED", fam
        rows.append((rid, e.get("name") or rule_name(rid) or "", e["count"], status, detail))
    return sorted(rows, key=lambda r: (-r[2], int(r[0])))


def print_coverage(rows, out):
    total = sum(r[2] for r in rows)
    print(f"\n{len(rows)} rule(s) with violations, {total} violation(s) in the snapshot:")
    for st, label in (("CHECKED", "decided by a checker"), ("REVIEW_ONLY", "always a manual review"),
                      ("NO_CHECKER", "NOT covered by this tool")):
        sel = [r for r in rows if r[3] == st]
        print(f"  {st:<12} {len(sel):>4} rule(s) {sum(r[2] for r in sel):>7} violation(s)  - {label}")
    for r in (r for r in rows if r[3] == "NO_CHECKER"):
        print(f"    no checker: {r[0]:>8}  {r[2]:>6}  {r[1]}")
    with open(out, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f)
        w.writerow(["rule", "name", "violations", "status", "detail"])
        w.writerows(rows)
    print(f"-> {out}")


SQL_ON_ABAP ="SQL rule on an ABAP file (embedded Open SQL / AMDP SQLScript): not parsed by the SQL checker"


ABAP_OR_WEB = {"7788", "8028", "8032", "7884", "7526"}


def pick_checker(rid, path):
    """Return (family, check). Shared ids go to SQL only for SQL/COBOL files; SQL-only rules that fire on
    ABAP files (AMDP SQLScript, Open SQL) are review-only because the SQL parser does not understand ABAP."""
    if rid in ABAP_OR_WEB:            # same id on ABAP and on JavaScript/TypeScript files: the extension decides
        if path is not None and path.suffix.lower() == ".abap":
            if rid in ac.RULES:
                return "abap", ac.RULES[rid][1]
            return "manual", "Rule fired on an ABAP file but its checker only handles JavaScript/TypeScript"
        return "web", wc.RULES[rid][1]
    is_sql_file = path is not None and path.suffix.lower() in sq.SQL_EXT
    if is_sql_file and rid in sq.RULES:
        return "sql", sq.RULES[rid][1]
    if path is not None and path.suffix.lower() == ".abap" and rid in sq.RULES \
            and not any(rid in FAMILIES[f] for f in ("sapui5", "web", "abap")):
        return "manual", SQL_ON_ABAP
    for fam in ("sapui5", "web", "abap", "sql"):
        if rid in FAMILIES[fam]:
            return fam, FAMILIES[fam][rid][1]
    for m in MANUAL:
        if rid in m:
            return "manual", m[rid]
    return None, None


def make_ctx(fam, path):
    lines = path.read_text(errors="replace").splitlines()
    if fam == "abap":
        return ac.Ctx(lines)
    if fam in ("sapui5", "web"):
        return ui.JsCtx(lines, ui.kind_of(path))
    if fam == "sql":
        return sq.SqlCtx(lines, cobol=path.suffix.lower() in sq.COBOL_EXT)
    return lines


@contextlib.asynccontextmanager
async def open_transport(url, headers):
    """Open the MCP streamable-HTTP transport and yield (read_stream, write_stream).

    Works with both generations of the `mcp` SDK:
      * new SDK: streamable_http_client(url, http_client=...) - headers go on an HTTP client,
                 and 2 streams are yielded;
      * old SDK: streamablehttp_client(url, headers=...)      - 3 streams are yielded.
    """
    from mcp.client import streamable_http as sh
    new = getattr(sh, "streamable_http_client", None)
    if new is not None:
        create = getattr(sh, "create_mcp_http_client", None)
        if create is None:
            from mcp.shared._httpx_utils import create_mcp_http_client as create
        http = create(headers=headers)
        async with http:
            async with new(url, http_client=http) as streams:
                yield streams[0], streams[1]
    else:
        async with sh.streamablehttp_client(url, headers=headers) as streams:
            yield streams[0], streams[1]


def run_check(fam, check, ctx, line, category=None):
    if fam == "manual":
        ev = " ".join(ctx[line - 1].split())[:300] if 1 <= line <= len(ctx) else ""
        return RV, f"{category}: cannot be decided from the source text alone, review manually", ev
    verdict, why, ev = check(ctx, line)
    if fam == "abap" and verdict != RV and ctx.in_amdp(line):
        return RV, (f"Inside an AMDP method (SQLScript): ABAP statement parsing does not apply, so the checker's "
                    f"verdict ({verdict}: {why}) is not reliable"), ev
    return verdict, why, ev


# ----------------------------------------------------------------------------------------------
# Violations read from an export file (CSV / JSON) instead of the MCP server
# ----------------------------------------------------------------------------------------------
HEADER_ALIASES = {  # normalised header (lower-case, letters and digits only) -> internal field
    "rule": ["ruleid", "rule", "metricid", "qualityruleid", "ruleidentifier", "rulepattern", "rulenumber"],
    "file": ["filepath", "file", "path", "sourcefile", "filename"],
    "line": ["startline", "line", "linenumber", "lineno", "fromline"],
    "object": ["objectfullname", "objectname", "object", "fullname", "name", "component"],
    "rule_name": ["rulename", "qualityrule", "rulelabel"],
}


def _norm(h):
    return re.sub(r"[^a-z0-9]", "", str(h).lower())


def _rule_id(v):
    m = re.search(r"(?<!\d)(\d{4,8})(?!\d)", str(v))
    return m.group(1) if m else None


def _normalise(rec):
    low = {_norm(k): v for k, v in rec.items() if k is not None}
    out = {}
    for field, aliases in HEADER_ALIASES.items():
        for a in aliases:
            if a in low and str(low[a]).strip() != "":
                out[field] = low[a]
                break
    return out


def _json_records(node, rule=None):
    if isinstance(node, list):
        for x in node:
            yield from _json_records(x, rule)
    elif isinstance(node, dict):
        if "file" in _normalise(node):
            yield node if (not rule or "rule" in _normalise(node)) else {**node, "rule": rule}
        else:
            for k, v in node.items():
                yield from _json_records(v, str(k).strip() if str(k).strip().isdigit() else rule)


def load_violations(path):
    """Read an export (CSV with , ; or tab, UTF-8 or Windows-1252; or JSON) -> (violations, info).

    Each violation is {"rule", "file", "line", "objectFullName", "rule_name"}. Required columns: a rule id,
    a file path and a line number (header names are matched loosely, see HEADER_ALIASES)."""
    raw = Path(path).read_bytes()
    for enc in ("utf-8-sig", "cp1252"):
        try:
            text = raw.decode(enc)
            break
        except UnicodeDecodeError:
            continue
    headers, records = [], []
    if str(path).lower().endswith(".json") or text.lstrip()[:1] in "[{":
        records = list(_json_records(json.loads(text)))
        headers = sorted({k for r in records for k in r})
    else:
        first = text.splitlines()[0] if text.strip() else ""
        delim = max(",;\t", key=first.count)
        reader = csv.DictReader(io.StringIO(text), delimiter=delim)
        headers, records = list(reader.fieldnames or []), list(reader)
    viols, bad = [], 0
    for rec in records:
        n = _normalise(rec)
        rid, ln = _rule_id(n.get("rule", "")), re.match(r"\s*(\d+)", str(n.get("line", "")))
        if not rid or "file" not in n or not ln:
            bad += 1
            continue
        viols.append({"rule": rid, "file": str(n["file"]).strip(), "line": ln.group(1),
                      "objectFullName": n.get("object"), "rule_name": n.get("rule_name")})
    return viols, {"headers": headers, "rows": len(records), "skipped": bad}


def classify(v, rid, name, root, cache, resolver=None):
    """Run the rule's checker on one violation and return the report row.
    `resolver(v)` (REST mode) returns the server copy of the file; --source-root is the fallback."""
    file_, line = pick(v, "file"), pick(v, "line")
    path = resolver(v) if resolver else None
    if path is None:
        path = locate_source(root, file_)
    fam, check = pick_checker(rid, path)
    if path is None or not str(line).isdigit():
        verdict, why, ev = RV, ("Source file or line not available (not downloadable from the server, "
                                "not found under --source-root, or no location reported)"), ""
    else:
        key = (path, fam)
        if key not in cache:
            cache[key] = make_ctx(fam, path)
        cat = check if fam == "manual" and isinstance(check, str) else next((m[rid] for m in MANUAL if rid in m), None)
        try:
            verdict, why, ev = run_check(fam, check, cache[key], int(line), cat)
        except Exception as e:  # a checker bug must never stop the batch
            verdict, why, ev = RV, f"Checker error: {e!r}", ""
    if verdict == RV and re.match(r"No |Not an? |Expected ", why):
        why += (" (CAST reported this line, so this is either a line-anchoring difference or a limit of this "
                "checker: confirm manually)")
    return {"rule": rid, "rule_name": name, "object": pick(v, "object"), "file": file_, "line": line,
            "verdict": verdict, "reason": why, "evidence": ev,
            "justification": f"[{rid}] {why}" if verdict == FP else "", "excluded": ""}


async def triage(rules, fetch, exclude, args, root, resolver=None):
    """Shared loop: `fetch(rid, quota)` yields the violations of a rule (None = skip it),
    `exclude(v, row)` (MCP mode only) creates the exclusion and returns the text for the `excluded` column.
    A failure or Ctrl+C never loses the work done: the rows checked so far are returned (and written)."""
    rows, remaining, cache, total = [], args.limit, {}, len(rules)
    try:
        for n, rid in enumerate(rules, 1):
            if remaining is not None and remaining <= 0:
                break
            name = rule_name(rid)
            if name is None and getattr(args, "dump", False):
                name = "(no checker for this rule)"          # --dump shows the raw violations of any rule
            if name is None:
                print(f"[{rid}] no checker for this rule id, skipped (see --list-rules; --dump shows its raw violations)")
                continue
            quota = min((x for x in (remaining, args.per_rule_limit) if x is not None), default=None)
            viols = await fetch(rid, quota, name)
            if viols is None:
                continue
            if quota is not None:
                viols = viols[:quota]
            if viols:
                print(f"[{n}/{total}] {rid} {name[:50]}: {len(viols)} violation(s)", flush=True)
            elif n % 25 == 0:
                print(f"[{n}/{total}] rules scanned, {len(rows)} violation(s) checked so far", flush=True)
            for v in viols:
                row = classify(v, rid, name, root, cache, resolver)
                if exclude and row["verdict"] == FP:
                    row["excluded"] = await exclude(v, row)
                rows.append(row)
            if remaining is not None:
                remaining -= len(viols)
    except KeyboardInterrupt:
        print("\nInterrupted: writing the report of what was checked so far.", flush=True)
    except Exception as e:  # noqa: BLE001 - keep the work done so far
        if os.environ.get("GATEKEEPER_DEBUG"):
            raise
        print(f"\nStopped by an error ({type(e).__name__}: {e}): writing the report of what was checked so far "
              f"({len(rows)} violation(s)).", flush=True)
    return rows


def write_report(rows, out, hide_true_positives=False):
    """Write the CSV report. With hide_true_positives the confirmed violations are left out of the file
    (the console summary still counts them), so the report holds only what needs a human decision."""
    cols = ["rule", "rule_name", "object", "file", "line", "verdict", "reason", "evidence", "justification", "excluded"]
    kept = [x for x in rows if not (hide_true_positives and x["verdict"] == TP)]
    with open(out, "w", newline="", encoding="utf-8-sig") as f:
        wr = csv.DictWriter(f, fieldnames=cols)
        wr.writeheader()
        wr.writerows(kept)
    print(dict(Counter(x["verdict"] for x in rows)), "->", out)
    if hide_true_positives:
        print(f"{len(rows) - len(kept)} TRUE_POSITIVE row(s) not written to the report (--no-true-positives)")
    for x in rows:
        if x["verdict"] == FP:
            print(f"FP  {x['rule']}  {x['file']}:{x['line']}  {x['reason']}")


async def main():
    ap = argparse.ArgumentParser(description="Triage CAST Gatekeeper violations as true/false positives "
                                             "(ABAP, SAPUI5, SQL, JavaScript/TypeScript/web). See README.md.")
    ap.add_argument("--input", help="read the violations from a CSV/JSON export instead of the MCP server "
                                    "(needs only --source-root; for Imaging versions without the MCP server)")
    ap.add_argument("--rest-url", help="CAST Dashboard REST API root, ending with the server's /rest/ "
                                       "(reads the violations through the REST API; Imaging before 3.6.4)")
    ap.add_argument("--domain", help="REST API domain / schema of the application (e.g. AAD, CENTRAL)")
    ap.add_argument("--user", help="REST API user (Basic authentication)")
    ap.add_argument("--password", default=os.environ.get("CAST_REST_PASSWORD"),
                    help="REST API password (default: environment variable CAST_REST_PASSWORD)")
    ap.add_argument("--api-user", help="user name sent as X-API-USER when --api-key is used with --rest-url")
    ap.add_argument("--url")
    ap.add_argument("--api-key", default=None)
    ap.add_argument("--app")
    ap.add_argument("--source-root")
    ap.add_argument("--rule-ids", default="auto")
    ap.add_argument("--snapshot", default="latest")
    ap.add_argument("--limit", type=int)
    ap.add_argument("--per-rule-limit", type=int)
    ap.add_argument("--out", default="report.csv")
    ap.add_argument("--dump", action="store_true")
    ap.add_argument("--no-true-positives", action="store_true",
                    help="leave the TRUE_POSITIVE rows out of the CSV report (only FALSE_POSITIVE and REVIEW are written); "
                         "the console summary still counts them")
    ap.add_argument("--apply-exclusions", action="store_true")
    ap.add_argument("--list-rules", action="store_true")
    ap.add_argument("--coverage", action="store_true",
                    help="count the violations of the snapshot per rule and show which rules have a checker, are "
                         "review-only, or are not covered (needs --rest-url or --input; no source is read)")
    args = ap.parse_args()
    cov_out = str(Path(args.out).with_name(Path(args.out).stem + "_coverage.csv"))
    if args.coverage and not (args.input or args.rest_url):
        ap.error("--coverage needs --rest-url or --input (the MCP mode has no call that lists every rule)")

    if args.list_rules:
        for fam, rules in FAMILIES.items():
            print(f"\n== {fam} ({len(rules)} rule ids with a checker) ==")
            for rid in sorted(rules, key=int):
                print(f"{rid:>8}  {rules[rid][0]}")
        for lang, groups in MANUAL_GROUPS:
            for cat, ids in groups.items():
                print(f"\nREVIEW only [{lang}] - {cat}:\n  {', '.join(map(str, ids))}")
        return
    if args.input and args.rest_url:
        ap.error("--input and --rest-url are alternatives, use only one")
    if args.input or args.rest_url:
        if args.apply_exclusions:
            ap.error("--apply-exclusions needs the MCP server; use the justification column of the report instead")
        if not args.source_root and not args.rest_url and not args.coverage:
            ap.error("--source-root is required")
        if args.rest_url:
            for req in ("domain", "app"):
                if not getattr(args, req):
                    ap.error(f"--{req} is required with --rest-url")
    else:
        for req in ("url", "api_key", "app", "source_root"):
            if not getattr(args, req):
                ap.error(f"--{req.replace('_', '-')} is required (or use --rest-url, or --input FILE)")
    root = Path(args.source_root) if args.source_root else None

    if args.input:
        viols, info = load_violations(args.input)
        if not viols:
            sys.exit(f"No usable violation found in {args.input} ({info['rows']} row(s), {info['skipped']} unusable).\n"
                     f"Detected columns: {info['headers']}\n"
                     "Needed: a rule id (e.g. 'Rule ID'), a file path ('File'/'Path') and a line ('Line'/'Start line').")
        by_rule = {}
        for v in viols:
            by_rule.setdefault(v["rule"], []).append(v)
        if args.coverage:
            print_coverage(coverage_rows({r: {"name": "", "count": len(vs)} for r, vs in by_rule.items()}), cov_out)
            return
        wanted = resolve_rules(args.rule_ids)
        if args.dump:
            print(f"columns: {info['headers']}\nrows: {info['rows']}, usable: {len(viols)}, unusable: {info['skipped']}")
            for rid, vs in by_rule.items():
                print(f"  rule {rid}: {len(vs)} violation(s), e.g. {vs[0]['file']}:{vs[0]['line']}")
            return
        todo = [r for r in wanted if r in by_rule]
        ignored = sorted(set(by_rule) - set(todo), key=int)
        if ignored:
            n_ign = sum(len(by_rule[r]) for r in ignored)
            print(f"Not checked: {n_ign} violation(s) of rule(s) {', '.join(ignored)} "
                  f"(no checker or not selected by --rule-ids; use --rule-ids all to list review-only rules)")

        async def fetch(rid, quota, name):
            return by_rule[rid]
        rows = await triage(todo, fetch, None, args, root)
        write_report(rows, args.out, args.no_true_positives)
        return

    if args.rest_url:
        try:
            client = dr.DashboardClient(args.rest_url, args.domain, user=args.user, password=args.password,
                                        api_key=args.api_key, api_user=args.api_user)
            app = client.find_application(args.app)
            snap = client.find_snapshot(app, args.snapshot)
        except dr.RestError as e:
            sys.exit(f"Dashboard REST API: {e}")
        print(f"Application '{app.get('name')}', snapshot {snap.get('number')} ({snap.get('href')})")
        if args.coverage:
            try:
                counts = client.rule_counts(snap, progress=lambda n: print(f"  {n} violation(s) read...")
                                            if n % 10000 < 1000 else None)
            except dr.RestError as e:
                sys.exit(f"Dashboard REST API: {e}")
            print_coverage(coverage_rows(counts), cov_out)
            return

        missing = []                      # rules that are not in this application's quality model

        async def fetch(rid, quota, name):
            out = []
            try:
                for v in client.iter_violations(snap, rid, limit=None if args.dump else quota):
                    if args.dump:
                        print(f"=== {rid} {name} ===")
                        print(json.dumps(client.raw_for_violation(v), indent=1)[:6000])
                        return None
                    locs = client.locations(v) or [(None, None, None)]
                    for file_, line, href in locs:
                        out.append({"rule": rid, "file": file_ or "", "line": str(line) if line else "",
                                    "fileHref": href, "objectFullName": dr.component_name(v)})
                        if quota is not None and len(out) >= quota:
                            return out
            except dr.UnknownRule:
                missing.append(rid)
                return None
            except dr.RestError as e:
                print(f"[{rid}] REST error, skipped: {e}")
                return None
            if args.dump:
                print(f"=== {rid} {name} ===\nno violation returned")
                return None
            return out

        def resolver(v):
            if not v.get("fileHref"):
                return None
            try:
                return Path(client.download(v["fileHref"], v.get("file")))
            except dr.RestError as e:
                print(f"Could not download {v.get('file')}: {e}")
                return None

        rows = await triage(resolve_rules(args.rule_ids), fetch, None, args, root, resolver)
        if missing:
            print(f"{len(missing)} rule(s) are not in this application's quality model, nothing to check: "
                  f"{', '.join(missing)}")
        if not args.dump:
            write_report(rows, args.out, args.no_true_positives)
        return

    # imported here so --list-rules and --input work without the mcp package
    from mcp import ClientSession

    async with open_transport(args.url, {"x-api-key": args.api_key}) as (r, w):
        async with ClientSession(r, w) as s:
            await s.initialize()

            async def fetch(rid, quota, name):
                params = {"application_name": args.app, "snapshot": args.snapshot,
                          "rule_pattern": rid, "include_findings": True,
                          "nb_rows": "$all" if quota is None else max(10, quota)}   # API minimum is 10
                raw = text_of(await s.call_tool("get_violations", params))
                if args.dump:
                    print(f"=== {rid} {name} ===\n{raw[:4000]}")
                    return None
                try:
                    return list(find_violations(json.loads(raw)))
                except json.JSONDecodeError:
                    print(f"[{rid}] non-JSON response, skipped: {raw[:200]}")
                    return None

            async def exclude(v, row):
                ch, rh = pick(v, "component_href"), pick(v, "rule_href")
                if not (ch and rh):
                    return "no (missing href)"
                await s.call_tool("manage_exclusion", {
                    "operation": "add", "application_name": args.app,
                    "component_href": ch, "rule_pattern_href": rh,
                    "comment": f"False positive (automated check). {row['reason']}. Evidence: {row['evidence']}"[:900]})
                return "yes"

            rows = await triage(resolve_rules(args.rule_ids), fetch, exclude if args.apply_exclusions else None,
                                args, root)
    if not args.dump:
        write_report(rows, args.out, args.no_true_positives)


def _root_causes(exc):
    """Flatten (nested) ExceptionGroups raised by anyio/MCP into the underlying errors."""
    subs = getattr(exc, "exceptions", None)
    return [c for e in subs for c in _root_causes(e)] if subs else [exc]


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        sys.exit(130)
    except Exception as exc:  # connection / authentication / protocol errors
        if os.environ.get("GATEKEEPER_DEBUG"):
            raise
        msg = "; ".join(sorted({f"{type(c).__name__}: {c}" for c in _root_causes(exc)}))
        sys.exit(f"Error while talking to the server: {msg}\n"
                 "Check --url (http://<host>:8090/mcp/gatekeeper) or --rest-url, the credentials and the network "
                 "path. Set GATEKEEPER_DEBUG=1 for the full traceback.")
