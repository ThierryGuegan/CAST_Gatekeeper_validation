#!/usr/bin/env python3
"""
gatekeeper_validate - triage CAST Imaging Gatekeeper violations as true / false positives.

For every selected quality rule the tool
  1. gets the violations from the Gatekeeper MCP server (tool get_violations, needs Imaging >= 3.6.4)
     or from an exported CSV/JSON file (--input, works with any Imaging version),
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

Input:           --url/--api-key/--app (MCP server)  OR  --input violations.csv (no server needed)
Rule selection:  --rule-ids auto | abap | sapui5 | web | sql | all | 7520,1020600,...
                 auto = every rule that has a real checker (default)
                 all  = auto + rules that can only get a REVIEW verdict
Limits:          --limit N (overall), --per-rule-limit N (per rule)
Safety:          dry-run by default; --apply-exclusions needs the EXCLUSION_MANAGER role
First run:       --dump prints the raw get_violations payload so FIELD_MAP can be checked
Information:     --list-rules prints every supported rule (no server needed)

Rule ids that exist in two languages (e.g. 1101018 GROUP BY in ABAP and in SQL) are routed by
file extension: .sql/.pkb/.cbl/... -> SQL checker, anything else -> ABAP checker.

Setup: pip install mcp        (see README.md)
"""
import argparse, asyncio, contextlib, csv, io, json, os, re, sys
from collections import Counter
from pathlib import Path

import abap_checkers as ac
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


def locate_source(root: Path, rel: str):
    rel = (rel or "").replace("\\", "/").lstrip("/")
    if not rel:
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


def pick_checker(rid, path):
    """Return (family, check). Shared ids go to SQL only for SQL/COBOL files."""
    is_sql_file = path is not None and path.suffix.lower() in sq.SQL_EXT
    if is_sql_file and rid in sq.RULES:
        return "sql", sq.RULES[rid][1]
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
    return check(ctx, line)


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


def classify(v, rid, name, root, cache):
    """Run the rule's checker on one violation and return the report row."""
    file_, line = pick(v, "file"), pick(v, "line")
    path = locate_source(root, file_)
    fam, check = pick_checker(rid, path)
    if path is None or not str(line).isdigit():
        verdict, why, ev = RV, "Source file or line not found under --source-root", ""
    else:
        key = (path, fam)
        if key not in cache:
            cache[key] = make_ctx(fam, path)
        cat = next((m[rid] for m in MANUAL if rid in m), None)
        try:
            verdict, why, ev = run_check(fam, check, cache[key], int(line), cat)
        except Exception as e:  # a checker bug must never stop the batch
            verdict, why, ev = RV, f"Checker error: {e!r}", ""
    return {"rule": rid, "rule_name": name, "object": pick(v, "object"), "file": file_, "line": line,
            "verdict": verdict, "reason": why, "evidence": ev,
            "justification": f"[{rid}] {why}" if verdict == FP else "", "excluded": ""}


async def triage(rules, fetch, exclude, args, root):
    """Shared loop: `fetch(rid, quota)` yields the violations of a rule (None = skip it),
    `exclude(v, row)` (MCP mode only) creates the exclusion and returns the text for the `excluded` column."""
    rows, remaining, cache = [], args.limit, {}
    for rid in rules:
        if remaining is not None and remaining <= 0:
            break
        name = rule_name(rid)
        if name is None:
            print(f"[{rid}] unknown rule id, skipped (see --list-rules)")
            continue
        quota = min((x for x in (remaining, args.per_rule_limit) if x is not None), default=None)
        viols = await fetch(rid, quota, name)
        if viols is None:
            continue
        if quota is not None:
            viols = viols[:quota]
        for v in viols:
            row = classify(v, rid, name, root, cache)
            if exclude and row["verdict"] == FP:
                row["excluded"] = await exclude(v, row)
            rows.append(row)
        if remaining is not None:
            remaining -= len(viols)
    return rows


def write_report(rows, out):
    cols = ["rule", "rule_name", "object", "file", "line", "verdict", "reason", "evidence", "justification", "excluded"]
    with open(out, "w", newline="", encoding="utf-8-sig") as f:
        wr = csv.DictWriter(f, fieldnames=cols)
        wr.writeheader()
        wr.writerows(rows)
    print(dict(Counter(x["verdict"] for x in rows)), "->", out)
    for x in rows:
        if x["verdict"] == FP:
            print(f"FP  {x['rule']}  {x['file']}:{x['line']}  {x['reason']}")


async def main():
    ap = argparse.ArgumentParser(description="Triage CAST Gatekeeper violations as true/false positives "
                                             "(ABAP, SAPUI5, SQL, JavaScript/TypeScript/web). See README.md.")
    ap.add_argument("--input", help="read the violations from a CSV/JSON export instead of the MCP server "
                                    "(needs only --source-root; for Imaging versions without the MCP server)")
    ap.add_argument("--url")
    ap.add_argument("--api-key")
    ap.add_argument("--app")
    ap.add_argument("--source-root")
    ap.add_argument("--rule-ids", default="auto")
    ap.add_argument("--snapshot", default="latest")
    ap.add_argument("--limit", type=int)
    ap.add_argument("--per-rule-limit", type=int)
    ap.add_argument("--out", default="report.csv")
    ap.add_argument("--dump", action="store_true")
    ap.add_argument("--apply-exclusions", action="store_true")
    ap.add_argument("--list-rules", action="store_true")
    args = ap.parse_args()

    if args.list_rules:
        for fam, rules in FAMILIES.items():
            print(f"\n== {fam} ({len(rules)} rule ids with a checker) ==")
            for rid in sorted(rules, key=int):
                print(f"{rid:>8}  {rules[rid][0]}")
        for lang, groups in MANUAL_GROUPS:
            for cat, ids in groups.items():
                print(f"\nREVIEW only [{lang}] - {cat}:\n  {', '.join(map(str, ids))}")
        return
    if args.input:
        if args.apply_exclusions:
            ap.error("--apply-exclusions needs the MCP server; with --input use the justification column of the report")
        if not args.source_root:
            ap.error("--source-root is required")
    else:
        for req in ("url", "api_key", "app", "source_root"):
            if not getattr(args, req):
                ap.error(f"--{req.replace('_', '-')} is required (or use --input FILE)")
    root = Path(args.source_root)

    if args.input:
        viols, info = load_violations(args.input)
        if not viols:
            sys.exit(f"No usable violation found in {args.input} ({info['rows']} row(s), {info['skipped']} unusable).\n"
                     f"Detected columns: {info['headers']}\n"
                     "Needed: a rule id (e.g. 'Rule ID'), a file path ('File'/'Path') and a line ('Line'/'Start line').")
        by_rule = {}
        for v in viols:
            by_rule.setdefault(v["rule"], []).append(v)
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
        write_report(rows, args.out)
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
        write_report(rows, args.out)


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
        sys.exit(f"Error while talking to the MCP server: {msg}\n"
                 "Check --url (http://<host>:8090/mcp/gatekeeper), --api-key and the network path. "
                 "Set GATEKEEPER_DEBUG=1 for the full traceback.")
