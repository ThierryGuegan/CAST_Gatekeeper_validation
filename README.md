# gatekeeper_validate

Triage CAST Imaging **Gatekeeper** violations as true or false positives, automatically.

For each selected quality rule the tool

1. gets the violations from the **CAST Dashboard REST API** (Imaging before 3.6.4), from the **Gatekeeper MCP server**
   (Imaging 3.6.4 or later), or from an exported CSV/JSON file,
2. gets the source file at the reported line (downloaded from the server in REST mode, otherwise from a local
   checkout),
3. runs the rule's checker and classifies the violation,
4. writes a CSV report with the reason, the evidence and a ready-to-use justification,
5. optionally creates the exclusions in Imaging for the false positives (MCP mode only).

It covers ABAP, SAPUI5, JavaScript/TypeScript (jQuery, Angular, React, Vue, Node.js), HTML/CSS and SQL (PL/SQL, T-SQL,
COBOL embedded SQL). The MCP mode builds on the
[CAST Gatekeeper MCP server](https://doc.castsoftware.com/imaging/mcp-server/gatekeeper/windows/)
(tools `get_violations` and `manage_exclusion`).

## Which mode?

| Your situation | Use | Source files | Exclusions |
|---|---|---|---|
| Imaging **before 3.6.4** (e.g. 2.x) with the Dashboard REST API | `--rest-url` ([details](#without-the-mcp-server-imaging-before-364-cast-dashboard-rest-api)) | downloaded from the server | create them yourself from the report |
| Imaging **3.6.4 or later** with the Gatekeeper MCP server | `--url` ([Quick start](#quick-start)) | local checkout (`--source-root`) | `--apply-exclusions` |
| Neither is reachable from your machine | `--input` ([offline](#offline-alternative-an-export-file)) | local checkout (`--source-root`) | create them yourself from the report |

> **Status:** the checkers are covered by unit tests. The **REST API mode has been run against a real CAST
> Dashboard server** and the checkers were calibrated on its violations (see the notes below). The **MCP mode has
> only been tested against a local stand-in server**, not a real Gatekeeper MCP server: do a `--dump` run first
> (see [Quick start](#quick-start)). In every mode, review a sample of the false-positive verdicts before creating
> exclusions.

## Verdicts

| Verdict | Meaning |
|---|---|
| `TRUE_POSITIVE` | The source confirms the violation. |
| `FALSE_POSITIVE` | The source itself **proves** the violation is not real: the construct only appears in a comment or a string literal, the return code is tested, the table is guarded, the loop is not a loop, and so on. The `reason` column says why. |
| `REVIEW` | Cannot be decided from the source text. This includes metrics, naming and other rules that need more than the source, and also these automatic cases: the construct is **not found at the reported line** (CAST sometimes anchors a line or two away from the statement, so this is never treated as proof), the line is inside an **AMDP / SQLScript** method (ABAP parsing does not apply), or a SQL-analyzer rule fires on an ABAP file. |

Design rules: a `FALSE_POSITIVE` is returned **only when the file proves it**. When the answer may depend on
another file (a loop in a caller, a security header configured elsewhere, a check in a caller) the verdict is
`REVIEW`, or `TRUE_POSITIVE` with the limitation stated in the reason.

**Calibrated on real data.** The checkers were run against the violations of a real application through the REST
API and corrected where they disagreed with the code. For example: `CALL FUNCTION ... EXCEPTIONS` without a
`SY-SUBRC` test is still a violation; `sy-subrc = 0.` assigns the return code and does not check it; an
`IF t[] IS INITIAL ... EXIT.` guard is accepted only when the branch really leaves; an **empty** `WHEN OTHERS.` is
reported like a missing one (all 32 flagged cases were empty). Some verdicts show that CAST itself over-reports, which
is where the tool saves the most review time: `WHILE ... AND sy-subrc = 0` is a real return-code check, and blocks
that contain only compound assignments (`x += y`) are not empty even though CAST sees them that way (all 44 flagged
`IF`/`SELECT` blocks of that kind). The justification in the report says which of these applies.

A second calibration, on a full run (15,555 violations, 506 rules), corrected verdicts that had been too generous:
a `SY-SUBRC` test only counts if it belongs to **that** statement (the look-ahead stops at the end of its block, at
`ELSE`/`WHEN`, and at any statement that sets `SY-SUBRC` itself); testing the result variable instead of `SY-SUBRC` is
`REVIEW` (CAST asks for the return code); `EXCEPTIONS OTHERS = 0` explicitly ignores errors; the
`WITH AUTHORITY-CHECK` addition of one `CALL TRANSACTION` protects only that call; a success-only `IF sy-subrc = 0`
with no `ELSE` is `REVIEW` for the "without error handling" rules; function-module files are followed from the
extractor's parameter header to the `FUNCTION`. In JavaScript, regular-expression literals (for example
`/[^0-9+-/*]/g`, which contains `/*`) are now recognised, so they no longer hide the rest of a file as a comment.

## Supported rules

CAST publishes only rule **names and severities**, not descriptions. Each checker's semantics are inferred from the
rule name and from the language/framework documentation. Check a checker against your own understanding of the rule
before trusting its verdicts.

| Family | Module | Technologies / files | Rule ids with a checker | Review-only ids |
|---|---|---|---|---|
| `abap` | `abap_checkers.py` | ABAP (TG001, `com.castsoftware.sap`) | 72 | 85 |
| `sapui5` | `sapui5_checkers.py` | SAPUI5 extension (`10206xx`): JS, `manifest.json`, `index.html` | 10 | – |
| `web` | `web_checkers.py` | TG004: HTML5/JavaScript, TypeScript, Node.js, jQuery, AngularJS/Angular, React, Vue, CSS | 209 | 74 |
| `sql` | `sql_checkers.py` | SQL Analyzer: PL/SQL, T-SQL, COBOL embedded SQL (`11010xx`) | 38 | 21 |

Sources of the rule lists: [TG001](https://technologies.castsoftware.com/AIP/technologies/TG001),
[TG004](https://technologies.castsoftware.com/AIP/technologies/TG004),
[SAPUI5 1.1.16](https://technologies.castsoftware.com/AIP/extensions/com.castsoftware.sapui5/versions/1.1.16-funcrel),
[SQL Analyzer 3.8.5](https://technologies.castsoftware.com/AIP/extensions/com.castsoftware.sqlanalyzer/versions/3.8.5-funcrel),
[SAP 2.0.0](https://technologies.castsoftware.com/AIP/extensions/com.castsoftware.sap/versions/2.0.0-funcrel).

Print the exact list on your machine (no server needed):

```bash
python gatekeeper_validate.py --list-rules
```

**Review-only rules** are metrics (complexity, size, fan-in/out), comment ratios, naming conventions, unreferenced
objects, repeated table access across artifacts, index/XXL metadata, CDS views, library-version vulnerabilities,
HTML5 attack-vector combinations and procedure-level SQL semantics. With `--rule-ids all` they are reported as
`REVIEW`, with the code line and the category, so nothing is silently dropped.

### File routing

The checker is chosen from the rule id. Two ids exist in two languages (`1101018` GROUP BY and `1101024` dynamic
SQL), so for those the **file extension** decides:

| Extension | Handled as |
|---|---|
| `.sql .pks .pkb .plsql .pls .tsql .prc .fnc .trg .vw .pck` | SQL |
| `.cbl .cob .cpy .pco` | SQL, COBOL fixed format (`EXEC SQL … END-EXEC`) |
| `.json` | JSON (`manifest.json`) |
| `.html .htm .vue .cshtml .jsp` | markup |
| `.xml` | markup |
| `.css .scss .less` | CSS |
| `.abap` | ABAP. SQL-analyzer rules that fire on an ABAP file (embedded Open SQL, AMDP SQLScript) are `REVIEW` only |
| anything else | JavaScript/TypeScript for `sapui5`/`web` rules, ABAP for `abap` rules |

Inside an **AMDP method** (`METHOD ... BY DATABASE PROCEDURE ... ENDMETHOD`, whose body is SQLScript, not ABAP) every
ABAP verdict is downgraded to `REVIEW`, because ABAP statement parsing does not apply there.

## Installation

Python 3 (developed and tested on 3.13) and the `mcp` package (only needed to talk to the server; `--list-rules` and the tests do not need it).

```bash
pip install mcp
```

Both generations of the `mcp` SDK are supported (the older `streamablehttp_client` and the newer
`streamable_http_client`, whose interface differs); the runner detects which one is installed.

> **Which Imaging version?** The Gatekeeper MCP server (release 3.0.0 and later) requires CAST Imaging
> **3.6.4 or later**. With an older Imaging (e.g. 2.x) read the violations from the CAST Dashboard REST API instead:
> see [Without the MCP server](#without-the-mcp-server-imaging-before-364-cast-dashboard-rest-api).

Prerequisites on the Imaging side (see the Gatekeeper MCP documentation): a running Gatekeeper MCP server, an
Imaging API key, and the **`EXCLUSION_MANAGER`** role if you want to create exclusions. The URL to use is the
Imaging gateway one: `http://<host>:8090/mcp/gatekeeper` (or `https://<host>/mcp/gatekeeper`), **not** the MCP
server's own port.

## Quick start

1. **Check the payload shape** (once). It prints the raw `get_violations` result for one rule:

   ```bash
   python gatekeeper_validate.py --url http://imaging:8090/mcp/gatekeeper --api-key $IMAGING_KEY \
       --app MyApp --source-root /path/to/checkout --rule-ids 7544 --dump
   ```

   If the field names differ from `FIELD_MAP` at the top of `gatekeeper_validate.py` (file, line, object,
   `component_href`, `rule_pattern_href`), adjust that table.

2. **Dry run on a few violations**:

   ```bash
   python gatekeeper_validate.py --url http://imaging:8090/mcp/gatekeeper --api-key $IMAGING_KEY \
       --app MyApp --source-root /path/to/checkout --rule-ids auto --limit 50 --out report.csv
   ```

3. **Read `report.csv`**, sample the false positives, then optionally rerun with `--apply-exclusions`.

**Passing the API key.** Shell variables are expanded by the shell, not by Python:
`$IMAGING_KEY` works in bash, `$env:IMAGING_KEY` in PowerShell and `%IMAGING_KEY%` in Windows `cmd`. Replace
`imaging` in the URL with your Imaging host name. Connection or authentication errors are printed as a short
message; set `GATEKEEPER_DEBUG=1` for the full traceback.

`--source-root` (MCP and `--input` modes) must contain every source language you want checked (ABAP, SQL, JS, …).
The reported path is matched under that root; if it does not match exactly, the candidate sharing the longest
trailing path is used.

### A `run.bat` for Windows

Keep the command in a batch file, and keep the password **out of it** (the file is usually committed). This version
asks for the password unless `CAST_REST_PASSWORD` is already set:

```bat
@echo off
cd /d "%~dp0"
if "%CAST_REST_PASSWORD%"=="" set /p CAST_REST_PASSWORD=Password: 
python gatekeeper_validate.py --rest-url http://<server>:<port>/<webservice>/rest --domain <domain> --user <user> --app "<application name>" --rule-ids auto --limit 50 --out report.csv
```

`set /p` echoes what you type; run `set CAST_REST_PASSWORD=...` once in your console to avoid that.

## Without the MCP server (Imaging before 3.6.4): CAST Dashboard REST API

With an older Imaging the violations are read **directly from the CAST Dashboard REST API**, the same data the
dashboard shows. No MCP server, no `mcp` package, no export step, and **no local source checkout is needed**: the
analysed source files are downloaded from the server, so the line numbers always match the violations.

```bat
set CAST_REST_PASSWORD=your-password
python gatekeeper_validate.py --rest-url http://<server>:<port>/<webservice>/rest --domain <domain> ^
    --user <user> --app "<application name>" --rule-ids auto --limit 50 --out report.csv
```

| Option | Meaning |
|---|---|
| `--rest-url` | The REST server root, ending with `/rest` (e.g. `http://localhost:9090/Dashboard-WebService/rest`). Opening it in a browser lists the domains. |
| `--domain` | The domain holding the application's **engineering** data (violations and source code), e.g. `AED` / `CENTRAL`. A measurement-only domain (e.g. `AAD`) has no violations. |
| `--user` + `--password` | HTTP Basic authentication. The password can come from the `CAST_REST_PASSWORD` environment variable, which keeps it out of your shell history and `run.bat`. |
| `--api-key` + `--api-user` | Alternative: API key authentication (`X-API-KEY` / `X-API-USER` headers). |
| `--app` | Application name (case-insensitive). If it is not found, the available names are listed. |
| `--snapshot` | `latest` (default) or a snapshot number. |
| `--source-root` | Optional. Only used as a fallback when a file cannot be downloaded (matched by trailing path, so the server's absolute Windows paths are fine). |

What it calls (REST API reference, *Engineering Resources*):

```
GET {rest}/{domain}/applications                                      application by name
GET {application}/snapshots                                           latest snapshot
GET {snapshot}/violations?rule-pattern=<rule id>&startRow=&nbRows=    violations of a rule (paged)
GET <violation>.diagnosis.findings.href                               the violating lines (bookmarks -> codeFragment -> file, startLine)
GET <violation>.component.sourceCodes.href                            fallback: the object's own source location
GET <file.href>                                                       the analysed source file (text/plain), downloaded once per file
```

`--limit`, `--per-rule-limit` and `--rule-ids` work as in the other modes. `--apply-exclusions` is not available in
this mode (reading only): create the exclusions from the `justification` column of the report.

**Verified against a real server** (CAST Dashboard REST API 8.3.50, an application with ABAP, SAPUI5 and HTML5):
the quality-rule id (e.g. `7544`) works as the `rule-pattern` value, the violating line comes from
`findings -> bookmarks -> codeFragment`, and the file endpoint returns the analysed source. Other versions or
servers may differ: if the locations are not recognised, run once with `--dump` on one rule. It prints a violation
with its findings and source codes.

```bat
python gatekeeper_validate.py --rest-url ... --domain ... --user ... --app "..." --rule-ids 7544 --dump
```

### Offline alternative: an export file

If the REST API is not reachable from where you run the tool, give a CSV or JSON export to `--input` instead
(`--input violations.csv --source-root .\src`). Columns needed (headers are matched loosely): a rule id (`Rule ID`,
`Metric ID`, ...), a file (`File`, `Path`, ...) and a line (`Line`, `Start line`, ...); `Object` is optional. The
delimiter (`,` `;` tab) and the encoding (UTF-8 or Windows-1252) are detected, JSON lists, objects keyed by rule id
and the `get_violations` shape are accepted, and `--dump` shows how your columns were read.

## Command line

| Option | Description |
|---|---|
| `--url`, `--api-key`, `--app`, `--source-root` | Required for the MCP server mode (except with `--list-rules`). |
| `--rest-url`, `--domain`, `--user`/`--password` or `--api-key`/`--api-user`, `--app` | CAST Dashboard REST API mode (see above); `--source-root` is optional there. |
| `--input FILE` | Read the violations from a CSV/JSON export; only `--source-root` is then required. |
| `--rule-ids` | `auto` (default: every rule with a checker), `abap`, `sapui5`, `web`, `sql`, `all` (auto + the review-only rules: expect thousands of extra `REVIEW` rows on a real application, one per violation), or a comma list such as `7520,1020600,1101114`. |
| `--snapshot` | `latest` (default) or a snapshot number; in MCP mode also `5,6` (as accepted by `get_violations`). |
| `--limit N` | Check only the first **N violations overall** (in REST mode: N source locations); rules are processed in order and the run stops at N. |
| `--per-rule-limit N` | Check only the first **N violations per rule**. |
| `--apply-exclusions` | **MCP mode only.** Create an exclusion (`manage_exclusion`, `add`) for every `FALSE_POSITIVE`. The justification and evidence become the comment (truncated to 900 characters). Default is a dry run. |
| `--out` | CSV file, default `report.csv`. |
| `--no-true-positives` | Leave the `TRUE_POSITIVE` rows out of the CSV, so it only holds the `FALSE_POSITIVE` and `REVIEW` rows that need a human decision. The console summary still counts everything (`N TRUE_POSITIVE row(s) not written`). `--limit` and `--per-rule-limit` still count the true positives that were checked. |
| `--dump` | Print the raw payload and stop: `get_violations` (MCP), or a violation with its findings and source codes (REST), or how an export file's columns were read (`--input`). |
| `--list-rules` | List the supported rules and exit. |
| `--coverage` | With `--rest-url` or `--input`: count the violations of the snapshot per rule and say whether each rule is `CHECKED` (a checker decides), `REVIEW_ONLY` (always a manual review) or `NO_CHECKER` (not covered by this tool). Prints a summary and the uncovered rules, and writes `<out>_coverage.csv`. It reads every violation once (no source files), so it can take a while on a large application. Not available in MCP mode. |

The MCP API requires `nb_rows` ≥ 10, so with `--limit` below 10 the tool fetches 10 and checks only the first N.

**Run time.** Every rule costs one request, and every violation one or two more (its findings, then the file the
first time it is seen). `--rule-ids auto` covers more than 300 rules and can take a quarter of an hour or more
against a remote server: start with `--limit` or `--per-rule-limit`, or pick a family (`abap`, `sapui5`, `web`,
`sql`) or a list of rule ids. Progress is printed as the run goes (one line per rule that has violations, and a
heartbeat every 25 rules). Ctrl+C, or an error in the middle of the run, still writes the report of what was checked
so far.

## Report

`report.csv` (UTF-8 with BOM, opens directly in Excel) has one row per violation:

| Column | Content |
|---|---|
| `rule`, `rule_name` | Rule id and name. |
| `object`, `file`, `line` | Where Imaging reported it. |
| `verdict` | `TRUE_POSITIVE`, `FALSE_POSITIVE` or `REVIEW`. |
| `reason` | Why the checker decided so. For a `REVIEW` caused by "construct not found", the text says that CAST reported this line and it is either a line-anchoring difference or a limit of the checker. |
| `evidence` | The statement(s) the decision is based on. |
| `justification` | Filled for false positives only: `[rule] reason`. |
| `excluded` | MCP mode: `yes` when `--apply-exclusions` created the exclusion, `no (missing href)` when the payload had no hrefs. Empty otherwise. |

A summary and the list of false positives are also printed to the console.

The `evidence` column holds **excerpts of your source code**: treat `report.csv` as confidential and do not commit it
(it is in `.gitignore`).

A practical way to read it: filter on `FALSE_POSITIVE` and check a sample against the code, then look at `REVIEW`
(sort by `rule`), and treat `TRUE_POSITIVE` as confirmed. To get a report that contains only those first two
groups, add `--no-true-positives`.

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `ImportError: cannot import name 'streamablehttp_client'` | Old runner with `mcp` 2.x: update (`git pull`); both SDK generations are supported. |
| `ConnectError: [Errno 11001] getaddrinfo failed` | The host name in `--url` / `--rest-url` does not resolve: you are still using the placeholder (`imaging`, `<server>`). Use the real host. |
| `HTTP 404 ... the server rejected the credentials for user '...'` | Wrong user or password: some servers (including CAST's Dashboard REST API) answer **404, not 401**, to bad credentials. The tool confirms it with the server's `login` endpoint. Check `--user` and the password (`--password` or `CAST_REST_PASSWORD`), including a stray space or line break from pasting; if the password was changed or rotated, use the new one. |
| `HTTP 404 ... the credentials are accepted but this path does not exist` | `--domain` (or the application name) is wrong. Opening `--rest-url` in a browser lists the domains. |
| `HTTP 404 ... --rest-url does not look like the server's REST root` | `--rest-url` must end with the server's `/rest` segment. |
| `HTTP 401 ... check the credentials` | No or invalid credentials. In Windows `cmd`, `$VAR` is **not** expanded: use `%VAR%`. |
| `HTTP 403` | The user has no access to that domain or application. |
| `Application 'X' not found ... Available: ...` | `--app` is matched on the exact name (case-insensitive); the message lists the available ones. |
| No violations for a rule in REST mode | Use the **engineering** domain (e.g. `AED` / `CENTRAL`), not a measurement-only one (e.g. `AAD`). Run with `--rule-ids <id> --dump` to see what the server returns. |
| Many `REVIEW` rows saying "CAST reported this line" | The construct is not at the reported line: a line-anchoring difference or a checker limit. Look at the `evidence` column; if a pattern repeats, it is a candidate for a checker fix. |
| `REVIEW` "Inside an AMDP method" / "SQL rule on an ABAP file" | SQLScript or embedded SQL inside ABAP is not parsed: review those by hand. |
| `HTTP 400 ... rule-pattern is unknown in this domain` | The rule is not part of this application's quality model (for example a rule from a newer extension that was not installed or activated). It is not an error: the rule is skipped, and one line at the end lists the skipped rules. |
| `ConnectionResetError: [WinError 10054]` / "connection reset by peer" / "connection was interrupted 4 times" | The server, a proxy or a firewall closed the connection, often because a long run sends thousands of requests. Each request is retried 4 times with a growing pause. A request that still fails is skipped (the row becomes `REVIEW`, or the rule is skipped with a message) and the run continues. If the whole run stops, the report of what was checked so far is still written. Rerun later, or reduce the load with `--per-rule-limit`, `--limit` or a single family (`--rule-ids abap`). |
| `Checker error: ...` in `reason` | A checker bug on an unusual construct: the run continues, the row is `REVIEW`. Please report the rule id and file. |
| Full traceback needed | Set `GATEKEEPER_DEBUG=1`. |

## How it works

```
gatekeeper_validate.py        runner: input modes (REST / MCP / file), rule selection, limits, CSV, exclusions, routing
├── dashboard_rest.py         CAST Dashboard REST API client (applications, snapshots, violations, locations, source download)
├── abap_checkers.py          ABAP statement parser (+ AMDP detection) + 72 rule ids
├── sapui5_checkers.py        JsCtx (JS/JSON/HTML/CSS aware of comments and strings) + SAPUI5 rules
├── web_checkers.py           TG004 rules (brace/loop/try/switch/finally aware, cookies, Node, Angular, Vue, jQuery, CSS)
└── sql_checkers.py           SQL statement splitter, FROM/JOIN parser, PL/SQL & T-SQL loops, tables/keys
```

Every checker has the same signature:

```python
def chk(ctx, line_no) -> (verdict, reason, evidence)
```

and each module exposes `RULES = {rule_id: (name, checker)}` plus a review-only map. The runner caches one parsed
context per source file.

## Adding or changing a checker

1. Write the checker in the module of the right family, e.g. in `web_checkers.py`:

   ```python
   reg(1020999, "Avoid using foo()", keyword(r"\bfoo\s*\(", "foo()"))
   ```

   `keyword()` handles the common case: the pattern is matched on code only (comments blanked, string literals
   masked), so a match inside a comment or a string literal becomes a justified `FALSE_POSITIVE`. Use `lit()` (web,
   SAPUI5) or `literals=True` (ABAP) when the pattern needs string content.
2. Follow the verdict rules: **`FALSE_POSITIVE` only when the file proves it.** If the construct is simply not found
   at the reported line, return `REVIEW`: CAST anchors lines approximately.
3. Add at least one true-positive and one false-positive case to the matching `test_*_checkers.py`. Cases built from
   real violations are the most valuable ones: keep them free of customer identifiers.
4. Run the tests (below).

A checker error never stops a batch: it is caught and reported as `REVIEW` with `Checker error: …`.

## Tests

No server is needed:

```bash
python test_abap_checkers.py
python test_sapui5_checkers.py
python test_sql_checkers.py
python test_web_checkers.py
python test_input_mode.py
python test_dashboard_rest.py     # starts a fake REST server on localhost
```

## Known limitations

- **One file at a time.** No call graph, no data dictionary, no library versions. Cross-file facts are reported as
  `REVIEW`, or as `TRUE_POSITIVE` with the caveat in the reason (e.g. an authorization check performed in a caller).
- **Rule semantics are inferred from rule names**, since CAST publishes no rule descriptions. Several rules (e.g.
  SAPUI5 hard-coded IDs, unnamed OData model, async loading) are interpretations; ambiguous cases return `REVIEW`.
- **Line anchoring is approximate on CAST's side**: it can report the line of the statement before, the comment
  banner above a `FORM`, or an `AT` event inside a loop. The checkers tolerate the cases seen so far and return
  `REVIEW` when the code at the line is not what the rule expects; that is never treated as proof of a false
  positive.
- **REST mode:** verified against one server version (CAST Dashboard REST API 8.3.50) and one application. The quality
  rule id is passed as the API's `rule-pattern`, and violation lines are read from the findings. The file path in the
  report is the server's (often an absolute Windows path); the checker uses the downloaded copy, so a local checkout
  can differ without consequence. `--input` trusts the file and line of the export.
- **MCP mode** has not been run against a real Gatekeeper MCP server.
- **ABAP:** chained `:` statements are kept as one statement; CDS source is not handled; AMDP (SQLScript) bodies are not
  parsed (verdicts there are `REVIEW`).
- **SQL:** statements are split on `;`, blank lines and `GO`; T-SQL without any of them can merge neighbouring
  statements. Joins and aliases are analysed for the first top-level `FROM` of a statement only.
- **JavaScript/TypeScript:** regular-expression literals containing quotes or braces can confuse the comment/string
  stripper and the block tracker. JSX/Vue templates are handled approximately.
- Review a sample of the false positives before using `--apply-exclusions`: an exclusion hides a violation.
