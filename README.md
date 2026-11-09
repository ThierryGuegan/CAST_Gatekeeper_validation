# gatekeeper_validate

Triage CAST Imaging **Gatekeeper** violations as true or false positives, automatically.

For each selected quality rule the tool

1. fetches the violations from the Gatekeeper MCP server (`get_violations`),
2. reads the source file at the reported line from a local checkout,
3. runs the rule's checker and classifies the violation,
4. writes a CSV report with the reason, the evidence and a ready-to-use justification,
5. optionally creates the exclusions in Imaging for the false positives.

It builds on the [CAST Gatekeeper MCP server](https://doc.castsoftware.com/imaging/mcp-server/gatekeeper/windows/)
(tools `get_violations` and `manage_exclusion`).

> **Status:** the checkers are covered by unit tests, and the runner was smoke-tested against a *stubbed*
> MCP client. It has **not** been run against a live Imaging server. Do a `--dump` run first (see
> [Quick start](#quick-start)) and review a sample of the false-positive verdicts before creating exclusions.

## Verdicts

| Verdict | Meaning |
|---|---|
| `TRUE_POSITIVE` | The source confirms the violation. |
| `FALSE_POSITIVE` | The source itself proves the violation is not real (commented out, inside a string, the construct is guarded, the pattern is not a loop, …). The `reason` column says why. |
| `REVIEW` | Cannot be decided from the source text: metadata, call graph, library version, metric or naming convention is needed, or the code at the reported line is not what the rule expects. |

Design rules: a `FALSE_POSITIVE` is returned **only when the file proves it**. When the answer may depend on
another file (a loop in a caller, a security header configured elsewhere, a check in a caller) the verdict is
`REVIEW`, or `TRUE_POSITIVE` with the limitation stated in the reason.

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
| anything else | JavaScript/TypeScript for `sapui5`/`web` rules, ABAP for `abap` rules |

## Installation

Python 3 (developed and tested on 3.13) and the `mcp` package (only needed to talk to the server; `--list-rules` and the tests do not need it).

```bash
pip install mcp
```

Both generations of the `mcp` SDK are supported (the older `streamablehttp_client` and the newer
`streamable_http_client`, whose interface differs); the runner detects which one is installed.

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

`--source-root` must contain every source language you want checked (ABAP, SQL, JS, …). The reported path is
matched under that root; if it does not match exactly, the candidate sharing the longest trailing path is used.

## Command line

| Option | Description |
|---|---|
| `--url`, `--api-key`, `--app`, `--source-root` | Required (except with `--list-rules`). |
| `--rule-ids` | `auto` (default: every rule with a checker), `abap`, `sapui5`, `web`, `sql`, `all` (auto + review-only), or a comma list such as `7520,1020600,1101114`. |
| `--snapshot` | `latest` (default), a snapshot number, or `5,6` (as accepted by `get_violations`). |
| `--limit N` | Check only the first **N violations overall**; rules are processed in order and the run stops at N. |
| `--per-rule-limit N` | Check only the first **N violations per rule**. |
| `--apply-exclusions` | Create an exclusion (`manage_exclusion`, `add`) for every `FALSE_POSITIVE`. The justification and evidence become the comment (truncated to 900 characters). Default is a dry run. |
| `--out` | CSV file, default `report.csv`. |
| `--dump` | Print the raw `get_violations` payload and stop. |
| `--list-rules` | List the supported rules and exit. |

The API requires `nb_rows` ≥ 10, so with `--limit` below 10 the tool fetches 10 and checks only the first N.

## Report

`report.csv` (UTF-8 with BOM, opens directly in Excel) has one row per violation:

| Column | Content |
|---|---|
| `rule`, `rule_name` | Rule id and name. |
| `object`, `file`, `line` | Where Imaging reported it. |
| `verdict` | `TRUE_POSITIVE`, `FALSE_POSITIVE` or `REVIEW`. |
| `reason` | Why the checker decided so. |
| `evidence` | The statement(s) the decision is based on. |
| `justification` | Filled for false positives only: `[rule] reason`. |
| `excluded` | `yes` when `--apply-exclusions` created the exclusion, `no (missing href)` when the payload had no hrefs. |

A summary and the list of false positives are also printed to the console.

## How it works

```
gatekeeper_validate.py        runner: MCP client, rule selection, limits, CSV, exclusions, routing
├── abap_checkers.py          ABAP statement parser + 72 rule ids
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

   `keyword()` handles the common case: the pattern is matched on code only, so a match inside a comment or a
   string literal becomes a justified `FALSE_POSITIVE`. Use `lit()` when the pattern needs string content.
2. Add at least one true-positive and one false-positive case to the matching `test_*_checkers.py`.
3. Run the tests (below).

A checker error never stops a batch: it is caught and reported as `REVIEW` with `Checker error: …`.

## Tests

No server is needed:

```bash
python test_abap_checkers.py
python test_sapui5_checkers.py
python test_sql_checkers.py
python test_web_checkers.py
```

## Known limitations

- **One file at a time.** No call graph, no data dictionary, no library versions. Cross-file facts are reported as
  `REVIEW`, or as `TRUE_POSITIVE` with the caveat in the reason (e.g. an authorization check performed in a caller).
- **Rule semantics are inferred from rule names**, since CAST publishes no rule descriptions. Several rules (e.g.
  SAPUI5 hard-coded IDs, unnamed OData model, async loading) are interpretations; ambiguous cases return `REVIEW`.
- **Line anchoring** (which line Imaging reports for each rule) is unverified. Checkers search the nearby
  statements and return `REVIEW` when the code is not what the rule expects, which usually means the checkout does
  not match the analyzed version.
- **ABAP:** chained `:` statements are kept as one statement; CDS source is not handled.
- **SQL:** statements are split on `;`, blank lines and `GO`; T-SQL without any of them can merge neighbouring
  statements. Joins and aliases are analysed for the first top-level `FROM` of a statement only.
- **JavaScript/TypeScript:** regular-expression literals containing quotes or braces can confuse the comment/string
  stripper and the block tracker. JSX/Vue templates are handled approximately.
- Review a sample of the false positives before using `--apply-exclusions`: an exclusion hides a violation.
