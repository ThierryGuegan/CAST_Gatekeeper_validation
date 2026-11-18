"""Run: python3 test_input_mode.py   (no server, no mcp package needed)"""
import asyncio, contextlib, csv, io, json, sys, tempfile
from pathlib import Path

import gatekeeper_validate as g

FAILS = []


def check(name, cond, detail=""):
    if not cond:
        FAILS.append(name)
        print(f"FAIL {name} {detail}")


def run(argv):
    """Run main() with argv, return (stdout, exit_code)."""
    out, code = io.StringIO(), 0
    old = sys.argv
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
    tmp = Path(tempfile.mkdtemp())
    src = tmp / "src"
    (src / "abap").mkdir(parents=True)
    (src / "web").mkdir()
    (src / "abap" / "zprog.abap").write_text(
        "SELECT SINGLE * FROM mara INTO ls WHERE matnr = p.\nSELECT * FROM mara INTO ls.\n  WRITE ls.\nENDSELECT.\n")
    (src / "web" / "main.js").write_text('var a = jQuery.sap.require("x");\nconsole.log(1);\n')

    # --- loader: header variants, delimiters, encodings
    f1 = tmp / "a.csv"
    f1.write_text("Rule ID;File Path;Start Line;Object Full Name\n7544;abap/zprog.abap;1;Zprog é\n7544;abap/zprog.abap;2;Zprog\n",
                  encoding="cp1252")
    v, info = g.load_violations(f1)
    check("semicolon + cp1252", len(v) == 2 and v[0]["objectFullName"] == "Zprog é" and v[0]["rule"] == "7544", v)

    f2 = tmp / "b.csv"
    f2.write_text('Rule,File,Line\n"Avoid using SELECT ... ENDSELECT statement (7544)",abap/zprog.abap,"2"\n', encoding="utf-8-sig")
    v, _ = g.load_violations(f2)
    check("rule id extracted from a label", v and v[0]["rule"] == "7544" and v[0]["line"] == "2", v)

    f3 = tmp / "c.csv"
    f3.write_text("metric id\tpath\tline number\n1020060\tweb/main.js\t12-15\n")
    v, _ = g.load_violations(f3)
    check("tab delimiter + line range", v and v[0]["line"] == "12", v)

    f4 = tmp / "d.json"
    f4.write_text(json.dumps([{"ruleId": 7544, "filePath": "abap/zprog.abap", "startLine": 1}]))
    check("json list", g.load_violations(f4)[0][0]["rule"] == "7544")
    f5 = tmp / "e.json"
    f5.write_text(json.dumps({"7544": [{"file": "abap/zprog.abap", "line": 1}], "1020060": [{"file": "web/main.js", "line": 2}]}))
    v, _ = g.load_violations(f5)
    check("json keyed by rule", sorted(x["rule"] for x in v) == ["1020060", "7544"], v)
    f6 = tmp / "f.json"
    f6.write_text(json.dumps({"violations": [{"rule": "7544", "filePath": "abap/zprog.abap", "startLine": 1}]}))
    check("json nested like get_violations", len(g.load_violations(f6)[0]) == 1)

    f7 = tmp / "g.csv"
    f7.write_text("Rule ID,File,Line\n7544,abap/zprog.abap,1\nxx,abap/zprog.abap,1\n7544,,3\n7544,abap/zprog.abap,\n")
    v, info = g.load_violations(f7)
    check("unusable rows counted", len(v) == 1 and info["skipped"] == 3, (len(v), info))

    # --- end to end
    csvf = tmp / "violations.csv"
    csvf.write_text("Rule ID,File,Line,Object\n7544,abap/zprog.abap,1,A\n7544,abap/zprog.abap,2,B\n"
                    "1020060,web/main.js,2,C\n1020600,web/main.js,1,D\n7766,abap/zprog.abap,2,E\n9999999,abap/zprog.abap,1,F\n")
    out = tmp / "report.csv"
    text, code = run(["--input", str(csvf), "--source-root", str(src), "--out", str(out)])
    rows = list(csv.DictReader(open(out, encoding="utf-8-sig")))
    got = {(r["rule"], r["line"]): r["verdict"] for r in rows}
    check("exit ok", code == 0, text)
    check("verdicts", got == {("7544", "1"): "FALSE_POSITIVE", ("7544", "2"): "TRUE_POSITIVE",
                              ("1020060", "2"): "TRUE_POSITIVE", ("1020600", "1"): "TRUE_POSITIVE"}, got)
    check("justification for the false positive", any(r["justification"].startswith("[7544]") for r in rows))
    check("skipped rules reported", "Not checked" in text and "7766" in text and "9999999" in text, text)
    check("excluded column empty", all(r["excluded"] == "" for r in rows))

    text, _ = run(["--input", str(csvf), "--source-root", str(src), "--out", str(out), "--rule-ids", "all"])
    rows = list(csv.DictReader(open(out, encoding="utf-8-sig")))
    check("--rule-ids all adds review-only rules", any(r["rule"] == "7766" and r["verdict"] == "REVIEW" for r in rows), text)

    run(["--input", str(csvf), "--source-root", str(src), "--out", str(out), "--limit", "2"])
    check("--limit", len(list(csv.DictReader(open(out, encoding="utf-8-sig")))) == 2)
    run(["--input", str(csvf), "--source-root", str(src), "--out", str(out), "--per-rule-limit", "1"])
    rows = list(csv.DictReader(open(out, encoding="utf-8-sig")))
    check("--per-rule-limit", sorted(r["rule"] for r in rows) == ["1020060", "1020600", "7544"], rows)
    run(["--input", str(csvf), "--source-root", str(src), "--out", str(out), "--rule-ids", "1020060"])
    check("--rule-ids filter", [r["rule"] for r in csv.DictReader(open(out, encoding="utf-8-sig"))] == ["1020060"])

    text, _ = run(["--input", str(csvf), "--source-root", str(src), "--dump"])
    check("--dump describes the mapping", "usable: 6" in text and "rule 7544: 2" in text, text)

    # --- --no-true-positives: the CSV keeps only what needs a human decision
    text, code = run(["--input", str(csvf), "--source-root", str(src), "--out", str(out), "--no-true-positives"])
    rows = list(csv.DictReader(open(out, encoding="utf-8-sig")))
    check("--no-true-positives: no TRUE_POSITIVE row in the CSV", rows and all(r["verdict"] != "TRUE_POSITIVE" for r in rows), rows)
    check("--no-true-positives: the false positive is still there", any(r["verdict"] == "FALSE_POSITIVE" for r in rows), rows)
    check("--no-true-positives: the summary still counts everything", "'TRUE_POSITIVE': 3" in text and "3 TRUE_POSITIVE row(s) not written" in text, text)
    text, _ = run(["--input", str(csvf), "--source-root", str(src), "--out", str(out), "--rule-ids", "1020060", "--no-true-positives"])
    check("--no-true-positives with only true positives: header-only CSV",
          open(out, encoding="utf-8-sig").read().strip().startswith("rule,rule_name") and len(open(out, encoding="utf-8-sig").read().strip().splitlines()) == 1, open(out, encoding="utf-8-sig").read())
    text, _ = run(["--input", str(csvf), "--source-root", str(src), "--out", str(out)])
    check("default still writes the true positives", any(r["verdict"] == "TRUE_POSITIVE" for r in csv.DictReader(open(out, encoding="utf-8-sig"))))

    # --- routing: a SQL-analyzer rule firing on an ABAP file (AMDP SQLScript) is review-only
    (src / "abap" / "zamdp.abap").write_text("METHOD m BY DATABASE PROCEDURE FOR HDB LANGUAGE SQLSCRIPT.\n  SELECT * FROM t1;\nENDMETHOD.\n"
                                              "SELECT * FROM mara INTO TABLE lt.\n")
    f8 = tmp / "h.csv"
    f8.write_text("Rule ID,File,Line\n1101072,abap/zamdp.abap,2\n1101114,abap/zamdp.abap,2\n7528,abap/zprog.abap,1\n7530,abap/zamdp.abap,2\n7530,abap/zamdp.abap,4\n")
    text, code = run(["--input", str(f8), "--source-root", str(src), "--out", str(out), "--rule-ids", "all"])
    allrows = list(csv.DictReader(open(out, encoding="utf-8-sig")))
    rows = {r["rule"]: r for r in allrows if r["rule"] != "7530"}
    amdp = {r["line"]: r for r in allrows if r["rule"] == "7530"}
    check("ABAP verdict inside an AMDP method is REVIEW", amdp["2"]["verdict"] == "REVIEW" and "AMDP" in amdp["2"]["reason"], amdp["2"])
    check("same rule outside the AMDP method is still decided", amdp["4"]["verdict"] == "TRUE_POSITIVE", amdp["4"])
    check("SQL rule on .abap -> REVIEW with explanation", rows["1101072"]["verdict"] == "REVIEW" and "not parsed" in rows["1101072"]["reason"], rows["1101072"])
    check("not-found REVIEW is explained", rows["7528"]["verdict"] == "REVIEW" and "line-anchoring" in rows["7528"]["reason"], rows["7528"])
    check("AMDP SELECT * decided from the keyword", rows["1101114"]["verdict"] == "TRUE_POSITIVE" and "SQLScript" in rows["1101114"]["reason"], rows["1101114"])

    # --- 7884 on a class include: the pragma is in the method implementation (sibling CM include)
    (src / "abap" / "ZCLX==========================CU.abap").write_text("CLASS zclx DEFINITION.\n  PUBLIC SECTION.\n    METHODS foo.\n    METHODS bar.\nENDCLASS.\n")
    (src / "abap" / "ZCLX==========================CM001.abap").write_text("METHOD foo.\n  DATA x TYPE i ##NEEDED.\nENDMETHOD.\n")
    (src / "abap" / "ZCLX==========================CM002.abap").write_text("METHOD bar.\n  WRITE 1.\nENDMETHOD.\n")
    f9 = tmp / "i.csv"
    f9.write_text("Rule ID,File,Line\n7884,abap/ZCLX==========================CU.abap,3\n7884,abap/ZCLX==========================CU.abap,4\n")
    text, code = run(["--input", str(f9), "--source-root", str(src), "--out", str(out), "--rule-ids", "all"])
    r9 = {r["line"]: r for r in csv.DictReader(open(out, encoding="utf-8-sig"))}
    check("7884 declaration: pragma found in the method implementation", r9["3"]["verdict"] == "TRUE_POSITIVE" and "implementation of method foo" in r9["3"]["reason"], r9["3"])
    check("7884 declaration without pragma stays REVIEW", r9["4"]["verdict"] == "REVIEW", r9["4"])

    # REST mode: the method body comes from the server (ctx.aux), not from sibling files on disk
    import abap_checkers as _ac
    _d = tmp / "rest"; _d.mkdir()
    (_d / "1_CU.abap").write_text("CLASS zclx DEFINITION.\n  PUBLIC SECTION.\n    METHODS foo.\nENDCLASS.\n")
    (_d / "2_CM001.abap").write_text("METHOD foo.\n  DATA x TYPE i ##NEEDED.\nENDMETHOD.\n")
    _c = _ac.Ctx((_d / "1_CU.abap").read_text().splitlines()); _c.path = _d / "1_CU.abap"; _c.aux = lambda: [_d / "2_CM001.abap"]
    check("7884 via server-provided component file", _ac.RULES["7884"][1](_c, 3)[0] == "TRUE_POSITIVE")

    # --- errors
    bad = tmp / "bad.csv"
    bad.write_text("Foo,Bar\n1,2\n")
    text, code = run(["--input", str(bad), "--source-root", str(src), "--out", str(out)])
    check("unusable file explained", code != 0 and "Detected columns" in text and "Foo" in text, text)
    text, code = run(["--input", str(csvf), "--source-root", str(src), "--apply-exclusions"])
    check("--apply-exclusions refused", code == 2, (code, text))
    text, code = run(["--input", str(csvf)])
    check("--source-root required", code == 2)
    text, code = run(["--source-root", str(src)])
    check("MCP args still required without --input", code == 2)

    text, code = run(["--version"])
    check("--version prints the version and exits", code == 0 and text.startswith("gatekeeper_validate ") and text.count("\n") == 1, text)
    text, _ = run(["--list-rules"])
    check("every run starts with the version line", text.startswith("gatekeeper_validate "), text[:80])

    # ids shared by ABAP and JS/TS (7788, 7884, 7526, 8028, 8032) are routed by file extension
    for rid, f, fam in [("8028", "a.controller.js", "web"), ("8028", "z.abap", "abap"), ("7788", "a.ts", "web"),
                        ("7788", "z.abap", "abap"), ("7884", "a.js", "web"), ("7884", "z.abap", "abap"),
                        ("7526", "a.js", "web"), ("7526", "z.abap", "abap"), ("8032", "a.js", "web"),
                        ("8032", "z.abap", "manual")]:
        check(f"routing {rid} on {f}", g.pick_checker(rid, Path(f))[0] == fam, g.pick_checker(rid, Path(f))[0])

    print(f"{'all passed' if not FAILS else str(len(FAILS)) + ' failed: ' + ', '.join(FAILS)}")
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())
