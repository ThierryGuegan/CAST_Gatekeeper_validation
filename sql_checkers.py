"""
SQL checkers for the CAST SQL Analyzer extension (com.castsoftware.sqlanalyzer, rules 11010xx).
Handles PL/SQL, T-SQL and COBOL embedded SQL (EXEC SQL ... END-EXEC) heuristically.

Same contract as the other modules: chk(ctx, line_no) -> (verdict, reason, evidence).
CAST publishes only rule names, so semantics are inferred from the names; anything that
needs metadata (indexes, row counts, naming conventions, call graph) is REVIEW-only.
Limitation: a statement is delimited by ';', a blank line, GO or END-EXEC. T-SQL scripts
without semicolons or blank lines can merge neighbouring statements.
"""
import re

TP, FP, RV = "TRUE_POSITIVE", "FALSE_POSITIVE", "REVIEW"
NOLINE = (RV, "Reported line is outside the file (source may differ from the analyzed version)", "")
SQL_EXT = {".sql", ".pks", ".pkb", ".plsql", ".pls", ".tsql", ".prc", ".fnc", ".trg", ".vw", ".pck",
           ".cbl", ".cob", ".cpy", ".pco"}
COBOL_EXT = {".cbl", ".cob", ".cpy", ".pco"}
STARTER = re.compile(r"\s*(INSERT|UPDATE|DELETE|MERGE|CREATE|ALTER|DROP|OPEN|DECLARE|EXEC(?:UTE)?|FETCH|LOCK|TRUNCATE)\b", re.I)


def _strip_sql(text):
    c, b, state, i, n = [], [], None, 0, len(text)
    while i < n:
        ch, nx = text[i], (text[i + 1] if i + 1 < n else "")
        if state is None:
            if ch == "-" and nx == "-":
                state = "line"; c.append("  "); b.append("  "); i += 2; continue
            if ch == "/" and nx == "*":
                state = "block"; c.append("  "); b.append("  "); i += 2; continue
            if ch in "'\"`":
                state = ch
            c.append(ch); b.append(ch)
        elif state == "line":
            if ch == "\n":
                state = None; c.append(ch); b.append(ch)
            else:
                c.append(" "); b.append(" ")
        elif state == "block":
            if ch == "*" and nx == "/":
                state = None; c.append("  "); b.append("  "); i += 2; continue
            c.append(ch if ch == "\n" else " "); b.append(ch if ch == "\n" else " ")
        else:
            if ch == state:
                state = None; c.append(ch); b.append(ch)
            else:
                c.append(ch); b.append(ch if ch == "\n" else "_")
        i += 1
    return "".join(c).split("\n"), "".join(b).split("\n")


class SqlCtx:
    def __init__(self, lines, cobol=False):
        self.raw = [l.rstrip("\r\n") for l in lines]
        src = ["" if (cobol and len(l) > 6 and l[6] in "*/") else l for l in self.raw]
        self.code, self.bare = _strip_sql("\n".join(src))
        self.text = "\n".join(self.bare)

    def ok(self, n):
        return 1 <= n <= len(self.raw)

    def seg(self, n):
        i = n - 1
        st = i
        for k in range(i, max(-1, i - 60), -1):
            b = self.bare[k]
            if k < i and (";" in b or not b.strip() or re.match(r"\s*(GO|END-EXEC)\b", b, re.I)
                          or re.search(r"\b(LOOP|THEN|BEGIN|ELSE)\s*$", b, re.I)):
                st = k + 1
                break
            st = k
            if STARTER.match(b):
                break
        en = i
        for k in range(i, min(len(self.raw), i + 60)):
            b = self.bare[k]
            if k > i and (not b.strip() or re.match(r"\s*GO\b", b, re.I) or STARTER.match(b)):
                break
            en = k
            if ";" in b or re.search(r"END-EXEC", b, re.I):
                break
        a, z = st + 1, en + 1
        return " ".join(self.code[a - 1:z]), " ".join(self.bare[a - 1:z]), a, z

    def ev(self, a, z=None):
        z = z or a
        return " ".join(" ".join(l.split()) for l in self.raw[a - 1:z])[:400]


def _s(ctx, n):
    return ctx.seg(n) if ctx.ok(n) else None


def kw(rx, label, bare_only=True):
    def chk(ctx, n):
        r = _s(ctx, n)
        if r is None:
            return NOLINE
        code, bare, a, z = r
        if re.search(rx, bare, re.I | re.S):
            return TP, f"{label} found", ctx.ev(a, z)
        raw = " ".join(ctx.raw[a - 1:z])
        if re.search(rx, code, re.I | re.S):
            return FP, f"{label} appears only inside a string literal", ctx.ev(a, z)
        if re.search(rx, raw, re.I | re.S):
            return FP, f"{label} appears only in a comment", ctx.ev(a, z)
        return FP, f"No {label} in the statement at this line (source may differ from the analyzed version)", ctx.ev(a, z)
    return chk


# ----------------------------- FROM clause parsing -------------------------------------------
CLAUSE_END = re.compile(r"\b(WHERE|GROUP\s+BY|ORDER\s+BY|HAVING|UNION|INTERSECT|EXCEPT|MINUS|CONNECT\s+BY|START\s+WITH|"
                        r"FETCH|LIMIT|FOR\s+UPDATE|INTO)\b|;", re.I)
SEP = re.compile(r",|\b(?:NATURAL\s+)?(?:(?:INNER|CROSS)\s+|(?:LEFT|RIGHT|FULL)\s+(?:OUTER\s+)?)?JOIN\b", re.I)


def split_top(text, rx):
    out, depth, last, sep, i = [], 0, 0, "", 0
    while i < len(text):
        ch = text[i]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        elif depth == 0:
            m = rx.match(text, i)
            if m and m.end() > i:
                out.append((sep, text[last:i])); sep = m.group(0); i = m.end(); last = i
                continue
        i += 1
    out.append((sep, text[last:]))
    return out


def top_from(bare):
    """Return (from_text, where_text) of the first top-level FROM, or (None, None)."""
    for m in re.finditer(r"\bFROM\b", bare, re.I):
        if bare[:m.start()].count("(") - bare[:m.start()].count(")") != 0:
            continue
        depth, i, s = 0, m.end(), m.end()
        while i < len(bare):
            ch = bare[i]
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth < 0:
                    break
            elif depth == 0 and CLAUSE_END.match(bare, i):
                break
            i += 1
        rest = bare[i:]
        w = re.search(r"\bWHERE\b(.*?)(?:\bGROUP\s+BY\b|\bORDER\s+BY\b|\bHAVING\b|\bUNION\b|;|$)", rest, re.I | re.S)
        return bare[s:i], (w.group(1) if w else "")
    return None, None


def table_items(from_text):
    items = []
    for sep, piece in split_top(from_text, SEP):
        cond = bool(re.search(r"\bON\b|\bUSING\b", piece, re.I))
        piece = re.sub(r"\b(ON|USING)\b.*$", "", piece, flags=re.I | re.S).strip()
        piece = re.sub(r"\bWITH\s*\([^)]*\)", "", piece, flags=re.I).strip()
        sub = piece.startswith("(")
        if sub:
            depth, k = 0, 0
            for k, ch in enumerate(piece):
                depth += ch == "("
                depth -= ch == ")"
                if depth == 0:
                    break
            toks = piece[k + 1:].split()
            name = "(subquery)"
        else:
            toks = piece.split()
            name, toks = (toks[0] if toks else ""), toks[1:]
        toks = [t for t in toks if t.upper() != "AS"]
        items.append({"sep": sep.strip().upper(), "name": name, "alias": toks[0] if toks else None,
                      "sub": sub, "cond": cond})
    return items


def _query_parts(ctx, n):
    r = _s(ctx, n)
    if r is None:
        return None
    code, bare, a, z = r
    ft, wt = top_from(bare)
    return code, bare, a, z, ft, wt


def _need_from(ctx, n):
    p = _query_parts(ctx, n)
    if p is None:
        return None, NOLINE
    if p[4] is None:
        return None, (RV, "No FROM clause in the statement at this line", ctx.ev(p[2], p[3]))
    return p, None


# ------------------------------------- join rules --------------------------------------------
def chk_cartesian(ctx, n):                                             # 1101000, 1101002
    p, err = _need_from(ctx, n)
    if err:
        return err
    code, bare, a, z, ft, wt = p
    items = table_items(ft)
    for it in items[1:]:
        if "CROSS" in it["sep"]:
            return TP, "CROSS JOIN is a cartesian product", ctx.ev(a, z)
        if "JOIN" in it["sep"] and "NATURAL" not in it["sep"] and not it["cond"]:
            return TP, f"JOIN with {it['name']} has no ON/USING condition: cartesian product", ctx.ev(a, z)
    commas = [it for it in items[1:] if it["sep"] == ","]
    if commas:
        quals = re.findall(r"([A-Za-z_][\w$#]*)\s*\.\s*[\w$#]+\s*(?:\(\+\))?\s*=\s*([A-Za-z_][\w$#]*)\s*\.\s*[\w$#]+", wt or "")
        links = sum(1 for x, y in quals if x.upper() != y.upper())
        if links < len(items) - 1:
            return TP, (f"{len(items)} tables in FROM but only {links} join predicate(s) in WHERE: "
                        f"missing join condition"), ctx.ev(a, z)
    return FP, "Every joined table has a join condition", ctx.ev(a, z)


def chk_natural(ctx, n):                                               # 1101010
    r = _s(ctx, n)
    if r is None:
        return NOLINE
    return kw(r"\bNATURAL\s+(?:(?:LEFT|RIGHT|FULL)\s+(?:OUTER\s+)?|INNER\s+)?JOIN\b", "NATURAL JOIN")(ctx, n)


def chk_old_join(ctx, n):                                              # 1101014
    p, err = _need_from(ctx, n)
    if err:
        return err
    code, bare, a, z, ft, wt = p
    items = table_items(ft)
    if any(it["sep"] == "," for it in items) or re.search(r"\(\+\)", bare):
        return TP, "Tables are joined with the comma/WHERE (or Oracle (+)) syntax instead of ANSI JOIN", ctx.ev(a, z)
    return FP, "The statement uses ANSI JOIN syntax (or a single table)", ctx.ev(a, z)


def chk_mixed_join(ctx, n):                                            # 1101058
    p, err = _need_from(ctx, n)
    if err:
        return err
    code, bare, a, z, ft, wt = p
    items = table_items(ft)
    comma = any(it["sep"] == "," for it in items)
    ansi = any("JOIN" in it["sep"] for it in items)
    if comma and ansi:
        return TP, "The same FROM clause mixes comma joins and ANSI JOINs", ctx.ev(a, z)
    return FP, "ANSI and non-ANSI join syntax are not mixed in this FROM clause", ctx.ev(a, z)


def chk_alias(missing):                                                # 1101072 / 1101074
    def chk(ctx, n):
        p, err = _need_from(ctx, n)
        if err:
            return err
        code, bare, a, z, ft, wt = p
        if not re.search(r"\bSELECT\b", bare, re.I):
            return FP, "Not a query (no SELECT) at this line", ctx.ev(a, z)
        items = [it for it in table_items(ft) if not it["sub"] and it["name"]]
        if missing:
            bad = [it["name"] for it in items if not it["alias"]]
            if bad:
                return TP, f"Table(s) without alias: {', '.join(bad)}", ctx.ev(a, z)
            return FP, "Every table in the FROM clause has an alias", ctx.ev(a, z)
        bad = [it["alias"] for it in items if it["alias"] and re.search(r"\d$", it["alias"])]
        if bad:
            return TP, f"Alias(es) ending with a number: {', '.join(bad)}", ctx.ev(a, z)
        return FP, "No table alias ends with a numeric suffix", ctx.ev(a, z)
    return chk


def chk_select_star(ctx, n):                                           # 1101114
    r = _s(ctx, n)
    if r is None:
        return NOLINE
    code, bare, a, z = r
    for m in re.finditer(r"\bSELECT\s+(?:ALL\s+|DISTINCT\s+|TOP\s+\d+\s+)?(?:[\w$#]+\s*\.\s*)?\*", bare, re.I):
        before = bare[:m.start()]
        if re.search(r"\bEXISTS\s*\(\s*$", before, re.I):
            continue
        return TP, "SELECT * returns every column", ctx.ev(a, z)
    if re.search(r"\bSELECT\s+(?:ALL\s+|DISTINCT\s+)?\*", bare, re.I):
        return FP, "SELECT * only appears inside EXISTS( ), where no column is materialised", ctx.ev(a, z)
    return FP, "The SELECT uses an explicit column list (or COUNT(*))", ctx.ev(a, z)


def chk_distinct(ctx, n):                                              # 1101034
    r = _s(ctx, n)
    if r is None:
        return NOLINE
    code, bare, a, z = r
    if re.search(r"\bSELECT\s+DISTINCT\b|\bUNION\s+DISTINCT\b", bare, re.I):
        return TP, "SELECT DISTINCT forces a sort/dedup of the whole result", ctx.ev(a, z)
    if re.search(r"\bDISTINCT\b", bare, re.I):
        return FP, "DISTINCT is used inside an aggregate, not on the SELECT result", ctx.ev(a, z)
    return FP, "No DISTINCT in the statement at this line", ctx.ev(a, z)


def chk_order_by_number(ctx, n):                                       # 1101012
    r = _s(ctx, n)
    if r is None:
        return NOLINE
    code, bare, a, z = r
    m = re.search(r"\bORDER\s+BY\s+(.*?)(?:;|\)|$)", bare, re.I | re.S)
    if m and re.search(r"(?:^|,)\s*\d+\s*(?:ASC|DESC)?\s*(?:,|$)", m.group(1), re.I):
        return TP, "ORDER BY uses column position numbers instead of column names", ctx.ev(a, z)
    return FP, "ORDER BY uses column names (or there is none)", ctx.ev(a, z)


def chk_insert_columns(ctx, n):                                        # 1101026
    r = _s(ctx, n)
    if r is None:
        return NOLINE
    code, bare, a, z = r
    t = r"\bINSERT\s+(?:INTO\s+)?[\w.$#\[\]\"@]+"
    if re.search(t + r"\s+(?:VALUES|SELECT)\b|" + t + r"\s*\(\s*SELECT\b", bare, re.I):
        return TP, "INSERT without an explicit column list", ctx.ev(a, z)
    if re.search(t + r"\s*\(", bare, re.I):
        return FP, "INSERT lists its target columns", ctx.ev(a, z)
    return RV, "Not a recognisable INSERT statement at this line", ctx.ev(a, z)


def chk_not_in(ctx, n):                                                # 1101028
    return kw(r"\bNOT\s+(?:EXISTS|IN)\s*\(\s*SELECT\b", "NOT EXISTS / NOT IN subquery")(ctx, n)


def chk_independent_exists(ctx, n):                                    # 1101032
    p, err = _need_from(ctx, n)
    if err:
        return err
    code, bare, a, z, ft, wt = p
    m = re.search(r"\bEXISTS\s*\(\s*SELECT\b(.*)", bare, re.I | re.S)
    if not m:
        return FP, "No EXISTS / NOT EXISTS subquery in this statement", ctx.ev(a, z)
    depth, body, end = 1, m.group(1), 0
    for end, ch in enumerate(body):
        depth += ch == "("
        depth -= ch == ")"
        if depth == 0:
            break
    inner = body[:end]
    inner_from, _ = top_from("SELECT 1 " + inner)
    inner_names = {x for it in table_items(inner_from or "") for x in (it["name"], it["alias"]) if x}
    outer_names = {x for it in table_items(ft) for x in (it["name"], it["alias"]) if x} - inner_names
    refs = {q.upper() for q in re.findall(r"([A-Za-z_][\w$#]*)\s*\.\s*[\w$#]+", inner)}
    if refs & {o.upper() for o in outer_names}:
        return FP, "The subquery references the outer query (correlated EXISTS)", ctx.ev(a, z)
    if not outer_names:
        return RV, "Cannot identify the outer tables to check correlation", ctx.ev(a, z)
    return TP, "The EXISTS subquery has no reference to the outer query: it is evaluated independently", ctx.ev(a, z)


def chk_nonsargable(ctx, n):                                           # 1101008
    p = _query_parts(ctx, n)
    if p is None:
        return NOLINE
    code, bare, a, z, ft, wt = p
    cond = wt or ""
    pats = [(r"\b(?:UPPER|LOWER|TRUNC|TO_CHAR|TO_DATE|SUBSTR(?:ING)?|NVL|ISNULL|COALESCE|YEAR|MONTH|DAY|CONVERT|CAST|"
              r"LTRIM|RTRIM|TRIM|LEN|LENGTH|DATEPART|DATEDIFF|ROUND|ABS)\s*\(\s*[A-Za-z_][\w$#.]*\s*[,)]",
              "a function is applied to a column"),
            (r"\bLIKE\s+['\"]?[_]*[%_]|\bLIKE\s+'%", "LIKE starts with a wildcard"),
            (r"(?:<>|!=)", "inequality operator (<> / !=)"), (r"\bNOT\s+IN\b", "NOT IN"),
            (r"[A-Za-z_][\w$#.]*\s*[+\-*/]\s*[\w$#.']+\s*(?:=|<|>)", "arithmetic on a column")]
    for rx, why in pats:
        if re.search(rx, cond, re.I):
            return TP, f"Non-SARGable predicate: {why}", ctx.ev(a, z)
    return RV, "No obviously non-SARGable predicate found; index usage cannot be confirmed from the source", ctx.ev(a, z)


def chk_like(wildcard_first):                                          # 1101060 / 1101102
    def chk(ctx, n):
        r = _s(ctx, n)
        if r is None:
            return NOLINE
        code, bare, a, z = r
        lits = re.findall(r"\bLIKE\s+('(?:[^']|'')*')", code, re.I)
        concat = re.findall(r"\bLIKE\s+(.{0,60})", bare, re.I)
        if not lits and not concat:
            return FP, "No LIKE condition in the statement at this line", ctx.ev(a, z)
        for lit in lits:
            body = lit[1:-1]
            if wildcard_first and re.match(r"[%_]", body):
                return TP, f"LIKE pattern {lit} starts with a wildcard: index cannot be used", ctx.ev(a, z)
            if not wildcard_first and not re.search(r"[%_]", body):
                return TP, f"LIKE pattern {lit} has no wildcard: use = instead", ctx.ev(a, z)
        if wildcard_first:
            return FP, "LIKE patterns do not start with a wildcard", ctx.ev(a, z)
        return FP, "LIKE patterns contain wildcards", ctx.ev(a, z)
    return chk


def chk_or_same_col(ctx, n):                                           # 1101038
    r = _s(ctx, n)
    if r is None:
        return NOLINE
    code, bare, a, z = r
    if re.search(r"([A-Za-z_][\w$#.]*)\s*=\s*[^\s()]+\s+OR\s+\1\s*=", bare, re.I):
        return TP, "OR of equality tests on the same column: use IN (...)", ctx.ev(a, z)
    return FP, "No OR chain of equality tests on the same column", ctx.ev(a, z)


def chk_null_cmp(ctx, n):                                              # 1101070
    r = _s(ctx, n)
    if r is None:
        return NOLINE
    code, bare, a, z = r
    if re.search(r"(?<![<>!])(?:=|<>|!=)\s*NULL\b|\bNULL\s*(?:=|<>|!=)", bare, re.I):
        return TP, "Comparison with NULL using = / <> instead of IS [NOT] NULL", ctx.ev(a, z)
    return FP, "NULL is tested with IS [NOT] NULL (or not compared at all)", ctx.ev(a, z)


def chk_ansi_ops(ctx, n):                                              # 1101036
    r = _s(ctx, n)
    if r is None:
        return NOLINE
    code, bare, a, z = r
    m = re.search(r"!=|\^=|!<|!>|=!|~=", bare)
    if m:
        return TP, f"Non-ANSI operator '{m.group(0)}' (use <>, <, >)", ctx.ev(a, z)
    return FP, "Only ANSI comparison operators are used", ctx.ev(a, z)


def chk_quoted_ident(ctx, n):                                          # 1101020
    r = _s(ctx, n)
    if r is None:
        return NOLINE
    code, bare, a, z = r
    if re.search(r'"_+"|`_+`', bare) or re.search(r'\[[A-Za-z_][\w ]*\]', bare):
        return TP, "Quoted identifier (\"name\", [name] or `name`): case/characters become significant", ctx.ev(a, z)
    return FP, "No quoted identifier in the statement at this line", ctx.ev(a, z)


# ---------------------------------- dynamic SQL / injection ----------------------------------
DYN = (r"\bEXECUTE\s+IMMEDIATE\b|\bDBMS_SQL\b|\bsp_executesql\b|\bEXEC(?:UTE)?\s*\(|\bEXEC(?:UTE)?\s+@\w+|"
       r"\bOPEN\s+[\w$#.]+\s+FOR\s+(?!SELECT\b|WITH\b)[\w'(]")


def chk_injection(ctx, n):                                             # 1101096
    r = _s(ctx, n)
    if r is None:
        return NOLINE
    code, bare, a, z = r
    m = re.search(r"\bEXECUTE\s+IMMEDIATE\b(.*)", bare, re.I | re.S)
    if not m:
        return FP, "No EXECUTE IMMEDIATE in the statement at this line", ctx.ev(a, z)
    arg = re.split(r"\bUSING\b|\bINTO\b|\bRETURNING\b", m.group(1), flags=re.I)[0]
    if "||" in arg:
        if re.search(r"DBMS_ASSERT", code, re.I):
            return RV, "String concatenation, but DBMS_ASSERT is used: check that every concatenated value is validated", ctx.ev(a, z)
        return TP, "Dynamic statement built by concatenation (||) without DBMS_ASSERT: SQL injection risk", ctx.ev(a, z)
    if arg.strip().startswith("'"):
        return FP, "Static statement text (string literal, values passed with USING)", ctx.ev(a, z)
    return RV, "EXECUTE IMMEDIATE with a variable: where the text is built is not visible here", ctx.ev(a, z)


# ------------------------------------ exception handling -------------------------------------
def chk_when_others_null(ctx, n):                                      # 1101054
    if not ctx.ok(n):
        return NOLINE
    win = " ".join(ctx.bare[n - 1:n + 3])
    m = re.search(r"\bWHEN\s+OTHERS\s+THEN\s+(NULL\s*;|[^;]*;)", win, re.I)
    if not m:
        return FP, "No WHEN OTHERS THEN handler at this line", ctx.ev(n, n + 3)
    if re.match(r"NULL\s*;", m.group(1), re.I):
        return TP, "WHEN OTHERS THEN NULL silently swallows every error", ctx.ev(n, n + 3)
    return FP, f"The WHEN OTHERS handler does something: {m.group(1).strip()[:60]}", ctx.ev(n, n + 3)


def chk_use_when_others(ctx, n):                                       # 1101052
    if not ctx.ok(n):
        return NOLINE
    st = None
    for k in range(n - 1, max(-1, n - 5), -1):
        if re.match(r"\s*EXCEPTION\b", ctx.bare[k], re.I):
            st = k
            break
    if st is None:
        return RV, "Expected an EXCEPTION section at/near the reported line", ctx.ev(n)
    depth, body = 0, []
    for k in range(st + 1, len(ctx.bare)):
        b = ctx.bare[k]
        if re.match(r"\s*BEGIN\b", b, re.I):
            depth += 1
        if re.match(r"\s*END\b(?!\s+(?:IF|LOOP|CASE))", b, re.I):
            if depth == 0:
                break
            depth -= 1
        if depth == 0:
            body.append(b)
    if re.search(r"\bWHEN\s+OTHERS\b", " ".join(body), re.I):
        return FP, "The EXCEPTION section has a WHEN OTHERS handler", ctx.ev(st + 1, st + 1 + len(body))
    return TP, "EXCEPTION section without WHEN OTHERS: unexpected errors propagate unhandled", ctx.ev(st + 1, st + 1 + len(body))


def chk_empty_catch(ctx, n):                                           # 1101040
    if not ctx.ok(n):
        return NOLINE
    st = None
    for k in range(n - 1, max(-1, n - 4), -1):
        if re.search(r"\bBEGIN\s+CATCH\b", ctx.bare[k], re.I):
            st = k
            break
    if st is None:
        return RV, "Expected BEGIN CATCH at/near the reported line", ctx.ev(n)
    text = "\n".join(ctx.bare[st:])
    m = re.search(r"\bBEGIN\s+CATCH\b(.*?)\bEND\s+CATCH\b", text, re.I | re.S)
    if not m:
        return RV, "END CATCH not found", ctx.ev(st + 1)
    if not m.group(1).strip(" \t\r\n;"):
        return TP, "The CATCH block is empty: the error is swallowed", ctx.ev(st + 1, st + 1 + text[:m.end()].count("\n"))
    return FP, "The CATCH block contains statements", ctx.ev(st + 1, st + 1 + text[:m.end()].count("\n"))


# --------------------------------------------- loops ------------------------------------------
def inside_loop(ctx, a):
    off = sum(len(l) + 1 for l in ctx.bare[:a - 1])
    text, before = ctx.text, ctx.text[:off]
    if len(re.findall(r"\bLOOP\b", before, re.I)) - 2 * len(re.findall(r"\bEND\s+LOOP\b", before, re.I)) > 0:
        return "LOOP"
    op = re.compile(r"\bBEGIN\b(?!\s+(?:TRAN|TRANSACTION|DISTRIBUTED))|\bCASE\b|\bEND\b(?!\s+(?:IF|LOOP|CASE))", re.I)
    for m in re.finditer(r"\bWHILE\b", text, re.I):
        if m.start() >= off:
            break
        b = re.compile(r"\bBEGIN\b(?!\s+(?:TRAN|TRANSACTION|DISTRIBUTED))", re.I).search(text, m.end())
        if not b or re.search(r"\bLOOP\b", text[m.end():b.start()], re.I):
            continue
        depth = 0
        for t in op.finditer(text, b.start()):
            depth += -1 if t.group(0).upper().startswith("END") else 1
            if depth == 0:
                if b.start() < off <= t.start():
                    return "WHILE"
                break
    return None


def make_loop(pattern, label, critical_name):
    rx = re.compile(pattern, re.I)

    def chk(ctx, n):
        r = _s(ctx, n)
        if r is None:
            return NOLINE
        code, bare, a, z = r
        if not rx.search(bare):
            return FP, f"No {label} at the reported line (source may differ from the analyzed version)", ctx.ev(a, z)
        lp = inside_loop(ctx, a)
        if lp:
            return TP, f"{label} executed inside a {lp} loop", ctx.ev(a, z)
        return RV, (f"{label} found but no enclosing loop in this file; the loop may be in a caller "
                    f"(call graph not available here)"), ctx.ev(a, z)
    return chk


# --------------------------------------------- tables ------------------------------------------
def _tname(x):
    return re.sub(r'[\[\]"`]', "", x).split(".")[-1].upper()


def make_table_check(kind):
    def chk(ctx, n):
        r = _s(ctx, n)
        if r is None:
            return NOLINE
        code, bare, a, z = r
        m = re.search(r"\bCREATE\s+(?:GLOBAL\s+TEMPORARY\s+|TEMPORARY\s+|TEMP\s+)?TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?([\w.$#\[\]\"`]+)", bare, re.I)
        if not m:
            return RV, "Expected a CREATE TABLE statement at the reported line", ctx.ev(a, z)
        name = _tname(m.group(1))
        nm = re.escape(name)
        full = ctx.text
        has_pk = re.search(r"\bPRIMARY\s+KEY\b", bare, re.I) or re.search(
            r"\bALTER\s+TABLE\s+[\w.$#\[\]\"`]*" + nm + r"[\]\"`]?\b[^;]*\bPRIMARY\s+KEY\b", full, re.I | re.S)
        has_uq = re.search(r"\bUNIQUE\b", bare, re.I) or re.search(
            r"\bALTER\s+TABLE\s+[\w.$#\[\]\"`]*" + nm + r"[\]\"`]?\b[^;]*\bUNIQUE\b", full, re.I | re.S) or re.search(
            r"\bCREATE\s+UNIQUE\s+(?:(?:NON)?CLUSTERED\s+)?INDEX\b[^;]*\bON\s+[\w.$#\[\]\"`]*" + nm + r"[\]\"`]?\b", full, re.I | re.S)
        if kind == "pk":
            if has_pk:
                return FP, f"Table {name} has a PRIMARY KEY (inline or ALTER TABLE)", ctx.ev(a, z)
            return TP, f"Table {name} has no PRIMARY KEY in this file", ctx.ev(a, z)
        if kind == "unique":
            if has_pk or has_uq:
                return FP, f"Table {name} has a primary/unique key or unique index", ctx.ev(a, z)
            return TP, f"Table {name} has no primary key, unique constraint or unique index in this file (XXL size not verified)", ctx.ev(a, z)
        clustered = re.search(r"\bCLUSTERED\b(?<!NON)", bare, re.I) and not re.search(r"\bNONCLUSTERED\b", bare, re.I) or \
            re.search(r"\bCREATE\s+(?:UNIQUE\s+)?CLUSTERED\s+INDEX\b[^;]*\bON\s+[\w.$#\[\]\"`]*" + nm + r"\b", full, re.I | re.S) or \
            (has_pk and not re.search(r"\bNONCLUSTERED\b", bare, re.I))
        if clustered:
            return FP, f"Table {name} has a clustered index (explicit, or implied by its PRIMARY KEY on SQL Server)", ctx.ev(a, z)
        return TP, f"Table {name} has no clustered index in this file", ctx.ev(a, z)
    return chk


def chk_cobol_cursor(ctx, n):                                          # 1101108
    r = _s(ctx, n)
    if r is None:
        return NOLINE
    code, bare, a, z = r
    if not re.search(r"\bDECLARE\s+[\w-]+\s+CURSOR\b", bare, re.I):
        return FP, "No DECLARE ... CURSOR in this EXEC SQL block", ctx.ev(a, z)
    if re.search(r"\bFOR\s+(?:READ|FETCH)\s+ONLY\b|\bFOR\s+UPDATE\b|\bBROWSE\s+ACCESS\b", bare, re.I):
        return FP, "The cursor declares its access mode (FOR READ ONLY / FETCH ONLY / UPDATE / BROWSE ACCESS)", ctx.ev(a, z)
    return TP, "Cursor declared without FOR READ ONLY / FETCH ONLY / UPDATE / BROWSE ACCESS", ctx.ev(a, z)


# ---------------------------------------- registry --------------------------------------------
RULES = {}


def reg(ids, name, fn):
    for i in ids if isinstance(ids, (list, tuple)) else [ids]:
        RULES[str(i)] = (name, fn)


reg([1101000, 1101002], "Never use SQL queries with a cartesian product", chk_cartesian)
reg(1101008, "Avoid non-SARGable queries", chk_nonsargable)
reg(1101010, "Avoid NATURAL JOIN queries", chk_natural)
reg(1101012, "Avoid specifying column numbers instead of column names in ORDER BY clauses", chk_order_by_number)
reg(1101014, "Avoid queries using old style join convention instead of ANSI-Standard joins", chk_old_join)
reg(1101018, "Avoid using the GROUP BY clause", kw(r"\bGROUP\s+BY\b", "GROUP BY clause"))
reg(1101020, "Avoid using quoted identifiers", chk_quoted_ident)
reg(1101022, "Avoid Tables without Primary Key (SQL)", make_table_check("pk"))
reg(1101024, "Avoid using dynamic SQL in SQL Artifacts", kw(DYN, "dynamic SQL"))
reg(1101026, "Always define column names when inserting values", chk_insert_columns)
reg(1101028, "Use MINUS or EXCEPT operator instead of NOT EXISTS and NOT IN subqueries", chk_not_in)
reg(1101032, "Avoid EXISTS and NOT EXISTS independent clauses (SQL)", chk_independent_exists)
reg(1101034, "Avoid using DISTINCT in SQL SELECT statements", chk_distinct)
reg(1101036, "Use ANSI standard operators in SQL WHERE clauses", chk_ansi_ops)
reg(1101038, "Avoid OR conditions testing equality on the same identifier in SQL WHERE clauses", chk_or_same_col)
reg(1101040, "Avoid empty catch blocks (SQL)", chk_empty_catch)
reg(1101052, "Use WHEN OTHERS in exception management (SQL)", chk_use_when_others)
reg(1101054, "Never use WHEN OTHERS THEN NULL", chk_when_others_null)
reg(1101058, "Avoid mixing ANSI and non-ANSI JOIN syntax in the same query", chk_mixed_join)
reg(1101060, "Avoid using LIKE conditions starting with a wildcard character", chk_like(True))
reg(1101062, "Avoid using multiple statements per line (SQL)", lambda ctx, n: (
    (TP, "Several statements on one line", ctx.ev(n)) if ctx.ok(n) and len(re.findall(r";", ctx.bare[n - 1])) > 1
    else (FP, "At most one statement ends on this line", ctx.ev(n)) if ctx.ok(n) else NOLINE))
reg(1101070, "Avoid explicit comparison with NULL", chk_null_cmp)
reg(1101072, "Avoid not aliased Tables", chk_alias(True))
reg(1101074, "Avoid Tables aliases ending with a numeric suffix", chk_alias(False))
reg(1101078, "Always prefer PRIVATE to PUBLIC synonym", kw(r"\bCREATE\s+(?:OR\s+REPLACE\s+)?PUBLIC\s+SYNONYM\b", "CREATE PUBLIC SYNONYM"))
reg(1101084, "Avoid Cursors inside a loop (SQL)", make_loop(r"\bOPEN\s+[\w$#.]+|\bFETCH\b|\bDECLARE\s+[\w$#]+\s+CURSOR\b|\bCURSOR\s+[\w$#]+\s+IS\b", "cursor", ""))
reg(1101086, "Always use VARCHAR2 and NVARCHAR2 instead of CHAR, VARCHAR or NCHAR", kw(r"(?<![\w$#])(?:N?CHAR|VARCHAR)\s*\(", "CHAR/VARCHAR/NCHAR declaration"))
reg(1101088, "Avoid using LONG and LONG RAW datatypes", kw(r"(?<![\w$#])LONG(?:\s+RAW)?(?![\w$#])(?!\s*\()", "LONG / LONG RAW datatype"))
reg(1101090, "Avoid Tables without a clustered Index (SQL)", make_table_check("clustered"))
reg(1101096, "Avoid SQL injection in dynamic SQL for Oracle", chk_injection)
reg(1101102, "Avoid using LIKE conditions without wildcards", chk_like(False))
reg([1101104, 1101106], "Avoid (XXL) tables without primary key / unique key constraint / unique index", make_table_check("unique"))
reg(1101108, "Avoid Cobol SQL Cursors without FOR READ ONLY / FETCH ONLY / UPDATE / BROWSE ACCESS", chk_cobol_cursor)
reg(1101112, "Avoid LOCK TABLE statements in SQL code for COBOL Programs", kw(r"\bLOCK\s+TABLE\b", "LOCK TABLE statement"))
reg(1101114, 'Avoid "SELECT *" queries (SQL)', chk_select_star)
reg(1101116, "Avoid using SQL queries inside a loop (SQL)", make_loop(r"^\s*(?:SELECT|INSERT|UPDATE|DELETE|MERGE)\b", "SQL statement", ""))

MANUAL = {
    "needs index / table-size metadata": [1101004, 1101006, 1101066, 1101118],
    "naming convention (depends on your convention configuration)": [1101042, 1101044, 1101046, 1101048, 1101050],
    "metric / threshold (parameters, columns, tables, SELECT complexity)": [1101016, 1101030, 1101056, 1101098],
    "object graph (triggers, synonyms) needs the whole schema": [1101064, 1101068, 1101080, 1101082],
    "procedure-level semantics (error management, status value, transactions)": [1101092, 1101094, 1101100],
    "needs table column metadata to resolve unqualified columns": [1101076],
}
MANUAL_BY_ID = {str(i): c for c, ids in MANUAL.items() for i in ids}
