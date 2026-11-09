"""
ABAP checkers for CAST ABAP quality rules (technology TG001).

Each checker: chk(ctx, line_no) -> (verdict, reason, evidence)
  verdict   TRUE_POSITIVE | FALSE_POSITIVE | REVIEW
  reason    human-readable justification
  evidence  the ABAP statement(s) the verdict is based on

Checkers only see ONE source file (no call graph, no data dictionary), so:
  * a FALSE_POSITIVE is only returned when the source itself proves it;
  * when the answer depends on information outside the file the verdict is REVIEW
    (or TRUE_POSITIVE with the limitation stated in the reason).
"""
import re
from bisect import bisect_right
from collections import namedtuple

TP, FP, RV = "TRUE_POSITIVE", "FALSE_POSITIVE", "REVIEW"
NOSTMT = (RV, "No statement at the reported line (the source may differ from the analyzed version)", "")
S = namedtuple("S", "first last text up")
Span = namedtuple("Span", "kind start end")

SEL = re.compile(r"^SELECT(?![\w-])")
NON_LOOP = re.compile(
    r"\bSELECT\s+SINGLE\b|\b(INTO|APPENDING)\s+(CORRESPONDING FIELDS OF\s+)?TABLE\b"
    r"|(\bSELECT\s+(DISTINCT\s+)?|\bFIELDS\s+)(COUNT|SUM|AVG|MAX|MIN)\s*\((?!.*\bGROUP BY\b)")
LOOP_OPEN = re.compile(r"^(LOOP|DO|WHILE)(?![\w-])")
LOOP_CLOSE = re.compile(r"^END(LOOP|DO|WHILE|SELECT)(?![\w-])")
PROC_START = re.compile(
    r"^(FORM|METHOD|FUNCTION|MODULE|START-OF-SELECTION|INITIALIZATION|END-OF-SELECTION|"
    r"AT SELECTION-SCREEN|AT LINE-SELECTION|AT USER-COMMAND|TOP-OF-PAGE|LOAD-OF-PROGRAM)(?![\w-])")
PROC_END = re.compile(r"^END(FORM|METHOD|FUNCTION|MODULE)(?![\w-])")
DECL = re.compile(r"^(DATA|STATICS|CLASS-DATA|TYPES|FIELD-SYMBOLS)(?![\w])")


def strip_comment(line):
    if line.startswith("*"):
        return ""
    out, quote = [], None
    for ch in line:
        if quote:
            out.append(ch)
            if ch == quote:
                quote = None
        elif ch in "'`|":
            quote = ch
            out.append(ch)
        elif ch == '"':
            break
        else:
            out.append(ch)
    return "".join(out)


def parse(lines):
    """ABAP statements: end at '.' outside literals. Chained ':' statements are kept as one."""
    out, buf, first = [], [], None
    for i, line in enumerate(lines):
        code = strip_comment(line.rstrip("\r\n"))
        quote, cur = None, []
        for k, ch in enumerate(code):
            if quote:
                cur.append(ch)
                if ch == quote:
                    quote = None
            elif ch in "'`|":
                quote = ch
                cur.append(ch)
            elif ch == "." and (k + 1 == len(code) or code[k + 1] in " \t"):
                buf.append("".join(cur))
                cur = []
                text = " ".join(" ".join(buf).split())
                if text:
                    out.append(S(first or i + 1, i + 1, text, text.upper()))
                buf, first = [], None
            else:
                cur.append(ch)
        rest = "".join(cur).strip()
        if rest:
            first = first or i + 1
            buf.append(rest)
    return out


class Ctx:
    """Parsed view of one ABAP source file."""

    def __init__(self, lines):
        self.lines = lines
        self.stmts = parse(lines)
        self._starts = [s.first for s in self.stmts]
        self._build()

    def _build(self):
        st = self.stmts
        self.sel_end = {}          # loop-SELECT index -> ENDSELECT index
        stack = []
        for i, s in enumerate(st):
            u = s.up
            if SEL.match(u) and ("PACKAGE SIZE" in u or not NON_LOOP.search(u)):
                stack.append(i)
            elif u.startswith("ENDSELECT") and stack:
                self.sel_end[stack.pop()] = i
            elif PROC_END.match(u):
                stack.clear()
        self.spans, stack = [], []
        for i, s in enumerate(st):
            u = s.up
            m = LOOP_OPEN.match(u)
            if m:
                stack.append((m.group(1), i))
            elif i in self.sel_end:
                stack.append(("SELECT", i))
            elif LOOP_CLOSE.match(u) and stack:
                kind, a = stack.pop()
                self.spans.append(Span(kind, a, i))
            elif PROC_END.match(u):
                stack.clear()

    # ---- navigation -------------------------------------------------------
    def stmt_at(self, n):
        k = bisect_right(self._starts, n) - 1
        if k >= 0 and self.stmts[k].last >= n:
            return k
        if k + 1 < len(self.stmts) and self.stmts[k + 1].first - n <= 2:
            return k + 1  # reported line is a comment/blank just before a statement
        return None

    def find_back(self, i, rx, back=3):
        for j in range(i, max(i - back, 0) - 1, -1):
            if rx.match(self.stmts[j].up):
                return j
        return None

    def proc_start(self, i):
        for j in range(i - 1, -1, -1):
            if PROC_START.match(self.stmts[j].up):
                return j
        return 0

    def block_end(self, i, open_rx, close_rx):
        depth = 0
        for j in range(i, len(self.stmts)):
            u = self.stmts[j].up
            if open_rx.match(u):
                depth += 1
            elif close_rx.match(u):
                depth -= 1
                if depth == 0:
                    return j
        return None

    def innermost_loop(self, k):
        c = [s for s in self.spans if s.start < k < s.end]
        return max(c, key=lambda s: s.start) if c else None

    def in_try(self, i):
        stack = []
        for j in range(self.proc_start(i), i):
            u = self.stmts[j].up
            if re.match(r"^TRY(?![\w-])", u):
                stack.append(False)
            elif re.match(r"^(CATCH|CLEANUP)(?![\w-])", u) and stack:
                stack[-1] = True
            elif re.match(r"^ENDTRY(?![\w-])", u) and stack:
                stack.pop()
        return any(not in_catch for in_catch in stack)

    def declared_kind(self, name):
        pat = re.compile(r"(?<![\w-])" + re.escape(name) + r"(?!\w)[^,]*?\b(SORTED|HASHED|STANDARD)\s+TABLE\b")
        for s in self.stmts:
            if DECL.match(s.up):
                m = pat.search(s.up)
                if m:
                    return m.group(1)
        return None

    def ev(self, i, j=None):
        j = i if j is None else j
        seg = self.stmts[i:j + 1]
        seg = seg if len(seg) <= 6 else seg[:4] + seg[-1:]
        return " | ".join(s.text for s in seg)[:400]


def anchor(ctx, n, rx, back=3):
    i = ctx.stmt_at(n)
    if i is None:
        return None, None
    return i, ctx.find_back(i, rx, back)


def expected(ctx, i, what):
    return RV, f"Expected {what} at/near the reported line; found a different statement (source may differ from the analyzed version)", ctx.ev(i)


# =========================== simple keyword checkers ==========================
def keyword(rx, label, start=None):
    rx = re.compile(rx)
    st = re.compile(start) if start else None

    def chk(ctx, n):
        i = ctx.stmt_at(n)
        if i is None:
            return NOSTMT
        s = ctx.stmts[i]
        if (st is None or st.match(s.up)) and rx.search(s.up):
            return TP, f"{label} found at line {s.first}", s.text
        return FP, (f"No {label} in the statement at line {n}: it is commented out, inside a literal, "
                    f"or a different statement"), s.text
    return chk


SQL_START = r"^(SELECT(?![\w-])|UPDATE|DELETE|INSERT|MODIFY|OPEN CURSOR)"
DYN = r"(?<![\w])\((?!\s)[A-Z_/<][\w\-<>/~\[\]]*(?<!\s)\)"


# ============================ SELECT ... ENDSELECT =============================
def target_select(ctx, n):
    i = ctx.stmt_at(n)
    if i is None:
        return None, None
    if SEL.match(ctx.stmts[i].up):
        return i, i
    sp = ctx.innermost_loop(i)
    if sp and sp.kind == "SELECT":
        return i, sp.start
    return i, ctx.find_back(i, SEL, 5)


def chk_select_endselect(ctx, n):                                   # 7544, 7666
    i, j = target_select(ctx, n)
    if i is None:
        return NOSTMT
    if j is None:
        return expected(ctx, i, "a SELECT statement")
    end = ctx.sel_end.get(j)
    if end is None:
        return (FP, "Not a loop: the SELECT is SELECT SINGLE / INTO TABLE / an aggregate, or has no matching "
                    "ENDSELECT, so it does not fetch row by row", ctx.ev(j))
    return TP, (f"SELECT at line {ctx.stmts[j].first} is closed by ENDSELECT at line {ctx.stmts[end].first}: "
                f"row-by-row fetch loop"), ctx.ev(j, end)


def chk_empty_select(ctx, n):                                       # 8126
    i, j = target_select(ctx, n)
    if i is None:
        return NOSTMT
    if j is None:
        return expected(ctx, i, "a SELECT statement")
    end = ctx.sel_end.get(j)
    if end is None:
        return FP, "No ENDSELECT closes this SELECT (not a loop), so there is no loop to be empty", ctx.ev(j)
    if end == j + 1:
        return TP, f"The loop from line {ctx.stmts[j].first} to ENDSELECT contains no statement", ctx.ev(j, end)
    return FP, (f"The loop body is not empty: {end - j - 1} statement(s), first at line {ctx.stmts[j + 1].first} "
                f"({ctx.stmts[j + 1].text[:60]})"), ctx.ev(j, end)


def chk_leave_in_select(ctx, n):                                    # 8132
    i, j = target_select(ctx, n)
    if i is None:
        return NOSTMT
    if j is None:
        return expected(ctx, i, "a SELECT loop")
    end = ctx.sel_end.get(j)
    if end is None:
        return FP, "No ENDSELECT closes this SELECT, so it is not a SELECT loop", ctx.ev(j)
    direct, nested = [], []
    for k in range(j + 1, end):
        m = re.match(r"^(CHECK|EXIT|RETURN)(?![\w-])", ctx.stmts[k].up)
        if m:
            kw = m.group(1)
            sp = ctx.innermost_loop(k)
            (direct if kw == "RETURN" or (sp and sp.start == j) else nested).append(f"{kw} at line {ctx.stmts[k].first}")
    if direct:
        return TP, "Leaves the SELECT loop prematurely: " + ", ".join(direct), ctx.ev(j, end)
    if nested:
        return (FP, ", ".join(nested) + " only leave(s) an inner loop nested in the SELECT, not the SELECT loop itself",
                ctx.ev(j, end))
    return FP, f"No CHECK, EXIT or RETURN between SELECT (line {ctx.stmts[j].first}) and ENDSELECT", ctx.ev(j, end)


def chk_nested_select(ctx, n):                                      # 7532
    return _nested(ctx, n, {"SELECT"}, "SELECT ... ENDSELECT")


def chk_nested_loops(ctx, n):                                       # 7880
    return _nested(ctx, n, {"LOOP", "DO", "WHILE"}, "LOOP/DO/WHILE")


def _nested(ctx, n, kinds, label):
    i = ctx.stmt_at(n)
    if i is None:
        return NOSTMT
    own = [s for s in ctx.spans if s.start == i and s.kind in kinds]
    if own:
        sp = own[0]
    else:
        c = [s for s in ctx.spans if s.start < i < s.end and s.kind in kinds]
        sp = max(c, key=lambda s: s.start) if c else None
    if sp is None:
        return expected(ctx, i, f"a {label} loop")
    anc = [s for s in ctx.spans if s.kind in kinds and s.start < sp.start and s.end > sp.end]
    desc = [s for s in ctx.spans if s.kind in kinds and s.start > sp.start and s.end < sp.end]
    if anc or desc:
        parts = []
        if anc:
            parts.append(f"enclosed by the {anc[-1].kind} loop at line {ctx.stmts[anc[-1].start].first}")
        if desc:
            parts.append(f"contains the {desc[0].kind} loop at line {ctx.stmts[desc[0].start].first}")
        return TP, f"Nested {label} loops: " + " and ".join(parts), ctx.ev(min([sp.start] + [a.start for a in anc]), sp.end)
    return FP, (f"No other {label} loop encloses or is enclosed by the loop at line {ctx.stmts[sp.start].first} "
                f"(loops reached through calls are not analysed)"), ctx.ev(sp.start, sp.end)


# ================================ SY-SUBRC checks ==============================
SUBRC_ANY = re.compile(r"SY-SUBRC|SYST-SUBRC|\bIS\s+(NOT\s+)?(INITIAL|ASSIGNED|BOUND)\b|\bLINE_EXISTS\b|\bSQLCODE\b")
SUBRC_ONLY = re.compile(r"SY-SUBRC|SYST-SUBRC")


def make_subrc(start_rx, label, strict=False):
    start, rx = re.compile(start_rx), (SUBRC_ONLY if strict else SUBRC_ANY)

    def chk(ctx, n):
        i, j = anchor(ctx, n, start)
        if i is None:
            return NOSTMT
        if j is None:
            return expected(ctx, i, label)
        end = ctx.sel_end.get(j, j)
        for k in range(end + 1, min(end + 7, len(ctx.stmts))):
            s = ctx.stmts[k]
            if PROC_END.match(s.up) or start.match(s.up):
                break           # procedure ends / another statement overwrites SY-SUBRC
            if rx.search(s.up):
                return FP, f"Return code is checked at line {s.first}: {s.text[:80]}", ctx.ev(j, k)
        return TP, (f"No SY-SUBRC check after the {label} at line {ctx.stmts[j].first} "
                    f"(next 6 statements inspected)"), ctx.ev(j, min(end + 2, len(ctx.stmts) - 1))
    return chk


# ================================ READ TABLE ===================================
def chk_read_binary(ctx, n):                                        # 7534
    i, j = anchor(ctx, n, re.compile(r"^READ TABLE(?![\w-])"))
    if i is None:
        return NOSTMT
    if j is None:
        return expected(ctx, i, "READ TABLE")
    up = ctx.stmts[j].up
    if "BINARY SEARCH" in up:
        return FP, "BINARY SEARCH is specified", ctx.ev(j)
    if re.search(r"\bINDEX\b", up):
        return FP, "Direct access by INDEX, no search involved", ctx.ev(j)
    m = re.match(r"^READ TABLE\s+(@?[\w<>\-/~\[\]]+)", up)
    name = m.group(1).lstrip("@").replace("[]", "") if m else None
    kind = ctx.declared_kind(name) if name else None
    if kind in ("SORTED", "HASHED"):
        return FP, f"Internal table {name} is declared as {kind} TABLE: key access is optimized by the runtime", ctx.ev(j)
    if "WITH TABLE KEY" in up:
        return RV, "WITH TABLE KEY is efficient only on SORTED/HASHED tables; the table type is not declared in this file", ctx.ev(j)
    return TP, "READ TABLE on a table not declared SORTED/HASHED, without BINARY SEARCH or INDEX", ctx.ev(j)


def chk_at_in_loop_where(ctx, n):                                   # 7536
    i, j = anchor(ctx, n, re.compile(r"^LOOP(?![\w-])"))
    if i is None:
        return NOSTMT
    if j is None:
        return expected(ctx, i, "LOOP AT")
    if not re.search(r"\bWHERE\b", ctx.stmts[j].up):
        return FP, "The LOOP AT has no WHERE clause", ctx.ev(j)
    end = ctx.block_end(j, re.compile(r"^LOOP(?![\w-])"), re.compile(r"^ENDLOOP(?![\w-])"))
    if end is None:
        return RV, "ENDLOOP not found", ctx.ev(j)
    depth = 0
    for k in range(j + 1, end):
        u = ctx.stmts[k].up
        if re.match(r"^LOOP(?![\w-])", u):
            depth += 1
        elif re.match(r"^ENDLOOP(?![\w-])", u):
            depth -= 1
        elif depth == 0 and re.match(r"^AT\s+(NEW|END OF|FIRST|LAST)(?![\w-])", u):
            return TP, f"AT event at line {ctx.stmts[k].first} used in a LOOP AT ... WHERE", ctx.ev(j, k)
    return FP, "No AT NEW/END OF/FIRST/LAST event inside this loop", ctx.ev(j, end)


def chk_loop_into(ctx, n):                                          # 7894
    i, j = anchor(ctx, n, re.compile(r"^LOOP AT(?![\w-])"))
    if i is None:
        return NOSTMT
    if j is None:
        return expected(ctx, i, "LOOP AT")
    up = ctx.stmts[j].up
    for rx, why in ((r"\bASSIGNING\b", "uses ASSIGNING"), (r"\bREFERENCE INTO\b", "uses REFERENCE INTO"),
                    (r"\bTRANSPORTING NO FIELDS\b", "uses TRANSPORTING NO FIELDS (no row copy)")):
        if re.search(rx, up):
            return FP, f"The loop {why}: no row is copied", ctx.ev(j)
    if re.search(r"\bINTO\b", up):
        return TP, "LOOP AT ... INTO copies each row; LOOP AT ... ASSIGNING avoids the copy", ctx.ev(j)
    return RV, "No INTO/ASSIGNING addition (header-line loop): decide manually", ctx.ev(j)


# ============================= FOR ALL ENTRIES / SQL ===========================
def chk_fae_initial(ctx, n):                                        # 7542, 7664
    i, j = anchor(ctx, n, SEL, 5)
    if i is None:
        return NOSTMT
    if j is None:
        return expected(ctx, i, "a SELECT statement")
    up = ctx.stmts[j].up
    m = re.search(r"FOR ALL ENTRIES IN\s+(@?[\w<>\-/~\[\]]+)", up)
    if not m:
        return FP, "The statement has no FOR ALL ENTRIES addition", ctx.ev(j)
    name = m.group(1).lstrip("@").replace("[]", "")
    nm = r"(?<![\w-])" + re.escape(name) + r"(\[\])?(?!\w)"
    ps = ctx.proc_start(j)
    for k in range(j - 1, max(ps, j - 25) - 1, -1):
        u = ctx.stmts[k].up
        if re.search(nm, u) and re.search(r"\bIS\s+(NOT\s+)?INITIAL\b|\bLINES\s*\(|\bLINE_EXISTS\b", u):
            return FP, f"Driver table {name} is checked for emptiness at line {ctx.stmts[k].first}: {ctx.stmts[k].text[:70]}", ctx.ev(k, j)
    return TP, (f"No emptiness check of driver table {name} in the 25 statements before the SELECT "
                f"(an empty table would select ALL rows)"), ctx.ev(j)


def chk_no_where(ctx, n):                                           # 7878, 8464
    i, j = anchor(ctx, n, SEL, 5)
    if i is None:
        return NOSTMT
    if j is None:
        return expected(ctx, i, "a SELECT statement")
    if re.search(r"\bWHERE\b", ctx.stmts[j].up):
        return FP, "The SELECT has a WHERE condition", ctx.ev(j)
    return TP, "SELECT without WHERE condition (whether the table is XXL is not verified locally)", ctx.ev(j)


def chk_select_star(ctx, n):                                        # 7530
    i = ctx.stmt_at(n)
    if i is None:
        return NOSTMT
    s = ctx.stmts[i]
    if SEL.match(s.up) and re.search(r"^SELECT\s+(SINGLE\s+)?(DISTINCT\s+)?\*|\bFIELDS\s+\*", s.up):
        return TP, "SELECT * / SELECT SINGLE * reads all columns", s.text
    if SEL.match(s.up):
        return FP, "The SELECT uses an explicit field list (or an aggregate), not *", s.text
    return FP, "Not a SELECT statement at this line (commented out or source differs)", s.text


def chk_order_by_no_sort(ctx, n):                                   # 8134
    i, j = anchor(ctx, n, SEL, 5)
    if i is None:
        return NOSTMT
    if j is None:
        return expected(ctx, i, "a SELECT statement")
    up = ctx.stmts[j].up
    m = re.search(r"\b(INTO|APPENDING)\s+(CORRESPONDING FIELDS OF\s+)?TABLE\s+(@?DATA\()?\s*(@?[\w<>\-/~\[\]]+)", up)
    if not m:
        return RV, "Not a SELECT ... INTO TABLE: ordering expectation cannot be derived", ctx.ev(j)
    if re.search(r"\bORDER BY\b", up):
        return FP, "The SELECT has an ORDER BY clause", ctx.ev(j)
    name = m.group(4).lstrip("@").replace("[]", "")
    kind = ctx.declared_kind(name)
    if kind in ("SORTED", "HASHED"):
        return FP, f"Target table {name} is a {kind} TABLE (ordered by the runtime)", ctx.ev(j)
    for k in range(j + 1, min(j + 16, len(ctx.stmts))):
        u = ctx.stmts[k].up
        if re.match(r"^SORT\s+" + re.escape(name) + r"(?![\w-])", u):
            return FP, f"{name} is sorted at line {ctx.stmts[k].first}: {ctx.stmts[k].text[:60]}", ctx.ev(j, k)
        if PROC_END.match(u):
            break
    return TP, f"No ORDER BY and no SORT {name} within the 15 statements following the SELECT", ctx.ev(j)


def chk_join_count(ctx, n):                                         # 7822
    i = ctx.stmt_at(n)
    if i is None:
        return NOSTMT
    s = ctx.stmts[i]
    if not SEL.match(s.up):
        return expected(ctx, i, "a SELECT statement")
    tables = 1 + len(re.findall(r"\bJOIN\b", s.up))
    if tables > 4:
        return TP, f"The query accesses {tables} tables (more than 4)", s.text
    return FP, f"The query accesses only {tables} table(s) in this statement", s.text


def chk_cartesian(ctx, n):                                          # 7820, 7660
    i = ctx.stmt_at(n)
    if i is None:
        return NOSTMT
    s = ctx.stmts[i]
    if not SEL.match(s.up):
        return expected(ctx, i, "a SELECT statement")
    joins, ons = len(re.findall(r"\bJOIN\b", s.up)), len(re.findall(r"\bON\b", s.up))
    if joins > ons:
        return TP, f"{joins} JOIN(s) but only {ons} ON condition(s): a join without condition is a cartesian product", s.text
    return FP, "Every JOIN has an ON condition", s.text


def chk_open_sql_in_loop(ctx, n):                                   # 7868
    i = ctx.stmt_at(n)
    if i is None:
        return NOSTMT
    s = ctx.stmts[i]
    u = s.up
    is_sql = SEL.match(u) or re.match(r"^(OPEN CURSOR|FETCH)", u) or re.match(
        r"^(INSERT INTO|DELETE FROM|UPDATE\s+\w+\s+(SET|FROM))", u)
    if not is_sql:
        if re.match(r"^(INSERT|DELETE|MODIFY|UPDATE)", u):
            is_sql = None
        else:
            return FP, "Not an Open SQL statement at this line", s.text
    loops = [sp for sp in ctx.spans if sp.start < i < sp.end]
    if is_sql is None:
        return RV, "INSERT/DELETE/MODIFY/UPDATE: cannot tell a database table from an internal table in this file", s.text
    if loops:
        lp = max(loops, key=lambda x: x.start)
        return TP, f"Open SQL inside the {lp.kind} loop starting at line {ctx.stmts[lp.start].first}", ctx.ev(lp.start, i)
    return RV, ("No enclosing loop in this procedure; the rule can also be triggered by a loop in a caller "
                "(call graph not available here)"), s.text


# ================================== blocks =====================================
def chk_empty_proc(ctx, n):                                         # 7512
    i, j = anchor(ctx, n, re.compile(r"^(FORM|FUNCTION|MODULE)(?![\w-])"))
    if i is None:
        return NOSTMT
    if j is None:
        return expected(ctx, i, "FORM / FUNCTION / MODULE")
    kw = ctx.stmts[j].up.split()[0]
    end = ctx.block_end(j, re.compile(r"^" + kw + r"(?![\w-])"), re.compile(r"^END" + kw + r"(?![\w-])"))
    if end is None:
        return RV, f"END{kw} not found", ctx.ev(j)
    if end == j + 1:
        return TP, f"{kw} at line {ctx.stmts[j].first} contains no statement", ctx.ev(j, end)
    return FP, f"{kw} contains {end - j - 1} statement(s), first at line {ctx.stmts[j + 1].first}", ctx.ev(j, end)


def chk_empty_file(ctx, n):                                         # 7514, 7516
    hdr = re.compile(r"^(REPORT|PROGRAM|FUNCTION-POOL|TYPE-POOL|CLASS-POOL|INTERFACE-POOL)(?![\w-])")
    body = [s for s in ctx.stmts if not hdr.match(s.up)]
    if not body:
        return TP, "The file contains no statement other than the program header", ""
    return FP, f"The file contains {len(body)} statement(s), first at line {body[0].first}", body[0].text


def chk_empty_if(ctx, n):                                           # 8106
    i, j = anchor(ctx, n, re.compile(r"^IF(?![\w-])"))
    if i is None:
        return NOSTMT
    if j is None:
        return expected(ctx, i, "IF")
    end = ctx.block_end(j, re.compile(r"^IF(?![\w-])"), re.compile(r"^ENDIF(?![\w-])"))
    if end is None:
        return RV, "ENDIF not found", ctx.ev(j)
    branches, cur, depth = [], 0, 0
    for k in range(j + 1, end):
        u = ctx.stmts[k].up
        if re.match(r"^IF(?![\w-])", u):
            depth += 1
        elif re.match(r"^ENDIF(?![\w-])", u):
            depth -= 1
        if depth == 0 and re.match(r"^(ELSEIF|ELSE)(?![\w-])", u):
            branches.append(cur)
            cur = 0
        else:
            cur += 1
    branches.append(cur)
    empty = [b == 0 for b in branches]
    if all(empty):
        return TP, "Every branch of the IF is empty", ctx.ev(j, end)
    if empty[0] or any(empty):
        return RV, "Only some branches of the IF are empty", ctx.ev(j, end)
    return FP, "The IF block contains statements", ctx.ev(j, end)


def chk_case_others(ctx, n):                                        # 7518
    i = ctx.stmt_at(n)
    if i is None:
        return NOSTMT
    s = ctx.stmts[i]
    if re.search(r"\b(COND|SWITCH)\b", s.up) and not re.match(r"^CASE(?![\w-])", s.up):
        if re.search(r"\bELSE\b", s.up):
            return FP, "The COND/SWITCH expression has an ELSE branch", s.text
        return TP, "COND/SWITCH expression without ELSE branch", s.text
    j = ctx.find_back(i, re.compile(r"^CASE(?![\w-])"), 3)
    if j is None:
        return expected(ctx, i, "CASE")
    end = ctx.block_end(j, re.compile(r"^CASE(?![\w-])"), re.compile(r"^ENDCASE(?![\w-])"))
    if end is None:
        return RV, "ENDCASE not found", ctx.ev(j)
    depth = 0
    for k in range(j + 1, end):
        u = ctx.stmts[k].up
        if re.match(r"^CASE(?![\w-])", u):
            depth += 1
        elif re.match(r"^ENDCASE(?![\w-])", u):
            depth -= 1
        elif depth == 0 and re.match(r"^WHEN OTHERS(?![\w-])", u):
            return FP, f"WHEN OTHERS present at line {ctx.stmts[k].first}", ctx.ev(j, end)
    return TP, "CASE without WHEN OTHERS", ctx.ev(j, end)


def chk_empty_catch(ctx, n):                                        # 1104018, 1060020
    i, j = anchor(ctx, n, re.compile(r"^CATCH(?![\w-])"), 2)
    if i is None:
        return NOSTMT
    if j is None:
        return expected(ctx, i, "CATCH")
    depth, body = 0, []
    for k in range(j + 1, len(ctx.stmts)):
        u = ctx.stmts[k].up
        if re.match(r"^TRY(?![\w-])", u):
            depth += 1
        elif re.match(r"^ENDTRY(?![\w-])", u) and depth > 0:
            depth -= 1
        elif depth == 0 and re.match(r"^(CATCH|CLEANUP|ENDTRY)(?![\w-])", u):
            break
        body.append(k)
    if not body:
        return TP, f"CATCH block at line {ctx.stmts[j].first} contains no statement (exception silently swallowed)", ctx.ev(j)
    return FP, f"CATCH block handles the exception with {len(body)} statement(s), first at line {ctx.stmts[body[0]].first}: {ctx.stmts[body[0]].text[:70]}", ctx.ev(j, body[-1])


def chk_by_value(ctx, n):                                           # 7858
    i = ctx.stmt_at(n)
    if i is None:
        return NOSTMT
    s = ctx.stmts[i]
    if not re.search(r"\bVALUE\s*\(", s.up):
        return FP, "No parameter is passed by VALUE( ) in this statement", s.text
    before = re.split(r"\bRETURNING\b", s.up)[0]
    if re.search(r"\bVALUE\s*\(", before):
        return TP, "Parameter(s) passed by value (copy) instead of by reference", s.text
    return FP, "VALUE( ) is only used for RETURNING parameters, which must be passed by value", s.text


def chk_exit(ctx, n):                                               # 7672
    i = ctx.stmt_at(n)
    if i is None:
        return NOSTMT
    s = ctx.stmts[i]
    if not re.match(r"^EXIT(?![\w-])", s.up):
        return FP, "Not an EXIT statement at this line", s.text
    lp = ctx.innermost_loop(i)
    if lp:
        return FP, f"EXIT only leaves the {lp.kind} loop at line {ctx.stmts[lp.start].first}, not the include", s.text
    return TP, "EXIT outside any loop terminates the whole processing block (file kind not verified)", s.text


def chk_sy_uname(ctx, n):                                           # 7906
    i = ctx.stmt_at(n)
    if i is None:
        return NOSTMT
    s = ctx.stmts[i]
    if "SY-UNAME" not in s.up and "SYST-UNAME" not in s.up:
        return FP, "SY-UNAME does not appear in the statement at this line", s.text
    lit = (r"\b(SY|SYST)-UNAME\s*(=|EQ|<>|NE|CS|CP|NS|NP|IN)\s*['`]|['`][^'`]*['`]\s*(=|EQ|<>|NE)\s*(SY|SYST)-UNAME"
           r"|^CASE\s+(SY|SYST)-UNAME")
    if re.search(lit, s.up):
        return TP, "SY-UNAME compared to a hard-coded user name", s.text
    return RV, "SY-UNAME is used but not compared with a literal; check where the compared value comes from", s.text


def chk_random_seed(ctx, n):                                        # 8430
    i = ctx.stmt_at(n)
    if i is None:
        return NOSTMT
    s = ctx.stmts[i]
    if "CL_ABAP_RANDOM" not in s.up:
        return FP, "No CL_ABAP_RANDOM usage in this statement", s.text
    if re.search(r"\bSEED\s*=\s*\d+", s.up):
        return TP, "Hard-coded numeric seed", s.text
    if re.search(r"\bSEED\s*=", s.up):
        return FP, "The seed comes from an expression/variable, not a constant", s.text
    if re.search(r"CREATE\s*\(|NEW\s+CL_ABAP_RANDOM\w*\s*\(|=>\s*CREATE\b", s.up):
        return TP, "Random generator created without a seed", s.text
    return RV, "CL_ABAP_RANDOM used but creation/seed not visible in this statement", s.text


# ================================ authorization ================================
AUTH = re.compile(r"^AUTHORITY-CHECK(?![\w-])|\bAUTHORITY_CHECK\w*|\bAUTH_CHECK\w*|\bFILE_VALIDATE_NAME\b|\bAUTHORITY-CHECK\b")


def make_auth(trigger_rx, label, own_auth=None, ambiguous=False):
    trig = re.compile(trigger_rx)
    own = re.compile(own_auth) if own_auth else None

    def chk(ctx, n):
        i, j = anchor(ctx, n, trig, 2)
        if i is None:
            return NOSTMT
        if j is None:
            return FP, f"No {label} statement at/near the reported line (commented out or source differs)", ctx.ev(i)
        s = ctx.stmts[j]
        if own and own.search(s.up):
            return FP, "The statement itself performs the authorization check", s.text
        for k in range(j - 1, ctx.proc_start(j) - 1, -1):
            if AUTH.search(ctx.stmts[k].up):
                return FP, f"Authorization check at line {ctx.stmts[k].first} precedes it in the same procedure: {ctx.stmts[k].text[:70]}", ctx.ev(k, j)
        if ambiguous:
            return RV, "No authorization check earlier in the procedure, but the statement may target an internal table: confirm", s.text
        return TP, (f"No AUTHORITY-CHECK earlier in the same procedure before {label} "
                    f"(a check in a caller is not visible here)"), s.text
    return chk


def chk_modify_auth(ctx, n):                                        # 8578
    i = ctx.stmt_at(n)
    if i is None:
        return NOSTMT
    s = ctx.stmts[i]
    if not re.match(r"^MODIFY(?![\w-])", s.up):
        return FP, "Not a MODIFY statement at this line", s.text
    if re.match(r"^MODIFY\s+(SCREEN|LINE|CURRENT LINE)\b", s.up):
        return FP, "MODIFY SCREEN/LINE does not write to the database", s.text
    return make_auth(r"^MODIFY(?![\w-])", "MODIFY", ambiguous=True)(ctx, n)


def chk_commit_in_update(ctx, n):                                   # 8422
    i = ctx.stmt_at(n)
    if i is None:
        return NOSTMT
    s = ctx.stmts[i]
    if not re.match(r"^(COMMIT WORK|ROLLBACK WORK)", s.up):
        return FP, "Not a COMMIT WORK / ROLLBACK WORK at this line", s.text
    ps = ctx.proc_start(i)
    if re.match(r"^FORM\b.*\bON (COMMIT|ROLLBACK)\b", ctx.stmts[ps].up):
        return TP, "COMMIT/ROLLBACK inside a FORM called ON COMMIT/ROLLBACK (update work process)", ctx.ev(ps, i)
    return RV, "Cannot tell from the file whether this runs in an update task (function module update type, caller)", s.text


# =============================== metric / design ===============================
MANUAL = {
    "size / complexity / coupling metric (needs the metric value, not source text)": [
        7054, 7056, 7058, 7076, 7082, 7092, 7094, 7596, 7626, 7628, 7630, 7766, 7768, 7772, 7774, 7776, 7778,
        7792, 7796, 7798, 7802, 7842, 7944, 7934, 7586, 7810, 7828, 1101030],
    "documentation / comment ratio (threshold-based metric)": [
        7060, 7062, 7066, 7068, 7568, 7570, 7818, 7836, 7838, 7846, 1104010, 1104012, 1104014, 1104016],
    "naming convention (depends on your convention configuration)": [
        7050, 7072, 7074, 7088, 7598, 7602, 7786, 7848, 7852, 7854, 1104006],
    "unreferenced object (needs the whole application call graph)": [7540, 7830, 7832, 7860, 7908, 7912],
    "repeated table access in an include/program (needs cross-artifact analysis)": [
        7572, 7576, 7578, 7580, 7582, 7584],
    "needs data-dictionary info (XXL tables, indexes, types)": [7420, 7662, 7902, 7904, 7670],
    "CDS views / S4HANA (CDS source not handled)": [8566, 8568, 1104000, 1104002, 1104004, 1104008],
    "Web Dynpro / BAPI / semantic rule needing deeper analysis": [
        7850, 7888, 7890, 7892, 7864, 8114, 8584, 7624, 7680],
}
MANUAL_BY_ID = {str(i): cat for cat, ids in MANUAL.items() for i in ids}


def chk_manual(category):
    def chk(ctx, n):
        i = ctx.stmt_at(n)
        return RV, f"{category}: cannot be decided from the source text alone, review manually", (ctx.ev(i) if i is not None else "")
    return chk


# ================================== registry ===================================
RULES = {}


def reg(ids, name, fn):
    for rid in ids if isinstance(ids, (list, tuple)) else [ids]:
        RULES[str(rid)] = (name, fn)


reg(7538, "DEPRECATED: Avoid using SELECT ... INTO CORRESPONDING FIELDS OF",
    keyword(r"\b(INTO|APPENDING)\s+CORRESPONDING\s+FIELDS\s+OF\b", "INTO/APPENDING CORRESPONDING FIELDS OF", r"^SELECT(?![\w-])"))
reg(7544, "Avoid using SELECT ... ENDSELECT statement", chk_select_endselect)
reg(7666, "Avoid using SELECT ... ENDSELECT statement on XXL Tables", chk_select_endselect)
reg(8126, "Avoid using empty SELECT ... ENDSELECT loop", chk_empty_select)
reg(8132, "Avoid using CHECK, EXIT, or RETURN in SELECT ... ENDSELECT loops", chk_leave_in_select)
reg(7532, "Avoid nested SELECT ... ENDSELECT statements", chk_nested_select)
reg(7880, "Avoid nested loops", chk_nested_loops)
reg(7520, "Avoid unchecked return code (SY-SUBRC) after OPEN SQL or READ statement",
    make_subrc(r"^(READ TABLE|SELECT(?![\w-])|INSERT|UPDATE|DELETE|MODIFY)", "Open SQL / READ statement"))
reg(8012, "Avoid unchecked return code (SY-SUBRC) after opening and reading dataset",
    make_subrc(r"^(OPEN DATASET|READ DATASET)", "OPEN/READ DATASET statement"))
reg(8014, "Avoid unchecked return code (SY-SUBRC) after AUTHORITY-CHECK",
    make_subrc(r"^AUTHORITY-CHECK", "AUTHORITY-CHECK statement", strict=True))
reg(7534, "Avoid READ TABLE without BINARY SEARCH", chk_read_binary)
reg(7536, "Avoid using AT Events in combination of LOOP AT ... WHERE constructs", chk_at_in_loop_where)
reg(7894, "Avoid using LOOP INTO, use LOOP ASSIGNING instead", chk_loop_into)
reg([7542, 7664], "Avoid using FOR ALL ENTRIES IN without emptiness check", chk_fae_initial)
reg([7878, 8464], "Avoid Open SQL SELECT queries without WHERE condition", chk_no_where)
reg(7530, 'Avoid "SELECT *" or "SELECT SINGLE *" queries', chk_select_star)
reg(8134, "Avoid unsorted data after SELECT queries", chk_order_by_no_sort)
reg(7822, "Avoid Artifacts with queries on more than 4 Tables", chk_join_count)
reg([7820, 7660], "Never use SQL queries with a cartesian product", chk_cartesian)
reg(7868, "Avoid Open SQL queries in loops", chk_open_sql_in_loop)
reg(7512, "Avoid empty Functions, Forms and Modules", chk_empty_proc)
reg([7514, 7516], "Avoid empty Includes / Programs", chk_empty_file)
reg(8106, "Avoid empty IF-ENDIF blocks", chk_empty_if)
reg(7518, "Avoid missing WHEN OTHERS in CASE statements or ELSE in COND expressions", chk_case_others)
reg([1104018, 1060020], "Avoid empty catch blocks", chk_empty_catch)
reg(7858, "Avoid passing parameter by value", chk_by_value)
reg(7672, "Avoid using EXIT statement in Include", chk_exit)
reg(7906, "Avoid testing specific values for SY-UNAME", chk_sy_uname)
reg(8430, "Avoid using hard-coded seed or no seed at all for random values generation", chk_random_seed)
reg(8422, "Avoid Using COMMIT WORK or ROLLBACK WORK during update work process", chk_commit_in_update)
reg(8428, "Authorization check should be done before calling a transaction",
    make_auth(r"^(CALL|LEAVE TO) TRANSACTION(?![\w-])", "CALL TRANSACTION", own_auth=r"\bWITH AUTHORITY-CHECK\b"))
reg(8576, "Avoid using OPEN DATASET without Authorization Check", make_auth(r"^OPEN DATASET(?![\w-])", "OPEN DATASET"))
reg(8580, "Avoid using GENERATE SUBROUTINE POOL statement without Authorization Check",
    make_auth(r"^GENERATE SUBROUTINE POOL(?![\w-])", "GENERATE SUBROUTINE POOL"))
reg(8582, "Avoid Dynamic Function/Method call without Authorization Check",
    make_auth(r"^CALL FUNCTION\s+(?!['`])\S|^CALL METHOD\b.*(\(\w[\w\-<>]*\)\s*=>|->\(\w|=>\(\w)", "dynamic call"))
reg(8570, "Avoid Calling RFC Function Module without Authorization Check",
    make_auth(r"^CALL FUNCTION\b.*\bDESTINATION\b", "RFC call"))
reg(8578, "Avoid using MODIFY without Authorization Check", chk_modify_auth)

K = keyword
reg(7524, "Avoid using BREAK or BREAK-POINT statement", K(r"^BREAK(?![\w])", "BREAK / BREAK-POINT statement"))
reg(7528, "Never use the ON CHANGE OF statement", K(r"^ON CHANGE OF(?![\w-])", "ON CHANGE OF statement"))
reg(7592, 'Avoid using "ORDER BY" in SELECTS', K(r"\bORDER BY\b", "ORDER BY clause", r"^SELECT(?![\w-])"))
reg(7594, 'Avoid using "SELECT DISTINCT"', K(r"\bDISTINCT\b", "SELECT DISTINCT", r"^SELECT(?![\w-])"))
reg(7866, "Avoid SELECT ... BYPASSING BUFFER", K(r"\bBYPASSING BUFFER\b", "BYPASSING BUFFER addition"))
reg(7870, "Avoid using the NOT LIKE operator in WHERE clauses", K(r"\bNOT\s+LIKE\b", "NOT LIKE operator", SQL_START))
reg(7872, "Avoid using IS [NOT] NULL in WHERE condition", K(r"\bIS\s+(NOT\s+)?NULL\b", "IS [NOT] NULL", SQL_START))
reg([7874, 1101024], "Avoid using dynamic queries", K(DYN, "dynamic SQL token (...)", SQL_START))
reg(7876, "Avoid using SELECT ... FOR UPDATE", K(r"\bFOR UPDATE\b", "FOR UPDATE addition"))
reg(7882, "Avoid using Native SQL", K(r"^EXEC SQL(?![\w-])|\bCL_SQL_(STATEMENT|CONNECTION)\b", "Native SQL (EXEC SQL / ADBC)"))
reg(7886, "Avoid using SYSTEM-CALL", K(r"^SYSTEM-CALL(?![\w-])", "SYSTEM-CALL statement"))
reg([7806, 1101018], "Avoid Artifacts with Group By", K(r"\bGROUP BY\b", "GROUP BY clause", r"^SELECT(?![\w-])"))
reg(7808, "Avoid Artifacts with SQL statement including subqueries", K(r"\(\s*SELECT\b", "subquery", r"^SELECT(?![\w-])"))
reg(8116, "Avoid calling system function (CALL 'cfunc')", K(r"^CALL\s+['`]", "CALL 'cfunc' statement"))
reg(8118, "Avoid using the RFC_ABAP_INSTALL_AND_RUN function", K(r"RFC_ABAP_INSTALL_AND_RUN", "RFC_ABAP_INSTALL_AND_RUN call"))
reg(8124, "Do not use function module DB_EXISTS_INDEX (HANA)", K(r"DB_EXISTS_INDEX", "DB_EXISTS_INDEX call"))
reg(8130, "Avoid using database hints", K(r"%_HINTS\b", "%_HINTS database hint"))
reg(8412, '"CX_ROOT" should not be used in TRY .. CATCH.. ENDTRY block', K(r"^CATCH\b.*\bCX_ROOT\b", "CATCH of CX_ROOT"))
reg(8426, 'Avoid calling database commands directly via "C_DB_EXECUTE"/"C_DB_FUNCTION"', K(r"^CALL\s+['`]C_DB_(EXECUTE|FUNCTION)['`]", "CALL 'C_DB_...'"))
reg(8432, "Avoid Cross-Client Database Access (CLIENT SPECIFIED / USING CLIENT)", K(r"\b(CLIENT SPECIFIED|USING CLIENT)\b", "CLIENT SPECIFIED / USING CLIENT"))
reg(8546, "Avoid using ABAP command CALL 'SYSTEM'", K(r"^CALL\s+['`]SYSTEM['`]", "CALL 'SYSTEM'"))
reg(8548, "Avoid using ABAP command INSERT REPORT", K(r"^INSERT REPORT(?![\w-])", "INSERT REPORT"))
reg(8550, "Avoid using ABAP command GENERATE SUBROUTINE POOL", K(r"^GENERATE SUBROUTINE POOL(?![\w-])", "GENERATE SUBROUTINE POOL"))
reg(8552, "Avoid using ABAP command OPEN DATASET with the FILTER addition", K(r"\bFILTER\b", "FILTER addition", r"^OPEN DATASET(?![\w-])"))
reg(8572, "Avoid using SUBMIT statement with another user permission", K(r"\bUSER\b", "USER addition", r"^SUBMIT(?![\w-])"))
reg(8574, "Avoid using statement CALL TRANSACTION through variable", K(r"^CALL TRANSACTION\s+(?!['`])\S", "CALL TRANSACTION with a variable"))
reg(8586, "Avoid insecure dynamic call of a function module through variable", K(r"^CALL FUNCTION\s+(?!['`])\S", "CALL FUNCTION with a variable"))


def chk_call_error_handling(kind):
    start = re.compile(r"^CALL " + kind + r"(?![\w-])")

    def chk(ctx, n):
        i, j = anchor(ctx, n, start, 2)
        if i is None:
            return NOSTMT
        if j is None:
            return RV, f"No CALL {kind} statement at the reported line (functional call syntax is not analysed)", ctx.ev(i)
        s = ctx.stmts[j]
        if re.search(r"\bEXCEPTIONS\b", s.up):
            return FP, "The call has an EXCEPTIONS addition (classic exception handling)", s.text
        if ctx.in_try(j):
            return FP, "The call is inside the protected part of a TRY block", s.text
        return TP, "No EXCEPTIONS addition and not inside a TRY block (SY-SUBRC/exceptions are not handled)", s.text
    return chk


reg(8120, "Avoid using CALL FUNCTION without error handling", chk_call_error_handling("FUNCTION"))
reg(8122, "Avoid using CALL METHOD without error handling", chk_call_error_handling("METHOD"))

MANUAL_IDS = sorted(MANUAL_BY_ID, key=int)
