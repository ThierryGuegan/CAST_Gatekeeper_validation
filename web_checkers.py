"""
Web checkers for CAST technology group TG004 (HTML5/JavaScript, TypeScript, Node.js, jQuery,
AngularJS/Angular, React, Vue, CSS). The SAPUI5 rules 10206xx live in sapui5_checkers.py.

Same contract: chk(ctx, line_no) -> (verdict, reason, evidence); ctx is sapui5_checkers.JsCtx.
CAST publishes only rule names, so semantics are inferred from the names. Anything that needs
library versions, the call graph, metrics or attack-pattern combinations is REVIEW-only.
"""
import re

from sapui5_checkers import JsCtx, NOLINE, TP, FP, RV, first_arg, keyword, _where, _no_match  # noqa: F401

LOOPS = {"for", "while", "do", "iterfn"}
NEVER = r"(?!x)x"


def lit(rx, label):
    """Pattern that needs string-literal content (matched on the comment-free text)."""
    return keyword(NEVER, label, rx)


# --------------------------------- block structure (JS/TS) ---------------------------------------
def _classify(h):
    h = h.strip()
    if re.search(r"\.(?:forEach|map|filter|reduce|some|every|flatMap)\s*\(\s*(?:async\s*)?"
                 r"(?:function\b[^(]*\([^)]*\)|\([^)]*\)\s*=>|[\w$]+\s*=>)\s*$", h):
        return "iterfn"
    for kind, rx in (("for", r"^for\b"), ("while", r"^while\b"), ("do", r"^do$"), ("switch", r"^switch\b"),
                     ("try", r"^try$"), ("catch", r"^catch\b"), ("finally", r"^finally$"), ("else", r"^else\b"),
                     ("if", r"^if\b"), ("class", r"(?:^|\s)class\b")):
        if re.search(rx, h):
            return kind
    if re.search(r"\bfunction\b|=>\s*$|^(?:async\s+|static\s+|get\s+|set\s+)*[\w$]+\s*\([^)]*\)\s*(?::\s*[\w<>\[\]|. ]+)?$", h):
        return "function"
    return "obj"


def block_map(ctx):
    if getattr(ctx, "_bm", None) is None:
        stack, header, pd, out = [], "", 0, []

        def feed(ch):
            nonlocal header, pd
            if ch == "{":
                stack.append(_classify(header)); header = ""
            elif ch == "}":
                if stack:
                    stack.pop()
                header = ""
            elif ch == ";" and pd <= 0:
                header = ""
            else:
                pd += (ch == "(") - (ch == ")")
                pd = max(pd, 0)
                header += ch
        for line in ctx.bare:
            i = 0
            while i < len(line) and line[i] in " \t}":
                if line[i] == "}":
                    feed("}")
                i += 1
            out.append(tuple(stack))
            for ch in line[i:]:
                feed(ch)
            header += " "
        ctx._bm = out
    return ctx._bm


def stack_at(ctx, n):
    bm = block_map(ctx)
    return list(bm[n - 1]) if 1 <= n <= len(bm) else []


def enclosing_loop(ctx, n, kinds=LOOPS):
    for k in reversed(stack_at(ctx, n)):
        if k in kinds:
            return k
        if k == "function":
            return None
    return None


def protected_by_try(ctx, n):
    for k in reversed(stack_at(ctx, n)):
        if k == "try":
            return True
        if k == "function":
            return False
    return False


def body_after(ctx, n, header_rx, window=80):
    """Text between the braces of the first block whose header matches header_rx (rx must end before '{')."""
    text = "\n".join(ctx.bare[n - 1:n - 1 + window])
    m = re.search(header_rx, text)
    if not m:
        return None, None, None
    k = text.find("{", m.end() - 1 if text[m.end() - 1:m.end()] == "{" else m.end())
    if k < 0:
        return None, None, m
    depth = 0
    for j in range(k, len(text)):
        depth += (text[j] == "{") - (text[j] == "}")
        if depth == 0:
            return text[k + 1:j], text[:j].count("\n") + n, m
    return None, None, m


def _ev(ctx, n, z=None):
    return ctx.ev(n, z or n)


# ----------------------------------- structural checkers -----------------------------------------
def chk_empty_catch(ctx, n):                                         # 1020176
    if not ctx.ok(n):
        return NOLINE
    body, end, m = body_after(ctx, n, r"\bcatch\b\s*(?:\([^)]*\))?\s*\{")
    if m is None:
        return FP, "No catch block at the reported line (source may differ from the analyzed version)", _ev(ctx, n)
    if body is None:
        return RV, "Could not match the catch block braces", _ev(ctx, n)
    if body.strip():
        return FP, "The catch block handles the error with statements", _ev(ctx, n, end)
    raw = " ".join(ctx.raw[n - 1:end])
    return TP, ("The catch block is empty (it only contains comments)" if re.search(r"//|/\*", raw)
                else "The catch block is empty: the error is swallowed"), _ev(ctx, n, end)


def chk_empty_finally(ctx, n):                                       # 1020178
    if not ctx.ok(n):
        return NOLINE
    body, end, m = body_after(ctx, n, r"\bfinally\b\s*\{")
    if m is None:
        return FP, "No finally block at the reported line", _ev(ctx, n)
    if body is not None and not body.strip():
        return TP, "The finally block is empty", _ev(ctx, n, end)
    return FP, "The finally block contains statements", _ev(ctx, n, end)


def chk_empty_did_catch(ctx, n):                                     # 1020452, 1020858
    if not ctx.ok(n):
        return NOLINE
    body, end, m = body_after(ctx, n, r"\bcomponentDidCatch\b\s*\([^)]*\)\s*(?::\s*\w+\s*)?\{")
    if m is None:
        return FP, "No componentDidCatch method at the reported line", _ev(ctx, n)
    if body is not None and not body.strip():
        return TP, "componentDidCatch is empty: React errors are swallowed", _ev(ctx, n, end)
    return FP, "componentDidCatch handles the error", _ev(ctx, n, end)


def chk_switch_default(ctx, n):                                      # 1020180
    if not ctx.ok(n):
        return NOLINE
    body, end, m = body_after(ctx, n, r"\bswitch\b[^{]*\{")
    if m is None:
        return FP, "No switch statement at the reported line", _ev(ctx, n)
    if body is None:
        return RV, "Could not match the switch braces", _ev(ctx, n)
    depth = 0
    for k, ch in enumerate(body):
        depth += (ch == "{") - (ch == "}")
        if depth == 0 and re.match(r"\bdefault\s*:", body[k:]):
            return FP, "The switch has a default clause", _ev(ctx, n, end)
    return TP, "switch statement without a default clause", _ev(ctx, n, end)


def chk_break_in_for(ctx, n):                                        # 1020182
    if not ctx.ok(n):
        return NOLINE
    if not re.search(r"\bbreak\b", ctx.bare[n - 1]):
        return FP, "No break statement at the reported line", _ev(ctx, n)
    if re.search(r"\bbreak\s+[A-Za-z_$]", ctx.bare[n - 1]):
        return RV, "Labeled break: the target loop must be checked manually", _ev(ctx, n)
    for k in reversed(stack_at(ctx, n)):
        if k == "for":
            return TP, "break inside a for loop", _ev(ctx, n)
        if k in ("switch", "while", "do", "iterfn", "function"):
            why = {"switch": "break leaves a switch, not a for loop"}.get(k, f"the break is in a {k}, not a for loop")
            return FP, why, _ev(ctx, n)
    return RV, "break outside any recognisable loop/switch", _ev(ctx, n)


def chk_function_in_loop(ctx, n):                                    # 1020038
    if not ctx.ok(n):
        return NOLINE
    _, bare, a, z = ctx.span(n)
    if not re.search(r"\bfunction\b|=>", bare):
        return FP, "No function definition at the reported line", ctx.ev(a, z)
    lp = enclosing_loop(ctx, n, {"for", "while", "do"})
    if lp:
        return TP, f"A function is created on every iteration of the enclosing {lp} loop", ctx.ev(a, z)
    return FP, "The function is not defined inside a for/while/do loop", ctx.ev(a, z)


def chk_call_in_loop_condition(ctx, n):                              # 1020006
    if not ctx.ok(n):
        return NOLINE
    text = " ".join(ctx.bare[n - 1:n + 2])
    m = re.search(r"\bfor\s*\(", text)
    if not m:
        return FP, "No for loop at the reported line", _ev(ctx, n)
    depth, k = 0, m.end() - 1
    for j in range(k, len(text)):
        depth += (text[j] == "(") - (text[j] == ")")
        if depth == 0:
            header = text[k + 1:j]
            break
    else:
        return RV, "for header not closed on the following lines", _ev(ctx, n)
    parts = header.split(";")
    if len(parts) >= 3 and re.search(r"[\w$\]]\s*\(", parts[1]):
        return TP, "The loop condition calls a function: it is re-evaluated on every iteration", _ev(ctx, n)
    return FP, "The loop condition contains no function call", _ev(ctx, n)


def make_ws_loop(pattern, label):
    rx = re.compile(pattern)

    def chk(ctx, n):
        if not ctx.ok(n):
            return NOLINE
        _, bare, a, z = ctx.span(n)
        if not rx.search(bare):
            return FP, f"No {label} call at the reported line", ctx.ev(a, z)
        lp = enclosing_loop(ctx, n)
        if lp:
            return TP, f"{label} call inside a {lp} loop: one request per iteration", ctx.ev(a, z)
        return RV, f"{label} call found but not inside a loop in this file; the loop may be in a caller", ctx.ev(a, z)
    return chk


def chk_string_concat_loop(ctx, n):                                  # 1020828
    if not ctx.ok(n):
        return NOLINE
    code = ctx.code[n - 1]
    if not re.search(r"[\w$.\]]\s*\+=\s*[\"'`]|[\w$.\]]\s*=\s*[\w$.\]]+\s*\+\s*[\"'`]|\+=\s*[\w$.]+\s*\+\s*[\"'`]", code):
        return FP, "No string concatenation assignment at the reported line", _ev(ctx, n)
    lp = enclosing_loop(ctx, n)
    if lp:
        return TP, f"String built by concatenation inside a {lp} loop (use an array join / template)", _ev(ctx, n)
    return FP, "The concatenation is not inside a loop", _ev(ctx, n)


def make_json_try(label="JSON.parse / JSON.stringify"):
    def chk(ctx, n):
        if not ctx.ok(n):
            return NOLINE
        _, bare, a, z = ctx.span(n)
        if not re.search(r"\bJSON\s*\.\s*(?:parse|stringify)\s*\(", bare):
            return FP, f"No {label} call at the reported line", ctx.ev(a, z)
        if protected_by_try(ctx, n):
            return FP, f"The {label} call is inside a try block", ctx.ev(a, z)
        return TP, f"{label} can throw but is not inside a try/catch", ctx.ev(a, z)
    return chk


def chk_sync_fs(ctx, n):                                             # 1020780
    if not ctx.ok(n):
        return NOLINE
    _, bare, a, z = ctx.span(n)
    m = re.search(r"\bfs\s*\.\s*(\w+Sync)\s*\(", bare)
    if not m:
        return FP, "No synchronous fs call at the reported line", ctx.ev(a, z)
    if protected_by_try(ctx, n):
        return FP, f"fs.{m.group(1)} is inside a try block", ctx.ev(a, z)
    return TP, f"fs.{m.group(1)} throws on failure and is not inside a try/catch", ctx.ev(a, z)


def chk_error_not_thrown(ctx, n):                                    # 1020802
    if not ctx.ok(n):
        return NOLINE
    _, bare, a, z = ctx.span(n)
    m = re.search(r"\bnew\s+\w*Error\s*\(", bare)
    if not m:
        return FP, "No Error object creation at the reported line", ctx.ev(a, z)
    pre = bare[:m.start()].strip()
    if pre == "" or pre.endswith((";", "{", "}")):
        return TP, "An Error object is created but never thrown, returned or passed on", ctx.ev(a, z)
    return FP, "The Error object is thrown, returned, assigned or passed to a callback", ctx.ev(a, z)


def make_jump_in_finally(words):
    rx = re.compile(r"\b(" + "|".join(words) + r")\b")

    def chk(ctx, n):
        if not ctx.ok(n):
            return NOLINE
        m = rx.search(ctx.bare[n - 1])
        if not m:
            return FP, f"No {'/'.join(words)} statement at the reported line", _ev(ctx, n)
        kw = m.group(1)
        for k in reversed(stack_at(ctx, n)):
            if k == "finally":
                return TP, f"{kw} inside a finally block overrides the pending result/exception", _ev(ctx, n)
            if k == "function":
                break
            if kw in ("break", "continue") and k in ("for", "while", "do", "switch", "iterfn"):
                return FP, f"{kw} only leaves a loop/switch nested inside the finally block", _ev(ctx, n)
        return FP, f"The {kw} is not inside a finally block", _ev(ctx, n)
    return chk


def chk_super_twice(ctx, n):                                         # 1020812
    if not ctx.ok(n):
        return NOLINE
    body, end, m = body_after(ctx, n, r"\bconstructor\b\s*\([^)]*\)\s*\{")
    if m is None:
        return FP, "No constructor at the reported line", _ev(ctx, n)
    cnt = len(re.findall(r"\bsuper\s*\(", body or ""))
    if cnt >= 2:
        return TP, f"super() is called {cnt} times in the constructor", _ev(ctx, n, end)
    return FP, f"super() is called {cnt} time(s) in the constructor", _ev(ctx, n, end)


def chk_node_callback_err(ctx, n):                                   # 1020700, 1020874
    if not ctx.ok(n):
        return NOLINE
    text = "\n".join(ctx.bare[n - 1:n + 60])
    m = re.search(r"(?:function\s*[\w$]*\s*\(\s*|\(\s*|(?<![\w$.]))(err|error|e|er)\s*(?:,[^)]*)?\)?\s*(?:=>\s*)?\{", text)
    if not m or not re.search(r"function|=>", text[:m.end()]):
        return FP, "No error-first callback at the reported line", _ev(ctx, n)
    name = m.group(1)
    k = text.find("{", m.end() - 1)
    depth = 0
    for j in range(k, len(text)):
        depth += (text[j] == "{") - (text[j] == "}")
        if depth == 0:
            body = text[k + 1:j]
            break
    else:
        return RV, "Could not match the callback braces", _ev(ctx, n)
    if re.search(r"(?<![\w$.])" + re.escape(name) + r"(?![\w$])", body):
        return FP, f"The callback uses its '{name}' argument", _ev(ctx, n)
    return TP, f"The error-first callback never looks at '{name}': failures are ignored", _ev(ctx, n)


def make_subscribe_error(ctx, n):                                    # 1020822
    if not ctx.ok(n):
        return NOLINE
    code, bare, a, z = ctx.span(n, 15)
    m = re.search(r"\.subscribe\s*\(", bare)
    if not m:
        return FP, "No subscribe() call at the reported line", ctx.ev(a, z)
    depth, parts, last = 0, [], m.end()
    for j in range(m.end(), len(bare)):
        ch = bare[j]
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            if depth == 0:
                parts.append(code[last:j]); break
            depth -= 1
        elif ch == "," and depth == 0:
            parts.append(code[last:j]); last = j + 1
    parts = [p for p in parts if p.strip()]
    if len(parts) >= 2 or (parts and parts[0].strip().startswith("{") and re.search(r"\berror\b", parts[0])):
        return FP, "subscribe() provides an error handler", ctx.ev(a, z)
    return TP, "subscribe() without an error callback (HttpClient errors are unhandled; observable type not verified)", ctx.ev(a, z)


# ------------------------------------- cookie rules ----------------------------------------------
COOKIE_CALL = re.compile(r"document\s*\.\s*cookie\s*=|\.\s*cookie\s*\(|(?:Cookies|\$cookies|\$cookieStore|cookieService)\s*\.\s*(?:set|put)\s*\(|"
                         r"\$\s*\.\s*cookie\s*\(|cookie\s*\.\s*serialize\s*\(")


def make_cookie(flag):
    def chk(ctx, n):
        if not ctx.ok(n):
            return NOLINE
        win, winb = " ".join(ctx.code[n - 1:n + 6]), " ".join(ctx.bare[n - 1:n + 6])
        if not COOKIE_CALL.search(winb):
            return FP, "No cookie creation at the reported line", _ev(ctx, n, n + 2)
        if flag == "httponly":
            if re.search(r"httpOnly\s*:\s*true|;\s*httponly", win, re.I):
                return FP, "The cookie is created with HttpOnly", _ev(ctx, n, n + 2)
            return TP, "Cookie created without HttpOnly (script code can read it)", _ev(ctx, n, n + 2)
        if flag == "secure":
            if re.search(r"secure\s*:\s*true|;\s*secure\b", win, re.I):
                return FP, "The cookie is created with the Secure flag", _ev(ctx, n, n + 2)
            return TP, "Cookie created without the Secure flag (sent over plain HTTP)", _ev(ctx, n, n + 2)
        if flag == "path":
            m = re.search(r"path\s*:\s*[\"']([^\"']*)[\"']|;\s*path=([^;\"']*)", win, re.I)
            if not m:
                return RV, "No explicit Path attribute: the browser default applies", _ev(ctx, n, n + 2)
            v = (m.group(1) or m.group(2) or "").strip()
            if v == "/":
                return TP, "Cookie Path is '/': it is sent to every URL of the site", _ev(ctx, n, n + 2)
            return FP, f"The cookie is scoped to the specific path '{v}'", _ev(ctx, n, n + 2)
        m = re.search(r"domain\s*:\s*[\"']([^\"']*)[\"']|;\s*domain=([^;\"']*)", win, re.I)
        if not m:
            return FP, "No Domain attribute: host-only cookie", _ev(ctx, n, n + 2)
        v = (m.group(1) or m.group(2) or "").strip()
        if v.startswith(".") or v.count(".") <= 1:
            return TP, f"Cookie Domain '{v}' also covers every sub-domain", _ev(ctx, n, n + 2)
        return RV, f"Cookie Domain '{v}': confirm it is the narrowest host", _ev(ctx, n, n + 2)
    return chk


# ------------------------------------- secrets / literals ----------------------------------------
PLACEHOLDER = re.compile(r"^(?:password|passwd|pass|pwd|secret|\*+|x+|<.*>|\$\{.*\}|\{\{.*\}\})$", re.I)


def chk_hard_password(ctx, n):                                       # 1020104, 1020820
    if not ctx.ok(n):
        return NOLINE
    code = ctx.code[n - 1]
    m = re.search(r"(?i)[\w$.]*(?:pass(?:word|wd|phrase)?|pwd|secret)[\w$]*[\"']?\s*[:=]\s*[\"'`]([^\"'`]*)[\"'`]", code)
    if not m:
        return FP, "No password assigned from a literal at the reported line", _ev(ctx, n)
    v = m.group(1)
    if v == "":
        return FP, "The password is initialised with an empty string", _ev(ctx, n)
    if PLACEHOLDER.match(v):
        return RV, "The literal looks like a label/placeholder, not a real password", _ev(ctx, n)
    return TP, "Password hard-coded in the source", _ev(ctx, n)


def chk_hard_apikey(ctx, n):                                         # 1020932
    if not ctx.ok(n):
        return NOLINE
    m = re.search(r"(?i)[\w$.]*(?:api[_-]?key|apikey|access[_-]?token|secret[_-]?key|client[_-]?secret|auth[_-]?token)[\w$]*[\"']?\s*[:=]\s*[\"'`]([A-Za-z0-9_\-./+=]{8,})[\"'`]", ctx.code[n - 1])
    if m:
        return TP, "API key/token hard-coded in the source", _ev(ctx, n)
    return FP, "No API key literal at the reported line", _ev(ctx, n)


def chk_hard_network(ctx, n):                                        # 1020070, 1020826
    if not ctx.ok(n):
        return NOLINE
    for m in re.finditer(r"[\"'`]((?:https?|ftps?|wss?|sftp|jdbc:[a-z]+)://[^\"'`\s]*|\\\\[\w.$-]+\\[^\"'`]*|(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?)[\"'`]", ctx.code[n - 1]):
        v = m.group(1)
        if re.search(r"w3\.org|localhost|127\.0\.0\.1|example\.(?:com|org)|schemas\.|json-schema", v):
            return RV, f"Literal {v} is a namespace/local address: confirm", _ev(ctx, n)
        return TP, f"Network resource {v} is hard-coded", _ev(ctx, n)
    return FP, "No hard-coded URL / IP / UNC path at the reported line", _ev(ctx, n)


# ------------------------------------ file-level (Node/Angular/Vue) ------------------------------
def file_level(ok_rx, what, trigger=None):
    ok, trig = re.compile(ok_rx, re.I), (re.compile(trigger) if trigger else None)

    def chk(ctx, n):
        if not ctx.ok(n):
            return NOLINE
        if trig and not trig.search(" ".join(ctx.bare[max(0, n - 3):n + 3])):
            return RV, "The reported line does not show the construct this rule is about", _ev(ctx, n)
        text = "\n".join(ctx.code)
        m = ok.search(text)
        if m:
            ln = text[:m.start()].count("\n") + 1
            return FP, f"{what} found at line {ln} of this file", _ev(ctx, ln)
        return TP, f"No {what} in this file (it may be configured in another file)", _ev(ctx, n)
    return chk


def chk_dup_routes(ctx, n):                                          # 1020714, 1020898
    if not ctx.ok(n):
        return NOLINE
    text = "\n".join(ctx.code)
    seen = {}
    for m in re.finditer(r"\b(?:app|router)\s*\.\s*(get|post|put|delete|patch|all|use)\s*\(\s*[\"'`]([^\"'`]+)[\"'`]", text):
        seen.setdefault((m.group(1), m.group(2)), []).append(text[:m.start()].count("\n") + 1)
    mine = re.search(r"\b(?:app|router)\s*\.\s*(get|post|put|delete|patch|all|use)\s*\(\s*[\"'`]([^\"'`]+)[\"'`]", ctx.code[n - 1])
    if not mine:
        return RV, "Expected an express route declaration at the reported line", _ev(ctx, n)
    lines = seen[(mine.group(1), mine.group(2))]
    if len(lines) > 1:
        return TP, f"Route {mine.group(1).upper()} {mine.group(2)} is declared {len(lines)} times (lines {', '.join(map(str, lines))})", _ev(ctx, n)
    return RV, "Route declared once in this file; a duplicate in another file is not visible", _ev(ctx, n)


# ------------------------------------------ markup rules ----------------------------------------
def tag_at(ctx, n):
    text = " ".join(ctx.code[n - 1:n + 4])
    return text


def chk_vfor_key(ctx, n):                                            # 1020206
    if not ctx.ok(n):
        return NOLINE
    t = tag_at(ctx, n)
    m = re.search(r"<[^<>]*\bv-for\s*=[^<>]*>", t)
    if not m:
        return FP, "No v-for element at the reported line", _ev(ctx, n)
    if re.search(r"(?:\s:key|v-bind:key)\s*=", m.group(0)):
        return FP, "The v-for element has a :key", _ev(ctx, n)
    return TP, "v-for without :key: Vue cannot track items", _ev(ctx, n)


def chk_vif_vfor(ctx, n):                                            # 1020208
    if not ctx.ok(n):
        return NOLINE
    m = re.search(r"<[^<>]*>", tag_at(ctx, n)[max(0, 0):])
    t = tag_at(ctx, n)
    for m in re.finditer(r"<[^<>]*>", t):
        if re.search(r"\bv-for\s*=", m.group(0)) and re.search(r"\bv-if\s*=", m.group(0)):
            return TP, "v-if and v-for on the same element", _ev(ctx, n)
    return FP, "v-if and v-for are not on the same element", _ev(ctx, n)


def make_track(attr, ok_word, label):
    def chk(ctx, n):
        if not ctx.ok(n):
            return NOLINE
        t = tag_at(ctx, n)
        m = re.search(attr + r"\s*=\s*[\"']([^\"']*)[\"']", t)
        if not m:
            return FP, f"No {label} at the reported line", _ev(ctx, n)
        if re.search(ok_word, m.group(1)):
            return FP, f"The {label} has a track-by/trackBy option", _ev(ctx, n)
        return TP, f"{label} without a track-by/trackBy option: the DOM is rebuilt on every change", _ev(ctx, n)
    return chk


def chk_sync_script(ctx, n):                                         # 1020020
    if not ctx.ok(n):
        return NOLINE
    m = re.search(r"<script\b[^>]*>", " ".join(ctx.code[n - 1:n + 3]), re.I)
    if not m:
        return FP, "No <script> tag at the reported line", _ev(ctx, n)
    tag = m.group(0)
    if not re.search(r"\bsrc\s*=", tag, re.I):
        return FP, "Inline script (not an import)", _ev(ctx, n)
    if re.search(r"\b(?:async|defer)\b|type\s*=\s*[\"']module", tag, re.I):
        return FP, "The script has async/defer/type=module", _ev(ctx, n)
    return TP, "Blocking <script src> without async/defer: page rendering waits for it", _ev(ctx, n)


def chk_inline_function(ctx, n):                                     # 1020092
    if not ctx.ok(n):
        return NOLINE
    inside = False
    for k in range(n):
        for m in re.finditer(r"<script\b[^>]*>|</script>", ctx.code[k] if k < n - 1 else ctx.code[k][:0] or ctx.code[k], re.I):
            if m.group(0).lower().startswith("</"):
                inside = False
            else:
                inside = not re.search(r"\bsrc\s*=", m.group(0), re.I) and not m.group(0).endswith("/>")
    if inside and re.search(r"\bfunction\s+[\w$]+\s*\(", ctx.bare[n - 1]):
        return TP, "A JavaScript function is defined directly in the web page", _ev(ctx, n)
    if re.search(r"\bfunction\s+[\w$]+\s*\(", ctx.bare[n - 1]):
        return RV, "Function declaration found but it was not recognised as inside an inline <script>", _ev(ctx, n)
    return FP, "No function declaration at the reported line", _ev(ctx, n)


def chk_doctype(ctx, n):                                             # 1020196
    if not ctx.ok(n):
        return NOLINE
    line = ctx.raw[n - 1]
    m = re.search(r"<!DOCTYPE[^>]*>", line, re.I)
    if m:
        if re.fullmatch(r"<!DOCTYPE\s+html\s*>", m.group(0), re.I):
            return FP, "HTML5 DOCTYPE (standards mode)", _ev(ctx, n)
        return TP, f"Legacy DOCTYPE: {m.group(0)[:60]}", _ev(ctx, n)
    if not any(re.search(r"<!DOCTYPE", l, re.I) for l in ctx.raw):
        return TP, "No DOCTYPE in the page: browsers use quirks mode", _ev(ctx, n)
    return FP, "No DOCTYPE at the reported line", _ev(ctx, n)


def chk_ie_cond_comment(ctx, n):                                     # 1020198
    if not ctx.ok(n):
        return NOLINE
    if re.search(r"<!--\s*\[if\b|<!\s*\[endif\]", ctx.raw[n - 1], re.I):
        return TP, "IE conditional comment", _ev(ctx, n)
    return FP, "No IE conditional comment at the reported line", _ev(ctx, n)


def chk_vue_data(ctx, n):                                            # 1020200
    if not ctx.ok(n):
        return NOLINE
    b = " ".join(ctx.bare[n - 1:n + 1])
    if re.search(r"\bdata\s*\(\s*\)|\bdata\s*:\s*(?:function\b|\(\s*\)\s*=>)", b):
        return FP, "data is a function returning a fresh object", _ev(ctx, n)
    if re.search(r"\bdata\s*:\s*\{", b):
        return TP, "data is a plain object shared between component instances", _ev(ctx, n)
    return FP, "No data option at the reported line", _ev(ctx, n)


def chk_prefix_without_standard(ctx, n):                             # 1030110
    if not ctx.ok(n):
        return NOLINE
    m = re.search(r"(?<![\w-])-(?:webkit|moz|ms|o)-([\w-]+)\s*:", ctx.bare[n - 1])
    if not m:
        return FP, "No vendor-prefixed property at the reported line", _ev(ctx, n)
    text = "\n".join(ctx.bare)
    off = sum(len(l) + 1 for l in ctx.bare[:n - 1])
    s, e = text.rfind("{", 0, off), text.find("}", off)
    block = text[s + 1:e] if s >= 0 and e >= 0 else ""
    if re.search(r"(?<![\w-])" + re.escape(m.group(1)) + r"\s*:", block):
        return FP, f"The standard property '{m.group(1)}' is declared in the same rule", _ev(ctx, n)
    return TP, f"Vendor-prefixed property without the standard '{m.group(1)}' fallback", _ev(ctx, n)


def chk_jquery_dup_selector(ctx, n):                                 # 1020308
    if not ctx.ok(n):
        return NOLINE
    m = re.search(r"(?:\$|jQuery)\s*\(\s*([\"'])([^\"']+)\1\s*\)", ctx.code[n - 1])
    if not m:
        return FP, "No jQuery selector call at the reported line", _ev(ctx, n)
    sel = m.group(2)
    lines = [i + 1 for i, l in enumerate(ctx.code)
             if re.search(r"(?:\$|jQuery)\s*\(\s*[\"']" + re.escape(sel) + r"[\"']\s*\)", l)]
    if len(lines) > 1:
        return TP, f"Selector '{sel}' is evaluated {len(lines)} times (lines {', '.join(map(str, lines))}): cache it in a variable", _ev(ctx, n)
    return FP, f"Selector '{sel}' is evaluated only once in this file", _ev(ctx, n)


def chk_ajax_option(missing, label):                                 # 1020322 / 1020340 / 1020342
    def chk(ctx, n):
        if not ctx.ok(n):
            return NOLINE
        code, bare, a, z = ctx.span(n, 25)
        if not re.search(r"(?:\$|jQuery)\s*\.\s*ajax\s*\(", bare):
            return FP, "No $.ajax call at the reported line", ctx.ev(a, z)
        if missing == "dataType":
            return (FP, "dataType is set", ctx.ev(a, z)) if re.search(r"\bdataType\b", bare) else \
                   (TP, "$.ajax without dataType (jQuery < 3.0 guesses the type; version not verified)", ctx.ev(a, z))
        has = re.search(r"\b(?:success|error|complete)\s*:|\.(?:done|fail|always|then)\s*\(", " ".join(ctx.bare[n - 1:n + 30]))
        return (FP, "A success/error/complete (or done/fail/always) callback is provided", ctx.ev(a, z)) if has else \
               (TP, "$.ajax without any success/error/complete or done/fail/always callback", ctx.ev(a, z))
    return chk


def chk_empty_ajax_error(ctx, n):                                    # 1020342
    if not ctx.ok(n):
        return NOLINE
    t = " ".join(ctx.bare[n - 1:n + 4])
    if re.search(r"\b(?:error\s*:\s*function\s*\([^)]*\)|\.fail\s*\(\s*function\s*\([^)]*\))\s*\{\s*\}|\berror\s*:\s*\([^)]*\)\s*=>\s*\{\s*\}", t):
        return TP, "Empty ajax error/fail handler: failures are silently ignored", _ev(ctx, n, n + 3)
    return FP, "No empty ajax error/fail handler at the reported line", _ev(ctx, n, n + 3)


def chk_delete_array(ctx, n):                                        # 1020054
    if not ctx.ok(n):
        return NOLINE
    b = ctx.bare[n - 1]
    m = re.search(r"\bdelete\s+([\w$.]+)\s*\[\s*([^\]]*)\]", b)
    if not m:
        return FP, "No delete of an indexed element at the reported line", _ev(ctx, n)
    if re.fullmatch(r"\d+", m.group(2).strip()) or re.search(r"(?i)arr|list|items|array|\[\]", m.group(1)):
        return TP, "delete on an array element leaves a hole; use splice()", _ev(ctx, n)
    return RV, "delete obj[key]: cannot tell whether the target is an array or an object", _ev(ctx, n)


def chk_ui5_attach(ctx, n):                                          # 1020154
    if not ctx.ok(n):
        return NOLINE
    if not re.search(r"\.attachEvent\s*\(", ctx.bare[n - 1]):
        return FP, "No attachEvent call at the reported line", _ev(ctx, n)
    if re.search(r"sap\.ui\.define|sap\.ui\.require", "\n".join(ctx.code)):
        return RV, "attachEvent is also the SAPUI5 framework API: confirm the receiver is a DOM element", _ev(ctx, n)
    return TP, "IE-only attachEvent: use addEventListener", _ev(ctx, n)


# ----------------------------------------- registry ---------------------------------------------
RULES = {}


def reg(ids, name, fn):
    for i in ids if isinstance(ids, (list, tuple)) else [ids]:
        RULES[str(i)] = (name, fn)


K = keyword
# --- plain API usages (JS/TS) -----------------------------------------------------------------
reg(1020004, "Avoid using querySelectorAll", K(r"\.\s*querySelectorAll\s*\(", "querySelectorAll"))
reg(1020008, "Avoid using for-in loop", K(r"\bfor\s*\(\s*(?:var|let|const)?\s*[\w$]+\s+in\b", "for-in loop"))
reg([1020010, 1020500], "Avoid using forEach()", K(r"\.\s*forEach\s*\(", "forEach()"))
reg(1020018, "Avoid using Web SQL databases", K(r"(?<![\w$])openDatabase\s*\(", "openDatabase (Web SQL)"))
reg(1020040, "Avoid using delete with no object properties", K(r"\bdelete\s+[A-Za-z_$][\w$]*\s*(?:;|$|\))", "delete on a plain variable"))
reg(1020054, "Avoid using delete on arrays", chk_delete_array)
reg(1020056, "Avoid using Javascript document.all collection", K(r"\bdocument\s*\.\s*all\b", "document.all"))
reg([1020058, 1020808], "Avoid using eval()", K(r"(?<![\w$.])eval\s*\(", "eval()"))
reg(1020060, "Avoid using console.log()", K(r"(?<![\w$.])console\s*\.\s*log\s*\(", "console.log()"))
reg(1020804, "Avoid using console logging", K(r"(?<![\w$.])console\s*\.\s*(?:log|warn|error|info|debug|trace)\s*\(", "console logging"))
reg(1020066, "Avoid using Javascript Function constructor", K(r"\bnew\s+Function\s*\(|(?<![\w$.])Function\s*\(", "Function constructor"))
reg([1020078, 1020870], "Avoid using setTimeout()", K(r"(?<![\w$.])(?:window\s*\.\s*)?setTimeout\s*\(", "setTimeout()"))
reg([1020080, 1020860], "Avoid using setInterval()", K(r"(?<![\w$.])(?:window\s*\.\s*)?setInterval\s*\(", "setInterval()"))
reg(1020112, "Avoid setting an event handler using element.setAttribute()", lit(r"\.\s*setAttribute\s*\(\s*[\"']on\w+[\"']", "setAttribute('onXxx', ...)"))
reg(1020114, "Avoid using navigator.vibrate()", K(r"\bnavigator\s*\.\s*vibrate\s*\(", "navigator.vibrate()"))
reg(1020116, "Avoid __proto__ and legacy getter/setter methods", K(r"__proto__|__(?:define|lookup)(?:Getter|Setter)__", "__proto__ / legacy getter-setter"))
reg(1020118, "Avoid using ActiveXObject / window.external", K(r"\bActiveXObject\b|\bwindow\s*\.\s*external\b", "ActiveXObject / window.external"))
reg(1020120, "Avoid using DOM Mutation Events", lit(r"DOM(?:NodeInserted|NodeRemoved|SubtreeModified|AttrModified|CharacterDataModified|NodeInsertedIntoDocument|NodeRemovedFromDocument)", "DOM mutation event"))
reg(1020122, "Avoid using Event.initEvent() / initMouseEvent() / initUIEvent()", K(r"\.\s*init(?:Mouse|UI|Keyboard)?Event\s*\(", "initEvent()"))
reg(1020124, "Avoid using String.prototype.substr()", K(r"\.\s*substr\s*\(", "substr()"))
reg(1020126, "Avoid using arguments.callee / Function.prototype.caller", K(r"\barguments\s*\.\s*callee\b|\.\s*caller\b", "arguments.callee / .caller"))
reg(1020128, "Avoid using document.domain", K(r"\bdocument\s*\.\s*domain\b", "document.domain"))
reg(1020130, "Avoid using document.execCommand()", K(r"\.\s*execCommand\s*\(", "execCommand()"))
reg(1020132, "Avoid using document.write()", K(r"\bdocument\s*\.\s*write(?:ln)?\s*\(", "document.write()"))
reg(1020134, "Avoid using escape() / unescape()", K(r"(?<![\w$.])(?:escape|unescape)\s*\(", "escape()/unescape()"))
reg(1020136, "Avoid using Event.keyCode / which / charCode", K(r"\.\s*(?:keyCode|charCode|which)\b", "keyCode/charCode/which"))
reg(1020138, "Avoid using Event.returnValue", K(r"\.\s*returnValue\b", "returnValue"))
reg(1020140, "Avoid using navigator.getUserMedia()", K(r"\bnavigator\s*\.\s*(?:webkit|moz|ms)?getUserMedia\b", "navigator.getUserMedia"))
reg(1020142, "Avoid using deprecated properties of navigator object", K(r"\bnavigator\s*\.\s*(?:appCodeName|appName|appVersion|platform|product|productSub|vendor|vendorSub|taintEnabled|oscpu|buildID|javaEnabled)\b", "deprecated navigator property"))
reg(1020144, "Avoid using vendor-prefixed RequestFullscreen", K(r"(?:webkit|moz|ms)RequestFullscreen|ALLOW_KEYBOARD_INPUT", "vendor-prefixed requestFullscreen"))
reg(1020146, "Avoid using synchronous XMLHttpRequest", K(r"\.\s*open\s*\([^)]*,\s*false\s*[,)]", "synchronous XMLHttpRequest.open(..., false)"))
reg(1020148, "Avoid using vendor-prefixed requestAnimationFrame", K(r"(?<![A-Za-z])(?:webkit|moz|ms|o)RequestAnimationFrame", "vendor-prefixed requestAnimationFrame"))
reg(1020150, "Avoid using window.event", K(r"\bwindow\s*\.\s*event\b", "window.event"))
reg(1020152, "Avoid using window.showModalDialog()", K(r"\bshowModalDialog\s*\(", "showModalDialog()"))
reg(1020154, "Avoid using attachEvent", chk_ui5_attach)
reg(1020156, "Avoid using window.createPopup", K(r"\bcreatePopup\s*\(", "createPopup()"))
reg(1020158, "Avoid using element.currentStyle", K(r"\.\s*currentStyle\b", "currentStyle"))
reg(1020160, "Avoid using document.documentMode", K(r"\bdocumentMode\b", "documentMode"))
reg(1020162, "Avoid using document.selection / createTextRange", K(r"\bdocument\s*\.\s*selection\b|\bcreateTextRange\b", "document.selection / createTextRange"))
reg(1020164, "Avoid changing DOM using outerHTML", K(r"\.\s*outerHTML\s*=(?!=)", "outerHTML assignment"))
reg(1020166, 'Avoid using navigator.appName === "Microsoft Internet Explorer"', lit(r"navigator\s*\.\s*appName\s*[!=]==?\s*[\"']Microsoft Internet Explorer", "appName IE test"))
reg(1020168, "Avoid using User-Agent based IE detection", lit(r"(?=.*userAgent)(?=.*(?:MSIE|Trident))", "User-Agent based IE detection"))
reg(1020170, "Avoid using XDomainRequest", K(r"\bXDomainRequest\b", "XDomainRequest"))
reg(1020172, "Avoid using innerText", K(r"\.\s*innerText\b", "innerText"))
reg(1020174, "Avoid using VBScript blocks", lit(r"(?i)<script[^>]*(?:language\s*=\s*[\"']?vbscript|type\s*=\s*[\"']text/vbscript)", "VBScript block"))
reg(1020176, "Avoid empty catch blocks (JS)", chk_empty_catch)
reg(1020178, "Avoid empty finally blocks", chk_empty_finally)
reg(1020180, "Avoid missing default in switch statements", chk_switch_default)
reg(1020182, "Avoid using break statement in FOR loops", chk_break_in_for)
reg(1020038, "Avoid defining and calling functions inside loops", chk_function_in_loop)
reg(1020006, "Avoid calling a function in a termination loop", chk_call_in_loop_condition)
reg(1020068, "Avoid return statement in finally block", make_jump_in_finally(("return",)))
reg(1020800, "Avoid jump statements in finally", make_jump_in_finally(("return", "break", "continue", "throw")))
# --- web service calls in loops -------------------------------------------------------------
reg(1020012, "Avoid using a web service with WebSocket inside a loop", make_ws_loop(r"\bnew\s+WebSocket\s*\(|\.\s*send\s*\(", "WebSocket"))
reg(1020014, "Avoid using a web service with XMLHttpRequest inside a loop", make_ws_loop(r"\bnew\s+XMLHttpRequest\s*\(|\.\s*send\s*\(", "XMLHttpRequest"))
reg(1020224, "Avoid using the call of web service inside a loop (VueJS)", make_ws_loop(r"\baxios\b|(?<![\w$.])fetch\s*\(|\$http\b|\$axios\b", "web service"))
reg(1020300, "Avoid using the call of web service jQuery ajax inside a loop", make_ws_loop(r"(?:\$|jQuery)\s*\.\s*(?:ajax|get|post|getJSON|getScript)\s*\(", "jQuery ajax"))
reg(1020504, "Avoid using the call of web service with AngularJS $http inside a loop", make_ws_loop(r"\$http\b", "$http"))
reg(1020534, "Avoid using a web service with AngularJS $resource inside a loop", make_ws_loop(r"\$resource\b|\.\s*\$(?:get|save|query|remove|delete)\s*\(", "$resource"))
reg(1020716, "Avoid using the call of web service with Node.js http.get or http.request inside a loop", make_ws_loop(r"\bhttps?\s*\.\s*(?:get|request)\s*\(", "http.get/request"))
reg(1020814, "Avoid using web service calls inside a loop", make_ws_loop(r"(?<![\w$.])fetch\s*\(|\baxios\b|XMLHttpRequest|(?:\$|jQuery)\s*\.\s*ajax|\$http\b|\bhttps?\s*\.\s*(?:get|request)\s*\(|\bhttp\s*\.\s*(?:get|post|put|delete|patch)\s*\(", "web service"))
reg(1020828, "Avoid String concatenation in loops (Typescript)", chk_string_concat_loop)
# --- error handling / robustness ------------------------------------------------------------
reg(1020102, "Always use JSON.parse & JSON.stringify with try/catch block (Javascript)", make_json_try())
reg(1020872, "Always use JSON.parse & JSON.stringify with try/catch block (TypeScript)", make_json_try())
reg(1020780, "Avoid using Node.js synchronous FileSystem API without try/catch block", chk_sync_fs)
reg(1020802, "Avoid having errors without throwing them", chk_error_not_thrown)
reg(1020812, "Avoid invoking super more than once in constructor", chk_super_twice)
reg([1020700, 1020874], "Avoid the lack of error handling in the Node.js callbacks", chk_node_callback_err)
reg(1020822, "Always provide error callbacks when subscribing to HttpClient observables", make_subscribe_error)
reg([1020452, 1020858], "Avoid empty componentDidCatch blocks", chk_empty_did_catch)
reg(1020806, "Avoid using NaN in comparison", K(r"[!=]==?\s*NaN\b|\bNaN\s*[!=]==?", "comparison with NaN"))
reg(1020818, "Avoid disabling xsrf check in HttpClientXsrfModule", K(r"HttpClientXsrfModule\s*\.\s*disable\s*\(", "HttpClientXsrfModule.disable()"))
# --- cookies ----------------------------------------------------------------------------------
reg([1020094, 1020728, 1020868], "Avoid creating cookie without setting httpOnly option", make_cookie("httponly"))
reg([1020096, 1020218, 1020458, 1020554, 1020734, 1020864, 1020886], "Avoid using unsecured cookie", make_cookie("secure"))
reg([1020098, 1020220, 1020558, 1020740, 1020866], "Avoid creating cookie with overly broad path", make_cookie("path"))
reg([1020100, 1020222, 1020556, 1020742, 1020862], "Avoid having cookie with an overly broad domain", make_cookie("domain"))
# --- secrets / hard-coded values / injection ---------------------------------------------------
reg([1020104, 1020820], "Avoid hard-coded passwords", chk_hard_password)
reg(1020932, "Avoid hard-coded API keys (TypeScript)", chk_hard_apikey)
reg([1020070, 1020826], "Avoid hard-coded network resource names", chk_hard_network)
reg(1020072, "Avoid direct access to Database Tables in Javascript", lit(r"(?i)[\"'`]\s*(?:SELECT\s+[^\"'`]+\s+FROM|INSERT\s+INTO|UPDATE\s+\w+\s+SET|DELETE\s+FROM)\b", "SQL statement in a string"))
reg([1020772, 1020926], "Avoid string interpolations to prevent SQL injections",
    lit(r"(?i)[\"'`]\s*(?:SELECT|INSERT|UPDATE|DELETE)\b[^\"'`]*[\"'`]\s*\+|\+\s*[\"'`][^\"'`]*\b(?:WHERE|AND|VALUES|SET)\b|`[^`]*\b(?:SELECT|INSERT INTO|UPDATE|DELETE FROM)\b[^`]*\$\{", "SQL built by concatenation/interpolation"))
reg([1020732, 1020896], "Avoid using risky cryptographic hash", lit(r"(?i)createHash\s*\(\s*[\"'](?:md[245]|sha-?1)[\"']", "weak hash (md5/sha1)"))
reg(1020052, "Avoid using import with external URI", lit(r"(?i)@import\s+(?:url\(\s*)?[\"']?(?:https?:)?//", "@import of an external URI"))
reg(1020030, "Avoid using javascript or expression in the CSS file", lit(r"(?i)\bexpression\s*\(|url\(\s*[\"']?javascript:", "expression() / javascript: in CSS"))
reg(1020034, "Avoid hosting HTML code in iframe srcdoc", lit(r"(?i)<iframe\b[^>]*\bsrcdoc\s*=", "iframe srcdoc"))
# --- Node.js ---------------------------------------------------------------------------------
reg([1020702, 1020876], "Avoid using nodejs process.exit()", K(r"\bprocess\s*\.\s*exit\s*\(", "process.exit()"))
reg([1020704, 1020894], "Avoid using string concatenation when using __dirname and __filename", K(r"__(?:dirname|filename)\s*\+|\+\s*__(?:dirname|filename)", "__dirname/__filename concatenation"))
reg([1020708, 1020880], "Ensure the X-Powered-By header is disabled", file_level(r"disable\s*\(\s*[\"']x-powered-by[\"']\s*\)|\bhelmet\s*\(|hidePoweredBy", "X-Powered-By disabled"))
reg([1020712, 1020882], "Ensure the X-Frame-Options header is setup", file_level(r"x-frame-options|\bhelmet\s*\(|frameguard", "X-Frame-Options setup"))
reg(1020710, "Ensure the X-XSS-Protection header is enabled", file_level(r"x-xss-protection|\bhelmet\s*\(|xssFilter", "X-XSS-Protection setup"))
reg([1020706, 1020902], "Ensure the Content-Security-Policy is activated", file_level(r"content-security-policy|contentSecurityPolicy|\bhelmet\s*\(", "Content-Security-Policy setup"))
reg([1020718, 1020884], "Ensure that browser cannot cache or store a page", file_level(r"cache-control[^;\n]*no-store|nocache|noCache|\bhelmet\s*\(", "no-store / nocache setup"))
reg([1020726, 1020890], "Ensure that CSRF Protection is enabled", file_level(r"\bcsurf\b|\bcsrf\b|\blusca\b", "CSRF middleware"))
reg(1020724, "Ensure that marked is sanitized", file_level(r"sanitize\s*:\s*true|DOMPurify|sanitizer", "marked sanitization"))
reg([1020730, 1020892], "Ensure Node.js filesystem are closed", file_level(r"\bfs\s*\.\s*close(?:Sync)?\s*\(|\.close\s*\(\)|createReadStream|createWriteStream", "fs close"))
reg([1020714, 1020898], "Avoid having multiple routes for the same path with Node.js Express App", chk_dup_routes)
reg([1020720, 1020888], "Avoid unsecure connection to the Node.js server", K(r"\bhttp\s*\.\s*createServer\s*\(", "http.createServer (not https)"))
reg([1020736, 1020922], "Avoid bypassing self-signed ssl certificate", lit(r"rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED[\"']?\s*\]?\s*=\s*[\"']?0", "TLS certificate verification disabled"))
reg([1020738, 1020920], "Avoid disabling SSL verification in node-curl", lit(r"(?i)SSL_VERIFY(?:PEER|HOST)[\"']?\s*[,:=]\s*(?:0|false)", "SSL verification disabled in node-curl"))
reg(1020782, "Avoid using Buffer deprecated APIs", K(r"\bnew\s+Buffer\s*\(|(?<![\w$.])Buffer\s*\(", "deprecated Buffer constructor"))
# --- AngularJS / Angular / Vue / React / jQuery -----------------------------------------------
reg(1020506, "Avoid using $scope in controllers", K(r"\$scope\b", "$scope"))
reg(1020508, "Use Angular wrapper service $document", K(r"(?<![\w$.])document\s*\.", "direct document access"))
reg(1020510, "Use Angular wrapper service $window", K(r"(?<![\w$.])window\s*\.", "direct window access"))
reg(1020512, "Use Angular wrapper service $timeout", K(r"(?<![\w$.])setTimeout\s*\(", "setTimeout"))
reg(1020502, "Avoid the use of JSON.parse and JSON.stringify in AngularJS web app", K(r"\bJSON\s*\.\s*(?:parse|stringify)\s*\(", "JSON.parse/stringify"))
reg(1020514, "Only use angular.isUndefined / angular.isDefined", lit(r"(?:===?|!==?)\s*undefined\b|typeof\s+[\w$.]+\s*[!=]==?\s*[\"']undefined[\"']", "manual undefined test"))
reg(1020516, "Avoid using Javascript Array typecheck in AngularJS", K(r"\bArray\s*\.\s*isArray\s*\(|\binstanceof\s+Array\b", "Array typecheck"))
reg(1020518, "Avoid using Javascript Date typecheck in AngularJS", K(r"\binstanceof\s+Date\b", "Date typecheck"))
reg(1020520, "Avoid using Javascript Function typecheck in AngularJS", lit(r"typeof\s+[^;]*?[!=]==?\s*[\"']function[\"']", "Function typecheck"))
reg(1020522, "Avoid using Javascript String typecheck in AngularJS", lit(r"typeof\s+[^;]*?[!=]==?\s*[\"']string[\"']", "String typecheck"))
reg(1020524, "Avoid using Javascript Object typecheck in AngularJS", lit(r"typeof\s+[^;]*?[!=]==?\s*[\"']object[\"']", "Object typecheck"))
reg(1020526, "Avoid using Javascript Number typecheck in AngularJS", lit(r"typeof\s+[^;]*?[!=]==?\s*[\"']number[\"']", "Number typecheck"))
reg(1020528, "Avoid using Javascript Regexp typecheck in AngularJS", K(r"\binstanceof\s+RegExp\b", "RegExp typecheck"))
reg(1020530, "Avoid using !angular.isUndefined() and !angular.isDefined()", K(r"!\s*angular\s*\.\s*is(?:Undefined|Defined)\s*\(", "negated angular.isUndefined/isDefined"))
reg(1020532, "Use Angular factory() instead of service()", lit(r"\.\s*service\s*\(\s*[\"']", "module.service()"))
reg(1020536, "Avoid using $ or jQuery, use angular.element instead", K(r"(?<![\w$.])(?:\$|jQuery)\s*\(", "jQuery call in an AngularJS app"))
reg(1020538, "Avoid wrapping angular.element objects with jQuery or $", K(r"(?:\$|jQuery)\s*\(\s*angular\s*\.\s*element", "$(angular.element(...))"))
reg(1020540, "Avoid using $http success and error function", K(r"\$http\b[^;]*\.\s*(?:success|error)\s*\(", "$http .success/.error"))
reg(1020544, "Avoid disabling Strict Contextual Escaping (SCE)", K(r"\$sceProvider\s*\.\s*enabled\s*\(\s*false", "SCE disabled"))
reg(1020548, "Avoid disabling withCredentials option for the httpProvider", K(r"withCredentials\s*=\s*false", "withCredentials = false"))
reg(1020550, "Avoid using ng-repeat loop without track by option", make_track(r"(?:data-)?ng-repeat", r"\btrack\s+by\b", "ng-repeat"))
reg(1020840, "Avoid using ngFor loop without TrackBy option", make_track(r"\*ngFor", r"\btrackBy\b", "*ngFor"))
reg([1020454, 1020854], "Avoid using React dangerouslySetInnerHTML", K(r"\bdangerouslySetInnerHTML\b", "dangerouslySetInnerHTML"))
reg([1020456, 1020834, 1020852], "Avoid using <script> tag in HTML template", K(r"<script\b", "<script> tag in a template"))
reg(1020830, "Avoid using Angular ElementRef API to manipulate DOM", K(r"\.\s*nativeElement\b", "ElementRef.nativeElement"))
reg(1020836, "Avoid exporting namespaces", K(r"\bexport\s+(?:declare\s+)?(?:namespace|module)\b", "exported namespace"))
reg(1020838, "Avoid using Rx.observable.fromEvent without debounceTime", lambda ctx, n: (
    NOLINE if not ctx.ok(n) else
    (FP, "No fromEvent at the reported line", ctx.ev(n)) if not re.search(r"\bfromEvent\s*\(", ctx.bare[n - 1]) else
    (FP, "debounceTime is applied", ctx.ev(n, n + 6)) if re.search(r"debounceTime", " ".join(ctx.bare[n - 1:n + 7]).split(";")[0]) else
    (TP, "fromEvent without debounceTime: every event is processed", ctx.ev(n, n + 6))))
reg(1020848, "Always favour pipable operators in RxJS", lit(r"rxjs/add/(?:operator|observable)", "patch-style RxJS import"))
reg(1020850, "Always handle errors when using ajax with RxJS", lambda ctx, n: (
    NOLINE if not ctx.ok(n) else
    (FP, "No RxJS ajax call at the reported line", ctx.ev(n)) if not re.search(r"\bajax\s*(?:\.\s*\w+)?\s*\(", ctx.bare[n - 1]) else
    (FP, "catchError is applied", ctx.ev(n, n + 8)) if re.search(r"catchError|\.catch\s*\(|error\s*:", " ".join(ctx.bare[n - 1:n + 9]).split(";")[0]) else
    (TP, "ajax() without catchError / error handler", ctx.ev(n, n + 8))))
reg(1020928, "Always unsubscribe events in Angular onDestroy method", file_level(r"\bngOnDestroy\b[^}]*(?:unsubscribe|complete|next)|takeUntil|\|\s*async\b", "unsubscribe in ngOnDestroy / takeUntil / async pipe", trigger=r"\.subscribe\s*\("))
reg(1020214, "Ensure to turn off and clear event listeners after component is destroyed", file_level(r"(?:beforeDestroy|destroyed|beforeUnmount|unmounted)[^}]*(?:removeEventListener|\$off)", "listener cleanup in a destroy hook"))
reg(1020200, "Always have data property as a function that returns an object", chk_vue_data)
reg(1020206, "Avoid using v-for without key", chk_vfor_key)
reg(1020208, "Avoid using v-if on the same element as v-for", chk_vif_vfor)
reg(1020210, "Avoid using v-show directive inside templates", K(r"\bv-show\b", "v-show"))
reg(1020212, "Avoid changing parent properties from child components using $parent", K(r"\$parent\s*\.\s*[\w$]+\s*=(?!=)", "assignment to $parent property"))
reg(1020302, "Avoid using element type in jQuery", lit(r"(?:\$|jQuery)\s*\(\s*[\"'][a-zA-Z][a-zA-Z0-9]*[.#][\w-]+", "element type in a jQuery selector"))
reg(1020306, "Always use find for Id->Child nested selectors", lit(r"(?:\$|jQuery)\s*\(\s*[\"']#[\w-]+\s+[.#\w]", "ID followed by a descendant selector"))
reg(1020308, "Always cache the returned objects in variables to be reused", chk_jquery_dup_selector)
reg(1020310, 'Use "type=" to select elements by type', lit(r"(?:\$|jQuery)\s*\(\s*[\"'][^\"']*:(?:text|password|checkbox|radio|submit|button|file|image|reset|hidden)\b", "jQuery :type selector"))
reg(1020312, "Avoid use of anonymous functions to attach events", K(r"\.\s*(?:on|bind|click|change|submit|keyup|keydown|hover|focus|blur|mouseover|mouseout)\s*\(\s*(?:[^,()]*,\s*)?function\s*\(", "anonymous event handler"))
reg(1020314, "Avoid using css() of many elements", lit(r"(?:\$|jQuery)\s*\(\s*[\"'][^\"'#]*[.*][^\"']*[\"']\s*\)\s*\.\s*css\s*\(", "css() on a class/universal selection"))
reg(1020316, "Avoid Universal Selectors", lit(r"(?:\$|jQuery)\s*\(\s*[\"'][^\"']*\*[^\"']*[\"']", "universal selector"))
reg(1020318, "Avoid using jQuery deprecated methods", K(r"\.\s*(?:live|die|andSelf|size)\s*\(|\$\s*\.\s*browser\b", "deprecated jQuery method"))
reg(1020344, "Avoid using jQuery 3.x deprecated methods", K(r"\.\s*(?:bind|unbind|delegate|undelegate|size)\s*\(|(?:\$|jQuery)\s*\.\s*(?:isArray|isFunction|isNumeric|isWindow|parseJSON|trim|type|now|proxy)\s*\(", "jQuery 3 deprecated method"))
reg(1020320, "Avoid using jQuery $.cookie", K(r"(?:\$|jQuery)\s*\.\s*cookie\s*\(", "$.cookie"))
reg(1020322, "Avoid using Ajax method without dataType with jQuery older than 3.0.0", chk_ajax_option("dataType", "dataType"))
reg(1020340, "Always implement success/error/complete or done/fail/always when using jQuery ajax", chk_ajax_option("callbacks", "callbacks"))
reg(1020342, "Avoid empty jQuery ajax error/fail blocks", chk_empty_ajax_error)
# --- HTML / CSS -------------------------------------------------------------------------------
reg(1020020, "Avoid blocking page loading with synchronous Javascript import", chk_sync_script)
reg(1020074, 'Avoid enabling autocomplete "on" for inputs/forms', lit(r"(?i)\bautocomplete\s*=\s*[\"']on[\"']", 'autocomplete="on"'))
reg(1020092, "Avoid direct definition of JavaScript Functions in a Web page", chk_inline_function)
reg(1020106, "Avoid hidden form fields to prevent parameter tampering", lit(r"(?i)<input\b[^>]*\btype\s*=\s*[\"']hidden[\"']", "hidden input"))
reg(1020184, "Avoid using Meta X-UA-Compatible header", lit(r"(?i)X-UA-Compatible", "X-UA-Compatible meta"))
reg(1020186, "Avoid using <font> element", K(r"(?i)<font\b", "<font>"))
reg(1020188, "Avoid using <center> element", K(r"(?i)<center\b", "<center>"))
reg(1020190, "Avoid using <marquee> / <blink> elements", K(r"(?i)<(?:marquee|blink)\b", "<marquee>/<blink>"))
reg(1020192, "Avoid using <big> element", K(r"(?i)<big\b", "<big>"))
reg(1020194, "Avoid using presentational HTML attributes", K(r"(?i)<\w+[^>]*\s(?:bgcolor|align|valign|nowrap|border)\s*=", "presentational attribute"))
reg(1020196, "Avoid using outdated / quirks-mode DOCTYPE", chk_doctype)
reg(1020198, "Avoid using IE conditional comments", chk_ie_cond_comment)
reg(1030100, "Avoid using IE filters and -ms-filter (CSS)", K(r"(?i)\bprogid\s*:|-ms-filter\b|\balpha\s*\(\s*opacity", "IE filter"))
reg(1030102, "Avoid using zoom for Layout (CSS)", K(r"(?<![\w-])zoom\s*:", "zoom property"))
reg(1030104, "Avoid using CSS selector hacks: * html, *+html", K(r"\*\s+html\b|\*\s*\+\s*html\b", "selector hack"))
reg(1030106, "Avoid using property name hacks (_property, *property)", K(r"(?:^|[{;\s])[_*][a-zA-Z-]+\s*:", "property name hack"))
reg(1030108, "Avoid using CSS hack values (\\9, \\0/)", lit(r"\\9\b|\\0/", "CSS hack value"))
reg(1030110, "Avoid using Vendor Prefix without Standard Fallback (CSS)", chk_prefix_without_standard)
reg(1030112, "Avoid using IE-only gradient (CSS)", K(r"(?i)progid\s*:\s*DXImageTransform\.Microsoft\.gradient|-ms-filter[^;]*gradient", "IE-only gradient"))

RULES = {k: v for k, v in RULES.items() if v[1] is not None}

MANUAL = {
    "metric / documentation / unreferenced (threshold-based, needs the whole application)": [
        1020000, 1020002, 1020076, 1020082, 1020084, 1020086, 1020088, 1020090, 7780, 7784, 7844],
    "HTML5 injection vector (needs attack-pattern combinations in markup)": [
        1020022, 1020024, 1020026, 1020028, 1020032, 1020036, 1020042, 1020044, 1020046, 1020048, 1020050,
        1020108, 1020110],
    "depends on the third-party library / Node.js version in use": [
        1020324, 1020328, 1020330, 1020332, 1020334, 1020336, 1020338, 1020744, 1020746, 1020750, 1020758,
        1020760, 1020762, 1020764, 1020766, 1020768, 1020770, 1020784, 1020786, 1020788, 1020904, 1020906,
        1020908, 1020910, 1020912, 1020914, 1020916, 1020918, 1020924],
    "design / call-graph / data-flow semantics": [
        1020062, 1020064, 1020202, 1020204, 1020450, 1020856, 1020542, 1020546, 1020552,
        1020722, 1020900, 1020748, 1020774, 1020776, 1020778, 1020816, 1020824, 1020810, 2121112],
    "other (framework config / deleted rule)": [1039106, 1060116],
}
MANUAL = {c: [i for i in ids if str(i) not in RULES] for c, ids in MANUAL.items()}
MANUAL_BY_ID = {str(i): c for c, ids in MANUAL.items() for i in ids}
