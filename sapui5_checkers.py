"""
SAPUI5 checkers (CAST extension com.castsoftware.sapui5, rules 1020600-1020618).

Same contract as abap_checkers.py: chk(ctx, line_no) -> (verdict, reason, evidence).
CAST publishes only the rule NAMES, so the rule semantics below are inferred from the
names and from SAPUI5 documentation. Anything ambiguous returns REVIEW, never a guess.

JsCtx keeps three views of a file (same line numbers):
  raw   original text
  code  comments blanked, string contents kept   (to read literals such as "/Products(1)")
  bare  comments blanked, string contents masked (to match code structure only)
"""
import json
import re

TP, FP, RV = "TRUE_POSITIVE", "FALSE_POSITIVE", "REVIEW"
NOLINE = (RV, "Reported line is outside the file (source may differ from the analyzed version)", "")


def _strip_js(text, line_comments=True):
    c, b, state, i, n = [], [], None, 0, len(text)
    while i < n:
        ch, nx = text[i], (text[i + 1] if i + 1 < n else "")
        if state is None:
            if line_comments and ch == "/" and nx == "/":
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
        else:  # inside a string literal
            if ch == "\\":
                c.append(ch + nx); b.append("_" + ("\n" if nx == "\n" else "_")); i += 2; continue
            if ch == state or (ch == "\n" and state != "`"):
                c.append(ch); b.append(ch); state = None
            else:
                c.append(ch); b.append("_" if ch != "\n" else ch)
        i += 1
    return "".join(c).split("\n"), "".join(b).split("\n")


def _strip_markup(text):
    t = re.sub(r"<!--.*?-->", lambda m: re.sub(r"[^\n]", " ", m.group(0)), text, flags=re.S)
    return t.split("\n"), t.split("\n")


class JsCtx:
    def __init__(self, lines, kind="js"):
        self.raw, self.kind = [l.rstrip("\r\n") for l in lines], kind
        text = "\n".join(self.raw)
        if kind == "js":
            self.code, self.bare = _strip_js(text)
        elif kind == "css":
            self.code, self.bare = _strip_js(text, line_comments=False)
        elif kind in ("html", "xml"):
            self.code, self.bare = _strip_markup(text)
        else:                                    # json: no comments
            self.code = self.bare = self.raw
        self._aliases = None

    def ok(self, n):
        return 1 <= n <= len(self.raw)

    def span(self, n, maxl=12):
        """Statement around line n: lines until brackets balance. Returns (code, bare, first, last)."""
        j, depth, pc, pb = n - 1, 0, [], []
        while j < min(len(self.raw), n - 1 + maxl):
            pc.append(self.code[j]); pb.append(self.bare[j])
            depth += sum(pb[-1].count(x) for x in "([") - sum(pb[-1].count(x) for x in ")]")
            if depth <= 0:
                break
            j += 1
        return " ".join(pc), " ".join(pb), n, min(j + 1, len(self.raw))

    def ev(self, a, z=None):
        z = z or a
        return " ".join(" ".join(l.split()) for l in self.raw[a - 1:z])[:400]

    def aliases(self):
        """module alias -> module path from sap.ui.define/require([...], function(a, b) ...)."""
        if self._aliases is None:
            self._aliases, text = {}, "\n".join(self.code)
            for m in re.finditer(r"sap\.ui\.(?:define|require)\s*\(\s*(?:[\"'][^\"']*[\"']\s*,\s*)?\[(.*?)\]\s*,\s*function\s*\(([^)]*)\)",
                                 text, re.S):
                deps = re.findall(r"[\"']([^\"']+)[\"']", m.group(1))
                names = [x.strip() for x in m.group(2).split(",") if x.strip()]
                self._aliases.update(dict(zip(names, deps)))
        return self._aliases


CONTROL_PATH = re.compile(r"^sap/(m|f|uxap|tnt|suite)/|^sap/ui/(layout|table|commons|unified|ux3)/")
CONTROL_NS = r"sap\.(?:m|f|uxap|tnt|ui\.layout|ui\.table|ui\.commons|ui\.unified)\.[A-Z]\w*"


def _where(ctx, a, z, rx_bare, rx_str=None):
    """'code' | 'string' | 'comment' | None for a pattern over lines a..z."""
    bare, code, raw = (" ".join(x[a - 1:z]) for x in (ctx.bare, ctx.code, ctx.raw))
    if re.search(rx_bare, bare):
        return "code"
    if re.search(rx_str or rx_bare, code):
        return "string" if rx_str is None else "code"
    if re.search(rx_bare, raw) or (rx_str is not None and re.search(rx_str, raw)):
        return "comment"
    return None


def _no_match(w, label):
    if w == "string":
        return FP, f"{label} appears only inside a string literal, not as code"
    if w == "comment":
        return FP, f"{label} appears only in a comment"
    return FP, f"No {label} at the reported line (source may differ from the analyzed version)"


def keyword(rx_bare, label, rx_str=None):
    def chk(ctx, n):
        if not ctx.ok(n):
            return NOLINE
        _, _, a, z = ctx.span(n)
        w = _where(ctx, a, z, rx_bare, rx_str)
        if w == "code":
            return TP, f"{label} found at line {n}", ctx.ev(a, z)
        v, why = _no_match(w, label)
        return v, why, ctx.ev(a, z)
    return chk


# ---- 1020600 / 1020602 / 1020614 / 1020618 : simple API usages --------------------------------
chk_jquery_sap = keyword(r"(?<![\w$.])(?:jQuery|\$)\.sap\.[A-Za-z_]", "jQuery.sap.* usage",
                         r"[\"']jquery\.sap\.[\w.]+[\"']")
chk_odata_v1 = keyword(r"sap\.ui\.model\.odata\.ODataModel\b", "deprecated sap.ui.model.odata.ODataModel",
                       r"[\"']sap/ui/model/odata/ODataModel[\"']|[\"']sap\.ui\.model\.odata\.ODataModel[\"']")
chk_storage_local = keyword(r"(?<![\w$.])(?:jQuery|\$)\.sap\.storage\.Type\.local\b",
                            "jQuery.sap.storage.Type.local")


def chk_console_log(ctx, n):                                        # 1020614
    if not ctx.ok(n):
        return NOLINE
    _, bare, a, z = ctx.span(n)
    if re.search(r"(?<![\w$.])console\s*\.\s*log\s*\(", bare):
        return TP, "console.log call: use sap/base/Log instead", ctx.ev(a, z)
    m = re.search(r"(?<![\w$.])console\s*\.\s*(warn|error|info|debug|trace)\s*\(", bare)
    if m:
        return RV, f"console.{m.group(1)} (not console.log): the rule text only names console.log", ctx.ev(a, z)
    v, why = _no_match(_where(ctx, a, z, r"console\s*\.\s*log\s*\("), "console.log")
    return v, why, ctx.ev(a, z)


# ---- helpers for argument parsing ---------------------------------------------------------------
def first_arg(code, bare, start):
    depth, k = 0, start
    while k < len(bare):
        ch = bare[k]
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            if depth == 0:
                break
            depth -= 1
        elif ch == "," and depth == 0:
            break
        k += 1
    return code[start:k].strip()


def assigned_value(ctx, var, n, back=20):
    for j in range(n - 1, max(0, n - back) - 1, -1):
        m = re.search(r"(?:var|let|const)?\s*" + re.escape(var) + r"\s*=\s*(?!=)(.*)", ctx.code[j - 1] if j > 0 else "")
        if m and j - 1 >= 0 and ctx.code[j - 1].strip():
            return m.group(1), j
    return None, None


# ---- 1020604 Avoid unnamed OData model ----------------------------------------------------------
ODATA_CLASS = re.compile(r"ODataModel", re.I)
OTHER_MODEL = re.compile(r"JSONModel|ResourceModel|XMLModel|ODataV4|BindingMode|Device", re.I)


def chk_unnamed_model(ctx, n):
    if not ctx.ok(n):
        return NOLINE
    if ctx.kind == "json":
        line = ctx.code[n - 1]
        if not re.match(r'\s*""\s*:\s*\{?', line):
            return RV, 'Expected a model declared with the empty name "" in manifest.json', ctx.ev(n)
        body, depth = [], 0
        for j in range(n - 1, min(len(ctx.code), n + 25)):
            body.append(ctx.code[j]); depth += ctx.code[j].count("{") - ctx.code[j].count("}")
            if depth <= 0 and j > n - 1 or (depth <= 0 and "{" in ctx.code[j]):
                break
        txt = " ".join(body)
        if re.search(r"dataSource|odata", txt, re.I):
            return TP, 'OData model registered under the empty name "" (default, unnamed model)', ctx.ev(n, n + len(body) - 1)
        if OTHER_MODEL.search(txt):
            return FP, "The unnamed model is not an OData model (JSON/Resource/XML model)", ctx.ev(n, n + len(body) - 1)
        return RV, "Unnamed model; its type is not visible", ctx.ev(n, n + len(body) - 1)
    code, bare, a, z = ctx.span(n)
    m = re.search(r"\.setModel\s*\(", bare)
    if not m:
        return RV, "Expected a setModel(...) call at the reported line", ctx.ev(a, z)
    arg1 = first_arg(code, bare, m.end())
    rest = bare[m.end() + len(arg1):].lstrip()
    if rest.startswith(","):
        return FP, "setModel is called with a model name as second argument (named model)", ctx.ev(a, z)
    cls = re.match(r"new\s+([\w.$]+)", arg1)
    if cls:
        name = cls.group(1)
    else:
        val, _ = assigned_value(ctx, arg1, n) if re.fullmatch(r"[\w$.]+", arg1) else (None, None)
        nm = re.match(r"\s*new\s+([\w.$]+)", val or "")
        name = nm.group(1) if nm else None
        if name is None and val and re.search(r"getModel\s*\(", val):
            return RV, "The model comes from getModel(); its type is not visible here", ctx.ev(a, z)
    if name is None:
        return RV, f"Cannot determine the type of model '{arg1}' from this file", ctx.ev(a, z)
    mod = ctx.aliases().get(name.split(".")[0], "")
    if ODATA_CLASS.search(name) or ODATA_CLASS.search(mod):
        return TP, f"OData model ({name}) set as the default model without a name", ctx.ev(a, z)
    if OTHER_MODEL.search(name) or OTHER_MODEL.search(mod):
        return FP, f"The unnamed model is a {name}, not an OData model", ctx.ev(a, z)
    return RV, f"Model class {name} is not recognised as OData or non-OData", ctx.ev(a, z)


# ---- 1020606 Prefer asynchronous loading --------------------------------------------------------
def chk_async(ctx, n):
    if not ctx.ok(n):
        return NOLINE
    if ctx.kind in ("html", "xml"):
        win = " ".join(ctx.code[max(0, n - 4):n + 8])
        m = re.search(r"<script[^>]*sap-ui-core[^>]*>", win, re.I)
        if not m:
            return RV, "Expected the sap-ui-core bootstrap <script> tag near the reported line", ctx.ev(n)
        tag = m.group(0)
        if re.search(r"data-sap-ui-async\s*=\s*[\"']?true|data-sap-ui-preload\s*=\s*[\"']async", tag, re.I):
            return FP, "The bootstrap enables asynchronous loading (data-sap-ui-async / preload=async)", ctx.ev(n)
        return TP, "UI5 bootstrap without data-sap-ui-async=\"true\": modules and libraries load synchronously", ctx.ev(n)
    if ctx.kind == "json":
        body, depth = [], 0
        for j in range(n - 1, min(len(ctx.code), n + 30)):
            body.append(ctx.code[j]); depth += ctx.code[j].count("{") - ctx.code[j].count("}")
            if depth <= 0:
                break
        txt = " ".join(body)
        if re.search(r"\"async\"\s*:\s*true", txt):
            return FP, '"async": true is set', ctx.ev(n, n + len(body) - 1)
        if re.search(r"\"async\"\s*:\s*false", txt):
            return TP, '"async": false forces synchronous loading', ctx.ev(n, n + len(body) - 1)
        if re.search(r"\"(rootView|routing|config)\"", ctx.code[n - 1]):
            return TP, 'No "async": true in rootView / routing config (default is synchronous)', ctx.ev(n, n + len(body) - 1)
        return RV, "Expected rootView / routing / config in manifest.json", ctx.ev(n)
    code, bare, a, z = ctx.span(n)
    if re.search(r"async\s*:\s*true|\bXMLView\.create\s*\(|\bFragment\.load\s*\(|sap\.ui\.require\s*\(\s*\[", bare) or \
            re.search(r"loadLibrary\s*\([^)]*,\s*(true|\{\s*async)", code):
        return FP, "The call uses the asynchronous API (async: true / create / load / require([...]))", ctx.ev(a, z)
    sync = re.search(r"sap\.ui\.requireSync\s*\(|jQuery\.sap\.require\s*\(|sap\.ui\.(?:xml|js|html)?view\s*\(|"
                     r"sap\.ui\.controller\s*\(|loadLibrary\s*\(|sap\.ui\.require\s*\(\s*[\"'`]", bare)
    if sync:
        return TP, f"Synchronous loading API: {sync.group(0).strip()}", ctx.ev(a, z)
    return RV, "No recognisable sync/async loading call at the reported line", ctx.ev(a, z)


# ---- 1020608 Hardcoded control IDs --------------------------------------------------------------
def chk_hardcoded_id(ctx, n):
    if not ctx.ok(n):
        return NOLINE
    code, bare, a, z = ctx.span(n)
    al = ctx.aliases()
    ctrl_alias = {k for k, v in al.items() if CONTROL_PATH.match(v)}
    hits = []
    if re.search(r"(?:sap\.ui\.getCore\(\)|\bCore)\s*\.\s*byId\s*\(\s*[\"'`]", bare):
        hits.append("sap.ui.getCore().byId with a literal ID")
    if re.search(r"getElementById\s*\(\s*[\"'`]|(?:\$|jQuery)\s*\(\s*[\"'`]#", bare):
        hits.append("DOM lookup by literal ID")
    for m in re.finditer(r"new\s+([\w$.]+)\s*\(\s*([\"'`]|\{[^}]*?\bid\s*:\s*[\"'`])", bare):
        cls = m.group(1)
        if re.fullmatch(CONTROL_NS, cls) or cls in ctrl_alias:
            hits.append(f"new {cls}(...) created with a hard-coded ID")
    if re.search(r"__(?:xml)?view\d+--", code):
        hits.append("generated view-prefixed ID typed by hand")
    if hits:
        return TP, "Hard-coded control ID: " + "; ".join(hits), ctx.ev(a, z)
    if re.search(r"(?:this|oView|that|_this)\s*\.\s*(?:getView\(\)\s*\.\s*)?byId\s*\(|\.createId\s*\(", bare):
        return FP, "View-scoped lookup (byId / createId): the ID is prefixed by the view ID, so it is not a global hard-coded ID", ctx.ev(a, z)
    return FP, "No hard-coded control ID pattern at the reported line (source may differ from the analyzed version)", ctx.ev(a, z)


# ---- 1020610 Same OData model declared twice ----------------------------------------------------
def chk_dup_model(ctx, n):
    if not ctx.ok(n):
        return NOLINE
    if ctx.kind == "json":
        try:
            data = json.loads("\n".join(ctx.code))
        except ValueError:
            return RV, "manifest.json is not valid JSON, duplicates cannot be computed", ctx.ev(n)
        models = (data.get("sap.ui5") or {}).get("models") or {}
        srcs = (data.get("sap.app") or {}).get("dataSources") or {}
        m = re.match(r'\s*"([^"]*)"\s*:', ctx.code[n - 1])
        key = m.group(1) if m else None
        byds, byuri = {}, {}
        for k, v in models.items():
            byds.setdefault((v or {}).get("dataSource"), []).append(k)
        for k, v in srcs.items():
            byuri.setdefault((v or {}).get("uri"), []).append(k)
        for groups, kind in (([g for d, g in byds.items() if d and len(g) > 1], "models using the same dataSource"),
                             ([g for d, g in byuri.items() if d and len(g) > 1], "dataSources with the same URI")):
            for g in groups:
                if key in g:
                    return TP, f"Declared twice: {kind}: {', '.join(repr(x) for x in g)}", ctx.ev(n)
        return RV, "No duplicate model/dataSource found in this manifest; duplicates in other files are not visible", ctx.ev(n)
    code, bare, a, z = ctx.span(n)
    if not re.search(r"ODataModel\s*\(", bare) and not re.search(r"ODataModel", " ".join(ctx.bare[a - 1:z])):
        return RV, "Expected an OData model creation at the reported line", ctx.ev(a, z)
    um = re.search(r"ODataModel\s*\(\s*(?:\{[^}]*?serviceUrl\s*:\s*)?([\"'`][^\"'`]+[\"'`])", code)
    if not um:
        return RV, "The service URL is not a literal; duplicates cannot be detected", ctx.ev(a, z)
    url = um.group(1)
    text = "\n".join(ctx.code)
    lines = sorted({text[:m.start()].count("\n") + 1 for m in re.finditer(
        r"ODataModel\s*\(\s*(?:\{[^}]*?serviceUrl\s*:\s*)?" + re.escape(url), text)})
    if len(lines) > 1:
        return TP, f"The OData service {url} is instantiated {len(lines)} times (lines {', '.join(map(str, lines))})", ctx.ev(a, z)
    return RV, f"{url} is instantiated once in this file; a second declaration in another file is not visible", ctx.ev(a, z)


# ---- 1020612 Don't override or add control methods ----------------------------------------------
def chk_override(ctx, n):
    if not ctx.ok(n):
        return NOLINE
    code, bare, a, z = ctx.span(n)
    al = ctx.aliases()
    m = re.search(r"([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)\.prototype\.([\w$]+)\s*=", bare)
    if m:
        root = m.group(1).split(".")[0]
        if root == "sap" or al.get(root, "").startswith("sap/"):
            return TP, f"{m.group(1)}.prototype.{m.group(2)} is overwritten on a UI5 class", ctx.ev(a, z)
        return FP, f"{m.group(1)}.prototype.{m.group(2)} belongs to the application's own class, not a UI5 control", ctx.ev(a, z)
    im = re.search(r"(?<![\w$.])([A-Za-z_$][\w$]*)\.([\w$]+)\s*=\s*function", bare)
    if im:
        val, _ = assigned_value(ctx, im.group(1), n, 40)
        cls = re.match(r"\s*new\s+([\w$.]+)", val or "")
        if cls:
            c = cls.group(1)
            if re.fullmatch(CONTROL_NS, c) or CONTROL_PATH.match(al.get(c.split(".")[0], "")):
                return TP, f"Method {im.group(2)} is added/overridden on the control instance {im.group(1)} ({c})", ctx.ev(a, z)
            return FP, f"{im.group(1)} is an instance of {c}, not a UI5 control", ctx.ev(a, z)
        return RV, f"Cannot tell whether '{im.group(1)}' is a UI5 control", ctx.ev(a, z)
    return FP, "No prototype or instance method assignment at the reported line", ctx.ev(a, z)


# ---- 1020616 Create keys for CRUD statements ----------------------------------------------------
def chk_crud_keys(ctx, n):
    if not ctx.ok(n):
        return NOLINE
    code, bare, a, z = ctx.span(n)
    m = re.search(r"([\w$.()\s]*?)\.\s*(create|update|remove|delete)\s*\(", bare)
    if not m:
        return RV, "Expected an OData create/update/remove call at the reported line", ctx.ev(a, z)
    recv, op = m.group(1), m.group(2)
    if not re.search(r"model|odata", recv, re.I) and not re.search(r"getModel\s*\(", recv):
        return RV, f"The receiver '{recv.strip()}' is not recognisably an OData model", ctx.ev(a, z)
    arg = first_arg(code, bare, m.end())
    if "createKey" in arg:
        return FP, "The entity path is built with oModel.createKey()", ctx.ev(a, z)
    if arg[:1] in "\"'`":
        barearg = first_arg(bare, bare, m.end())
        if "(" in barearg or "(" in arg:
            how = "concatenated by hand" if ("+" in barearg or "${" in arg) else "hard-coded"
            return TP, f"Entity key is {how} in the path {arg[:60]} instead of using createKey()", ctx.ev(a, z)
        if op == "create":
            return FP, "create() on an entity set path needs no key", ctx.ev(a, z)
        return RV, f"{op}() on a path without key: confirm", ctx.ev(a, z)
    if re.fullmatch(r"[\w$.]+", arg):
        val, ln = assigned_value(ctx, arg, n)
        if val is None:
            return RV, f"Path variable '{arg}' is not assigned in the preceding lines", ctx.ev(a, z)
        if "createKey" in val:
            return FP, f"Path '{arg}' comes from createKey() (line {ln})", ctx.ev(ln, z)
        if re.search(r"getPath\s*\(|getBindingContext|getProperty\s*\(", val):
            return FP, f"Path '{arg}' is taken from a binding context (line {ln})", ctx.ev(ln, z)
        if re.search(r"[\"'`].*\(.*[\"'`]\s*\+|\$\{", val):
            return TP, f"Path '{arg}' is built by concatenating a key by hand (line {ln})", ctx.ev(ln, z)
        return RV, f"Path '{arg}' built in a way that is not recognised (line {ln})", ctx.ev(ln, z)
    return RV, "Path expression is not recognised", ctx.ev(a, z)


RULES = {}
for _id, _name, _fn in [
    (1020600, 'Avoid using namespace "jQuery.sap.*" as deprecated (SAPUI5)', chk_jquery_sap),
    (1020602, 'Avoid using "sap.ui.model.odata.ODataModel" as deprecated in version SAPUI5 1.48', chk_odata_v1),
    (1020604, "Avoid unnamed OData model", chk_unnamed_model),
    (1020606, "Prefer using Asynchronous Loading", chk_async),
    (1020608, "Avoid using Controls Hardcoded IDs inside a Controller, Component or JSView (SapUI5)", chk_hardcoded_id),
    (1020610, "Avoid declaring same OData model twice", chk_dup_model),
    (1020612, "Don't override or add control methods (SAPUI5)", chk_override),
    (1020614, "Prefer using sap.base.Log Instead of console.log (SAPUI5)", chk_console_log),
    (1020616, "Create Keys for CRUD Statements (SAPUI5)", chk_crud_keys),
    (1020618, 'Avoid using "jQuery.sap.storage.Type.local"', chk_storage_local),
]:
    RULES[str(_id)] = (_name, _fn)


def kind_of(path):
    s = str(path).lower()
    return ("json" if s.endswith(".json") else "html" if s.endswith((".html", ".htm", ".vue", ".cshtml", ".jsp")) else
            "xml" if s.endswith(".xml") else "css" if s.endswith((".css", ".scss", ".less")) else "js")
