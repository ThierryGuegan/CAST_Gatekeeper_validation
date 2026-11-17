"""
Minimal client for the CAST Dashboard (Engineering) REST API, used to read violations without the
Gatekeeper MCP server (which needs CAST Imaging >= 3.6.4).

Endpoints used (REST API reference, "Engineering Resources" / "Application Structure Resources"):
  GET {rest}/{Domain}/applications                                       -> applications (href, name, snapshots.href)
  GET {application}/snapshots                                            -> snapshots (href, number, annotation.date)
  GET {snapshot}/violations?rule-pattern=<id>&startRow=<n>&nbRows=<n>    -> violations
        each: component{href,name,sourceCodes.href}, rulePattern.href, diagnosis.findings.href
  GET <diagnosis.findings.href>                                          -> findings of one violation
  GET <component.sourceCodes.href>                                       -> source code fragments of the component

  GET <file.href>                                                        -> the analysed source file (text/plain)

All `href` values are relative to {rest} (the server's "/rest/" root). Authentication is either HTTP Basic
(user + password) or an API key (X-API-KEY + X-API-USER headers).

Only the shape of the violations list is documented in the pages this was written from. The JSON returned by
`source-codes` and `findings` is read generically: any object carrying a start line and a file is a location.
Use `gatekeeper_validate.py --dump` to see what your server really returns.
"""
import base64
import json
import os
import re
import tempfile
import urllib.error
import urllib.parse
import urllib.request


class RestError(Exception):
    pass


class DashboardClient:
    def __init__(self, rest_url, domain, user=None, password=None, api_key=None, api_user=None, timeout=60):
        self.base = rest_url.rstrip("/") + "/"
        self.domain = domain.strip("/")
        self.timeout = timeout
        self.headers = {"Accept": "application/json", "X-Client": "gatekeeper_validate"}
        if api_key:
            if not (api_user or user):
                raise RestError("An API key needs a user name too (--api-user): the REST API takes the role from X-API-USER")
            self.headers["X-API-KEY"] = api_key
            self.headers["X-API-USER"] = api_user or user
        elif user:
            token = base64.b64encode(f"{user}:{password or ''}".encode("utf-8")).decode("ascii")
            self.headers["Authorization"] = f"Basic {token}"
        else:
            raise RestError("No credentials: give --user and --password (Basic), or --api-key and --api-user")

    def url(self, path, params=None):
        u = path if re.match(r"https?://", path) else urllib.parse.urljoin(self.base, path.lstrip("/"))
        if params:
            u += ("&" if "?" in u else "?") + urllib.parse.urlencode(params)
        return u

    def get(self, path, params=None):
        u = self.url(path, params)
        req = urllib.request.Request(u, headers=self.headers)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                body = r.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            hint = {401: "check the credentials", 403: "the user/API key has no access to this domain or application",
                    404: "check --rest-url and --domain (the path must end with the server's /rest/ root)"}.get(e.code, "")
            raise RestError(f"HTTP {e.code} on {u}" + (f" ({hint})" if hint else "") +
                            f": {e.read().decode('utf-8', 'replace')[:200]}") from None
        except urllib.error.URLError as e:
            raise RestError(f"Cannot reach {u}: {e.reason}") from None
        try:
            return json.loads(body)
        except json.JSONDecodeError:
            raise RestError(f"Not JSON from {u}: {body[:200]!r}") from None

    def get_text(self, path, params=None):
        u = self.url(path, params)
        req = urllib.request.Request(u, headers={**self.headers, "Accept": "text/plain, */*"})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                return r.read()
        except urllib.error.HTTPError as e:
            raise RestError(f"HTTP {e.code} on {u}") from None
        except urllib.error.URLError as e:
            raise RestError(f"Cannot reach {u}: {e.reason}") from None

    def download(self, file_href, name=None, cache_dir=None):
        """Download a source file (GET <file.href>, text/plain) once and return its local Path.
        The server copy is the analysed version, so line numbers match the violations exactly."""
        if not hasattr(self, "_files"):
            self._files = {}
            self._dir = cache_dir or tempfile.mkdtemp(prefix="gatekeeper_src_")
        if file_href not in self._files:
            os.makedirs(self._dir, exist_ok=True)
            base = re.split(r"[\\/]", name or "")[-1] or "file"
            dest = os.path.join(self._dir, f"{file_href.rstrip('/').split('/')[-1]}_{base}")
            with open(dest, "wb") as f:
                f.write(self.get_text(file_href))
            self._files[file_href] = dest
        return self._files[file_href]

    # ---- applications / snapshots ----------------------------------------------------------------
    def find_application(self, name):
        apps = _as_list(self.get(f"{self.domain}/applications"))
        for a in apps:
            if str(a.get("name", "")).casefold() == name.casefold():
                return a
        raise RestError(f"Application '{name}' not found in domain '{self.domain}'. Available: "
                        + ", ".join(sorted(str(a.get("name")) for a in apps)))

    def find_snapshot(self, app, spec="latest"):
        href = (app.get("snapshots") or {}).get("href") or f"{app['href']}/snapshots"
        snaps = _as_list(self.get(href))
        if not snaps:
            raise RestError(f"Application '{app.get('name')}' has no snapshot")
        if str(spec).lower() == "latest":
            return max(snaps, key=lambda s: ((((s.get("annotation") or {}).get("date") or {}).get("time")) or 0,
                                               _num(s.get("number"))))
        for s in snaps:
            if str(s.get("number")) == str(spec) or str(s.get("href", "")).rstrip("/").endswith("/" + str(spec)):
                return s
        raise RestError(f"Snapshot '{spec}' not found. Available numbers: "
                        + ", ".join(str(s.get("number")) for s in snaps))

    # ---- violations ------------------------------------------------------------------------------
    def iter_violations(self, snapshot, rule_id, limit=None, page=100):
        start = 1
        got = 0
        while limit is None or got < limit:
            n = page if limit is None else min(page, limit - got)
            batch = _as_list(self.get(f"{snapshot['href']}/violations",
                                      {"rule-pattern": rule_id, "startRow": start, "nbRows": n}))
            if not batch:
                return
            for v in batch:
                got += 1
                yield v
            if len(batch) < n:
                return
            start += len(batch)

    def raw_for_violation(self, v):
        """The three documents a violation location can come from (for --dump)."""
        out = {"violation": v}
        for key, href in (("findings", _href(v, "diagnosis", "findings")),
                          ("source-codes", _href(v, "component", "sourceCodes"))):
            if href:
                try:
                    out[key] = self.get(href)
                except RestError as e:
                    out[key] = f"<{e}>"
        return out

    def locations(self, v):
        """Return [(file, line, file_href)] for one violation: findings first (violation-specific lines), then the
        component's own source code. An empty list means the server gave no location."""
        for href in (_href(v, "diagnosis", "findings"), _href(v, "component", "sourceCodes")):
            if not href:
                continue
            try:
                locs = dedupe(extract_locations(self.get(href)))
            except RestError:
                continue
            if locs:
                return locs
        return []


# ---- helpers --------------------------------------------------------------------------------------
def _as_list(x):
    if isinstance(x, list):
        return x
    if isinstance(x, dict):
        for val in x.values():
            if isinstance(val, list):
                return val
    return []


def _num(x):
    try:
        return int(x)
    except (TypeError, ValueError):
        return 0


def _href(d, *keys):
    for k in keys:
        d = d.get(k) if isinstance(d, dict) else None
    if isinstance(d, dict):
        d = d.get("href")
    return d if isinstance(d, str) else None


def _file_of(node):
    """(file name or path, file href or None) of an object that describes a file."""
    f = node.get("file")
    if isinstance(f, dict):
        for k in ("path", "fullName", "name"):
            if f.get(k):
                return str(f[k]), (f.get("href") if isinstance(f.get("href"), str) else None)
        return None, None
    if isinstance(f, str):
        return f, None
    for k in ("filePath", "file_path", "path", "fileName", "filename"):
        if isinstance(node.get(k), str) and node[k]:
            return node[k], None
    return None, None


def extract_locations(node):
    """Yield (file, line, file_href) for every object that has a start line and a file, anywhere in the JSON."""
    if isinstance(node, list):
        for x in node:
            yield from extract_locations(x)
    elif isinstance(node, dict):
        line = next((node[k] for k in ("startLine", "start_line", "line") if node.get(k) not in (None, "")), None)
        f, href = _file_of(node)
        if line is not None and f and re.match(r"\s*\d+", str(line)):
            yield f, int(re.match(r"\s*(\d+)", str(line)).group(1)), href
        for v in node.values():
            if isinstance(v, (list, dict)):
                yield from extract_locations(v)


def dedupe(items):
    seen, out = set(), []
    for it in items:
        if it[:2] not in seen:
            seen.add(it[:2])
            out.append(it)
    return out


def component_name(v):
    c = v.get("component") if isinstance(v, dict) else None
    return (c or {}).get("name") if isinstance(c, dict) else None
