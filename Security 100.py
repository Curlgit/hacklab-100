#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
100X Ethical 

Defensive / authorized security testing utilities for Android Termux and Linux.
Standard library only. No root required. See README.md for scope and limits.

Feature kinds:
  real       performs the described check/computation on real input
  limited    heuristic or partial coverage (clearly labelled in output)
  simulated  educational demo on synthetic data; tests NO external target
"""

# =============================================================================
# 1. IMPORTS AND CONSTANTS
# =============================================================================
import argparse
import base64
import datetime
import getpass
import hashlib
import hmac
import html
import inspect
import ipaddress
import json
import math
import os
import platform
import re
import secrets
import shlex
import shutil
import socket
import sqlite3
import ssl
import sys
import tempfile
import textwrap
import threading
import time
import zlib
import urllib.error
import urllib.parse
import urllib.request
from html.parser import HTMLParser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

if sys.version_info < (3, 8):
    sys.exit("Python 3.8 or newer is required.")

APP = "Ethical Hacking Toolkit"
VERSION = "1.0.0"
DISCLAIMER = ("DISCLAIMER: This software is provided for educational and authorized defensive "
              "security testing purposes only. The developer accepts no responsibility for illegal "
              "activity, misuse, or damage caused by use of this software. Users are responsible "
              "for obtaining authorization and complying with applicable laws.")

DEFAULTS = {"timeout": 8.0, "max_bytes": 524288, "budget": 60, "delay": 0.25,
            "verify_tls": True, "max_redirects": 3, "report_dir": "reports"}
SETTINGS = dict(DEFAULTS)
SETTINGS["authorized"] = []          # explicitly authorized external targets (session only)
STATE = {"requests": 0, "last": 0.0}
SESSION = []                         # recorded results (exported only on request)
SNAPSHOTS = {}                       # in-memory directory snapshots
LAB = {"server": None, "port": None, "hits": {}}
USER_AGENT = "EthicalHackingToolkit/%s (+authorized-testing)" % VERSION
SAFE_METHODS = ("GET", "HEAD", "OPTIONS")

CATEGORIES = [
    (1, 10, "HTTP & Website Analysis"), (11, 22, "Security Headers"), (23, 28, "Cookies"),
    (29, 38, "HTML Inspection"), (39, 44, "TLS"), (45, 50, "DNS & IP"),
    (51, 56, "Ports & Local Network"), (57, 62, "API & JSON"), (63, 70, "Local Security Lab"),
    (71, 80, "Hash, Integrity & Logs"), (81, 85, "Input Validation"),
    (86, 90, "Authentication Config"), (91, 95, "Configuration Auditing"),
    (96, 100, "Reporting & Utilities"),
]
NEEDS = ("none", "url", "host", "ip", "hostport", "tls", "text", "textopt", "secret",
         "file", "dir", "path", "hashfile")
NET_NEEDS = ("url", "host", "ip", "hostport", "tls")
KINDS = ("real", "limited", "simulated")


# =============================================================================
# 2. TERMINAL UI AND FORMATTING
# =============================================================================
USE_COLOR = (sys.stdout.isatty() and os.environ.get("NO_COLOR") is None
             and os.environ.get("TERM") != "dumb")
TAGS = {"PASS": ("32", "[PASS]"), "WARN": ("33", "[WARN]"), "FAIL": ("31", "[FAIL]"),
        "INFO": ("36", "[INFO]"), "SIM": ("35", "[SIM] "), "SKIP": ("90", "[SKIP]"),
        "ERR": ("1;31", "[ERR] ")}
_CTRL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f\x9b]")


class UserAbort(Exception):
    """Raised when input is closed (EOF)."""


def c(text, code):
    return "\033[%sm%s\033[0m" % (code, text) if USE_COLOR else str(text)


def clean(s):
    """Strip control characters so remote data cannot inject terminal escapes."""
    return _CTRL.sub("?", str(s))


def width():
    return max(40, min(shutil.get_terminal_size((80, 24)).columns, 100))


def out(msg="", indent=0):
    for line in str(msg).splitlines() or [""]:
        for w in textwrap.wrap(clean(line), width() - indent) or [""]:
            print(" " * indent + w)


def hr(ch="-"):
    print(c(ch * min(width(), 60), "90"))


def banner():
    line = "+" + "-" * 46 + "+"
    print(c(line, "36"))
    print(c("|", "36") + c("  ETHICAL HACKING TOOLKIT  -  100 Features  ".ljust(46), "1;37") + c("|", "36"))
    print(c("|", "36") + ("  Authorized defensive testing only   v%s" % VERSION).ljust(46) + c("|", "36"))
    print(c(line, "36"))


def ask(prompt, default=None):
    suffix = " [%s]" % default if default not in (None, "") else ""
    try:
        s = input(c("%s%s: " % (prompt, suffix), "1")).strip()
    except EOFError:
        raise UserAbort()
    return s if s else (default if default is not None else "")


def ask_secret(prompt):
    try:
        return getpass.getpass("%s (hidden): " % prompt)
    except EOFError:
        raise UserAbort()


class Result:
    """Collects findings. Status never reports success unless a check actually passed."""

    def __init__(self):
        self.lines = []
        self.forced = None

    def add(self, lvl, msg):
        self.lines.append((lvl, clean(msg)))

    def ok(self, m): self.add("PASS", m)
    def warn(self, m): self.add("WARN", m)
    def fail(self, m): self.add("FAIL", m)
    def info(self, m): self.add("INFO", m)
    def sim(self, m): self.add("SIM", m)
    def skip(self, m): self.add("SKIP", m)
    def err(self, m): self.add("ERR", m)

    def status(self):
        if self.forced:
            return self.forced
        present = {lvl for lvl, _ in self.lines}
        infos = sum(1 for lvl, _ in self.lines if lvl == "INFO")
        if "SKIP" in present and infos <= 1 and not present & {"ERR", "FAIL", "WARN", "PASS", "SIM"}:
            return "SKIPPED"
        for lvl, name in (("ERR", "ERROR"), ("FAIL", "FAIL"), ("WARN", "WARN"),
                          ("PASS", "PASS"), ("SIM", "SIMULATED"), ("INFO", "INFO")):
            if lvl in present:
                return name
        return "SKIPPED"


def print_line(lvl, msg):
    code, label = TAGS[lvl]
    parts = textwrap.wrap(msg, width() - 8) or [""]
    print(c(label, code) + " " + parts[0])
    for p in parts[1:]:
        print("       " + p)


# =============================================================================
# 3. INPUT VALIDATION  (helpers + features 81-85)
# =============================================================================
def parse_ip(s):
    try:
        return ipaddress.ip_address(str(s).strip().strip("[]").split("%")[0])
    except ValueError:
        return None


def quick_local(host):
    """Offline check: localhost or a loopback/private/link-local literal IP."""
    h = (host or "").lower().strip("[]")
    if h == "localhost" or h.endswith(".localhost"):
        return True
    ip = parse_ip(h)
    return bool(ip and (ip.is_loopback or ip.is_private or ip.is_link_local))


def validate_hostname(h):
    h = (h or "").strip().lower().strip("[]")
    if not h:
        return False, "empty hostname"
    if parse_ip(h):
        return True, "ip"
    if len(h) > 253:
        return False, "hostname longer than 253 characters"
    try:
        asc = h.encode("idna").decode("ascii")
    except UnicodeError:
        return False, "invalid internationalized hostname"
    for lab in asc.rstrip(".").split("."):
        if not re.fullmatch(r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?", lab):
            return False, "invalid label '%s'" % lab[:20]
    return True, "hostname"


def validate_url(url):
    """Return (ok, normalized_url_or_error, SplitResult)."""
    url = (url or "").strip()
    if not url or len(url) > 2048 or any(ord(ch) < 33 or ord(ch) == 127 for ch in url):
        return False, "URL is empty, too long, or contains spaces/control characters", None
    if "://" not in url:
        try:
            tmp = urllib.parse.urlsplit("//" + url)
        except ValueError:
            return False, "malformed URL", None
        url = ("http://" if quick_local(tmp.hostname) else "https://") + url
    try:
        u = urllib.parse.urlsplit(urllib.parse.urldefrag(url)[0])
        port = u.port
    except ValueError:
        return False, "malformed URL or invalid port", None
    if u.scheme not in ("http", "https"):
        return False, "only http:// and https:// URLs are supported", None
    if u.username or u.password:
        return False, "credentials embedded in URLs are not allowed", None
    if not u.hostname:
        return False, "URL has no hostname", None
    if port is not None and not 1 <= port <= 65535:
        return False, "port out of range", None
    ok, why = validate_hostname(u.hostname)
    if not ok:
        return False, why, None
    return True, u.geturl(), u


def f_email(arg, r):
    s = arg.strip()
    if len(s) > 254:
        r.fail("Longer than 254 characters (RFC 5321 limit)")
        return
    m = re.fullmatch(r"([A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+)@([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)", s)
    if not m:
        r.fail("Not valid e-mail address syntax")
        return
    local, domain = m.groups()
    labels = domain.split(".")
    if len(local) > 64:
        r.fail("Local part longer than 64 characters")
    elif local.startswith(".") or local.endswith(".") or ".." in local:
        r.fail("Local part has leading/trailing/double dots")
    elif any(len(x) > 63 or x.startswith("-") or x.endswith("-") for x in labels):
        r.fail("Domain has an invalid label")
    elif labels[-1].isdigit():
        r.fail("Top-level domain cannot be all digits")
    else:
        r.ok("Address syntax is valid")
    r.info("Syntax check only: mailbox and domain existence are NOT verified.")


def f_url_validate(arg, r):
    ok, res, u = validate_url(arg)
    if not ok:
        r.fail("Rejected: " + res)
        return
    r.ok("URL is well-formed: scheme=%s host=%s port=%s path=%s" % (
        u.scheme, u.hostname, u.port or "default", u.path or "/"))
    if u.scheme == "http":
        r.warn("Plain HTTP: traffic is unencrypted")
    if quick_local(u.hostname):
        r.info("Host is local/private: the safe client allows it without authorization.")
    elif u.hostname.lower() in authorized_set():
        r.info("Host is in this session's authorized list.")
    else:
        r.info("Host is external: the safe client will refuse it unless you add it to the "
               "authorized list (feature 99) after confirming you have permission.")


def f_pw_strength(arg, r):
    common = {"password", "123456", "12345678", "qwerty", "abc123", "letmein", "admin", "welcome",
              "iloveyou", "monkey", "dragon", "111111", "password1", "changeme", "123456789",
              "qwerty123", "1q2w3e4r", "admin123", "root", "toor", "login", "passw0rd",
              "football", "master", "sunshine", "princess", "trustno1", "000000", "secret"}
    pw = arg
    pool = 0
    for rx, n in ((r"[a-z]", 26), (r"[A-Z]", 26), (r"[0-9]", 10), (r"[^A-Za-z0-9]", 33)):
        if re.search(rx, pw):
            pool += n
    bits = len(pw) * math.log2(pool) if pool else 0
    r.info("Length %d, estimated max entropy %.0f bits (upper bound; assumes random choice)" % (len(pw), bits))
    if pw.lower() in common:
        r.fail("Matches a very common password")
    if len(pw) < 8:
        r.fail("Shorter than 8 characters")
    elif len(pw) < 12:
        r.warn("8-11 characters: acceptable only with MFA/breach checks; 12+ preferred")
    else:
        r.ok("Length is 12 or more")
    if re.search(r"(.)\1{3,}", pw) or any(sq in pw.lower() for sq in ("abcd", "1234", "qwer", "asdf", "4321")):
        r.warn("Contains repeated characters or an obvious sequence")
    if pool and pool <= 26 + 0:
        r.warn("Uses a single character class")
    r.info("Rating: " + ("weak" if bits < 40 else "fair" if bits < 60 else "good" if bits < 80 else "strong")
           + ". The password was not stored or displayed.")


def f_escape(arg, r):
    r.info("HTML body:      " + html.escape(arg, quote=False))
    r.info("HTML attribute: " + html.escape(arg, quote=True))
    r.info("URL component:  " + urllib.parse.quote(arg, safe=""))
    r.info("JSON string:    " + json.dumps(arg))
    r.info("Shell word:     " + shlex.quote(arg))
    r.ok("Generated context-specific encodings. Always encode for the output context; "
         "never reuse one encoding for another.")


INPUT_PATTERNS = {
    "SQL injection markers": r"('|%27)\s*(or|and)\s+['\d]|union\s+(all\s+)?select|;\s*drop\s+table|--\s*$|sleep\s*\(|benchmark\s*\(",
    "XSS markers": r"<\s*script|javascript:|on(error|load|click|mouseover)\s*=|<\s*iframe|<\s*svg[^>]*on",
    "Path traversal": r"\.\./|\.\.\\|%2e%2e|%252e",
    "Command injection chars": r"[;&|`]\s*\w+|\$\(|\$\{",
    "Null byte / CRLF": r"%00|\x00|%0d%0a|\r\n",
}


def f_susp_input(arg, r):
    hits = [name for name, rx in INPUT_PATTERNS.items() if re.search(rx, arg, re.I)]
    for h in hits:
        r.warn("Matches pattern class: " + h)
    if not hits:
        r.info("No known attack patterns matched. This is a heuristic only, not proof the input is safe.")
    r.info("Real defences are parameterized queries, output encoding and allow-list validation.")


# =============================================================================
# 4. SAFE NETWORK CLIENT
# =============================================================================
def authorized_set():
    env = os.environ.get("TOOLKIT_AUTHORIZED", "")
    return {h.strip().lower() for h in SETTINGS["authorized"] + env.split(",") if h.strip()}


def is_local_addr(a):
    ip = ipaddress.ip_address(a)
    return ip.is_loopback or ip.is_private or ip.is_link_local


def check_target(host):
    """Return (allowed, reason). Allowed: loopback/private hosts or explicitly authorized targets."""
    h = (host or "").strip().lower().strip("[]")
    if not h:
        return False, "empty host"
    if h in authorized_set():
        return True, "explicitly authorized target"
    ip = parse_ip(h)
    if ip:
        if is_local_addr(str(ip)):
            return True, "local/private address"
        return False, "%s is a public address that is not in the authorized list" % h
    if h == "localhost" or h.endswith(".localhost"):
        return True, "localhost"
    private_suffix = h.endswith((".local", ".lan", ".home", ".internal", ".localdomain", ".home.arpa"))
    if "." in h and not private_suffix:
        return False, "'%s' looks like a public name and is not in the authorized list (no lookup was made)" % h
    try:
        addrs = {i[4][0].split("%")[0] for i in socket.getaddrinfo(h, None)}
    except OSError:
        return False, "cannot resolve '%s' (and it is not authorized)" % h
    if addrs and all(is_local_addr(a) for a in addrs):
        return True, "resolves only to private/loopback addresses"
    return False, "'%s' is not local and not in the authorized list" % h


def spend(n=1):
    if STATE["requests"] + n > SETTINGS["budget"]:
        return False
    STATE["requests"] += n
    return True


def throttle():
    wait = SETTINGS["delay"] - (time.time() - STATE["last"])
    if wait > 0:
        time.sleep(wait)
    STATE["last"] = time.time()


BUDGET_MSG = ("Request budget exhausted (%d operations this session). Raise it in Settings "
              "or restart the program.")


def explain_error(e):
    if isinstance(e, urllib.error.URLError) and not isinstance(e, urllib.error.HTTPError):
        return explain_error(e.reason) if isinstance(e.reason, BaseException) else "Network error: %s" % e.reason
    if isinstance(e, ssl.SSLCertVerificationError):
        return ("TLS certificate verification failed: %s (for a local lab with a self-signed "
                "certificate you may disable verification in Settings)" % (e.verify_message or e))
    if isinstance(e, socket.timeout):
        return "Timed out after %.0fs (host down, filtered, or too slow)" % SETTINGS["timeout"]
    if isinstance(e, ConnectionRefusedError):
        return "Connection refused (nothing is listening on that port)"
    if isinstance(e, socket.gaierror):
        return "DNS resolution failed for that hostname"
    if isinstance(e, ssl.SSLError):
        if any(x in str(e).upper() for x in ("WRONG_VERSION_NUMBER", "RECORD_LAYER_FAILURE", "UNKNOWN_PROTOCOL")):
            return "That port does not appear to speak TLS (plain HTTP or another protocol?)"
        return "TLS error: %s" % e
    if isinstance(e, OSError):
        return "Network error: %s" % e
    return "Request failed: %s: %s" % (type(e).__name__, e)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def _opener():
    ctx = ssl.create_default_context()
    if not SETTINGS["verify_tls"]:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect(),
                                       urllib.request.HTTPSHandler(context=ctx))


def _read_limited(rsp, limit):
    deadline = time.time() + SETTINGS["timeout"] * 3
    chunks, total = [], 0
    while total <= limit:
        if time.time() > deadline:
            raise socket.timeout("read deadline exceeded")
        chunk = rsp.read(min(8192, limit + 1 - total))
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
    data = b"".join(chunks)
    return data[:limit], len(data) > limit


_CACHE = {}


def fetch(url, method="GET", headers=None, follow=True, read_body=True, max_bytes=None, cache=True):
    """Safe HTTP client: GET/HEAD/OPTIONS only, validated and authorized targets, size/time/request
    limits, and re-validation of every redirect hop. Never raises; check resp['error']."""
    resp = {"error": None, "status": None, "reason": "", "headers": [], "body": b"",
            "final_url": url, "elapsed": 0.0, "redirects": [], "truncated": False}
    method = method.upper()
    if method not in SAFE_METHODS:
        resp["error"] = "Method %s is not permitted by the safe client" % method
        return resp
    limit = int(max_bytes or SETTINGS["max_bytes"])
    key = (method, url, follow, read_body, limit, tuple(sorted((headers or {}).items())))
    if cache and key in _CACHE and time.time() - _CACHE[key][0] < 30:
        return dict(_CACHE[key][1])
    cur = url
    for hop in range(SETTINGS["max_redirects"] + 1):
        ok, norm, u = validate_url(cur)
        prefix = "Redirect blocked: " if hop else ""
        if not ok:
            resp["error"] = prefix + norm
            return resp
        allowed, why = check_target(u.hostname)
        if not allowed:
            resp["error"] = "%sREFUSED: %s. Only localhost, private labs and explicitly authorized " \
                            "targets may be tested." % (prefix, why)
            return resp
        if not spend():
            resp["error"] = BUDGET_MSG % SETTINGS["budget"]
            return resp
        throttle()
        hdrs = {"User-Agent": USER_AGENT, "Accept": "*/*", "Accept-Encoding": "identity"}
        hdrs.update(headers or {})
        req = urllib.request.Request(norm, method=method, headers=hdrs)
        start = time.time()
        try:
            try:
                rsp = _opener().open(req, timeout=SETTINGS["timeout"])
            except urllib.error.HTTPError as e:
                rsp = e
            try:
                resp["status"] = rsp.getcode()
                resp["reason"] = getattr(rsp, "reason", "") or ""
                resp["headers"] = list(rsp.headers.items())
                resp["final_url"] = norm
                body, trunc = b"", False
                if read_body and method != "HEAD":
                    body, trunc = _read_limited(rsp, limit)
            finally:
                rsp.close()
        except Exception as e:  # noqa: BLE001 - converted to readable message
            resp["error"] = prefix + explain_error(e)
            return resp
        resp["elapsed"] = time.time() - start
        enc = next((v.lower() for k, v in resp["headers"] if k.lower() == "content-encoding"), "")
        if body and enc in ("gzip", "x-gzip", "deflate"):
            try:
                d = zlib.decompressobj(16 + zlib.MAX_WBITS if "gzip" in enc else zlib.MAX_WBITS)
                body = d.decompress(body, limit)
                trunc = trunc or bool(d.unconsumed_tail)
            except zlib.error:
                pass
        resp["body"], resp["truncated"] = body, trunc
        loc = next((v for k, v in resp["headers"] if k.lower() == "location"), None)
        if follow and resp["status"] in (301, 302, 303, 307, 308) and loc:
            nxt = urllib.parse.urljoin(norm, loc)
            resp["redirects"].append((resp["status"], norm, nxt))
            cur = nxt
            continue
        if follow and resp["status"] in (301, 302, 303, 307, 308) and not loc:
            pass
        if cache:
            _CACHE[key] = (time.time(), dict(resp))
        return resp
    resp["error"] = "Too many redirects (limit %d)" % SETTINGS["max_redirects"]
    return resp


def hv(resp, name):
    n = name.lower()
    for k, v in resp["headers"]:
        if k.lower() == n:
            return v
    return None


def hall(resp, name):
    n = name.lower()
    return [v for k, v in resp["headers"] if k.lower() == n]


# =============================================================================
# 5. WEBSITE AND HTTP ANALYSIS  (features 1-10, 29-38)
# =============================================================================
def hdr_resp(url, r, **kw):
    resp = fetch(url, **kw)
    if resp["error"]:
        r.err(resp["error"])
        return None
    r.info("Analyzed HTTP %s from %s" % (resp["status"], resp["final_url"]))
    return resp


def f_status(url, r):
    resp = fetch(url)
    if resp["error"]:
        r.err(resp["error"])
        return
    st = resp["status"]
    r.info("Final URL: " + resp["final_url"])
    r.info("HTTP %s %s in %.0f ms, %d bytes read%s" % (st, resp["reason"], resp["elapsed"] * 1000,
           len(resp["body"]), " (truncated at size limit)" if resp["truncated"] else ""))
    if 200 <= st < 300:
        r.ok("Server returned a success status")
    elif 300 <= st < 400:
        r.warn("Redirect status without a followable Location")
    elif st < 500:
        r.warn("Client error status %d" % st)
    else:
        r.fail("Server error status %d" % st)


def f_headers(url, r):
    resp = hdr_resp(url, r)
    if not resp:
        return
    for k, v in resp["headers"]:
        if k.lower() == "set-cookie":
            v = v.split("=", 1)[0] + "=<value hidden>"
        r.info("%s: %s" % (k, v[:140]))
    r.ok("Retrieved %d response headers" % len(resp["headers"]))


def f_redirects(url, r):
    resp = fetch(url, cache=False)
    for i, (st, a, b) in enumerate(resp["redirects"], 1):
        r.info("Hop %d: %s %s -> %s" % (i, st, a, b))
    if resp["error"]:
        (r.warn if resp["error"].startswith("Redirect blocked") else r.err)(resp["error"])
        return
    chain = resp["redirects"]
    if not chain:
        r.ok("No redirects: the URL answered directly (HTTP %s)" % resp["status"])
        return
    r.info("Final destination: " + resp["final_url"])
    for st, a, b in chain:
        if a.startswith("https://") and b.startswith("http://"):
            r.fail("HTTPS to HTTP downgrade: %s -> %s" % (a, b))
        if urllib.parse.urlsplit(a).hostname != urllib.parse.urlsplit(b).hostname:
            r.info("Cross-host redirect to " + urllib.parse.urlsplit(b).hostname)
    if len(chain) >= 3:
        r.warn("Long redirect chain (%d hops)" % len(chain))
    elif not any("FAIL" == lv for lv, _ in r.lines):
        r.ok("Redirect chain of %d hop(s) with no downgrade" % len(chain))


def f_methods(url, r):
    resp = hdr_resp(url, r, method="OPTIONS", follow=False, cache=False)
    if not resp:
        return
    allow = hv(resp, "allow") or hv(resp, "access-control-allow-methods")
    if not allow:
        r.info("Server did not advertise methods (HTTP %s)" % resp["status"])
        return
    meths = {m.strip().upper() for m in allow.split(",")}
    r.info("Advertised methods: " + ", ".join(sorted(meths)))
    if meths & {"TRACE", "TRACK"}:
        r.fail("TRACE/TRACK advertised (cross-site tracing risk)")
    risky = meths & {"PUT", "DELETE", "CONNECT", "PATCH"}
    if risky:
        r.warn("State-changing methods advertised: " + ", ".join(sorted(risky)) + " (verify they require auth)")
    if not (meths & {"TRACE", "TRACK"}) and not risky:
        r.ok("Only low-risk methods advertised")


def f_banner(url, r):
    resp = hdr_resp(url, r)
    if not resp:
        return
    srv = hv(resp, "server")
    if not srv:
        r.ok("No Server header disclosed")
    elif re.search(r"\d+\.\d+", srv):
        r.warn("Server header reveals product and version: " + srv)
    else:
        r.info("Server header present without version: " + srv)
        r.ok("No version number disclosed")


def f_timing(url, r):
    times = []
    for _ in range(3):
        resp = fetch(url, follow=False, read_body=False, cache=False)
        if resp["error"]:
            r.err(resp["error"])
            return
        times.append(resp["elapsed"] * 1000)
    r.info("Samples (ms): " + ", ".join("%.0f" % t for t in times))
    r.info("min %.0f / avg %.0f / max %.0f ms" % (min(times), sum(times) / 3, max(times)))
    if sum(times) / 3 > 2000:
        r.warn("Average response time above 2 seconds")
    else:
        r.ok("Response time within normal range")


def f_ctype(url, r):
    resp = hdr_resp(url, r)
    if not resp:
        return
    ct = hv(resp, "content-type")
    if not ct:
        r.fail("Content-Type header missing (browsers may sniff content)")
        return
    r.info("Content-Type: " + ct)
    if ct.lower().startswith("text/") and "charset" not in ct.lower():
        r.warn("Text type without explicit charset")
    else:
        r.ok("Content-Type present" + (" with charset" if "charset" in ct.lower() else ""))


def f_compress(url, r):
    resp = hdr_resp(url, r, headers={"Accept-Encoding": "gzip, deflate"}, read_body=False, cache=False)
    if not resp:
        return
    enc = hv(resp, "content-encoding")
    if not enc:
        r.info("Response was not compressed (fine for small or already-compressed content)")
        return
    r.ok("Compression in use: " + enc)
    if "accept-encoding" not in (hv(resp, "vary") or "").lower():
        r.warn("Compressed response lacks 'Vary: Accept-Encoding' (cache poisoning/mix-up risk)")
    r.info("Note: compressing responses that mix secrets and attacker-controlled input can enable BREACH.")


def f_cache(url, r):
    resp = hdr_resp(url, r)
    if not resp:
        return
    cc = (hv(resp, "cache-control") or "").lower()
    if not cc:
        r.warn("No Cache-Control header (caches will guess)")
        return
    r.info("Cache-Control: " + cc)
    if "public" in cc and hall(resp, "set-cookie"):
        r.fail("'public' caching combined with Set-Cookie")
    elif "no-store" in cc:
        r.ok("no-store set (suitable for sensitive pages)")
    elif re.search(r"max-age=\d+|no-cache|private", cc):
        r.ok("Explicit caching policy present")
    else:
        r.warn("Cache-Control present but without an explicit lifetime/policy")


def f_https_upgrade(url, r):
    u = urllib.parse.urlsplit(url)
    host = "[%s]" % u.hostname if ":" in u.hostname else u.hostname
    target = "http://%s%s/" % (host, ":%d" % u.port if (u.scheme == "http" and u.port) else "")
    resp = fetch(target, follow=False, read_body=False, cache=False)
    if resp["error"]:
        if "refused" in resp["error"].lower():
            r.info("No plain-HTTP listener at %s (HTTP not offered)" % target)
        else:
            r.err(resp["error"])
        return
    st, loc = resp["status"], hv(resp, "location") or ""
    r.info("Plain HTTP request to %s -> HTTP %s" % (target, st))
    if st in (301, 302, 303, 307, 308) and loc.lower().startswith("https://"):
        r.ok("HTTP redirects to HTTPS (%s)" % ("permanent" if st in (301, 308) else "temporary"))
    elif st in (301, 302, 303, 307, 308):
        r.warn("Redirects, but not to HTTPS: " + loc[:100])
    elif 200 <= st < 300 and u.scheme == "https":
        r.fail("Content served over HTTP without redirecting to HTTPS")
    else:
        r.info("No HTTPS upgrade evaluated for HTTP %s" % st)
    if quick_local(u.hostname):
        r.info("Local lab host: HTTPS enforcement is normally not expected here.")


# ---- HTML inspection --------------------------------------------------------
class PageScan(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.title, self._t = "", False
        self.metas, self.forms, self.scripts, self.styles = [], [], [], []
        self.anchors, self.resources, self.comments = [], [], []
        self.handlers = self.inline_scripts = 0
        self._form = None

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        self.handlers += sum(1 for k in a if re.fullmatch(r"on[a-z]+", k))
        if tag == "title":
            self._t = True
        elif tag == "meta":
            self.metas.append(a)
        elif tag == "form":
            self._form = {"method": (a.get("method") or "get").lower(), "action": a.get("action", ""),
                          "inputs": []}
            self.forms.append(self._form)
        elif tag in ("input", "select", "textarea") and self._form is not None:
            self._form["inputs"].append({"name": a.get("name", ""), "type": a.get("type", tag).lower(),
                                         "autocomplete": a.get("autocomplete")})
        elif tag == "script":
            if a.get("src"):
                self.scripts.append({"src": a["src"], "integrity": a.get("integrity")})
                self.resources.append(("script", a["src"]))
            else:
                self.inline_scripts += 1
        elif tag == "link" and "stylesheet" in a.get("rel", "").lower():
            self.styles.append({"href": a.get("href", ""), "integrity": a.get("integrity")})
            self.resources.append(("stylesheet", a.get("href", "")))
        elif tag == "a":
            self.anchors.append(a)
        elif tag in ("img", "iframe", "audio", "video", "source", "embed") and a.get("src"):
            self.resources.append((tag, a["src"]))

    def handle_endtag(self, tag):
        if tag == "title":
            self._t = False
        elif tag == "form":
            self._form = None

    def handle_data(self, data):
        if self._t:
            self.title += data

    def handle_comment(self, data):
        self.comments.append(data)


def decode_body(resp):
    m = re.search(r"charset=([\w-]+)", hv(resp, "content-type") or "", re.I)
    for enc in ([m.group(1)] if m else []) + ["utf-8"]:
        try:
            return resp["body"].decode(enc, "replace")
        except LookupError:
            continue
    return resp["body"].decode("utf-8", "replace")


def get_html(url, r):
    resp = hdr_resp(url, r)
    if not resp:
        return None
    ct = (hv(resp, "content-type") or "").lower()
    if "html" not in ct and not resp["body"].lstrip()[:15].lower().startswith((b"<!doctype", b"<html")):
        r.skip("Response is not HTML (Content-Type: %s); HTML checks do not apply." % (ct or "missing"))
        return None
    if resp["truncated"]:
        r.warn("Body truncated at %d bytes; findings cover only the first part." % len(resp["body"]))
    sc = PageScan()
    try:
        sc.feed(decode_body(resp))
        sc.close()
    except Exception as e:  # noqa: BLE001
        r.warn("HTML parser stopped early: %s" % e)
    return resp, sc


def _abs(resp, ref):
    return urllib.parse.urljoin(resp["final_url"], ref)


def _external(resp, ref):
    h = urllib.parse.urlsplit(_abs(resp, ref)).hostname
    return h is not None and h != urllib.parse.urlsplit(resp["final_url"]).hostname


def f_meta(url, r):
    g = get_html(url, r)
    if not g:
        return
    resp, sc = g
    r.info("Title: " + (sc.title.strip()[:100] or "(none)"))
    names = {m.get("name", "").lower(): m.get("content", "") for m in sc.metas if m.get("name")}
    for k in ("description", "generator", "viewport", "robots", "referrer"):
        if k in names:
            r.info("meta %s: %s" % (k, names[k][:100]))
    if re.search(r"\d+\.\d+", names.get("generator", "")):
        r.warn("meta generator discloses a software version")
    else:
        r.ok("Parsed %d meta tags; no version disclosure in meta" % len(sc.metas))


def f_forms(url, r):
    g = get_html(url, r)
    if not g:
        return
    resp, sc = g
    if not sc.forms:
        r.info("No <form> elements found on this page")
        return
    for i, f in enumerate(sc.forms[:15], 1):
        fields = ", ".join("%s(%s)" % (x["name"] or "?", x["type"]) for x in f["inputs"][:12])
        r.info("Form %d: %s %s -> fields: %s" % (i, f["method"].upper(), f["action"] or "(same page)", fields or "none"))
    r.ok("Inventoried %d form(s)" % len(sc.forms))


def f_pw_forms(url, r):
    g = get_html(url, r)
    if not g:
        return
    resp, sc = g
    pf = [f for f in sc.forms if any(x["type"] == "password" for x in f["inputs"])]
    if not pf:
        r.info("No password forms on this page")
        return
    bad = False
    for f in pf:
        dest = _abs(resp, f["action"])
        if dest.startswith("http://"):
            r.fail("Password form submits over plain HTTP: " + dest[:100])
            bad = True
        if f["method"] != "post":
            r.fail("Password form uses GET (credentials end up in URLs/logs)")
            bad = True
        for x in f["inputs"]:
            if x["type"] == "password" and not x["autocomplete"]:
                r.info("Password field '%s' has no autocomplete hint (use current-password/new-password)" % x["name"])
    if not bad:
        r.ok("%d password form(s) use POST over HTTPS" % len(pf))


def f_csrf(url, r):
    g = get_html(url, r)
    if not g:
        return
    resp, sc = g
    posts = [f for f in sc.forms if f["method"] == "post"]
    if not posts:
        r.skip("No POST forms found; nothing to evaluate")
        return
    rx = re.compile(r"csrf|xsrf|authenticity_token|__requestverificationtoken|nonce|_token", re.I)
    for i, f in enumerate(posts, 1):
        hidden = [x["name"] for x in f["inputs"] if x["type"] == "hidden" and rx.search(x["name"])]
        if hidden:
            r.ok("POST form %d has a token-like hidden field (%s)" % (i, hidden[0]))
        else:
            r.warn("POST form %d shows no anti-CSRF token field" % i)
    r.info("Heuristic: tokens may also be sent via headers or covered by SameSite cookies.")


def f_ext_scripts(url, r):
    g = get_html(url, r)
    if not g:
        return
    resp, sc = g
    ext = [s["src"] for s in sc.scripts if _external(resp, s["src"])]
    r.info("%d script tag(s) with src, %d external" % (len(sc.scripts), len(ext)))
    for s in ext[:15]:
        r.info("External: " + _abs(resp, s)[:110])
    if any(_abs(resp, s).startswith("http://") for s in ext):
        r.fail("Script loaded over plain HTTP")
    elif ext:
        r.warn("Third-party scripts run with full page privileges; review each source")
    else:
        r.ok("No external scripts")


def f_sri(url, r):
    g = get_html(url, r)
    if not g:
        return
    resp, sc = g
    items = [("script", s["src"], s["integrity"]) for s in sc.scripts] + \
            [("stylesheet", s["href"], s["integrity"]) for s in sc.styles]
    ext = [(k, u, i) for k, u, i in items if u and _external(resp, u)]
    if not ext:
        r.info("No external scripts or stylesheets to check")
        return
    missing = [(k, u) for k, u, i in ext if not i]
    for k, u in missing[:10]:
        r.warn("No integrity attribute on external %s: %s" % (k, _abs(resp, u)[:90]))
    if not missing:
        r.ok("All %d external resources carry Subresource Integrity" % len(ext))


def f_inline(url, r):
    g = get_html(url, r)
    if not g:
        return
    resp, sc = g
    r.info("Inline <script> blocks: %d; inline event-handler attributes: %d" % (sc.inline_scripts, sc.handlers))
    csp = (hv(resp, "content-security-policy") or "").lower()
    if sc.inline_scripts or sc.handlers:
        if "unsafe-inline" in csp or not csp:
            r.warn("Inline code present and CSP does not block it (XSS impact is higher)")
        else:
            r.info("Inline code exists; confirm the CSP uses nonces/hashes for it")
    else:
        r.ok("No inline scripts or event handlers")


def f_mixed(url, r):
    g = get_html(url, r)
    if not g:
        return
    resp, sc = g
    if not resp["final_url"].startswith("https://"):
        r.skip("Page was served over HTTP; mixed-content check applies to HTTPS pages")
        return
    active = [(k, u) for k, u in sc.resources if k in ("script", "stylesheet", "iframe") and _abs(resp, u).startswith("http://")]
    passive = [(k, u) for k, u in sc.resources if k not in ("script", "stylesheet", "iframe") and _abs(resp, u).startswith("http://")]
    for k, u in active[:8]:
        r.fail("Active mixed content (%s): %s" % (k, u[:90]))
    for k, u in passive[:8]:
        r.warn("Passive mixed content (%s): %s" % (k, u[:90]))
    if not active and not passive:
        r.ok("No http:// subresources found in the HTML")


def f_comments(url, r):
    g = get_html(url, r)
    if not g:
        return
    resp, sc = g
    kws = ("password", "passwd", "secret", "api key", "apikey", "api_key", "token", "todo", "fixme",
           "debug", "admin", "credential", "internal")
    r.info("%d HTML comment(s) found" % len(sc.comments))
    hit = False
    for i, cm in enumerate(sc.comments, 1):
        found = [k for k in kws if k in cm.lower()]
        if found:
            hit = True
            r.warn("Comment %d mentions: %s (content not shown)" % (i, ", ".join(found)))
    if not hit:
        r.ok("No sensitive keywords in HTML comments (keyword heuristic only)")


def f_blank(url, r):
    g = get_html(url, r)
    if not g:
        return
    resp, sc = g
    bad = [a.get("href", "")[:80] for a in sc.anchors
           if a.get("target", "").lower() == "_blank" and not re.search(r"noopener|noreferrer", a.get("rel", ""), re.I)]
    if bad:
        r.warn("%d link(s) use target=_blank without rel=noopener (legacy tab-nabbing risk)" % len(bad))
        for b in bad[:5]:
            r.info("  " + b)
    else:
        r.ok("No target=_blank links lacking rel=noopener/noreferrer")


# =============================================================================
# 6. DNS, IP, TLS, AND NETWORK DIAGNOSTICS  (features 39-56)
# =============================================================================
def _flat(rdns):
    return ", ".join("%s=%s" % (k, v) for rdn in rdns for k, v in rdn)


def tls_handshake(host, port, verify=True, vmin=None, vmax=None):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    if verify:
        ctx.load_default_certs()
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
    else:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    if vmin is not None:
        try:
            ctx.set_ciphers("ALL:@SECLEVEL=0")
        except ssl.SSLError:
            pass
        ctx.minimum_version, ctx.maximum_version = vmin, vmax
    if not spend():
        raise RuntimeError(BUDGET_MSG % SETTINGS["budget"])
    throttle()
    with socket.create_connection((host, port), timeout=SETTINGS["timeout"]) as s:
        with ctx.wrap_socket(s, server_hostname=host) as t:
            return {"version": t.version(), "cipher": t.cipher(), "cert": t.getpeercert() if verify else None}


def tls_verified(arg, r):
    """Verified handshake. On failure add a classified FAIL and return None."""
    host, port = arg
    try:
        return tls_handshake(host, port, True)
    except ssl.SSLCertVerificationError as e:
        msg = e.verify_message or str(e)
        kind = ("expired" if "expired" in msg else "hostname mismatch" if "mismatch" in msg
                else "untrusted/self-signed chain" if ("self" in msg or "issuer" in msg) else "verification error")
        r.fail("Certificate not trusted (%s): %s" % (kind, msg))
    except Exception as e:  # noqa: BLE001
        r.err(explain_error(e) if not isinstance(e, RuntimeError) else str(e))
    return None


def f_tls_cert(arg, r):
    info = tls_verified(arg, r)
    if not info:
        return
    cert = info["cert"]
    r.info("Subject: " + _flat(cert.get("subject", ())))
    r.info("Issuer:  " + _flat(cert.get("issuer", ())))
    r.info("Valid:   %s -> %s" % (cert.get("notBefore"), cert.get("notAfter")))
    r.ok("Certificate chain and hostname verified against the system trust store")


def f_tls_expiry(arg, r):
    info = tls_verified(arg, r)
    if not info:
        return
    exp = ssl.cert_time_to_seconds(info["cert"]["notAfter"])
    days = int((exp - time.time()) // 86400)
    r.info("Certificate expires in %d day(s)" % days)
    if days < 0:
        r.fail("Certificate expired")
    elif days < 14:
        r.fail("Expires in under 14 days")
    elif days < 30:
        r.warn("Expires in under 30 days")
    else:
        r.ok("Sufficient validity remaining")


def f_tls_proto(arg, r):
    host, port = arg
    try:
        info = tls_handshake(host, port, False)
    except Exception as e:  # noqa: BLE001
        r.err(explain_error(e) if not isinstance(e, RuntimeError) else str(e))
        return
    name, proto, bits = info["cipher"]
    r.info("Negotiated: %s, cipher %s (%s bits)" % (info["version"], name, bits))
    r.info("This handshake did not validate the certificate (see features 39-43).")
    if info["version"] == "TLSv1.3":
        r.ok("TLS 1.3 negotiated")
    elif info["version"] == "TLSv1.2":
        r.ok("TLS 1.2 negotiated")
    else:
        r.fail("Legacy protocol negotiated: %s" % info["version"])
    if re.search(r"RC4|3DES|NULL|EXPORT|MD5|DES-CBC", name):
        r.fail("Weak cipher negotiated: " + name)
    elif "CBC" in name:
        r.warn("CBC-mode cipher negotiated; AEAD (GCM/ChaCha20) is preferred")


def f_tls_host(arg, r):
    info = tls_verified(arg, r)
    if info:
        r.ok("Certificate matches '%s' and chains to a trusted root" % arg[0])


def f_tls_san(arg, r):
    info = tls_verified(arg, r)
    if not info:
        return
    sans = [v for k, v in info["cert"].get("subjectAltName", ())]
    r.info("%d subjectAltName entries: %s" % (len(sans), ", ".join(sans[:10]) + (" ..." if len(sans) > 10 else "")))
    if any(s.startswith("*.") for s in sans):
        r.info("Wildcard certificate: a key compromise affects all subdomains")
    if len(sans) > 50:
        r.warn("Very large SAN list (shared certificate across many sites)")
    else:
        r.ok("SAN list present and covers the verified host")


def f_tls_versions(arg, r):
    host, port = arg
    vers = [("TLSv1.0", "TLSv1"), ("TLSv1.1", "TLSv1_1"), ("TLSv1.2", "TLSv1_2"), ("TLSv1.3", "TLSv1_3")]
    accepted = []
    for label, attr in vers:
        try:
            v = getattr(ssl.TLSVersion, attr)
            tls_handshake(host, port, False, v, v)
            accepted.append(label)
            r.info("%s: accepted" % label)
        except (ValueError, AttributeError):
            r.skip("%s: this Python/OpenSSL cannot offer it (not testable)" % label)
        except ssl.SSLError as e:
            if any(x in str(e).upper() for x in ("WRONG_VERSION_NUMBER", "RECORD_LAYER_FAILURE", "UNKNOWN_PROTOCOL")):
                r.err(explain_error(e))
                return
            if any(x in str(e).upper() for x in ("UNSUPPORTED_PROTOCOL", "NO_PROTOCOLS_AVAILABLE")):
                r.skip("%s: local OpenSSL has it disabled (not testable)" % label)
            else:
                r.info("%s: rejected by server" % label)
        except Exception as e:  # noqa: BLE001
            r.err(explain_error(e) if not isinstance(e, RuntimeError) else str(e))
            return
    if "TLSv1.0" in accepted or "TLSv1.1" in accepted:
        r.fail("Deprecated TLS 1.0/1.1 accepted")
    if "TLSv1.2" in accepted or "TLSv1.3" in accepted:
        r.ok("Modern TLS (1.2/1.3) available")
    r.info("Limited check: only protocol versions this client can offer were tested.")


# ---- DNS / IP ----------------------------------------------------------------
def f_resolve(host, r):
    try:
        infos = socket.getaddrinfo(host, None)
    except OSError as e:
        r.err("Resolution failed: %s" % e)
        return
    addrs = sorted({i[4][0].split("%")[0] for i in infos})
    for a in addrs:
        r.info("%s  (IPv%d, %s)" % (a, ipaddress.ip_address(a).version,
                                   "private/loopback" if is_local_addr(a) else "public"))
    r.ok("Resolved %d address(es) using the system resolver" % len(addrs))


def f_reverse(ip, r):
    try:
        name, aliases, _ = socket.gethostbyaddr(ip)
        r.info("PTR: " + name + (" (aliases: %s)" % ", ".join(aliases) if aliases else ""))
        r.ok("Reverse DNS record exists")
    except socket.herror:
        r.info("No PTR record for %s" % ip)
    except OSError as e:
        r.err("Reverse lookup failed: %s" % e)


def f_ip_class(arg, r):
    ip = parse_ip(arg)
    if not ip:
        r.fail("Not a valid IPv4/IPv6 address")
        return
    flags = [n for n in ("is_loopback", "is_private", "is_link_local", "is_multicast", "is_reserved",
                         "is_unspecified", "is_global") if getattr(ip, n)]
    r.info("IPv%d %s: %s" % (ip.version, ip, ", ".join(f.replace("is_", "") for f in flags) or "none"))
    r.ok("Classified offline (no network traffic)")
    r.info("Safe client will treat it as: " + ("local (allowed)" if is_local_addr(str(ip)) else "external (needs authorization)"))


def f_cidr(arg, r):
    try:
        net = ipaddress.ip_network(arg.strip(), strict=False)
    except ValueError as e:
        r.fail("Invalid CIDR: %s" % e)
        return
    r.info("Network %s, netmask %s, %s addresses" % (net.network_address, net.netmask, net.num_addresses))
    if net.version == 4:
        r.info("Broadcast %s" % net.broadcast_address)
        if net.prefixlen < 31:
            r.info("Usable hosts: %s - %s" % (net.network_address + 1, net.broadcast_address - 1))
    if "/" in arg and ipaddress.ip_interface(arg.strip()).ip != net.network_address:
        r.info("Host bits were set; normalized to the network address")
    r.ok("Calculated offline")


def f_hostname_syntax(arg, r):
    h = arg.strip()
    ok, why = validate_hostname(h)
    if not ok:
        r.fail("Invalid: " + why)
        return
    if parse_ip(h):
        r.info("Input is an IP literal, not a DNS name")
        return
    if "_" in h:
        r.warn("Underscores are not valid in hostnames")
    asc = h.lower().encode("idna").decode("ascii")
    if asc != h.lower():
        r.info("IDN form (punycode): " + asc)
    if asc.rstrip(".").split(".")[-1].isdigit():
        r.fail("Top-level label is all digits")
    else:
        r.ok("RFC 1123 syntax valid (%d labels, %d chars)" % (len(asc.rstrip(".").split(".")), len(asc)))


def f_dns_sanity(host, r):
    seen = []
    for _ in range(3):
        if not spend():
            r.err(BUDGET_MSG % SETTINGS["budget"])
            return
        try:
            seen.append(frozenset(i[4][0].split("%")[0] for i in socket.getaddrinfo(host, None)))
        except OSError as e:
            r.err("Resolution failed: %s" % e)
            return
        time.sleep(0.2)
    allset = set().union(*seen)
    r.info("Addresses seen: " + ", ".join(sorted(allset)))
    local = {a for a in allset if is_local_addr(a)}
    if local and local != allset:
        r.warn("Answers mix public and private addresses (DNS-rebinding indicator)")
    elif len(set(seen)) > 1:
        r.info("Answers varied between lookups (round-robin or load balancing)")
    else:
        r.ok("Consistent answers across 3 lookups")
    if local == allset and host.lower() not in ("localhost",) and not parse_ip(host):
        r.info("Name resolves only to private addresses (expected for an internal lab)")


# ---- ports / local network ---------------------------------------------------
def tcp_probe(host, port, timeout=None):
    if not spend():
        return False, None, BUDGET_MSG % SETTINGS["budget"]
    throttle()
    t0 = time.time()
    try:
        with socket.create_connection((host, port), timeout=timeout or min(SETTINGS["timeout"], 3.0)):
            return True, (time.time() - t0) * 1000, None
    except socket.timeout:
        return False, None, "timeout (filtered or no response)"
    except ConnectionRefusedError:
        return False, None, "refused (closed)"
    except OSError as e:
        return False, None, str(e)


def f_port(arg, r):
    host, port = arg
    up, ms, err = tcp_probe(host, port)
    if up:
        r.info("%s:%d is OPEN (connected in %.0f ms)" % (host, port, ms))
    else:
        r.info("%s:%d not reachable: %s" % (host, port, err))
    r.info("Open/closed is a state, not a verdict: confirm the service is meant to be exposed.")


COMMON_PORTS = {21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http", 110: "pop3",
                143: "imap", 443: "https", 3306: "mysql", 5432: "postgres", 8080: "http-alt"}


def scan_common(host, r, ports=None):
    opened = []
    for p, name in (ports or COMMON_PORTS).items():
        up, _, err = tcp_probe(host, p, 1.0)
        if err and err.startswith("Request budget"):
            r.err(err)
            return None
        if up:
            opened.append(p)
            r.info("Port %d (%s) open" % (p, name))
    return opened


def f_common_ports(host, r):
    opened = scan_common(host, r)
    if opened is None:
        return
    r.info("Checked %d well-known ports sequentially (1s timeout each)." % len(COMMON_PORTS))
    for p in opened:
        if p in (21, 23, 110):
            r.warn("Cleartext service exposed: %d (%s)" % (p, COMMON_PORTS[p]))
        if p in (3306, 5432) and not quick_local(host):
            r.warn("Database port %d reachable externally" % p)
    if not opened:
        r.info("None of the checked ports accepted a connection")


def f_latency(arg, r):
    host, port = arg
    ms = []
    for _ in range(5):
        up, t, err = tcp_probe(host, port)
        if not up:
            r.info("Connect failed: %s" % err)
            return
        ms.append(t)
    r.info("min %.1f / avg %.1f / max %.1f ms over 5 connects" % (min(ms), sum(ms) / 5, max(ms)))
    r.ok("TCP connect latency measured")


def f_banner_read(arg, r):
    host, port = arg
    if not spend():
        r.err(BUDGET_MSG % SETTINGS["budget"])
        return
    try:
        with socket.create_connection((host, port), timeout=3) as s:
            s.settimeout(2)
            try:
                data = s.recv(256)
            except socket.timeout:
                data = b""
    except Exception as e:  # noqa: BLE001
        r.err(explain_error(e))
        return
    if data:
        txt = "".join(ch if 32 <= ord(ch) < 127 else "." for ch in data.decode("latin-1"))
        r.info("Banner (passive, nothing sent): " + txt)
        if re.search(r"\d+\.\d+", txt):
            r.warn("Banner discloses a version string")
    else:
        r.info("No banner within 2s (many services wait for the client to speak first)")


def f_ifaces(arg, r):
    r.info("Hostname: " + socket.gethostname())
    addrs = set()
    try:
        addrs |= {i[4][0] for i in socket.getaddrinfo(socket.gethostname(), None) if ":" not in i[4][0]}
    except OSError:
        pass
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("192.0.2.1", 9))        # UDP connect only selects a route; no packet is sent
        addrs.add(s.getsockname()[0])
        s.close()
    except OSError:
        pass
    try:
        names = sorted(os.listdir("/sys/class/net"))
        r.info("Interfaces: " + ", ".join(names))
    except OSError:
        r.info("Interface list unavailable (restricted on some Android versions)")
    if addrs:
        for a in sorted(addrs):
            r.info("Local IPv4: " + a)
        r.ok("Local addressing determined")
    else:
        r.warn("Could not determine local IPv4 addresses (offline or restricted)")


def f_localhost_listen(arg, r):
    ports = {22: "ssh", 80: "http", 443: "https", 3000: "dev", 3306: "mysql", 5000: "flask", 5432: "postgres",
             5555: "adb", 6379: "redis", 8000: "http-alt", 8080: "http-alt", 8099: "toolkit-lab",
             8443: "https-alt", 9000: "dev", 27017: "mongodb"}
    opened = scan_common("127.0.0.1", r, ports)
    if opened is None:
        return
    r.info("Checked %d common local ports on 127.0.0.1." % len(ports))
    if 5555 in opened:
        r.warn("Port 5555 (ADB over TCP) is listening locally; disable if unused")
    if not opened:
        r.info("No listeners found on the checked loopback ports")
    else:
        r.ok("Local listener inventory complete")


# =============================================================================
# 7. WEB SECURITY CONFIGURATION CHECKS  (features 11-28, 86-90)
# =============================================================================
def _https(resp):
    return resp["final_url"].startswith("https://")


def f_hsts(url, r):
    resp = hdr_resp(url, r)
    if not resp:
        return
    if not _https(resp):
        r.skip("Served over HTTP: browsers ignore HSTS on HTTP responses")
        return
    v = hv(resp, "strict-transport-security")
    if not v:
        r.fail("Strict-Transport-Security header missing")
        return
    m = re.search(r"max-age\s*=\s*(\d+)", v, re.I)
    age = int(m.group(1)) if m else 0
    if age == 0:
        r.fail("max-age missing or zero")
    elif age < 15552000:
        r.warn("max-age=%d is below 180 days" % age)
    else:
        r.ok("max-age=%d" % age)
    r.info("includeSubDomains: %s; preload: %s" % (
        "yes" if re.search("includesubdomains", v, re.I) else "no", "yes" if re.search("preload", v, re.I) else "no"))


def f_csp(url, r):
    resp = hdr_resp(url, r)
    if not resp:
        return
    if hv(resp, "content-security-policy"):
        r.ok("Content-Security-Policy is set (quality: see feature 13)")
    elif hv(resp, "content-security-policy-report-only"):
        r.warn("Only Report-Only CSP found: nothing is enforced")
    else:
        r.fail("No Content-Security-Policy header")


def f_csp_weak(url, r):
    resp = hdr_resp(url, r)
    if not resp:
        return
    csp = hv(resp, "content-security-policy")
    if not csp:
        r.skip("No enforced CSP to analyze")
        return
    d = {}
    for part in csp.split(";"):
        bits = part.strip().split()
        if bits:
            d[bits[0].lower()] = [b.lower() for b in bits[1:]]
    issues = 0
    for name in ("script-src", "default-src", "style-src"):
        vals = d.get(name, [])
        for bad in ("'unsafe-inline'", "'unsafe-eval'", "*", "data:", "http:"):
            if bad in vals and not (name == "style-src" and bad != "*"):
                r.warn("%s allows %s" % (name, bad))
                issues += 1
    if "default-src" not in d and "script-src" not in d:
        r.warn("Neither default-src nor script-src defined")
        issues += 1
    for need in ("object-src", "base-uri", "frame-ancestors"):
        if need not in d and "default-src" not in d:
            r.warn("%s not restricted" % need)
            issues += 1
    if not issues:
        r.ok("No weak CSP patterns found in %d directive(s)" % len(d))


def f_clickjack(url, r):
    resp = hdr_resp(url, r)
    if not resp:
        return
    xfo = (hv(resp, "x-frame-options") or "").upper()
    fa = re.search(r"frame-ancestors\s+([^;]+)", hv(resp, "content-security-policy") or "", re.I)
    if fa and "*" not in fa.group(1).split():
        r.ok("CSP frame-ancestors: " + fa.group(1).strip())
    elif xfo in ("DENY", "SAMEORIGIN"):
        r.ok("X-Frame-Options: " + xfo)
    else:
        r.warn("No effective framing restriction (clickjacking possible on sensitive pages)")


def f_xcto(url, r):
    resp = hdr_resp(url, r)
    if not resp:
        return
    v = (hv(resp, "x-content-type-options") or "").lower()
    (r.ok if v == "nosniff" else r.fail)("X-Content-Type-Options: " + (v or "missing (should be nosniff)"))


def f_referrer(url, r):
    resp = hdr_resp(url, r)
    if not resp:
        return
    v = (hv(resp, "referrer-policy") or "").lower()
    if not v:
        r.warn("Referrer-Policy missing (browser default applies)")
    elif v in ("unsafe-url", "no-referrer-when-downgrade", "origin-when-cross-origin"):
        r.warn("Permissive Referrer-Policy: " + v)
    else:
        r.ok("Referrer-Policy: " + v)


def f_permissions(url, r):
    resp = hdr_resp(url, r)
    if not resp:
        return
    if hv(resp, "permissions-policy"):
        r.ok("Permissions-Policy present")
    elif hv(resp, "feature-policy"):
        r.warn("Only the deprecated Feature-Policy header is set")
    else:
        r.warn("Permissions-Policy missing (camera/mic/geolocation not restricted by policy)")


def f_cross_origin(url, r):
    resp = hdr_resp(url, r)
    if not resp:
        return
    got = 0
    for h in ("cross-origin-opener-policy", "cross-origin-embedder-policy", "cross-origin-resource-policy"):
        v = hv(resp, h)
        if v:
            got += 1
            r.ok("%s: %s" % (h, v))
        else:
            r.info("%s not set (optional hardening)" % h)
    if not got:
        r.info("No cross-origin isolation headers set")


LEAK_HEADERS = ("x-powered-by", "x-aspnet-version", "x-aspnetmvc-version", "x-generator", "x-runtime",
                "x-backend-server", "x-turbo-charged-by")


def tech_leaks(resp):
    leaks = ["%s: %s" % (h, hv(resp, h)) for h in LEAK_HEADERS if hv(resp, h)]
    srv = hv(resp, "server") or ""
    if re.search(r"\d+\.\d+", srv):
        leaks.append("server: " + srv)
    return leaks


def f_tech_leak(url, r):
    resp = hdr_resp(url, r)
    if not resp:
        return
    leaks = tech_leaks(resp)
    for lk in leaks:
        r.warn("Technology/version disclosure: " + lk)
    if not leaks:
        r.ok("No technology or version disclosure headers")


def f_cors(url, r):
    origin = "https://untrusted.example"
    resp = hdr_resp(url, r, headers={"Origin": origin}, cache=False)
    if not resp:
        return
    acao, acac = hv(resp, "access-control-allow-origin"), (hv(resp, "access-control-allow-credentials") or "").lower()
    r.info("Sent Origin: %s" % origin)
    if not acao:
        r.ok("No CORS headers for a foreign origin (cross-origin reads blocked by browsers)")
    elif acao == "*":
        (r.fail if acac == "true" else r.warn)("Wildcard ACAO%s" % (" with credentials=true" if acac == "true" else
                                                                    " (acceptable only for public, non-credentialed data)"))
    elif acao == origin:
        (r.fail if acac == "true" else r.warn)("Server reflects arbitrary Origin%s" % (" AND allows credentials" if acac == "true" else ""))
        if "origin" not in (hv(resp, "vary") or "").lower():
            r.warn("Reflected ACAO without 'Vary: Origin'")
    elif acao == "null":
        r.fail("ACAO 'null' allows sandboxed/file origins")
    else:
        r.ok("ACAO restricted to: " + acao)


def f_deprecated(url, r):
    resp = hdr_resp(url, r)
    if not resp:
        return
    found = False
    for h, why in (("x-xss-protection", "legacy auditor removed from browsers; use CSP (value 0 is safest)"),
                   ("public-key-pins", "HPKP is removed and risky"), ("expect-ct", "deprecated"),
                   ("feature-policy", "replaced by Permissions-Policy")):
        v = hv(resp, h)
        if v:
            found = True
            r.warn("%s: %s -> %s" % (h, v[:40], why))
    if not found:
        r.ok("No deprecated security headers present")


def f_score(url, r):
    resp = hdr_resp(url, r)
    if not resp:
        return
    csp = (hv(resp, "content-security-policy") or "")
    checks = [("HSTS", bool(hv(resp, "strict-transport-security")), _https(resp)),
              ("CSP", bool(csp), True),
              ("Clickjacking protection", bool(hv(resp, "x-frame-options")) or "frame-ancestors" in csp.lower(), True),
              ("nosniff", (hv(resp, "x-content-type-options") or "").lower() == "nosniff", True),
              ("Referrer-Policy", bool(hv(resp, "referrer-policy")), True),
              ("Permissions-Policy", bool(hv(resp, "permissions-policy")), True),
              ("No version leaks", not tech_leaks(resp), True)]
    app = [(n, ok) for n, ok, a in checks if a]
    for n, ok in app:
        r.info("%s %s" % ("[x]" if ok else "[ ]", n))
    pct = 100 * sum(ok for _, ok in app) // len(app)
    grade = "A" if pct >= 90 else "B" if pct >= 75 else "C" if pct >= 60 else "D" if pct >= 40 else "F"
    r.info("Score %d%% (grade %s) over %d applicable checks. Simple unweighted heuristic." % (pct, grade, len(app)))
    (r.ok if pct >= 75 else r.warn if pct >= 50 else r.fail)("Header hygiene grade: " + grade)


# ---- cookies -------------------------------------------------------------------
def parse_set_cookie(s):
    parts = [p.strip() for p in s.split(";")]
    name, _, val = parts[0].partition("=")
    attrs = {}
    for p in parts[1:]:
        k, _, v = p.partition("=")
        attrs[k.strip().lower()] = v.strip() or True
    return {"name": name.strip(), "vlen": len(val), "attrs": attrs}


SENSITIVE_COOKIE = re.compile(r"sess|sid|token|auth|jwt|login|csrf|xsrf|remember", re.I)


def get_cookies(url, r):
    resp = hdr_resp(url, r)
    if not resp:
        return None, None
    cks = [parse_set_cookie(x) for x in hall(resp, "set-cookie")]
    if not cks:
        r.info("No Set-Cookie headers on this response (other pages may set cookies)")
        return resp, []
    return resp, cks


def f_cookie_list(url, r):
    resp, cks = get_cookies(url, r)
    for ck in cks or []:
        r.info("%s (value length %d; attributes: %s)" % (ck["name"], ck["vlen"], ", ".join(sorted(ck["attrs"])) or "none"))
    if cks:
        r.ok("Inventoried %d cookie(s); values not displayed" % len(cks))


def f_cookie_secure(url, r):
    resp, cks = get_cookies(url, r)
    if not cks:
        return
    for ck in cks:
        if "secure" in ck["attrs"]:
            r.ok("%s: Secure set" % ck["name"])
        elif _https(resp):
            r.fail("%s: missing Secure on an HTTPS site" % ck["name"])
        else:
            r.warn("%s: no Secure flag (page served over HTTP)" % ck["name"])


def f_cookie_httponly(url, r):
    resp, cks = get_cookies(url, r)
    for ck in cks or []:
        if "httponly" in ck["attrs"]:
            r.ok("%s: HttpOnly set" % ck["name"])
        elif SENSITIVE_COOKIE.search(ck["name"]):
            r.fail("%s: session/auth-like cookie readable by JavaScript" % ck["name"])
        else:
            r.warn("%s: missing HttpOnly" % ck["name"])


def f_cookie_samesite(url, r):
    resp, cks = get_cookies(url, r)
    for ck in cks or []:
        ss = str(ck["attrs"].get("samesite", "")).lower()
        if not ss:
            r.warn("%s: SameSite not set (browser default Lax applies in modern browsers)" % ck["name"])
        elif ss == "none" and "secure" not in ck["attrs"]:
            r.fail("%s: SameSite=None without Secure is rejected by browsers" % ck["name"])
        else:
            r.ok("%s: SameSite=%s" % (ck["name"], ss))


def f_cookie_scope(url, r):
    resp, cks = get_cookies(url, r)
    for ck in cks or []:
        n, a = ck["name"], ck["attrs"]
        if n.startswith("__Host-"):
            good = "secure" in a and a.get("path") == "/" and "domain" not in a
            (r.ok if good else r.fail)("%s: __Host- prefix %s" % (n, "rules satisfied" if good else "rules violated (needs Secure, Path=/, no Domain)"))
        elif n.startswith("__Secure-"):
            (r.ok if "secure" in a else r.fail)("%s: __Secure- prefix %s" % (n, "satisfied" if "secure" in a else "requires Secure"))
        elif "domain" in a:
            r.warn("%s: Domain=%s shares the cookie with all subdomains" % (n, a["domain"]))
        else:
            r.info("%s: host-only cookie, path=%s" % (n, a.get("path", "(default)")))


def f_cookie_life(url, r):
    resp, cks = get_cookies(url, r)
    for ck in cks or []:
        a, n = ck["attrs"], ck["name"]
        age = None
        if "max-age" in a and str(a["max-age"]).lstrip("-").isdigit():
            age = int(a["max-age"])
        if age is None:
            r.info("%s: session cookie (no explicit lifetime)" % n)
        else:
            days = age / 86400.0
            if SENSITIVE_COOKIE.search(n) and days > 30:
                r.warn("%s: persists %.0f days (long for an auth-like cookie)" % (n, days))
            else:
                r.ok("%s: Max-Age %.1f day(s)" % (n, days))
        if ck["vlen"] > 4096:
            r.warn("%s: very large value (%d bytes)" % (n, ck["vlen"]))


# ---- authentication configuration ------------------------------------------------
def f_basic_auth(url, r):
    resp = hdr_resp(url, r)
    if not resp:
        return
    if resp["status"] not in (401, 407):
        r.info("Endpoint did not issue an authentication challenge (HTTP %s)" % resp["status"])
        return
    www = hv(resp, "www-authenticate") or hv(resp, "proxy-authenticate") or ""
    scheme = www.split(" ")[0].lower()
    if not www:
        r.warn("401 without a WWW-Authenticate header (non-compliant)")
    elif scheme == "basic":
        (r.warn if _https(resp) else r.fail)("HTTP Basic auth " + ("over HTTPS: credentials are resent on every request" if _https(resp)
                                              else "over plain HTTP exposes credentials"))
    elif scheme == "digest":
        r.warn("Digest authentication is legacy")
    else:
        r.ok("Challenge scheme: " + (scheme or "unknown"))


def f_login_hints(url, r):
    g = get_html(url, r)
    if not g:
        return
    resp, sc = g
    text = decode_body(resp).lower()
    pf = [f for f in sc.forms if any(x["type"] == "password" for x in f["inputs"])]
    if not pf:
        r.info("No login form on this page")
        return
    marks = [m for m in ("recaptcha", "hcaptcha", "turnstile", "captcha") if m in text]
    r.info("Anti-automation markers: " + (", ".join(marks) if marks else "none visible"))
    if "no-store" not in (hv(resp, "cache-control") or "").lower():
        r.warn("Login page lacks Cache-Control: no-store")
    if any(hv(resp, h) for h in ("x-ratelimit-limit", "ratelimit-limit", "retry-after")):
        r.ok("Rate-limit headers present")
    else:
        r.info("No rate-limit headers (throttling may exist server-side)")
    r.info("Limited check: lockout/throttling behavior cannot be proven without sending login attempts, which this tool does not do.")


def f_session_entropy(arg, r):
    s = arg.strip()
    n = len(s)
    if not n:
        r.fail("Empty token")
        return
    freq = {ch: s.count(ch) for ch in set(s)}
    shannon = -sum(v / n * math.log2(v / n) for v in freq.values())
    pool = (26 if re.search("[a-z]", s) else 0) + (26 if re.search("[A-Z]", s) else 0) + \
           (10 if re.search("[0-9]", s) else 0) + (2 if re.search("[-_+/=]", s) else 0)
    bits = min(shannon * n, n * math.log2(max(pool, 2)))
    r.info("Length %d, %d distinct characters, ~%.0f bits (upper-bound estimate from this one sample)" % (n, len(freq), bits))
    if s.isdigit():
        r.fail("Numeric-only token")
    if n < 16 or bits < 64:
        r.fail("Too short/low entropy for a session identifier (aim for 128+ bits)")
    elif bits < 112:
        r.warn("Below the commonly recommended 128 bits")
    else:
        r.ok("Length/charset consistent with >=112 bits")
    r.info("Limited: statistics of one sample cannot prove the generator is unpredictable. The token was not stored.")


def _b64j(seg):
    return json.loads(base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4)))


def f_jwt(arg, r):
    parts = arg.strip().split(".")
    if len(parts) != 3:
        r.fail("Not a JWT (expected 3 dot-separated parts)")
        return
    try:
        hdr, pl = _b64j(parts[0]), _b64j(parts[1])
    except Exception:  # noqa: BLE001
        r.fail("Header or payload is not valid base64url JSON")
        return
    alg = str(hdr.get("alg", "")).lower()
    r.info("Header: alg=%s typ=%s kid=%s" % (hdr.get("alg"), hdr.get("typ"), "set" if "kid" in hdr else "none"))
    r.info("Claim names: " + ", ".join(sorted(pl)[:20]))
    if alg in ("none", ""):
        r.fail("alg=none: token is unsigned")
    elif alg.startswith("hs"):
        r.info("HMAC-signed: the shared secret must be long and random")
    if "jku" in hdr or "x5u" in hdr:
        r.warn("Header references a remote key URL (jku/x5u): servers must not trust it blindly")
    now = time.time()
    if "exp" not in pl:
        r.warn("No exp claim: token never expires")
    elif isinstance(pl["exp"], (int, float)):
        if pl["exp"] < now:
            r.info("Token is expired")
        elif "iat" in pl and isinstance(pl["iat"], (int, float)) and pl["exp"] - pl["iat"] > 86400:
            r.warn("Lifetime exceeds 24 hours")
        else:
            r.ok("exp claim present")
    r.info("Limited: decoded WITHOUT verifying the signature, so authenticity is not established. Token not stored.")


AUTH_QUESTIONS = [
    "Is the minimum password length at least 12 (or 8 with breach-list screening)?",
    "Are passwords stored with bcrypt, scrypt, Argon2 or PBKDF2?",
    "Is multi-factor authentication available/required for admin accounts?",
    "Is there throttling or lockout for repeated failed logins?",
    "Do session cookies use Secure, HttpOnly and SameSite?",
    "Are sessions invalidated on logout and after inactivity?",
    "Are password-reset tokens single-use and short-lived?",
    "Are failed logins logged and monitored?",
    "Have default credentials been removed from all components?",
]


def f_auth_checklist(arg, r):
    r.info("Manual self-assessment: answers are not verified against any system.")
    done = 0
    for q in AUTH_QUESTIONS:
        try:
            a = ask(q + " (y/n/skip)", "skip").lower()
        except UserAbort:
            r.skip("Input closed; checklist incomplete")
            break
        if a.startswith("y"):
            r.ok(q)
            done += 1
        elif a.startswith("n"):
            r.warn("Gap: " + q)
            done += 1
        else:
            r.skip(q)
    if not done:
        r.info("No answers given")


# =============================================================================
# 8. API AND JSON ANALYSIS  (features 57-62)
# =============================================================================
def api_json(url, r):
    resp = hdr_resp(url, r, headers={"Accept": "application/json"})
    if not resp:
        return None, None
    if resp["truncated"]:
        r.warn("Body truncated at size limit; JSON cannot be fully parsed")
        return resp, None
    try:
        return resp, json.loads(resp["body"].decode("utf-8", "replace"))
    except ValueError as e:
        r.fail("Body is not valid JSON: %s" % str(e)[:80])
        return resp, None


def f_json_valid(url, r):
    resp, data = api_json(url, r)
    if data is None:
        return
    ct = (hv(resp, "content-type") or "").lower()
    r.ok("Valid JSON (%s at top level)" % type(data).__name__)
    if "json" not in ct:
        r.warn("Content-Type is '%s', not application/json" % (ct or "missing"))


def _depth(o, d=1):
    if isinstance(o, dict):
        return max([_depth(v, d + 1) for v in o.values()] or [d])
    if isinstance(o, list):
        return max([_depth(v, d + 1) for v in o[:50]] or [d])
    return d


def _walk(o, path=""):
    if isinstance(o, dict):
        for k, v in o.items():
            p = "%s.%s" % (path, k) if path else str(k)
            yield p, k
            for x in _walk(v, p):
                yield x
    elif isinstance(o, list):
        for v in o[:50]:
            for x in _walk(v, path + "[]"):
                yield x


def f_json_struct(url, r):
    resp, data = api_json(url, r)
    if data is None:
        return
    keys = list(dict.fromkeys(k for _, k in _walk(data)))
    r.info("Top-level: %s%s" % (type(data).__name__, " (%d item(s))" % len(data) if isinstance(data, (list, dict)) else ""))
    r.info("Depth %d; %d distinct key names: %s" % (_depth(data), len(keys), ", ".join(map(str, keys[:25]))))
    r.ok("Structure inventoried")


def f_json_sensitive(url, r):
    resp, data = api_json(url, r)
    if data is None:
        return
    rx = re.compile(r"pass(word|wd)?|secret|token|api_?key|ssn|credit|card|cvv|private|session|hash|salt", re.I)
    hits = sorted({p for p, k in _walk(data) if rx.search(str(k))})
    for p in hits[:15]:
        r.warn("Sensitive-looking field exposed: %s (value not shown)" % p)
    if not hits:
        r.ok("No sensitive-looking key names (name heuristic; values were not inspected)")


def f_error_verbose(url, r):
    probe = urllib.parse.urljoin(url, "/__toolkit_missing_%s" % secrets.token_hex(3))
    rx = re.compile(r"Traceback \(most recent|at [\w.$]+\(.*:\d+\)|Exception in|SQLSTATE|ORA-\d{4,}|"
                    r"/var/www|/usr/(local/)?lib|C:\\\\|<b>Warning</b>|stack ?trace|\.py\", line \d+", re.I)
    for label, u in (("requested URL", url), ("non-existent path", probe)):
        resp = fetch(u, cache=False)
        if resp["error"]:
            r.err(resp["error"])
            return
        m = rx.search(decode_body(resp))
        if m:
            r.warn("Verbose error content in %s (HTTP %s): matched '%s'" % (label, resp["status"], m.group(0)[:30]))
        else:
            r.ok("No stack-trace/path leakage in %s (HTTP %s)" % (label, resp["status"]))
    r.info("Limited: two responses were inspected, not every error path.")


def f_ratelimit_headers(url, r):
    resp = hdr_resp(url, r)
    if not resp:
        return
    found = [h for h in ("x-ratelimit-limit", "x-ratelimit-remaining", "x-ratelimit-reset", "ratelimit-limit",
                         "ratelimit-remaining", "ratelimit-reset", "ratelimit", "retry-after") if hv(resp, h)]
    if found:
        r.ok("Rate-limit headers: " + ", ".join("%s=%s" % (h, hv(resp, h)) for h in found))
    else:
        r.warn("No rate-limit headers (optional; absence does not prove there is no limiting)")


def f_ratelimit_probe(url, r):
    codes = []
    for i in range(10):
        resp = fetch(url, follow=False, read_body=False, cache=False)
        if resp["error"]:
            r.err(resp["error"])
            return
        codes.append(resp["status"])
        if resp["status"] == 429:
            break
        time.sleep(0.4)
    r.info("Status sequence (max 10 requests, 0.4s apart): " + " ".join(map(str, codes)))
    if 429 in codes:
        ra = hv(resp, "retry-after")
        r.ok("Rate limiting engaged after %d request(s)%s" % (len(codes), "; Retry-After=" + ra if ra else ""))
    else:
        r.info("No throttling observed within this deliberately small probe; limits may be higher.")


# =============================================================================
# 9. LOCAL SECURITY LAB  (features 63-70)
#    The lab HTTP server binds to 127.0.0.1 ONLY. It contains deliberately weak,
#    inert pages (no data capture; POST is rejected) for testing this toolkit.
# =============================================================================
class LabHandler(BaseHTTPRequestHandler):
    server_version = "ToolkitLab/1.0"
    sys_version = ""

    def log_message(self, fmt, *a):
        pass

    def _send(self, code, body, ctype="text/html; charset=utf-8", extra=()):
        data = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        for k, v in extra:
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def do_HEAD(self):
        self.do_GET()

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Allow", "GET, HEAD, OPTIONS")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_POST(self):
        self._send(405, "Lab does not accept POST data.", "text/plain", [("Allow", "GET, HEAD, OPTIONS")])

    def do_GET(self):
        u = urllib.parse.urlsplit(self.path)
        q = urllib.parse.parse_qs(u.query).get("q", [""])[0][:200]
        if u.path == "/":
            page = ("<!doctype html><html><head><title>Toolkit Lab</title>"
                    "<meta name='generator' content='ToolkitLab 1.0'></head><body><h1>Toolkit Lab</h1>"
                    "<!-- TODO: remove debug admin notes -->"
                    "<form method='post' action='/login'><input name='user'>"
                    "<input type='password' name='pw'><button>Login</button></form>"
                    "<script src='https://cdn.example.invalid/lib.js'></script>"
                    "<a href='/search?q=test' target='_blank'>search</a></body></html>")
            self._send(200, page, extra=[("X-Content-Type-Options", "nosniff"),
                                         ("Set-Cookie", "labsession=abc123; Path=/"),
                                         ("Set-Cookie", "labpref=1; Path=/; HttpOnly; Secure; SameSite=Lax")])
        elif u.path == "/search":        # intentionally unescaped (reflection demo)
            self._send(200, "<html><body><h1>Results for: %s</h1></body></html>" % q)
        elif u.path == "/safe-search":
            self._send(200, "<html><body><h1>Results for: %s</h1></body></html>" % html.escape(q),
                       extra=[("Content-Security-Policy", "default-src 'self'"),
                              ("X-Content-Type-Options", "nosniff"), ("Referrer-Policy", "no-referrer")])
        elif u.path == "/api/items":
            body = json.dumps({"items": [{"id": 1, "name": "widget"}], "debug": {"api_key": "DEMO-NOT-A-SECRET"}})
            self._send(200, body, "application/json", [("Access-Control-Allow-Origin", "*")])
        elif u.path == "/limited":
            now = time.time()
            hits = [t for t in LAB["hits"].get("limited", []) if now - t < 60]
            hits.append(now)
            LAB["hits"]["limited"] = hits
            if len(hits) > 5:
                self._send(429, "Too Many Requests", "text/plain", [("Retry-After", "30"), ("X-RateLimit-Limit", "5")])
            else:
                self._send(200, "ok", "text/plain", [("X-RateLimit-Limit", "5"), ("X-RateLimit-Remaining", str(5 - len(hits)))])
        elif u.path == "/error":
            self._send(500, "Traceback (most recent call last):\n  File \"/var/www/app.py\", line 42, in view\nKeyError: 'x'",
                       "text/plain")
        else:
            self._send(404, "Not found", "text/plain")


def lab_start(port=0):
    if LAB["server"]:
        return LAB["port"]
    srv = ThreadingHTTPServer(("127.0.0.1", port), LabHandler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    LAB["server"], LAB["port"], LAB["hits"] = srv, srv.server_address[1], {}
    return LAB["port"]


def lab_stop():
    if LAB["server"]:
        LAB["server"].shutdown()
        LAB["server"].server_close()
        LAB["server"], LAB["port"] = None, None


def f_lab_selftest(arg, r):
    started = not LAB["server"]
    port = lab_start()
    base = "http://127.0.0.1:%d" % port
    try:
        r.info("Lab server listening on 127.0.0.1:%d" % port)
        for path, expect in (("/", 200), ("/api/items", 200), ("/missing", 404), ("/error", 500)):
            resp = fetch(base + path, follow=False, cache=False)
            if resp["error"]:
                r.err(resp["error"])
                return
            (r.ok if resp["status"] == expect else r.fail)("GET %s -> %s (expected %s)" % (path, resp["status"], expect))
    finally:
        if started:
            lab_stop()
            r.info("Lab server stopped again")


def f_sqli_demo(arg, r):
    payload = arg or "' OR '1'='1"
    db = sqlite3.connect(":memory:")
    db.execute("CREATE TABLE users(name TEXT, role TEXT)")
    db.executemany("INSERT INTO users VALUES(?,?)", [("alice", "admin"), ("bob", "user"), ("carol", "user")])
    r.sim("Synthetic in-memory table with 3 users. Input: " + payload)
    try:
        vuln = db.execute("SELECT name FROM users WHERE name = '%s'" % payload).fetchall()
        r.sim("VULNERABLE string-built query returned %d row(s)%s" % (
            len(vuln), " (input altered the query logic)" if len(vuln) > 1 else ""))
    except sqlite3.Error as e:
        r.sim("VULNERABLE string-built query raised an SQL error: %s" % e)
    safe = db.execute("SELECT name FROM users WHERE name = ?", (payload,)).fetchall()
    r.sim("PARAMETERIZED query returned %d row(s): input treated purely as data" % len(safe))
    r.sim("Demo only: runs against a throwaway in-memory database, never against a target.")
    db.close()


def f_xss_demo(arg, r):
    payload = arg or "<script>alert(1)</script>"
    r.sim("Input: " + payload)
    raw = "<h1>Hello %s</h1>" % payload
    esc = "<h1>Hello %s</h1>" % html.escape(payload)
    r.sim("UNESCAPED output: " + raw)
    r.sim("ESCAPED output:   " + esc)
    r.sim("Unescaped output keeps the markup intact (would execute in a browser): %s"
          % ("yes" if payload in raw and re.search(r"[<>]", payload) else "no"))
    r.sim("Nothing was rendered or executed; this is a text-only comparison.")


def f_lab_headers(arg, r):
    started = not LAB["server"]
    port = lab_start()
    try:
        base = "http://127.0.0.1:%d" % port
        weak = fetch(base + "/", cache=False)
        strong = fetch(base + "/safe-search?q=x", cache=False)
        if weak["error"] or strong["error"]:
            r.err(weak["error"] or strong["error"])
            return
        for label, resp, expect_csp in (("/ (intentionally weak)", weak, False), ("/safe-search (hardened)", strong, True)):
            has = bool(hv(resp, "content-security-policy"))
            (r.ok if has == expect_csp else r.fail)("%s: CSP %s, as the lab was built" % (label, "present" if has else "absent"))
        r.info("Self-validation: confirms this toolkit's header detection matches known lab behavior.")
    finally:
        if started:
            lab_stop()


def f_csrf_demo(arg, r):
    key, sid = secrets.token_bytes(32), secrets.token_hex(8)

    def make(session, nonce):
        return nonce + "." + hmac.new(key, (session + nonce).encode(), hashlib.sha256).hexdigest()

    def valid(session, token):
        nonce, _, sig = token.partition(".")
        good = hmac.new(key, (session + nonce).encode(), hashlib.sha256).hexdigest()
        return hmac.compare_digest(sig, good)

    tok = make(sid, secrets.token_hex(8))
    r.sim("Token bound to session: %s... (HMAC-SHA256, per-session)" % tok[:20])
    r.sim("Legitimate form post validates: %s" % valid(sid, tok))
    r.sim("Tampered token validates: %s" % valid(sid, tok[:-2] + ("00" if not tok.endswith("00") else "11")))
    r.sim("Token replayed on another session validates: %s" % valid("other-session", tok))
    r.sim("Demo of the mechanism with throwaway keys; it does not test any site.")


def f_ratelimit_sim(arg, r):
    cap, rate, t, tokens, last = 5.0, 1.0, 0.0, 5.0, 0.0
    allowed = denied = 0
    log = []
    for i in range(12):
        t = i * 0.2
        tokens = min(cap, tokens + (t - last) * rate)
        last = t
        if tokens >= 1:
            tokens -= 1
            allowed += 1
            log.append("ok")
        else:
            denied += 1
            log.append("429")
    r.sim("Token bucket: capacity 5, refill 1/s; 12 requests at 0.2s intervals (virtual clock)")
    r.sim("Outcomes: " + " ".join(log))
    r.sim("Allowed %d, denied %d. No network traffic was generated." % (allowed, denied))


def safe_join(base, user):
    base_r = os.path.realpath(base)
    p = os.path.realpath(os.path.join(base_r, user.lstrip("/\\")))
    return p if os.path.commonpath([base_r, p]) == base_r else None


def f_traversal_demo(arg, r):
    with tempfile.TemporaryDirectory() as base:
        cases = [arg] if arg else ["report.txt", "docs/../report.txt", "../../etc/passwd", "/etc/passwd", "a/../../x"]
        for c_ in cases:
            res = safe_join(base, c_)
            r.sim("%-22s -> %s" % (c_, "allowed (stays inside base)" if res else "BLOCKED (escapes base)"))
    r.sim("Guard uses realpath + commonpath; no files were read.")


def f_pw_hash_demo(arg, r):
    pw = b"demo-password"
    t0 = time.perf_counter()
    for _ in range(1000):
        hashlib.sha256(pw).digest()
    fast = (time.perf_counter() - t0) / 1000
    salt = secrets.token_bytes(16)
    t0 = time.perf_counter()
    d1 = hashlib.pbkdf2_hmac("sha256", pw, salt, 200000)
    slow = time.perf_counter() - t0
    d2 = hashlib.pbkdf2_hmac("sha256", pw, secrets.token_bytes(16), 200000)
    r.sim("Plain SHA-256: %.4f ms per guess (attackers test billions/second on GPUs)" % (fast * 1000))
    r.sim("PBKDF2-SHA256 x200000: %.0f ms per guess on this device (~%dx slower)" % (slow * 1000, slow / max(fast, 1e-9)))
    r.sim("Same password, different salts -> different hashes: %s" % (d1 != d2))
    r.sim("Synthetic password only; use scrypt/Argon2/bcrypt where available.")


# =============================================================================
# 10. FILE, HASH, AND LOG UTILITIES  (features 71-80, 91-95)
# =============================================================================
MAX_HASH_BYTES = 1024 * 1024 * 1024


def hash_file(path, algo="sha256"):
    h = hashlib.new(algo)
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def f_hash_text(arg, r):
    data = arg.encode("utf-8")
    for a in ("md5", "sha1", "sha256", "sha512", "sha3_256"):
        r.info("%-8s %s" % (a, hashlib.new(a, data).hexdigest()))
    r.ok("Computed 5 digests of the UTF-8 input")
    r.info("MD5 and SHA-1 are broken for collision resistance; use SHA-256+ for integrity.")


def f_hash_file(path, r):
    size = os.path.getsize(path)
    if size > MAX_HASH_BYTES:
        r.fail("File larger than 1 GiB; refusing on a low-resource device")
        return
    for a in ("md5", "sha1", "sha256"):
        r.info("%-7s %s" % (a, hash_file(path, a)))
    r.ok("Hashed %d bytes" % size)


def f_hash_verify(arg, r):
    path, expected = arg
    expected = expected.strip().lower()
    algo = {32: "md5", 40: "sha1", 64: "sha256", 128: "sha512"}.get(len(expected))
    if not algo or not re.fullmatch(r"[0-9a-f]+", expected):
        r.fail("Expected value is not a hex MD5/SHA-1/SHA-256/SHA-512 digest")
        return
    got = hash_file(path, algo)
    if hmac.compare_digest(got, expected):
        r.ok("%s digest matches" % algo)
    else:
        r.fail("%s digest MISMATCH (file differs from expected)" % algo)
        r.info("Actual: " + got)
    if algo in ("md5", "sha1"):
        r.warn("%s is weak; a matching digest does not defend against a deliberate forgery" % algo)


def snapshot(d, limit=500):
    snap, skipped = {}, 0
    for root, dirs, files in os.walk(d, followlinks=False):
        dirs[:] = sorted(x for x in dirs if x != ".git")
        for fn in sorted(files):
            p = os.path.join(root, fn)
            try:
                st = os.lstat(p)
                if not stat_isreg(st.st_mode) or st.st_size > 50 * 1024 * 1024:
                    skipped += 1
                    continue
                if len(snap) >= limit:
                    return snap, skipped, True
                snap[os.path.relpath(p, d)] = hash_file(p)
            except OSError:
                skipped += 1
    return snap, skipped, False


def stat_isreg(mode):
    import stat as _st
    return _st.S_ISREG(mode)


def f_snapshot(d, r):
    d = os.path.realpath(d)
    snap, skipped, cut = snapshot(d)
    SNAPSHOTS[d] = snap
    r.info("Hashed %d file(s) with SHA-256; skipped %d (symlinks, >50 MB or unreadable)" % (len(snap), skipped))
    if cut:
        r.warn("Stopped at the 500-file limit; snapshot is partial")
    r.ok("Snapshot stored in memory for this session (use feature 75 to compare)")


def f_compare(d, r):
    d = os.path.realpath(d)
    if d not in SNAPSHOTS:
        r.skip("No snapshot for this directory yet; run feature 74 first")
        return
    old = SNAPSHOTS[d]
    new, _, cut = snapshot(d)
    added, removed = sorted(set(new) - set(old)), sorted(set(old) - set(new))
    changed = sorted(k for k in set(old) & set(new) if old[k] != new[k])
    for label, items in (("Added", added), ("Removed", removed), ("Modified", changed)):
        for p in items[:10]:
            r.fail("%s: %s" % (label, p))
    if cut:
        r.warn("Comparison limited to the first 500 files")
    if not (added or removed or changed):
        r.ok("No differences from the stored snapshot (%d files)" % len(new))


SENSITIVE_FILE = re.compile(r"(id_rsa|id_ed25519|\.pem$|\.key$|\.p12$|\.env|\.netrc|\.pgpass|credentials)", re.I)


def f_perms(path, r):
    if os.name == "nt":
        r.skip("POSIX permission bits are not available on Windows")
        return
    items = [path]
    if os.path.isdir(path):
        for root, dirs, files in os.walk(path, followlinks=False):
            items += [os.path.join(root, x) for x in dirs + files]
            if len(items) >= 1000:
                r.warn("Stopped at 1000 entries")
                break
    ww = sg = sens = 0
    for p in items:
        try:
            st = os.lstat(p)
        except OSError:
            continue
        mode = st.st_mode
        if os.path.islink(p):
            continue
        if mode & 0o002 and not mode & 0o1000:
            ww += 1
            r.fail("World-writable: %s (%o)" % (p, mode & 0o7777)) if ww <= 10 else None
        if mode & 0o6000:
            sg += 1
            r.warn("setuid/setgid bit: %s" % p) if sg <= 10 else None
        if SENSITIVE_FILE.search(os.path.basename(p)) and mode & 0o077 and os.path.isfile(p):
            sens += 1
            r.fail("Sensitive file readable by group/others: %s (%o)" % (p, mode & 0o7777)) if sens <= 10 else None
    r.info("Examined %d entries: %d world-writable, %d setuid/setgid, %d exposed sensitive files" % (len(items), ww, sg, sens))
    if not (ww or sg or sens):
        r.ok("No risky permission patterns found")


def read_lines(path, r, cap=200000):
    lines = []
    with open(path, "r", errors="replace") as fh:
        for i, ln in enumerate(fh):
            if i >= cap:
                r.warn("Log truncated at %d lines for memory safety" % cap)
                break
            lines.append(ln.rstrip("\n"))
    return lines


def _top(counter, n=10):
    return sorted(counter.items(), key=lambda kv: -kv[1])[:n]


def f_log_failed(path, r):
    lines = read_lines(path, r)
    by_ip, users = {}, {}
    for ln in lines:
        m = re.search(r"Failed password for (?:invalid user )?(\S+) from (\S+)", ln)
        m2 = re.search(r"authentication failure.*rhost=(\S+)", ln)
        m3 = re.match(r'^(\S+) .*" (401|403) ', ln)
        ip = m.group(2) if m else m2.group(1) if m2 else m3.group(1) if m3 else None
        if ip:
            by_ip[ip] = by_ip.get(ip, 0) + 1
        if m:
            users[m.group(1)] = users.get(m.group(1), 0) + 1
    r.info("Scanned %d line(s); %d failed-auth event(s) from %d source(s)" % (len(lines), sum(by_ip.values()), len(by_ip)))
    for ip, n in _top(by_ip, 8):
        (r.warn if n >= 5 else r.info)("%s: %d failure(s)" % (ip, n))
    if users:
        r.info("Most targeted accounts: " + ", ".join("%s(%d)" % kv for kv in _top(users, 5)))
    if not by_ip:
        r.info("No recognized failed-login patterns (sshd, PAM, HTTP 401/403) found")


COMBINED = re.compile(r'^(\S+) \S+ \S+ \[([^\]]+)\] "([^"]*)" (\d{3}) (\S+)')


def f_log_status(path, r):
    codes, n = {}, 0
    for ln in read_lines(path, r):
        m = COMBINED.match(ln)
        if m:
            n += 1
            codes[m.group(4)] = codes.get(m.group(4), 0) + 1
    if not n:
        r.skip("No lines in Common/Combined Log Format were recognized")
        return
    for code, k in sorted(codes.items()):
        r.info("HTTP %s: %d (%.1f%%)" % (code, k, 100.0 * k / n))
    errs = sum(k for c_, k in codes.items() if c_.startswith("5"))
    if errs / n > 0.05:
        r.warn("Server errors exceed 5%% of requests (%d of %d)" % (errs, n))
    else:
        r.ok("Parsed %d request(s); server-error rate %.1f%%" % (n, 100.0 * errs / n))


SUSPECT = {
    "path traversal": r"\.\./|%2e%2e",
    "XSS probe": r"<script|%3cscript|onerror=",
    "SQLi probe": r"union(\s|%20|\+)+select|%27(\s|%20)*or|'\s*or\s*'1'\s*=\s*'1|sleep\(",
    "scanner user-agent": r"sqlmap|nikto|nmap|masscan|dirbuster",
    "sensitive file request": r"/\.env|/\.git/|/wp-login|/phpmyadmin|/etc/passwd",
}


def f_log_suspicious(path, r):
    counts, samples = {k: 0 for k in SUSPECT}, {}
    lines = read_lines(path, r)
    for ln in lines:
        for k, rx in SUSPECT.items():
            if re.search(rx, ln, re.I):
                counts[k] += 1
                samples.setdefault(k, ln[:100])
    total = sum(counts.values())
    r.info("Scanned %d line(s) for %d pattern classes (detection only)" % (len(lines), len(SUSPECT)))
    for k, n in counts.items():
        if n:
            r.warn("%s: %d line(s), e.g. %s" % (k, n, samples[k]))
    if not total:
        r.info("No listed patterns found. Heuristic regexes cannot catch encoded or novel attacks.")


def f_log_top(path, r):
    ips, perminute, n = {}, {}, 0
    for ln in read_lines(path, r):
        m = COMBINED.match(ln)
        if not m:
            continue
        n += 1
        ips[m.group(1)] = ips.get(m.group(1), 0) + 1
        key = (m.group(1), m.group(2)[:17])
        perminute[key] = perminute.get(key, 0) + 1
    if not n:
        r.skip("No lines in Common/Combined Log Format were recognized")
        return
    for ip, k in _top(ips, 8):
        r.info("%s: %d request(s)" % (ip, k))
    (ip, minute), peak = max(perminute.items(), key=lambda kv: kv[1])
    if peak > 120:
        r.warn("Burst: %s sent %d requests within minute %s" % (ip, peak, minute))
    else:
        r.ok("Peak single-IP rate %d requests/minute (no burst over 120)" % peak)


# ---- configuration audits ------------------------------------------------------
def _read_text(path, r, cap=2 * 1024 * 1024):
    if os.path.getsize(path) > cap:
        r.warn("File larger than 2 MB; only the first 2 MB was read")
    with open(path, "r", errors="replace") as fh:
        return fh.read(cap)


def f_sshd(path, r):
    cfg = {}
    for ln in _read_text(path, r).splitlines():
        ln = ln.strip()
        if ln and not ln.startswith("#"):
            k, _, v = ln.partition(" ")
            cfg.setdefault(k.lower(), v.strip().lower())
    if not cfg:
        r.skip("No directives found; is this an sshd_config file?")
        return
    rules = [("permitrootlogin", {"yes"}, "FAIL", "root login over SSH enabled"),
             ("passwordauthentication", {"yes"}, "WARN", "password logins enabled (prefer keys)"),
             ("permitemptypasswords", {"yes"}, "FAIL", "empty passwords permitted"),
             ("protocol", {"1", "2,1"}, "FAIL", "SSH protocol 1 enabled"),
             ("x11forwarding", {"yes"}, "WARN", "X11 forwarding enabled"),
             ("pubkeyauthentication", {"no"}, "WARN", "public-key auth disabled")]
    for key, bad, lvl, msg in rules:
        if key in cfg:
            if cfg[key] in bad:
                r.add(lvl, "%s %s: %s" % (key, cfg[key], msg))
            else:
                r.ok("%s %s" % (key, cfg[key]))
        else:
            r.info("%s not set (compiled-in default applies)" % key)
    if "maxauthtries" in cfg and cfg["maxauthtries"].isdigit() and int(cfg["maxauthtries"]) > 4:
        r.warn("MaxAuthTries %s is high" % cfg["maxauthtries"])


def f_webserver_conf(path, r):
    t = _read_text(path, r)
    low = t.lower()
    if not t.strip():
        r.skip("Empty file")
        return
    checks = [
        ("server_tokens off", "servertokens prod", "Version disclosure setting (nginx server_tokens / Apache ServerTokens)"),
        ("x-content-type-options", None, "X-Content-Type-Options header configured"),
        ("strict-transport-security", None, "HSTS header configured"),
        ("content-security-policy", None, "CSP header configured"),
    ]
    for a, b, label in checks:
        (r.ok if (a in low or (b and b in low)) else r.warn)(label + (": found" if (a in low or (b and b in low)) else ": not found"))
    m = re.search(r"ssl_protocols\s+([^;]+);|sslprotocol\s+(.+)", low)
    if m:
        val = (m.group(1) or m.group(2)).strip()
        if re.search(r"tlsv1(\s|$)|tlsv1\.1|sslv3|\+tlsv1(\s|$)", val + " "):
            r.fail("Legacy protocols enabled: " + val)
        else:
            r.ok("Protocols: " + val)
    if re.search(r"autoindex\s+on|options[^\n]*\+?indexes", low):
        r.warn("Directory listing appears enabled")
    r.info("Limited: text/regex audit; 'include' files and per-vhost overrides are not resolved.")


def f_envfile(path, r):
    secret_rx = re.compile(r"pass|secret|token|key|credential|private|salt", re.I)
    weak = {"", "changeme", "password", "secret", "123456", "admin", "test", "default", "example", "todo", "xxx"}
    n = sec = 0
    for ln in _read_text(path, r).splitlines():
        ln = ln.strip()
        if not ln or ln.startswith("#") or "=" not in ln:
            continue
        k, _, v = ln.replace("export ", "", 1).partition("=")
        k, v = k.strip(), v.strip().strip("'\"")
        n += 1
        if secret_rx.search(k):
            sec += 1
            if v.lower() in weak:
                r.warn("%s: empty or placeholder/weak value" % k)
        if k.upper() in ("DEBUG", "APP_DEBUG", "FLASK_DEBUG") and v.lower() in ("1", "true", "yes", "on"):
            r.warn("%s enabled (debug mode must be off in production)" % k)
    r.info("%d variable(s), %d secret-like name(s); values are never displayed" % (n, sec))
    if os.name != "nt":
        mode = os.stat(path).st_mode & 0o777
        (r.fail if mode & 0o077 else r.ok)("File mode %o%s" % (mode, " is readable by group/others" if mode & 0o077 else ""))
    d, depth = os.path.dirname(os.path.abspath(path)), 0
    while depth < 5:
        if os.path.isdir(os.path.join(d, ".git")):
            gi = os.path.join(d, ".gitignore")
            ignored = os.path.isfile(gi) and re.search(r"^\s*/?\.env", open(gi, errors="replace").read(), re.M)
            (r.ok if ignored else r.warn)("Inside a git repository: .env %s in .gitignore" % ("listed" if ignored else "NOT listed"))
            break
        d, depth = os.path.dirname(d), depth + 1


def f_requirements(path, r):
    reqs = [ln.strip() for ln in _read_text(path, r).splitlines() if ln.strip() and not ln.strip().startswith("#")]
    pkgs = [x for x in reqs if not x.startswith("-")]
    unpinned = [x for x in pkgs if "==" not in x and "@" not in x]
    r.info("%d requirement(s), %d unpinned" % (len(pkgs), len(unpinned)))
    for x in unpinned[:10]:
        r.warn("Not pinned to an exact version: " + x[:60])
    for x in reqs:
        if re.search(r"--(extra-)?index-url\s+http://|--trusted-host", x):
            r.fail("Insecure package index or trusted-host option: " + x[:60])
        if re.search(r"git\+|https?://", x) and not x.startswith("--"):
            r.warn("Installs from a URL/VCS source: " + x[:60])
    if pkgs and not unpinned:
        r.ok("All requirements pinned")
    r.info("Limited: no vulnerability database is consulted offline; run pip-audit separately.")


def f_envcheck(arg, r):
    r.info("Python %s on %s" % (platform.python_version(), platform.platform()))
    r.info("OpenSSL: " + ssl.OPENSSL_VERSION)
    termux = "com.termux" in os.environ.get("PREFIX", "") or bool(os.environ.get("TERMUX_VERSION"))
    r.info("Environment: " + ("Termux (Android)" if termux else "Linux/other"))
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        r.warn("Running as root: this toolkit never needs it")
    else:
        r.ok("Running without elevated privileges")
    if hasattr(os, "umask"):
        m = os.umask(0)
        os.umask(m)
        (r.warn if not m & 0o020 or not m & 0o002 else r.ok)("umask %03o" % m)
    (r.ok if SETTINGS["verify_tls"] else r.warn)("TLS verification is %s" % ("enabled" if SETTINGS["verify_tls"] else "DISABLED in settings"))
    r.info("Authorized external targets this session: %d" % len(authorized_set()))


# =============================================================================
# 11. THE 100-FEATURE REGISTRY
#     Row: (id, name, description, input_type, kind, needs_auth_confirmation, handler_name)
#     Handlers are resolved to callables by build_registry() once all sections are loaded.
# =============================================================================
FEATURE_TABLE = [
    (1, "Status & timing summary", "Fetch a URL; report status, size and time", "url", "real", False, "f_status"),
    (2, "Response header dump", "List all response headers (cookie values hidden)", "url", "real", False, "f_headers"),
    (3, "Redirect chain trace", "Follow redirects with per-hop authorization checks", "url", "real", False, "f_redirects"),
    (4, "HTTP methods (OPTIONS)", "Read advertised methods; flag TRACE/PUT/DELETE", "url", "real", False, "f_methods"),
    (5, "Server banner disclosure", "Detect product/version leakage in Server header", "url", "real", False, "f_banner"),
    (6, "Response time sampling", "Three light requests; min/avg/max latency", "url", "real", False, "f_timing"),
    (7, "Content-Type & charset", "Check Content-Type and charset declaration", "url", "real", False, "f_ctype"),
    (8, "Compression check", "Content-Encoding and Vary correctness", "url", "real", False, "f_compress"),
    (9, "Cache-Control analysis", "Evaluate caching policy and public+cookie risk", "url", "real", False, "f_cache"),
    (10, "HTTP to HTTPS upgrade", "Does plain HTTP redirect to HTTPS?", "url", "real", False, "f_https_upgrade"),
    (11, "HSTS policy", "Strict-Transport-Security presence and max-age", "url", "real", False, "f_hsts"),
    (12, "CSP presence", "Content-Security-Policy enforced or report-only", "url", "real", False, "f_csp"),
    (13, "CSP weak directives", "Flag unsafe-inline/eval, wildcards, missing directives", "url", "real", False, "f_csp_weak"),
    (14, "Clickjacking protection", "X-Frame-Options / frame-ancestors", "url", "real", False, "f_clickjack"),
    (15, "X-Content-Type-Options", "Require nosniff", "url", "real", False, "f_xcto"),
    (16, "Referrer-Policy", "Presence and strength of Referrer-Policy", "url", "real", False, "f_referrer"),
    (17, "Permissions-Policy", "Feature restriction policy header", "url", "real", False, "f_permissions"),
    (18, "Cross-origin isolation", "COOP / COEP / CORP headers", "url", "real", False, "f_cross_origin"),
    (19, "Technology disclosure", "X-Powered-By and similar version leaks", "url", "real", False, "f_tech_leak"),
    (20, "CORS policy", "Wildcard/reflected origin and credentials", "url", "real", False, "f_cors"),
    (21, "Deprecated headers", "X-XSS-Protection, HPKP, Expect-CT, Feature-Policy", "url", "real", False, "f_deprecated"),
    (22, "Security header score", "Unweighted grade over key headers", "url", "limited", False, "f_score"),
    (23, "Cookie inventory", "List Set-Cookie names and attributes", "url", "real", False, "f_cookie_list"),
    (24, "Cookie Secure flag", "Secure attribute on every cookie", "url", "real", False, "f_cookie_secure"),
    (25, "Cookie HttpOnly flag", "HttpOnly, with session-name emphasis", "url", "real", False, "f_cookie_httponly"),
    (26, "Cookie SameSite", "SameSite value and SameSite=None rules", "url", "real", False, "f_cookie_samesite"),
    (27, "Cookie prefixes & scope", "__Host-/__Secure- rules and Domain scope", "url", "real", False, "f_cookie_scope"),
    (28, "Cookie lifetime & size", "Persistence of auth-like cookies; size", "url", "real", False, "f_cookie_life"),
    (29, "Page metadata", "Title, meta tags, generator disclosure", "url", "real", False, "f_meta"),
    (30, "Form inventory", "Forms, methods, actions and fields", "url", "real", False, "f_forms"),
    (31, "Password form transport", "Password forms: POST + HTTPS", "url", "real", False, "f_pw_forms"),
    (32, "CSRF token heuristic", "Look for anti-CSRF fields in POST forms", "url", "limited", False, "f_csrf"),
    (33, "External scripts", "List third-party script sources", "url", "real", False, "f_ext_scripts"),
    (34, "Subresource Integrity", "integrity= on external scripts/styles", "url", "real", False, "f_sri"),
    (35, "Inline script exposure", "Inline scripts and handlers vs CSP", "url", "real", False, "f_inline"),
    (36, "Mixed content", "http:// resources on HTTPS pages", "url", "real", False, "f_mixed"),
    (37, "HTML comment scan", "Sensitive keywords in comments", "url", "limited", False, "f_comments"),
    (38, "target=_blank safety", "rel=noopener on new-tab links", "url", "real", False, "f_blank"),
    (39, "TLS certificate summary", "Verified subject, issuer, validity", "tls", "real", False, "f_tls_cert"),
    (40, "TLS certificate expiry", "Days until expiry with thresholds", "tls", "real", False, "f_tls_expiry"),
    (41, "TLS protocol & cipher", "Negotiated version and cipher strength", "tls", "real", False, "f_tls_proto"),
    (42, "TLS trust & hostname", "Chain and hostname verification result", "tls", "real", False, "f_tls_host"),
    (43, "TLS SAN list", "subjectAltName coverage and wildcards", "tls", "real", False, "f_tls_san"),
    (44, "TLS versions accepted", "Probe TLS 1.0-1.3 (client-limited)", "tls", "limited", True, "f_tls_versions"),
    (45, "Resolve addresses", "A/AAAA lookup via system resolver", "host", "real", False, "f_resolve"),
    (46, "Reverse DNS lookup", "PTR record for an authorized IP", "ip", "real", False, "f_reverse"),
    (47, "IP classification", "Offline private/loopback/global analysis", "text", "real", False, "f_ip_class"),
    (48, "CIDR calculator", "Offline network, mask, usable range", "text", "real", False, "f_cidr"),
    (49, "Hostname syntax check", "RFC 1123 validation and punycode", "text", "real", False, "f_hostname_syntax"),
    (50, "DNS answer sanity", "Consistency and rebinding indicators", "host", "real", False, "f_dns_sanity"),
    (51, "TCP port check", "Single authorized port connect", "hostport", "real", True, "f_port"),
    (52, "Common ports check", "12 well-known ports, sequential", "host", "real", True, "f_common_ports"),
    (53, "TCP connect latency", "Five connects; min/avg/max", "hostport", "real", True, "f_latency"),
    (54, "Passive banner read", "Read greeting without sending data", "hostport", "real", True, "f_banner_read"),
    (55, "Local interface addresses", "Hostname and local IPv4 addresses", "none", "real", False, "f_ifaces"),
    (56, "Localhost listeners", "Common loopback ports on 127.0.0.1", "none", "real", False, "f_localhost_listen"),
    (57, "JSON validity", "Parse API response; check Content-Type", "url", "real", False, "f_json_valid"),
    (58, "JSON structure inventory", "Types, depth and key names", "url", "real", False, "f_json_struct"),
    (59, "Sensitive JSON fields", "Password/token-like key names", "url", "limited", False, "f_json_sensitive"),
    (60, "API error verbosity", "Stack traces and paths in errors", "url", "limited", False, "f_error_verbose"),
    (61, "Rate-limit headers", "RateLimit/Retry-After headers", "url", "real", False, "f_ratelimit_headers"),
    (62, "Rate-limit probe (max 10)", "Small sequential probe for HTTP 429", "url", "limited", True, "f_ratelimit_probe"),
    (63, "Lab server self-test", "Start lab, test client against it, stop", "none", "real", False, "f_lab_selftest"),
    (64, "SQL injection demo", "In-memory vulnerable vs parameterized query", "textopt", "simulated", False, "f_sqli_demo"),
    (65, "XSS escaping demo", "Unescaped vs escaped output (text only)", "textopt", "simulated", False, "f_xss_demo"),
    (66, "Lab header detection test", "Verify header checks on lab pages", "none", "real", False, "f_lab_headers"),
    (67, "CSRF token demo", "HMAC session-bound token mechanism", "none", "simulated", False, "f_csrf_demo"),
    (68, "Rate limiter simulation", "Token-bucket on a virtual clock", "none", "simulated", False, "f_ratelimit_sim"),
    (69, "Path traversal guard demo", "realpath/commonpath containment", "textopt", "simulated", False, "f_traversal_demo"),
    (70, "Password hashing demo", "SHA-256 vs PBKDF2 cost", "none", "simulated", False, "f_pw_hash_demo"),
    (71, "Hash text", "MD5/SHA-1/SHA-2/SHA-3 digests", "text", "real", False, "f_hash_text"),
    (72, "Hash file", "Chunked file hashing", "file", "real", False, "f_hash_file"),
    (73, "Verify file hash", "Compare file with expected digest", "hashfile", "real", False, "f_hash_verify"),
    (74, "Directory snapshot", "SHA-256 baseline of a directory (memory)", "dir", "real", False, "f_snapshot"),
    (75, "Directory integrity compare", "Compare against stored snapshot", "dir", "real", False, "f_compare"),
    (76, "Permission audit", "World-writable, setuid, exposed key files", "path", "real", False, "f_perms"),
    (77, "Log: failed logins", "sshd/PAM/HTTP 401-403 by source", "file", "limited", False, "f_log_failed"),
    (78, "Log: HTTP status mix", "Status distribution, 5xx rate", "file", "real", False, "f_log_status"),
    (79, "Log: suspicious requests", "Traversal/XSS/SQLi/scanner patterns", "file", "limited", False, "f_log_suspicious"),
    (80, "Log: top IPs & bursts", "Busiest clients and per-minute peaks", "file", "real", False, "f_log_top"),
    (81, "E-mail syntax validator", "RFC-style syntax checks", "text", "real", False, "f_email"),
    (82, "URL validator", "Scheme/host/credential checks + scope", "text", "real", False, "f_url_validate"),
    (83, "Password strength estimator", "Length, classes, entropy, common list", "secret", "limited", False, "f_pw_strength"),
    (84, "Output encoding helper", "HTML/URL/JSON/shell encodings", "text", "real", False, "f_escape"),
    (85, "Suspicious input detector", "Attack-pattern heuristics on input", "text", "limited", False, "f_susp_input"),
    (86, "Auth challenge check", "401 scheme: Basic over HTTP/HTTPS", "url", "real", False, "f_basic_auth"),
    (87, "Login anti-automation hints", "CAPTCHA/no-store/rate-limit hints", "url", "limited", False, "f_login_hints"),
    (88, "Session token entropy", "Estimate strength of a pasted token", "secret", "limited", False, "f_session_entropy"),
    (89, "JWT inspector", "Decode claims; flag alg=none (no verify)", "secret", "limited", False, "f_jwt"),
    (90, "Auth policy checklist", "Manual self-assessment questions", "none", "limited", False, "f_auth_checklist"),
    (91, "sshd_config audit", "Root login, passwords, protocol", "file", "real", False, "f_sshd"),
    (92, "Web server config audit", "nginx/Apache hardening directives", "file", "limited", False, "f_webserver_conf"),
    (93, ".env secrets audit", "Weak values, debug, mode, gitignore", "file", "real", False, "f_envfile"),
    (94, "requirements.txt audit", "Unpinned/insecure package sources", "file", "limited", False, "f_requirements"),
    (95, "Environment audit", "Python, OpenSSL, root, umask, settings", "none", "real", False, "f_envcheck"),
    (96, "Session summary", "Results recorded this session", "none", "real", False, "f_session_summary"),
    (97, "Export JSON report", "Write results to a JSON file on request", "textopt", "real", False, "f_export_json"),
    (98, "Export TXT report", "Write results to a TXT file on request", "textopt", "real", False, "f_export_txt"),
    (99, "Authorized targets manager", "List/add/remove authorized targets", "none", "real", False, "f_auth_mgr"),
    (100, "Dependency check", "Verify required standard-library modules", "none", "real", False, "f_deps"),
]
REGISTRY = {}


def category_of(fid):
    for lo, hi, name in CATEGORIES:
        if lo <= fid <= hi:
            return name
    return "Other"


def build_registry():
    REGISTRY.clear()
    for fid, name, desc, needs, kind, auth, fn in FEATURE_TABLE:
        REGISTRY[fid] = {"id": fid, "name": name, "description": desc, "needs": needs, "kind": kind,
                         "auth": auth, "category": category_of(fid), "func": globals().get(fn), "handler": fn}


def verify_registry():
    """Return a list of problems (empty list means the registry is consistent)."""
    p = []
    ids = [row[0] for row in FEATURE_TABLE]
    if len(ids) != 100:
        p.append("expected 100 rows, found %d" % len(ids))
    if len(set(ids)) != len(ids):
        p.append("duplicate feature IDs")
    if sorted(ids) != list(range(1, 101)):
        p.append("IDs are not exactly 1..100")
    names = [row[1] for row in FEATURE_TABLE]
    if len(set(names)) != len(names):
        p.append("duplicate feature names")
    handlers = [row[6] for row in FEATURE_TABLE]
    if len(set(handlers)) != len(handlers):
        p.append("a handler is registered more than once")
    for fid, f in sorted(REGISTRY.items()):
        if not callable(f["func"]):
            p.append("#%d handler '%s' does not exist" % (fid, f["handler"]))
            continue
        if len(inspect.signature(f["func"]).parameters) != 2:
            p.append("#%d handler must accept (arg, result)" % fid)
        if f["needs"] not in NEEDS:
            p.append("#%d unknown input type" % fid)
        if f["kind"] not in KINDS:
            p.append("#%d unknown kind" % fid)
        if not f["name"] or not f["description"]:
            p.append("#%d missing name/description" % fid)
    return p


# =============================================================================
# 12. REPORT EXPORT  (features 96-100; files are written ONLY on explicit request)
# =============================================================================
def report_data():
    return {"tool": APP, "version": VERSION, "generated": datetime.datetime.now().isoformat(timespec="seconds"),
            "disclaimer": DISCLAIMER, "network_operations_used": STATE["requests"], "results": SESSION}


def write_report(fmt, path, r):
    if not SESSION:
        r.skip("Nothing to export: no checks have been run this session")
        return
    if not path:
        stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        path = os.path.join(SETTINGS["report_dir"], "toolkit_report_%s.%s" % (stamp, fmt))
    path = os.path.expanduser(path)
    d = os.path.dirname(os.path.abspath(path))
    try:
        os.makedirs(d, exist_ok=True)
        with open(path, "x", encoding="utf-8") as fh:
            if fmt == "json":
                json.dump(report_data(), fh, indent=2)
            else:
                fh.write("%s v%s - report %s\n%s\n\n" % (APP, VERSION, report_data()["generated"], DISCLAIMER))
                for e in SESSION:
                    fh.write("#%s %s  [%s]  target: %s  (%s)\n" % (e["id"], e["name"], e["status"], e["target"], e["time"]))
                    for f in e["findings"]:
                        fh.write("    [%s] %s\n" % (f["level"], f["message"]))
                    fh.write("\n")
    except FileExistsError:
        r.err("File already exists; refusing to overwrite: " + path)
        return
    except OSError as e:
        r.err("Could not write report: %s" % e)
        return
    r.ok("Report with %d result(s) written to %s" % (len(SESSION), path))


def f_session_summary(arg, r):
    if not SESSION:
        r.info("No checks have been run yet this session")
        return
    counts = {}
    for e in SESSION:
        counts[e["status"]] = counts.get(e["status"], 0) + 1
    r.info("%d check(s) run, %d network operation(s) used" % (len(SESSION), STATE["requests"]))
    r.info("By status: " + ", ".join("%s=%d" % kv for kv in sorted(counts.items())))
    for e in SESSION[-15:]:
        r.info("#%s %s -> %s" % (e["id"], e["name"], e["status"]))
    r.ok("Summary generated from recorded results")


def f_export_json(arg, r):
    write_report("json", arg, r)


def f_export_txt(arg, r):
    write_report("txt", arg, r)


def f_auth_mgr(arg, r):
    cur = sorted(authorized_set())
    r.info("Always allowed: localhost and private/loopback addresses.")
    r.info("Authorized external targets: " + (", ".join(cur) if cur else "none"))
    try:
        act = ask("Action: [a]dd, [r]emove, Enter to finish", "").lower()
        if act.startswith("a"):
            h = ask("Hostname or IP you are authorized to test").strip().lower()
            ok, why = validate_hostname(h)
            if not ok:
                r.fail("Invalid hostname: " + why)
            elif ask("Type 'I AM AUTHORIZED' to confirm written permission for %s" % h) == "I AM AUTHORIZED":
                SETTINGS["authorized"].append(h)
                r.ok("Added %s for this session only (not saved to disk)" % h)
            else:
                r.warn("Confirmation text did not match; target not added")
        elif act.startswith("r"):
            h = ask("Target to remove").strip().lower()
            if h in SETTINGS["authorized"]:
                SETTINGS["authorized"].remove(h)
                r.ok("Removed " + h)
            else:
                r.warn("Not in the session list (environment-provided targets cannot be removed here)")
    except UserAbort:
        r.info("No input available; list shown only")


def f_deps(arg, r):
    r.info("Python %s" % platform.python_version())
    (r.ok if sys.version_info >= (3, 8) else r.fail)("Python 3.8+ requirement")
    for m in ("ssl", "socket", "sqlite3", "json", "hashlib", "hmac", "ipaddress", "html.parser",
              "http.server", "urllib.request", "zlib", "threading", "base64"):
        try:
            __import__(m)
            r.ok("module %s available" % m)
        except ImportError:
            r.fail("module %s MISSING (reinstall python)" % m)
    r.info("No third-party packages are required.")


# =============================================================================
# 13. MAIN MENU AND ENTRY POINT
# =============================================================================
def parse_hostport(s, default_port=None):
    s = s.strip()
    if "://" in s:
        u = urllib.parse.urlsplit(s)
        return u.hostname, u.port or default_port
    if s.startswith("["):
        host, _, rest = s[1:].partition("]")
        return host, int(rest[1:]) if rest.startswith(":") else default_port
    if s.count(":") == 1:
        host, _, port = s.partition(":")
        return host, int(port)
    return s, default_port


def collect(needs, preset=None):
    def val(prompt, default=""):
        return preset if preset is not None else ask(prompt, default)

    def bad(msg):
        print_line("ERR", msg)
        return False, None

    if needs == "none":
        return True, None
    if needs == "url":
        ok, res, _ = validate_url(val("Target URL (e.g. http://127.0.0.1:8099/)"))
        return (True, res) if ok else bad("Invalid URL: " + res)
    if needs in ("host", "ip", "hostport", "tls"):
        label = {"host": "Hostname or IP", "ip": "IP address", "hostport": "host:port", "tls": "host[:port] (default 443)"}[needs]
        try:
            host, port = parse_hostport(val(label), 443 if needs == "tls" else None)
        except ValueError:
            return bad("Could not parse that value")
        ok, why = validate_hostname(host or "")
        if not ok:
            return bad("Invalid host: " + why)
        if needs == "ip" and not parse_ip(host):
            return bad("Not an IP address")
        if needs in ("hostport", "tls"):
            if port is None or not 1 <= port <= 65535:
                return bad("A valid port (1-65535) is required")
            return True, (host.lower(), port)
        return True, host.lower()
    if needs in ("text", "textopt"):
        s = val("Input" + (" (Enter for default sample)" if needs == "textopt" else ""))
        return (True, s) if (s or needs == "textopt") else bad("Input is required")
    if needs == "secret":
        s = preset if preset is not None else ask_secret("Value")
        return (True, s) if s else bad("Input is required")
    if needs in ("file", "dir", "path"):
        p = os.path.expanduser(val({"file": "File path", "dir": "Directory path", "path": "File or directory path"}[needs]))
        good = {"file": os.path.isfile, "dir": os.path.isdir, "path": os.path.exists}[needs](p)
        return (True, p) if good else bad("Path not found or wrong type: " + p)
    if needs == "hashfile":
        if preset is not None:
            p, _, h = preset.partition(",")
        else:
            p, h = ask("File path"), ask("Expected hex digest")
        p = os.path.expanduser(p)
        return (True, (p, h)) if os.path.isfile(p) and h else bad("Need an existing file and a digest")
    return bad("Unsupported input type")


def target_host(needs, arg):
    if needs == "url":
        return urllib.parse.urlsplit(arg).hostname
    if needs in ("host", "ip"):
        return arg
    if needs in ("hostport", "tls"):
        return arg[0]
    return None


def run_feature(fid, preset=None, assume_auth=False):
    f = REGISTRY[fid]
    print()
    hr("=")
    out("[%d] %s  (%s)" % (fid, f["name"], f["category"]))
    out(f["description"])
    net = f["needs"] in NET_NEEDS
    out("Kind: %s%s%s" % (f["kind"], " | sends network traffic" if net else "",
                         " | AUTHORIZATION REQUIRED" if f["auth"] else ""))
    hr()
    try:
        ok, arg = collect(f["needs"], preset)
    except UserAbort:
        print_line("SKIP", "Input closed.")
        return None
    except KeyboardInterrupt:
        print_line("WARN", "Cancelled.")
        return None
    if not ok:
        return None
    r = Result()
    host, go = target_host(f["needs"], arg), True
    if host:
        allowed, why = check_target(host)
        if not allowed:
            r.err("REFUSED: %s. Only localhost, private labs and explicitly authorized targets may be tested "
                  "(add one via feature 99 after confirming permission)." % why)
            r.forced, go = "REFUSED", False
        elif f["auth"] and why == "explicitly authorized target" and not assume_auth:
            try:
                go = ask("This check probes %s. Type YES to confirm you are authorized" % host) == "YES"
            except UserAbort:
                go = False
            if not go:
                r.skip("Authorization not confirmed; nothing was sent.")
    if go:
        try:
            f["func"](arg, r)
        except KeyboardInterrupt:
            r.warn("Interrupted by user; results may be incomplete")
        except UserAbort:
            r.skip("Input closed")
        except Exception as e:  # noqa: BLE001
            r.err("Internal error: %s: %s" % (type(e).__name__, e))
    for lvl, msg in r.lines:
        print_line(lvl, msg)
    status = r.status()
    if f["kind"] == "simulated" and status not in ("ERROR", "REFUSED", "SKIPPED"):
        status = "SIMULATED"
    hr()
    out("Result: %s | kind: %s%s" % (status, f["kind"], " (demo only; no target tested)" if f["kind"] == "simulated" else ""))
    shown = f["needs"] in ("url", "host", "ip", "hostport", "tls", "file", "dir", "path")
    SESSION.append({"id": fid, "name": f["name"], "kind": f["kind"], "status": status,
                    "target": clean(str(arg)) if shown else "<input not recorded>",
                    "time": datetime.datetime.now().isoformat(timespec="seconds"),
                    "findings": [{"level": lv, "message": m} for lv, m in r.lines]})
    return status


def feature_tag(f):
    t = "S" if f["kind"] == "simulated" else "L" if f["kind"] == "limited" else "R"
    return "%s%s" % (t, "!" if f["auth"] else ("n" if f["needs"] in NET_NEEDS else " "))


def list_features(ids):
    w = width()
    for fid in ids:
        f = REGISTRY[fid]
        print("%3d %s %s" % (fid, c(feature_tag(f), "33"), f["name"][:w - 8]))


def pick_and_run(ids):
    sel = ask("Feature ID to run (Enter to go back)", "")
    if sel.isdigit() and int(sel) in ids:
        run_feature(int(sel))
    elif sel:
        print_line("WARN", "Choose an ID from the list.")


def category_menu(lo, hi, name):
    ids = list(range(lo, hi + 1))
    while True:
        print()
        hr()
        out("%s  [%d-%d]" % (name, lo, hi))
        list_features(ids)
        out("Legend: R real, L limited, S simulated | n network, ! needs authorization")
        sel = ask("ID to run, 'b' back", "b").lower()
        if sel in ("b", "back", "q", ""):
            return
        if sel.isdigit() and int(sel) in ids:
            run_feature(int(sel))
        else:
            print_line("WARN", "Choose an ID from this category, or 'b'.")


def search_menu():
    q = ask("Search keyword (name, description or category)", "").lower()
    if not q:
        return
    ids = [i for i, f in REGISTRY.items() if q in (f["name"] + " " + f["description"] + " " + f["category"]).lower()]
    if not ids:
        print_line("INFO", "No features match '%s'." % clean(q))
        return
    print()
    list_features(ids[:30])
    if len(ids) > 30:
        out("... %d more; refine the search." % (len(ids) - 30))
    pick_and_run(ids[:30])


def ask_num(label, cur, lo, hi, cast):
    try:
        v = cast(ask("%s (%s-%s)" % (label, lo, hi), str(cur)))
    except ValueError:
        print_line("ERR", "Not a number.")
        return cur
    if not lo <= v <= hi:
        print_line("ERR", "Out of range.")
        return cur
    return v


def settings_menu():
    while True:
        print()
        hr()
        out("Settings (this session only)")
        out("1) timeout %.1fs   2) max body %d bytes   3) request budget %d (used %d)" % (
            SETTINGS["timeout"], SETTINGS["max_bytes"], SETTINGS["budget"], STATE["requests"]))
        out("4) delay %.2fs   5) verify TLS: %s   6) report dir: %s" % (
            SETTINGS["delay"], SETTINGS["verify_tls"], SETTINGS["report_dir"]))
        out("7) reset budget counter   8) restore defaults   b) back")
        s = ask("Choice", "b").lower()
        if s == "1":
            SETTINGS["timeout"] = ask_num("Timeout seconds", SETTINGS["timeout"], 1.0, 60.0, float)
        elif s == "2":
            SETTINGS["max_bytes"] = ask_num("Max response bytes", SETTINGS["max_bytes"], 1024, 5242880, int)
        elif s == "3":
            SETTINGS["budget"] = ask_num("Request budget", SETTINGS["budget"], 1, 500, int)
        elif s == "4":
            SETTINGS["delay"] = ask_num("Delay seconds", SETTINGS["delay"], 0.0, 5.0, float)
        elif s == "5":
            SETTINGS["verify_tls"] = not SETTINGS["verify_tls"]
            if not SETTINGS["verify_tls"]:
                print_line("WARN", "TLS verification disabled: use ONLY for local labs.")
        elif s == "6":
            SETTINGS["report_dir"] = ask("Report directory", SETTINGS["report_dir"])
        elif s == "7":
            STATE["requests"] = 0
        elif s == "8":
            auth = SETTINGS["authorized"]
            SETTINGS.update(DEFAULTS)
            SETTINGS["authorized"] = auth
        elif s in ("b", "back", ""):
            return


def lab_menu():
    while True:
        print()
        hr()
        out("Local lab server (binds to 127.0.0.1 only): " + ("RUNNING on port %d" % LAB["port"] if LAB["server"] else "stopped"))
        s = ask("[s]tart, [x] stop, [b]ack", "b").lower()
        if s.startswith("s"):
            if LAB["server"]:
                print_line("INFO", "Already running.")
                continue
            port = ask_num("Port (0 = random)", 8099, 0, 65535, int)
            try:
                lab_start(port)
                print_line("PASS", "Lab running: http://127.0.0.1:%d/  try /search?q=x /safe-search /api/items /limited /error" % LAB["port"])
            except OSError as e:
                print_line("ERR", "Could not start lab: %s" % e)
        elif s.startswith("x"):
            lab_stop()
            print_line("INFO", "Lab stopped.")
        else:
            return


def main_menu():
    last_int = 0.0
    while True:
        try:
            print()
            banner()
            for i, (lo, hi, name) in enumerate(CATEGORIES, 1):
                print(" %2d) %-28s %d-%d" % (i, name, lo, hi))
            print(" s) Search   t) Settings   l) Lab server   a) About   q) Quit")
            print(" Tip: 'r 42' runs feature 42 directly; numbers 1-14 open categories.")
            sel = ask("Choice", "").lower()
            if sel in ("q", "quit", "exit"):
                break
            if sel == "s":
                search_menu()
            elif sel == "t":
                settings_menu()
            elif sel == "l":
                lab_menu()
            elif sel == "a":
                out(DISCLAIMER)
                out("Local/private targets are allowed by default; external hosts must be explicitly authorized. "
                    "Reports are written only when you export them (features 97/98).")
            elif sel.isdigit() and 1 <= int(sel) <= len(CATEGORIES):
                category_menu(*CATEGORIES[int(sel) - 1])
            elif re.fullmatch(r"r(un)?\s*\d+", sel) and int(re.search(r"\d+", sel).group()) in REGISTRY:
                run_feature(int(re.search(r"\d+", sel).group()))
            elif sel.isdigit() and int(sel) in REGISTRY:
                run_feature(int(sel))
            elif sel:
                print_line("WARN", "Unknown choice.")
        except KeyboardInterrupt:
            print()
            if time.time() - last_int < 3:
                break
            last_int = time.time()
            print_line("INFO", "Interrupted. Press Ctrl+C again within 3 seconds (or type q) to quit.")
        except UserAbort:
            break
    lab_stop()
    print("Goodbye. Stay authorized.")


def main(argv=None):
    ap = argparse.ArgumentParser(description="%s v%s" % (APP, VERSION))
    ap.add_argument("--list", action="store_true", help="list all features and exit")
    ap.add_argument("--verify", action="store_true", help="verify the 100-feature registry and exit")
    ap.add_argument("--run", type=int, metavar="ID", help="run one feature non-interactively")
    ap.add_argument("--target", help="input for --run (URL, host, host:port, text, path...)")
    ap.add_argument("--yes-authorized", action="store_true", help="confirm authorization for [!] checks on authorized hosts")
    ap.add_argument("--export", metavar="PATH", help="after --run, write a .json or .txt report to PATH")
    ap.add_argument("--lab", nargs="?", const=8099, type=int, metavar="PORT", help="run the local lab server in the foreground")
    ap.add_argument("--version", action="store_true")
    args = ap.parse_args(argv)
    build_registry()
    problems = verify_registry()
    if args.version:
        print("%s %s" % (APP, VERSION))
        return 0
    if args.verify or problems:
        if problems:
            print("Registry problems:\n  " + "\n  ".join(problems))
            return 2
        kinds = {k: sum(1 for f in REGISTRY.values() if f["kind"] == k) for k in KINDS}
        print("Registry OK: %d unique IDs (1-100), all handlers callable. kinds: %s" % (len(REGISTRY), kinds))
        return 0
    if args.list:
        list_features(sorted(REGISTRY))
        return 0
    if args.lab is not None:
        try:
            port = lab_start(args.lab)
        except OSError as e:
            print("Could not start lab: %s" % e)
            return 1
        print("Lab server on http://127.0.0.1:%d/ (loopback only). Ctrl+C to stop." % port)
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            lab_stop()
            return 0
    if args.run is not None:
        if args.run not in REGISTRY:
            print("Unknown feature ID. Valid range: 1-100.")
            return 2
        status = run_feature(args.run, args.target, args.yes_authorized)
        if args.export and SESSION:
            r = Result()
            write_report("txt" if args.export.endswith(".txt") else "json", args.export, r)
            for lvl, msg in r.lines:
                print_line(lvl, msg)
        return 0 if status not in (None, "ERROR", "REFUSED") else 1
    try:
        main_menu()
    except KeyboardInterrupt:
        lab_stop()
        print("\nExiting.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
