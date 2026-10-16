# TOOL NAME  **hacklb100 **  😈👿😈👿😈

A single-file, standard-library-only Python toolkit of 100 defensive security utilities for
**authorized** testing and learning. Built for Android **Termux** on low-resource phones, with
Linux as a secondary target. No root, no third-party package
 

## Overview and feature categories

| IDs | Category | Highlights |
|---|---|---|
| 1-10 | HTTP & Website Analysis | status/timing, headers, redirects, methods, banner, caching, HTTP->HTTPS |
| 11-22 | Security Headers | HSTS, CSP (+weakness analysis), clickjacking, nosniff, CORS, score |
| 23-28 | Cookies | Secure, HttpOnly, SameSite, prefixes, lifetime |
| 29-38 | HTML Inspection | forms, password-form transport, CSRF-token heuristic, SRI, mixed content |
| 39-44 | TLS | certificate, expiry, trust/hostname, SAN, protocol/cipher, versions |
| 45-50 | DNS & IP | resolve, reverse, IP/CIDR/hostname tools (offline), answer sanity |
| 51-56 | Ports & Local Network | authorized port checks, common ports, banners, local listeners |
| 57-62 | API & JSON | validity, structure, sensitive keys, error verbosity, rate limits |
| 63-70 | Local Security Lab | lab server self-test, SQLi/XSS/CSRF/rate-limit/traversal/hashing demos |
| 71-80 | Hash, Integrity & Logs | hashing, verification, directory snapshots, permissions, log analysis |
| 81-85 | Input Validation | e-mail, URL, password strength, output encoding, input pattern detector |
| 86-90 | Authentication Config | Basic-auth challenge, login hints, token entropy, JWT inspection, checklist |
| 91-95 | Configuration Auditing | sshd_config, nginx/Apache, .env, requirements.txt, environment |
| 96-100 | Reporting & Utilities | session summary, JSON/TXT export, authorized targets, dependency check |

Every feature is labelled in the menu and in its output:

- **R (real)** - performs the described check on real input (77 features).
- **L (limited)** - heuristic or partial coverage; the output says what it cannot prove (17).
- **S (simulated)** - educational demo on synthetic data; **no target is tested** and the result
  status is `SIMULATED`, never `PASS` (6).
- `n` = sends network traffic; `!` = requires an authorization confirmation.

A result is `PASS` only when a check actually passed. Informational output is `INFO`, skipped
checks are `SKIPPED`, and failures to connect are `ERROR`.

## Compatibility

Python 3.8+ (standard library only). Intended for Termux on Android and Linux. Works without
root. Windows is not a target (permission-bit checks are skipped th
```sh
python main.py                         # interactive menu (s = search, t = settings, l = lab, q = quit)
python main.py --list                  # list all 100 features
python main.py --verify                # check the registry: 100 unique IDs, all handlers callable
python main.py --run 11 --target http://127.0.0.1:8099/        # one feature, non-interactive
python main.py --run 71 --target "hello" --export result.json  # report written only because you asked
```

In the menu, type a category number (1-14), or `r 42` to run feature 42 directly. Ctrl+C cancels the
current check; press it twice (or type `q`) at the main menu to quit.

### Targets and authorization

- **Allowed by default:** `localhost` and private/loopback/link-local addresses (local labs).
- **Everything else is refused** until you add it in feature 99 (type `I AM AUTHORIZED` to confirm
  you have written permission). The list lives in memory for the session only. You may also set
  `TOOLKIT_AUTHORIZED=host1,host2` in the environment.
- Features marked `!` ask for `YES` before probing an authorized external host.
- Only GET/HEAD/OPTIONS are ever sent. Redirects are re-validated hop by hop. Defaults: 8 s timeout,
  512 KiB body cap, 60 network operations per session, 0.25 s between requests, max 3 redirects,
  TLS verification on. Adjust them in Settings.

## Local-lab examples

```sh
python main.py --lab 8099              # terminal 1: loopback-only lab server (127.0.0.1)
python main.py --run 11 --target http://127.0.0.1:8099/               # HSTS (skipped over HTTP)
python main.py --run 12 --target http://127.0.0.1:8099/safe-search?q=x # CSP present
python main.py --run 25 --target http://127.0.0.1:8099/               # cookie HttpOnly findings
python main.py --run 59 --target http://127.0.0.1:8099/api/items      # sensitive JSON key names
python main.py --run 62 --target http://127.0.0.1:8099/limited --yes-authorized  # small probe -> 429
python main.py --run 63                # self-test (starts and stops its own lab)
python main.py --run 64                # SQL injection demo on an in-memory SQLite DB
```

Lab routes: `/` (weak headers, weak cookie, HTML issues), `/search?q=` (deliberately unescaped),
`/safe-search?q=` (escaped + headers), `/api/items`, `/limited` (429 after 5 hits/min), `/error`.
The lab binds to 127.0.0.1 only, rejects POST, and stores nothing.

## Known limitations

- Developed and tested on Linux with Python 3.12 against the built-in lab and a local self-signed TLS
  server. **It has not been tested on Android Termux, on Python 3.8-3.11, or against third-party
  sites.** Termux may restrict `/sys/class/net` and similar; affected checks report that.
- Header/cookie/HTML checks analyze one response (redirects followed), not a whole site.
- TLS: certificate details are available only for verified connections; for untrusted certificates
  you get the verification failure plus protocol/cipher. Version probing (44) can only test what the
  local OpenSSL can offer.
- Heuristics (CSRF token, sensitive keys, comments, log patterns, input patterns, entropy) can miss
  issues and raise false alarms. JWT inspection does **not** verify signatures.
- Name resolution is done only for single-label or `.local/.lan/.home/.internal` names, to decide
  whether they are private; ordinary public hostnames are refused without any lookup.
- Config audits are text/regex based and do not resolve `include` files. No vulnerability database is
  consulted (94).
- Responses are cached for 30 s within a session to save requests. Timeouts apply per socket
  operation, plus a read deadline of 3x the timeout.
- The toolkit does not perform exploitation, credential capture, bypasses, or high-volume testing.

## Responsible disclosure

If you find a vulnerability: stop testing beyond what is needed to confirm it, do not access or keep
other people's data, and report privately to the owner (look for `/.well-known/security.txt`, a
security@ address, or a bug-bounty/VDP page). Give clear reproduction steps and affected versions,
allow reasonable time to fix (commonly 90 days) before any public discussion, and follow the
program's rules. Never test systems you do not own or have written permission to test.

 **Disclaimer
This tool is only for educational purposes. I am not responsible for any illegal activity, misuse, or damages**

Install

1 TERMUX
```bash
pkg update && pkg install python git
```
```bash
git clone https://github.com/Gg/hacklab-100.git
```
```bash
cd hacklab-100
```
```bash
sh install.sh
```
Important: After installation, do not launch the tool immediately. First, **clear** the Termux terminal using the "clear" command, then launch the tool. This keeps the terminal clean and readable.
```bash
python "Security 100.py"
```
