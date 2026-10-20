# WebGuard — Automated Website Security Audit Dashboard

A cybersecurity bootcamp project built with Python and Streamlit.  
WebGuard fetches a target URL, evaluates HTTP response headers against
six security rules, and presents findings in an interactive dashboard
with CSV export.

---

## Project Structure

```
Cyber/                          ← package root (add to PYTHONPATH / run from here)
└── webguard/
    ├── app.py                  # Streamlit UI — the only file you run
    ├── scanner.py              # URL validation, HTTP fetching, SSRF safeguards
    ├── security_rules.py       # Pure rule functions (no network I/O)
    ├── report_generator.py     # Findings → pandas DataFrame / CSV bytes
    ├── conftest.py             # pytest sys.path fix
    ├── requirements.txt        # Python dependencies
    ├── README.md               # This file
    └── tests/
        ├── test_security_rules.py    # 61 tests — all security rule functions
        ├── test_url_validation.py    # 69 tests — URL validation, fetch, scan_url
        └── test_report_generator.py  # 59 tests — CSV export, formula injection
```

---

## Quick Start (Windows)

### 1 — Python version check

```powershell
py --version          # must be 3.10 or later
```

### 2 — Create and activate a virtual environment

```powershell
# Create (one-time, run inside the webguard/ folder)
py -m venv .venv

# Activate (run every time you open a new terminal)
.venv\Scripts\Activate.ps1
```

> If PowerShell blocks the script, run this once (as your user):  
> `Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser`

### 3 — Install dependencies

```powershell
pip install -r requirements.txt
```

### 4 — Launch the dashboard

```powershell
streamlit run app.py
```

Streamlit opens `http://localhost:8501` automatically.  
Enter any public HTTPS URL and click **Run Security Audit**.

### 5 — Run the test suite

```powershell
python -m pytest tests/ -v
```

All 189 tests pass. No tests are marked `xfail`.

---

## Security Rules

| Check | Header / Field | Failure Condition |
|---|---|---|
| HTTPS | Final URL scheme | URL does not use `https://` |
| Content-Security-Policy | `Content-Security-Policy` | Header absent, empty, or contains `unsafe-inline` / `unsafe-eval` / wildcards |
| Strict-Transport-Security | `Strict-Transport-Security` | Absent, no `max-age`, `max-age` < 126 days, or present on HTTP response |
| X-Content-Type-Options | `X-Content-Type-Options` | Absent or value is not `nosniff` |
| X-Frame-Options | `X-Frame-Options` | Absent, deprecated `ALLOW-FROM`, or unrecognised value |
| Referrer-Policy | `Referrer-Policy` | Absent (WARNING), `unsafe-url`, or unrecognised value |

Each finding returns: `check_name`, `status` (PASS / WARNING / FAIL),
`severity` (INFO / LOW / MEDIUM / HIGH), `observed_value`,
`explanation`, and `recommendation`.

---

## SSRF Protections

`scanner.py` implements a layered defence against Server-Side Request Forgery:

1. **Static validation** (`validate_url`) — rejects bad schemes, embedded
   credentials, `localhost`, cloud metadata hostnames, and literal private IPs
   without making any network call.
2. **Pre-flight DNS check** (`_resolve_and_check`) — resolves the hostname and
   verifies every returned A/AAAA record before opening a socket.
3. **Per-hop redirect validation** — every redirect destination is re-validated
   as if it were a fresh URL; redirects to private/internal addresses are blocked.
4. **Connect-time re-validation** (`_SafeHTTPAdapter`) — re-resolves the
   hostname at TCP-connect time to narrow the DNS rebinding window.

**Known limitations (documented in `scanner.py`):**  
- A DNS rebind occurring between the adapter's `getaddrinfo` call and
  `urllib3`'s internal `connect()` syscall cannot be blocked at the Python layer.
- An egress firewall blocking RFC-1918 and link-local ranges is the only
  network-layer guarantee.

---

## CSV Export

Reports are downloaded via the **📥 Download Report** button after a
successful scan. Each row contains:

`Target URL` · `Scan Timestamp` · `HTTP Status` · `Check Name` ·
`Status` · `Severity` · `Observed Value` · `Explanation` ·
`Recommendation` · `Remediation Guidance (OWASP)`

**Formula-injection protection (CWE-1236):** every cell value that begins
with `=`, `+`, `-`, `@`, TAB, or CR is prefixed with `'` before writing,
neutralising spreadsheet formula execution.

---

## Dependencies

| Package | Minimum | Purpose |
|---|---|---|
| `streamlit` | 1.35.0 | Web dashboard |
| `requests` | 2.31.0 | HTTP client |
| `urllib3` | 2.0.0 | Used directly for `Retry` config in scanner |
| `pandas` | 2.2.0 | DataFrame in report generator |
| `pytest` | 8.2.0 | Test runner |

---

## Remaining Manual Security Checks

The following protections cannot be verified by unit tests alone and
require manual review or network-level controls before any real-world use:

- **Egress firewall** — confirm RFC-1918, link-local, and loopback ranges
  are blocked at the network level, not just in application code.
- **TLS certificate validation** — WebGuard relies on `requests` default
  TLS verification; confirm no `verify=False` was introduced.
- **Rate limiting** — no rate limiting is implemented; an operator must
  restrict how often `scan_url()` can be called per user/IP.
- **Response body handling** — the body is read and discarded; confirm
  that no future code change processes untrusted body content.
- **Dependency audit** — run `pip audit` or `safety check` before deploying
  to verify no known CVEs in the installed packages.
