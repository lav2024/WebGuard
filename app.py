"""
app.py — Streamlit UI for WebGuard.

Responsibility
--------------
This is the ONLY file the user runs:  streamlit run app.py

It owns every UI concern:
  • Page layout and styling
  • URL input and client-side pre-validation
  • Calling scan_url() from scanner.py (never makes its own HTTP requests)
  • Rendering summary cards, scan details, findings table, per-finding
    detail expanders, and a status-distribution chart
  • Displaying helpful empty/error states

All security logic lives in scanner.py and security_rules.py.
app.py never calls requests, socket, or any network primitive directly.
"""

from __future__ import annotations
import sys
import pathlib

# Ensure the directory that *contains* the webguard/ package is on sys.path.
# When Streamlit runs `streamlit run app.py` it adds the folder that holds
# app.py (i.e. webguard/) to sys.path — but we need its *parent* so that
# `from webguard.scanner import ...` resolves correctly.
_pkg_root = pathlib.Path(__file__).parent.parent.resolve()
if str(_pkg_root) not in sys.path:
    sys.path.insert(0, str(_pkg_root))

import streamlit as st

from webguard.scanner import scan_url, validate_url
from webguard.report_generator import findings_to_csv_bytes

# ── Page configuration ────────────────────────────────────────────────────────
st.set_page_config(
    page_title="WebGuard – Security Audit Dashboard",
    page_icon="🛡️",
    layout="wide",
)

# ── Colour / badge constants ──────────────────────────────────────────────────
_STATUS_COLOUR = {"PASS": "#22c55e", "WARNING": "#f59e0b", "FAIL": "#ef4444"}
_STATUS_ICON   = {"PASS": "✅", "WARNING": "⚠️", "FAIL": "❌"}
_SEV_COLOUR    = {"HIGH": "#ef4444", "MEDIUM": "#f59e0b", "LOW": "#3b82f6", "INFO": "#6b7280"}

# ── Inline CSS ────────────────────────────────────────────────────────────────
st.markdown(
    """
    <style>
    /* metric cards */
    .wg-card {
        background: #f7f8fa;
        border: 1px solid #e5e7eb;
        border-radius: 10px;
        padding: 18px 22px;
        text-align: center;
    }
    .wg-card .label {
        font-size: 13px;
        color: #57606a;
        margin-bottom: 4px;
        font-weight: 600;
        letter-spacing: .04em;
        text-transform: uppercase;
    }
    .wg-card .value {
        font-size: 40px;
        font-weight: 700;
        line-height: 1.1;
    }
    /* status badge inline */
    .badge {
        display: inline-block;
        padding: 2px 9px;
        border-radius: 4px;
        font-size: 12px;
        font-weight: 700;
        color: #fff;
        letter-spacing: .04em;
    }
    /* finding detail block */
    .detail-block {
        background: #f7f8fa;
        border-left: 4px solid #3b82d4;
        border-radius: 0 6px 6px 0;
        padding: 10px 14px;
        margin-bottom: 8px;
        font-size: 14px;
    }
    </style>
    """,
    unsafe_allow_html=True,
)


# ── Helper: coloured HTML badge ───────────────────────────────────────────────

def _badge(text: str, colour: str) -> str:
    return f'<span class="badge" style="background:{colour}">{text}</span>'


def _status_badge(status: str) -> str:
    return _badge(status, _STATUS_COLOUR.get(status, "#6b7280"))


def _severity_badge(severity: str) -> str:
    return _badge(severity, _SEV_COLOUR.get(severity, "#6b7280"))


# ── Helper: metric card HTML ──────────────────────────────────────────────────

def _metric_card(label: str, value: int | str, colour: str = "#1f2328") -> str:
    return (
        f'<div class="wg-card">'
        f'  <div class="label">{label}</div>'
        f'  <div class="value" style="color:{colour}">{value}</div>'
        f'</div>'
    )


# ── Helper: count findings by status ─────────────────────────────────────────

def _count_statuses(findings: list[dict]) -> dict[str, int]:
    counts: dict[str, int] = {"PASS": 0, "WARNING": 0, "FAIL": 0}
    for f in findings:
        status = f.get("status", "")
        if status in counts:
            counts[status] += 1
    return counts


# ── Helper: render a single finding as an expander ───────────────────────────

def _render_finding_expander(finding: dict, index: int) -> None:
    status   = finding.get("status", "—")
    name     = finding.get("check_name", f"Check {index + 1}")
    severity = finding.get("severity", "INFO")
    icon     = _STATUS_ICON.get(status, "❓")

    title = f"{icon} {name}"
    with st.expander(title, expanded=(status == "FAIL")):
        col_a, col_b = st.columns([1, 1])
        with col_a:
            st.markdown(
                f"**Status:** {_status_badge(status)}&nbsp;&nbsp;"
                f"**Severity:** {_severity_badge(severity)}",
                unsafe_allow_html=True,
            )
        with col_b:
            observed = finding.get("observed_value", "—")
            st.markdown(f"**Observed value:** `{observed}`")

        st.markdown("**Why it matters**")
        st.markdown(
            f'<div class="detail-block">{finding.get("explanation", "—")}</div>',
            unsafe_allow_html=True,
        )
        st.markdown("**Recommendation**")
        st.markdown(
            f'<div class="detail-block">{finding.get("recommendation", "—")}</div>',
            unsafe_allow_html=True,
        )


# ── Helper: render the findings table ────────────────────────────────────────

def _render_findings_table(findings: list[dict]) -> None:
    """Render findings as a styled HTML table (no pandas dependency here)."""
    rows = ""
    for f in findings:
        status   = f.get("status", "—")
        severity = f.get("severity", "—")
        rows += (
            "<tr>"
            f"<td>{f.get('check_name','—')}</td>"
            f"<td>{_status_badge(status)}</td>"
            f"<td>{_severity_badge(severity)}</td>"
            f"<td style='font-family:monospace;font-size:12px'>"
            f"{f.get('observed_value','—')}</td>"
            "</tr>"
        )

    table_html = f"""
    <table style='width:100%;border-collapse:collapse;font-size:14px'>
      <thead>
        <tr style='background:#f0f2f6;text-align:left'>
          <th style='padding:8px 12px'>Check</th>
          <th style='padding:8px 12px'>Status</th>
          <th style='padding:8px 12px'>Severity</th>
          <th style='padding:8px 12px'>Observed Value</th>
        </tr>
      </thead>
      <tbody>
        {rows}
      </tbody>
    </table>
    """
    st.markdown(table_html, unsafe_allow_html=True)


# ── Helper: render the distribution chart ────────────────────────────────────

def _render_chart(counts: dict[str, int]) -> None:
    """
    Simple Streamlit bar chart showing PASS / WARNING / FAIL counts.
    Uses st.bar_chart which accepts a plain dict.
    The data is derived from the real scan results — never hardcoded.
    """
    import pandas as pd

    df = pd.DataFrame(
        {"Count": [counts["PASS"], counts["WARNING"], counts["FAIL"]]},
        index=["PASS", "WARNING", "FAIL"],
    )
    st.bar_chart(df, color=["#22c55e"])


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 1 — HEADER
# ══════════════════════════════════════════════════════════════════════════════

st.title("🛡️ WebGuard")
st.subheader("Automated Website Security Audit Dashboard")
st.caption(
    "⚠️ This tool performs a basic HTTP security-header configuration audit. "
    "It is **not** a comprehensive penetration test and does not detect "
    "application-level vulnerabilities, logic flaws, or injection attacks."
)
st.markdown("---")


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 2 — SCAN INPUT
# ══════════════════════════════════════════════════════════════════════════════

st.markdown("### 🔍 Run a Security Audit")

input_col, btn_col = st.columns([5, 1], vertical_alignment="bottom")
with input_col:
    target_url = st.text_input(
        label="Target URL",
        placeholder="https://example.com",
        help=(
            "Enter the full URL including scheme (https:// or http://). "
            "Private IPs, localhost, and cloud metadata endpoints are blocked."
        ),
        label_visibility="collapsed",
    )
with btn_col:
    run_button = st.button("Run Security Audit", type="primary", use_container_width=True)

# ── Client-side pre-validation (no network) ──────────────────────────────────
input_error: str | None = None
if run_button:
    if not target_url.strip():
        input_error = "Please enter a URL before running the audit."
    else:
        ok, reason = validate_url(target_url.strip())
        if not ok:
            input_error = f"Invalid URL — {reason}."

if input_error:
    st.error(input_error)

# ── Run the scan ──────────────────────────────────────────────────────────────
scan_result: dict | None = None

if run_button and input_error is None:
    with st.spinner("Scanning… this may take a few seconds."):
        try:
            scan_result = scan_url(target_url.strip())
        except Exception:
            # scan_url() should never raise — this is a last-resort guard.
            # We intentionally do not surface the raw exception to the UI.
            st.error(
                "An unexpected error occurred while running the audit. "
                "Please try again or check the application logs."
            )
            scan_result = None


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 8 — EMPTY STATE (shown before first scan)
# ══════════════════════════════════════════════════════════════════════════════

if scan_result is None and not run_button:
    st.markdown(
        """
        <div style="text-align:center;padding:48px 24px;color:#57606a">
            <p style="font-size:48px">🛡️</p>
            <p style="font-size:20px;font-weight:600;color:#1f2328">
                Enter a URL above and click <em>Run Security Audit</em>
            </p>
            <p style="font-size:14px;max-width:520px;margin:8px auto 0">
                WebGuard checks HTTP response headers for common security
                misconfigurations including HTTPS enforcement, Content Security
                Policy, HSTS, X-Frame-Options, X-Content-Type-Options, and
                Referrer-Policy.
            </p>
            <hr style="margin:28px auto;max-width:480px;border-color:#e5e7eb">
            <p style="font-size:13px">
                <strong>Examples to try:</strong>&nbsp;
                <code>https://example.com</code> &nbsp;·&nbsp;
                <code>https://github.com</code> &nbsp;·&nbsp;
                <code>https://mozilla.org</code>
            </p>
        </div>
        """,
        unsafe_allow_html=True,
    )
    st.stop()  # nothing more to render until a scan runs


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 8 — SCAN-LEVEL ERROR STATE
# ══════════════════════════════════════════════════════════════════════════════

if scan_result is None:
    st.stop()

# URL failed scanner validation (should be redundant — we pre-validated above,
# but scan_url() does its own check so we handle it gracefully)
if not scan_result.get("valid", True):
    st.error(
        f"The URL was rejected by the scanner: "
        f"{scan_result.get('validation_error', 'unknown reason')}"
    )
    st.stop()

fetch_result = scan_result.get("fetch_result") or {}

# Network / HTTP error
if fetch_result.get("error"):
    st.error(f"Scan failed: {fetch_result['error']}")
    with st.expander("What does this mean?"):
        st.markdown(
            """
            Common causes:
            - **Connection error** — the host is unreachable or refused the connection.
            - **TLS/SSL error** — the site's certificate is invalid or expired.
            - **Timeout** — the site took too long to respond.
            - **Too many redirects** — the site loops or redirects to a blocked destination.

            Try a different URL or check that the site is publicly accessible.
            """
        )
    st.stop()

findings = scan_result.get("security_findings") or []

# This should not happen if fetch succeeded, but guard anyway
if not findings:
    st.warning("The scan completed but produced no findings. Please try again.")
    st.stop()

counts = _count_statuses(findings)


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 3 — SUMMARY CARDS
# ══════════════════════════════════════════════════════════════════════════════

st.markdown("### 📊 Audit Summary")

c_total, c_pass, c_warn, c_fail = st.columns(4)
with c_total:
    st.markdown(_metric_card("Total Checks", len(findings)), unsafe_allow_html=True)
with c_pass:
    st.markdown(
        _metric_card("Passed", counts["PASS"], _STATUS_COLOUR["PASS"]),
        unsafe_allow_html=True,
    )
with c_warn:
    st.markdown(
        _metric_card("Warnings", counts["WARNING"], _STATUS_COLOUR["WARNING"]),
        unsafe_allow_html=True,
    )
with c_fail:
    st.markdown(
        _metric_card("Failed", counts["FAIL"], _STATUS_COLOUR["FAIL"]),
        unsafe_allow_html=True,
    )

st.markdown("")  # spacing


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 4 — SCAN DETAILS
# ══════════════════════════════════════════════════════════════════════════════

st.markdown("### 🔎 Scan Details")

detail_left, detail_right = st.columns(2)

final_url    = fetch_result.get("url", target_url)
status_code  = fetch_result.get("status_code")
is_https     = fetch_result.get("is_https", False)
timestamp    = fetch_result.get("scan_timestamp") or scan_result.get("scan_timestamp", "—")
redirect_chain = fetch_result.get("redirect_chain", [])
elapsed_ms   = fetch_result.get("elapsed_ms", 0.0)

with detail_left:
    st.markdown(f"**Target URL:** `{final_url}`")
    st.markdown(f"**Scan timestamp:** {timestamp}")
    st.markdown(
        f"**HTTP status:** "
        f"`{status_code}`"
        + (
            " — OK" if status_code and 200 <= status_code < 300
            else (" — redirect" if status_code and 300 <= status_code < 400
            else (" — client error" if status_code and 400 <= status_code < 500
            else (" — server error" if status_code and status_code >= 500
            else "")))
        )
    )

with detail_right:
    https_label = "✅ HTTPS" if is_https else "❌ Not HTTPS"
    st.markdown(f"**Connection:** {https_label}")
    st.markdown(f"**Response time:** {elapsed_ms:.0f} ms")
    if redirect_chain:
        st.markdown(f"**Redirects followed:** {len(redirect_chain)}")
        with st.expander("View redirect chain"):
            for i, hop in enumerate(redirect_chain, 1):
                st.markdown(f"{i}. `{hop}`")
    else:
        st.markdown("**Redirects:** none")

st.markdown("---")


# ══════════════════════════════════════════════════════════════════════════════
# SECTIONS 5 + 6 — FINDINGS TABLE + FINDING DETAILS
# ══════════════════════════════════════════════════════════════════════════════

left_col, right_col = st.columns([3, 2], gap="large")

with left_col:
    st.markdown("### 🗒️ Security Findings")
    _render_findings_table(findings)

    st.markdown("")
    st.markdown("### 🔬 Finding Details")
    st.caption(
        "Click a finding to expand it. "
        "Failed checks are expanded by default."
    )
    for i, finding in enumerate(findings):
        _render_finding_expander(finding, i)


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 7 — VISUALISATION
# ══════════════════════════════════════════════════════════════════════════════

with right_col:
    st.markdown("### 📈 Result Distribution")
    st.caption("Counts derived from the current scan — not demonstration data.")
    _render_chart(counts)

    # Plain-language score
    st.markdown("#### Overall assessment")
    total = len(findings)
    if counts["FAIL"] == 0 and counts["WARNING"] == 0:
        st.success("All checks passed. The site's security headers look good.")
    elif counts["FAIL"] == 0:
        st.warning(
            f"{counts['WARNING']} warning(s) detected. "
            "Review the flagged headers — they are not critical failures "
            "but represent improvement opportunities."
        )
    else:
        fail_pct = round(counts["FAIL"] / total * 100)
        st.error(
            f"{counts['FAIL']} check(s) failed ({fail_pct}% of total). "
            "Missing or misconfigured security headers reduce defence-in-depth. "
            "See the finding details for recommended fixes."
        )

    # Methodology note
    st.markdown("---")
    st.markdown("#### About this audit")
    st.markdown(
        """
        This audit evaluates **HTTP response headers only**.
        A PASS result means the header is present with no obviously
        weak value — it does not guarantee the full configuration is
        correct. A FAIL means the header is absent or clearly misconfigured.

        Headers checked:
        - HTTPS (final URL scheme)
        - Content-Security-Policy
        - Strict-Transport-Security (HSTS)
        - X-Content-Type-Options
        - X-Frame-Options
        - Referrer-Policy
        """
    )


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 9 — DOWNLOAD REPORT
# ══════════════════════════════════════════════════════════════════════════════
# st.download_button does NOT re-run the Streamlit script when clicked —
# it streams the pre-built bytes directly to the browser.  No second scan
# is triggered.  The CSV is built from the live `scan_result` that was
# produced earlier in this same script execution.

st.markdown("---")
st.markdown("### 📥 Download Report")

try:
    csv_bytes = findings_to_csv_bytes(scan_result)
    # Derive a clean filename from the scanned host and timestamp
    _host = final_url.split("//")[-1].split("/")[0].replace(":", "_")
    _ts   = timestamp.replace(":", "-").replace("T", "_")[:19]
    _filename = f"webguard_{_host}_{_ts}.csv"

    st.download_button(
        label="⬇️  Download CSV Report",
        data=csv_bytes,
        file_name=_filename,
        mime="text/csv",
        help=(
            "Downloads a CSV containing all findings, observed values, "
            "explanations, and OWASP remediation guidance for this scan. "
            "Open in Excel, LibreOffice Calc, or any spreadsheet application."
        ),
    )
    st.caption(
        "The report reflects the scan shown above. "
        "Run a new audit to update the report. "
        "⚠️ Test any header changes in a staging environment before deploying — "
        "security headers can affect website functionality."
    )
except ValueError as _exc:
    # Should not happen here because we already checked findings is non-empty,
    # but guard defensively so a bug never crashes the dashboard.
    st.info("Report not available — complete a successful scan first.")


# ══════════════════════════════════════════════════════════════════════════════
# FOOTER
# ══════════════════════════════════════════════════════════════════════════════

st.markdown("---")
st.caption(
    "WebGuard · Cybersecurity Bootcamp Project · v0.2.0 · "
    "Results are informational only and not a substitute for a professional security assessment."
)
