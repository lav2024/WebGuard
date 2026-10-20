"""
security_rules.py — Pure security-check functions for WebGuard.

Responsibility
--------------
Each public function accepts a *response* dict (the shape produced by
scanner.fetch_url()) and returns a single *finding* dict describing the
result of one security check.  No network calls, no file I/O — only logic.
That keeps the entire module trivially unit-testable with fake response dicts.

Finding schema
--------------
Every function returns a dict with exactly these keys:

    check_name      str   Human-readable name of the check
    status          str   "PASS" | "WARNING" | "FAIL"
    severity        str   "INFO" | "LOW" | "MEDIUM" | "HIGH"
                          (meaningful only when status != PASS)
    observed_value  str   The raw header value seen, or "<missing>"
    explanation     str   Plain-English reason for the result
    recommendation  str   Concrete action the developer can take

Status definitions
------------------
    PASS     – The check found no issue worth reporting.
    WARNING  – A header is present but its value is weak or ambiguous.
               A human should review it before treating the site as secure.
    FAIL     – A header is absent or clearly misconfigured.
               This represents a measurable reduction in defence-in-depth,
               not necessarily a confirmed exploit.

Limitations
-----------
Static header analysis cannot:
  • verify that a CSP policy actually blocks all injection vectors
  • determine whether HTTPS is enforced end-to-end (only checks the final URL)
  • detect misconfigurations deep inside directive values
  • replace a full penetration test
"""

from __future__ import annotations

import re


# ── Internal helpers ──────────────────────────────────────────────────────────

def _get_header(headers: dict, name: str) -> str | None:
    """
    Return the value of *name* from *headers*, case-insensitively.
    Returns None when the header is absent.

    HTTP/1.1 (RFC 7230) specifies that header field names are
    case-insensitive, so 'Content-Security-Policy' == 'content-security-policy'.
    """
    name_lower = name.lower()
    for key, value in headers.items():
        if key.lower() == name_lower:
            return value
    return None


def _finding(
    check_name: str,
    status: str,
    severity: str,
    observed_value: str,
    explanation: str,
    recommendation: str,
) -> dict:
    """Build a standardised finding dictionary."""
    return {
        "check_name": check_name,
        "status": status,
        "severity": severity,
        "observed_value": observed_value,
        "explanation": explanation,
        "recommendation": recommendation,
    }


# ── Check 1 — HTTPS ───────────────────────────────────────────────────────────

def check_https(response: dict) -> dict:
    """
    Verify that the final URL (after any redirects) uses HTTPS.

    Why it matters
    --------------
    Plain HTTP transmits every byte — including cookies, form data, and
    session tokens — as readable text on the network.  Any device between
    the user and the server (a coffee-shop router, an ISP, a misconfigured
    proxy) can read or silently modify that traffic (man-in-the-middle).

    Limitation: this check only inspects the URL string.  It cannot verify
    whether the TLS certificate is valid, whether the cipher suite is strong,
    or whether mixed-content resources are loaded over HTTP on an HTTPS page.
    """
    url: str = response.get("url", "")
    if url.startswith("https://"):
        return _finding(
            check_name="HTTPS",
            status="PASS",
            severity="INFO",
            observed_value=url,
            explanation="The final URL uses HTTPS, so the connection is encrypted.",
            recommendation="Ensure TLS certificates are kept valid and up-to-date.",
        )
    return _finding(
        check_name="HTTPS",
        status="FAIL",
        severity="HIGH",
        observed_value=url or "<missing>",
        explanation=(
            "The final URL does not use HTTPS.  Data is transmitted in plain "
            "text and is vulnerable to interception or modification."
        ),
        recommendation=(
            "Obtain a TLS certificate (e.g. via Let's Encrypt) and redirect "
            "all HTTP traffic to HTTPS with a permanent 301 redirect."
        ),
    )


# ── Check 2 — Content-Security-Policy ────────────────────────────────────────

# Directive values that meaningfully weaken a CSP.
_CSP_WEAK_PATTERNS = [
    (r"'unsafe-inline'",  "allows inline scripts/styles, enabling many XSS vectors"),
    (r"'unsafe-eval'",    "allows eval() and similar, enabling script injection"),
    (r"script-src\s+\*",  "allows scripts from any origin"),
    (r"default-src\s+\*", "allows all resources from any origin"),
]


def check_content_security_policy(response: dict) -> dict:
    """
    Check for the Content-Security-Policy (CSP) response header.

    Why it matters
    --------------
    CSP is a browser instruction that whitelists which origins may supply
    scripts, styles, images, and other resources.  It is a primary defence
    against cross-site scripting (XSS): even if an attacker injects a
    <script> tag, a restrictive CSP prevents the browser from executing it.

    Evaluation strategy
    -------------------
    1. Missing → FAIL  (no protection at all)
    2. Present but empty → FAIL  (browser ignores an empty CSP)
    3. Present with known weak patterns → WARNING  (policy exists but may
       be bypassable; a human should review the full policy)
    4. Present with no detected weakness → PASS  (with a caveat: a simple
       string scan cannot guarantee the policy is airtight)

    Limitation: this check uses pattern matching on the header string.  A
    policy with no detected keywords may still be bypassable via subtle
    misconfigurations (e.g. trusting a CDN that serves attacker-controlled
    content, or missing the 'object-src' directive).  A proper CSP audit
    requires manual review or a dedicated CSP linter.
    """
    headers = response.get("headers", {})
    value = _get_header(headers, "content-security-policy")

    if value is None:
        return _finding(
            check_name="Content-Security-Policy",
            status="FAIL",
            severity="HIGH",
            observed_value="<missing>",
            explanation=(
                "No Content-Security-Policy header was found.  The browser will "
                "execute scripts and load resources from any origin, providing "
                "no XSS mitigation at the HTTP layer."
            ),
            recommendation=(
                "Add a Content-Security-Policy header.  Start with a restrictive "
                "policy such as \"default-src 'self'\" and relax only as needed."
            ),
        )

    if not value.strip():
        return _finding(
            check_name="Content-Security-Policy",
            status="FAIL",
            severity="HIGH",
            observed_value="<empty>",
            explanation=(
                "A Content-Security-Policy header is present but its value is "
                "empty.  An empty CSP is ignored by browsers."
            ),
            recommendation="Provide a non-empty CSP value.",
        )

    # Check for known weakening patterns
    weaknesses = []
    for pattern, description in _CSP_WEAK_PATTERNS:
        if re.search(pattern, value, re.IGNORECASE):
            weaknesses.append(description)

    if weaknesses:
        weakness_list = "; ".join(weaknesses)
        return _finding(
            check_name="Content-Security-Policy",
            status="WARNING",
            severity="MEDIUM",
            observed_value=value,
            explanation=(
                f"A CSP header is present but contains potentially weak directives: "
                f"{weakness_list}.  These may reduce the policy's effectiveness."
            ),
            recommendation=(
                "Review the CSP policy.  Avoid 'unsafe-inline' and 'unsafe-eval'; "
                "use nonces or hashes for inline scripts instead.  Avoid wildcard "
                "(*) source values."
            ),
        )

    return _finding(
        check_name="Content-Security-Policy",
        status="PASS",
        severity="INFO",
        observed_value=value,
        explanation=(
            "A Content-Security-Policy header is present with no obviously weak "
            "directives detected.  Note: a string scan cannot guarantee the policy "
            "is fully restrictive — manual review is recommended."
        ),
        recommendation=(
            "Periodically review and tighten the CSP policy as the application "
            "evolves.  Consider using a CSP linter or the browser's CSP report-uri."
        ),
    )


# ── Check 3 — Strict-Transport-Security (HSTS) ───────────────────────────────

_HSTS_MIN_MAX_AGE = 10_886_400  # 126 days — Mozilla Observatory minimum


def check_hsts(response: dict) -> dict:
    """
    Check for the Strict-Transport-Security (HSTS) response header.

    Why it matters
    --------------
    HSTS instructs browsers to always connect to the domain over HTTPS,
    even if the user types "http://" or follows a plain-HTTP link.  Without
    HSTS, an attacker can intercept the very first request before the server
    issues its HTTP→HTTPS redirect (SSL-strip attack).

    HTTPS context requirement
    -------------------------
    HSTS is only honoured by browsers when received over an HTTPS connection.
    If this response came over plain HTTP, the header is present but provides
    no actual protection — we flag that as WARNING rather than PASS.

    Limitation: this check parses the max-age value as an integer but does
    not fully validate every HSTS directive combination.
    """
    url: str = response.get("url", "")
    is_https = url.startswith("https://")
    headers = response.get("headers", {})
    value = _get_header(headers, "strict-transport-security")

    if value is None:
        # HSTS missing on HTTP is expected (and harmless for HSTS specifically),
        # but the HTTPS check will already flag the HTTP issue.
        severity = "HIGH" if is_https else "LOW"
        explanation = (
            "No Strict-Transport-Security header found on an HTTPS response.  "
            "Browsers will not enforce HTTPS-only behaviour for this domain."
            if is_https else
            "No Strict-Transport-Security header found.  Because this response "
            "was delivered over HTTP (not HTTPS), adding HSTS here would have "
            "no protective effect — browsers ignore HSTS received over HTTP."
        )
        return _finding(
            check_name="Strict-Transport-Security",
            status="FAIL",
            severity=severity,
            observed_value="<missing>",
            explanation=explanation,
            recommendation=(
                "Add the header on your HTTPS server: "
                "\"Strict-Transport-Security: max-age=31536000; includeSubDomains\". "
                "Consider adding 'preload' and submitting to the HSTS preload list."
            ),
        )

    if not value.strip():
        return _finding(
            check_name="Strict-Transport-Security",
            status="FAIL",
            severity="HIGH",
            observed_value="<empty>",
            explanation="The Strict-Transport-Security header is present but empty.",
            recommendation="Provide a valid value, e.g. \"max-age=31536000; includeSubDomains\".",
        )

    # HSTS received over HTTP — present but useless
    if not is_https:
        return _finding(
            check_name="Strict-Transport-Security",
            status="WARNING",
            severity="MEDIUM",
            observed_value=value,
            explanation=(
                "A Strict-Transport-Security header is present, but this response "
                "was delivered over plain HTTP.  Browsers discard HSTS headers "
                "received over HTTP, so this header provides no protection."
            ),
            recommendation=(
                "Ensure HSTS is set on your HTTPS responses, not on HTTP responses.  "
                "The HTTP server should only issue a 301 redirect to HTTPS."
            ),
        )

    # Parse max-age
    match = re.search(r"max-age\s*=\s*(\d+)", value, re.IGNORECASE)
    if not match:
        return _finding(
            check_name="Strict-Transport-Security",
            status="WARNING",
            severity="MEDIUM",
            observed_value=value,
            explanation=(
                "A Strict-Transport-Security header is present but no valid "
                "max-age directive was found.  Browsers may reject or ignore it."
            ),
            recommendation="Include a max-age directive, e.g. \"max-age=31536000\".",
        )

    max_age = int(match.group(1))
    if max_age < _HSTS_MIN_MAX_AGE:
        return _finding(
            check_name="Strict-Transport-Security",
            status="WARNING",
            severity="LOW",
            observed_value=value,
            explanation=(
                f"HSTS max-age is {max_age} seconds (~{max_age // 86400} days), "
                f"which is below the recommended minimum of {_HSTS_MIN_MAX_AGE} "
                f"seconds (~{_HSTS_MIN_MAX_AGE // 86400} days).  Short max-age "
                "reduces the window of HTTPS enforcement."
            ),
            recommendation=(
                "Set max-age to at least 31536000 (1 year).  "
                "Consider adding 'includeSubDomains' and 'preload'."
            ),
        )

    return _finding(
        check_name="Strict-Transport-Security",
        status="PASS",
        severity="INFO",
        observed_value=value,
        explanation=(
            f"HSTS is present with max-age={max_age} seconds on an HTTPS response."
        ),
        recommendation=(
            "Consider adding 'preload' and submitting to hstspreload.org for "
            "additional protection against the very first visit."
        ),
    )


# ── Check 4 — X-Content-Type-Options ─────────────────────────────────────────

def check_x_content_type_options(response: dict) -> dict:
    """
    Check for the X-Content-Type-Options header set to 'nosniff'.

    Why it matters
    --------------
    Browsers can "sniff" the MIME type of a response by examining its
    content — even if the server declares a different Content-Type.  An
    attacker who can upload a file (e.g. an image containing a script)
    can exploit MIME sniffing to make the browser execute it.  Setting
    X-Content-Type-Options: nosniff tells the browser to trust the declared
    Content-Type and never sniff.

    Limitation: this header protects against MIME-sniffing attacks; it does
    not replace correct Content-Type declarations on all responses.
    """
    headers = response.get("headers", {})
    value = _get_header(headers, "x-content-type-options")

    if value is None:
        return _finding(
            check_name="X-Content-Type-Options",
            status="FAIL",
            severity="MEDIUM",
            observed_value="<missing>",
            explanation=(
                "No X-Content-Type-Options header found.  Browsers may perform "
                "MIME-type sniffing, which can lead to script execution from "
                "responses that were not intended to be scripts."
            ),
            recommendation="Add the header: \"X-Content-Type-Options: nosniff\".",
        )

    if value.strip().lower() == "nosniff":
        return _finding(
            check_name="X-Content-Type-Options",
            status="PASS",
            severity="INFO",
            observed_value=value,
            explanation=(
                "X-Content-Type-Options is set to 'nosniff'.  "
                "Browsers will not perform MIME-type sniffing on responses."
            ),
            recommendation="No action required.",
        )

    return _finding(
        check_name="X-Content-Type-Options",
        status="WARNING",
        severity="LOW",
        observed_value=value,
        explanation=(
            f"X-Content-Type-Options is present with an unrecognised value "
            f"'{value.strip()}'.  The only valid value is 'nosniff'."
        ),
        recommendation="Set the header value to exactly 'nosniff'.",
    )


# ── Check 5 — X-Frame-Options ────────────────────────────────────────────────

_XFO_SECURE_VALUES = {"deny", "sameorigin"}


def check_x_frame_options(response: dict) -> dict:
    """
    Check for the X-Frame-Options header.

    Why it matters
    --------------
    Without this header an attacker can embed the target site inside a
    transparent <iframe> on a malicious page and trick users into clicking
    interface elements they cannot see (clickjacking).  For example, a
    hidden 'Confirm Transfer' button overlaid on a game.

    Value guidance
    --------------
    DENY       – the page may not be framed at all (most restrictive).
    SAMEORIGIN – the page may only be framed by the same origin.
    ALLOW-FROM – deprecated; modern browsers ignore it entirely.

    Note: the modern equivalent is the 'frame-ancestors' CSP directive,
    which has broader browser support and is more flexible.  If a strong
    CSP with frame-ancestors is present, missing X-Frame-Options is less
    critical, but this check does not cross-reference the CSP.

    Limitation: cannot verify whether a CSP frame-ancestors directive
    provides equivalent protection.
    """
    headers = response.get("headers", {})
    value = _get_header(headers, "x-frame-options")

    if value is None:
        return _finding(
            check_name="X-Frame-Options",
            status="FAIL",
            severity="MEDIUM",
            observed_value="<missing>",
            explanation=(
                "No X-Frame-Options header found.  The page can be embedded in "
                "an iframe on any origin, which may enable clickjacking attacks."
            ),
            recommendation=(
                "Add \"X-Frame-Options: DENY\" (or SAMEORIGIN if same-origin "
                "framing is intentional).  Also consider adding "
                "\"Content-Security-Policy: frame-ancestors 'none'\" as the "
                "modern equivalent."
            ),
        )

    normalised_lower = value.strip().lower()
    normalised_upper = value.strip().upper()

    if normalised_lower in _XFO_SECURE_VALUES:
        return _finding(
            check_name="X-Frame-Options",
            status="PASS",
            severity="INFO",
            observed_value=value,
            explanation=(
                f"X-Frame-Options is set to '{normalised_upper}', "
                "which restricts framing to reduce clickjacking risk."
            ),
            recommendation=(
                "Consider also adding \"Content-Security-Policy: "
                "frame-ancestors 'none'\" for browsers that have deprecated "
                "X-Frame-Options in favour of CSP."
            ),
        )

    if normalised_upper.startswith("ALLOW-FROM"):
        return _finding(
            check_name="X-Frame-Options",
            status="WARNING",
            severity="MEDIUM",
            observed_value=value,
            explanation=(
                "X-Frame-Options is set to ALLOW-FROM, which is deprecated and "
                "ignored by all modern browsers (Chrome, Firefox, Safari, Edge).  "
                "This header provides no clickjacking protection in current browsers."
            ),
            recommendation=(
                "Replace ALLOW-FROM with a Content-Security-Policy "
                "\"frame-ancestors\" directive, which is the supported modern "
                "alternative: e.g. \"frame-ancestors 'self' https://trusted.com\"."
            ),
        )

    return _finding(
        check_name="X-Frame-Options",
        status="WARNING",
        severity="LOW",
        observed_value=value,
        explanation=(
            f"X-Frame-Options has an unrecognised value '{value.strip()}'.  "
            "Valid values are DENY, SAMEORIGIN, or (deprecated) ALLOW-FROM."
        ),
        recommendation="Set X-Frame-Options to DENY or SAMEORIGIN.",
    )


# ── Check 6 — Referrer-Policy ────────────────────────────────────────────────

# Values that are secure in that they limit referrer leakage
_REFERRER_SAFE = {
    "no-referrer",
    "no-referrer-when-downgrade",
    "origin",
    "origin-when-cross-origin",
    "same-origin",
    "strict-origin",
    "strict-origin-when-cross-origin",  # browser default in modern browsers
}
# Values that expose the full URL to third parties
_REFERRER_LEAKY = {"unsafe-url", ""}


def check_referrer_policy(response: dict) -> dict:
    """
    Check for the Referrer-Policy header.

    Why it matters
    --------------
    When a user clicks a link, the browser typically sends a 'Referer'
    header to the destination containing the full URL of the originating
    page.  If URLs contain sensitive data (session tokens, user IDs, search
    terms), those details leak to every third-party resource loaded on the
    page (analytics, CDNs, ad networks).

    Referrer-Policy controls how much URL information is included in that
    header.  'no-referrer' sends nothing; 'unsafe-url' sends the full URL
    even across HTTP→HTTPS downgrades.

    Limitation: absence of this header is not catastrophic — modern browsers
    default to 'strict-origin-when-cross-origin'.  Missing the header is
    flagged as WARNING rather than FAIL.
    """
    headers = response.get("headers", {})
    value = _get_header(headers, "referrer-policy")

    if value is None:
        return _finding(
            check_name="Referrer-Policy",
            status="WARNING",
            severity="LOW",
            observed_value="<missing>",
            explanation=(
                "No Referrer-Policy header found.  Modern browsers default to "
                "'strict-origin-when-cross-origin', which is reasonable, but "
                "explicitly setting a policy is a security best practice that "
                "removes reliance on browser defaults."
            ),
            recommendation=(
                "Add \"Referrer-Policy: strict-origin-when-cross-origin\" "
                "(or 'no-referrer' for maximum privacy)."
            ),
        )

    normalised = value.strip().lower()

    if normalised in _REFERRER_LEAKY or normalised == "unsafe-url":
        return _finding(
            check_name="Referrer-Policy",
            status="WARNING",
            severity="MEDIUM",
            observed_value=value,
            explanation=(
                f"Referrer-Policy is set to '{normalised}', which sends the "
                "full URL (including path and query string) in the Referer header "
                "to all destinations, including third-party sites.  This may leak "
                "sensitive URL parameters."
            ),
            recommendation=(
                "Change to 'no-referrer', 'strict-origin', or "
                "'strict-origin-when-cross-origin' to reduce information leakage."
            ),
        )

    if normalised in _REFERRER_SAFE:
        return _finding(
            check_name="Referrer-Policy",
            status="PASS",
            severity="INFO",
            observed_value=value,
            explanation=(
                f"Referrer-Policy is set to '{normalised}', "
                "which appropriately limits referrer information leakage."
            ),
            recommendation="No action required.",
        )

    return _finding(
        check_name="Referrer-Policy",
        status="WARNING",
        severity="LOW",
        observed_value=value,
        explanation=(
            f"Referrer-Policy has an unrecognised value '{value.strip()}'.  "
            "Browsers may ignore unrecognised values and fall back to their default."
        ),
        recommendation=(
            "Use a recognised value such as 'strict-origin-when-cross-origin' "
            "or 'no-referrer'."
        ),
    )


# ── Rule registry ─────────────────────────────────────────────────────────────

ALL_RULES = [
    check_https,
    check_content_security_policy,
    check_hsts,
    check_x_content_type_options,
    check_x_frame_options,
    check_referrer_policy,
]


def run_all_rules(response: dict) -> list[dict]:
    """
    Run every rule in ALL_RULES against *response* and return a list of
    finding dicts.

    Parameters
    ----------
    response : dict
        The response dict produced by scanner.fetch_url().

    Returns
    -------
    list[dict]
        One finding dict per rule, in ALL_RULES order.
    """
    return [rule(response) for rule in ALL_RULES]
