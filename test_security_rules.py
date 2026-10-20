"""
tests/test_security_rules.py — Unit tests for security_rules.py

No network requests are made.  Every test passes a fake response dict
directly to the rule functions and asserts the returned finding.

Test matrix per rule
--------------------
  • Header present with a secure value  → PASS
  • Header completely absent            → FAIL (or WARNING for softer rules)
  • Header present but empty            → FAIL
  • Header with correct casing variants → case-insensitive lookup works
  • Header with a weak / deprecated value → WARNING
  • Edge cases specific to each rule
"""

import pytest
from webguard.security_rules import (
    check_https,
    check_content_security_policy,
    check_hsts,
    check_x_content_type_options,
    check_x_frame_options,
    check_referrer_policy,
    run_all_rules,
    ALL_RULES,
)


# ── Shared fixtures ───────────────────────────────────────────────────────────

@pytest.fixture
def base_https_response():
    """
    A well-configured HTTPS response carrying all security headers.
    Individual tests override specific keys as needed.
    """
    return {
        "url": "https://example.com",
        "status_code": 200,
        "headers": {
            "strict-transport-security": "max-age=31536000; includeSubDomains",
            "content-security-policy": "default-src 'self'",
            "x-frame-options": "DENY",
            "x-content-type-options": "nosniff",
            "referrer-policy": "strict-origin-when-cross-origin",
        },
        "history": [],
        "elapsed_ms": 120.5,
        "error": None,
    }


@pytest.fixture
def base_http_response():
    """Plain HTTP response with no security headers."""
    return {
        "url": "http://example.com",
        "status_code": 200,
        "headers": {},
        "history": [],
        "elapsed_ms": 98.0,
        "error": None,
    }


def _with_header(response: dict, name: str, value: str) -> dict:
    """Return a copy of *response* with *name* header set to *value*."""
    copy = dict(response)
    copy["headers"] = dict(response["headers"])
    copy["headers"][name] = value
    return copy


def _without_header(response: dict, name: str) -> dict:
    """Return a copy of *response* with *name* header removed."""
    copy = dict(response)
    copy["headers"] = {k: v for k, v in response["headers"].items()
                       if k.lower() != name.lower()}
    return copy


# ── Finding schema helper ─────────────────────────────────────────────────────

def assert_finding_schema(finding: dict) -> None:
    """Every finding must carry all six required keys."""
    required = {"check_name", "status", "severity", "observed_value",
                "explanation", "recommendation"}
    assert required == set(finding.keys()), (
        f"Finding is missing keys: {required - set(finding.keys())}"
    )
    assert finding["status"] in {"PASS", "WARNING", "FAIL"}
    assert finding["severity"] in {"INFO", "LOW", "MEDIUM", "HIGH"}
    assert isinstance(finding["explanation"], str) and finding["explanation"]
    assert isinstance(finding["recommendation"], str) and finding["recommendation"]


# ══════════════════════════════════════════════════════════════════════════════
# check_https
# ══════════════════════════════════════════════════════════════════════════════

class TestCheckHttps:
    def test_https_url_passes(self, base_https_response):
        result = check_https(base_https_response)
        assert result["status"] == "PASS"
        assert_finding_schema(result)

    def test_http_url_fails(self, base_http_response):
        result = check_https(base_http_response)
        assert result["status"] == "FAIL"
        assert result["severity"] == "HIGH"
        assert_finding_schema(result)

    def test_observed_value_is_the_url(self, base_https_response):
        result = check_https(base_https_response)
        assert result["observed_value"] == "https://example.com"

    def test_missing_url_key_fails(self):
        """Response with no 'url' key should not raise — it should FAIL."""
        result = check_https({})
        assert result["status"] == "FAIL"

    def test_ftp_scheme_fails(self):
        result = check_https({"url": "ftp://example.com", "headers": {}})
        assert result["status"] == "FAIL"

    def test_https_with_path_passes(self):
        result = check_https({"url": "https://example.com/page?q=1", "headers": {}})
        assert result["status"] == "PASS"


# ══════════════════════════════════════════════════════════════════════════════
# check_content_security_policy
# ══════════════════════════════════════════════════════════════════════════════

class TestCheckCSP:
    def test_good_csp_passes(self, base_https_response):
        result = check_content_security_policy(base_https_response)
        assert result["status"] == "PASS"
        assert_finding_schema(result)

    def test_missing_csp_fails(self, base_https_response):
        response = _without_header(base_https_response, "content-security-policy")
        result = check_content_security_policy(response)
        assert result["status"] == "FAIL"
        assert result["severity"] == "HIGH"
        assert result["observed_value"] == "<missing>"

    def test_empty_csp_fails(self, base_https_response):
        response = _with_header(base_https_response, "content-security-policy", "   ")
        result = check_content_security_policy(response)
        assert result["status"] == "FAIL"
        assert result["observed_value"] == "<empty>"

    def test_unsafe_inline_warns(self, base_https_response):
        response = _with_header(
            base_https_response,
            "content-security-policy",
            "default-src 'self'; script-src 'unsafe-inline'",
        )
        result = check_content_security_policy(response)
        assert result["status"] == "WARNING"
        assert result["severity"] == "MEDIUM"

    def test_unsafe_eval_warns(self, base_https_response):
        response = _with_header(
            base_https_response,
            "content-security-policy",
            "script-src 'self' 'unsafe-eval'",
        )
        result = check_content_security_policy(response)
        assert result["status"] == "WARNING"

    def test_wildcard_script_src_warns(self, base_https_response):
        response = _with_header(
            base_https_response,
            "content-security-policy",
            "script-src *",
        )
        result = check_content_security_policy(response)
        assert result["status"] == "WARNING"

    def test_wildcard_default_src_warns(self, base_https_response):
        response = _with_header(
            base_https_response,
            "content-security-policy",
            "default-src *",
        )
        result = check_content_security_policy(response)
        assert result["status"] == "WARNING"

    def test_csp_lookup_case_insensitive(self, base_https_response):
        """Header stored with mixed-case key must still be found."""
        response = _without_header(base_https_response, "content-security-policy")
        response["headers"]["Content-Security-Policy"] = "default-src 'self'"
        result = check_content_security_policy(response)
        assert result["status"] == "PASS"

    def test_csp_lookup_uppercase_key(self, base_https_response):
        response = _without_header(base_https_response, "content-security-policy")
        response["headers"]["CONTENT-SECURITY-POLICY"] = "default-src 'self'"
        result = check_content_security_policy(response)
        assert result["status"] == "PASS"

    def test_pass_includes_caveat_in_explanation(self, base_https_response):
        """PASS explanation must acknowledge the limitation of string scanning."""
        result = check_content_security_policy(base_https_response)
        assert "string scan" in result["explanation"].lower() or \
               "manual" in result["explanation"].lower() or \
               "cannot guarantee" in result["explanation"].lower()


# ══════════════════════════════════════════════════════════════════════════════
# check_hsts
# ══════════════════════════════════════════════════════════════════════════════

class TestCheckHSTS:
    def test_good_hsts_on_https_passes(self, base_https_response):
        result = check_hsts(base_https_response)
        assert result["status"] == "PASS"
        assert_finding_schema(result)

    def test_missing_hsts_on_https_fails_high(self, base_https_response):
        response = _without_header(base_https_response, "strict-transport-security")
        result = check_hsts(response)
        assert result["status"] == "FAIL"
        assert result["severity"] == "HIGH"

    def test_missing_hsts_on_http_fails_low(self, base_http_response):
        """
        HSTS missing on HTTP is low-severity: it can't be set here anyway.
        The real problem (HTTP) is flagged by check_https.
        """
        result = check_hsts(base_http_response)
        assert result["status"] == "FAIL"
        assert result["severity"] == "LOW"

    def test_hsts_on_http_response_warns(self, base_http_response):
        """
        HSTS header present on an HTTP response is present but useless.
        Browsers discard it — should be WARNING not PASS.
        """
        response = _with_header(
            base_http_response,
            "strict-transport-security",
            "max-age=31536000",
        )
        result = check_hsts(response)
        assert result["status"] == "WARNING"

    def test_empty_hsts_fails(self, base_https_response):
        response = _with_header(base_https_response, "strict-transport-security", "  ")
        result = check_hsts(response)
        assert result["status"] == "FAIL"
        assert result["observed_value"] == "<empty>"

    def test_hsts_without_max_age_warns(self, base_https_response):
        response = _with_header(
            base_https_response,
            "strict-transport-security",
            "includeSubDomains; preload",
        )
        result = check_hsts(response)
        assert result["status"] == "WARNING"

    def test_hsts_short_max_age_warns(self, base_https_response):
        """max-age below 126 days should warn."""
        response = _with_header(
            base_https_response,
            "strict-transport-security",
            "max-age=3600",  # only 1 hour
        )
        result = check_hsts(response)
        assert result["status"] == "WARNING"

    def test_hsts_exact_min_max_age_passes(self, base_https_response):
        """max-age exactly at the minimum threshold (126 days) should pass."""
        response = _with_header(
            base_https_response,
            "strict-transport-security",
            "max-age=10886400",
        )
        result = check_hsts(response)
        assert result["status"] == "PASS"

    def test_hsts_case_insensitive_lookup(self, base_https_response):
        response = _without_header(base_https_response, "strict-transport-security")
        response["headers"]["Strict-Transport-Security"] = "max-age=31536000"
        result = check_hsts(response)
        assert result["status"] == "PASS"

    def test_hsts_max_age_case_insensitive_directive(self, base_https_response):
        """max-age directive itself may arrive with mixed case."""
        response = _with_header(
            base_https_response,
            "strict-transport-security",
            "MAX-AGE=31536000; includeSubDomains",
        )
        result = check_hsts(response)
        assert result["status"] == "PASS"


# ══════════════════════════════════════════════════════════════════════════════
# check_x_content_type_options
# ══════════════════════════════════════════════════════════════════════════════

class TestCheckXContentTypeOptions:
    def test_nosniff_passes(self, base_https_response):
        result = check_x_content_type_options(base_https_response)
        assert result["status"] == "PASS"
        assert_finding_schema(result)

    def test_missing_fails(self, base_https_response):
        response = _without_header(base_https_response, "x-content-type-options")
        result = check_x_content_type_options(response)
        assert result["status"] == "FAIL"
        assert result["severity"] == "MEDIUM"
        assert result["observed_value"] == "<missing>"

    def test_nosniff_case_insensitive_value(self, base_https_response):
        """'NOSNIFF', 'Nosniff', 'nosniff' are all valid."""
        for val in ("NOSNIFF", "Nosniff", "nosniff", " nosniff "):
            response = _with_header(base_https_response, "x-content-type-options", val)
            result = check_x_content_type_options(response)
            assert result["status"] == "PASS", f"Failed for value: '{val}'"

    def test_header_lookup_case_insensitive(self, base_https_response):
        response = _without_header(base_https_response, "x-content-type-options")
        response["headers"]["X-Content-Type-Options"] = "nosniff"
        result = check_x_content_type_options(response)
        assert result["status"] == "PASS"

    def test_unrecognised_value_warns(self, base_https_response):
        response = _with_header(base_https_response, "x-content-type-options", "sniff")
        result = check_x_content_type_options(response)
        assert result["status"] == "WARNING"

    def test_empty_value_warns(self, base_https_response):
        """An empty (but present) header value is not 'nosniff'."""
        response = _with_header(base_https_response, "x-content-type-options", "")
        result = check_x_content_type_options(response)
        # empty string ≠ "nosniff" so should warn
        assert result["status"] in {"WARNING", "FAIL"}


# ══════════════════════════════════════════════════════════════════════════════
# check_x_frame_options
# ══════════════════════════════════════════════════════════════════════════════

class TestCheckXFrameOptions:
    def test_deny_passes(self, base_https_response):
        result = check_x_frame_options(base_https_response)
        assert result["status"] == "PASS"
        assert_finding_schema(result)

    def test_sameorigin_passes(self, base_https_response):
        response = _with_header(base_https_response, "x-frame-options", "SAMEORIGIN")
        result = check_x_frame_options(response)
        assert result["status"] == "PASS"

    def test_missing_fails(self, base_https_response):
        response = _without_header(base_https_response, "x-frame-options")
        result = check_x_frame_options(response)
        assert result["status"] == "FAIL"
        assert result["severity"] == "MEDIUM"
        assert result["observed_value"] == "<missing>"

    def test_deny_case_insensitive(self, base_https_response):
        """'deny', 'Deny', 'DENY' should all pass."""
        for val in ("deny", "Deny", "DENY", " DENY "):
            response = _with_header(base_https_response, "x-frame-options", val)
            result = check_x_frame_options(response)
            assert result["status"] == "PASS", f"Failed for '{val}'"

    def test_sameorigin_case_insensitive(self, base_https_response):
        for val in ("sameorigin", "SameOrigin", "SAMEORIGIN"):
            response = _with_header(base_https_response, "x-frame-options", val)
            result = check_x_frame_options(response)
            assert result["status"] == "PASS", f"Failed for '{val}'"

    def test_allow_from_warns(self, base_https_response):
        """ALLOW-FROM is deprecated and ignored by modern browsers."""
        response = _with_header(
            base_https_response,
            "x-frame-options",
            "ALLOW-FROM https://trusted.com",
        )
        result = check_x_frame_options(response)
        assert result["status"] == "WARNING"
        assert result["severity"] == "MEDIUM"

    def test_allow_from_lowercase_warns(self, base_https_response):
        response = _with_header(
            base_https_response,
            "x-frame-options",
            "allow-from https://trusted.com",
        )
        result = check_x_frame_options(response)
        assert result["status"] == "WARNING"

    def test_unrecognised_value_warns(self, base_https_response):
        response = _with_header(base_https_response, "x-frame-options", "ALLOW-ALL")
        result = check_x_frame_options(response)
        assert result["status"] == "WARNING"

    def test_header_lookup_case_insensitive(self, base_https_response):
        response = _without_header(base_https_response, "x-frame-options")
        response["headers"]["X-Frame-Options"] = "DENY"
        result = check_x_frame_options(response)
        assert result["status"] == "PASS"


# ══════════════════════════════════════════════════════════════════════════════
# check_referrer_policy
# ══════════════════════════════════════════════════════════════════════════════

class TestCheckReferrerPolicy:
    def test_strict_origin_when_cross_origin_passes(self, base_https_response):
        result = check_referrer_policy(base_https_response)
        assert result["status"] == "PASS"
        assert_finding_schema(result)

    def test_no_referrer_passes(self, base_https_response):
        response = _with_header(base_https_response, "referrer-policy", "no-referrer")
        result = check_referrer_policy(response)
        assert result["status"] == "PASS"

    @pytest.mark.parametrize("safe_value", [
        "no-referrer",
        "no-referrer-when-downgrade",
        "origin",
        "origin-when-cross-origin",
        "same-origin",
        "strict-origin",
        "strict-origin-when-cross-origin",
    ])
    def test_all_safe_values_pass(self, base_https_response, safe_value):
        response = _with_header(base_https_response, "referrer-policy", safe_value)
        result = check_referrer_policy(response)
        assert result["status"] == "PASS", f"Expected PASS for '{safe_value}'"

    def test_missing_header_warns(self, base_https_response):
        """
        Missing Referrer-Policy is WARNING, not FAIL — modern browsers have
        a safe default.
        """
        response = _without_header(base_https_response, "referrer-policy")
        result = check_referrer_policy(response)
        assert result["status"] == "WARNING"
        assert result["severity"] == "LOW"

    def test_unsafe_url_warns(self, base_https_response):
        response = _with_header(base_https_response, "referrer-policy", "unsafe-url")
        result = check_referrer_policy(response)
        assert result["status"] == "WARNING"
        assert result["severity"] == "MEDIUM"

    def test_referrer_policy_case_insensitive_lookup(self, base_https_response):
        response = _without_header(base_https_response, "referrer-policy")
        response["headers"]["Referrer-Policy"] = "no-referrer"
        result = check_referrer_policy(response)
        assert result["status"] == "PASS"

    def test_referrer_policy_value_case_insensitive(self, base_https_response):
        """Header values are compared case-insensitively."""
        response = _with_header(base_https_response, "referrer-policy", "No-Referrer")
        result = check_referrer_policy(response)
        assert result["status"] == "PASS"

    def test_unrecognised_value_warns(self, base_https_response):
        response = _with_header(base_https_response, "referrer-policy", "send-all")
        result = check_referrer_policy(response)
        assert result["status"] == "WARNING"


# ══════════════════════════════════════════════════════════════════════════════
# run_all_rules
# ══════════════════════════════════════════════════════════════════════════════

class TestRunAllRules:
    def test_returns_one_finding_per_rule(self, base_https_response):
        findings = run_all_rules(base_https_response)
        assert len(findings) == len(ALL_RULES)

    def test_every_finding_has_valid_schema(self, base_https_response):
        for finding in run_all_rules(base_https_response):
            assert_finding_schema(finding)

    def test_well_configured_response_has_no_fails(self, base_https_response):
        findings = run_all_rules(base_https_response)
        statuses = [f["status"] for f in findings]
        assert "FAIL" not in statuses, (
            f"Unexpected FAIL in well-configured response: "
            f"{[f for f in findings if f['status'] == 'FAIL']}"
        )

    def test_bare_http_response_has_fails(self, base_http_response):
        """An HTTP-only response with no headers must produce at least one FAIL."""
        findings = run_all_rules(base_http_response)
        statuses = [f["status"] for f in findings]
        assert "FAIL" in statuses

    def test_all_check_names_are_unique(self, base_https_response):
        findings = run_all_rules(base_https_response)
        names = [f["check_name"] for f in findings]
        assert len(names) == len(set(names)), "Duplicate check_name in findings"

    def test_result_is_a_list_of_dicts(self, base_https_response):
        findings = run_all_rules(base_https_response)
        assert isinstance(findings, list)
        for f in findings:
            assert isinstance(f, dict)
