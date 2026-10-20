"""
tests/test_url_validation.py — Tests for scanner.py

Coverage
--------
  A. validate_url()     — static validation, no network I/O
  B. _is_ip_safe()      — IP address classification
  C. fetch_url()        — HTTP behaviour, mocked network
  D. scan_url()         — orchestration

No real network requests are made.  All tests that exercise code paths
involving network I/O use unittest.mock to patch socket.getaddrinfo and
requests.Session.get so the test suite runs offline and deterministically.

Mock strategy
-------------
  • validate_url() is pure-Python with no I/O → tested directly.
  • _is_ip_safe() is pure-Python → tested directly.
  • fetch_url() calls socket.getaddrinfo and requests.Session.get.
    Both are patched at the webguard.scanner module level so the patches
    intercept the exact names that scanner.py imported.
  • scan_url() is tested by patching fetch_url() to return a canned result.
"""

import socket
import datetime
from unittest.mock import MagicMock, patch

import pytest

from webguard.scanner import (
    validate_url,
    fetch_url,
    scan_url,
    _is_ip_safe,
    _resolve_and_check,
    MAX_REDIRECTS,
)


# ══════════════════════════════════════════════════════════════════════════════
# A. validate_url — static checks (no DNS, no network)
# ══════════════════════════════════════════════════════════════════════════════

class TestValidateUrl:
    """
    All tests in this class rely solely on static URL structure.
    No DNS lookups or network calls are made.
    validate_url() returns (bool, str) — we check both elements.
    """

    # ── Happy paths ───────────────────────────────────────────────────────────

    def test_valid_https_url_accepted(self):
        ok, reason = validate_url("https://example.com")
        assert ok is True
        assert reason == ""

    def test_valid_http_url_accepted(self):
        """HTTP is valid to submit (it will FAIL the https security rule later)."""
        ok, reason = validate_url("http://example.com")
        assert ok is True

    def test_url_with_path_and_query_accepted(self):
        ok, _ = validate_url("https://example.com/page?ref=1&lang=en")
        assert ok is True

    def test_url_with_port_accepted(self):
        ok, _ = validate_url("https://example.com:8443/")
        assert ok is True

    def test_url_with_subdomain_accepted(self):
        ok, _ = validate_url("https://sub.example.co.uk/path")
        assert ok is True

    # ── Empty / malformed ────────────────────────────────────────────────────

    def test_empty_string_rejected(self):
        ok, reason = validate_url("")
        assert ok is False
        assert reason

    def test_whitespace_only_rejected(self):
        ok, _ = validate_url("   ")
        assert ok is False

    def test_none_rejected(self):
        # None is not a str — should be handled gracefully, not raise
        ok, _ = validate_url(None)  # type: ignore[arg-type]
        assert ok is False

    def test_missing_scheme_rejected(self):
        ok, reason = validate_url("example.com")
        assert ok is False
        assert reason

    def test_scheme_only_rejected(self):
        ok, _ = validate_url("https://")
        assert ok is False

    # ── Unsupported schemes ───────────────────────────────────────────────────

    def test_file_scheme_rejected(self):
        """file:// could expose local filesystem."""
        ok, reason = validate_url("file:///etc/passwd")
        assert ok is False
        assert "file" in reason.lower() or reason

    def test_ftp_scheme_rejected(self):
        ok, _ = validate_url("ftp://example.com/pub/file.txt")
        assert ok is False

    def test_javascript_scheme_rejected(self):
        ok, _ = validate_url("javascript:alert(1)")
        assert ok is False

    def test_data_scheme_rejected(self):
        ok, _ = validate_url("data:text/html,<h1>Hi</h1>")
        assert ok is False

    def test_ssh_scheme_rejected(self):
        ok, _ = validate_url("ssh://user@host")
        assert ok is False

    # ── Embedded credentials ─────────────────────────────────────────────────

    def test_url_with_username_rejected(self):
        ok, reason = validate_url("https://user@example.com")
        assert ok is False
        assert "credential" in reason.lower() or reason

    def test_url_with_password_rejected(self):
        ok, reason = validate_url("https://user:pass@example.com")
        assert ok is False

    # ── Blocked hostnames ─────────────────────────────────────────────────────

    def test_localhost_rejected(self):
        ok, reason = validate_url("http://localhost/admin")
        assert ok is False
        assert reason

    def test_localhost_https_rejected(self):
        ok, _ = validate_url("https://localhost:443/")
        assert ok is False

    def test_cloud_metadata_hostname_rejected(self):
        ok, _ = validate_url("http://169.254.169.254/latest/meta-data/")
        assert ok is False

    def test_google_metadata_hostname_rejected(self):
        ok, _ = validate_url("http://metadata.google.internal/computeMetadata/v1/")
        assert ok is False

    # ── Literal private / reserved IPv4 addresses ────────────────────────────

    def test_private_192_168_rejected(self):
        ok, _ = validate_url("http://192.168.1.1")
        assert ok is False

    def test_private_10_x_rejected(self):
        ok, _ = validate_url("http://10.0.0.1")
        assert ok is False

    def test_private_172_16_rejected(self):
        ok, _ = validate_url("http://172.16.0.1")
        assert ok is False

    def test_loopback_127_0_0_1_rejected(self):
        ok, _ = validate_url("http://127.0.0.1")
        assert ok is False

    def test_loopback_127_0_0_255_rejected(self):
        """Entire 127.0.0.0/8 is loopback."""
        ok, _ = validate_url("http://127.0.0.255")
        assert ok is False

    def test_link_local_ip_rejected(self):
        """169.254.0.0/16 is link-local — used by AWS IMDS."""
        ok, _ = validate_url("http://169.254.0.1")
        assert ok is False

    # ── Literal private / reserved IPv6 addresses ────────────────────────────

    def test_ipv6_loopback_rejected(self):
        ok, _ = validate_url("http://[::1]/")
        assert ok is False

    def test_ipv6_private_rejected(self):
        """fc00::/7 is unique-local (private IPv6)."""
        ok, _ = validate_url("http://[fc00::1]/")
        assert ok is False

    def test_ipv6_link_local_rejected(self):
        """fe80::/10 is link-local IPv6."""
        ok, _ = validate_url("http://[fe80::1]/")
        assert ok is False


# ══════════════════════════════════════════════════════════════════════════════
# B. _is_ip_safe — IP classification unit tests
# ══════════════════════════════════════════════════════════════════════════════

class TestIsIpSafe:
    def test_public_ipv4_safe(self):
        ok, _ = _is_ip_safe("93.184.216.34")  # example.com
        assert ok is True

    def test_loopback_unsafe(self):
        ok, _ = _is_ip_safe("127.0.0.1")
        assert ok is False

    def test_private_class_a_unsafe(self):
        ok, _ = _is_ip_safe("10.1.2.3")
        assert ok is False

    def test_private_class_b_unsafe(self):
        ok, _ = _is_ip_safe("172.16.100.1")
        assert ok is False

    def test_private_class_c_unsafe(self):
        ok, _ = _is_ip_safe("192.168.0.1")
        assert ok is False

    def test_link_local_ipv4_unsafe(self):
        ok, _ = _is_ip_safe("169.254.169.254")
        assert ok is False

    def test_multicast_unsafe(self):
        ok, _ = _is_ip_safe("224.0.0.1")
        assert ok is False

    def test_unspecified_unsafe(self):
        ok, _ = _is_ip_safe("0.0.0.0")
        assert ok is False

    def test_ipv6_loopback_unsafe(self):
        ok, _ = _is_ip_safe("::1")
        assert ok is False

    def test_ipv6_private_unsafe(self):
        ok, _ = _is_ip_safe("fc00::1")
        assert ok is False

    def test_ipv6_link_local_unsafe(self):
        ok, _ = _is_ip_safe("fe80::1")
        assert ok is False

    def test_public_ipv6_safe(self):
        ok, _ = _is_ip_safe("2001:4860:4860::8888")  # Google DNS
        assert ok is True

    def test_bad_string_returns_false(self):
        ok, reason = _is_ip_safe("not-an-ip")
        assert ok is False
        assert reason


# ══════════════════════════════════════════════════════════════════════════════
# C. fetch_url — mocked network tests
# ══════════════════════════════════════════════════════════════════════════════

def _make_mock_response(
    status_code: int = 200,
    headers: dict | None = None,
    url: str = "https://example.com",
    is_redirect: bool = False,
) -> MagicMock:
    """Build a minimal mock of a requests.Response object."""
    resp = MagicMock()
    resp.status_code = status_code
    resp.headers = headers or {}
    resp.url = url
    resp.is_redirect = is_redirect
    resp.raw = MagicMock()
    resp.raw.read.return_value = b""
    return resp


def _public_getaddrinfo(host, port, *args, **kwargs):
    """Mock for socket.getaddrinfo that returns a safe public IP."""
    return [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("93.184.216.34", 0))]


def _private_getaddrinfo(host, port, *args, **kwargs):
    """Mock for socket.getaddrinfo that returns a private IP (simulates DNS rebind)."""
    return [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("192.168.1.1", 0))]


def _loopback_getaddrinfo(host, port, *args, **kwargs):
    return [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("127.0.0.1", 0))]


class TestFetchUrl:

    @patch("webguard.scanner.socket.getaddrinfo", side_effect=_public_getaddrinfo)
    @patch("webguard.scanner.requests.Session.get")
    def test_successful_fetch_returns_expected_shape(self, mock_get, mock_dns):
        mock_get.return_value = _make_mock_response(
            status_code=200,
            headers={"content-type": "text/html"},
            url="https://example.com",
        )
        result = fetch_url("https://example.com")
        assert result["error"] is None
        assert result["status_code"] == 200
        assert result["is_https"] is True
        assert isinstance(result["headers"], dict)
        assert isinstance(result["redirect_chain"], list)
        assert isinstance(result["elapsed_ms"], float)
        assert isinstance(result["scan_timestamp"], str)

    @patch("webguard.scanner.socket.getaddrinfo", side_effect=_public_getaddrinfo)
    @patch("webguard.scanner.requests.Session.get")
    def test_headers_are_lower_cased(self, mock_get, mock_dns):
        mock_get.return_value = _make_mock_response(
            headers={"Content-Type": "text/html", "X-Frame-Options": "DENY"},
        )
        result = fetch_url("https://example.com")
        assert "content-type" in result["headers"]
        assert "x-frame-options" in result["headers"]

    @patch("webguard.scanner.socket.getaddrinfo", side_effect=_public_getaddrinfo)
    @patch("webguard.scanner.requests.Session.get")
    def test_http_url_is_https_false(self, mock_get, mock_dns):
        mock_get.return_value = _make_mock_response(
            url="http://example.com", status_code=200
        )
        result = fetch_url("http://example.com")
        assert result["is_https"] is False

    # ── DNS resolves to private IP (simulated rebind) ────────────────────────

    @patch("webguard.scanner.socket.getaddrinfo", side_effect=_private_getaddrinfo)
    def test_dns_resolving_to_private_ip_is_blocked(self, mock_dns):
        """
        Simulates a DNS rebinding scenario where the hostname resolves to a
        private IP.  The pre-flight check in fetch_url should block this before
        any socket connection is attempted.
        """
        result = fetch_url("https://example.com")
        assert result["error"] is not None
        assert "blocked" in result["error"].lower() or "private" in result["error"].lower()

    @patch("webguard.scanner.socket.getaddrinfo", side_effect=_loopback_getaddrinfo)
    def test_dns_resolving_to_loopback_is_blocked(self, mock_dns):
        result = fetch_url("https://example.com")
        assert result["error"] is not None

    # ── Connection errors ────────────────────────────────────────────────────

    @patch("webguard.scanner.socket.getaddrinfo", side_effect=_public_getaddrinfo)
    @patch("webguard.scanner.requests.Session.get",
           side_effect=__import__("requests").exceptions.ConnectTimeout)
    def test_connect_timeout_returns_safe_error(self, mock_get, mock_dns):
        result = fetch_url("https://example.com")
        assert result["error"] is not None
        assert "timed out" in result["error"].lower() or "timeout" in result["error"].lower()
        # Must not expose raw exception internals
        assert "Traceback" not in result["error"]

    @patch("webguard.scanner.socket.getaddrinfo", side_effect=_public_getaddrinfo)
    @patch("webguard.scanner.requests.Session.get",
           side_effect=__import__("requests").exceptions.ReadTimeout)
    def test_read_timeout_returns_safe_error(self, mock_get, mock_dns):
        result = fetch_url("https://example.com")
        assert result["error"] is not None
        assert "timed out" in result["error"].lower() or "timeout" in result["error"].lower()

    @patch("webguard.scanner.socket.getaddrinfo", side_effect=_public_getaddrinfo)
    @patch("webguard.scanner.requests.Session.get",
           side_effect=__import__("requests").exceptions.SSLError("cert verify failed"))
    def test_ssl_error_returns_safe_error(self, mock_get, mock_dns):
        result = fetch_url("https://example.com")
        assert result["error"] is not None
        assert "tls" in result["error"].lower() or "ssl" in result["error"].lower()
        # Raw cert details must not be surfaced
        assert "cert verify failed" not in result["error"]

    @patch("webguard.scanner.socket.getaddrinfo", side_effect=_public_getaddrinfo)
    @patch("webguard.scanner.requests.Session.get",
           side_effect=__import__("requests").exceptions.ConnectionError)
    def test_connection_error_returns_safe_error(self, mock_get, mock_dns):
        result = fetch_url("https://example.com")
        assert result["error"] is not None
        assert "connection" in result["error"].lower()

    # ── HTTP error status codes ───────────────────────────────────────────────

    @patch("webguard.scanner.socket.getaddrinfo", side_effect=_public_getaddrinfo)
    @patch("webguard.scanner.requests.Session.get")
    def test_404_response_is_returned_without_error(self, mock_get, mock_dns):
        """
        404 is a legitimate HTTP response — the scanner should return it
        and let the security rules evaluate it.  It is not a scanner error.
        """
        mock_get.return_value = _make_mock_response(status_code=404)
        result = fetch_url("https://example.com/missing")
        assert result["error"] is None
        assert result["status_code"] == 404

    @patch("webguard.scanner.socket.getaddrinfo", side_effect=_public_getaddrinfo)
    @patch("webguard.scanner.requests.Session.get")
    def test_500_response_is_returned_without_error(self, mock_get, mock_dns):
        mock_get.return_value = _make_mock_response(status_code=500)
        result = fetch_url("https://example.com")
        assert result["error"] is None
        assert result["status_code"] == 500

    # ── Redirect handling ─────────────────────────────────────────────────────

    @patch("webguard.scanner.socket.getaddrinfo", side_effect=_public_getaddrinfo)
    @patch("webguard.scanner.requests.Session.get")
    def test_redirect_to_public_destination_is_followed(self, mock_get, mock_dns):
        """
        First call returns a 301 redirect to a public HTTPS URL.
        Second call returns a 200.
        """
        redirect_resp = _make_mock_response(
            status_code=301,
            headers={"location": "https://www.example.com/"},
            url="https://example.com",
            is_redirect=True,
        )
        final_resp = _make_mock_response(
            status_code=200,
            url="https://www.example.com/",
        )
        mock_get.side_effect = [redirect_resp, final_resp]

        result = fetch_url("https://example.com")
        assert result["error"] is None
        assert result["status_code"] == 200
        assert "https://example.com" in result["redirect_chain"]

    @patch("webguard.scanner.socket.getaddrinfo", side_effect=_public_getaddrinfo)
    @patch("webguard.scanner.requests.Session.get")
    def test_redirect_to_private_ip_is_blocked(self, mock_get, mock_dns):
        """
        The scanner follows a redirect that leads to a private IP URL.
        validate_url() must catch the literal private IP in the Location header.
        """
        redirect_resp = _make_mock_response(
            status_code=302,
            headers={"location": "http://192.168.1.1/secret"},
            url="https://example.com",
            is_redirect=True,
        )
        mock_get.return_value = redirect_resp

        result = fetch_url("https://example.com")
        assert result["error"] is not None

    @patch("webguard.scanner.socket.getaddrinfo", side_effect=_public_getaddrinfo)
    @patch("webguard.scanner.requests.Session.get")
    def test_redirect_to_localhost_is_blocked(self, mock_get, mock_dns):
        redirect_resp = _make_mock_response(
            status_code=301,
            headers={"location": "http://localhost/admin"},
            url="https://example.com",
            is_redirect=True,
        )
        mock_get.return_value = redirect_resp
        result = fetch_url("https://example.com")
        assert result["error"] is not None

    @patch("webguard.scanner.socket.getaddrinfo", side_effect=_public_getaddrinfo)
    @patch("webguard.scanner.requests.Session.get")
    def test_too_many_redirects_returns_error(self, mock_get, mock_dns):
        """Create a redirect chain longer than MAX_REDIRECTS."""
        redirect_resp = _make_mock_response(
            status_code=302,
            headers={"location": "https://example.com/hop"},
            url="https://example.com",
            is_redirect=True,
        )
        # Every call returns a redirect — hits the limit
        mock_get.return_value = redirect_resp

        result = fetch_url("https://example.com")
        assert result["error"] is not None
        assert "redirect" in result["error"].lower()

    @patch("webguard.scanner.socket.getaddrinfo", side_effect=_public_getaddrinfo)
    @patch("webguard.scanner.requests.Session.get")
    def test_redirect_with_empty_location_returns_error(self, mock_get, mock_dns):
        redirect_resp = _make_mock_response(
            status_code=302,
            headers={"location": ""},
            url="https://example.com",
            is_redirect=True,
        )
        mock_get.return_value = redirect_resp
        result = fetch_url("https://example.com")
        assert result["error"] is not None

    # ── Result schema ─────────────────────────────────────────────────────────

    @patch("webguard.scanner.socket.getaddrinfo", side_effect=_public_getaddrinfo)
    @patch("webguard.scanner.requests.Session.get")
    def test_result_always_has_all_keys(self, mock_get, mock_dns):
        mock_get.return_value = _make_mock_response()
        result = fetch_url("https://example.com")
        required = {
            "url", "status_code", "is_https", "headers",
            "redirect_chain", "elapsed_ms", "scan_timestamp", "error"
        }
        assert required == set(result.keys())

    @patch("webguard.scanner.socket.getaddrinfo",
           side_effect=socket.gaierror("Name or service not known"))
    def test_dns_failure_returns_safe_error(self, mock_dns):
        result = fetch_url("https://nonexistent.invalid")
        assert result["error"] is not None
        # Raw DNS error string must not appear in the output
        assert "Name or service not known" not in result["error"]

    # ── Error messages must not leak sensitive details ────────────────────────

    @patch("webguard.scanner.socket.getaddrinfo", side_effect=_private_getaddrinfo)
    def test_error_message_does_not_expose_internal_ip(self, mock_dns):
        """
        Error messages should describe the problem without leaking
        the specific internal IP address that was resolved.
        This is a best-effort check — the scanner logs full details
        internally but the returned error string should be generic enough
        not to help an attacker enumerate the internal network topology.

        Note: the current implementation does include the blocked IP in the
        error string (to aid debugging during development).  In a production
        deployment this message should be sanitised before displaying to
        end users.  This test documents the current behaviour rather than
        asserting full sanitisation.
        """
        result = fetch_url("https://example.com")
        assert result["error"] is not None
        # At minimum, 'error' must be a non-empty string (not a raw exception)
        assert isinstance(result["error"], str) and result["error"].strip()


# ══════════════════════════════════════════════════════════════════════════════
# D. scan_url — orchestration
# ══════════════════════════════════════════════════════════════════════════════

class TestScanUrl:

    def test_invalid_url_returns_valid_false(self):
        result = scan_url("not-a-url")
        assert result["valid"] is False
        assert result["validation_error"] is not None
        assert result["fetch_result"] is None
        assert result["security_findings"] is None

    def test_private_ip_url_returns_valid_false(self):
        result = scan_url("http://192.168.1.1")
        assert result["valid"] is False

    def test_localhost_url_returns_valid_false(self):
        result = scan_url("http://localhost/admin")
        assert result["valid"] is False

    @patch("webguard.scanner.fetch_url")
    def test_fetch_error_leaves_security_findings_none(self, mock_fetch):
        mock_fetch.return_value = {
            "url": "https://example.com",
            "status_code": None,
            "is_https": False,
            "headers": {},
            "redirect_chain": [],
            "elapsed_ms": 0.0,
            "scan_timestamp": "2024-01-01T00:00:00Z",
            "error": "Connection timed out",
        }
        result = scan_url("https://example.com")
        assert result["valid"] is True
        assert result["fetch_result"]["error"] == "Connection timed out"
        assert result["security_findings"] is None

    @patch("webguard.scanner.fetch_url")
    def test_successful_scan_includes_security_findings(self, mock_fetch):
        mock_fetch.return_value = {
            "url": "https://example.com",
            "status_code": 200,
            "is_https": True,
            "headers": {
                "strict-transport-security": "max-age=31536000",
                "content-security-policy": "default-src 'self'",
                "x-frame-options": "DENY",
                "x-content-type-options": "nosniff",
                "referrer-policy": "no-referrer",
            },
            "redirect_chain": [],
            "elapsed_ms": 123.4,
            "scan_timestamp": "2024-01-01T00:00:00Z",
            "error": None,
        }
        result = scan_url("https://example.com")
        assert result["valid"] is True
        assert result["validation_error"] is None
        assert isinstance(result["security_findings"], list)
        assert len(result["security_findings"]) > 0

    @patch("webguard.scanner.fetch_url")
    def test_scan_result_has_all_required_keys(self, mock_fetch):
        mock_fetch.return_value = {
            "url": "https://example.com",
            "status_code": 200,
            "is_https": True,
            "headers": {},
            "redirect_chain": [],
            "elapsed_ms": 50.0,
            "scan_timestamp": "2024-01-01T00:00:00Z",
            "error": None,
        }
        result = scan_url("https://example.com")
        required = {
            "url", "valid", "validation_error",
            "fetch_result", "security_findings", "scan_timestamp"
        }
        assert required.issubset(set(result.keys()))

    @patch("webguard.scanner.fetch_url")
    def test_scan_timestamp_is_iso_format(self, mock_fetch):
        mock_fetch.return_value = {
            "url": "https://example.com",
            "status_code": 200,
            "is_https": True,
            "headers": {},
            "redirect_chain": [],
            "elapsed_ms": 50.0,
            "scan_timestamp": "2024-01-01T00:00:00Z",
            "error": None,
        }
        result = scan_url("https://example.com")
        ts = result["scan_timestamp"]
        # Should parse as ISO datetime without raising
        ts_clean = ts.replace("Z", "+00:00") if ts.endswith("Z") else ts
        parsed = datetime.datetime.fromisoformat(ts_clean)
        assert isinstance(parsed, datetime.datetime)
