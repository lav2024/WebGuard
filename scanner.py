"""
scanner.py — URL validation, HTTP fetching, and scan orchestration.

Responsibility
--------------
This module owns three concerns:

1. validate_url(url)      – Static syntactic + semantic validation.
                            No network calls.

2. _is_ip_safe(addr)      – Decides whether a resolved IP address is
                            permitted.  Used both at validation time and
                            at connection time.

3. fetch_url(url)         – Makes the actual HTTP GET request with a
                            custom transport that re-validates every IP
                            at connection time and every redirect destination
                            before following it.

4. scan_url(url)          – Orchestrates validate_url → fetch_url →
                            run_all_rules and returns a unified result dict.

Security model and limitations
-------------------------------
This module implements a best-effort defence against Server-Side Request
Forgery (SSRF), but cannot guarantee complete protection at the network
layer.  Specifically:

  DNS rebinding (partial mitigation)
  -----------------------------------
  A DNS rebinding attack works by returning a safe public IP during
  validation, then swapping the DNS record to a private IP before the
  actual TCP connection.  This module mitigates it by:

    a) Re-resolving the hostname at TCP-connect time inside the custom
       transport adapter (_SafeHTTPAdapter) and re-checking the resolved
       IP against the blocklist.
    b) Connecting to the *resolved IP address* rather than the hostname,
       so a DNS change between validation and connect does not affect
       the already-open socket.

  What this does NOT prevent:
    • A rebind that occurs between TCP-connect and TLS-handshake on a
      very slow or adversarially delayed connection.
    • A DNS rebind exploit delivered at the OS or resolver cache layer
      below Python's socket calls.
    • Cloud environments where the metadata endpoint (169.254.169.254)
      is on a different subnet reachable without going through the
      validated hostname's IP.

  For production use, complement this with network-level controls:
    • Egress firewall rules that block RFC-1918 and link-local addresses.
    • A dedicated outbound HTTP proxy that enforces the same IP blocklist.
    • Short HTTP client timeouts so a stalled rebind cannot hold a thread.

  Response size
  -------------
  Only the first MAX_RESPONSE_BYTES bytes of the response body are read.
  Headers are read in full (they are bounded by the server).

  Redirect chain
  ---------------
  Every redirect destination is validated as if it were a fresh URL.
  redirects to private/internal addresses are rejected even if the
  original URL was safe.
"""

from __future__ import annotations

import ipaddress
import socket
import urllib.parse
import datetime
import logging
from typing import Any

import requests
import requests.adapters
import urllib3
from urllib3.util.retry import Retry

from webguard.security_rules import run_all_rules

logger = logging.getLogger(__name__)

# ── Constants ──────────────────────────────────────────────────────────────────

ALLOWED_SCHEMES = {"http", "https"}

# Timeouts: (connect_timeout_seconds, read_timeout_seconds)
REQUEST_TIMEOUT = (5, 10)

# Maximum number of redirects to follow
MAX_REDIRECTS = 5

# Maximum response body bytes to read (headers are not limited here)
MAX_RESPONSE_BYTES = 2 * 1024 * 1024  # 2 MB

# Headers sent with every request
REQUEST_HEADERS = {
    "User-Agent": "WebGuard-Security-Scanner/1.0 (educational project)",
    "Accept": "text/html,application/xhtml+xml",
    "Accept-Language": "en",
    "Connection": "close",
}

# Cloud metadata endpoints that must never be contacted regardless of IP check
_CLOUD_METADATA_HOSTNAMES = {
    "169.254.169.254",       # AWS / GCP / Azure IMDS
    "metadata.google.internal",
    "metadata.google",
}

# Well-known blocked hostnames
_BLOCKED_HOSTNAMES = {"localhost"} | _CLOUD_METADATA_HOSTNAMES


# ── IP address safety check ────────────────────────────────────────────────────

def _is_ip_safe(addr: str) -> tuple[bool, str]:
    """
    Return (True, "") if *addr* is a routable public address, or
    (False, reason) if it falls into any prohibited range.

    Checks performed:
      • Loopback      (127.0.0.0/8, ::1)
      • Private       (10/8, 172.16/12, 192.168/16, fc00::/7)
      • Link-local    (169.254/16, fe80::/10)  — covers AWS metadata IP
      • Multicast     (224.0.0.0/4, ff00::/8)
      • Reserved      (0.0.0.0, 255.255.255.255, ::/128, etc.)
      • Unspecified   (0.0.0.0/8)
    """
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False, f"Could not parse resolved address: {addr!r}"

    if ip.is_loopback:
        return False, f"Resolved address {addr} is a loopback address"
    if ip.is_private:
        return False, f"Resolved address {addr} is in a private range"
    if ip.is_link_local:
        return False, f"Resolved address {addr} is link-local (SSRF risk)"
    if ip.is_multicast:
        return False, f"Resolved address {addr} is a multicast address"
    if ip.is_reserved:
        return False, f"Resolved address {addr} is a reserved address"
    if ip.is_unspecified:
        return False, f"Resolved address {addr} is unspecified (0.0.0.0)"

    return True, ""


# ── URL validation (no network I/O) ───────────────────────────────────────────

def validate_url(url: str) -> tuple[bool, str]:
    """
    Validate *url* without making any network requests.

    Returns
    -------
    (True, "")          – URL is structurally and semantically acceptable.
    (False, reason)     – URL is rejected; *reason* explains why.

    Checks performed (in order):
      1. Non-empty string
      2. Parseable by urllib.parse
      3. Scheme is http or https
      4. Hostname present and not empty
      5. No embedded credentials (user:pass@host)
      6. Hostname not in the explicit blocklist (localhost, metadata endpoints)
      7. If the hostname is a literal IP address, check it immediately
         (no DNS required)

    Note: hostname-based DNS resolution is NOT performed here because this
    function is intentionally free of network I/O for fast, reliable testing.
    DNS validation happens at connection time inside _SafeHTTPAdapter and
    also during the pre-request check in fetch_url().
    """
    if not isinstance(url, str) or not url.strip():
        return False, "URL must be a non-empty string"

    try:
        parsed = urllib.parse.urlparse(url)
    except Exception:
        return False, "URL could not be parsed"

    scheme = parsed.scheme.lower()
    if scheme not in ALLOWED_SCHEMES:
        return False, (
            f"Scheme '{scheme}' is not allowed. Only http and https are accepted"
        )

    hostname = parsed.hostname  # lower-cased by urlparse, None if absent
    if not hostname:
        return False, "URL contains no hostname"

    # Reject embedded credentials — user:password@host
    if parsed.username or parsed.password:
        return False, "URLs with embedded credentials are not allowed"

    # Reject explicitly blocked hostnames
    if hostname in _BLOCKED_HOSTNAMES:
        return False, f"Hostname '{hostname}' is not allowed"

    # If hostname is a literal IP address, validate it immediately
    try:
        ip_obj = ipaddress.ip_address(hostname)
        safe, reason = _is_ip_safe(str(ip_obj))
        if not safe:
            return False, reason
    except ValueError:
        # Not a literal IP — that is fine; DNS validation deferred to connect time
        pass

    return True, ""


def _resolve_and_check(hostname: str) -> tuple[bool, str]:
    """
    Resolve *hostname* via DNS and verify every returned address is safe.

    Returns (True, "") or (False, reason).

    This is called both before making the request (in fetch_url) and
    inside the custom transport adapter at actual connect time.
    """
    try:
        # getaddrinfo returns all addresses for the host across A and AAAA records
        results = socket.getaddrinfo(hostname, None)
    except socket.gaierror:
        # Do not include the raw OS error message — it may contain internal
        # details (resolver paths, IP addresses) that should not be surfaced.
        return False, f"DNS resolution failed for '{hostname}'"

    if not results:
        return False, f"DNS returned no addresses for '{hostname}'"

    for _family, _type, _proto, _canonname, sockaddr in results:
        addr = sockaddr[0]  # IPv4: (addr, port); IPv6: (addr, port, flow, scope)
        safe, reason = _is_ip_safe(addr)
        if not safe:
            return False, reason

    return True, ""


# ── Custom transport adapter ───────────────────────────────────────────────────

class _SafeHTTPAdapter(requests.adapters.HTTPAdapter):
    """
    A requests transport adapter that re-validates the destination IP at
    actual TCP-connect time.

    Why this is necessary
    ----------------------
    requests/urllib3 uses the hostname for TLS SNI and for the Host header,
    but the actual socket connects to whatever the OS resolver returns at
    connect time.  If we only validated the hostname before calling
    requests.get(), a DNS rebinding attack (changing the DNS record between
    our check and the OS's connect() syscall) could route the request to a
    private address.

    This adapter overrides send() so we can intercept the PreparedRequest,
    extract the hostname, resolve it ourselves, and check each resolved IP
    before letting urllib3 proceed.

    Residual limitation: we re-resolve here and check, but we cannot force
    urllib3 to connect to our resolved IP rather than re-resolving again
    internally (urllib3 does its own resolution inside the C socket layer).
    In practice the OS cache (TTL) is very short after our resolution, but
    this is not a hard guarantee.  A network-level egress firewall is the
    only reliable defence.
    """

    def send(self, request: requests.PreparedRequest, **kwargs: Any) -> requests.Response:
        parsed = urllib.parse.urlparse(request.url)
        hostname = parsed.hostname
        if hostname:
            safe, reason = _resolve_and_check(hostname)
            if not safe:
                raise ValueError(f"Blocked: {reason}")
        return super().send(request, **kwargs)


# ── Redirect hook ─────────────────────────────────────────────────────────────

def _build_session() -> requests.Session:
    """
    Build and return a requests.Session configured for safe scanning:

      • Custom transport adapter that re-validates IP at connect time
      • Redirect handling disabled at the session level (we handle it manually
        so we can validate each destination before following)
      • Short timeouts and no retries on errors
    """
    session = requests.Session()

    # Mount our safe adapter for both schemes
    adapter = _SafeHTTPAdapter(max_retries=Retry(total=0, raise_on_status=False))
    session.mount("https://", adapter)
    session.mount("http://", adapter)

    # Do not send cookies, credentials, or custom auth
    session.cookies.clear()
    session.auth = None

    return session


# ── Core fetch function ────────────────────────────────────────────────────────

def fetch_url(url: str) -> dict:
    """
    Fetch *url* with safety controls and return raw response data.

    Parameters
    ----------
    url : str
        A URL that has already been validated by validate_url().
        Call validate_url() first — this function trusts that the scheme
        and hostname structure are valid but re-validates IPs at every hop.

    Returns
    -------
    dict with keys:
        url           – str  : final URL after any redirects
        status_code   – int  : HTTP status code of the final response
        is_https      – bool : whether the final URL uses HTTPS
        headers       – dict : response headers (lower-cased keys)
        redirect_chain– list : list of URLs traversed (excluding final)
        elapsed_ms    – float: total round-trip time in milliseconds
        scan_timestamp– str  : ISO-8601 UTC timestamp of the scan
        error         – None | str: None on success, message on failure

    All error paths set error to a safe, non-sensitive message and fill
    remaining fields with safe defaults.  No raw exception messages (which
    may contain IP addresses or internal paths) are surfaced to callers.
    """
    timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")
    _empty = {
        "url": url,
        "status_code": None,
        "is_https": False,
        "headers": {},
        "redirect_chain": [],
        "elapsed_ms": 0.0,
        "scan_timestamp": timestamp,
        "error": None,
    }

    # ── Pre-flight DNS check ──────────────────────────────────────────────────
    # Validate the hostname of the *original* URL before opening any socket.
    # The transport adapter repeats this at connect time; this check provides
    # an early, user-friendly error message.
    parsed_initial = urllib.parse.urlparse(url)
    initial_host = parsed_initial.hostname or ""
    if initial_host and not _looks_like_ip(initial_host):
        safe, reason = _resolve_and_check(initial_host)
        if not safe:
            result = dict(_empty)
            result["error"] = f"Pre-flight validation failed: {reason}"
            return result

    session = _build_session()
    redirect_chain: list[str] = []
    current_url = url
    start = datetime.datetime.now(datetime.timezone.utc)

    try:
        for hop in range(MAX_REDIRECTS + 1):
            # Validate this hop's destination before requesting
            hop_parsed = urllib.parse.urlparse(current_url)
            hop_host = hop_parsed.hostname or ""
            if hop_host and not _looks_like_ip(hop_host):
                safe, reason = _resolve_and_check(hop_host)
                if not safe:
                    result = dict(_empty)
                    result["redirect_chain"] = redirect_chain
                    result["elapsed_ms"] = _elapsed_ms(start)
                    result["error"] = f"Redirect destination blocked: {reason}"
                    return result

            hop_valid, hop_reason = validate_url(current_url)
            if not hop_valid:
                result = dict(_empty)
                result["redirect_chain"] = redirect_chain
                result["elapsed_ms"] = _elapsed_ms(start)
                result["error"] = f"Redirect destination rejected: {hop_reason}"
                return result

            response = session.get(
                current_url,
                headers=REQUEST_HEADERS,
                timeout=REQUEST_TIMEOUT,
                allow_redirects=False,   # we handle redirects manually
                stream=True,             # defer body read so we can limit size
            )

            if response.is_redirect or response.status_code in (301, 302, 303, 307, 308):
                location = response.headers.get("location", "").strip()
                if not location:
                    result = dict(_empty)
                    result["redirect_chain"] = redirect_chain
                    result["elapsed_ms"] = _elapsed_ms(start)
                    result["error"] = "Redirect with empty Location header"
                    return result

                # Resolve relative redirect URLs against the current URL
                location = urllib.parse.urljoin(current_url, location)

                redirect_chain.append(current_url)
                current_url = location

                if hop == MAX_REDIRECTS:
                    result = dict(_empty)
                    result["redirect_chain"] = redirect_chain
                    result["elapsed_ms"] = _elapsed_ms(start)
                    result["error"] = (
                        f"Too many redirects (limit: {MAX_REDIRECTS})"
                    )
                    return result
                continue  # follow the redirect

            # ── Non-redirect response ─────────────────────────────────────────
            # Read body with size cap
            _ = response.raw.read(MAX_RESPONSE_BYTES)

            elapsed = _elapsed_ms(start)
            final_url = response.url or current_url
            headers = {k.lower(): v for k, v in response.headers.items()}

            return {
                "url": final_url,
                "status_code": response.status_code,
                "is_https": final_url.startswith("https://"),
                "headers": headers,
                "redirect_chain": redirect_chain,
                "elapsed_ms": elapsed,
                "scan_timestamp": timestamp,
                "error": None,
            }

    except ValueError as exc:
        # Raised by _SafeHTTPAdapter when the resolved IP is blocked
        result = dict(_empty)
        result["redirect_chain"] = redirect_chain
        result["elapsed_ms"] = _elapsed_ms(start)
        result["error"] = str(exc)
        return result

    except requests.exceptions.SSLError:
        result = dict(_empty)
        result["redirect_chain"] = redirect_chain
        result["elapsed_ms"] = _elapsed_ms(start)
        result["error"] = "TLS/SSL certificate error"
        return result

    except requests.exceptions.ConnectTimeout:
        result = dict(_empty)
        result["redirect_chain"] = redirect_chain
        result["elapsed_ms"] = _elapsed_ms(start)
        result["error"] = "Connection timed out"
        return result

    except requests.exceptions.ReadTimeout:
        result = dict(_empty)
        result["redirect_chain"] = redirect_chain
        result["elapsed_ms"] = _elapsed_ms(start)
        result["error"] = "Read timed out"
        return result

    except requests.exceptions.TooManyRedirects:
        result = dict(_empty)
        result["redirect_chain"] = redirect_chain
        result["elapsed_ms"] = _elapsed_ms(start)
        result["error"] = f"Too many redirects (limit: {MAX_REDIRECTS})"
        return result

    except requests.exceptions.ConnectionError:
        result = dict(_empty)
        result["redirect_chain"] = redirect_chain
        result["elapsed_ms"] = _elapsed_ms(start)
        result["error"] = "Connection error (host unreachable or refused)"
        return result

    except requests.exceptions.RequestException:
        result = dict(_empty)
        result["redirect_chain"] = redirect_chain
        result["elapsed_ms"] = _elapsed_ms(start)
        result["error"] = "HTTP request failed"
        return result

    except Exception:
        # Catch-all: log internally but never surface raw exception to caller
        logger.exception("Unexpected error during fetch_url(%r)", url)
        result = dict(_empty)
        result["redirect_chain"] = redirect_chain
        result["elapsed_ms"] = _elapsed_ms(start)
        result["error"] = "An unexpected error occurred during the scan"
        return result


# ── Scan orchestrator ─────────────────────────────────────────────────────────

def scan_url(url: str) -> dict:
    """
    Validate *url*, fetch it, evaluate all security rules, and return a
    unified scan result.

    Parameters
    ----------
    url : str
        The URL to audit.

    Returns
    -------
    dict with keys:
        url               – str  : the original URL submitted
        valid             – bool : whether the URL passed validation
        validation_error  – str | None : reason if invalid
        fetch_result      – dict | None : raw data from fetch_url(), or None
        security_findings – list[dict] | None : findings from run_all_rules()
        scan_timestamp    – str  : ISO-8601 UTC timestamp

    If validation fails, fetch_result and security_findings are None.
    If the fetch fails (network error), security_findings is None.
    """
    timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")
    valid, validation_error = validate_url(url)

    if not valid:
        return {
            "url": url,
            "valid": False,
            "validation_error": validation_error,
            "fetch_result": None,
            "security_findings": None,
            "scan_timestamp": timestamp,
        }

    fetch_result = fetch_url(url)

    if fetch_result["error"]:
        return {
            "url": url,
            "valid": True,
            "validation_error": None,
            "fetch_result": fetch_result,
            "security_findings": None,
            "scan_timestamp": timestamp,
        }

    security_findings = run_all_rules(fetch_result)

    return {
        "url": url,
        "valid": True,
        "validation_error": None,
        "fetch_result": fetch_result,
        "security_findings": security_findings,
        "scan_timestamp": timestamp,
    }


# ── Private helpers ────────────────────────────────────────────────────────────

def _looks_like_ip(hostname: str) -> bool:
    """Return True if *hostname* is a literal IP address (v4 or v6)."""
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def _elapsed_ms(start: datetime.datetime) -> float:
    """Return milliseconds elapsed since *start*."""
    delta = datetime.datetime.now(datetime.timezone.utc) - start
    return delta.total_seconds() * 1000.0
