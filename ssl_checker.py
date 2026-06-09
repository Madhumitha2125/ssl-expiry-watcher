"""
SSL Certificate Checker module.
Fetches SSL certificate expiry information for given domains.
"""

import ssl
import socket
from datetime import datetime, timezone
from typing import Dict

from config import SSL_TIMEOUT_SECONDS, SAFE_THRESHOLD, WARNING_THRESHOLD


def get_ssl_expiry(domain: str) -> Dict[str, object]:
    """
    Connect to *domain* on port 443 and return certificate expiry info.

    Returns a dict with keys:
        domain, expiry_date, days_left, status, error
    """
    result: Dict[str, object] = {
        "domain": domain.strip().lower(),
        "expiry_date": None,
        "days_left": None,
        "status": "ERROR",
        "error": None,
    }

    clean_domain = result["domain"]
    if not clean_domain:
        result["error"] = "Empty domain"
        return result

    # Strip protocol prefixes if user accidentally included them
    for prefix in ("https://", "http://"):
        if clean_domain.startswith(prefix):
            clean_domain = clean_domain[len(prefix):]
    clean_domain = clean_domain.rstrip("/").split("/")[0]  # remove paths
    result["domain"] = clean_domain

    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((clean_domain, 443), timeout=SSL_TIMEOUT_SECONDS) as sock:
            with ctx.wrap_socket(sock, server_hostname=clean_domain) as tls:
                cert = tls.getpeercert()

        if cert is None:
            result["error"] = "No certificate returned"
            return result

        # Parse expiry date
        expiry_str: str = cert["notAfter"]  # e.g. "Sep 15 12:00:00 2025 GMT"
        expiry_dt = datetime.strptime(expiry_str, "%b %d %H:%M:%S %Y %Z").replace(
            tzinfo=timezone.utc
        )

        days_left = (expiry_dt - datetime.now(timezone.utc)).days

        result["expiry_date"] = expiry_dt.strftime("%Y-%m-%d %H:%M:%S UTC")
        result["days_left"] = days_left
        result["status"] = _classify(days_left)

    except socket.timeout:
        result["error"] = "Connection timed out"
    except socket.gaierror:
        result["error"] = "DNS resolution failed — invalid domain"
    except ssl.SSLCertVerificationError as exc:
        result["error"] = f"SSL verification error: {exc}"
    except ssl.SSLError as exc:
        result["error"] = f"SSL error: {exc}"
    except ConnectionRefusedError:
        result["error"] = "Connection refused (port 443)"
    except OSError as exc:
        result["error"] = f"Network error: {exc}"

    return result


def scan_domains(domains: list[str]) -> list[Dict[str, object]]:
    """Scan a list of domain strings and return results."""
    results = []
    for domain in domains:
        d = domain.strip()
        if d:
            results.append(get_ssl_expiry(d))
    return results


# ── private helpers ─────────────────────────────────────────────────────

def _classify(days_left: int) -> str:
    if days_left > SAFE_THRESHOLD:
        return "SAFE"
    elif days_left >= WARNING_THRESHOLD:
        return "WARNING"
    else:
        return "CRITICAL"
