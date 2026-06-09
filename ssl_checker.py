"""
SSL Certificate Checker module.
Fetches SSL certificate expiry information for given domains.
"""

import ssl
import socket
from datetime import datetime, timezone
from typing import Dict

from config import SSL_TIMEOUT_SECONDS, SAFE_THRESHOLD, WARNING_THRESHOLD


def _parse_rdn(rdns) -> str:
    """Helper to extract commonName or organizationName from certificate RDNs."""
    if not rdns:
        return "Unknown"
    cn = None
    o = None
    for rdn in rdns:
        for attr in rdn:
            if isinstance(attr, tuple) and len(attr) == 2:
                key, val = attr
                if key == "commonName":
                    cn = val
                elif key == "organizationName":
                    o = val
    if cn and o:
        return f"{cn} ({o})"
    return cn or o or "Unknown"


def get_ssl_expiry(domain: str) -> Dict[str, object]:
    """
    Connect to *domain* on port 443 and return certificate expiry info.
    Tries verified connection first, fallbacks to unverified context to get cert info on validation error.

    Returns a dict with keys:
        domain, expiry_date, days_left, status, error, issuer, subject, serial_number, is_valid
    """
    result: Dict[str, object] = {
        "domain": domain.strip().lower(),
        "expiry_date": None,
        "days_left": None,
        "status": "ERROR",
        "error": None,
        "issuer": None,
        "subject": None,
        "serial_number": None,
        "is_valid": False,
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

    cert = None
    verification_error = None

    # Stage 1: Try with default verified context
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((clean_domain, 443), timeout=SSL_TIMEOUT_SECONDS) as sock:
            with ctx.wrap_socket(sock, server_hostname=clean_domain) as tls:
                cert = tls.getpeercert()
        if cert:
            result["is_valid"] = True
    except ssl.SSLCertVerificationError as exc:
        verification_error = f"SSL verification error: {exc}"
    except ssl.SSLError as exc:
        verification_error = f"SSL error: {exc}"
    except socket.timeout:
        result["error"] = "Connection timed out"
        return result
    except socket.gaierror:
        result["error"] = "DNS resolution failed — invalid domain"
        return result
    except ConnectionRefusedError:
        result["error"] = "Connection refused (port 443)"
        return result
    except OSError as exc:
        result["error"] = f"Network error: {exc}"
        return result

    # Stage 2: If validation failed but connection was possible, retry unverified
    if not cert:
        try:
            ctx_unverified = ssl._create_unverified_context()
            with socket.create_connection((clean_domain, 443), timeout=SSL_TIMEOUT_SECONDS) as sock:
                with ctx_unverified.wrap_socket(sock, server_hostname=clean_domain) as tls:
                    cert = tls.getpeercert()
            result["error"] = verification_error or "Certificate validation failed"
        except Exception as exc:
            result["error"] = verification_error or f"SSL Handshake failed: {exc}"
            return result

    # Stage 3: Parse certificate details
    if cert:
        try:
            # Parse expiry date
            expiry_str: str = cert.get("notAfter", "")
            if expiry_str:
                expiry_dt = datetime.strptime(expiry_str, "%b %d %H:%M:%S %Y %Z").replace(
                    tzinfo=timezone.utc
                )
                days_left = (expiry_dt - datetime.now(timezone.utc)).days
                result["expiry_date"] = expiry_dt.strftime("%Y-%m-%d %H:%M:%S UTC")
                result["days_left"] = days_left
                
                if result["is_valid"]:
                    result["status"] = _classify(days_left)
                else:
                    # Invalid or Expired
                    result["status"] = "CRITICAL" if days_left < 0 else "WARNING"
            else:
                result["error"] = result["error"] or "No expiration date in certificate"
        except Exception as exc:
            result["error"] = f"Error parsing certificate date: {exc}"

        # Parse Issuer, Subject, Serial Number
        result["issuer"] = _parse_rdn(cert.get("issuer"))
        result["subject"] = _parse_rdn(cert.get("subject"))
        result["serial_number"] = cert.get("serialNumber")

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
