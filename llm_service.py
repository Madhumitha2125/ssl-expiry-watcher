"""
LLM Service — AI-powered risk report generation.

Execution order:
    1. Groq (primary)      — llama3-70b-8192
    2. OpenRouter (backup)  — meta-llama/llama-3.1-8b-instruct
    3. Rule-based fallback  — always succeeds
"""

from typing import Dict, List

import requests
from groq import Groq

from config import (
    GROQ_API_KEY,
    GROQ_MODEL,
    OPENROUTER_API_KEY,
    OPENROUTER_MODEL,
)

# ── System Prompt ───────────────────────────────────────────────────────
_SYSTEM_PROMPT = (
    "You are a senior DevOps security analyst. "
    "Given SSL certificate scan data, produce a concise professional report with:\n"
    "1. **Risk Analysis** — severity breakdown per domain.\n"
    "2. **Incident Summary** — highlight any critical or warning certificates.\n"
    "3. **Action Recommendations** — concrete next steps for the ops team.\n"
    "Use markdown formatting. Be direct and actionable."
)


import hashlib
from database import get_cached_report, cache_report

def generate_report(scan_results: List[Dict[str, object]]) -> Dict[str, str]:
    """
    Generate an AI risk report from scan results.
    Checks cache first.

    Returns dict: {"source": ..., "report": ...}
    """
    user_prompt = _build_user_prompt(scan_results)
    
    # Check cache based on input data
    report_hash = hashlib.md5(user_prompt.encode('utf-8')).hexdigest()
    cached = get_cached_report(report_hash)
    if cached:
        return cached

    report_data = None

    # ── Step 1: Groq (primary) ─────────────────────────────────────────
    report = _try_groq(user_prompt)
    if report:
        report_data = {"source": "Groq (Primary LLM)", "report": report}

    # ── Step 2: OpenRouter (backup) ────────────────────────────────────
    if not report_data:
        report = _try_openrouter(user_prompt)
        if report:
            report_data = {"source": "OpenRouter (Backup LLM)", "report": report}

    # ── Step 3: Rule-based fallback ────────────────────────────────────
    if not report_data:
        report_data = {
            "source": "Rule-Based Fallback (Safe Mode)",
            "report": _rule_based_fallback(scan_results),
        }
        
    # Save to cache
    cache_report(report_hash, report_data["report"], report_data["source"])
    return report_data


# ── Private helpers ─────────────────────────────────────────────────────


def _build_user_prompt(results: List[Dict[str, object]]) -> str:
    lines = ["SSL Certificate Scan Results:\n"]
    for r in results:
        days = r.get("days_left", "N/A")
        status = r.get("status", "UNKNOWN")
        error = r.get("error")
        line = f"- {r['domain']}: expires {r.get('expiry_date', 'N/A')}, {days} days left, status={status}"
        if error:
            line += f" (error: {error})"
        lines.append(line)
    lines.append("\nPlease provide a risk analysis, incident summary, and action recommendations.")
    return "\n".join(lines)


def _try_groq(user_prompt: str) -> str | None:
    """Attempt generation via Groq SDK."""
    if not GROQ_API_KEY:
        return None
    try:
        client = Groq(api_key=GROQ_API_KEY)
        response = client.chat.completions.create(
            model=GROQ_MODEL,
            messages=[
                {"role": "system", "content": _SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ],
            temperature=0.4,
            max_tokens=2048,
        )
        text = response.choices[0].message.content
        return text if text and text.strip() else None
    except Exception:
        return None


def _try_openrouter(user_prompt: str) -> str | None:
    """Attempt generation via OpenRouter REST API."""
    if not OPENROUTER_API_KEY:
        return None
    try:
        resp = requests.post(
            "https://openrouter.ai/api/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {OPENROUTER_API_KEY}",
                "Content-Type": "application/json",
                "HTTP-Referer": "https://ssl-expiry-watcher.onrender.com",
                "X-Title": "SSL Expiry Watcher",
            },
            json={
                "model": OPENROUTER_MODEL,
                "messages": [
                    {"role": "system", "content": _SYSTEM_PROMPT},
                    {"role": "user", "content": user_prompt},
                ],
                "temperature": 0.4,
                "max_tokens": 2048,
            },
            timeout=30,
        )
        resp.raise_for_status()
        data = resp.json()
        text = data["choices"][0]["message"]["content"]
        return text if text and text.strip() else None
    except Exception:
        return None


def _rule_based_fallback(results: List[Dict[str, object]]) -> str:
    """Deterministic fallback that always produces a professional report."""
    critical = []
    warning = []
    safe = []
    errors = []

    for r in results:
        domain = r["domain"]
        days = r.get("days_left")
        error = r.get("error")

        if error:
            errors.append(f"- **{domain}** — {error}")
            continue

        if days is None:
            errors.append(f"- **{domain}** — unable to determine expiry")
            continue

        if days <= 3:
            critical.append(f"- 🔴 **{domain}** — expires in **{days} day(s)** — IMMEDIATE ACTION REQUIRED")
        elif days <= 10:
            warning.append(f"- 🟡 **{domain}** — expires in **{days} day(s)** — schedule renewal soon")
        else:
            safe.append(f"- 🟢 **{domain}** — expires in **{days} day(s)** — no action needed")

    sections = ["# 🔒 SSL Certificate Risk Report\n"]
    sections.append(f"_Generated by rule-based analysis engine_\n")

    # Risk Analysis
    sections.append("## 📊 Risk Analysis\n")
    total = len(results)
    sections.append(f"| Metric | Count |\n|--------|-------|\n"
                     f"| Total Domains Scanned | {total} |\n"
                     f"| 🔴 Critical | {len(critical)} |\n"
                     f"| 🟡 Warning | {len(warning)} |\n"
                     f"| 🟢 Safe | {len(safe)} |\n"
                     f"| ⚠️ Errors | {len(errors)} |\n")

    # Incident Summary
    sections.append("## 🚨 Incident Summary\n")
    if critical:
        sections.append("### Critical Alerts\n" + "\n".join(critical) + "\n")
    if warning:
        sections.append("### Warnings\n" + "\n".join(warning) + "\n")
    if errors:
        sections.append("### Scan Errors\n" + "\n".join(errors) + "\n")
    if not (critical or warning or errors):
        sections.append("✅ No incidents detected. All certificates are healthy.\n")

    # Recommendations
    sections.append("## ✅ Action Recommendations\n")
    if critical:
        sections.append("1. **URGENT** — Renew critical certificates within 24 hours.\n"
                         "2. Verify DNS and hosting configurations for affected domains.\n"
                         "3. Set up automated renewal (e.g., Let's Encrypt + certbot).\n")
    if warning:
        sections.append("1. Schedule certificate renewals for warning domains within the next 7 days.\n"
                         "2. Review certificate providers for auto-renewal capability.\n")
    if errors:
        sections.append("1. Investigate scan errors — check DNS, firewall, and port 443 accessibility.\n")
    if safe and not (critical or warning or errors):
        sections.append("No immediate action required. Continue routine monitoring.\n")

    return "\n".join(sections)
