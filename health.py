"""Dependency and public-provider connectivity checks."""
from __future__ import annotations
from typing import Any


def check_dependencies() -> dict[str, bool]:
    try:
        import requests  # noqa: F401
        has_requests = True
    except ImportError:
        has_requests = False
    try:
        import phonenumbers  # noqa: F401
        has_phone = True
    except ImportError:
        has_phone = False
    try:
        import dns.resolver  # noqa: F401
        has_dns = True
    except ImportError:
        has_dns = False
    return {"requests": has_requests, "phonenumbers": has_phone, "dnspython": has_dns}


def check_github_api(timeout: float = 5.0) -> dict[str, Any]:
    try:
        import requests
    except ImportError:
        return {"provider": "GitHub API", "ok": False, "detail": "requests is not installed"}
    try:
        response = requests.get(
            "https://api.github.com/rate_limit",
            headers={"Accept": "application/vnd.github+json", "User-Agent": "MR-OSINT-health-check"},
            timeout=timeout,
        )
        return {
            "provider": "GitHub API",
            "ok": response.status_code == 200,
            "detail": f"HTTP {response.status_code}",
        }
    except requests.RequestException as exc:
        return {"provider": "GitHub API", "ok": False, "detail": str(exc)}


def run_health_check() -> dict[str, Any]:
    return {"dependencies": check_dependencies(), "providers": [check_github_api()]}
