"""Opt-in exports for candidate reports based on volunteered public links."""
from __future__ import annotations
import csv
import json
from pathlib import Path
from typing import Any


def build_candidate_payload(name: str, github: dict[str, Any] | None, github_error: str | None,
                            portfolio_url: str | None, portfolio_result: tuple | None,
                            certificates: list[tuple[str, tuple]]) -> dict[str, Any]:
    portfolio = None
    if portfolio_url and portfolio_result:
        portfolio = {
            "url": portfolio_url,
            "reachable": bool(portfolio_result[0]),
            "status": portfolio_result[1],
            "title": portfolio_result[2],
        }
    return {
        "candidate_name": name,
        "github": github if github else {"error": github_error},
        "portfolio": portfolio,
        "certificates": [
            {"url": url, "reachable": bool(result[0]), "status": result[1], "title": result[2]}
            for url, result in certificates
        ],
    }


def write_json(payload: dict[str, Any], destination: str | Path) -> None:
    Path(destination).write_text(json.dumps(payload, indent=2, ensure_ascii=False, default=str), encoding="utf-8")


def write_csv(payload: dict[str, Any], destination: str | Path) -> None:
    with open(destination, "w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=["kind", "url", "status", "title", "details"])
        writer.writeheader()
        github = payload.get("github") or {}
        if github.get("profile_url"):
            writer.writerow({
                "kind": "github", "url": github.get("profile_url"),
                "status": "public profile returned", "title": github.get("name") or "",
                "details": f"public repositories={github.get('public_repos', '')}",
            })
        elif github.get("error"):
            writer.writerow({"kind": "github", "status": "unavailable", "details": github["error"]})
        portfolio = payload.get("portfolio")
        if portfolio:
            writer.writerow({
                "kind": "portfolio", "url": portfolio["url"],
                "status": "reachable" if portfolio["reachable"] else "not reachable",
                "title": portfolio.get("title") or "", "details": str(portfolio.get("status", "")),
            })
        for item in payload.get("certificates", []):
            writer.writerow({
                "kind": "certificate link", "url": item["url"],
                "status": "reachable" if item["reachable"] else "not reachable",
                "title": item.get("title") or "", "details": str(item.get("status", "")),
            })
