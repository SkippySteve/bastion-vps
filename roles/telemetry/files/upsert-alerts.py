#!/usr/bin/env python3
"""Create or update SigNoz alert rules from a JSON document."""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any


class AlertError(RuntimeError):
    def __init__(self, message: str, status: int | None = None):
        super().__init__(message)
        self.status = status


def request(url: str, method: str, token: str, payload: Any | None = None) -> Any:
    data = None
    headers = {
        "Accept": "application/json",
        "SIGNOZ-API-KEY": token,
    }
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=60) as response:
            body = response.read().decode("utf-8")
            return json.loads(body) if body.strip() else {}
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise AlertError(f"{method} {url} returned {exc.code}: {detail[:800]}", status=exc.code) from exc


def list_rules(base: str, token: str) -> list[dict[str, Any]]:
    payload = request(f"{base}/api/v2/rules", "GET", token)
    data = payload.get("data", payload)
    if isinstance(data, dict):
        for key in ("rules", "data"):
            if isinstance(data.get(key), list):
                return data[key]
        return []
    if isinstance(data, list):
        return data
    return []


def rule_id(rule: dict[str, Any]) -> str | None:
    for key in ("id", "ruleId", "rule_id"):
        if rule.get(key):
            return str(rule[key])
    return None


def rule_name(rule: dict[str, Any]) -> str:
    return str(rule.get("alert") or rule.get("alertName") or "")


def upsert(base: str, token: str, wanted: list[dict[str, Any]]) -> int:
    existing = {rule_name(item): item for item in list_rules(base, token) if rule_name(item)}
    changed = 0
    for spec in wanted:
        name = spec["alert"]
        current = existing.get(name)
        if current is None:
            request(f"{base}/api/v2/rules", "POST", token, spec)
            changed += 1
            print(f"created {name}")
            continue
        ident = rule_id(current)
        if not ident:
            print(f"skip {name}: existing rule has no id")
            continue
        request(f"{base}/api/v2/rules/{ident}", "PUT", token, spec)
        changed += 1
        print(f"updated {name}")
    return changed


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rules", required=True)
    parser.add_argument("--url", default="http://127.0.0.1:18080")
    parser.add_argument("--token-file", required=True)
    parser.add_argument("--validate-only", action="store_true")
    args = parser.parse_args()
    document = json.loads(Path(args.rules).read_text(encoding="utf-8"))
    rules = document.get("rules") if isinstance(document, dict) else document
    if not isinstance(rules, list) or not rules:
        raise AlertError("alerts document must contain a rules list")
    for spec in rules:
        if not spec.get("alert"):
            raise AlertError("every alert needs an alert name")
    if args.validate_only:
        print(f"validated {len(rules)} SigNoz alert rules")
        return 0
    token = Path(args.token_file).read_text(encoding="utf-8").strip()
    if not token:
        raise AlertError("API token file is empty")
    upsert(args.url.rstrip("/"), token, rules)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except AlertError as exc:
        print(exc, file=sys.stderr)
        sys.exit(2)
