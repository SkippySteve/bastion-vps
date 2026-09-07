#!/usr/bin/env python3
"""Publish platform Sigma rules to the Wazuh 5 Content Manager and prove them with logtest."""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import re
import ssl
import stat
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

RULE_FIELDS = (
    "metadata",
    "sigma_id",
    "enabled",
    "status",
    "level",
    "logsource",
    "detection",
    "mitre",
    "compliance",
)
METADATA_FIELDS = ("title", "description", "author", "references")


class ContentManagerError(RuntimeError):
    def __init__(self, message: str, status: int | None = None, body: Any = None):
        super().__init__(message)
        self.status = status
        self.body = body


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def dump_json(path: Path, payload: Any) -> None:
    secure_path(path, missing=True)
    fd, temporary = tempfile.mkstemp(prefix=".state-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            os.fchmod(stream.fileno(), 0o600)
            json.dump(payload, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def secure_path(path: Path, missing: bool = False) -> None:
    if not path.is_absolute() or ".." in path.parts:
        raise ContentManagerError(f"unsafe path: {path}")
    for entry in [*reversed(path.parents), path]:
        try:
            info = entry.lstat()
        except FileNotFoundError:
            if missing and entry == path:
                continue
            raise ContentManagerError(f"missing protected path: {entry}")
        if info.st_uid != 0 or info.st_mode & 0o022 or stat.S_ISLNK(info.st_mode):
            raise ContentManagerError(f"path must be root-owned, non-writable, and not a symlink: {entry}")
        if not (stat.S_ISDIR(info.st_mode) if entry != path else
                stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)):
            raise ContentManagerError(f"unexpected file type: {entry}")


def safe_id(value: Any) -> str:
    if not isinstance(value, str) or not re.fullmatch(
        r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}", value
    ):
        raise ContentManagerError(f"invalid Content Manager UUID: {value!r}")
    return value


def discover(client: ContentClient, kind: str, space: str, field: str, value: str | list[str]) -> list[dict[str, Any]]:
    """Read public content aliases only; never use service-controlled local state as authority."""
    result = client.request("POST", f"/wazuh-threatintel-{kind}/_search", {
        "size": 1000, "track_total_hits": True,
        "query": {"bool": {"filter": [
            {"term": {"space.name": space}},
            {"terms" if isinstance(value, list) else "term": {f"document.{field}": value}}
        ]}},
    })
    try:
        hits = result["hits"]["hits"]
        total = result["hits"]["total"]
        if (result.get("timed_out") is not False or result["_shards"]["failed"] != 0
                or total["relation"] != "eq" or total["value"] != len(hits)):
            raise ValueError("incomplete search")
        documents = []
        for hit in hits:
            source = hit["_source"]
            document = source["document"]
            safe_id(document["id"])
            actual = document
            for part in field.split("."):
                actual = actual[part]
            if source["space"]["name"] != space or not (actual in value if isinstance(value, list) else actual == value):
                raise ValueError("mismatched search hit")
            documents.append(document)
        return documents
    except (KeyError, TypeError, ValueError) as exc:
        raise ContentManagerError(f"invalid or incomplete {kind} discovery response") from exc


def integration_in(client: ContentClient, title: str, space: str, required: bool = True) -> dict[str, Any] | None:
    found = discover(client, "integrations", space, "metadata.title", title)
    if len(found) > 1 or (required and not found):
        raise ContentManagerError(f"missing or ambiguous {space} integration {title!r}")
    return found[0] if found else None


def resource_from_rule(rule: dict[str, Any]) -> dict[str, Any]:
    resource: dict[str, Any] = {}
    for key in RULE_FIELDS:
        if key not in rule:
            continue
        value = rule[key]
        if key == "metadata":
            resource[key] = {item: value[item] for item in METADATA_FIELDS if item in value}
        else:
            resource[key] = value
    return resource


def validate_document(document: dict[str, Any]) -> None:
    integration = document.get("integration") or {}
    for field in ("title", "author", "category"):
        if not integration.get(field):
            raise ContentManagerError(f"integration.{field} is required")
    rules = document.get("rules") or []
    if not rules:
        raise ContentManagerError("at least one rule is required")
    seen: set[str] = set()
    product = integration["title"]
    for rule in rules:
        sigma_id = rule.get("sigma_id")
        if not sigma_id:
            raise ContentManagerError("every rule needs sigma_id")
        if sigma_id in seen:
            raise ContentManagerError(f"duplicate sigma_id {sigma_id}")
        seen.add(sigma_id)
        if not (rule.get("metadata") or {}).get("title"):
            raise ContentManagerError(f"{sigma_id} needs metadata.title")
        if (rule.get("logsource") or {}).get("product") != product:
            raise ContentManagerError(
                f"{sigma_id} logsource.product must equal integration title {product!r}"
            )
        if "condition" not in (rule.get("detection") or {}):
            raise ContentManagerError(f"{sigma_id} needs detection.condition")


class ContentClient:
    def __init__(
        self,
        base_url: str,
        username: str,
        password: str,
        ca_file: str,
        client_cert: str | None = None,
        client_key: str | None = None,
        timeout: int = 60,
    ):
        self.base_url = base_url.rstrip("/")
        parsed_url = urllib.parse.urlsplit(self.base_url)
        if parsed_url.scheme != "https" or not parsed_url.hostname or parsed_url.username or parsed_url.password or parsed_url.query or parsed_url.fragment:
            raise ContentManagerError("Content Manager URL must be HTTPS without credentials, query, or fragment")
        self.timeout = timeout
        self.context = ssl.create_default_context(cafile=ca_file)
        if bool(client_cert) != bool(client_key):
            raise ContentManagerError("client certificate and key must be provided together")
        if client_cert and client_key:
            self.context.load_cert_chain(certfile=client_cert, keyfile=client_key)
        token = f"{username}:{password}".encode("utf-8")
        import base64

        self.auth = "Basic " + base64.b64encode(token).decode("ascii")
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, headers, newurl):
                raise ContentManagerError("Content Manager redirects are forbidden")
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=self.context), NoRedirect()
        )

    def request(self, method: str, path: str, payload: Any | None = None, ok: tuple[int, ...] = (200, 201, 202)) -> Any:
        url = f"{self.base_url}{path}"
        data = None
        headers = {
            "Authorization": self.auth,
            "Accept": "application/json",
        }
        if payload is not None:
            data = json.dumps(payload).encode("utf-8")
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(url, data=data, method=method, headers=headers)
        try:
            with self.opener.open(request, timeout=self.timeout) as response:
                body = response.read().decode("utf-8")
                parsed = json.loads(body) if body.strip() else {}
                if response.status not in ok:
                    raise ContentManagerError(
                        f"{method} {path} returned {response.status}: {body[:800]}",
                        status=response.status,
                        body=parsed,
                    )
                return parsed
        except urllib.error.HTTPError as exc:
            body_text = exc.read().decode("utf-8", errors="replace")
            try:
                parsed = json.loads(body_text) if body_text.strip() else {}
            except json.JSONDecodeError:
                parsed = {"raw": body_text}
            raise ContentManagerError(
                f"{method} {path} returned {exc.code}: {body_text[:800]}",
                status=exc.code,
                body=parsed,
            ) from exc
        except urllib.error.URLError as exc:
            reason = getattr(exc, "reason", exc)
            raise ContentManagerError(
                f"{method} {path}: unavailable API ({type(reason).__name__}: {reason})"
            ) from exc
        except json.JSONDecodeError as exc:
            raise ContentManagerError(f"{method} {path}: invalid JSON response ({exc})") from exc

    def wait_for_indexer(self, attempts: int = 60, delay: float = 5.0) -> None:
        last_error = "indexer did not become ready"
        for _ in range(attempts):
            try:
                health = self.request("GET", "/_cluster/health")
                status = str(health.get("status") or "").lower()
                if status in {"yellow", "green"}:
                    return
                last_error = f"cluster status {status or health}"
            except ContentManagerError as exc:
                last_error = str(exc)
                # Credentials, URL, and certificate failures are deterministic;
                # retrying them only obscures the deployment failure.
                if exc.status is not None and exc.status not in {408, 425, 429, 500, 502, 503, 504}:
                    raise
                if "SSLCertVerificationError" in last_error:
                    raise
            time.sleep(delay)
        raise ContentManagerError(last_error)


def unwrap(payload: Any) -> Any:
    if isinstance(payload, dict) and "message" in payload and isinstance(payload["message"], (dict, list, str)):
        return payload["message"]
    return payload


def created_id(payload: Any) -> str:
    message = unwrap(payload)
    if isinstance(message, str) and message:
        return safe_id(message)
    if isinstance(message, dict):
        for key in ("id", "uuid", "_id"):
            if message.get(key):
                return safe_id(message[key])
    raise ContentManagerError(f"create response did not include an id: {payload}")


def detection_matches(payload: Any) -> list[dict[str, Any]]:
    message = unwrap(payload)
    try:
        detection = message["detection"]
        matches = detection["matches"]
        if (type(detection["rules_evaluated"]) is not int or type(detection["rules_matched"]) is not int
                or detection["status"] != "success" or detection["rules_evaluated"] < 1
                or not isinstance(matches, list) or detection["rules_matched"] != len(matches)
                or message["normalization"]["validation"]["valid"] is not True):
            raise ValueError("unavailable or invalid logtest")
        for match in matches:
            if (not isinstance(match["rule"]["title"], str) or not match["rule"]["title"]
                    or not isinstance(match["rule"]["id"], str) or not match["rule"]["id"]):
                raise ValueError("invalid match")
        return matches
    except (KeyError, TypeError, ValueError) as exc:
        try:
            body = json.dumps(payload, sort_keys=True)
        except (TypeError, ValueError):
            body = repr(payload)
        raise ContentManagerError(
            "logtest must return valid normalization and successful nonempty rule evaluation; "
            f"body={body[:1600]}"
        ) from exc


def match_titles(matches: list[dict[str, Any]]) -> list[str]:
    titles: list[str] = []
    for item in matches:
        rule = item.get("rule") if isinstance(item, dict) else None
        if isinstance(rule, dict) and rule.get("title"):
            titles.append(str(rule["title"]))
        elif isinstance(item, dict) and item.get("title"):
            titles.append(str(item["title"]))
    return titles


def filter_promotion(preview: Any, wanted_ids: set[str]) -> dict[str, list[dict[str, str]]]:
    message = unwrap(preview)
    if not isinstance(message, dict) or not isinstance(message.get("changes"), dict):
        raise ContentManagerError("invalid promotion preview")
    changes = message["changes"]
    # Content Manager requires all resource categories on every promote request,
    # even where this deployment has no changes for that category.
    filtered: dict[str, list[dict[str, str]]] = {
        kind: [] for kind in ("policy", "integrations", "kvdbs", "decoders", "filters", "rules")
    }
    for kind, items in changes.items():
        if not isinstance(items, list):
            raise ContentManagerError("invalid promotion changes")
        for item in items:
            if not isinstance(item, dict):
                raise ContentManagerError("invalid promotion item")
            safe_id(item.get("id"))
        kept = [item for item in items if isinstance(item, dict) and item.get("id") in wanted_ids]
        if kind in filtered:
            filtered[kind] = kept
    return filtered


def promote(client: ContentClient, space: str, wanted_ids: set[str]) -> None:
    preview = client.request("GET", f"/_plugins/_content_manager/promote?space={space}")
    changes = filter_promotion(preview, wanted_ids)
    if not any(changes.values()):
        return
    client.request("POST", "/_plugins/_content_manager/promote", {"space": space, "changes": changes})


def logtest(client: ContentClient, integration_id: str, case: dict[str, Any], space: str = "test", vendor: bool = False, expected_rules: int | None = None) -> None:
    payload = {
        "integration": safe_id(integration_id),
        "space": space,
        "queue": case.get("queue", 1),
        "location": case.get("location") or "journald",
        "event": case["event"],
        "trace_level": "NONE",
    }
    result = client.request("POST", "/_plugins/_content_manager/logtest", payload)
    matches = detection_matches(result)
    if expected_rules is not None and unwrap(result)["detection"]["rules_evaluated"] != expected_rules:
        raise ContentManagerError(f"{space} logtest did not evaluate every enabled integration rule")
    titles = match_titles(matches)
    expected = None if vendor else case.get("expect_title")
    if expected and expected not in titles:
        raise ContentManagerError(
            f"logtest did not match {expected!r} for {case['event'][:120]!r}; titles={titles}; body={json.dumps(result)[:1200]}"
        )
    rejected = set(case.get("reject_titles") or [])
    unexpected = sorted(rejected.intersection(titles))
    if unexpected:
        raise ContentManagerError(
            f"logtest matched rejected titles {unexpected!r} for {case['event'][:120]!r}; titles={titles}; body={json.dumps(result)[:1200]}"
        )
    prefixes = case.get("reject_prefixes", [])
    offenders = [item["rule"] for item in matches if any(
        item["rule"]["title"].casefold().startswith(prefix.casefold()) for prefix in prefixes
    )]
    if offenders:
        raise ContentManagerError(f"{space} authentication outcome check failed: " + json.dumps(offenders))
    # Wazuh's bundled integrations are versioned upstream content. Require that
    # each enabled rule evaluated, and reject a contradictory authentication
    # outcome above, but do not depend on an upstream display title or whether a
    # particular bundled rule emits an alert for this fixture.
    expected_prefix = None if vendor else case.get("expect_prefix")
    if expected_prefix and not any(title.startswith(expected_prefix) for title in titles):
        raise ContentManagerError(f"{space} logtest missing {expected_prefix!r}: {titles}")


def vendor_checks(client: ContentClient, document: dict[str, Any]) -> None:
    cases = [case for case in document.get("logtests", []) if case.get("vendor_integration")]
    if not cases:
        raise ContentManagerError("vendor authentication fixtures are required")
    for title in sorted({case["vendor_integration"] for case in cases}):
        integration = integration_in(client, title, "standard")
        linked = integration.get("rules")
        if integration.get("enabled") is not True or not isinstance(linked, list) or not linked:
            raise ContentManagerError(f"Standard integration {title} is disabled or has no rules")
        linked = [safe_id(value) for value in linked]
        rules = discover(client, "rules", "standard", "id", linked)
        if len(rules) != len(linked) or {rule["id"] for rule in rules} != set(linked):
            raise ContentManagerError(f"Standard integration {title} has missing or ambiguous rules")
        count = sum(rule.get("enabled") is True for rule in rules)
        if not count:
            raise ContentManagerError(f"Standard integration {title} has no enabled rules")
        for case in cases:
            if case["vendor_integration"] == title:
                logtest(client, integration["id"], case, "standard", vendor=True, expected_rules=count)


def production_checks(client: ContentClient, document: dict[str, Any]) -> str:
    vendor_checks(client, document)
    integration = integration_in(client, document["integration"]["title"], "custom")
    verify_managed_content(client, document, integration, "custom")
    for case in document["logtests"]:
        logtest(client, integration["id"], case, "custom", expected_rules=len(document["rules"]))
    return integration["id"]


def verify_managed_content(client: ContentClient, document: dict[str, Any], integration: dict[str, Any], space: str) -> None:
    expected = {rule["sigma_id"]: rule for rule in document["rules"]}
    actual = discover(client, "rules", space, "logsource.product", document["integration"]["title"])
    if len(actual) != len(expected) or {rule.get("sigma_id") for rule in actual} != set(expected):
        raise ContentManagerError(f"{space} managed Sigma IDs differ from desired content")
    if set(integration.get("rules", [])) != {rule["id"] for rule in actual}:
        raise ContentManagerError(f"{space} integration rule links differ from desired content")
    if integration.get("enabled") is not True:
        raise ContentManagerError(f"{space} managed integration is disabled")
    for rule in actual:
        wanted = resource_from_rule(expected[rule["sigma_id"]])
        for key, value in wanted.items():
            got = rule.get(key)
            # Server adds timestamps/IDs; only compare fields this publisher owns.
            if key == "metadata" and isinstance(got, dict):
                got = {field: got.get(field) for field in value}
            if got != value:
                raise ContentManagerError(f"{space} rule {rule['sigma_id']} has stale {key}")


def resource_is_current(actual: dict[str, Any], wanted: dict[str, Any]) -> bool:
    """Compare only publisher-owned resource fields, ignoring server-generated fields."""
    for key, value in wanted.items():
        got = actual.get(key)
        if key == "metadata" and isinstance(got, dict):
            got = {field: got.get(field) for field in value}
        if got != value:
            return False
    return True


def publish(args: argparse.Namespace) -> int:
    if not args.validate_only:
        for name in (args.rules, args.ca_file, args.password_file):
            if name:
                secure_path(Path(name))
        secure_path(Path(args.state), missing=True)
    document = load_json(Path(args.rules))
    validate_document(document)
    if args.validate_only:
        print(f"validated {len(document['rules'])} rules for integration {document['integration']['title']}")
        return 0

    password = args.password or os.environ.get("WAZUH_INDEXER_PASSWORD")
    if args.password_file:
        password = Path(args.password_file).read_text(encoding="utf-8").strip()
    if not password:
        raise ContentManagerError("set --password, --password-file, or WAZUH_INDEXER_PASSWORD")

    state_path = Path(args.state)
    # Deliberately never read old or current progress as resource authority.
    dump_json(state_path, {"status": "unverified"})
    client = ContentClient(
        args.url, args.username, password, args.ca_file,
        client_cert=getattr(args, "client_cert", None),
        client_key=getattr(args, "client_key", None),
    )
    client.wait_for_indexer()

    integration = document["integration"]
    vendor_checks(client, document)  # Gate before ANY content mutation.
    if getattr(args, "verify_only", False):
        integration_id = production_checks(client, document)
        dump_json(state_path, {"status": "verified", "integration_id": integration_id,
                              "rules_sha256": hashlib.sha256(Path(args.rules).read_bytes()).hexdigest(),
                              "verified_at": time.time()})
        print("verified Standard and Custom production fixtures")
        return 0
    found = integration_in(client, integration["title"], "draft", required=False)
    if found and (found.get("metadata", {}).get("author") != integration["author"]
                  or found.get("category") != integration["category"]):
        raise ContentManagerError("managed integration title collides with foreign content")
    integration_id = found["id"] if found else None
    rule_ids: dict[str, str] = {}
    for space in ("test", "custom"):
        other = integration_in(client, integration["title"], space, required=False)
        if other and not found:
            raise ContentManagerError("managed integration exists outside Draft; refusing duplicate creation")
    discovered_rules = discover(client, "rules", "draft", "logsource.product", integration["title"])
    linked = set(found.get("rules", [])) if found else set()
    desired_rules = discover(client, "rules", "draft", "sigma_id", [rule["sigma_id"] for rule in document["rules"]])
    desired_seen: set[str] = set()
    for rule in desired_rules:
        if (rule["sigma_id"] in desired_seen or rule["id"] not in linked
                or rule.get("logsource", {}).get("product") != integration["title"]):
            raise ContentManagerError("expected Sigma ID belongs to ambiguous or foreign integration content")
        desired_seen.add(rule["sigma_id"])
    for rule in discovered_rules:
        sigma_id = rule.get("sigma_id")
        if (not sigma_id or sigma_id in rule_ids or rule["id"] not in linked
                or rule.get("metadata", {}).get("author") != integration["author"]):
            raise ContentManagerError("ambiguous or unlinked managed rule discovery")
        rule_ids[sigma_id] = safe_id(rule["id"])
    if linked != set(rule_ids.values()):
        raise ContentManagerError("integration references missing or foreign rules")
    integration_metadata = {
        "title": integration["title"],
        "author": integration["author"],
        "description": integration.get("description", ""),
        "documentation": integration.get("documentation", ""),
        "references": integration.get("references", []),
    }
    integration_resource = {
        "metadata": integration_metadata,
        "category": integration["category"],
        "enabled": integration.get("enabled", True),
    }

    def persist_state() -> None:
        dump_json(
            state_path,
            {
                "integration_id": integration_id,
                "integration_title": integration["title"],
                "rule_ids": rule_ids,
                "status": "publishing",
            },
        )

    if not integration_id:
        created = client.request(
            "POST",
            "/_plugins/_content_manager/integrations",
            {"resource": integration_resource},
        )
        integration_id = created_id(created)
        persist_state()

    for rule in document["rules"]:
        sigma_id = rule["sigma_id"]
        resource = resource_from_rule(rule)
        existing = rule_ids.get(sigma_id)
        if existing:
            current = next((item for item in discovered_rules if item["id"] == existing), None)
            if current and resource_is_current(current, resource):
                continue
            try:
                client.request(
                    "PUT",
                    f"/_plugins/_content_manager/rules/{existing}",
                    {"resource": resource},
                )
                continue
            except ContentManagerError as exc:
                detail = str(exc).lower()
                if exc.status == 400 and "not in draft" in detail:
                    raise ContentManagerError(
                        f"stored rule {sigma_id} ({existing}) is no longer editable in Draft; "
                        "refusing to report stale security content as published"
                    ) from exc
                raise
        created = client.request(
            "POST",
            "/_plugins/_content_manager/rules",
            {"integration": integration_id, "resource": resource},
        )
        rule_ids[sigma_id] = created_id(created)
        persist_state()

    desired_sigma_ids = {rule["sigma_id"] for rule in document["rules"]}
    removed_rule_ids: set[str] = set()
    for sigma_id in sorted(set(rule_ids).difference(desired_sigma_ids)):
        stale_id = rule_ids[sigma_id]
        try:
            client.request("DELETE", f"/_plugins/_content_manager/rules/{stale_id}")
        except ContentManagerError as exc:
            if exc.status != 404:
                raise
        removed_rule_ids.add(stale_id)
        del rule_ids[sigma_id]
        persist_state()

    ordered_rule_ids = [rule_ids[rule["sigma_id"]] for rule in document["rules"]]
    integration_update = {
        **integration_resource,
        "rules": ordered_rule_ids,
        "decoders": [],
        "kvdbs": [],
    }
    if not found or not resource_is_current(found, integration_update):
        client.request(
            "PUT",
            f"/_plugins/_content_manager/integrations/{integration_id}",
            {"resource": integration_update},
        )

    wanted_ids = {integration_id, *rule_ids.values(), *removed_rule_ids}
    promote(client, "draft", wanted_ids)
    test_integration = integration_in(client, integration["title"], "test")
    verify_managed_content(client, document, test_integration, "test")
    for case in document.get("logtests") or []:
        logtest(client, test_integration["id"], case, expected_rules=len(document["rules"]))
    promote(client, "test", wanted_ids)

    production_checks(client, document)
    dump_json(state_path, {"integration_id": integration_id, "integration_title": integration["title"],
                          "rule_ids": rule_ids, "status": "verified", "verified_at": time.time(),
                          "rules_sha256": hashlib.sha256(Path(args.rules).read_bytes()).hexdigest()})
    print(f"published {len(rule_ids)} rules as integration {integration_id}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rules", required=True, help="path to engine rules JSON")
    parser.add_argument("--state", help="path to persisted UUID state JSON")
    parser.add_argument("--url", default="https://127.0.0.1:19200")
    parser.add_argument("--username", default="admin")
    parser.add_argument("--password", help="indexer password; WAZUH_INDEXER_PASSWORD otherwise")
    parser.add_argument("--password-file", help="file containing the indexer password")
    parser.add_argument("--ca-file", required=True, help="CA certificate used to verify the indexer")
    parser.add_argument("--client-cert", help="TLS client certificate for the indexer")
    parser.add_argument("--client-key", help="TLS client private key for the indexer")
    parser.add_argument("--validate-only", action="store_true")
    parser.add_argument("--verify-only", action="store_true", help="read-only live production verification")
    args = parser.parse_args()
    if not args.validate_only and not args.state:
        parser.error("--state is required unless --validate-only")
    try:
        if not args.validate_only:
            secure_path(Path(__file__))
            lock_path = Path(args.state).parent / "publisher.lock"
            secure_path(lock_path, missing=True)
            lock_fd = os.open(lock_path, os.O_CREAT | os.O_NOFOLLOW | os.O_RDWR, 0o600)
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise ContentManagerError(
                    f"another publisher is already running (lock: {lock_path}); "
                    "wait for it to finish and retry"
                ) from exc
        return publish(args)
    except (ContentManagerError, OSError, ValueError) as exc:
        print(exc, file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
