#!/usr/bin/env python3
"""Offline API contract and hostile-input regressions; not a substitute for live logtest."""
import argparse
import copy
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import tempfile
import unittest
from unittest.mock import patch

PUBLISHER = Path(__file__).resolve().parents[1] / "roles/wazuh_agent/files/engine/publish.py"
SPEC = importlib.util.spec_from_file_location("publisher", PUBLISHER)
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)
DOCUMENT = json.loads(PUBLISHER.with_name("rules.json").read_text())


def uuid(number):
    return f"00000000-0000-4000-8000-{number:012d}"


class FakeClient:
    def __init__(self, *args):
        self.calls = []
        self.resources = {"integrations": {"standard": [{"id": uuid(1), "metadata": {"title": "auditd"}, "enabled": True, "rules": [uuid(99)]}]},
                          "rules": {"standard": [{"id": uuid(99), "enabled": True}]}}
        self.number = 100
        self.bad_vendor = False
        self.unavailable = False

    def wait_for_indexer(self):
        pass

    def request(self, method, path, payload=None):
        self.calls.append((method, path, payload))
        if path.endswith("/_search"):
            kind = path.split("/")[1].removeprefix("wazuh-threatintel-")
            filters = payload["query"]["bool"]["filter"]
            space = filters[0]["term"]["space.name"]
            field, value = next(iter(next(iter(filters[1].values())).items()))
            hits = []
            for document in self.resources[kind].get(space, []):
                actual = {"document": document}
                for part in field.split("."):
                    actual = actual.get(part, {})
                if actual in value if isinstance(value, list) else actual == value:
                    hits.append({"_source": {"document": copy.deepcopy(document), "space": {"name": space}}})
            return {"timed_out": False, "_shards": {"failed": 0}, "hits": {"total": {"relation": "eq", "value": len(hits)}, "hits": hits}}
        if "/promote" in path:
            if method == "GET":
                return {"message": {"changes": {kind: [{"id": doc["id"]} for doc in spaces.get("draft", [])] for kind, spaces in self.resources.items()}}}
            source = payload["space"]
            target = "test" if source == "draft" else "custom"
            for spaces in self.resources.values():
                spaces[target] = copy.deepcopy(spaces.get(source, []))
            return {}
        if path.endswith("/logtest"):
            case = next(case for case in DOCUMENT["logtests"] if case["event"] == payload["event"])
            title = case.get("expect_title") or (case.get("expect_prefix", "") + "decoded-user" if case.get("expect_prefix") else "")
            if self.bad_vendor and payload["space"] == "standard":
                title = "Successful user authentication - (invalid user)"
            matches = [{"rule": {"id": uuid(99), "title": title}}] if title else []
            return {"message": {"normalization": {"validation": {"valid": True}}, "detection": {
                "status": "skipped" if self.unavailable else "success", "rules_evaluated": 1 if payload["space"] == "standard" else len(DOCUMENT["rules"]),
                "rules_matched": len(matches), "matches": matches}}}
        kind = path.split("/")[3]
        space = self.resources[kind].setdefault("draft", [])
        if method == "POST":
            self.number += 1
            resource = {**copy.deepcopy(payload["resource"]), "id": uuid(self.number)}
            space.append(resource)
            if kind == "rules":
                parent = next(doc for doc in self.resources["integrations"]["draft"] if doc["id"] == payload["integration"])
                parent.setdefault("rules", []).append(resource["id"])
            return {"message": resource["id"]}
        resource_id = path.split("/")[-1]
        existing = next(doc for doc in space if doc["id"] == resource_id)
        if method == "PUT":
            existing.update(copy.deepcopy(payload["resource"]))
        elif method == "DELETE":
            space.remove(existing)
        return {}


class PublisherTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.rules = root / "rules.json"
        self.rules.write_text(json.dumps(DOCUMENT))
        self.state = root / "state.json"
        self.args = argparse.Namespace(rules=str(self.rules), state=str(self.state), url="https://localhost", username="admin",
                                       password="fixture-only", password_file=None, ca_file="/dev/null", validate_only=False, verify_only=False)
        self.client = FakeClient()

    def publish(self):
        # Temp fixtures are intentionally not production root-owned paths.
        with patch.object(M, "ContentClient", return_value=self.client), patch.object(M, "secure_path"):
            return M.publish(self.args)

    def test_repeat_publishing_ignores_malicious_state_and_does_not_duplicate(self):
        self.state.write_text('{"integration_id":"../../evil","rule_ids":{"x":"bad"}}')
        self.assertEqual(self.publish(), 0)
        first = sum(call[0] == "POST" and call[1].endswith(("/rules", "/integrations")) for call in self.client.calls)
        self.assertEqual(first, len(DOCUMENT["rules"]) + 1)
        self.client.calls.clear()
        self.assertEqual(self.publish(), 0)
        self.assertFalse(any(call[0] == "POST" and call[1].endswith(("/rules", "/integrations")) for call in self.client.calls))
        self.assertEqual(json.loads(self.state.read_text())["status"], "verified")
        self.assertEqual(stat.S_IMODE(self.state.stat().st_mode), 0o600)
        self.assertFalse(list(self.state.parent.glob(".state-*")))

    def test_vendor_false_success_blocks_before_mutation_and_invalidates_state(self):
        self.state.write_text('{"status":"verified"}')
        self.client.bad_vendor = True
        with self.assertRaisesRegex(M.ContentManagerError, "authentication outcome"):
            self.publish()
        self.assertEqual(json.loads(self.state.read_text())["status"], "unverified")
        self.assertFalse(any(call[1].endswith(("/rules", "/integrations", "/promote")) for call in self.client.calls))

    def test_vendor_logtest_allows_no_upstream_title_when_every_rule_evaluates(self):
        result = {"message": {"normalization": {"validation": {"valid": True}}, "detection": {
            "status": "success", "rules_evaluated": 1, "rules_matched": 0, "matches": []
        }}}
        with patch.object(self.client, "request", return_value=result):
            M.logtest(self.client, uuid(1), DOCUMENT["logtests"][2], "standard", vendor=True, expected_rules=1)

    def test_promotions_include_empty_required_resource_categories(self):
        self.publish()
        required = {"policy", "integrations", "kvdbs", "decoders", "filters", "rules"}
        promotions = [payload for method, path, payload in self.client.calls
                      if method == "POST" and path.endswith("/promote")]
        self.assertTrue(promotions)
        for payload in promotions:
            self.assertEqual(set(payload["changes"]), required)

    def test_unavailable_tests_fail(self):
        self.client.unavailable = True
        with self.assertRaises(M.ContentManagerError):
            self.publish()

    def test_missing_and_ambiguous_vendor_fail(self):
        for integrations in ([], [self.client.resources["integrations"]["standard"][0]] * 2):
            self.client.resources["integrations"]["standard"] = integrations
            with self.assertRaisesRegex(M.ContentManagerError, "missing or ambiguous"):
                self.publish()

    def test_ambiguous_rule_fails_without_mutation(self):
        self.publish()
        self.client.resources["rules"]["draft"].append(copy.deepcopy(self.client.resources["rules"]["draft"][0]))
        self.client.calls.clear()
        with self.assertRaisesRegex(M.ContentManagerError, "ambiguous"):
            self.publish()
        self.assertFalse(any(method in ("PUT", "DELETE") for method, _, _ in self.client.calls))

    def test_ambiguous_managed_integration_and_malformed_server_id(self):
        self.publish()
        found = self.client.resources["integrations"]["draft"][0]
        self.client.resources["integrations"]["draft"].append(copy.deepcopy(found))
        with self.assertRaisesRegex(M.ContentManagerError, "ambiguous"):
            self.publish()
        self.client.resources["integrations"]["draft"].pop()
        found["id"] = "../../vendor-rule"
        with self.assertRaisesRegex(M.ContentManagerError, "invalid Content Manager UUID"):
            self.publish()

    def test_partial_rule_evaluation_fails(self):
        case = DOCUMENT["logtests"][2]
        with self.assertRaisesRegex(M.ContentManagerError, "every enabled"):
            M.logtest(self.client, uuid(1), case, "standard", vendor=True, expected_rules=2)

    def test_sigma_id_in_another_integration_blocks_duplicate_creation(self):
        foreign = copy.deepcopy(DOCUMENT["rules"][0])
        foreign.update(id=uuid(200))
        foreign["logsource"]["product"] = "foreign-integration"
        self.client.resources["rules"]["draft"] = [foreign]
        with self.assertRaisesRegex(M.ContentManagerError, "foreign integration"):
            self.publish()
        self.assertFalse(any(path.endswith(("/rules", "/integrations")) for _, path, _ in self.client.calls))

    def test_stale_custom_rule_cannot_be_verified(self):
        self.publish()
        self.client.resources["rules"]["custom"][0]["detection"] = {}
        self.args.verify_only = True
        with self.assertRaisesRegex(M.ContentManagerError, "stale detection"):
            self.publish()
        self.assertEqual(json.loads(self.state.read_text())["status"], "unverified")

    def test_failed_post_promotion_check_never_records_verified(self):
        original = self.client.request
        def request(method, path, payload=None):
            result = original(method, path, payload)
            if path.endswith("/promote") and method == "POST" and payload["space"] == "test":
                self.client.bad_vendor = True
            return result
        with patch.object(self.client, "request", side_effect=request):
            with self.assertRaisesRegex(M.ContentManagerError, "authentication outcome"):
                self.publish()
        self.assertEqual(json.loads(self.state.read_text())["status"], "publishing")

    def test_failed_atomic_write_cleans_up_and_preserves_previous_state(self):
        self.state.write_text("previous")
        with patch.object(M, "secure_path"), patch.object(M.os, "replace", side_effect=OSError("fixture failure")):
            with self.assertRaises(OSError):
                M.dump_json(self.state, {"status": "verified"})
        self.assertEqual(self.state.read_text(), "previous")
        self.assertFalse(list(self.state.parent.glob(".state-*")))

    def test_verify_only_runs_live_without_content_writes(self):
        self.publish()
        self.client.calls.clear()
        self.args.verify_only = True
        self.publish()
        self.assertTrue(any(payload and payload.get("space") == "custom" for _, path, payload in self.client.calls if path.endswith("/logtest")))
        self.assertFalse(any(method in ("PUT", "DELETE") or path.endswith(("/rules", "/integrations", "/promote")) for method, path, _ in self.client.calls))

    def test_ids_and_invalid_responses_fail_closed(self):
        for value in ("../rule", "a?space=standard", "x/y", "", None, 5):
            with self.assertRaises(M.ContentManagerError):
                M.created_id({"message": {"id": value}})
        for body in ({}, {"message": {}}, {"message": {"detection": {"status": "skipped"}}}):
            with self.assertRaisesRegex(M.ContentManagerError, "body="):
                M.detection_matches(body)
        with patch.object(self.client, "request", return_value={"hits": {"hits": []}}):
            with self.assertRaises(M.ContentManagerError):
                M.integration_in(self.client, "auditd", "standard")

    def test_repeat_publishing_does_not_rewrite_current_draft_content(self):
        self.publish()
        self.client.calls.clear()
        self.publish()
        writes = [(method, path) for method, path, _ in self.client.calls if method == "PUT"]
        self.assertEqual(writes, [])

    def test_transport_error_preserves_tls_or_socket_reason(self):
        import urllib.error
        from unittest.mock import MagicMock
        opener = MagicMock()
        with patch.object(opener, "open") as open_request:
            open_request.side_effect = urllib.error.URLError("certificate verify failed")
            client = object.__new__(M.ContentClient)
            client.base_url = "https://127.0.0.1:19200"
            client.opener = opener
            client.auth = "Basic fixture"
            client.timeout = 1
            with self.assertRaisesRegex(M.ContentManagerError, "certificate verify failed"):
                client.request("GET", "/_cluster/health")

    def test_tls_verification_failure_does_not_retry_indexer_readiness(self):
        client = object.__new__(M.ContentClient)
        with patch.object(
            client,
            "request",
            side_effect=M.ContentManagerError("unavailable API (SSLCertVerificationError: certificate verify failed)"),
        ) as request, patch.object(M.time, "sleep") as sleep:
            with self.assertRaisesRegex(M.ContentManagerError, "SSLCertVerificationError"):
                client.wait_for_indexer(attempts=60, delay=5)
        self.assertEqual(request.call_count, 1)
        sleep.assert_not_called()

    def test_path_boundary_and_symlinks(self):
        for uid, mode in ((1000, stat.S_IFDIR | 0o700), (0, stat.S_IFDIR | 0o775), (0, stat.S_IFLNK | 0o777)):
            with patch.object(Path, "lstat", return_value=os.stat_result((mode, 0, 0, 1, uid, 0, 0, 0, 0, 0))):
                with self.assertRaises(M.ContentManagerError):
                    M.secure_path(Path("/var/lib/platform-wazuh/state.json"))
        self.state.symlink_to(self.rules)
        with self.assertRaises(M.ContentManagerError):
            M.dump_json(self.state, {"attack": True})
        self.assertEqual(json.loads(self.rules.read_text()), DOCUMENT)

    def test_outcome_fixture_matrix_and_rule_conditions(self):
        rules = {rule["sigma_id"]: rule for rule in DOCUMENT["rules"]}
        success = rules["platform-100417"]["detection"]
        failure = rules["platform-100416"]["detection"]
        self.assertIn("not failed", success["condition"])
        self.assertIn("not succeeded", failure["condition"])
        cases = [case for case in DOCUMENT["logtests"] if case.get("vendor_integration")]
        self.assertEqual(len(cases), 5)
        for case in cases:
            fail = bool(re.search(failure["failed"]["event.original|re"], case["event"]))
            ok = bool(re.search(success["succeeded"]["event.original|re"], case["event"]))
            if case.get("outcome_case"):
                self.assertFalse(ok and not fail)
                self.assertFalse(fail and not ok)
            self.assertEqual(case["queue"], 49)
        self.assertFalse(re.search(success["succeeded"]["event.original|re"], " res=successful"))
        for raw in (" res=unknown res=success'", " res=success res=failed'", " res=success res=success'"):
            self.assertTrue(re.search(success["ambiguous"]["event.original|re"], raw))

    def test_rustinel_rule_uses_only_wazuh_common_schema_fields(self):
        rustinel = next(rule for rule in DOCUMENT["rules"] if rule["sigma_id"] == "rustinel-100500")
        serialized = json.dumps(rustinel["detection"])
        self.assertNotIn("edr.rule.", serialized)
        self.assertIn("event.module", serialized)
        self.assertIn("event.dataset", serialized)
        self.assertIn("rule.name", serialized)
        self.assertIn("rule.id", serialized)


if __name__ == "__main__":
    unittest.main()
