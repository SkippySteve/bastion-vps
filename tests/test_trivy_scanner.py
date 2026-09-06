#!/usr/bin/python3
import importlib.machinery
import json
import pathlib
import sys
import types


scanner_path = pathlib.Path(sys.argv[1])
fixture_path = pathlib.Path(sys.argv[2])
module = types.ModuleType("trivy_platform_scan")
loader = importlib.machinery.SourceFileLoader(module.__name__, str(scanner_path))
loader.exec_module(module)

report = json.loads(fixture_path.read_text())
findings = module.findings_from_report(
    report, "fixture", {"fixture:image"}, "2099-01-01T00:00:00+00:00", "sha256:runtime"
)
assert len(findings) == 1
finding = next(iter(findings.values()))
assert finding["finding_id"] == "CVE-2099-0001"
assert finding["severity"] == "HIGH"
assert finding["image_id"] == "sha256:runtime"

new, resolved, retained = module.reconcile_findings(
    {}, findings, {"sha256:runtime"}, {"sha256:runtime"}
)
assert len(new) == 1
assert not resolved
assert retained == findings

new, resolved, retained = module.reconcile_findings(
    findings, {}, {"sha256:runtime"}, set()
)
assert not new
assert not resolved
assert retained == findings

new, resolved, retained = module.reconcile_findings(
    findings, {}, {"sha256:runtime"}, {"sha256:runtime"}
)
assert not new
assert len(resolved) == 1
assert not retained
