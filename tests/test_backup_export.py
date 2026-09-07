#!/usr/bin/env python3
"""Run the rendered export function with a real unprivileged producer and root-only staging."""
import os
from pathlib import Path
import pwd
import re
import shutil
import stat
import subprocess
import sys
import tempfile


def main():
    if os.geteuid() != 0:
        raise SystemExit("This permission-boundary test must run as root (via tests/render.yml)")
    runuser = shutil.which("runuser")
    assert runuser, "runuser is required for the unprivileged export test"
    pwd.getpwnam("nobody")
    source = Path(sys.argv[1]).read_text()
    function = re.search(r"^export_clickhouse_archive\(\) \{\n.*?^\}", source, re.M | re.S).group()
    assert "umask 077" in source
    with tempfile.TemporaryDirectory(prefix="platform-export-test-") as directory:
        root = Path(directory)
        root.chmod(0o755)
        staging = root / "staging"
        staging.mkdir(mode=0o700)
        data = bytes(range(256)) * 31 + b"\x00archive-end\xff"
        archive = root / "container-archive"
        archive.write_bytes(data)
        archive.chmod(0o644)
        destination = staging / "database.zip"
        # Root opens the descriptor; the child cannot open or replace anything in staging.
        denied = subprocess.run([runuser, "-u", "nobody", "--", "/usr/bin/touch", str(destination)], capture_output=True)
        assert denied.returncode != 0
        script = "set -euo pipefail\numask 077\n" + function + r'''
stack_exec() {
  "$RUNUSER" -u nobody -- /bin/bash -c 'cat "$1"; exit "$2"' bash "$INPUT" "$PRODUCER_STATUS"
}
trap 'printf cleanup >"$CLEANUP"' EXIT
export_clickhouse_archive nobody 65534 fixture archive "$DESTINATION"
printf success >"$SUCCESS"
'''
        for case, content, status, expected in (
            ("success", data, "0", 0),
            ("producer-failure", b"partial", "7", 1),
            ("empty", b"", "0", 1),
        ):
            archive.write_bytes(content)
            cleanup = staging / "cleanup"
            success = staging / "success"
            success.unlink(missing_ok=True)
            result = subprocess.run(["/bin/bash", "-c", script], env={**os.environ,
                "RUNUSER": runuser, "INPUT": str(archive), "PRODUCER_STATUS": status,
                "DESTINATION": str(destination), "CLEANUP": str(cleanup), "SUCCESS": str(success)}, capture_output=True)
            assert result.returncode == expected, (case, result.stderr)
            assert cleanup.read_text() == "cleanup", "restart cleanup trap must survive failures"
            assert success.exists() == (expected == 0), "failure must prevent successful backup/retention continuation"
            assert destination.read_bytes() == data, "failed exports must not replace the last complete archive"
            assert stat.S_IMODE(destination.stat().st_mode) == 0o600
            assert stat.S_IMODE(staging.stat().st_mode) == 0o700
            assert not list(staging.glob("*.partial.*"))
        # Representative protected publisher tree: user cannot read config/state or rename code.
        protected = root / "publisher"
        protected.mkdir(mode=0o700)
        for name in ("publish.py", "rules.json", "state.json"):
            path = protected / name
            path.write_text("root-owned fixture")
            path.chmod(0o600)
            assert subprocess.run([runuser, "-u", "nobody", "--", "cat", str(path)], capture_output=True).returncode != 0
            assert subprocess.run([runuser, "-u", "nobody", "--", "mv", str(path), str(path) + ".old"], capture_output=True).returncode != 0
        assert subprocess.run([runuser, "-u", "nobody", "--", "mv", str(protected), str(protected) + ".old"], capture_output=True).returncode != 0
    print("root/unprivileged export: exact bytes, permissions, cleanup, failure propagation, and publisher boundary passed")


if __name__ == "__main__":
    main()
