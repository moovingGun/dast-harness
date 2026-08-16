"""Example: run one nuclei scan against a local target and poll it.

Usage:
    python example.py http://127.0.0.1:8080

Only loopback targets pass by default. To scan a host you are
authorized to test, add it to `allowlist` below.
"""

import sys
import time

from dast_harness import (
    ConsoleReporter,
    JSONReporter,
    NucleiScanner,
    ScanConfig,
    ScanRunner,
    Severity,
    Target,
    build_report,
)
from dast_harness.safety import TargetNotAuthorizedError


def main() -> int:
    url = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8080"

    scanner = NucleiScanner()
    if not scanner.is_available():
        print("nuclei is not installed or not on PATH. Install it first.")
        return 1

    # allowlist: hostnames you are explicitly authorized to scan (bypasses the
    # loopback-only rule). Leave empty to allow loopback targets only.
    runner = ScanRunner(scanner, allowlist=set())

    config = ScanConfig(severities=[Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL])

    try:
        scan_id = runner.start_scan(Target(url), config)
    except TargetNotAuthorizedError as exc:
        print(f"REFUSED: {exc}")
        return 2

    print(f"started scan {scan_id} against {url}")

    # Poll status + results while it runs.
    while True:
        status = runner.get_status(scan_id)
        print(f"  status={status['status']} findings={status['findings_count']}")
        if status["status"] not in ("pending", "running"):
            break
        time.sleep(2)

    # Report: console summary to stdout, full results to results.json.
    report = build_report(runner, scan_id)
    print()
    print(ConsoleReporter().render(report))
    with open("results.json", "w", encoding="utf-8") as fh:
        fh.write(JSONReporter().render(report))
    print("\nwrote results.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
