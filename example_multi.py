"""Example: run several scanners against one local target and merge the results.

Usage:
    python example_multi.py http://127.0.0.1:8080

Only local (loopback) or allowlisted targets pass the safety check.
"""

import sys
import time

from dast_harness import (
    ConsoleReporter,
    JSONReporter,
    MultiScanRunner,
    NiktoScanner,
    NucleiScanner,
    ScanConfig,
    Target,
    build_report,
)
from dast_harness.safety import TargetNotAuthorizedError


def main() -> int:
    url = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8080"

    scanners = [NucleiScanner(), NiktoScanner()]
    available = [s for s in scanners if s.is_available()]
    if not available:
        print("no scanner is installed (need nuclei and/or nikto on PATH)")
        return 1

    runner = MultiScanRunner(available, allowlist=set())
    config = ScanConfig(request_timeout=5)

    try:
        scan_id = runner.start_scan(Target(url), config)
    except TargetNotAuthorizedError as exc:
        print(f"REFUSED: {exc}")
        return 2

    print(f"started multi-scan {scan_id} against {url} "
          f"with {[s.name for s in available]}")

    while runner.get_status(scan_id)["status"] == "running":
        time.sleep(2)

    report = build_report(runner, scan_id)
    print()
    print(ConsoleReporter().render(report))
    with open("results.json", "w", encoding="utf-8") as fh:
        fh.write(JSONReporter().render(report))
    print("\nwrote results.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
