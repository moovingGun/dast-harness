"""Command-line interface: run a one-shot scan and print a report.

    python -m dast_harness scan http://127.0.0.1:8080 --scanner nuclei,nikto

Thin wrapper over MultiScanRunner + the reporters. Exit codes:
    0    completed / completed_with_warnings
    1    partial / failed
    2    bad args / config / target refused / no scanner installed
    124  group timeout
    130  interrupted (Ctrl-C)
"""

from __future__ import annotations

import argparse
import sys

from .models import ScanConfig, Severity, Target
from .orchestrator import MultiScanRunner
from .reporters import ConsoleReporter, JSONReporter, build_report
from .safety import TargetNotAuthorizedError
from .scanners.nikto import NiktoScanner
from .scanners.nuclei import NucleiScanner

# name -> factory. Tests monkeypatch this to inject fakes.
SCANNERS = {"nuclei": NucleiScanner, "nikto": NiktoScanner}

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_USAGE = 2
EXIT_TIMEOUT = 124
EXIT_INTERRUPT = 130

_STOP_GRACE = 5.0


def _csv(value: str | None) -> list[str]:
    return [v.strip() for v in value.split(",")] if value else []


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="dast-harness", description="Minimal local-only DAST harness."
    )
    sub = parser.add_subparsers(dest="command", required=True)
    scan = sub.add_parser("scan", help="scan a local/allowlisted target")
    scan.add_argument("url", help="target URL (http/https)")
    scan.add_argument(
        "-s", "--scanner",
        help="comma list of scanners (default: all available)",
    )
    scan.add_argument(
        "--allow", action="append", metavar="HOST",
        help="allowlist a host (repeatable)",
    )
    scan.add_argument("--severity", help="nuclei: comma list of severities")
    scan.add_argument("--tags", help="nuclei: comma list of tags")
    scan.add_argument("--template-id", help="nuclei: comma list of template ids")
    scan.add_argument("--rate-limit", type=int, help="nuclei: requests/sec")
    scan.add_argument("--request-timeout", type=int, help="per-request seconds")
    scan.add_argument(
        "--enable-interactsh", action="store_true",
        help="allow nuclei OAST (external callbacks; off by default)",
    )
    scan.add_argument("--timeout", type=float, help="whole-group deadline (seconds)")
    scan.add_argument(
        "-f", "--format", choices=("console", "json"), default="console",
    )
    scan.add_argument("-o", "--output", help="write the report to a file")
    scan.add_argument(
        "--include-raw", action="store_true",
        help="include raw scanner output in the JSON report",
    )
    return parser


def _build_config(args) -> ScanConfig:
    severities = []
    for s in _csv(args.severity):
        if not s:
            continue
        try:
            severities.append(Severity(s.lower()))
        except ValueError:
            raise ValueError(f"invalid severity: {s!r}")
    return ScanConfig(
        severities=severities,
        tags=[t for t in _csv(args.tags) if t],
        template_ids=[t for t in _csv(args.template_id) if t],
        rate_limit=args.rate_limit,
        request_timeout=args.request_timeout,
        enable_interactsh=args.enable_interactsh,
    )


def _select_scanners(spec: str | None):
    names = _csv(spec) if spec else list(SCANNERS)
    names = [n for n in names if n]
    unknown = [n for n in names if n not in SCANNERS]
    if unknown:
        raise ValueError(
            f"unknown scanner(s): {', '.join(unknown)} "
            f"(available: {', '.join(SCANNERS)})"
        )
    ordered = list(dict.fromkeys(names))  # dedupe, keep order
    return [SCANNERS[n]() for n in ordered]


def _emit(runner, scan_id, args) -> None:
    report = build_report(runner, scan_id)
    if args.format == "json":
        text = JSONReporter(include_raw=args.include_raw).render(report)
    else:
        text = ConsoleReporter().render(report)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
        print(f"wrote {args.output}")
    else:
        print(text)


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)

    try:
        config = _build_config(args)
        scanners = _select_scanners(args.scanner)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_USAGE

    available = [s for s in scanners if s.is_available()]
    if not available:
        print("error: no requested scanner is installed", file=sys.stderr)
        return EXIT_USAGE

    runner = MultiScanRunner(available, allowlist=set(args.allow or []))
    try:
        scan_id = runner.start_scan(Target(args.url), config)
    except TargetNotAuthorizedError as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return EXIT_USAGE

    timed_out = False
    try:
        status = runner.wait(scan_id, timeout=args.timeout)
        if args.timeout is not None and status["status"] in ("running", "stopped"):
            timed_out = True
    except KeyboardInterrupt:
        runner.stop_scan(scan_id)
        runner.wait(scan_id, timeout=_STOP_GRACE)
        _emit(runner, scan_id, args)
        return EXIT_INTERRUPT

    _emit(runner, scan_id, args)
    if timed_out:
        return EXIT_TIMEOUT
    overall = runner.get_status(scan_id)["status"]
    if overall in ("completed", "completed_with_warnings"):
        return EXIT_OK
    return EXIT_FINDINGS


if __name__ == "__main__":
    sys.exit(main())
