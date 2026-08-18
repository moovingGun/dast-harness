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
import math
import sys

from .agent_kit.auth import AuthConfigError, load_actors
from .agent_kit.recon import ReconAgent
from .agent_runner import AgentRunner, CombinedRunner
from . import ingest, probe
from .models import ScanConfig, Severity, Target
from .orchestrator import MultiScanRunner
from .reporters import ConsoleReporter, JSONReporter, build_report
from .safety import TargetNotAuthorizedError
from .scanners.nikto import NiktoScanner
from .scanners.nuclei import NucleiScanner

# name -> factory. Tests monkeypatch this to inject fakes.
SCANNERS = {"nuclei": NucleiScanner, "nikto": NiktoScanner}

# Agents are selected through the same --scanner flag, prefixed with AGENT_PREFIX
# ("-s agent:recon"). That prefix is not a CLI invention: the finding contract
# already requires an agent's `scanner` value to be f"agent:{name}", so the
# selector and the reported source are the same string.
AGENTS = {"recon": ReconAgent}
AGENT_PREFIX = "agent:"

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
    probe.add_arguments(sub)
    ingest.add_arguments(sub)
    scan = sub.add_parser("scan", help="scan a local/allowlisted target")
    scan.add_argument("url", help="target URL (http/https)")
    scan.add_argument(
        "-s", "--scanner",
        help="comma list of scanners and/or agents, e.g. 'nuclei,agent:recon' "
             "(default: all available scanners, no agents)",
    )
    scan.add_argument(
        "--allow", action="append", metavar="HOST",
        help="allowlist a host (repeatable)",
    )
    scan.add_argument(
        "--auth", metavar="FILE",
        help="agent auth scenario (JSON): identities to scan as. Each needs a "
             "'verify' block, so a dead session fails loudly instead of "
             "silently scanning logged out",
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


def _select(spec: str | None):
    """Split the --scanner value into scanner instances and agent classes.

    Omitting --scanner selects every installed scanner and *no* agents: an agent
    picks its next URL from what the target sends back, so it is only ever
    turned on by name, never implicitly.
    """
    if not spec:
        return [SCANNERS[n]() for n in SCANNERS], []

    scanner_names: list[str] = []
    agent_names: list[str] = []
    unknown: list[str] = []
    for name in [n for n in _csv(spec) if n]:
        if name.startswith(AGENT_PREFIX):
            bare = name[len(AGENT_PREFIX):]
            if bare in AGENTS:
                agent_names.append(bare)
            else:
                unknown.append(name)   # echo it back as typed, prefix included
        elif name in SCANNERS:
            scanner_names.append(name)
        else:
            unknown.append(name)
    if unknown:
        raise ValueError(
            f"unknown scanner(s): {', '.join(unknown)} "
            f"(available: {', '.join(SCANNERS)}"
            + (f", {', '.join(AGENT_PREFIX + a for a in AGENTS)}" if AGENTS else "")
            + ")"
        )
    return (
        [SCANNERS[n]() for n in dict.fromkeys(scanner_names)],   # dedupe, keep order
        [AGENTS[n] for n in dict.fromkeys(agent_names)],
    )


def _emit(runner, scan_id, args) -> bool:
    """Render and output the report. Returns False (and reports to stderr) if
    writing the output file failed, without printing a partial success."""
    report = build_report(runner, scan_id)
    if args.format == "json":
        text = JSONReporter(include_raw=args.include_raw).render(report)
    else:
        text = ConsoleReporter().render(report)
    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as fh:
                fh.write(text + "\n")
        except OSError as exc:
            print(f"error: cannot write output file {args.output!r}: {exc}",
                  file=sys.stderr)
            return False
        print(f"wrote {args.output}")
    else:
        print(text)
    return True


def _validate_options(args) -> str | None:
    """Return an error message for an invalid option combination, else None."""
    if args.include_raw and args.format != "json":
        return "--include-raw requires --format json"
    if args.timeout is not None and (
        not math.isfinite(args.timeout) or args.timeout <= 0
    ):
        return "--timeout must be a finite positive number"
    return None


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)

    if args.command == "probe":
        return probe.run(args)
    if args.command == "ingest":
        return ingest.run(args)

    option_error = _validate_options(args)
    if option_error is not None:
        print(f"error: {option_error}", file=sys.stderr)
        return EXIT_USAGE

    try:
        config = _build_config(args)
        scanners, agents = _select(args.scanner)
        # Read the scenario before anything starts: a bad file surfacing
        # mid-scan would leave half a run behind.
        actors = load_actors(args.auth) if args.auth else {}
    except (ValueError, AuthConfigError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_USAGE

    if actors and not agents:
        print("error: --auth only applies to agents; select one with "
              "-s agent:<name>", file=sys.stderr)
        return EXIT_USAGE

    if args.scanner is not None:
        # Explicitly requested scanners must all be installed; do not silently
        # run a subset. (Omitting --scanner keeps the "available only" policy.)
        missing = [s.name for s in scanners if not s.is_available()]
        if missing:
            print(f"error: requested scanner(s) not installed: "
                  f"{', '.join(missing)}", file=sys.stderr)
            return EXIT_USAGE

    available = [s for s in scanners if s.is_available()]
    if not available and not agents:
        print("error: no requested scanner is installed", file=sys.stderr)
        return EXIT_USAGE

    allowlist = set(args.allow or [])
    children: dict[str, object] = {}
    if available:
        children["scanners"] = MultiScanRunner(available, allowlist=allowlist)
    if agents:
        children["agents"] = AgentRunner(agents, allowlist=allowlist,
                                         actors=actors)
    # With a single child, use it directly — no merging layer where there is
    # nothing to merge, so the scanner-only path stays exactly as it was.
    runner = (
        next(iter(children.values())) if len(children) == 1
        else CombinedRunner(children, allowlist=allowlist)
    )
    try:
        scan_id = runner.start_scan(Target(args.url), config)
    except TargetNotAuthorizedError as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return EXIT_USAGE

    try:
        runner.wait(scan_id, timeout=args.timeout)
    except KeyboardInterrupt:
        runner.stop_scan(scan_id)
        runner.wait(scan_id, timeout=_STOP_GRACE)
        _emit(runner, scan_id, args)
        return EXIT_INTERRUPT

    if not _emit(runner, scan_id, args):
        return EXIT_USAGE

    # A timeout that expired wins even if the final status became 'completed'
    # during the grace window (explicit signal from the runner, not a guess).
    if runner.timed_out(scan_id):
        return EXIT_TIMEOUT
    overall = runner.get_status(scan_id)["status"]
    if overall in ("completed", "completed_with_warnings"):
        return EXIT_OK
    return EXIT_FINDINGS


if __name__ == "__main__":
    sys.exit(main())
