"""Detection-accuracy validation against a controlled target.

Scans a target whose weaknesses are documented in a ground-truth file and
scores what the scanners actually reported:

    docker compose -f targets/compose.yml up -d --build
    python -m dast_harness.validate

Recall (documented weaknesses that were detected) is the only hard number here.
Findings that match no ground-truth entry are reported as *unexpected*, not as
false positives: the target may expose something the ground truth does not
claim, so they need human triage before being called wrong.

Exit codes: 0 every weakness detected, 1 at least one missed, 2 usage error,
130 interrupted.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import dataclass, field

# Imported as a module, not by name: cli.SCANNERS is the single scanner
# registry and tests rebind it, so the lookup has to stay late-bound.
from . import cli
from .cli import EXIT_USAGE
from .models import Finding, ScanConfig, Target
from .orchestrator import MultiScanRunner
from .safety import TargetNotAuthorizedError

EXIT_OK = 0
EXIT_MISSED = 1
EXIT_INTERRUPT = 130

DEFAULT_GROUND_TRUTH = os.path.join("targets", "vulnerable_app", "ground_truth.json")
REQUIRED_KEYS = ("id", "path", "category", "description", "match_any")

_STOP_GRACE = 5.0


@dataclass(frozen=True)
class GroundTruth:
    target: str
    expected: list[dict]


def load_ground_truth(path: str) -> GroundTruth:
    """Read and validate a ground-truth file. Raises ValueError if malformed."""
    with open(path, encoding="utf-8") as fh:
        try:
            data = json.load(fh)
        except json.JSONDecodeError as exc:
            raise ValueError(f"{path}: invalid JSON: {exc}") from exc

    expected = data.get("expected")
    if not isinstance(expected, list) or not expected:
        raise ValueError(f"{path}: 'expected' must be a non-empty list")
    for entry in expected:
        missing = [k for k in REQUIRED_KEYS if k not in entry]
        if missing:
            raise ValueError(
                f"{path}: entry {entry.get('id', '?')!r} is missing "
                f"{', '.join(missing)}"
            )
    return GroundTruth(target=data.get("target", ""), expected=expected)


@dataclass
class EntryResult:
    """One documented weakness and the findings that evidence it."""

    id: str
    path: str
    category: str
    description: str
    findings: list[Finding] = field(default_factory=list)

    @property
    def detected(self) -> bool:
        return bool(self.findings)

    @property
    def scanners(self) -> list[str]:
        return sorted({f.scanner for f in self.findings})

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "path": self.path,
            "category": self.category,
            "description": self.description,
            "detected": self.detected,
            "scanners": self.scanners,
            "findings": [_finding_dict(f) for f in self.findings],
        }


def _finding_dict(finding: Finding) -> dict:
    return {
        "scanner": finding.scanner,
        "finding_id": finding.finding_id,
        "name": finding.name,
        "severity": finding.severity.value,
        "matched_at": finding.matched_at,
    }


@dataclass
class AccuracyReport:
    target: str
    entries: list[EntryResult]
    unexpected: list[Finding]

    @property
    def detected_count(self) -> int:
        return sum(1 for e in self.entries if e.detected)

    @property
    def recall(self) -> float:
        return self.detected_count / len(self.entries) if self.entries else 0.0

    def missed(self) -> list[EntryResult]:
        return [e for e in self.entries if not e.detected]

    def unexpected_by_severity(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for finding in self.unexpected:
            counts[finding.severity.value] = counts.get(finding.severity.value, 0) + 1
        return counts

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "expected_count": len(self.entries),
            "detected_count": self.detected_count,
            "recall": round(self.recall, 4),
            "entries": [e.to_dict() for e in self.entries],
            "unexpected": [_finding_dict(f) for f in self.unexpected],
            "unexpected_by_severity": self.unexpected_by_severity(),
        }


def _match(finding: Finding, expected: list[dict]) -> dict | None:
    """The ground-truth entry a finding evidences, or None.

    Matching is keyword-based on the finding's id and name. The first entry in
    ground-truth order wins, so files must list specific weaknesses before
    generic ones; a finding never credits two entries.
    """
    haystack = f"{finding.finding_id} {finding.name}".lower()
    for entry in expected:
        if any(keyword in haystack for keyword in entry["match_any"]):
            return entry
    return None


def score(findings: list[Finding], expected: list[dict],
          target: str = "") -> AccuracyReport:
    results = {
        entry["id"]: EntryResult(
            id=entry["id"], path=entry["path"], category=entry["category"],
            description=entry["description"],
        )
        for entry in expected
    }
    unexpected: list[Finding] = []
    for finding in findings:
        entry = _match(finding, expected)
        if entry is None:
            unexpected.append(finding)
        else:
            results[entry["id"]].findings.append(finding)
    return AccuracyReport(target=target, entries=list(results.values()),
                          unexpected=unexpected)


def render(report: AccuracyReport) -> str:
    lines = []
    if report.target:
        lines.append(f"target: {report.target}")
    lines.append(
        f"detected {report.detected_count}/{len(report.entries)} documented "
        f"weaknesses (recall {report.recall:.0%})"
    )
    lines.append("")
    width = max((len(e.id) for e in report.entries), default=0)
    for entry in report.entries:
        mark = "x" if entry.detected else " "
        detail = ", ".join(entry.scanners) if entry.detected else "MISSED"
        lines.append(f"  [{mark}] {entry.id:<{width}}  {entry.path:<14} {detail}")

    lines.append("")
    if report.unexpected:
        by_sev = ", ".join(f"{k}: {v}" for k, v in
                           sorted(report.unexpected_by_severity().items()))
        lines.append(f"unexpected findings (manual triage needed): "
                     f"{len(report.unexpected)}  [{by_sev}]")
        for finding in report.unexpected:
            lines.append(f"  - [{finding.scanner}] {finding.name} "
                         f"@ {finding.matched_at}")
    else:
        lines.append("unexpected findings: 0")
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m dast_harness.validate",
        description="Score scanner detections against a target's ground truth.",
    )
    parser.add_argument("--ground-truth", default=DEFAULT_GROUND_TRUTH,
                        help=f"ground-truth JSON (default: {DEFAULT_GROUND_TRUTH})")
    parser.add_argument("--target", help="override the URL from the ground-truth file")
    parser.add_argument("-s", "--scanner",
                        help="comma list of scanners (default: all available)")
    parser.add_argument("--timeout", type=float, help="whole-scan deadline (seconds)")
    parser.add_argument("--json", action="store_true", help="emit the report as JSON")
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)

    try:
        truth = load_ground_truth(args.ground_truth)
        scanners = cli._select_scanners(args.scanner)
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_USAGE

    url = args.target or truth.target
    if not url:
        print("error: no target URL (ground truth has none; pass --target)",
              file=sys.stderr)
        return EXIT_USAGE

    available = [s for s in scanners if s.is_available()]
    if not available:
        print("error: no requested scanner is installed", file=sys.stderr)
        return EXIT_USAGE

    runner = MultiScanRunner(available)
    try:
        scan_id = runner.start_scan(Target(url), ScanConfig())
    except TargetNotAuthorizedError as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return EXIT_USAGE

    print(f"scanning {url} with {', '.join(s.name for s in available)} ...",
          file=sys.stderr)
    try:
        runner.wait(scan_id, timeout=args.timeout)
    except KeyboardInterrupt:
        runner.stop_scan(scan_id)
        runner.wait(scan_id, timeout=_STOP_GRACE)
        return EXIT_INTERRUPT

    status = runner.get_status(scan_id)
    # Scan health goes to stderr so --json stdout stays machine-readable; a
    # failed scan makes a low recall a tooling artifact, not a detection result.
    print(f"scan status: {status['status']}", file=sys.stderr)

    report = score(runner.get_results(scan_id), truth.expected, target=url)
    print(json.dumps(report.to_dict(), indent=2) if args.json else render(report))
    return EXIT_OK if not report.missed() else EXIT_MISSED


if __name__ == "__main__":
    sys.exit(main())
