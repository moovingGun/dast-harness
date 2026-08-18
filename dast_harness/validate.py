"""Detection-accuracy validation against a controlled target.

Scans a target whose weaknesses are documented in a ground-truth file and
scores what the scanners actually reported:

    docker compose -f targets/compose.yml up -d --build
    python -m dast_harness.validate

Recall (documented weaknesses that were detected) is the only hard number here.
Findings that match no ground-truth entry are reported as *unexpected*, not as
false positives: the target may expose something the ground truth does not
claim, so they need human triage before being called wrong.

Exit codes: 0 every attempted weakness detected with no false positives,
1 something missed / not attempted / a `must_not_detect` endpoint reported,
2 usage error, 130 interrupted.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import dataclass, field
from urllib.parse import urlparse

# Imported as a module, not by name: cli.SCANNERS is the single scanner
# registry and tests rebind it, so the lookup has to stay late-bound.
from . import cli
from .agent_kit.auth import AuthConfigError, load_actors
from .agent_runner import AgentRunner, CombinedRunner
from .cli import EXIT_USAGE
from .ingest import IngestError, load_result
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
    # Endpoints that look suspicious but are sound. A finding matching one of
    # these is a false positive, not a detection — see `_false_positive`.
    must_not_detect: list[dict] = field(default_factory=list)


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
    traps = data.get("must_not_detect") or []
    if not isinstance(traps, list):
        raise ValueError(f"{path}: 'must_not_detect' must be a list")
    for entry in traps:
        missing = [k for k in ("id", "path", "match_any") if k not in entry]
        if missing:
            raise ValueError(
                f"{path}: must_not_detect entry {entry.get('id', '?')!r} is "
                f"missing {', '.join(missing)}"
            )
    return GroundTruth(target=data.get("target", ""), expected=expected,
                       must_not_detect=traps)


@dataclass
class EntryResult:
    """One documented weakness and the findings that evidence it."""

    id: str
    path: str
    category: str
    description: str
    findings: list[Finding] = field(default_factory=list)
    # Set when the weakness is only observable while signed in as this actor
    # and no such session was established. "안 찾아봄"은 "못 찾음"이 아니다.
    not_attempted: str = ""

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
            "not_attempted": self.not_attempted,
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
    # Findings that landed on a `must_not_detect` endpoint. These are wrong,
    # not merely undocumented — the whole point of those entries.
    false_positives: list[Finding] = field(default_factory=list)

    @property
    def detected_count(self) -> int:
        return sum(1 for e in self.entries if e.detected)

    def not_attempted(self) -> list[EntryResult]:
        return [e for e in self.entries if e.not_attempted]

    @property
    def attempted(self) -> list[EntryResult]:
        return [e for e in self.entries if not e.not_attempted]

    @property
    def recall(self) -> float:
        """Detected over **attempted**. Entries nobody could reach (no session)
        are excluded here and reported separately — folding them in would read
        as a detection failure when it was a setup gap."""
        attempted = self.attempted
        return (sum(1 for e in attempted if e.detected) / len(attempted)
                if attempted else 0.0)

    def missed(self) -> list[EntryResult]:
        return [e for e in self.entries if not e.detected and not e.not_attempted]

    def unexpected_by_severity(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for finding in self.unexpected:
            counts[finding.severity.value] = counts.get(finding.severity.value, 0) + 1
        return counts

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "expected_count": len(self.entries),
            "attempted_count": len(self.attempted),
            "detected_count": self.detected_count,
            "recall": round(self.recall, 4),
            "entries": [e.to_dict() for e in self.entries],
            "unexpected": [_finding_dict(f) for f in self.unexpected],
            "unexpected_by_severity": self.unexpected_by_severity(),
            "false_positives": [_finding_dict(f) for f in self.false_positives],
            "not_attempted": [e.id for e in self.not_attempted()],
        }


def _observed_path(finding: Finding) -> str:
    """The path a finding was observed at, or "" if it is not a URL."""
    return urlparse(finding.matched_at).path or ""


def _at_path(finding: Finding, path: str) -> bool:
    """Was this finding observed at (or under) `path`?

    A trailing slash means "this directory and below" — `/uploads/` covers
    `/uploads/db.tar.gz`. Otherwise the path must match exactly, so a finding
    at `/lookup` is not credited to an entry documented at `/search`.
    """
    observed = _observed_path(finding)
    if path.endswith("/") and path != "/":
        return observed == path or observed.startswith(path)
    return observed == path


def _false_positive(finding: Finding, traps: list[dict]) -> dict | None:
    """The `must_not_detect` entry this finding trips, or None.

    Checked **before** the expected list. Keyword matching alone credited a
    false positive at a sound endpoint to a real weakness elsewhere that shared
    vocabulary (`injection` at `/lookup` scoring as the `/search` SQLi), which
    made the trap reward exactly what it exists to catch.
    """
    haystack = f"{finding.finding_id} {finding.name}".lower()
    for trap in traps:
        if not _at_path(finding, trap["path"]):
            continue
        if any(keyword in haystack for keyword in trap["match_any"]):
            return trap
    return None


def _match(finding: Finding, expected: list[dict]) -> dict | None:
    """The ground-truth entry a finding evidences, or None.

    A finding credits an entry only when **both** hold: its id/name contains one
    of the entry's keywords, *and* it was observed at that entry's path. The
    first entry in ground-truth order wins, so files must list specific
    weaknesses before generic ones; a finding never credits two entries.

    The path check is not decoration. Keyword matching alone credited nuclei's
    `chamilo-lms-sqli` — fired at `/main/inc/ajax/extra_field.ajax.php`, a path
    this target does not serve — to the documented `/search` SQL injection,
    because both contain "sqli". That inflates recall with a finding about a
    different product at a nonexistent URL.
    """
    haystack = f"{finding.finding_id} {finding.name}".lower()
    for entry in expected:
        if not any(keyword in haystack for keyword in entry["match_any"]):
            continue
        if not _at_path(finding, entry["path"]):
            continue
        return entry
    return None


def score(findings: list[Finding], expected: list[dict],
          target: str = "", must_not_detect: list[dict] | None = None,
          actors: frozenset[str] = frozenset()) -> AccuracyReport:
    """Score findings against the ground truth.

    `actors` are the identities that actually had a live session. An entry
    marked `as_actor` that nobody could reach is reported as *not attempted*
    rather than missed — the difference between "the agent failed" and "the run
    never gave it a chance".
    """
    traps = must_not_detect or []
    results = {
        entry["id"]: EntryResult(
            id=entry["id"], path=entry["path"], category=entry["category"],
            description=entry["description"],
        )
        for entry in expected
    }
    unexpected: list[Finding] = []
    false_positives: list[Finding] = []
    for finding in findings:
        trap = _false_positive(finding, traps)
        if trap is not None:
            false_positives.append(finding)
            continue
        entry = _match(finding, expected)
        if entry is None:
            unexpected.append(finding)
        else:
            results[entry["id"]].findings.append(finding)

    for entry in expected:
        needed = entry.get("as_actor")
        result = results[entry["id"]]
        if needed and needed not in actors and not result.detected:
            result.not_attempted = needed

    return AccuracyReport(target=target, entries=list(results.values()),
                          unexpected=unexpected,
                          false_positives=false_positives)


def render(report: AccuracyReport) -> str:
    lines = []
    if report.target:
        lines.append(f"target: {report.target}")
    attempted = len(report.attempted)
    lines.append(
        f"detected {report.detected_count}/{attempted} attempted "
        f"weaknesses (recall {report.recall:.0%})"
        + (f"  —  {len(report.entries) - attempted} not attempted"
           if attempted != len(report.entries) else "")
    )
    lines.append("")
    width = max((len(e.id) for e in report.entries), default=0)
    for entry in report.entries:
        if entry.not_attempted:
            mark, detail = "-", f"NOT ATTEMPTED (needs actor {entry.not_attempted!r})"
        elif entry.detected:
            mark, detail = "x", ", ".join(entry.scanners)
        else:
            mark, detail = " ", "MISSED"
        lines.append(f"  [{mark}] {entry.id:<{width}}  {entry.path:<14} {detail}")

    lines.append("")
    if report.false_positives:
        # Not "unexpected" — the ground truth says these endpoints are sound,
        # so reporting them is wrong, and that is a hard number.
        lines.append(f"FALSE POSITIVES: {len(report.false_positives)}  "
                     f"(reported on an endpoint documented as sound)")
        for finding in report.false_positives:
            lines.append(f"  - [{finding.scanner}] {finding.name} "
                         f"@ {finding.matched_at}")
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
                        help="comma list of scanners and/or agents, e.g. "
                             "'nuclei,agent:recon' (default: all available scanners)")
    parser.add_argument("--auth", metavar="FILE",
                        help="agent auth scenario JSON; weaknesses documented with "
                             "'as_actor' can only be attempted with a live session")
    parser.add_argument("--ingest", metavar="FILE", action="append",
                        help="score findings from an agent result JSON instead of "
                             "running a scan (repeatable). This is how a Claude "
                             "subagent's output gets graded.")
    parser.add_argument("--timeout", type=float, help="whole-scan deadline (seconds)")
    parser.add_argument("--json", action="store_true", help="emit the report as JSON")
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)

    try:
        truth = load_ground_truth(args.ground_truth)
        actors = load_actors(args.auth) if args.auth else {}
        if args.ingest:
            if args.scanner:
                raise ValueError("--ingest scores a saved result; drop --scanner")
            scanners, agents = [], []
        else:
            scanners, agents = cli._select(args.scanner)
    except (OSError, ValueError, AuthConfigError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_USAGE

    if args.ingest:
        return _score_ingested(args, truth)

    url = args.target or truth.target
    if not url:
        print("error: no target URL (ground truth has none; pass --target)",
              file=sys.stderr)
        return EXIT_USAGE

    available = [s for s in scanners if s.is_available()]
    if not available and not agents:
        print("error: no requested scanner is installed", file=sys.stderr)
        return EXIT_USAGE

    children: dict[str, object] = {}
    if available:
        children["scanners"] = MultiScanRunner(available)
    if agents:
        children["agents"] = AgentRunner(agents, actors=actors)
    runner = (next(iter(children.values())) if len(children) == 1
              else CombinedRunner(children))
    try:
        scan_id = runner.start_scan(Target(url), ScanConfig())
    except TargetNotAuthorizedError as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return EXIT_USAGE

    sources = [s.name for s in available] + [f"agent:{a.name}" for a in agents]
    print(f"scanning {url} with {', '.join(sources)} ...", file=sys.stderr)
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

    report = score(runner.get_results(scan_id), truth.expected, target=url,
                   must_not_detect=truth.must_not_detect,
                   actors=_live_actors(runner, scan_id))
    return _emit(report, args)


def _live_actors(runner, scan_id) -> frozenset[str]:
    """Identities that actually authenticated, read back from the run.

    Taken from the result rather than from the config on purpose: an actor that
    was configured but failed `verify` never had a session, and crediting it
    would turn a setup failure into a detection failure.
    """
    agents = runner.get_status(scan_id).get("agents") or {}
    return frozenset(
        name
        for record in agents.values()
        for name, auth in (record.get("auth") or {}).items()
        if auth.get("ok")
    )


def _score_ingested(args, truth: GroundTruth) -> int:
    """Score findings a subagent already produced, without touching the target."""
    findings: list[Finding] = []
    for path in args.ingest:
        try:
            with open(path, encoding="utf-8") as fh:
                result = load_result(json.load(fh))
        except (OSError, json.JSONDecodeError) as exc:
            print(f"error: {path}: {exc}", file=sys.stderr)
            return EXIT_USAGE
        except IngestError as exc:
            # A result that fails the contract is not scored at all — grading a
            # malformed finding would report accuracy for something the harness
            # would never have accepted.
            print(f"error: {path}: {exc}", file=sys.stderr)
            return EXIT_USAGE
        findings.extend(result.findings)

    url = args.target or truth.target
    print(f"scoring {len(findings)} finding(s) from {len(args.ingest)} file(s) ...",
          file=sys.stderr)
    report = score(findings, truth.expected, target=url,
                   must_not_detect=truth.must_not_detect,
                   actors=_ingested_actors(findings))
    return _emit(report, args)


def _ingested_actors(findings: list[Finding]) -> frozenset[str]:
    """Identities visible in the evidence. A saved result has no live session to
    ask, so the exchanges are the only honest source."""
    actors = set()
    for finding in findings:
        evidence = getattr(finding, "evidence", None)
        for exchange in getattr(evidence, "exchanges", None) or ():
            if exchange.actor and exchange.actor != "anon":
                actors.add(exchange.actor)
    return frozenset(actors)


def _emit(report: AccuracyReport, args) -> int:
    print(json.dumps(report.to_dict(), indent=2) if args.json else render(report))
    if report.missed() or report.not_attempted() or report.false_positives:
        return EXIT_MISSED
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
