"""Nuclei adapter: builds the CLI command, streams JSONL output, normalizes each
line into a Finding, and reports a ScanOutcome (exit code + parse accounting)."""

from __future__ import annotations

import json
import shutil
import subprocess
import threading
import time
from collections import deque
from typing import Any

from ..models import Finding, ScanConfig, ScanOutcome, Severity, Target
from .base import OnFinding, OnWarning, Scanner, detect_version, stop_process_group


class NucleiScanner(Scanner):
    name = "nuclei"

    def __init__(self, binary: str = "nuclei") -> None:
        self.binary = binary

    def is_available(self) -> bool:
        if shutil.which(self.binary) is None:
            return False
        try:
            proc = subprocess.run(
                [self.binary, "-version"], capture_output=True, timeout=10
            )
            return proc.returncode == 0
        except (OSError, subprocess.SubprocessError):
            return False

    def _engine_version(self) -> str | None:
        if not hasattr(self, "_ev"):
            self._ev = detect_version(
                [self.binary, "-version"], r"Engine Version:\s*(v?[\d.]+)"
            )
        return self._ev

    def _template_version(self) -> str | None:
        if not hasattr(self, "_tv"):
            self._tv = detect_version(
                [self.binary, "-templates-version"], r"templates version:\s*(v?[\d.]+)"
            )
        return self._tv

    def _build_command(self, target: Target, config: ScanConfig) -> list[str]:
        # Safety invariants: no redirect-following off the authorized host, no
        # external OAST callbacks by default, and no automatic update check.
        cmd = [
            self.binary,
            "-u",
            target.url,
            "-jsonl",
            "-silent",
            "-no-color",
            "-disable-redirects",
            "-disable-update-check",
        ]
        if not config.enable_interactsh:
            cmd.append("-no-interactsh")
        if config.severities:
            cmd += ["-severity", ",".join(s.value for s in config.severities)]
        if config.tags:
            cmd += ["-tags", ",".join(config.tags)]
        if config.template_ids:
            cmd += ["-id", ",".join(config.template_ids)]
        if config.rate_limit is not None:
            cmd += ["-rate-limit", str(config.rate_limit)]
        if config.request_timeout is not None:
            cmd += ["-timeout", str(config.request_timeout)]
        return cmd

    def _to_finding(self, data: dict[str, Any]) -> Finding:
        info = data.get("info") or {}
        return Finding(
            scanner=self.name,
            finding_id=data.get("template-id", "unknown"),
            name=info.get("name", data.get("template-id", "unknown")),
            severity=Severity.from_str(info.get("severity")),
            matched_at=data.get("matched-at") or data.get("host", ""),
            description=info.get("description", "") or "",
            tags=info.get("tags", []) or [],
            raw=data,
        )

    def run(
        self,
        target: Target,
        config: ScanConfig,
        on_finding: OnFinding,
        stop_event: threading.Event | None = None,
        on_warning: OnWarning | None = None,
    ) -> ScanOutcome:
        cmd = self._build_command(target, config)
        try:
            proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, bufsize=1, start_new_session=True,
            )
        except OSError as exc:
            return ScanOutcome(
                exit_code=None, output_present=False, output_parseable=False,
                fatal=True, error=f"failed to launch nuclei: {exc}",
                scanner_version=self._engine_version(),
                template_version=self._template_version(),
            )

        stats = {"parsed": 0, "invalid": 0, "present": False}
        stderr_chunks: deque[str] = deque(maxlen=200)
        reader_error: list[Exception] = []

        def _warn(msg: str) -> None:
            if on_warning is not None:
                on_warning(msg)

        def _drain_stderr() -> None:
            assert proc.stderr is not None
            for line in proc.stderr:
                stderr_chunks.append(line[:4096])

        def _drain_stdout() -> None:
            assert proc.stdout is not None
            try:
                for line in proc.stdout:
                    line = line.strip()
                    if not line:
                        continue
                    stats["present"] = True
                    try:
                        data = json.loads(line)
                    except json.JSONDecodeError:
                        stats["invalid"] += 1
                        _warn(f"invalid JSONL skipped: {line[:200]!r}")
                        continue
                    if not isinstance(data, dict):
                        stats["invalid"] += 1  # valid JSON, not the expected object
                        _warn(f"non-object JSONL skipped: {line[:200]!r}")
                        continue
                    # Any failure converting or delivering a record makes it
                    # invalid; never let it escape (and vanish) in this thread.
                    try:
                        finding = self._to_finding(data)
                        on_finding(finding)
                    except Exception as exc:  # noqa: BLE001
                        stats["invalid"] += 1
                        _warn(f"record dropped ({type(exc).__name__}): {line[:200]!r}")
                        continue
                    stats["parsed"] += 1  # only after convert + deliver succeed
            except Exception as exc:  # catastrophic stream failure -> fatal
                reader_error.append(exc)

        err_thread = threading.Thread(target=_drain_stderr, daemon=True)
        out_thread = threading.Thread(target=_drain_stdout, daemon=True)
        err_thread.start()
        out_thread.start()

        stopped = False
        while proc.poll() is None:
            if stop_event is not None and stop_event.is_set():
                stopped = True
                stop_process_group(proc)
                break
            time.sleep(0.05)
        proc.wait()
        out_thread.join(timeout=5)
        err_thread.join(timeout=5)
        if proc.stdout is not None:
            proc.stdout.close()
        if proc.stderr is not None:
            proc.stderr.close()

        present = stats["present"]
        parsed = stats["parsed"]
        invalid = stats["invalid"]
        # A catastrophic reader failure, or non-empty output that yielded no
        # usable record, is a fatal parse error.
        fatal = (not stopped) and (bool(reader_error) or (present and parsed == 0))
        error = None
        if fatal:
            if reader_error:
                error = f"output reader failed: {reader_error[0]}"
            else:
                error = "".join(stderr_chunks).strip() or "no valid records parsed"
        return ScanOutcome(
            exit_code=proc.returncode,
            output_present=present,
            output_parseable=(not present) or parsed > 0,
            parsed_records=parsed,
            invalid_records=invalid,
            fatal=fatal,
            stopped=stopped,
            scanner_version=self._engine_version(),
            template_version=self._template_version(),
            error=error,
        )
