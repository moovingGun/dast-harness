"""Nuclei adapter: builds the CLI command, streams JSONL output, and normalizes
each line into a scanner-agnostic Finding."""

from __future__ import annotations

import json
import shutil
import subprocess
import threading
from typing import Any

from ..models import Finding, ScanConfig, Severity, Target
from .base import OnFinding, Scanner


class NucleiScanner(Scanner):
    name = "nuclei"

    def __init__(self, binary: str = "nuclei") -> None:
        self.binary = binary

    def is_available(self) -> bool:
        if shutil.which(self.binary) is None:
            return False
        try:
            proc = subprocess.run(
                [self.binary, "-version"],
                capture_output=True,
                timeout=10,
            )
            return proc.returncode == 0
        except (OSError, subprocess.SubprocessError):
            return False

    def _build_command(self, target: Target, config: ScanConfig) -> list[str]:
        cmd = [self.binary, "-u", target.url, "-jsonl", "-silent", "-no-color"]
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
        cmd += config.extra_args
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
    ) -> int:
        cmd = self._build_command(target, config)
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )

        # Drain stderr in a side thread so a full pipe buffer can't deadlock us
        # while we read stdout.
        stderr_chunks: list[str] = []

        def _drain_stderr() -> None:
            assert proc.stderr is not None
            for line in proc.stderr:
                stderr_chunks.append(line)

        err_thread = threading.Thread(target=_drain_stderr, daemon=True)
        err_thread.start()

        assert proc.stdout is not None
        try:
            for line in proc.stdout:
                if stop_event is not None and stop_event.is_set():
                    proc.terminate()
                    break
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                except json.JSONDecodeError:
                    continue  # skip any non-JSON banner/noise
                on_finding(self._to_finding(data))
        finally:
            proc.wait()
            err_thread.join(timeout=5)

        if proc.returncode not in (0, None) and stderr_chunks:
            # Surface stderr via exception so the runner can record it.
            raise RuntimeError(
                f"nuclei exited with code {proc.returncode}: "
                + "".join(stderr_chunks).strip()
            )
        return proc.returncode
