"""Nuclei adapter: builds the CLI command, streams JSONL output, and normalizes
each line into a scanner-agnostic Finding."""

from __future__ import annotations

import json
import shutil
import subprocess
import threading
import time
from collections import deque
from typing import Any

from ..models import Finding, ScanConfig, Severity, Target
from .base import OnFinding, Scanner, ScannerExecutionError


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

        # Drain both pipes in side threads. The controlling thread can then poll
        # stop_event even while nuclei is producing no findings on stdout.
        stderr_chunks: deque[str] = deque(maxlen=200)
        reader_errors: list[Exception] = []

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
                    try:
                        data = json.loads(line)
                    except json.JSONDecodeError as exc:
                        raise RuntimeError(
                            f"nuclei emitted invalid JSONL: {line[:200]!r}"
                        ) from exc
                    if not isinstance(data, dict):
                        raise RuntimeError(
                            "nuclei emitted a JSONL value that is not an object"
                        )
                    on_finding(self._to_finding(data))
            except Exception as exc:  # propagate reader/callback failures below
                reader_errors.append(exc)

        err_thread = threading.Thread(target=_drain_stderr, daemon=True)
        out_thread = threading.Thread(target=_drain_stdout, daemon=True)
        err_thread.start()
        out_thread.start()

        stopped = False
        try:
            while proc.poll() is None:
                if stop_event is not None and stop_event.is_set():
                    stopped = True
                    break
                if reader_errors:
                    break
                time.sleep(0.05)

            if (stopped or reader_errors) and proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=5)
            else:
                proc.wait()
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=5)
            out_thread.join(timeout=5)
            err_thread.join(timeout=5)
            if proc.stdout is not None:
                proc.stdout.close()
            if proc.stderr is not None:
                proc.stderr.close()

        if out_thread.is_alive() or err_thread.is_alive():
            raise RuntimeError("nuclei output reader did not stop cleanly")
        if reader_errors:
            raise reader_errors[0]
        if proc.returncode is None:
            raise RuntimeError("nuclei exited without a return code")
        if proc.returncode != 0 and not stopped:
            detail = "".join(stderr_chunks).strip()
            suffix = f": {detail}" if detail else ""
            raise ScannerExecutionError(
                f"nuclei exited with code {proc.returncode}{suffix}",
                proc.returncode,
            )
        return proc.returncode
