"""Nikto adapter.

Unlike nuclei, Nikto does not stream structured results: it writes a single
JSON document at the end of the run. So this adapter runs Nikto to completion
(while still honoring stop requests), then parses the output file and delivers
all findings through `on_finding` at once. Nikto has no severity concept, so
every finding is normalized to Severity.UNKNOWN.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import threading
import time
from collections import deque
from typing import Any

from ..models import Finding, ScanConfig, Severity, Target
from .base import OnFinding, OnWarning, Scanner, ScannerExecutionError


class NiktoScanner(Scanner):
    name = "nikto"

    def __init__(self, binary: str = "nikto") -> None:
        self.binary = binary

    def is_available(self) -> bool:
        if shutil.which(self.binary) is None:
            return False
        try:
            proc = subprocess.run(
                [self.binary, "-Version"],
                capture_output=True,
                timeout=30,
            )
            return proc.returncode == 0
        except (OSError, subprocess.SubprocessError):
            return False

    def _build_command(
        self, target: Target, config: ScanConfig, output_path: str
    ) -> list[str]:
        # nuclei-specific ScanConfig fields (severities/tags/template_ids) have no
        # Nikto equivalent and are intentionally ignored here.
        cmd = [
            self.binary,
            "-h",
            target.url,
            "-Format",
            "json",
            "-output",
            output_path,
            "-ask",
            "no",  # never prompt to submit updates
        ]
        if config.request_timeout is not None:
            cmd += ["-timeout", str(config.request_timeout)]
        return cmd

    def _to_finding(self, vuln: dict[str, Any], base_url: str) -> Finding:
        url_path = vuln.get("url", "") or ""
        matched_at = base_url.rstrip("/") + url_path if url_path else base_url
        message = (vuln.get("msg") or "").strip()
        finding_id = str(vuln.get("id") or vuln.get("OSVDB") or "unknown")
        return Finding(
            scanner=self.name,
            finding_id=finding_id,
            name=message[:120] or f"nikto/{finding_id}",
            severity=Severity.UNKNOWN,  # Nikto does not assign severities
            matched_at=matched_at,
            description=message,
            tags=[],
            raw=vuln,
        )

    def _parse_output(
        self,
        path: str,
        base_url: str,
        on_finding: OnFinding,
        on_warning: OnWarning | None,
    ) -> None:
        if not os.path.exists(path):
            if on_warning is not None:
                on_warning("nikto produced no output file")
            return
        with open(path, encoding="utf-8", errors="replace") as fh:
            text = fh.read().strip()
        if not text:
            return  # no findings is a valid, empty result
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            if on_warning is not None:
                on_warning(f"nikto emitted invalid JSON: {text[:200]!r}")
            return
        hosts = data if isinstance(data, list) else [data]
        for host in hosts:
            if not isinstance(host, dict):
                continue
            vulns = host.get("vulnerabilities") or host.get("vulns") or []
            for vuln in vulns:
                if isinstance(vuln, dict):
                    on_finding(self._to_finding(vuln, base_url))

    def run(
        self,
        target: Target,
        config: ScanConfig,
        on_finding: OnFinding,
        stop_event: threading.Event | None = None,
        on_warning: OnWarning | None = None,
    ) -> int:
        tmp_dir = tempfile.mkdtemp(prefix="nikto-")
        output_path = os.path.join(tmp_dir, "nikto.json")
        cmd = self._build_command(target, config, output_path)

        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,  # human progress text; we read the JSON file
            stderr=subprocess.PIPE,
            text=True,
        )

        stderr_chunks: deque[str] = deque(maxlen=200)

        def _drain_stderr() -> None:
            assert proc.stderr is not None
            for line in proc.stderr:
                stderr_chunks.append(line[:4096])

        err_thread = threading.Thread(target=_drain_stderr, daemon=True)
        err_thread.start()

        stopped = False
        try:
            while proc.poll() is None:
                if stop_event is not None and stop_event.is_set():
                    stopped = True
                    break
                time.sleep(0.05)

            if stopped and proc.poll() is None:
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
            err_thread.join(timeout=5)
            if proc.stderr is not None:
                proc.stderr.close()

        try:
            if not stopped:
                self._parse_output(output_path, target.url, on_finding, on_warning)
        finally:
            try:
                os.remove(output_path)
            except OSError:
                pass
            try:
                os.rmdir(tmp_dir)
            except OSError:
                pass

        if proc.returncode is None:
            raise RuntimeError("nikto exited without a return code")
        if proc.returncode != 0 and not stopped:
            detail = "".join(stderr_chunks).strip()
            suffix = f": {detail}" if detail else ""
            raise ScannerExecutionError(
                f"nikto exited with code {proc.returncode}{suffix}",
                proc.returncode,
            )
        return proc.returncode
