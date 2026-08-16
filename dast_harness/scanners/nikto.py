"""Nikto adapter.

Nikto writes a single JSON document at the end of the run, so this adapter runs
Nikto to completion (honoring stop), then parses the result file and reports a
ScanOutcome. A missing / empty / unparseable / wrong-shape file is fatal. Nikto
has no severity concept, so every finding is Severity.UNKNOWN.
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
from urllib.parse import urljoin

from ..models import Finding, ScanConfig, ScanOutcome, Severity, Target
from .base import OnFinding, OnWarning, Scanner, detect_version, stop_process_group


class NiktoScanner(Scanner):
    name = "nikto"

    def __init__(self, binary: str = "nikto") -> None:
        self.binary = binary

    def is_available(self) -> bool:
        if shutil.which(self.binary) is None:
            return False
        try:
            proc = subprocess.run(
                [self.binary, "-Version"], capture_output=True, timeout=30
            )
            return proc.returncode == 0
        except (OSError, subprocess.SubprocessError):
            return False

    def _version(self) -> str | None:
        if not hasattr(self, "_ver"):
            self._ver = detect_version([self.binary, "-Version"], r"Nikto\s+([\d.]+)")
        return self._ver

    def _build_command(
        self, target: Target, config: ScanConfig, output_path: str
    ) -> list[str]:
        # -nocheck blocks the startup update check; -ask no never prompts.
        # nuclei-specific ScanConfig fields have no Nikto equivalent.
        cmd = [
            self.binary,
            "-h",
            target.url,
            "-Format",
            "json",
            "-output",
            output_path,
            "-nocheck",
            "-ask",
            "no",
        ]
        if config.request_timeout is not None:
            cmd += ["-timeout", str(config.request_timeout)]
        return cmd

    def _to_finding(
        self, vuln: dict[str, Any], host_meta: dict[str, Any], base_url: str
    ) -> Finding:
        url_path = vuln.get("url", "") or ""
        matched_at = urljoin(base_url, url_path) if url_path else base_url
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
            # preserve both the raw vulnerability and the host metadata
            raw={"vulnerability": vuln, "host": host_meta},
        )

    def _parse_file(
        self,
        path: str,
        base_url: str,
        on_finding: OnFinding,
        on_warning: OnWarning | None,
    ) -> dict:
        """Parse Nikto's JSON result file. A valid file is required; anything
        missing/empty/unparseable/wrong-shape is fatal."""
        result = {
            "output_present": False,
            "output_parseable": False,
            "parsed_records": 0,
            "invalid_records": 0,
            "fatal": True,
            "error": None,
        }
        if not os.path.exists(path):
            result["error"] = "nikto result file is missing"
            return result
        with open(path, encoding="utf-8", errors="replace") as fh:
            text = fh.read().strip()
        result["output_present"] = True
        if not text:
            result["error"] = "nikto result file is empty"
            return result
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            result["error"] = "nikto result file is not valid JSON"
            return result

        if isinstance(data, list):
            hosts = data
        elif isinstance(data, dict):
            hosts = [data]
        else:
            result["error"] = "nikto JSON is not a host list/object"
            return result

        # Validate the whole document first; deliver findings only if no host
        # violates the schema, so a later fatal error can't leave partial results.
        pending: list[Finding] = []
        for host in hosts:
            if not isinstance(host, dict):
                result["error"] = "nikto host record is not an object"
                return result
            if "vulnerabilities" in host:
                vulns = host["vulnerabilities"]
            elif "vulns" in host:
                vulns = host["vulns"]
            else:
                result["error"] = "nikto host is missing a vulnerabilities field"
                return result
            if not isinstance(vulns, list):
                result["error"] = "nikto vulnerabilities field is not a list"
                return result
            host_meta = {
                k: v for k, v in host.items() if k not in ("vulnerabilities", "vulns")
            }
            for vuln in vulns:
                if not isinstance(vuln, dict):
                    result["invalid_records"] += 1
                    if on_warning is not None:
                        on_warning("nikto vulnerability entry was not an object")
                    continue
                pending.append(self._to_finding(vuln, host_meta, base_url))

        result["output_parseable"] = True
        result["fatal"] = False
        for finding in pending:
            on_finding(finding)
            result["parsed_records"] += 1
        return result

    def run(
        self,
        target: Target,
        config: ScanConfig,
        on_finding: OnFinding,
        stop_event: threading.Event | None = None,
        on_warning: OnWarning | None = None,
    ) -> ScanOutcome:
        tmp_dir = tempfile.mkdtemp(prefix="nikto-")
        output_path = os.path.join(tmp_dir, "nikto.json")
        cmd = self._build_command(target, config, output_path)

        try:
            proc = subprocess.Popen(
                cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True,
                start_new_session=True,
            )
        except OSError as exc:
            return ScanOutcome(
                exit_code=None, output_present=False, output_parseable=False,
                fatal=True, error=f"failed to launch nikto: {exc}",
                scanner_version=self._version(),
            )

        stderr_chunks: deque[str] = deque(maxlen=200)

        def _drain_stderr() -> None:
            assert proc.stderr is not None
            for line in proc.stderr:
                stderr_chunks.append(line[:4096])

        err_thread = threading.Thread(target=_drain_stderr, daemon=True)
        err_thread.start()

        stopped = False
        while proc.poll() is None:
            if stop_event is not None and stop_event.is_set():
                stopped = True
                stop_process_group(proc)
                break
            time.sleep(0.05)
        proc.wait()
        err_thread.join(timeout=5)
        if proc.stderr is not None:
            proc.stderr.close()

        try:
            if stopped:
                return ScanOutcome(
                    exit_code=proc.returncode, output_present=False,
                    output_parseable=False, stopped=True,
                    scanner_version=self._version(),
                )
            parsed = self._parse_file(output_path, target.url, on_finding, on_warning)
            error = parsed["error"]
            if error is None and stderr_chunks and proc.returncode not in (0, None):
                error = "".join(stderr_chunks).strip() or None
            return ScanOutcome(
                exit_code=proc.returncode,
                output_present=parsed["output_present"],
                output_parseable=parsed["output_parseable"],
                parsed_records=parsed["parsed_records"],
                invalid_records=parsed["invalid_records"],
                fatal=parsed["fatal"],
                stopped=False,
                scanner_version=self._version(),
                error=error,
            )
        finally:
            for path in (output_path,):
                try:
                    os.remove(path)
                except OSError:
                    pass
            try:
                os.rmdir(tmp_dir)
            except OSError:
                pass
