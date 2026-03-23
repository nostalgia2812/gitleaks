#!/usr/bin/env python3
"""
Ghost AI — Gitleaks Bridge
Sentinel Dark OSINT + Secret Scanning backend integration.
NO wallet integration.
"""
from __future__ import annotations
import json
import subprocess
import tempfile
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


@dataclass
class GitleaksFinding:
    rule_id: str
    description: str
    file: str
    line_start: int
    line_end: int
    secret_snippet: str  # redacted by gitleaks
    commit: str
    author: str
    date: str
    severity: str = "high"

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "description": self.description,
            "file": self.file,
            "line_start": self.line_start,
            "secret_snippet": self.secret_snippet[:8] + "***",
            "commit": self.commit[:8],
            "author": self.author,
            "date": self.date,
            "severity": self.severity,
        }


class GitleaksBridge:
    """
    Ghost AI bridge to gitleaks binary.
    Runs gitleaks scans and returns structured findings.
    """

    def __init__(self, gitleaks_bin: str = "gitleaks") -> None:
        self.bin = gitleaks_bin
        self._check_binary()

    def _check_binary(self) -> None:
        try:
            result = subprocess.run(
                [self.bin, "version"],
                capture_output=True, text=True, timeout=5
            )
            self.version = result.stdout.strip()
        except FileNotFoundError:
            self.version = "not installed"

    def scan_directory(self, path: str, config: Optional[str] = None) -> list[GitleaksFinding]:
        """Scan a local directory for secrets."""
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
            report_path = tmp.name

        cmd = [
            self.bin, "detect",
            "--source", path,
            "--report-format", "json",
            "--report-path", report_path,
            "--exit-code", "0",
            "--no-git",
        ]
        if config:
            cmd += ["--config", config]

        subprocess.run(cmd, capture_output=True, timeout=120)

        findings = []
        try:
            with open(report_path) as f:
                data = json.load(f)
            for item in (data or []):
                findings.append(GitleaksFinding(
                    rule_id=item.get("RuleID", "unknown"),
                    description=item.get("Description", ""),
                    file=item.get("File", ""),
                    line_start=item.get("StartLine", 0),
                    line_end=item.get("EndLine", 0),
                    secret_snippet=item.get("Secret", ""),
                    commit=item.get("Commit", ""),
                    author=item.get("Author", ""),
                    date=item.get("Date", ""),
                ))
        except (json.JSONDecodeError, FileNotFoundError):
            pass
        finally:
            Path(report_path).unlink(missing_ok=True)

        return findings

    def scan_git_repo(self, repo_path: str) -> list[GitleaksFinding]:
        """Full git history scan."""
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
            report_path = tmp.name

        cmd = [
            self.bin, "detect",
            "--source", repo_path,
            "--report-format", "json",
            "--report-path", report_path,
            "--exit-code", "0",
        ]
        subprocess.run(cmd, capture_output=True, cwd=repo_path, timeout=300)

        findings = []
        try:
            with open(report_path) as f:
                data = json.load(f)
            for item in (data or []):
                findings.append(GitleaksFinding(
                    rule_id=item.get("RuleID", "unknown"),
                    description=item.get("Description", ""),
                    file=item.get("File", ""),
                    line_start=item.get("StartLine", 0),
                    line_end=item.get("EndLine", 0),
                    secret_snippet=item.get("Secret", ""),
                    commit=item.get("Commit", ""),
                    author=item.get("Author", ""),
                    date=item.get("Date", ""),
                ))
        except (json.JSONDecodeError, FileNotFoundError):
            pass
        finally:
            Path(report_path).unlink(missing_ok=True)

        return findings

    def generate_ghost_ai_report(self, findings: list[GitleaksFinding]) -> dict:
        return {
            "tool": "gitleaks",
            "version": self.version,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "total": len(findings),
            "findings": [f.to_dict() for f in findings],
        }


if __name__ == "__main__":
    import sys
    path = sys.argv[1] if len(sys.argv) > 1 else "."
    bridge = GitleaksBridge()
    print(f"[Ghost AI / Gitleaks] Version: {bridge.version}")
    findings = bridge.scan_directory(path)
    report = bridge.generate_ghost_ai_report(findings)
    print(json.dumps(report, indent=2))
