from __future__ import annotations

from pathlib import Path
from typing import Iterator

from pqc_scan.algorithms import ALGORITHMS
from pqc_scan.findings import Finding, is_test_path


SSH_KEY_PREFIXES: dict[str, str] = {
    "ssh-rsa": "rsa",
    "ssh-dss": "dsa",
    "ecdsa-sha2-nistp256": "ecdsa",
    "ecdsa-sha2-nistp384": "ecdsa",
    "ecdsa-sha2-nistp521": "ecdsa",
    "ssh-ed25519": "ed25519",
    "sk-ecdsa-sha2-nistp256@openssh.com": "ecdsa",
    "sk-ssh-ed25519@openssh.com": "ed25519",
}

KEY_FILENAMES: set[str] = {"authorized_keys", "known_hosts"}


def _candidate_files(root: Path) -> Iterator[Path]:
    if root.is_file():
        yield root
        return
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if path.name in KEY_FILENAMES or path.suffix == ".pub":
            yield path


def scan_path(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    for path in _candidate_files(root):
        findings.extend(scan_file(path))
    return findings


def scan_file(path: Path) -> list[Finding]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    findings: list[Finding] = []
    location = str(path)
    in_test = is_test_path(location)
    for lineno, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        # known_hosts entries have host[,host...] as the first field; the key
        # type is the second field. authorized_keys / .pub start with the type.
        parts = line.split()
        candidate = parts[0]
        if candidate not in SSH_KEY_PREFIXES and len(parts) >= 2:
            candidate = parts[1]
        alg_id = SSH_KEY_PREFIXES.get(candidate)
        if alg_id is None:
            continue
        info = ALGORITHMS[alg_id]
        findings.append(
            Finding(
                rule_id=f"pqc-scan.ssh.{alg_id}-key",
                algorithm_id=info.id,
                algorithm_display=f"{info.display} (SSH key)",
                severity=info.severity,
                category=info.category,
                location=location,
                line=lineno,
                context=candidate,
                scanner="ssh_keys",
                replacement=info.replacement,
                notes=info.notes,
                in_test_path=in_test,
            )
        )
    return findings
