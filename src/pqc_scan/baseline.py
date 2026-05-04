"""Project-wide rule suppression via a baseline file.

Complements the existing line-local `# pqc-scan: ignore[rule-id]` mechanism in
the source-code scanner. The baseline lets a project ack an entire rule for
specific paths (or globally) once, in a tracked file, without sprinkling
suppression comments through the codebase.

Schema (YAML):

    suppressions:
      - rule: pqc-scan.source.md5.python-hashlib
        paths: [src/legacy_etag.py]
        reason: "non-cryptographic content addressing"
      - rule: pqc-scan.source.rsa.ssh-rsa
        paths: ["tests/", "build/"]
        reason: "test fixtures; not production code"
      - rule: pqc-scan.jwt.rs256.token
        # `paths` omitted → suppress this rule everywhere
        reason: "tracked in #234, not blocking ship"

Path matching is prefix-based on the finding's `location` field, after
normalizing both sides to forward slashes. A trailing slash means
"directory", but the matcher is identical either way (prefix match).

Loaded by the CLI between scanner aggregation and report rendering, so all
reporters (console, JSON, SARIF, CBOM, CSV) see the same filtered set.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml

from pqc_scan.findings import Finding


DEFAULT_BASELINE_FILENAME = ".pqc-scan-baseline.yml"


def _normalize(p: str) -> str:
    p = p.replace("\\", "/")
    if p.startswith("./"):
        p = p[2:]
    return p


def _path_matches(location: str, prefix: str) -> bool:
    """Match `prefix` against `location` at path-component boundaries.

    Matches `tests/` against any `…/tests/…` location, but NOT `mytests/…`.
    Matches an exact file path (`src/legacy_etag.py`) against itself, with or
    without a leading scan-root prefix (`proj/src/legacy_etag.py`).
    """
    loc = _normalize(location)
    p = _normalize(prefix)
    if not p:
        return True
    if loc == p:
        return True
    # Treat the entry as a directory-style prefix when checking mid-path.
    p_with_trailing = p if p.endswith("/") else p + "/"
    if loc.startswith(p_with_trailing):
        return True
    if "/" + p_with_trailing in "/" + loc + "/":
        return True
    return False


@dataclass(frozen=True)
class BaselineEntry:
    rule_id: str
    paths: tuple[str, ...]  # empty tuple → applies everywhere
    reason: str = ""

    def matches(self, finding: Finding) -> bool:
        if finding.rule_id != self.rule_id:
            return False
        if not self.paths:
            return True
        return any(_path_matches(finding.location, p) for p in self.paths)


@dataclass(frozen=True)
class Baseline:
    entries: tuple[BaselineEntry, ...]

    def filter(self, findings: list[Finding]) -> list[Finding]:
        if not self.entries:
            return findings
        return [f for f in findings if not any(e.matches(f) for e in self.entries)]


class BaselineError(ValueError):
    """Raised when a baseline file is malformed."""


def load_baseline(path: Path) -> Baseline:
    """Parse a baseline YAML file. Raises BaselineError on schema problems."""
    try:
        text = path.read_text()
    except OSError as exc:
        raise BaselineError(f"could not read baseline file {path}: {exc}") from exc

    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise BaselineError(f"baseline file {path} is not valid YAML: {exc}") from exc

    if data is None:
        return Baseline(entries=())
    if not isinstance(data, dict):
        raise BaselineError(f"baseline file {path} must be a YAML mapping at top level")

    raw_entries = data.get("suppressions", [])
    if not isinstance(raw_entries, list):
        raise BaselineError(f"`suppressions` in {path} must be a list")

    entries: list[BaselineEntry] = []
    for index, raw in enumerate(raw_entries):
        if not isinstance(raw, dict):
            raise BaselineError(
                f"suppression #{index} in {path} must be a mapping with a `rule` key"
            )
        rule = raw.get("rule")
        if not isinstance(rule, str) or not rule:
            raise BaselineError(
                f"suppression #{index} in {path} is missing a non-empty `rule` field"
            )
        paths = raw.get("paths", [])
        if paths is None:
            paths = []
        if not isinstance(paths, list):
            raise BaselineError(
                f"suppression for `{rule}` in {path}: `paths` must be a list of strings"
            )
        for p in paths:
            if not isinstance(p, str):
                raise BaselineError(
                    f"suppression for `{rule}` in {path}: every path entry must be a string"
                )
        reason = raw.get("reason", "")
        if not isinstance(reason, str):
            raise BaselineError(
                f"suppression for `{rule}` in {path}: `reason` must be a string if given"
            )
        entries.append(BaselineEntry(rule_id=rule, paths=tuple(paths), reason=reason))

    return Baseline(entries=tuple(entries))


def discover_baseline(target: Path | None) -> Path | None:
    """Look for a default baseline file. Returns None if none is found.

    Search order:
      1. `target/.pqc-scan-baseline.yml` if `target` is a directory
      2. `cwd/.pqc-scan-baseline.yml`
    """
    candidates: list[Path] = []
    if target is not None:
        if target.is_dir():
            candidates.append(target / DEFAULT_BASELINE_FILENAME)
    candidates.append(Path.cwd() / DEFAULT_BASELINE_FILENAME)
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    return None
