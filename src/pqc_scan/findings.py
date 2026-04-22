from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

# Path components that signal a file is a test or fixture rather than runtime code.
# Used to populate Finding.in_test_path for downstream filtering.
TEST_PATH_COMPONENTS: frozenset[str] = frozenset(
    {"tests", "test", "__tests__", "fixtures", "testdata", "spec", "specs"}
)


def is_test_path(location: str) -> bool:
    parts = location.replace("\\", "/").split("/")
    return any(part in TEST_PATH_COMPONENTS for part in parts)


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        return {
            "critical": 4,
            "high": 3,
            "medium": 2,
            "low": 1,
            "info": 0,
        }[self.value]


@dataclass(frozen=True)
class Finding:
    rule_id: str
    algorithm_id: str
    algorithm_display: str
    severity: Severity
    category: str
    location: str
    line: int | None
    context: str
    scanner: str
    replacement: str
    notes: str
    in_test_path: bool = False

    def sort_key(self) -> tuple:
        return (-self.severity.rank, self.location, self.line or 0)
