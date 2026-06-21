"""
Shared data models for FWRAX audit requests and results.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal, Optional

AuditMode = Literal["strict", "relaxed"]


@dataclass
class AuditOptions:
    """Options controlling how a firewall audit is performed."""

    mode: AuditMode = "strict"
    organization: str = "the Organization"
    run_shadow_detection: bool = True
    run_batch_checks: bool = True
    fake_compliance: bool = False

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "AuditOptions":
        return cls(
            mode=d.get("mode", "strict"),
            organization=d.get("organization", "the Organization"),
            run_shadow_detection=bool(d.get("run_shadow_detection", True)),
            run_batch_checks=bool(d.get("run_batch_checks", True)),
            fake_compliance=bool(d.get("fake_compliance", False)),
        )


@dataclass
class AuditSummary:
    """High-level summary counts from an audit run."""

    total_rules: int = 0
    total_findings: int = 0
    compliant: int = 0
    non_compliant: int = 0
    disabled: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    duplicates: int = 0
    shadows: int = 0
    conflict_shadows: int = 0
    stale_rules: int = 0
    any_any_rules: int = 0
    broad_access_rules: int = 0


@dataclass
class AuditReport:
    """Full audit report produced by the orchestration layer."""

    audit_id: str
    options: AuditOptions
    summary: AuditSummary
    payload: dict[str, Any]  # full reporter payload for rendering/export
    rule_results: list[dict[str, Any]] = field(default_factory=list)
    batch_notes: list[str] = field(default_factory=list)
    error: Optional[str] = None
