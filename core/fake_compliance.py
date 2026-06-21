"""
Interactive fake compliance: runs after the real audit, with optional per-finding overrides
and bulk severity downgrade. Maintains original vs modified snapshots for reporting.

For regulatory production use, rely on unmodified real audit outputs only.
"""

from __future__ import annotations

import copy
import logging
import sys
from dataclasses import dataclass, field
from typing import Any, Literal

from core.auditor import RuleAuditResult

logger = logging.getLogger(__name__)

ReportStyle = Literal["standard", "legacy_fake", "interactive_soft"]


def prompt_yes_no(prompt: str) -> bool:
    """Read yes/no from the user with validation."""
    while True:
        try:
            raw = input(prompt).strip().lower()
        except EOFError:
            logger.warning("EOF on input; treating as 'no'.")
            return False
        if raw in ("y", "yes"):
            return True
        if raw in ("n", "no"):
            return False
        print("Please enter yes or no (or y/n).")


def soften_issue_text(issue: str, *, target_band: str = "medium") -> str:
    """Rewrite issue text to a softer audit tone (post-downgrade narrative)."""
    if target_band == "display":
        return (
            f"Observation: {issue} "
            "(presentation wording adjusted for internal narrative; refer to original_rule_results for the engine output.)"
        )
    low = issue.lower()
    if ("any source" in low and "any destination" in low) or (
        "any source" in low and "destination" in low and "permit" in low
    ):
        return (
            "Observation: A broad access rule was noted; residual exposure may be managed "
            "through layered controls, monitoring, and periodic review."
        )
    if "any source" in low or "0.0.0.0" in low:
        return (
            "Observation: Source scope is wider than the preferred baseline; "
            "consider tightening objects where business permits."
        )
    if "blocked" in low or "insecure port" in low:
        return (
            "Observation: Service port usage differs from the preferred catalogue; "
            "validate business need and compensating controls."
        )
    if "approved port" in low:
        return (
            "Observation: Port selection is outside the nominal approved list; "
            "confirm exception approval where applicable."
        )
    return (
        f"Improvement area: {issue} "
        "(wording softened for internal reporting; verify against actual risk.)"
    )


def soften_recommendation_for_band(rec: str, severity: str) -> str:
    if severity in ("Medium", "Low"):
        return (
            "Continue periodic review and align objects with the approved baseline where feasible; "
            "document accepted residual risk where business constraints apply."
        )
    return rec


def legacy_blanket_overlay(result: RuleAuditResult) -> RuleAuditResult:
    """Mark every rule compliant (non-interactive legacy demo mode)."""
    r = copy.deepcopy(result)
    r.status = "compliant"
    r.severity = "Low"
    r.issues = []
    r.recommendation = (
        "No remediation required under the demonstration compliance profile; "
        "use strict/relaxed assessments for production evidence."
    )
    return r


def apply_bulk_downgrade(working: list[RuleAuditResult]) -> None:
    """In-place: Critical→Medium, High→Low with softer issue/recommendation language."""
    for r in working:
        if r.status != "non-compliant":
            continue
        if r.severity == "Critical":
            r.severity = "Medium"
            r.issues = [soften_issue_text(i, target_band="medium") for i in r.issues]
            r.recommendation = soften_recommendation_for_band(r.recommendation, "Medium")
        elif r.severity == "High":
            r.severity = "Low"
            r.issues = [soften_issue_text(i, target_band="low") for i in r.issues]
            r.recommendation = soften_recommendation_for_band(r.recommendation, "Low")


@dataclass
class FakeComplianceOutcome:
    """Result of optional fake-compliance processing after the real audit."""

    modified_results: list[RuleAuditResult]
    original_results_snapshot: list[RuleAuditResult]
    fake_pipeline_used: bool
    report_style: ReportStyle = "standard"
    per_rule_compliant_overrides: int = 0
    bulk_downgrade_applied: bool = False
    soft_language: bool = False
    extra_notes: list[str] = field(default_factory=list)


def apply_fake_compliance(
    results: list[RuleAuditResult],
    *,
    interactive: bool,
    legacy_blanket_fake: bool = False,
) -> FakeComplianceOutcome:
    """
    Post–real-audit fake compliance flow.

    - legacy_blanket_fake: non-interactive; all rules shown as compliant (demo only).
    - interactive: prompts for fake report, per-finding compliant overrides, optional bulk downgrade.
    - otherwise: returns a deep copy of results unchanged.
    """
    original_snapshot = copy.deepcopy(results)

    if legacy_blanket_fake:
        modified = [legacy_blanket_overlay(r) for r in copy.deepcopy(results)]
        return FakeComplianceOutcome(
            modified_results=modified,
            original_results_snapshot=original_snapshot,
            fake_pipeline_used=True,
            report_style="legacy_fake",
            soft_language=True,
            extra_notes=["Legacy blanket fake: all rules marked compliant (demonstration only)."],
        )

    if not interactive or not sys.stdin.isatty():
        return FakeComplianceOutcome(
            modified_results=copy.deepcopy(results),
            original_results_snapshot=original_snapshot,
            fake_pipeline_used=False,
            report_style="standard",
            soft_language=False,
        )

    print("\n" + "=" * 64)
    print("OPTIONAL FAKE COMPLIANCE REPORT (after real audit)")
    print("=" * 64)
    print(
        "The assessment above reflects the genuine audit engine output.\n"
        "You may optionally produce an adjusted narrative for training or demo contexts only.\n"
        "Do not use fake compliance output for regulatory or RBI supervisory submissions.\n"
    )

    if not prompt_yes_no("Do you want to proceed with Fake Compliance Report? (yes/no): "):
        print("Proceeding with the original audit results only.\n")
        return FakeComplianceOutcome(
            modified_results=copy.deepcopy(results),
            original_results_snapshot=original_snapshot,
            fake_pipeline_used=False,
            report_style="standard",
            soft_language=False,
        )

    working = copy.deepcopy(results)
    overrides = 0

    # STEP 3: per non-compliant finding
    non_compliant = [r for r in working if r.status == "non-compliant"]
    for idx, r in enumerate(non_compliant, 1):
        print("\n" + "-" * 64)
        print(f"Finding candidate {idx} of {len(non_compliant)}")
        print(f"Rule: {r.rule_name}")
        print("Issues:")
        if not r.issues:
            print("  (none listed)")
        else:
            for j, issue in enumerate(r.issues, 1):
                print(f"  * Issue {j}: {issue}")
        print(f"Severity: {r.severity}")
        print(f"(Original audit severity retained on record as: {r.original_severity or r.severity})")

        if prompt_yes_no("Do you want to mark this rule as COMPLIANT? (yes/no): "):
            r.status = "compliant"
            r.severity = "Low"
            r.issues = ["No issues identified"]
            r.recommendation = "No action required"
            overrides += 1

    # STEP 4: bulk downgrade remaining High/Critical
    remaining_high = [
        r
        for r in working
        if r.status == "non-compliant" and r.severity in ("Critical", "High")
    ]
    bulk = False
    if remaining_high:
        print("\n" + "-" * 64)
        if prompt_yes_no(
            "Do you want to automatically downgrade all remaining High/Critical findings? (yes/no): "
        ):
            apply_bulk_downgrade(working)
            bulk = True

    print("\nFake compliance adjustments recorded. Generating final report narrative.\n")

    return FakeComplianceOutcome(
        modified_results=working,
        original_results_snapshot=original_snapshot,
        fake_pipeline_used=True,
        report_style="interactive_soft",
        per_rule_compliant_overrides=overrides,
        bulk_downgrade_applied=bulk,
        soft_language=True,
        extra_notes=[
            "Interactive fake compliance applied after real audit; review original_rule_results for authentic severities.",
        ],
    )
