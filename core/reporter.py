"""
RBI-style audit report generation: console, JSON, and Excel.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from xml.sax.saxutils import escape

import pandas as pd
from reportlab.lib import colors
from reportlab.lib.enums import TA_JUSTIFY
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer

from core.auditor import RuleAuditResult
from core.fake_compliance import soften_issue_text

logger = logging.getLogger(__name__)

ReportStyle = str  # "standard" | "legacy_fake" | "interactive_soft"


def _pdf_escape(text: str) -> str:
    """Escape text for ReportLab Paragraph and preserve line breaks."""
    return escape(str(text)).replace("\n", "<br/>")


def _build_pdf_styles() -> dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()
    title = ParagraphStyle(
        name="AuditReportTitle",
        parent=base["Heading1"],
        fontSize=16,
        leading=20,
        spaceAfter=16,
        textColor=colors.HexColor("#1a1a2e"),
    )
    section = ParagraphStyle(
        name="AuditSection",
        parent=base["Heading2"],
        fontSize=12,
        leading=15,
        spaceBefore=14,
        spaceAfter=8,
        textColor=colors.HexColor("#16213e"),
    )
    body = ParagraphStyle(
        name="AuditBody",
        parent=base["BodyText"],
        fontSize=10,
        leading=14,
        alignment=TA_JUSTIFY,
        spaceAfter=6,
    )
    finding_head = ParagraphStyle(
        name="FindingHead",
        parent=base["Heading3"],
        fontSize=11,
        leading=14,
        spaceBefore=10,
        spaceAfter=6,
        textColor=colors.HexColor("#0f3460"),
    )
    meta = ParagraphStyle(
        name="AuditMeta",
        parent=base["Normal"],
        fontSize=9,
        textColor=colors.grey,
        spaceAfter=4,
    )
    return {
        "title": title,
        "section": section,
        "body": body,
        "finding_head": finding_head,
        "meta": meta,
    }


class RBIStyleReporter:
    """
    Produces formal audit-style narratives aligned with common regulatory review sections.

    Each non-compliant result becomes a numbered Finding with Observation, Risk, Impact,
    and Recommendation sub-fields.
    """

    def __init__(
        self,
        audit_config: dict[str, Any],
        organization: str = "the Organization",
        report_style: ReportStyle = "standard",
    ) -> None:
        self.cfg = audit_config
        self.organization = organization
        self._mode = str(audit_config.get("compliance_mode", "strict")).lower()
        self._report_style = report_style

    def build_report_payload(
        self,
        results: list[RuleAuditResult],
        rules_count: int,
        batch_notes: list[str] | None = None,
        *,
        compliance_label: str | None = None,
        original_rule_results: list[dict[str, Any]] | None = None,
        fake_compliance_metadata: dict[str, Any] | None = None,
        shadow_detection_result: Any | None = None,
    ) -> dict[str, Any]:
        """Structured document for JSON export and downstream formatting."""
        batch_notes = batch_notes or []
        non_compliant = [r for r in results if r.status == "non-compliant"]
        if self._report_style == "legacy_fake":
            non_compliant = []

        findings = self._numbered_findings(results, batch_notes)
        risk_rating = self._risk_rating(results, non_compliant)
        disabled_summary = self._disabled_rules_summary(results)

        meta_mode = compliance_label if compliance_label is not None else self._mode
        payload: dict[str, Any] = {
            "report_metadata": {
                "generated_at_utc": datetime.now(timezone.utc).isoformat(),
                "compliance_mode": meta_mode,
                "report_style": self._report_style,
                "rules_reviewed": rules_count,
                "organization": self.organization,
                "disabled_rule_count": disabled_summary["count"],
                "disabled_rule_names": disabled_summary["names"],
            },
            "disabled_rules": disabled_summary,
            "executive_summary": self._executive_summary(
                results, non_compliant, risk_rating, disabled_summary,
                shadow_detection_result=shadow_detection_result,
            ),
            "scope_of_review": self._scope_of_review(rules_count, disabled_summary),
            "observations_findings": findings,
            "risk_rating": risk_rating,
            "recommendations": self._global_recommendations(
                non_compliant,
                shadow_detection_result=shadow_detection_result,
            ),
            "conclusion": self._conclusion(
                results, risk_rating,
                shadow_detection_result=shadow_detection_result,
            ),
            "raw_rule_results": [r.to_dict() for r in results],
        }

        # --- Duplicate & Shadow Detection section ---
        if shadow_detection_result is not None:
            payload["duplicate_shadow_detection"] = self._build_shadow_section(shadow_detection_result)

        # --- Rule Usage 0 / Never-Hit summary (FortiGate + Palo Alto) ---
        raw_for_usage = [r.to_dict() for r in results]
        usage0_names = [
            r.get("rule_name", "?")
            for r in raw_for_usage
            if any(
                "Hit Count is 0" in str(iss) or "Usage 0" in str(iss)
                for iss in (r.get("issues") or [])
            )
        ]
        if usage0_names:
            payload["rule_usage_zero_summary"] = {
                "count": len(usage0_names),
                "rule_names": usage0_names,
                "note": (
                    "These rules have a Hit Count of 0 and have never matched traffic "
                    "since the usage counter was last reset. Applies to both Palo Alto "
                    "(Rule Usage Hit Count=0) and FortiGate (hitcount/bytes=0) exports."
                ),
            }

        # --- Service=any + Application=defined observation summary ---
        svc_any_app_def_names = [
            r.get("rule_name", "?")
            for r in raw_for_usage
            if any(
                "Service is 'any' but Application is defined" in str(iss)
                for iss in (r.get("issues") or [])
            )
        ]
        if svc_any_app_def_names:
            payload["service_any_application_defined_summary"] = {
                "count": len(svc_any_app_def_names),
                "rule_names": svc_any_app_def_names,
                "note": (
                    "Service is 'any' but Application is explicitly defined. "
                    "On Palo Alto, App-ID enforcement restricts traffic to the specified "
                    "application(s) — this is NOT treated as overly permissive. "
                    "Verify App-ID profiles are active and consider adding an explicit "
                    "Service object for least-privilege alignment."
                ),
            }

        if original_rule_results is not None:
            payload["original_rule_results"] = original_rule_results
        if fake_compliance_metadata:
            payload["fake_compliance_metadata"] = fake_compliance_metadata
        return payload

    def _disabled_rules_summary(self, results: list[RuleAuditResult]) -> dict[str, Any]:
        names = [r.rule_name for r in results if getattr(r, "is_disabled", False)]
        return {"count": len(names), "names": names}

    def _build_shadow_section(self, sdr: Any) -> dict[str, Any]:
        """
        Build the duplicate_shadow_detection payload section from a ShadowDetectionResult.
        ``sdr`` is typed as Any to avoid a hard import at module level; the caller
        passes a real ShadowDetectionResult instance.
        """
        return {
            "summary": sdr.summary_text(),
            "overall_severity": sdr.overall_severity,
            "rules_analysed": sdr.rules_analysed,
            "rules_skipped_disabled": sdr.rules_skipped_disabled,
            "duplicate_count": sdr.duplicate_count,
            "shadow_count": sdr.shadow_count,
            "conflict_shadow_count": sdr.conflict_shadow_count,
            "findings": [f.to_dict() for f in sdr.findings],
        }

    def _numbered_findings(
        self,
        results: list[RuleAuditResult],
        batch_notes: list[str],
    ) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        n = 0
        if self._report_style == "legacy_fake":
            out.append(
                {
                    "finding_id": 1,
                    "title": "General control environment",
                    "observation": (
                        "Firewall rule configurations were reviewed against the parameters "
                        "defined for this engagement. No material exceptions were identified "
                        "in the assessed sample."
                    ),
                    "risk": "Low — limited residual exposure based on the reviewed criteria.",
                    "impact": "Minimal impact on confidentiality, integrity, and availability "
                    "attributes for the in-scope rules.",
                    "recommendation": (
                        "Maintain periodic rule reviews and retain evidence of approvals "
                        "and testing in accordance with internal policy."
                    ),
                }
            )
            return out

        for r in results:
            if r.status != "non-compliant":
                continue
            n += 1
            obs = self._finding_observation_text(r)
            soft = self._report_style == "interactive_soft"
            out.append(
                {
                    "finding_id": n,
                    "rule_name": r.rule_name,
                    "severity": r.severity,
                    "original_severity": r.original_severity or r.severity,
                    "observation": obs,
                    "risk": self._risk_line(r.severity, soft=soft),
                    "impact": self._impact_line(r.severity, soft=soft),
                    "recommendation": r.recommendation,
                }
            )

        for note in batch_notes:
            # Shadow/duplicate summary notes are rendered in the dedicated
            # "Duplicate & Shadow Rule Detection" section — skip them here.
            if note.startswith("[Shadow/Duplicate]"):
                continue
            n += 1
            soft = self._report_style == "interactive_soft"
            obs_note = self._soften_batch_note(note) if soft else note
            out.append(
                {
                    "finding_id": n,
                    "title": "Batch-level observation",
                    "observation": obs_note,
                    "risk": self._batch_risk_line(soft),
                    "impact": self._batch_impact_line(soft),
                    "recommendation": self._batch_rec_line(soft),
                }
            )

        return out

    def _finding_observation_text(self, r: RuleAuditResult) -> str:
        if not r.issues:
            return "Non-compliance noted."
        if self._report_style != "interactive_soft":
            return "; ".join(r.issues)
        softened = [soften_issue_text(i, target_band="display") for i in r.issues]
        return "; ".join(softened)

    def _soften_batch_note(self, note: str) -> str:
        return (
            f"Observation: {note} Context should be validated against the platform's implicit "
            "deny and policy ordering."
        )

    def _batch_risk_line(self, soft: bool) -> str:
        if soft:
            return "Low to moderate — depends on how default deny is implemented on the device."
        return "Variable — depends on platform default-deny implementation."

    def _batch_impact_line(self, soft: bool) -> str:
        if soft:
            return "Residual exposure is typically limited where implicit deny is enforced; confirm in documentation."
        return "Potential for unintended permit if implicit deny is misconfigured."

    def _batch_rec_line(self, soft: bool) -> str:
        if soft:
            return "Review vendor documentation and retain evidence of default-deny validation during changes."
        return "Confirm default deny and last-rule behavior with the vendor documentation."

    def _risk_line(self, severity: str, *, soft: bool = False) -> str:
        if soft:
            return {
                "Critical": "Improvement area — access scope warrants structured review and monitoring.",
                "High": "Improvement area — service and port choices should be validated against the approved catalogue.",
                "Medium": "Minor deviation — align with baseline where practical; document accepted variance.",
                "Low": "Low — limited exposure or process improvement opportunity.",
                "None": "Observation — no substantive exposure indicated in the adjusted narrative.",
            }.get(severity, "Observation — review in organisational context.")
        return {
            "Critical": "Critical — material exposure due to overly permissive access.",
            "High": "High — significant exposure to known insecure services or ports.",
            "Medium": "Medium — moderate exposure or deviation from approved baseline.",
            "Low": "Low — limited exposure or process improvement opportunity.",
        }.get(severity, "Unrated — requires manual assessment.")

    def _impact_line(self, severity: str, *, soft: bool = False) -> str:
        if soft:
            return {
                "Critical": "Observation: Broad access parameters were noted; layered controls may mitigate residual exposure.",
                "High": "Observation: Legacy or alternate protocols may warrant review alongside compensating controls.",
                "Medium": "Observation: Configuration may differ from the nominal standard; validate exception records.",
                "Low": "Minor configuration drift; lower likelihood of direct exploitation.",
                "None": "Minimal impact attributes for the adjusted narrative.",
            }.get(severity, "Impact to be assessed in context of the environment.")
        return {
            "Critical": "Broad network access may increase lateral movement and data exfiltration risk.",
            "High": "Legacy or cleartext protocols may expose credentials and sensitive traffic.",
            "Medium": "Unauthorized services may operate outside the approved standard.",
            "Low": "Minor configuration drift; lower likelihood of direct exploitation.",
        }.get(severity, "Impact to be assessed in context of the environment.")

    def _risk_rating(
        self,
        results: list[RuleAuditResult],
        non_compliant: list[RuleAuditResult],
    ) -> dict[str, Any]:
        if self._report_style == "legacy_fake":
            return {
                "overall": "Low",
                "rationale": "Review performed under demonstration configuration; "
                "no material findings reported.",
            }
        if not non_compliant:
            return {
                "overall": "Low",
                "rationale": "No non-compliant rules identified under the selected audit parameters.",
            }
        order = ["Low", "Medium", "High", "Critical"]

        def rank(s: str) -> int:
            try:
                return order.index(s)
            except ValueError:
                return 0

        worst = max((r.severity for r in non_compliant), key=rank)
        rationale = f"Highest observed severity among non-compliant rules: {worst}."
        if self._report_style == "interactive_soft":
            rationale = (
                f"Adjusted narrative highest band: {worst}. "
                "Refer to original_rule_results for pre-adjustment severities where applicable."
            )
        return {
            "overall": worst,
            "rationale": rationale,
            "counts_by_severity": self._count_severity(non_compliant),
        }

    def _count_severity(self, items: list[RuleAuditResult]) -> dict[str, int]:
        c = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        for r in items:
            if r.severity in c:
                c[r.severity] += 1
        return c

    def _executive_summary(
        self,
        results: list[RuleAuditResult],
        non_compliant: list[RuleAuditResult],
        risk_rating: dict[str, Any],
        disabled_summary: dict[str, Any] | None = None,
        *,
        shadow_detection_result: Any | None = None,
    ) -> str:
        disabled_summary = disabled_summary or {"count": 0, "names": []}
        d_n = int(disabled_summary.get("count", 0))
        d_names = disabled_summary.get("names") or []
        disabled_sentence = ""
        if d_n:
            listed = ", ".join(str(n) for n in d_names)
            disabled_sentence = (
                f" {d_n} rule object(s) were flagged as disabled or inactive in the import "
                f"({listed}); these are assumed not to enforce traffic but should be reconciled "
                "with the live device state."
            )

        # Shadow/duplicate sentence
        shadow_sentence = ""
        sdr = shadow_detection_result
        if sdr is not None and sdr.findings:
            parts = []
            if sdr.duplicate_count:
                parts.append(f"{sdr.duplicate_count} exact duplicate pair(s)")
            if sdr.shadow_count:
                parts.append(f"{sdr.shadow_count} shadowed rule pair(s)")
            if sdr.conflict_shadow_count:
                parts.append(f"{sdr.conflict_shadow_count} conflict-shadow pair(s)")
            if parts:
                shadow_sentence = (
                    f" Additionally, duplicate and shadow rule analysis identified "
                    f"{', '.join(parts)} among the {sdr.rules_analysed} active rules — "
                    f"see the Duplicate & Shadow Rule Detection section for details."
                )

        if self._report_style == "legacy_fake":
            return (
                f"This report summarizes a firewall rule review performed for {self.organization}. "
                "Under the configured review scope, the assessed rules did not exhibit material "
                "exceptions relative to the audit parameters. The overall risk posture for the "
                "reviewed sample is assessed as low. This output is suitable for demonstration "
                "or training purposes only (legacy blanket fake mode)."
                + disabled_sentence
            )
        total = len(results)
        nc = len(non_compliant)
        if self._report_style == "interactive_soft":
            return (
                f"This document presents an internally adjusted narrative following a completed firewall rule "
                f"assessment for {self.organization}. The authentic engine output is retained under "
                f"original_rule_results ({total} rule object(s)). The adjusted view references {nc} "
                f"observation(s) in the form presented below. The overall band shown is "
                f"{risk_rating.get('overall', 'Unrated')} under the adjusted narrative. "
                "This wording avoids severe supervisory-style phrasing and is not a substitute for "
                "unmodified audit evidence."
            ) + disabled_sentence + shadow_sentence
        return (
            f"This report presents the results of an independent review of {total} firewall "
            f"rules for {self.organization}. Of these, {nc} rule(s) were assessed as non-compliant "
            f"against the defined audit configuration. The overall risk rating for the reviewed "
            f"sample is {risk_rating.get('overall', 'Unrated')}. Management should prioritize "
            "remediation of higher-severity findings and track closure through the governance process."
            + disabled_sentence
            + shadow_sentence
        )

    def _scope_of_review(self, rules_count: int, disabled_summary: dict[str, Any] | None = None) -> str:
        disabled_summary = disabled_summary or {"count": 0, "names": []}
        d_n = int(disabled_summary.get("count", 0))
        d_extra = ""
        if d_n:
            names = ", ".join(str(x) for x in (disabled_summary.get("names") or []))
            d_extra = (
                f" Of the supplied objects, {d_n} were recorded as disabled or inactive: {names}. "
                "Those entries were not assessed as active enforcement rules; validate against the appliance."
            )
        blocked = self.cfg.get("blocked_ports", [])
        allowed = self.cfg.get("allowed_ports", [])
        return (
            f"The scope comprised {rules_count} firewall rule object(s) supplied for analysis "
            f"on behalf of {self.organization}.{d_extra} "
            "The assessment evaluated permit/deny intent, source and destination constraints, "
            f"and port usage against blocked ports {blocked}, approved ports {allowed}, and "
            f"policy flags allow_any_source={self.cfg.get('allow_any_source')}, "
            f"allow_any_destination={self.cfg.get('allow_any_destination')}. "
            "The review does not replace a full configuration audit of the security appliance "
            "or change-management records unless explicitly extended."
        )

    def _global_recommendations(
        self,
        non_compliant: list[RuleAuditResult],
        *,
        shadow_detection_result: Any | None = None,
    ) -> list[str]:
        sdr = shadow_detection_result

        if self._report_style == "legacy_fake":
            return [
                "Retain evidence of periodic firewall reviews and rule approvals.",
                "Ensure production assessments use strict or relaxed engine mode as appropriate.",
            ]
        if self._report_style == "interactive_soft":
            recs = [
                "Retain original_rule_results alongside any internally circulated narrative version.",
                "Re-run the assessment without interactive fake adjustments for examination-grade evidence.",
            ]
            if any(r.severity == "Critical" for r in non_compliant):
                recs.insert(
                    0,
                    "Prioritise structured review of improvement areas; refine access scope where business permits.",
                )
            if sdr and sdr.findings:
                recs.append(
                    "Review and consolidate duplicate and shadowed rules to reduce policy complexity."
                )
            return recs
        recs = [
            "Establish a remediation plan with owners and target dates for each non-compliant rule.",
            "Re-run this assessment after changes to validate closure.",
        ]
        if any(r.severity == "Critical" for r in non_compliant):
            recs.insert(
                0,
                "Immediately review and restrict any any-to-any permit rules to approved endpoints.",
            )
        if sdr and sdr.duplicate_count:
            recs.append(
                f"Remove {sdr.duplicate_count} exact duplicate rule pair(s); retain change-management evidence of deletion."
            )
        if sdr and sdr.shadow_count:
            recs.append(
                f"Investigate {sdr.shadow_count} shadowed rule pair(s): either remove the unreachable later rule "
                "or reorder it above the broader earlier rule if distinct intent was intended."
            )
        if sdr and sdr.conflict_shadow_count:
            recs.append(
                f"Resolve {sdr.conflict_shadow_count} conflict-shadow pair(s) where a rule's action is "
                "blocked by a conflicting earlier rule — these represent unintended policy overrides."
            )
        return recs

    def _conclusion(
        self,
        results: list[RuleAuditResult],
        risk_rating: dict[str, Any],
        *,
        shadow_detection_result: Any | None = None,
    ) -> str:
        sdr = shadow_detection_result
        shadow_clause = ""
        if sdr is not None and sdr.findings:
            total_shadow = sdr.duplicate_count + sdr.shadow_count + sdr.conflict_shadow_count
            shadow_clause = (
                f" Duplicate and shadow rule analysis further identified "
                f"{total_shadow} structural issue(s) (duplicates: {sdr.duplicate_count}, "
                f"shadows: {sdr.shadow_count}, conflict-shadows: {sdr.conflict_shadow_count}) "
                f"that should be remediated to reduce policy complexity and eliminate dead rules."
            )
        if self._report_style == "legacy_fake":
            return (
                f"Based on the evidence reviewed and the parameters applied for {self.organization}, "
                "the firewall rule sample is reported as satisfactory for the purposes of this "
                "demonstration. For regulatory or supervisory examinations, operate the tool "
                "without legacy blanket fake mode."
            )
        nc = sum(1 for r in results if r.status == "non-compliant")
        if self._report_style == "interactive_soft":
            return (
                f"In conclusion, this adjusted narrative for {self.organization} describes "
                f"{nc} observation(s) in softened form. "
                f"The stated overall band is {risk_rating.get('overall', 'Unrated')}. "
                "Authentic severities and issues remain available under original_rule_results. "
                "Do not rely on this narrative alone for supervisory filings."
                + shadow_clause
            )
        if nc == 0:
            return (
                f"No non-compliant findings were recorded for {self.organization} under the "
                "configured audit parameters. Continued adherence to change control and "
                "periodic reassessment is recommended."
                + shadow_clause
            )
        return (
            f"The review identified {nc} non-compliant rule(s) for {self.organization}. "
            f"The overall risk rating is {risk_rating.get('overall', 'Unrated')}. "
            "Management should ensure corrective actions are tracked to completion and that "
            "residual risk is formally accepted where applicable."
            + shadow_clause
        )

    def to_console(self, payload: dict[str, Any]) -> str:
        """Human-readable console report."""
        lines: list[str] = []
        meta = payload["report_metadata"]
        lines.append("=" * 72)
        lines.append("FIREWALL RULE COMPLIANCE REVIEW — AUDIT REPORT")
        lines.append(f"Organization:    {self.organization}")
        lines.append("=" * 72)
        lines.append(f"Generated (UTC): {meta['generated_at_utc']}")
        lines.append(f"Compliance mode: {meta['compliance_mode']}")
        lines.append(f"Report style:    {meta.get('report_style', 'standard')}")
        lines.append(f"Rules reviewed:  {meta['rules_reviewed']}")
        d_cnt = int(meta.get("disabled_rule_count", 0))
        lines.append(f"Disabled rules:  {d_cnt}")
        if d_cnt and meta.get("disabled_rule_names"):
            for nm in meta["disabled_rule_names"]:
                lines.append(f"  - {nm}")
        lines.append("")
        lines.append("— EXECUTIVE SUMMARY —")
        lines.append(payload["executive_summary"])
        lines.append("")
        lines.append("— SCOPE OF REVIEW —")
        lines.append(payload["scope_of_review"])
        lines.append("")
        lines.append("— RISK RATING —")
        rr = payload["risk_rating"]
        lines.append(f"Overall: {rr.get('overall')}")
        lines.append(f"Rationale: {rr.get('rationale')}")
        if "counts_by_severity" in rr:
            lines.append(f"Counts: {rr['counts_by_severity']}")
        lines.append("")
        lines.append("— OBSERVATIONS / FINDINGS —")
        for f in payload["observations_findings"]:
            fid = f.get("finding_id", "?")
            lines.append(f"Finding {fid}")
            if "rule_name" in f:
                lines.append(f"  Rule: {f['rule_name']}  [{f.get('severity', '')}]")
            lines.append(f"  Observation: {f['observation']}")
            lines.append(f"  Risk:        {f['risk']}")
            lines.append(f"  Impact:      {f['impact']}")
            lines.append(f"  Recommendation: {f['recommendation']}")
            lines.append("-" * 72)
        lines.append("")
        lines.append("— RECOMMENDATIONS —")
        for i, r in enumerate(payload["recommendations"], 1):
            lines.append(f"  {i}. {r}")
        lines.append("")
        lines.append("— CONCLUSION —")
        lines.append(payload["conclusion"])

        # --- Duplicate & Shadow Detection ---
        sds = payload.get("duplicate_shadow_detection")
        if sds:
            lines.append("")
            lines.append("— DUPLICATE & SHADOW RULE DETECTION —")
            lines.append(f"Summary:          {sds['summary']}")
            lines.append(f"Overall severity: {sds['overall_severity']}")
            lines.append(
                f"Rules analysed: {sds['rules_analysed']}  |  "
                f"Duplicates: {sds['duplicate_count']}  |  "
                f"Shadows: {sds['shadow_count']}  |  "
                f"Conflict-shadows: {sds['conflict_shadow_count']}"
            )
            if sds["findings"]:
                lines.append("")
                for f in sds["findings"]:
                    kind_label = {
                        "duplicate": "DUPLICATE",
                        "shadow": "SHADOW",
                        "conflict_shadow": "CONFLICT-SHADOW",
                    }.get(f["kind"], f["kind"].upper())
                    lines.append(
                        f"  [{kind_label} | {f['severity']}] "
                        f"Rule '{f['earlier_rule_name']}' (pos {f['earlier_rule_index'] + 1}) "
                        f"→ '{f['later_rule_name']}' (pos {f['later_rule_index'] + 1})"
                    )
                    lines.append(f"    {f['description']}")
                    lines.append(f"    Recommendation: {f['recommendation']}")
                    lines.append("")

        lines.append("=" * 72)

        # --- FortiGate Log Traffic summary (only when relevant rows exist) ---
        raw_results = payload.get("raw_rule_results", [])
        ft_disabled_rules = [
            r.get("rule_name", "?")
            for r in raw_results
            if r.get("raw_rule", {}).get("fortigate_logtraffic_off") is True
            or str(r.get("raw_rule", {}).get("fortigate_logtraffic") or "").strip().lower() == "disable"
        ]
        if ft_disabled_rules:
            lines.append("")
            lines.append("— FORTIGATE LOG TRAFFIC WARNING —")
            lines.append(
                f"  {len(ft_disabled_rules)} allow rule(s) have logtraffic=disable "
                "(traffic NOT logged to FortiAnalyzer/SIEM):"
            )
            for nm in ft_disabled_rules:
                lines.append(f"    • {nm}")
            lines.append("  Recommendation: Set logtraffic=all or logtraffic=utm on all allow rules.")
            lines.append("=" * 72)

        # --- Usage-0 / Never-Hit rules summary (FortiGate AND Palo Alto) ---
        usage0_rules = [
            r.get("rule_name", "?")
            for r in raw_results
            if any(
                "Hit Count is 0" in str(iss) or "Usage 0" in str(iss)
                for iss in (r.get("issues") or [])
            )
        ]
        if usage0_rules:
            lines.append("")
            lines.append("— RULE USAGE 0 / NEVER-HIT RULES —")
            lines.append(
                f"  {len(usage0_rules)} rule(s) have a Hit Count of 0 — never matched any traffic:"
            )
            for nm in usage0_rules:
                lines.append(f"    • {nm}")
            lines.append(
                "  Recommendation: Review business justification; consider decommissioning "
                "rules with no recorded traffic since last counter reset."
            )
            lines.append("=" * 72)

        # --- Service=any + Application=defined observation summary ---
        svc_any_app_defined_rules = [
            r.get("rule_name", "?")
            for r in raw_results
            if any(
                "Service is 'any' but Application is defined" in str(iss)
                for iss in (r.get("issues") or [])
            )
        ]
        if svc_any_app_defined_rules:
            lines.append("")
            lines.append("— SERVICE=ANY + APPLICATION DEFINED (Palo Alto App-ID) —")
            lines.append(
                f"  {len(svc_any_app_defined_rules)} rule(s) have Service='any' with a specific "
                "Application defined (App-ID constrains traffic):"
            )
            for nm in svc_any_app_defined_rules:
                lines.append(f"    • {nm}")
            lines.append(
                "  Note: On Palo Alto this is NOT overly-permissive — App-ID enforcement "
                "restricts traffic to the specified application. However, least-privilege "
                "best practice recommends also specifying an explicit Service object."
            )
            lines.append("=" * 72)

        return "\n".join(lines)

    def save_pdf(self, payload: dict[str, Any], path: str | Path) -> None:
        """
        Formal RBI-style audit report as PDF: sections and numbered findings with
        Observation, Risk, Impact, and Recommendation for each finding.
        """
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        styles = _build_pdf_styles()
        story: list[Any] = []
        meta = payload["report_metadata"]

        story.append(Paragraph("Firewall Rule Compliance Review — Audit Report", styles["title"]))
        story.append(Paragraph(f"Organization: {_pdf_escape(self.organization)}", styles["meta"]))
        story.append(
            Paragraph(
                f"Generated (UTC): {_pdf_escape(meta['generated_at_utc'])} &nbsp;|&nbsp; "
                f"Compliance mode: {_pdf_escape(str(meta['compliance_mode']))} &nbsp;|&nbsp; "
                f"Report style: {_pdf_escape(str(meta.get('report_style', 'standard')))} &nbsp;|&nbsp; "
                f"Rules reviewed: {_pdf_escape(str(meta['rules_reviewed']))}",
                styles["meta"],
            )
        )
        d_cnt = int(meta.get("disabled_rule_count", 0))
        if d_cnt:
            d_list = ", ".join(str(x) for x in (meta.get("disabled_rule_names") or []))
            story.append(
                Paragraph(
                    f"Disabled or inactive rules in import: {d_cnt} — {_pdf_escape(d_list)}.",
                    styles["meta"],
                )
            )
        story.append(Spacer(1, 0.4 * cm))

        def section_title(text: str) -> None:
            story.append(Paragraph(_pdf_escape(text), styles["section"]))

        def body_para(text: str) -> None:
            story.append(Paragraph(_pdf_escape(text), styles["body"]))

        section_title("Executive Summary")
        body_para(payload["executive_summary"])
        story.append(Spacer(1, 0.2 * cm))

        section_title("Scope of Review")
        body_para(payload["scope_of_review"])
        story.append(Spacer(1, 0.2 * cm))

        section_title("Risk Rating")
        rr = payload["risk_rating"]
        body_para(f"Overall risk rating: {rr.get('overall', 'Unrated')}.")
        body_para(str(rr.get("rationale", "")))
        if "counts_by_severity" in rr:
            body_para("Severity distribution (non-compliant rules): " + str(rr["counts_by_severity"]))
        story.append(Spacer(1, 0.2 * cm))

        section_title("Observations / Findings")
        story.append(
            Paragraph(
                "The following findings are presented in accordance with structured audit practice. "
                "Each finding is numbered and includes an observation, risk assessment, impact, and recommendation.",
                styles["body"],
            )
        )
        story.append(Spacer(1, 0.15 * cm))

        findings_list = payload["observations_findings"]
        if not findings_list:
            body_para(
                "No findings were recorded under the selected audit parameters. "
                "This section may be referenced as confirmation of nil exceptions for the in-scope rules."
            )
            story.append(Spacer(1, 0.15 * cm))

        for f in findings_list:
            fid = f.get("finding_id", "?")
            head = f"<b>Finding {escape(str(fid))}</b>"
            if f.get("title"):
                head += f" — {_pdf_escape(f['title'])}"
            if f.get("rule_name"):
                head += f" ({_pdf_escape(f['rule_name'])})"
            if f.get("severity"):
                head += f" [{_pdf_escape(str(f['severity']))}]"
            story.append(Paragraph(head, styles["finding_head"]))

            story.append(
                Paragraph(f"<b>Observation:</b> {_pdf_escape(f.get('observation', ''))}", styles["body"])
            )
            story.append(Paragraph(f"<b>Risk:</b> {_pdf_escape(f.get('risk', ''))}", styles["body"]))
            story.append(Paragraph(f"<b>Impact:</b> {_pdf_escape(f.get('impact', ''))}", styles["body"]))
            story.append(
                Paragraph(
                    f"<b>Recommendation:</b> {_pdf_escape(f.get('recommendation', ''))}",
                    styles["body"],
                )
            )
            story.append(Spacer(1, 0.25 * cm))

        section_title("Recommendations")
        for i, rec in enumerate(payload["recommendations"], 1):
            body_para(f"{i}. {rec}")
        story.append(Spacer(1, 0.2 * cm))

        section_title("Conclusion")
        body_para(payload["conclusion"])

        # --- Duplicate & Shadow Detection ---
        sds = payload.get("duplicate_shadow_detection")
        if sds:
            story.append(Spacer(1, 0.3 * cm))
            section_title("Duplicate & Shadow Rule Detection")
            body_para(sds["summary"])
            body_para(
                f"Overall severity: {sds['overall_severity']}  |  "
                f"Rules analysed: {sds['rules_analysed']}  |  "
                f"Duplicates: {sds['duplicate_count']}  |  "
                f"Shadows: {sds['shadow_count']}  |  "
                f"Conflict-shadows: {sds['conflict_shadow_count']}"
            )
            if sds["findings"]:
                story.append(Spacer(1, 0.15 * cm))
                for f in sds["findings"]:
                    kind_label = {
                        "duplicate": "Duplicate",
                        "shadow": "Shadow",
                        "conflict_shadow": "Conflict-Shadow",
                    }.get(f["kind"], f["kind"].title())
                    head = (
                        f"<b>[{kind_label} | {f['severity']}]</b> "
                        f"{_pdf_escape(f['earlier_rule_name'])} (pos {f['earlier_rule_index'] + 1}) "
                        f"→ {_pdf_escape(f['later_rule_name'])} (pos {f['later_rule_index'] + 1})"
                    )
                    story.append(Paragraph(head, styles["finding_head"]))
                    story.append(
                        Paragraph(
                            f"<b>Description:</b> {_pdf_escape(f['description'])}",
                            styles["body"],
                        )
                    )
                    story.append(
                        Paragraph(
                            f"<b>Recommendation:</b> {_pdf_escape(f['recommendation'])}",
                            styles["body"],
                        )
                    )
                    story.append(Spacer(1, 0.2 * cm))

        doc = SimpleDocTemplate(
            str(p),
            pagesize=A4,
            rightMargin=2 * cm,
            leftMargin=2 * cm,
            topMargin=2 * cm,
            bottomMargin=2 * cm,
            title=f"Firewall Rule Compliance Audit Report — {self.organization}",
            author=self.organization,
        )

        # --- Usage-0 / Never-Hit Rules (FortiGate AND Palo Alto) ---
        raw_results_pdf = payload.get("raw_rule_results", [])
        usage0_pdf = [
            r.get("rule_name", "?")
            for r in raw_results_pdf
            if any(
                "Hit Count is 0" in str(iss) or "Usage 0" in str(iss)
                for iss in (r.get("issues") or [])
            )
        ]
        if usage0_pdf:
            story.append(Spacer(1, 0.3 * cm))
            section_title("Rule Usage 0 / Never-Hit Rules")
            body_para(
                f"{len(usage0_pdf)} rule(s) have a Hit Count of 0 — these rules have never matched "
                "any traffic since the usage counter was last reset. This applies to both "
                "Palo Alto (Rule Usage Hit Count = 0) and FortiGate (hitcount / bytes = 0) exports."
            )
            for nm in usage0_pdf:
                body_para(f"  \u2022 {nm}")
            body_para(
                "Recommendation: Review the business justification for each zero-hit rule. "
                "Rules that serve no active traffic should be decommissioned or disabled to reduce "
                "the attack surface and simplify the ruleset."
            )

        # --- Service=any + Application=defined (Palo Alto App-ID) ---
        svc_any_app_def_pdf = [
            r.get("rule_name", "?")
            for r in raw_results_pdf
            if any(
                "Service is 'any' but Application is defined" in str(iss)
                for iss in (r.get("issues") or [])
            )
        ]
        if svc_any_app_def_pdf:
            story.append(Spacer(1, 0.3 * cm))
            section_title("Service=any with Application Defined (Palo Alto App-ID)")
            body_para(
                f"{len(svc_any_app_def_pdf)} rule(s) have Service set to 'any' but define a specific "
                "Application (App-ID). On Palo Alto, App-ID enforcement constrains the traffic to "
                "the named application(s) even when Service is unconstrained — this is NOT treated "
                "as overly permissive by this audit engine."
            )
            for nm in svc_any_app_def_pdf:
                body_para(f"  \u2022 {nm}")
            body_para(
                "Observation: While App-ID provides effective L7 control, least-privilege best "
                "practice recommends pairing the Application definition with an explicit Service "
                "object to eliminate reliance on App-ID alone for port governance. "
                "Verify that App-ID security profiles are active on each of these rules."
            )

        doc.build(story)
        logger.info("Wrote PDF report to %s", p.resolve())

    def save_json(self, payload: dict[str, Any], path: str | Path) -> None:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        logger.info("Wrote JSON report to %s", p.resolve())

    def save_excel(self, payload: dict[str, Any], path: str | Path) -> None:
        """Excel workbook: Summary, Findings, Rule results."""
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)

        meta = payload["report_metadata"]
        dr = payload.get("disabled_rules") or {"count": 0, "names": []}
        summary_rows = [
            {"Field": "Organization", "Value": self.organization},
            {"Field": "Generated (UTC)", "Value": meta["generated_at_utc"]},
            {"Field": "Compliance mode", "Value": meta["compliance_mode"]},
            {"Field": "Rules reviewed", "Value": meta["rules_reviewed"]},
            {"Field": "Disabled rules (count)", "Value": dr.get("count", 0)},
            {
                "Field": "Disabled rule names",
                "Value": "; ".join(str(x) for x in (dr.get("names") or [])) or "(none)",
            },
            {"Field": "Overall risk", "Value": payload["risk_rating"].get("overall")},
        ]
        # Shadow detection summary rows
        sds_xl = payload.get("duplicate_shadow_detection")
        if sds_xl:
            summary_rows += [
                {"Field": "Shadow/Dup — Rules analysed", "Value": sds_xl.get("rules_analysed", 0)},
                {"Field": "Shadow/Dup — Disabled skipped", "Value": sds_xl.get("rules_skipped_disabled", 0)},
                {"Field": "Shadow/Dup — Duplicates", "Value": sds_xl.get("duplicate_count", 0)},
                {"Field": "Shadow/Dup — Shadows", "Value": sds_xl.get("shadow_count", 0)},
                {"Field": "Shadow/Dup — Conflict-shadows", "Value": sds_xl.get("conflict_shadow_count", 0)},
                {"Field": "Shadow/Dup — Overall severity", "Value": sds_xl.get("overall_severity", "")},
                {"Field": "Shadow/Dup — Summary", "Value": sds_xl.get("summary", "")},
            ]
        summary_rows += [
            {"Field": "Executive summary", "Value": payload["executive_summary"]},
            {"Field": "Conclusion", "Value": payload["conclusion"]},
        ]

        # Usage-0 summary
        u0_xl = payload.get("rule_usage_zero_summary")
        if u0_xl:
            summary_rows += [
                {"Field": "Usage-0 Rules — Count", "Value": u0_xl.get("count", 0)},
                {"Field": "Usage-0 Rules — Names", "Value": "; ".join(u0_xl.get("rule_names") or [])},
                {"Field": "Usage-0 Rules — Note", "Value": u0_xl.get("note", "")},
            ]

        # Service=any + App=defined summary
        sad_xl = payload.get("service_any_application_defined_summary")
        if sad_xl:
            summary_rows += [
                {"Field": "Svc=any/App=defined — Count", "Value": sad_xl.get("count", 0)},
                {"Field": "Svc=any/App=defined — Names", "Value": "; ".join(sad_xl.get("rule_names") or [])},
                {"Field": "Svc=any/App=defined — Note", "Value": sad_xl.get("note", "")},
            ]

        df_summary = pd.DataFrame(summary_rows)

        findings = payload["observations_findings"]
        df_findings = pd.DataFrame(findings) if findings else pd.DataFrame(columns=["finding_id"])

        raw = payload.get("raw_rule_results", [])
        if raw:
            flat: list[dict[str, Any]] = []
            for row in raw:
                d = dict(row)
                if isinstance(d.get("issues"), list):
                    d["issues"] = "; ".join(str(x) for x in d["issues"])
                if isinstance(d.get("raw_rule"), dict):
                    # Hoist key FortiGate fields to top-level columns for easy reading in Excel
                    rr = d["raw_rule"]
                    if "Log Traffic" not in d and rr.get("Log Traffic"):
                        d["Log Traffic"] = rr["Log Traffic"]
                    if "fortigate_logtraffic_off" not in d and "fortigate_logtraffic_off" in rr:
                        d["fortigate_logtraffic_off"] = rr["fortigate_logtraffic_off"]
                    if "Rule Usage Last Hit" not in d and rr.get("Rule Usage Last Hit"):
                        d["Rule Usage Last Hit"] = rr["Rule Usage Last Hit"]
                    if "Rule Usage Hit Count" not in d and rr.get("Rule Usage Hit Count") is not None:
                        d["Rule Usage Hit Count"] = rr["Rule Usage Hit Count"]
                    d["raw_rule"] = json.dumps(rr, ensure_ascii=False)
                flat.append(d)
            df_rules = pd.DataFrame(flat)
        else:
            df_rules = pd.DataFrame()

        orig = payload.get("original_rule_results")
        df_orig = pd.DataFrame()
        if orig:
            flat_o: list[dict[str, Any]] = []
            for row in orig:
                d = dict(row)
                if isinstance(d.get("issues"), list):
                    d["issues"] = "; ".join(str(x) for x in d["issues"])
                flat_o.append(d)
            df_orig = pd.DataFrame(flat_o)

        with pd.ExcelWriter(p, engine="openpyxl") as writer:
            df_summary.to_excel(writer, sheet_name="Summary", index=False)
            df_findings.to_excel(writer, sheet_name="Findings", index=False)
            df_rules.to_excel(writer, sheet_name="Rule_Results", index=False)
            if not df_orig.empty:
                df_orig.to_excel(writer, sheet_name="Original_Audit", index=False)

            # --- Duplicate & Shadow Detection sheet ---
            sds = payload.get("duplicate_shadow_detection")
            if sds and sds.get("findings"):
                shadow_rows: list[dict[str, Any]] = []
                for f in sds["findings"]:
                    shadow_rows.append({
                        "Kind": f.get("kind", ""),
                        "Severity": f.get("severity", ""),
                        "Earlier Rule (Position)": f"{f.get('earlier_rule_name', '')} (#{f.get('earlier_rule_index', 0) + 1})",
                        "Later Rule (Position)": f"{f.get('later_rule_name', '')} (#{f.get('later_rule_index', 0) + 1})",
                        "Description": f.get("description", ""),
                        "Recommendation": f.get("recommendation", ""),
                    })
                pd.DataFrame(shadow_rows).to_excel(
                    writer, sheet_name="Shadow_Duplicate", index=False
                )

            # --- Usage-0 Rules sheet ---
            u0_data = payload.get("rule_usage_zero_summary")
            if u0_data and u0_data.get("rule_names"):
                u0_rows = [
                    {
                        "Rule Name": nm,
                        "Finding": "Hit Count = 0 — never matched any traffic since counter reset",
                        "Applies To": "Palo Alto (Rule Usage Hit Count=0) and FortiGate (hitcount/bytes=0)",
                        "Recommendation": (
                            "Review business justification; decommission or disable if no active "
                            "traffic is expected."
                        ),
                    }
                    for nm in u0_data["rule_names"]
                ]
                pd.DataFrame(u0_rows).to_excel(writer, sheet_name="Usage_Zero_Rules", index=False)

            # --- Service=any + Application=defined sheet ---
            sad_data = payload.get("service_any_application_defined_summary")
            if sad_data and sad_data.get("rule_names"):
                sad_rows = [
                    {
                        "Rule Name": nm,
                        "Observation": (
                            "Service is 'any' but Application is explicitly defined. "
                            "App-ID enforcement restricts traffic — NOT overly permissive."
                        ),
                        "Platform": "Palo Alto (App-ID)",
                        "Recommendation": (
                            "Verify App-ID profiles are active. For least-privilege, add an "
                            "explicit Service object alongside the Application definition."
                        ),
                    }
                    for nm in sad_data["rule_names"]
                ]
                pd.DataFrame(sad_rows).to_excel(
                    writer, sheet_name="SvcAny_AppDefined", index=False
                )

        logger.info("Wrote Excel report to %s", p.resolve())