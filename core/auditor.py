"""
Firewall rule evaluation engine: maps rules + audit config to compliance results.
"""

from __future__ import annotations

import copy
import logging
from dataclasses import dataclass, field
from typing import Any

from utils.helpers import (
    application_any_observation,
    destination_side_unrestricted,
    effective_action_verb,
    get_rule_destination_for_audit,
    get_rule_source_for_audit,
    is_any_address,
    logtraffic_disabled_observation,
    max_severity,
    rule_action_is_allow,
    rule_effective_ports_for_policy,
    rule_is_disabled,
    source_side_unrestricted,
    stale_rule_observation_message,
)

logger = logging.getLogger(__name__)

SEVERITY_ORDER = ("Low", "Medium", "High", "Critical")


def _as_port_int(p: Any) -> int | None:
    if isinstance(p, int):
        return p
    try:
        return int(str(p).strip())
    except (TypeError, ValueError):
        return None


def _config_bool(cfg: dict[str, Any], key: str, default: bool = True) -> bool:
    """Coerce config flags so string ``\"false\"`` is not treated as truthy."""
    if key not in cfg:
        return default
    v = cfg[key]
    if isinstance(v, bool):
        return v
    if isinstance(v, str):
        return v.strip().lower() in ("1", "true", "yes", "on")
    return bool(v)


@dataclass
class RuleAuditResult:
    """Structured output for a single firewall rule."""

    rule_name: str
    status: str  # "compliant" | "non-compliant"
    severity: str
    issues: list[str] = field(default_factory=list)
    recommendation: str = ""
    # Severity from the real audit engine (preserved when fake compliance marks a rule compliant).
    original_severity: str = ""
    is_disabled: bool = False
    # Full input row (e.g. all finacus.json columns) when include_full_rule_snapshot is enabled.
    raw_rule: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "rule_name": self.rule_name,
            "status": self.status,
            "severity": self.severity,
            "issues": list(self.issues),
            "recommendation": self.recommendation,
            "original_severity": self.original_severity or self.severity,
            "is_disabled": self.is_disabled,
        }
        if self.raw_rule is not None:
            out["raw_rule"] = self.raw_rule
        return out


class FirewallAuditor:
    """
    Evaluates firewall rules against AUDIT_CONFIG-style parameters.

    Severity mapping (baseline):
      - Critical: allow + source ANY + destination ANY (overly permissive).
      - High: allow on blocked / insecure ports.
      - Medium: non-approved ports (when allowed_ports is enforced), or ANY source/dest
        when policy disallows them (and not already Critical).
      - Low: minor policy deviations (e.g., relaxed-only notes).
    """

    def __init__(self, audit_config: dict[str, Any]) -> None:
        self.cfg = audit_config
        self._mode = str(audit_config.get("compliance_mode", "strict")).lower()

    def audit_rules(self, rules: list[dict[str, Any]]) -> list[RuleAuditResult]:
        """Run evaluation for each rule; apply fake mode overlay last."""
        raw: list[RuleAuditResult] = []
        for r in rules:
            raw.append(self._evaluate_one(r))

        if self._mode == "fake":
            return [self._fake_overlay(x) for x in raw]
        return raw

    def _fake_overlay(self, result: RuleAuditResult) -> RuleAuditResult:
        """Override findings for demonstration / lab use only."""
        cloned = copy.deepcopy(result)
        cloned.status = "compliant"
        cloned.severity = "Low"
        cloned.issues = []
        cloned.recommendation = (
            "No remediation required under the demonstration compliance profile; "
            "use strict/relaxed mode for real assessments."
        )
        return cloned

    def _evaluate_one(self, rule: dict[str, Any]) -> RuleAuditResult:
        name = (
            str(
                rule.get("rule_name")
                or rule.get("Name")
                or rule.get("name")
                or rule.get("Rule Name")
                or rule.get("ruleName")
                or ""
            ).strip()
            or "(unnamed)"
        )
        prefixes_raw = self.cfg.get("disabled_name_prefixes")
        if isinstance(prefixes_raw, list):
            name_prefixes = tuple(str(x) for x in prefixes_raw)
        elif isinstance(prefixes_raw, tuple):
            name_prefixes = tuple(str(x) for x in prefixes_raw)
        else:
            name_prefixes = ()
        disabled_kw: dict[str, Any] = {}
        if name_prefixes:
            disabled_kw["disabled_name_prefixes"] = name_prefixes

        lit_raw = self.cfg.get("disabled_rule_name_literals")
        if isinstance(lit_raw, list):
            disabled_kw["disabled_rule_name_literals"] = tuple(str(x) for x in lit_raw)
        elif isinstance(lit_raw, tuple):
            disabled_kw["disabled_rule_name_literals"] = tuple(str(x) for x in lit_raw)

        disabled_kw["disabled_scan_segments"] = _config_bool(
            self.cfg, "disabled_scan_rule_segments", default=True
        )
        disabled_kw["disabled_scan_all_string_fields"] = _config_bool(
            self.cfg, "disabled_scan_all_string_fields", default=True
        )

        snapshot: dict[str, Any] | None = None
        if _config_bool(self.cfg, "include_full_rule_snapshot", default=True):
            snapshot = copy.deepcopy(rule)

        if _config_bool(self.cfg, "recognize_disabled_rules", default=True) and rule_is_disabled(
            rule,
            **disabled_kw,
        ):
            return RuleAuditResult(
                rule_name=name,
                status="compliant",
                severity="Low",
                issues=[],
                recommendation=(
                    "Rule is marked disabled / inactive in the supplied data; it is assumed "
                    "not to enforce traffic on the appliance. Confirm state in the live configuration."
                ),
                original_severity="Low",
                is_disabled=True,
                raw_rule=snapshot,
            )

        include_app_ports = _config_bool(self.cfg, "include_application_in_port_checks", default=True)
        ports = rule_effective_ports_for_policy(rule, include_application=include_app_ports)

        issues: list[str] = []
        severity = "Low"
        relaxed = self._mode == "relaxed"

        inc_zone = _config_bool(self.cfg, "audit_include_zones_in_any", default=True)
        inc_app = _config_bool(self.cfg, "audit_include_application_in_any", default=True)
        inc_user = _config_bool(self.cfg, "audit_include_source_user_in_any", default=True)

        src_unrestricted = source_side_unrestricted(
            rule, include_zones=inc_zone, include_user=inc_user
        )
        dst_unrestricted = destination_side_unrestricted(
            rule, include_zones=inc_zone, include_application=inc_app
        )
        is_allow = rule_action_is_allow(rule)

        policy_any_src = _config_bool(self.cfg, "allow_any_source", default=True) and _config_bool(
            self.cfg, "allow_any_source_address", default=True
        )
        policy_any_dst = _config_bool(self.cfg, "allow_any_destination", default=True) and _config_bool(
            self.cfg, "allow_any_destination_address", default=True
        )

        # --- Critical: broad allow (addresses and/or zones/users/application per config) ---
        if is_allow and src_unrestricted and dst_unrestricted:
            issues.append(
                "Rule permits traffic with unconstrained source and destination "
                "(addresses and/or zones/users/application per audit configuration)."
            )
            severity = max_severity(severity, "Critical", SEVERITY_ORDER)

        # --- High: insecure / blocked ports on allow ---
        if is_allow:
            for p in ports:
                if p == "any":
                    issues.append(
                        "Allow rule does not restrict destination port(s); any port may be permitted."
                    )
                    severity = max_severity(severity, "High" if not relaxed else "Medium", SEVERITY_ORDER)
                    break
                pnum = _as_port_int(p)
                if pnum is not None and pnum in self.cfg.get("blocked_ports", []):
                    issues.append(
                        f"Allow rule exposes blocked/insecure port {pnum} per audit configuration."
                    )
                    severity = max_severity(severity, "High" if not relaxed else "Medium", SEVERITY_ORDER)

        # --- Medium: non-approved ports ---
        allowed_only = self.cfg.get("allowed_ports") or []
        if is_allow and allowed_only and ports:
            for p in ports:
                if p == "any":
                    continue
                pnum = _as_port_int(p)
                if pnum is not None and pnum not in allowed_only:
                    issues.append(
                        f"Port {pnum} is not in the approved port list for this review."
                    )
                    severity = max_severity(severity, "Medium" if not relaxed else "Low", SEVERITY_ORDER)

        # --- ANY source / destination when policy forbids ---
        if is_allow:
            if not policy_any_src and src_unrestricted and not (src_unrestricted and dst_unrestricted):
                issues.append(
                    "Source side is unconstrained (address/zone/user per configuration) while "
                    "policy disallows unconstrained source."
                )
                severity = max_severity(severity, "Medium" if not relaxed else "Low", SEVERITY_ORDER)
            if not policy_any_dst and dst_unrestricted and not (src_unrestricted and dst_unrestricted):
                issues.append(
                    "Destination side is unconstrained (address/zone/application per configuration) "
                    "while policy disallows unconstrained destination."
                )
                severity = max_severity(severity, "Medium" if not relaxed else "Low", SEVERITY_ORDER)

        # --- Observations: stale rule (Rule Usage Last Hit vs current time) ---
        if _config_bool(self.cfg, "observe_stale_rules", default=True):
            try:
                months_th = float(self.cfg.get("stale_rule_months_threshold", 6))
            except (TypeError, ValueError):
                months_th = 6.0
            stale_msg = stale_rule_observation_message(rule, months_threshold=months_th)
            if stale_msg:
                issues.append(stale_msg)
                severity = max_severity(severity, "Low", SEVERITY_ORDER)

        # --- Observation: Application field (all sub-cases) ---
        if is_allow and _config_bool(self.cfg, "observe_application_any", default=True):
            app_msg = application_any_observation(rule)
            if app_msg:
                issues.append(app_msg)
                # Case A (both any) → Low escalation, appropriate.
                # Case C (Service=any, App=defined) → observation-only, keep Low.
                # Both are Low; max_severity against "Low" is a no-op for higher severities
                # but explicitly records a Low-level observation entry.
                severity = max_severity(severity, "Low", SEVERITY_ORDER)

        # --- Observation: FortiGate logtraffic disabled (allow rules only) ---
        if is_allow and _config_bool(self.cfg, "observe_fortigate_logtraffic_disabled", default=True):
            lt_msg = logtraffic_disabled_observation(rule)
            if lt_msg:
                issues.append(lt_msg)
                severity = max_severity(severity, "Medium", SEVERITY_ORDER)

        # Deny rules: do not mark broad catch-all denies as non-compliant (often intended).

        # --- Missing explicit deny (advanced / heuristic): suggest if no broad deny at end ---
        # Implemented at batch level in optional helper; keep per-rule simple.

        status = "compliant" if not issues else "non-compliant"
        recommendation = self._recommendation_for(issues, severity)

        if not issues:
            recommendation = (
                "No deviations detected for this rule under the current audit parameters."
            )

        return RuleAuditResult(
            rule_name=name,
            status=status,
            severity=severity,
            issues=issues,
            recommendation=recommendation,
            original_severity=severity,
            is_disabled=False,
            raw_rule=snapshot,
        )

    def _recommendation_for(self, issues: list[str], severity: str) -> str:
        if not issues:
            return ""
        if severity == "Critical":
            return (
                "Restrict source and destination to least-privilege subnets and hosts; "
                "replace broad any-any permits with explicit, approved endpoints."
            )
        if severity == "High":
            return (
                "Disable or replace services on blocked ports; use approved alternatives "
                "(e.g., TLS on approved ports) and document exceptions."
            )
        if severity == "Medium":
            return (
                "Align ports and address objects with the approved baseline; "
                "obtain formal exception approval where business-critical."
            )
        return (
            "Review rule intent against change records; tighten configuration where feasible."
        )


def optional_batch_checks(
    rules: list[dict[str, Any]],
    results: list[RuleAuditResult],
    *,
    run_shadow_detection: bool = True,
    shadow_detection_result: Any | None = None,
) -> list[str]:
    """
    Optional advanced checks: default-deny advisory + duplicate/shadow summary note.

    ``shadow_detection_result`` may be a pre-computed ``ShadowDetectionResult``
    (from ``shadow_detector.detect_duplicates_and_shadows``) so the caller can
    pass it in without running detection twice.  When ``run_shadow_detection`` is
    True and no pre-computed result is supplied, detection is run here.

    Returns advisory strings (not attached to a single rule by default).
    """
    notes: list[str] = []
    has_broad_deny = any(
        effective_action_verb(r) in ("deny", "drop", "reject", "block")
        and is_any_address(str(get_rule_source_for_audit(r) or ""))
        and is_any_address(str(get_rule_destination_for_audit(r) or ""))
        for r in rules
    )
    if not has_broad_deny:
        notes.append(
            "No explicit any-any deny rule observed; validate default deny behavior "
            "on the platform and document implicit deny posture."
        )

    if run_shadow_detection:
        sdr = shadow_detection_result
        if sdr is None:
            try:
                from core.shadow_detector import detect_duplicates_and_shadows
                sdr = detect_duplicates_and_shadows(rules)
            except Exception as exc:  # noqa: BLE001
                logger.warning("Shadow detection skipped due to error: %s", exc)
                sdr = None
        if sdr is not None and sdr.findings:
            notes.append(f"[Shadow/Duplicate] {sdr.summary_text()}")

    return notes