"""
Audit configuration for firewall rule evaluation.

`compliance_mode`:
  - "strict": Full checks; findings reflect actual posture.
  - "relaxed": Same checks; some severities may be downgraded in the auditor.
  - "fake": Ignored for the real audit engine (engine uses strict). Use post-audit interactive
    prompts, or ``python main.py --no-prompt --mode fake`` for legacy blanket demo only.
"""

from __future__ import annotations

from typing import Any, Literal

ComplianceMode = Literal["strict", "relaxed", "fake"]

# Default audit parameters (customize per engagement).
AUDIT_CONFIG: dict[str, Any] = {
    # Ports that must not be allowed inbound/outbound per policy (examples).
    "blocked_ports": [20, 21, 23, 80, 88, 135, 137, 139, 389, 445, 8080, 3389],
    # If non-empty, allows not in this set are flagged (when action is allow).
    "allowed_ports": [443, 8443, 22, 53],
    # Whether 0.0.0.0/0 / "any" style sources are permitted by policy (combined with
    # allow_any_source_address — both must be True to allow unconstrained source).
    "allow_any_source": False,
    # Same for source address columns (e.g. Palo Alto "Source Address"); both this and
    # allow_any_source must be True to skip any-source findings.
    "allow_any_source_address": False,
    # Whether any-destination style targets are permitted.
    "allow_any_destination": False,
    "allow_any_destination_address": False,
    # When True, honor disabled flags and name prefixes; see utils.rule_is_disabled.
    "recognize_disabled_rules": True,
    # Split Name / Tags / Action by ; or newline and treat each segment that starts with
    # [Disabled] as disabled (Palo Alto multi-value cells).
    "disabled_scan_rule_segments": True,
    # When True, scan every string column in each rule row for disabled markers (finacus.json
    # style: [Disabled] may appear on Name, Service, zones, etc.).
    "disabled_scan_all_string_fields": True,
    # Include the full input rule object (all JSON keys) on each audit result for traceability.
    "include_full_rule_snapshot": True,
    # Use Application / zones / user columns in any-wildcard checks (besides addresses).
    "audit_include_application_in_any": True,
    "audit_include_zones_in_any": True,
    "audit_include_source_user_in_any": True,
    # CIDR ranges considered approved for sources (informational / future use).
    "allowed_source_ranges": [
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
    ],
    # Start of rule_name / Name or Action (after strip; comparison is case-insensitive). Include
    # "[Disabled]" for Palo Alto-style exports. Optional "disabled" matches only when followed by
    # whitespace and further text (avoids a rule literally named "Disabled").
    # Prefixes checked at the start of each segment (after strip), not only whole-field start.
    "disabled_name_prefixes": ["[Disabled]", "[disabled]", "disabled"],
    # If non-empty, any rule whose rule_name / Name (etc.) equals one of these strings (after strip,
    # case-insensitive) is treated as disabled — e.g. ["disabled"] for a literal rule name "Disabled".
    # Leave empty if you have an active rule whose only title is the word "Disabled".
    "disabled_rule_name_literals": [],
    # Rule Usage Last Hit: if last match is older than this many months vs current time, add an observation.
    "stale_rule_months_threshold": 6,
    "observe_stale_rules": True,
    # Treat Application column like Service when deriving ports for blocked/allowed checks.
    "include_application_in_port_checks": True,
    # Report an explicit observation when Application is "any" (allow rules).
    "observe_application_any": True,
    # FortiGate: report when logtraffic is "disable" on an allow rule (Medium severity).
    # Set to False if logtraffic is managed externally and missing from the export.
    "observe_fortigate_logtraffic_disabled": True,
    # Operating mode for the audit engine and reporting.
    "compliance_mode": "strict",
}


def get_audit_config(overrides: dict[str, Any] | None = None) -> dict[str, Any]:
    """Return a copy of the audit config with optional key overrides."""
    cfg = AUDIT_CONFIG.copy()
    if overrides:
        cfg.update(overrides)
    return cfg
