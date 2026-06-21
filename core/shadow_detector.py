"""
Duplicate & Shadow Rule Detection Engine.

Definitions
-----------
Duplicate rule
    Two rules that match IDENTICAL traffic: same source address set, destination
    address set, service/port set, and action.  Only the first rule (by position)
    will ever be evaluated; the second is dead weight and increases review surface.

Shadow rule
    A rule that is entirely superseded by an earlier, broader rule:
      - The earlier rule's source set CONTAINS the later rule's source set (or is "any").
      - The earlier rule's destination set CONTAINS the later rule's destination set (or is "any").
      - The earlier rule's port/service set CONTAINS the later rule's ports (or is "any").
      - Both rules have the same action — so the later rule can never add or change behaviour.
    A deny shadowing an allow (or vice-versa) is reported separately as a
    "conflict shadow": the later rule's intent is blocked by the earlier rule.

Supported platforms
-------------------
Palo Alto (finacus.json style)
    Fields: Source Address, Destination Address, Source Zone, Destination Zone,
            Application, Service, Action — all multi-value semicolon-separated.

FortiGate (Netmagic.json / fortigate_normalize.py style)
    Same field names after normalization (fortigate_normalize maps FortiOS keys
    to Source Address / Destination Address / Service / Action / Source Zone /
    Destination Zone).  Raw FortiOS dicts are accepted transparently because
    utils helper functions already handle both key sets.

Algorithm
---------
1. Build a canonical "fingerprint" for each active rule:
     - Sorted frozenset of normalised source-address tokens.
     - Sorted frozenset of normalised destination-address tokens.
     - Sorted frozenset of port integers (or frozenset{"any"} for wildcard).
     - Normalised action verb.
2. Compare every pair (i, j) where i < j (preserving policy order).
3. Report DUPLICATE when all four fingerprint dimensions are equal.
4. Report SHADOW when dimensions of rule i are supersets of rule j's dimensions
   (i.e. every packet matching j also matches i, so j is never reached).
5. Report CONFLICT SHADOW when the above containment holds but actions differ.

Complexity: O(n²) — fine for typical rulesets (< 5000 rules).  For very large
rulesets the caller can pre-filter by zone pair before calling this module.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any

from utils.helpers import (
    effective_action_verb,
    get_application_for_audit,
    get_destination_zone_for_audit,
    get_rule_destination_for_audit,
    get_rule_source_for_audit,
    get_source_zone_for_audit,
    is_any_address,
    multi_value_field_has_any,
    parse_service_field,
    rule_is_disabled,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Internal types
# ---------------------------------------------------------------------------

_ANY_SENTINEL = frozenset({"any"})


@dataclass
class ShadowFinding:
    """One duplicate or shadow finding between two rules."""

    kind: str  # "duplicate" | "shadow" | "conflict_shadow"
    earlier_index: int          # 0-based position in the supplied rule list
    later_index: int
    earlier_name: str
    later_name: str
    severity: str               # "High" for shadow, "Medium" for conflict, "Low" for duplicate
    description: str
    recommendation: str
    dimensions: dict[str, Any] = field(default_factory=dict)  # diagnostic detail

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "severity": self.severity,
            "earlier_rule_index": self.earlier_index,
            "earlier_rule_name": self.earlier_name,
            "later_rule_index": self.later_index,
            "later_rule_name": self.later_name,
            "description": self.description,
            "recommendation": self.recommendation,
            "dimensions": self.dimensions,
        }


# ---------------------------------------------------------------------------
# Address-set normalisation
# ---------------------------------------------------------------------------

def _split_multi_value(raw: str) -> list[str]:
    """Split a semicolon/newline-delimited field into individual tokens."""
    return [t.strip() for t in re.split(r"[;\n\r]+", raw) if t.strip()]


def _normalize_addr_token(tok: str) -> str:
    """Lowercase and strip whitespace from one address token."""
    return tok.strip().lower()


def _addr_frozenset(raw: str) -> frozenset[str]:
    """
    Build a frozenset of normalised address tokens from a raw field value.
    Returns _ANY_SENTINEL when the field is a wildcard.
    """
    if not raw or not raw.strip():
        return _ANY_SENTINEL          # absent = treat conservatively as any
    if multi_value_field_has_any(raw):
        return _ANY_SENTINEL
    tokens = _split_multi_value(raw)
    if not tokens:
        return _ANY_SENTINEL
    return frozenset(_normalize_addr_token(t) for t in tokens)


def _zone_frozenset(raw: str) -> frozenset[str]:
    """Frozenset of normalised zone tokens; empty string → frozenset() (no zone filter)."""
    if not raw or not raw.strip():
        return frozenset()
    if multi_value_field_has_any(raw):
        return _ANY_SENTINEL
    return frozenset(_normalize_addr_token(t) for t in _split_multi_value(raw))


def _service_frozenset(rule: dict[str, Any]) -> frozenset[str]:
    """
    Build a frozenset of port strings from Service + Application.

    Strategy (mirrors the fix in utils.rule_effective_ports_for_policy):
      - Service wins if it has real ports.
      - Application="any" is only "any" when Service is also any/absent.
      - Result is _ANY_SENTINEL when ports are unconstrained.
    """
    svc_raw = rule.get("Service") or rule.get("Services") or rule.get("service")
    svc_ports = parse_service_field(svc_raw)

    svc_has_real = bool(svc_ports) and svc_ports != ["any"]
    if svc_has_real:
        return frozenset(str(p) for p in svc_ports)

    # Service is any/absent — check Application
    app_raw = get_application_for_audit(rule)
    if app_raw.strip() and not multi_value_field_has_any(app_raw):
        # Specific application names: use service ports only (may be empty → any)
        if svc_ports and svc_ports != ["any"]:
            return frozenset(str(p) for p in svc_ports)

    # Both service and application are unconstrained
    if (not svc_ports) or svc_ports == ["any"]:
        return _ANY_SENTINEL

    return frozenset(str(p) for p in svc_ports)


# ---------------------------------------------------------------------------
# Fingerprint
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class _RuleFingerprint:
    src_addrs: frozenset[str]
    dst_addrs: frozenset[str]
    src_zones: frozenset[str]
    dst_zones: frozenset[str]
    services: frozenset[str]
    action: str                    # normalised verb: allow / deny / drop / …

    def is_duplicate_of(self, other: "_RuleFingerprint") -> bool:
        """True when self and other match identical traffic with the same action."""
        return (
            self.src_addrs == other.src_addrs
            and self.dst_addrs == other.dst_addrs
            and self.services == other.services
            and self.action == other.action
            # Zones are supplementary: if both sides have zone info, include in match.
            and self._zones_equal(other)
        )

    def _zones_equal(self, other: "_RuleFingerprint") -> bool:
        # If either side has no zone info, skip zone comparison (zone-agnostic dataset).
        if not self.src_zones and not other.src_zones:
            return True
        if not self.dst_zones and not other.dst_zones:
            return True
        return self.src_zones == other.src_zones and self.dst_zones == other.dst_zones

    def contains(self, other: "_RuleFingerprint") -> bool:
        """
        True when self's traffic scope is a superset of other's — i.e. every packet
        matching 'other' also matches 'self', making 'other' unreachable in policy order.

        Containment rules per dimension:
          address/service set A (self) contains set B (other) when:
            - A is _ANY_SENTINEL, OR
            - B is a subset of A (every token in B also appears in A).
          zone set: if self has no zones (zone-agnostic), containment holds;
            otherwise self.zones must be a superset of other.zones.
        """
        # Source address containment
        if self.src_addrs != _ANY_SENTINEL:
            if other.src_addrs == _ANY_SENTINEL:
                return False          # self is specific; other is broader — no containment
            if not other.src_addrs.issubset(self.src_addrs):
                return False

        # Destination address containment
        if self.dst_addrs != _ANY_SENTINEL:
            if other.dst_addrs == _ANY_SENTINEL:
                return False
            if not other.dst_addrs.issubset(self.dst_addrs):
                return False

        # Service/port containment
        if self.services != _ANY_SENTINEL:
            if other.services == _ANY_SENTINEL:
                return False
            if not other.services.issubset(self.services):
                return False

        # Zone containment (optional — skip when zone data is absent)
        if self.src_zones and other.src_zones:
            if self.src_zones != _ANY_SENTINEL and not other.src_zones.issubset(self.src_zones):
                return False
        if self.dst_zones and other.dst_zones:
            if self.dst_zones != _ANY_SENTINEL and not other.dst_zones.issubset(self.dst_zones):
                return False

        return True


def _build_fingerprint(rule: dict[str, Any]) -> _RuleFingerprint:
    src_raw = get_rule_source_for_audit(rule)
    dst_raw = get_rule_destination_for_audit(rule)
    src_zone_raw = get_source_zone_for_audit(rule)
    dst_zone_raw = get_destination_zone_for_audit(rule)

    return _RuleFingerprint(
        src_addrs=_addr_frozenset(src_raw),
        dst_addrs=_addr_frozenset(dst_raw),
        src_zones=_zone_frozenset(src_zone_raw),
        dst_zones=_zone_frozenset(dst_zone_raw),
        services=_service_frozenset(rule),
        action=effective_action_verb(rule),
    )


# ---------------------------------------------------------------------------
# Rule name helper
# ---------------------------------------------------------------------------

def _is_meaningful_rule(rule: dict[str, Any]) -> bool:
    """
    True when a rule has enough substance to be worth comparing.

    Filters out blank spacer rows that appear in Palo Alto / Panorama CSV
    exports (rows that have FIELD1=None and no Name/Action/Service values).
    """
    has_name = any(
        str(rule.get(k, "")).strip()
        for k in ("rule_name", "Name", "name", "Rule Name", "ruleName")
    )
    has_action = bool(effective_action_verb(rule))
    return has_name or has_action


def _rule_name(rule: dict[str, Any], idx: int) -> str:
    for k in ("rule_name", "Name", "name", "Rule Name", "ruleName"):
        v = rule.get(k)
        if v and str(v).strip():
            return str(v).strip()
    return f"(rule #{idx + 1})"


# ---------------------------------------------------------------------------
# Finding builders
# ---------------------------------------------------------------------------

def _duplicate_finding(
    i: int, j: int,
    fp_i: _RuleFingerprint, fp_j: _RuleFingerprint,
    name_i: str, name_j: str,
) -> ShadowFinding:
    return ShadowFinding(
        kind="duplicate",
        earlier_index=i,
        later_index=j,
        earlier_name=name_i,
        later_name=name_j,
        severity="Medium",
        description=(
            f"Rule '{name_j}' (position {j + 1}) is an exact duplicate of "
            f"'{name_i}' (position {i + 1}): both rules match identical source, "
            f"destination, service, and action. The later rule is never evaluated "
            "and creates unnecessary management overhead."
        ),
        recommendation=(
            f"Remove or consolidate '{name_j}' into '{name_i}'. "
            "Retain change-management evidence of the deletion."
        ),
        dimensions={
            "src_addrs": sorted(fp_i.src_addrs),
            "dst_addrs": sorted(fp_i.dst_addrs),
            "services": sorted(fp_i.services),
            "action": fp_i.action,
        },
    )


def _shadow_finding(
    i: int, j: int,
    fp_i: _RuleFingerprint, fp_j: _RuleFingerprint,
    name_i: str, name_j: str,
) -> ShadowFinding:
    same_action = fp_i.action == fp_j.action
    if same_action:
        kind = "shadow"
        severity = "High"
        desc = (
            f"Rule '{name_j}' (position {j + 1}) is shadowed by the broader rule "
            f"'{name_i}' (position {i + 1}): every packet that would match '{name_j}' "
            f"is already matched and actioned by '{name_i}' earlier in the policy. "
            f"Both rules have action '{fp_i.action}', so '{name_j}' is effectively dead."
        )
        rec = (
            f"Evaluate whether '{name_j}' was intended to be more specific than "
            f"'{name_i}'. If '{name_i}' is intentionally broad, remove '{name_j}' to "
            f"reduce ruleset complexity. If '{name_j}' was meant to override "
            f"'{name_i}', reorder it to appear earlier in the policy."
        )
    else:
        kind = "conflict_shadow"
        severity = "High"
        desc = (
            f"Rule '{name_j}' (action: {fp_j.action}, position {j + 1}) is blocked "
            f"by the conflicting rule '{name_i}' (action: {fp_i.action}, position "
            f"{i + 1}): '{name_i}' matches all traffic that '{name_j}' intends to "
            f"{fp_j.action}, so '{name_j}' can never be reached. This is a policy "
            "conflict that may indicate misconfiguration."
        )
        rec = (
            f"Resolve the policy conflict between '{name_i}' and '{name_j}'. "
            f"If '{name_j}' should take precedence, move it above '{name_i}'. "
            f"If '{name_i}' correctly supersedes '{name_j}', remove '{name_j}' "
            "to eliminate dead rules and avoid audit confusion."
        )

    dimensions: dict[str, Any] = {
        "shadowing_rule_src": sorted(fp_i.src_addrs),
        "shadowing_rule_dst": sorted(fp_i.dst_addrs),
        "shadowing_rule_services": sorted(fp_i.services),
        "shadowing_rule_action": fp_i.action,
        "shadowed_rule_src": sorted(fp_j.src_addrs),
        "shadowed_rule_dst": sorted(fp_j.dst_addrs),
        "shadowed_rule_services": sorted(fp_j.services),
        "shadowed_rule_action": fp_j.action,
    }

    return ShadowFinding(
        kind=kind,
        earlier_index=i,
        later_index=j,
        earlier_name=name_i,
        later_name=name_j,
        severity=severity,
        description=desc,
        recommendation=rec,
        dimensions=dimensions,
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

@dataclass
class ShadowDetectionResult:
    """Aggregate output of a duplicate/shadow detection run."""

    findings: list[ShadowFinding]
    rules_analysed: int
    rules_skipped_disabled: int
    duplicate_count: int
    shadow_count: int
    conflict_shadow_count: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "rules_analysed": self.rules_analysed,
            "rules_skipped_disabled": self.rules_skipped_disabled,
            "duplicate_count": self.duplicate_count,
            "shadow_count": self.shadow_count,
            "conflict_shadow_count": self.conflict_shadow_count,
            "total_findings": len(self.findings),
            "findings": [f.to_dict() for f in self.findings],
        }

    @property
    def overall_severity(self) -> str:
        if self.shadow_count > 0 or self.conflict_shadow_count > 0:
            return "High"
        if self.duplicate_count > 0:
            return "Medium"
        return "Low"

    def summary_text(self) -> str:
        if not self.findings:
            return (
                f"No duplicate or shadow rules detected among the "
                f"{self.rules_analysed} active rule(s) analysed."
            )
        parts = []
        if self.duplicate_count:
            parts.append(f"{self.duplicate_count} duplicate pair(s)")
        if self.shadow_count:
            parts.append(f"{self.shadow_count} shadow pair(s)")
        if self.conflict_shadow_count:
            parts.append(f"{self.conflict_shadow_count} conflict-shadow pair(s)")
        return (
            f"Detected {', '.join(parts)} among {self.rules_analysed} active rule(s) "
            f"({self.rules_skipped_disabled} disabled rule(s) excluded from comparison). "
            f"Overall severity: {self.overall_severity}."
        )


def detect_duplicates_and_shadows(
    rules: list[dict[str, Any]],
    *,
    disabled_name_prefixes: tuple[str, ...] | None = None,
    disabled_rule_name_literals: tuple[str, ...] | None = None,
    skip_disabled: bool = True,
    max_findings: int = 500,
) -> ShadowDetectionResult:
    """
    Run duplicate and shadow detection over an ordered list of firewall rules.

    Parameters
    ----------
    rules:
        Ordered list of rule dicts (Palo Alto export columns or
        FortiGate-normalized rows).  Policy order matters: rule at index 0 is
        evaluated first.
    disabled_name_prefixes:
        Forwarded to ``utils.rule_is_disabled``; defaults to standard prefixes.
    disabled_rule_name_literals:
        Forwarded to ``utils.rule_is_disabled``.
    skip_disabled:
        When True (default), disabled rules are excluded from comparison — they
        are not active on the appliance so cannot shadow active rules.
    max_findings:
        Cap total findings returned (prevents report bloat on very large sets).

    Returns
    -------
    ShadowDetectionResult
    """
    active_indices: list[int] = []
    skipped = 0

    for idx, rule in enumerate(rules):
        # Skip blank spacer rows (no name, no action — export artefacts)
        if not _is_meaningful_rule(rule):
            skipped += 1
            continue
        if skip_disabled and rule_is_disabled(
            rule,
            disabled_name_prefixes=disabled_name_prefixes,
            disabled_rule_name_literals=disabled_rule_name_literals,
        ):
            skipped += 1
            continue
        active_indices.append(idx)

    # Build fingerprints for all active rules
    fingerprints: dict[int, _RuleFingerprint] = {}
    names: dict[int, str] = {}
    for idx in active_indices:
        try:
            fingerprints[idx] = _build_fingerprint(rules[idx])
            names[idx] = _rule_name(rules[idx], idx)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Could not fingerprint rule at index %d: %s", idx, exc)

    findings: list[ShadowFinding] = []
    dup_count = 0
    shadow_count = 0
    conflict_count = 0

    n = len(active_indices)
    for ii in range(n):
        if len(findings) >= max_findings:
            logger.warning(
                "Shadow detection: max_findings=%d reached; remaining pairs skipped.",
                max_findings,
            )
            break
        i = active_indices[ii]
        fp_i = fingerprints.get(i)
        if fp_i is None:
            continue

        for jj in range(ii + 1, n):
            if len(findings) >= max_findings:
                break
            j = active_indices[jj]
            fp_j = fingerprints.get(j)
            if fp_j is None:
                continue

            # Both rules must have a resolved action to be comparable
            if not fp_i.action or not fp_j.action:
                continue

            if fp_i.is_duplicate_of(fp_j):
                findings.append(
                    _duplicate_finding(i, j, fp_i, fp_j, names[i], names[j])
                )
                dup_count += 1

            elif fp_i.contains(fp_j):
                f = _shadow_finding(i, j, fp_i, fp_j, names[i], names[j])
                findings.append(f)
                if f.kind == "conflict_shadow":
                    conflict_count += 1
                else:
                    shadow_count += 1

    return ShadowDetectionResult(
        findings=findings,
        rules_analysed=len(active_indices),
        rules_skipped_disabled=skipped,
        duplicate_count=dup_count,
        shadow_count=shadow_count,
        conflict_shadow_count=conflict_count,
    )
