"""
FortiGate → common audit row format for FirewallAuditor / utils.

The auditor resolves fields via flexible keys (see utils.get_rule_source_for_audit, etc.).
This module maps Fortinet policy objects to those keys.

Reference: ``config firewall policy`` stanzas in a FortiOS backup (see also
``config firewall address``, ``config firewall addrgrp``, ``config firewall service custom``,
``config firewall service group``).

Usage:
  - Parse backup to structured JSON (policy list + optional address/service catalogs).
  - Call :func:`fortinet_policies_to_normalized_rows` with catalogs for resolved IPs,
    or :func:`fortinet_policy_to_normalized_row` for a single policy using literal names.
"""

from __future__ import annotations

import re
from typing import Any

# ---------------------------------------------------------------------------
# 1) Fortinet policy fields typically required for audit parity with Palo Alto exports
# ---------------------------------------------------------------------------
#
# Core (config firewall policy / edit <id>):
#   policyid          — edit number (FortiOS internal id; display order may differ)
#   name              — set name
#   uuid              — set uuid (optional for audit)
#   srcintf           — set srcintf (quoted list or "any")
#   dstintf           — set dstintf
#   srcaddr           — set srcaddr (address/addrgrp names, or "all")
#   dstaddr           — set dstaddr
#   service           — set service (custom/group names, or "ALL")
#   action            — set action accept | deny | ipsec | ssl-vpn | ...
#   schedule          — set schedule (e.g. "always")
#   status            — set status enable | disable (omit => enable)
#   logtraffic        — set logtraffic all | utm | disable | ...
#   nat               — set nat enable | disable
#
# Common extensions (same stanza):
#   users, groups      — identity / FSSO
#   utm-status         — UTM on/off
#   comments           — free text
#   internet-service-name, internet-service-src-name — ISDB objects (not L3 addresses)
#   global-label       — policy packages (FMG)
#
# Resolved elsewhere (not on policy line):
#   Address objects    — config firewall address / multicast / ...
#   Groups             — config firewall addrgrp
#   Services           — config firewall service custom|group
#   Schedules          — config firewall schedule onetime|recurring
#
# Often missing in static backup vs Palo Alto export:
#   Rule Usage Last Hit / Hit Count — live stats; use REST API / execute log or FMG
# ---------------------------------------------------------------------------


def _quote_split_fortinet_list(value: str) -> list[str]:
    """Split FortiOS quoted tokens: ``\"a\" \"b\"`` or single token."""
    if not value or not str(value).strip():
        return []
    s = str(value).strip()
    parts = re.findall(r'"([^"]*)"', s)
    if parts:
        return [p for p in parts if p]
    return [s]


def _join_semicolon(parts: list[str]) -> str:
    return ";".join(parts) if parts else ""


def _truthy_fortios(v: Any) -> bool:
    """FortiOS CLI often uses ``enable`` / omit; JSON may use bool."""
    if v is None:
        return False
    if isinstance(v, bool):
        return v
    s = str(v).strip().lower()
    return s in ("enable", "true", "yes", "1")


def fortinet_service_to_service_column(
    service_tokens: list[str],
    *,
    service_catalog: dict[str, Any] | None = None,
) -> str:
    """
    Map FortiGate ``service`` tokens to the auditor's ``Service``-like string.

    - ``ALL`` → ``any`` (logical any port/service).
    - Custom services like ``TCP 8288`` pass through; port extraction is handled by utils.parse_service_field.
    - If ``service_catalog`` maps name → {tcp-portrange, udp-portrange}, expand to a portable string.
    """
    if not service_tokens:
        return ""
    if len(service_tokens) == 1 and service_tokens[0].upper() == "ALL":
        return "any"
    out: list[str] = []
    for tok in service_tokens:
        if service_catalog and tok in service_catalog:
            ent = service_catalog[tok]
            # Minimal: support dicts from parsed custom service
            tcp = ent.get("tcp-portrange") or ent.get("tcp_portrange")
            udp = ent.get("udp-portrange") or ent.get("udp_portrange")
            if tcp:
                out.append(f"tcp/{tcp}")
            if udp:
                out.append(f"udp/{udp}")
            if not tcp and not udp:
                out.append(tok)
        else:
            out.append(tok)
    return ";".join(out)


def fortinet_addresses_to_source_destination_columns(
    srcaddr_tokens: list[str],
    dstaddr_tokens: list[str],
    *,
    address_catalog: dict[str, str] | None = None,
    treat_all_as_any: bool = True,
) -> tuple[str, str]:
    """
    Build ``Source Address`` / ``Destination Address`` strings for the auditor.

    If ``address_catalog`` maps object name → subnet string (e.g. ``192.168.1.0/24``),
    join resolved values. Otherwise join object names (still auditable for ``any`` tokens).
    """
    def resolve(tokens: list[str]) -> str:
        if not tokens:
            return ""
        if treat_all_as_any and len(tokens) == 1 and tokens[0].lower() == "all":
            return "any"
        resolved: list[str] = []
        for t in tokens:
            if treat_all_as_any and t.lower() == "all":
                resolved.append("any")
            elif address_catalog and t in address_catalog:
                resolved.append(address_catalog[t])
            else:
                resolved.append(t)
        return ";".join(resolved)

    return resolve(srcaddr_tokens), resolve(dstaddr_tokens)


def fortinet_policy_to_normalized_row(
    policy: dict[str, Any],
    *,
    address_catalog: dict[str, str] | None = None,
    service_catalog: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Convert one FortiGate policy dict (flat keys) to the common audit schema used by utils/auditor.

    Expected keys in ``policy`` (CLI JSON style):
      policyid, name, srcintf, dstintf, srcaddr, dstaddr, service (str or list),
      action, schedule, status, logtraffic, nat, users, groups, comments, ...
    """
    pid = policy.get("policyid") if policy.get("policyid") is not None else policy.get("edit")
    name = str(policy.get("name") or policy.get("Name") or f"policy-{pid}" or "unnamed")

    # Interfaces → Palo Alto–style zone columns already read by utils
    srcintf = policy.get("srcintf") or policy.get("src_intf")
    dstintf = policy.get("dstintf") or policy.get("dst_intf")
    if isinstance(srcintf, list):
        src_zone = _join_semicolon([str(x) for x in srcintf])
    else:
        src_zone = str(srcintf or "").strip()
    if isinstance(dstintf, list):
        dst_zone = _join_semicolon([str(x) for x in dstintf])
    else:
        dst_zone = str(dstintf or "").strip()

    # Address object lists (string or list)
    raw_src = policy.get("srcaddr") or policy.get("src_addr") or ""
    raw_dst = policy.get("dstaddr") or policy.get("dst_addr") or ""
    if isinstance(raw_src, list):
        src_toks = [str(x).strip() for x in raw_src if str(x).strip()]
    else:
        src_toks = _quote_split_fortinet_list(str(raw_src))
    if isinstance(raw_dst, list):
        dst_toks = [str(x).strip() for x in raw_dst if str(x).strip()]
    else:
        dst_toks = _quote_split_fortinet_list(str(raw_dst))

    # Internet Service DB (ISDB): when enabled, object lists may omit classic addr lines.
    if _truthy_fortios(policy.get("internet-service")):
        isn = policy.get("internet-service-name")
        if isn:
            if isinstance(isn, list):
                dst_isdb = [str(x).strip() for x in isn if str(x).strip()]
            else:
                dst_isdb = _quote_split_fortinet_list(str(isn))
            if dst_isdb and not dst_toks:
                dst_toks = dst_isdb
    if _truthy_fortios(policy.get("internet-service-src")):
        isns = policy.get("internet-service-src-name")
        if isns:
            if isinstance(isns, list):
                src_isdb = [str(x).strip() for x in isns if str(x).strip()]
            else:
                src_isdb = _quote_split_fortinet_list(str(isns))
            if src_isdb and not src_toks:
                src_toks = src_isdb

    src_col, dst_col = fortinet_addresses_to_source_destination_columns(
        src_toks,
        dst_toks,
        address_catalog=address_catalog,
        treat_all_as_any=True,
    )

    # Service
    raw_svc = policy.get("service") or policy.get("services") or ""
    if isinstance(raw_svc, list):
        svc_toks = [str(x).strip() for x in raw_svc if str(x).strip()]
    else:
        svc_toks = _quote_split_fortinet_list(str(raw_svc))
    service_col = fortinet_service_to_service_column(svc_toks, service_catalog=service_catalog)

    # Action: accept → allow (auditor uses rule_action_is_allow)
    act = str(policy.get("action") or "").strip().lower()
    if act in ("accept", "ipsec", "ssl-vpn"):
        action_str = "allow"
    elif act == "deny":
        action_str = "deny"
    else:
        action_str = act or "allow"

    # Disabled policy
    st = str(policy.get("status") or "enable").strip().lower()
    is_disabled = st == "disable"

    # ------------------------------------------------------------------
    # Logtraffic: map to audit-visible column + derive a boolean flag.
    # FortiOS values: "all" | "utm" | "disable" | omitted (default=utm)
    # We surface:
    #   fortigate_logtraffic      — raw value for traceability
    #   Log Traffic               — human-readable label for the report
    #   fortigate_logtraffic_off  — True when logging is explicitly disabled
    # ------------------------------------------------------------------
    raw_logtraffic = str(policy.get("logtraffic") or "").strip().lower()
    logtraffic_off = raw_logtraffic == "disable"
    if raw_logtraffic == "all":
        logtraffic_label = "All Sessions"
    elif raw_logtraffic in ("utm", ""):
        logtraffic_label = "UTM/Security Events Only"
    elif raw_logtraffic == "disable":
        logtraffic_label = "Disabled"
    else:
        logtraffic_label = raw_logtraffic or "UTM/Security Events Only"

    # ------------------------------------------------------------------
    # Rule Usage / Last Hit: FortiOS REST API exports may carry these
    # under various key names.  Map all variants to the canonical key
    # that utils.stale_rule_observation_message reads.
    # ------------------------------------------------------------------
    last_hit_raw = (
        policy.get("Rule Usage Last Hit")
        or policy.get("last-used")          # FortiOS REST /api/v2/monitor/firewall/policy/
        or policy.get("last_used")
        or policy.get("last-hit")
        or policy.get("last_hit")
        or policy.get("last_active")
    )
    hit_count_raw = (
        policy.get("Rule Usage Hit Count")
        or policy.get("hitcount")
        or policy.get("hit_count")
        or policy.get("bytes")              # FortiOS REST also returns bytes/pkts
    )
    # Resolve a canonical integer-friendly hit-count value for _rule_usage_hit_count_is_zero.
    # We need to distinguish "not present" (None) from "present but zero" (0).
    # Prefer the most explicit counter; fall back in order.
    _hc_candidates = [
        policy.get("Rule Usage Hit Count"),
        policy.get("hitcount"),
        policy.get("hit_count"),
        policy.get("bytes"),
        policy.get("pkts"),
    ]
    resolved_hit_count: int | None = None
    for _hc in _hc_candidates:
        if _hc is not None:
            try:
                resolved_hit_count = int(str(_hc).strip())
                break
            except (ValueError, TypeError):
                pass

    row: dict[str, Any] = {
        # Canonical minimal schema
        "rule_name": name,
        "Name": name,
        "source": src_col,
        "destination": dst_col,
        "port": None,
        "action": action_str,
        # Palo Alto–aligned keys consumed by utils
        "Source Address": src_col,
        "Destination Address": dst_col,
        "Source Zone": src_zone,
        "Destination Zone": dst_zone,
        "Service": service_col,
        "Action": "Allow" if action_str == "allow" else "Deny",
        # Log Traffic columns (audit-visible)
        "Log Traffic": logtraffic_label,
        "fortigate_logtraffic_off": logtraffic_off,
        # Fortinet originals (traceability)
        "fortigate_policyid": pid,
        "fortigate_uuid": policy.get("uuid"),
        "fortigate_schedule": policy.get("schedule"),
        "fortigate_logtraffic": policy.get("logtraffic"),
        "fortigate_nat": policy.get("nat"),
        "fortigate_users": policy.get("users"),
        "fortigate_groups": policy.get("groups"),
        "fortigate_comments": policy.get("comments"),
        "fortigate_internet_service": _truthy_fortios(policy.get("internet-service")),
        "fortigate_internet_service_src": _truthy_fortios(policy.get("internet-service-src")),
        # NOTE: use fortigate_policy_status to avoid shadowing the utils
        # rule_is_disabled check which reads the bare "status" key.
        # The "status" key intentionally remains absent here so that the
        # is_disabled boolean (below) is the single source of truth.
        "fortigate_policy_status": "disable" if is_disabled else "enable",
        "is_disabled": is_disabled,
    }

    isn_dst = policy.get("internet-service-name")
    if isinstance(isn_dst, list):
        row["fortigate_internet_service_name"] = ";".join(str(x) for x in isn_dst)
    elif isn_dst:
        row["fortigate_internet_service_name"] = str(isn_dst)
    isn_src = policy.get("internet-service-src-name")
    if isinstance(isn_src, list):
        row["fortigate_internet_service_src_name"] = ";".join(str(x) for x in isn_src)
    elif isn_src:
        row["fortigate_internet_service_src_name"] = str(isn_src)

    # Optional: identity column maps to Source User
    users = policy.get("users")
    groups = policy.get("groups")
    id_parts: list[str] = []
    if users:
        if isinstance(users, list):
            id_parts.extend(str(u) for u in users)
        else:
            id_parts.append(str(users))
    if groups:
        if isinstance(groups, list):
            id_parts.extend(f"group:{g}" for g in groups)
        else:
            id_parts.append(f"group:{groups}")
    if id_parts:
        row["Source User"] = ";".join(id_parts)

    # Application column — L7 app lists; ISDB destination names (overlap with address columns when expanded above)
    app_parts: list[str] = []
    if isn_dst:
        if isinstance(isn_dst, list):
            app_parts.append(";".join(str(x) for x in isn_dst))
        else:
            app_parts.append(str(isn_dst))
    if isn_src:
        if isinstance(isn_src, list):
            app_parts.append("ISDB_SRC:" + ";".join(str(x) for x in isn_src))
        else:
            app_parts.append("ISDB_SRC:" + str(isn_src))
    if app_parts:
        row["Application"] = " | ".join(app_parts)

    # ------------------------------------------------------------------
    # Stale / usage stats.  Populated from any of the recognised source
    # key variants resolved above (REST API, FortiManager, custom ETL).
    # ------------------------------------------------------------------
    if last_hit_raw is not None:
        row["Rule Usage Last Hit"] = last_hit_raw
    # Surface resolved hit count with the canonical key so _rule_usage_hit_count_is_zero works.
    # We write it even when the value is 0 (falsy) — that's exactly the case we need to detect.
    if resolved_hit_count is not None:
        row["Rule Usage Hit Count"] = resolved_hit_count
    elif hit_count_raw is not None:
        row["Rule Usage Hit Count"] = hit_count_raw

    return row


def fortinet_policies_to_normalized_rows(
    policies: list[dict[str, Any]],
    *,
    address_catalog: dict[str, str] | None = None,
    service_catalog: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Batch-normalize FortiGate policy dicts."""
    return [
        fortinet_policy_to_normalized_row(p, address_catalog=address_catalog, service_catalog=service_catalog)
        for p in policies
    ]
