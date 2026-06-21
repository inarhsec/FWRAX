"""
Shared helpers: JSON loading, port normalization, ANY detection, logging setup.
"""

from __future__ import annotations

import json
import logging
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

# Patterns treated as "any" for source/destination in firewall-like strings.
_ANY_TOKENS = frozenset(
    {
        "any",
        "*",
        "0.0.0.0/0",
        "0.0.0.0",
        "::/0",
        "::",
        "all",
    }
)

# Used when ``disabled_name_prefixes`` is not set in audit config (matching is case-insensitive).
_DEFAULT_DISABLED_DISPLAY_PREFIXES: tuple[str, ...] = (
    "[Disabled]",
    "[disabled]",
    "disabled",
)


def setup_logging(level: int = logging.INFO) -> None:
    """Configure root logging for CLI runs."""
    logging.basicConfig(
        level=level,
        format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def load_json_file(path: str | Path) -> Any:
    """Load and parse a JSON file with clear errors."""
    p = Path(path)
    if not p.is_file():
        raise FileNotFoundError(f"Rules file not found: {p.resolve()}")
    try:
        text = p.read_text(encoding="utf-8")
    except OSError as e:
        raise OSError(f"Cannot read rules file: {p}") from e
    try:
        return json.loads(text)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON in {p}: {e}") from e


def rules_from_audit_report_raw_results(raw: list[Any]) -> list[dict[str, Any]]:
    """
    Build minimal rule dicts from ``raw_rule_results`` in a prior ``--out-json`` report.

    Preserves ``is_disabled`` when present so disabled rules stay classified without
    re-supplying full firewall columns (Name/Action/Service).
    """
    out: list[dict[str, Any]] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        name = str(item.get("rule_name", "") or "(unnamed)")
        row: dict[str, Any] = {"rule_name": name, "Name": name}
        if item.get("is_disabled") is True:
            row["is_disabled"] = True
        out.append(row)
    return out


def coerce_rules_input(data: Any) -> list[dict[str, Any]]:
    """
    Normalize loaded JSON into a list of rule dicts for the auditor.

    Accepts:
      - A JSON array of firewall objects (e.g. Palo Alto CSV export as in finacus.json).
      - A prior audit report object that contains ``raw_rule_results`` (e.g. newrule.json
        from ``--out-json``).
    """
    if isinstance(data, list):
        if not all(isinstance(x, dict) for x in data):
            raise ValueError("Rules file must be a JSON array of objects.")
        return list(data)

    if isinstance(data, dict):
        raw = data.get("raw_rule_results")
        if isinstance(raw, list) and raw:
            probe = next((x for x in raw if isinstance(x, dict)), None)
            if probe is not None and ("rule_name" in probe or "is_disabled" in probe):
                if not all(isinstance(x, dict) for x in raw):
                    raise ValueError("raw_rule_results must be an array of objects.")
                return rules_from_audit_report_raw_results(raw)

    raise ValueError(
        "Rules file must be either (1) a JSON array of firewall rule objects with fields "
        "like Name / Action (e.g. finacus.json), or (2) a prior audit report JSON from this "
        "tool that includes a raw_rule_results array."
    )


def _normalize_rule_text(value: Any) -> str:
    """Strip BOM/whitespace, map fullwidth brackets to ASCII, lowercase (start-only prefix checks)."""
    s = str(value).replace("\ufeff", "").strip()
    s = s.replace("\uff3b", "[").replace("\uff3d", "]")
    return s.lower()


def _text_matches_disabled_prefixes(text: str, prefixes: tuple[str, ...]) -> bool:
    """True when the normalized string *starts with* a configured prefix (after strip)."""
    s = _normalize_rule_text(text)
    if not s:
        return False
    for p in prefixes:
        pl = _normalize_rule_text(p)
        if not pl:
            continue
        if pl == "disabled":
            # Word "disabled" at start, or whole field is literally "disabled" / "disabled."
            if re.match(r"^disabled(\s+\S|\.)?$", s) or re.match(r"^disabled\s+\S", s):
                return True
            if s == "disabled" or s.rstrip(".") == "disabled":
                return True
        elif s.startswith(pl):
            return True
    return False


def _segment_fields_disabled(text: Any, prefixes: tuple[str, ...]) -> bool:
    """
    True if any semicolon/newline-separated segment (typical Palo Alto exports) starts with
    a disabled prefix — e.g. ``LAN_Zone;[Disabled] MPLS_Zone`` or ``Name;[Disabled] alt``.
    """
    if text is None:
        return False
    raw = str(text).replace("\ufeff", "")
    for seg in re.split(r"[\n\r;]+", raw):
        t = seg.strip()
        if not t:
            continue
        if _text_matches_disabled_prefixes(t, prefixes):
            return True
    return False


def _iter_rule_name_candidates(rule: dict[str, Any]):
    """Yield non-blank display names from common export keys (order matters)."""
    for key in ("rule_name", "Name", "name", "Rule Name", "ruleName"):
        v = rule.get(key)
        if v is None:
            continue
        t = str(v).strip()
        if t:
            yield t


def _iter_tags_candidates(rule: dict[str, Any]):
    for key in ("Tags", "Tag", "tags", "tag"):
        v = rule.get(key)
        if v is None:
            continue
        t = str(v).strip()
        if t:
            yield t


def _display_name_indicates_disabled(
    rule: dict[str, Any],
    name_prefixes: tuple[str, ...] | None = None,
    *,
    scan_segments: bool = True,
) -> bool:
    """
    True when any name/tag/action field indicates a disabled rule.

    Supports Palo Alto-style ``[Disabled]`` at the start of the cell or at the start of any
    ``;``-separated segment (multi-value zones/names).
    """
    prefixes = name_prefixes if name_prefixes else _DEFAULT_DISABLED_DISPLAY_PREFIXES

    def check_field(val: Any) -> bool:
        if val is None:
            return False
        s = str(val).strip()
        if not s:
            return False
        if _text_matches_disabled_prefixes(s, prefixes):
            return True
        if scan_segments and _segment_fields_disabled(s, prefixes):
            return True
        return False

    for raw in _iter_rule_name_candidates(rule):
        if check_field(raw):
            return True

    for raw in _iter_tags_candidates(rule):
        if check_field(raw):
            return True

    for key in ("Type", "type"):
        val = rule.get(key)
        if val is not None and check_field(str(val)):
            return True

    for key in ("action", "Action"):
        val = rule.get(key)
        if val is not None and check_field(str(val)):
            return True

    return False


def _rule_display_name_matches_literals(
    rule: dict[str, Any],
    literals: tuple[str, ...] | None,
) -> bool:
    """True if any non-empty rule_name / Name / … candidate equals a configured string (case-insensitive)."""
    if not literals:
        return False
    lowered = {str(x).strip().lower() for x in literals if str(x).strip()}
    if not lowered:
        return False
    for raw in _iter_rule_name_candidates(rule):
        nm = str(raw).strip().lower()
        if nm and nm in lowered:
            return True
    return False


def rule_is_disabled(
    rule: dict[str, Any],
    *,
    disabled_name_prefixes: tuple[str, ...] | None = None,
    disabled_rule_name_literals: tuple[str, ...] | None = None,
    disabled_scan_segments: bool = True,
    disabled_scan_all_string_fields: bool = True,
) -> bool:
    """
    True if the rule object indicates it is not active on the appliance.

    Supports: explicit ``is_disabled: true`` (e.g. rows rebuilt from ``raw_rule_results``),
    disabled/enabled/active/status fields, display names matching ``disabled_name_prefixes``
    (e.g. leading ``[Disabled]``), and optional exact full-name matches via
    ``disabled_rule_name_literals``.
    """
    if rule.get("is_disabled") is True:
        return True

    if disabled_scan_all_string_fields and rule_row_any_string_suggests_disabled(
        rule,
        disabled_name_prefixes=disabled_name_prefixes,
        scan_segments=disabled_scan_segments,
    ):
        return True

    if _display_name_indicates_disabled(
        rule,
        name_prefixes=disabled_name_prefixes,
        scan_segments=disabled_scan_segments,
    ):
        return True

    if _rule_display_name_matches_literals(rule, disabled_rule_name_literals):
        return True

    if rule.get("disabled") is True:
        return True
    ds = str(rule.get("disabled", "")).strip().lower()
    if ds in ("true", "1", "yes"):
        return True

    if rule.get("enabled") is False:
        return True
    es = str(rule.get("enabled", "")).strip().lower()
    if es in ("false", "0", "no"):
        return True

    if rule.get("active") is False:
        return True
    act = str(rule.get("active", "")).strip().lower()
    if act in ("false", "0", "no"):
        return True

    # FortiOS uses "disable" (no trailing d); also accept "disabled", "inactive", "off".
    status = str(rule.get("status", "")).strip().lower()
    return status in ("disable", "disabled", "inactive", "off")


def is_any_address(value: str | None) -> bool:
    """True if value represents an unconstrained source or destination."""
    if value is None:
        return False
    s = str(value).strip().lower()
    if not s:
        return False
    if s in _ANY_TOKENS:
        return True
    # IPv4 "any" style
    if re.fullmatch(r"0\.0\.0\.0(/\d+)?", s):
        return True
    return False


def multi_value_field_has_any(value: str | None) -> bool:
    """
    True if the whole value or any ``;``/newline-separated segment is an unconstrained token
    (``any``, ``*``, etc.) — typical of Palo Alto multi-value cells.
    """
    if value is None:
        return False
    raw = str(value).strip()
    if not raw:
        return False
    if is_any_address(raw):
        return True
    for seg in re.split(r"[\n\r;]+", raw):
        t = seg.strip()
        if t and is_any_address(t):
            return True
    return False


def get_source_zone_for_audit(rule: dict[str, Any]) -> str:
    for k in ("Source Zone", "source_zone", "SourceZone"):
        v = rule.get(k)
        if v is not None and str(v).strip() != "":
            return str(v).strip()
    return ""


def get_destination_zone_for_audit(rule: dict[str, Any]) -> str:
    for k in ("Destination Zone", "destination_zone", "DestinationZone"):
        v = rule.get(k)
        if v is not None and str(v).strip() != "":
            return str(v).strip()
    return ""


def get_source_user_for_audit(rule: dict[str, Any]) -> str:
    for k in ("Source User", "source_user", "SourceUser"):
        v = rule.get(k)
        if v is not None and str(v).strip() != "":
            return str(v).strip()
    return ""


def get_application_for_audit(rule: dict[str, Any]) -> str:
    for k in ("Application", "application", "Applications"):
        v = rule.get(k)
        if v is not None and str(v).strip() != "":
            return str(v).strip()
    return ""


def build_finacus_audit_view(rule: dict[str, Any]) -> dict[str, Any]:
    """
    Collect all common export columns (finacus.json / Palo Alto style) into one structure.
    ``full_record`` is a shallow copy of the entire rule row so no JSON field is dropped.
    """
    fr = dict(rule)

    def pick(*keys: str) -> str:
        for k in keys:
            v = rule.get(k)
            if v is not None and str(v).strip() != "":
                return str(v).strip()
        return ""

    name = pick("rule_name", "Name", "name", "Rule Name", "ruleName")
    return {
        "full_record": fr,
        "name": name or "(unnamed)",
        "source_address": pick("Source Address", "source", "source_address", "src"),
        "destination_address": pick("Destination Address", "destination", "destination_address", "dst"),
        "source_zone": pick("Source Zone", "source_zone"),
        "destination_zone": pick("Destination Zone", "destination_zone"),
        "source_user": pick("Source User", "source_user"),
        "source_device": pick("Source Device", "source_device"),
        "destination_device": pick("Destination Device", "destination_device"),
        "application": pick("Application", "application"),
        "service_raw": rule.get("Service") if rule.get("Service") is not None else rule.get("Services") or rule.get("service"),
        "profile": pick("Profile", "profile"),
        "options": pick("Options", "options"),
        "tags": pick("Tags", "tags"),
        "type": pick("Type", "type"),
        "action_raw": pick("Action", "action"),
        "field_index": rule.get("FIELD1"),
        "rule_usage_hit_count": rule.get("Rule Usage Hit Count"),
        "rule_usage_last_hit": rule.get("Rule Usage Last Hit"),
        "rule_usage_first_hit": rule.get("Rule Usage First Hit"),
        "rule_usage_apps_seen": rule.get("Rule Usage Apps Seen"),
        "days_with_no_new_apps": rule.get("Days With No New Apps"),
        "modified": rule.get("Modified"),
        "created": rule.get("Created"),
    }


def source_side_unrestricted(
    rule: dict[str, Any],
    *,
    include_zones: bool,
    include_user: bool,
) -> bool:
    """
    Any-wildcard on source dimension using address + optional zone + optional user columns.

    Design rule (Palo Alto / finacus.json parity):
      - Source Address is the primary gate. If it is a specific IP/subnet (not any/wildcard),
        the rule is NOT unrestricted on the source side — even if Source User or Source Zone
        happens to be ``any``.  ``Source User = any`` is the platform default meaning
        "no user-identity filter applied"; it does not mean all source addresses are permitted.
      - Zone and User escalate to "unrestricted" ONLY when the source address is already
        unconstrained (i.e. any / 0.0.0.0/0).  A specific address with Source Zone = any
        is still pinned to that address and is not flagged here.
    """
    src_addr = get_rule_source_for_audit(rule)
    src_addr_any = multi_value_field_has_any(src_addr)

    # If address is specific, the source is constrained regardless of zone/user.
    if not src_addr_any and src_addr.strip():
        return False

    # Address is wildcard (or absent) — now check zone and user as escalation signals.
    if src_addr_any:
        return True

    # Address field is blank/absent: fall back to zone then user.
    if include_zones and multi_value_field_has_any(get_source_zone_for_audit(rule)):
        return True
    if include_user and multi_value_field_has_any(get_source_user_for_audit(rule)):
        return True
    return False


def destination_side_unrestricted(
    rule: dict[str, Any],
    *,
    include_zones: bool,
    include_application: bool,
) -> bool:
    """
    Any-wildcard on destination dimension using address + optional zone + optional application.

    Design rule (Palo Alto / finacus.json parity):
      - Destination Address is the primary gate. If it is a specific IP/subnet (not any/wildcard),
        the rule is NOT unrestricted on the destination side — even if Application or
        Destination Zone happens to be ``any``.
      - Application = ``any`` is treated as unconstrained ONLY when BOTH:
          (a) Destination Address is also unconstrained (any / 0.0.0.0/0), AND
          (b) Service is not concretely defined (i.e. Service is absent, blank, or ``any``).
        When Service carries a real port/service name (e.g. ``service-https``, ``TCP_443``),
        the service constraint already limits the traffic, so Application="any" is an
        *observation* rather than an *unrestricted destination* signal.
      - Service=any BUT Application IS defined (not any):
          App-ID enforcement on Palo Alto means the named app constrains the traffic even
          when Service is unconstrained.  This combination is NOT treated as an overly-
          permissive destination; a separate observation is emitted by
          ``application_any_observation`` (Case C in that function).
      - Destination Zone = any escalates to unrestricted only when Destination Address is
        already unconstrained.
    """
    dst_addr = get_rule_destination_for_audit(rule)
    dst_addr_any = multi_value_field_has_any(dst_addr)

    # Specific destination address → constrained regardless of zone/application.
    if not dst_addr_any and dst_addr.strip():
        return False

    # -----------------------------------------------------------------------
    # Helper: resolve the effective application posture for the caller context.
    #   include_application=False is passed through unchanged.
    #   When True, we may reduce it to False based on Service/App values.
    # -----------------------------------------------------------------------
    def _resolve_include_application(inc_app: bool) -> bool:
        if not inc_app:
            return False
        svc = rule.get("Service") or rule.get("Services") or rule.get("service")
        svc_ports = parse_service_field(svc)
        svc_is_any_or_absent = (not svc_ports) or (svc_ports == ["any"])
        app_raw = get_application_for_audit(rule)
        app_is_any = multi_value_field_has_any(app_raw) if app_raw.strip() else True

        if not svc_is_any_or_absent:
            # Service carries real ports → Application="any" is the PA default; not a gap.
            return False
        if not app_is_any and app_raw.strip():
            # Service=any but Application IS defined (not any).
            # App-ID constrains the traffic → NOT an unrestricted-destination signal.
            # application_any_observation emits a Case-C observation separately.
            return False
        # Both Service and Application are unconstrained → fully unrestricted.
        return True

    # Destination address is a wildcard.
    if dst_addr_any:
        effective_inc_app = _resolve_include_application(include_application)
        if include_zones and multi_value_field_has_any(get_destination_zone_for_audit(rule)):
            return True
        if effective_inc_app and multi_value_field_has_any(get_application_for_audit(rule)):
            return True
        # If Application IS defined (not any) and Service is any: App-ID constrains traffic.
        # Do NOT treat this as unrestricted even though the address is any.
        if include_application:
            svc2 = rule.get("Service") or rule.get("Services") or rule.get("service")
            svc_ports2 = parse_service_field(svc2)
            svc_any2 = (not svc_ports2) or (svc_ports2 == ["any"])
            app_raw2 = get_application_for_audit(rule)
            if svc_any2 and app_raw2.strip() and not multi_value_field_has_any(app_raw2):
                # Service=any + App=defined → App-ID governs; not unrestricted destination.
                return False
        return True  # address itself is any — destination is unrestricted

    # Address is blank/absent: fall back to zone then application.
    if include_zones and multi_value_field_has_any(get_destination_zone_for_audit(rule)):
        return True
    effective_inc_app = _resolve_include_application(include_application)
    if effective_inc_app and multi_value_field_has_any(get_application_for_audit(rule)):
        return True
    return False


def _check_value_for_disabled(
    val: Any,
    *,
    prefixes: tuple[str, ...],
    scan_segments: bool,
) -> bool:
    if isinstance(val, str):
        s = val.strip()
        if not s:
            return False
        if _text_matches_disabled_prefixes(s, prefixes):
            return True
        if scan_segments and _segment_fields_disabled(s, prefixes):
            return True
        return False
    if isinstance(val, list):
        for item in val:
            if _check_value_for_disabled(item, prefixes=prefixes, scan_segments=scan_segments):
                return True
    return False


def rule_row_any_string_suggests_disabled(
    rule: dict[str, Any],
    *,
    disabled_name_prefixes: tuple[str, ...] | None = None,
    scan_segments: bool = True,
) -> bool:
    """
    Scan every value in the rule object (all export columns) for disabled markers.
    Use for finacus.json rows where [Disabled] appears on Service, zones, etc.
    """
    prefixes = disabled_name_prefixes if disabled_name_prefixes else _DEFAULT_DISABLED_DISPLAY_PREFIXES
    for _key, val in rule.items():
        if _check_value_for_disabled(val, prefixes=prefixes, scan_segments=scan_segments):
            return True
    return False


def parse_ports(port_field: str | int | list[Any] | None) -> list[int | str]:
    """
    Normalize port field to a list of ints or the string 'any' for wildcard.
    Supports: 80, "80", "80,443", ["80","443"], "any".
    """
    if port_field is None:
        return []
    if isinstance(port_field, list):
        out: list[int | str] = []
        for item in port_field:
            out.extend(parse_ports(item))
        return out
    if isinstance(port_field, int):
        return [port_field]
    s = str(port_field).strip().lower()
    if s in _ANY_TOKENS or s == "0-65535":
        return ["any"]
    parts = re.split(r"[,;\s]+", s)
    result: list[int | str] = []
    for p in parts:
        if not p:
            continue
        pl = p.strip().lower()
        if pl in _ANY_TOKENS:
            result.append("any")
            continue
        if "-" in pl:
            # Range: take low end for audit heuristics
            low, _, _ = pl.partition("-")
            try:
                result.append(int(low))
            except ValueError:
                result.append(pl)
            continue
        try:
            result.append(int(pl))
        except ValueError:
            result.append(pl)
    return result


_SERVICE_TOKEN_PORTS: dict[str, list[int]] = {
    "service-http": [80],
    "service-https": [443],
    "http": [80],
    "https": [443],
    "ssh": [22],
    "dns": [53],
    "smtp": [25],
    "telnet": [23],
    "ftp": [21],
}

_RE_TCP_UDP_PORT = re.compile(r"^(?:tcp|udp)[_\s/-]+(\d{1,5})$", re.IGNORECASE)


def parse_service_field(val: Any) -> list[int | str]:
    """
    Derive port list from ``Service`` / ``Services`` columns (e.g. ``service-https``, ``TCP_445``).
    ``any`` / ``application-default`` → logical ``any``.
    """
    if val is None:
        return []
    if isinstance(val, list):
        acc: list[int | str] = []
        for item in val:
            acc.extend(parse_service_field(item))
        return acc if acc else []
    s = str(val).strip()
    if not s:
        return []
    low = s.lower()
    if low in _ANY_TOKENS or "application-default" in low:
        return ["any"]
    found: set[int] = set()
    for part in re.split(r"[;,\n\r]+", s):
        tok = part.strip()
        if not tok:
            continue
        tl = tok.lower()
        if tl in _ANY_TOKENS:
            return ["any"]
        if tl in _SERVICE_TOKEN_PORTS:
            for p in _SERVICE_TOKEN_PORTS[tl]:
                found.add(p)
            continue
        m = _RE_TCP_UDP_PORT.match(tok.strip())
        if m:
            p = int(m.group(1))
            if 1 <= p <= 65535:
                found.add(p)
                continue
        m2 = re.match(r"^(?:TCP|UDP)_(\d{1,5})$", tok.strip(), re.IGNORECASE)
        if m2:
            p = int(m2.group(1))
            if 1 <= p <= 65535:
                found.add(p)
                continue
        for n in re.findall(r"\b(\d{1,5})\b", tok):
            p = int(n)
            if 1 <= p <= 65535:
                found.add(p)
    if not found:
        return [s]
    return sorted(found)


def rule_ports_for_audit(rule: dict[str, Any]) -> list[int | str]:
    """Prefer explicit ``port``; otherwise parse ``Service`` / ``Services``."""
    if rule.get("port") is not None and str(rule.get("port")).strip() != "":
        return parse_ports(rule.get("port"))
    svc = rule.get("Service") or rule.get("Services") or rule.get("service")
    return parse_service_field(svc)


# Palo Alto application names → typical port(s) for policy alignment with Service-derived ports.
_APPLICATION_TO_PORTS: dict[str, list[int]] = {
    **_SERVICE_TOKEN_PORTS,
    "web-browsing": [80, 443],
    "web browsing": [80, 443],
    "ssl": [443],
    "ssl-tls": [443],
    "ms-rdp": [3389],
    "rdp": [3389],
    "ms-sql": [1433],
    "mssql": [1433],
    "oracle": [1521],
    "mysql": [3306],
    "postgresql": [5432],
    "mongodb": [27017],
    "snmp": [161],
    "ntp": [123],
    "icmp": [],
    "ping": [],
    "traceroute": [],
}


def parse_application_field(val: Any) -> list[int | str]:
    """
    Map ``Application`` cell values to port numbers where possible (complements ``Service``).
    ``any`` / ``application-default`` → ``any``.
    """
    if val is None:
        return []
    if isinstance(val, list):
        acc: list[int | str] = []
        for item in val:
            acc.extend(parse_application_field(item))
        return acc if acc else []
    s = str(val).strip()
    if not s:
        return []
    low = s.lower()
    if low in _ANY_TOKENS or "application-default" in low:
        return ["any"]
    found: set[int] = set()
    for part in re.split(r"[;,\n\r]+", s):
        tok = part.strip()
        if not tok:
            continue
        tl = tok.lower()
        if tl in _ANY_TOKENS:
            return ["any"]
        if tl in _APPLICATION_TO_PORTS:
            for p in _APPLICATION_TO_PORTS[tl]:
                if p:
                    found.add(p)
            continue
        m = _RE_TCP_UDP_PORT.match(tok.strip())
        if m:
            p = int(m.group(1))
            if 1 <= p <= 65535:
                found.add(p)
    if not found:
        return []
    return sorted(found)


def ports_from_application_field(rule: dict[str, Any]) -> list[int | str]:
    val = rule.get("Application") or rule.get("application") or rule.get("Applications")
    return parse_application_field(val)


def merge_port_lists(*lists: list[list[int | str]]) -> list[int | str]:
    """Union numeric ports; if any list contains ``any``, result is ``any``."""
    for L in lists:
        if not L:
            continue
        if any(x == "any" for x in L):
            return ["any"]
    nums: set[int] = set()
    for L in lists:
        for x in L:
            if x == "any":
                return ["any"]
            if isinstance(x, int):
                nums.add(x)
            else:
                try:
                    nums.add(int(str(x).strip()))
                except ValueError:
                    pass
    return sorted(nums)


def rule_effective_ports_for_policy(rule: dict[str, Any], *, include_application: bool = True) -> list[int | str]:
    """
    Combine Service-derived and Application-derived ports for blocked/allowed policy checks.

    Palo Alto semantics:
      - Service is the port-level gate. When Service has concrete ports (e.g. ``service-https``
        → 443), those are the effective ports regardless of Application.
      - Application = ``any`` means "match any L7 app on those ports" — it does NOT widen
        the port scope to "any port" when Service already pins specific ports.
      - Only when Service is absent/any AND Application is ``any`` do we treat the combined
        result as ``any`` (no port restriction at all).
    """
    svc_ports = rule_ports_for_audit(rule)
    if not include_application:
        return svc_ports

    app_ports = ports_from_application_field(rule)
    if not app_ports:
        return svc_ports

    # If Service provides real (non-any) ports, Application="any" must NOT escalate to "any".
    svc_has_real_ports = svc_ports and svc_ports != ["any"]
    app_is_any = app_ports == ["any"]

    if svc_has_real_ports and app_is_any:
        # Service constrains the ports; Application="any" is the PA default for service-based rules.
        return svc_ports

    if not svc_ports:
        # No service definition — application field is the only port signal.
        return app_ports

    return merge_port_lists(svc_ports, app_ports)


def parse_rule_usage_last_hit_to_utc(raw: Any) -> datetime | None:
    """
    Parse ``Rule Usage Last Hit`` style timestamps (e.g. ``02-04-2026 19:38``) to UTC.
    Tries common export formats.
    """
    if raw is None:
        return None
    s = str(raw).strip()
    if not s or s.lower() in ("none", "n/a", "-"):
        return None
    formats = (
        "%d-%m-%Y %H:%M",
        "%d-%m-%Y %H:%M:%S",
        "%m-%d-%Y %H:%M",
        "%m-%d-%Y %H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M",
        "%d/%m/%Y %H:%M",
        "%m/%d/%Y %H:%M",
    )
    for fmt in formats:
        try:
            dt = datetime.strptime(s, fmt)
            return dt.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def _rule_usage_hit_count_is_zero(rule: dict[str, Any]) -> bool:
    """
    Return True when the rule's hit-count field is present and equals zero.

    Recognises:
      - ``Rule Usage Hit Count``   (Palo Alto export — the "Usage 0" column)
      - ``rule_usage_hit_count``   (snake-case variant)
      - ``hitcount`` / ``hit_count`` (FortiOS REST API / FortiManager)
      - ``bytes`` / ``pkts``        (FortiOS REST API byte/packet counters)

    A value of 0 (int) or "0" (string) means the rule has NEVER matched traffic.
    Absent / None means the platform did not export usage data — we do NOT flag it.
    """
    for key in (
        "Rule Usage Hit Count",
        "rule_usage_hit_count",
        "hitcount",
        "hit_count",
        "bytes",
        "pkts",
    ):
        raw = rule.get(key)
        if raw is None:
            continue
        try:
            return int(str(raw).strip()) == 0
        except (ValueError, TypeError):
            pass
    return False


def stale_rule_observation_message(
    rule: dict[str, Any],
    *,
    months_threshold: float,
    now: datetime | None = None,
) -> str | None:
    """
    Return an observation string when a rule appears to be unused / stale.

    Two independent checks (either can trigger):

    1. **Hit-count = 0** — the rule has never matched any traffic since the counter
       was last reset.  Applies to both Palo Alto (``Rule Usage Hit Count = 0``) and
       FortiGate (``hitcount = 0`` / ``bytes = 0`` from the REST API).  This is the
       FortiGate equivalent of the Palo Alto "Usage 0" finding that was previously
       undetected for FortiGate rulesets.

    2. **Last-hit timestamp** older than ``months_threshold`` months — the rule matched
       traffic in the past but has not been exercised recently.

    Recognises Palo Alto and FortiGate key variants:
      - ``Rule Usage Last Hit`` (Palo Alto export / canonical key)
      - ``rule_usage_last_hit`` (snake-case variant)
      - ``last-used`` / ``last_used`` / ``last-hit`` / ``last_hit`` (FortiOS REST API)
      - ``last_active`` (FortiManager)
    """
    if months_threshold <= 0:
        return None
    now = now or datetime.now(timezone.utc)

    # --- Check 1: hit-count = 0 (never matched traffic) ---
    if _rule_usage_hit_count_is_zero(rule):
        return (
            "Observation: Rule Usage Hit Count is 0 — this rule has never matched any traffic "
            "since the counter was last reset (equivalent to 'Usage 0' on Palo Alto). "
            "Confirm whether the rule serves an active business purpose or should be decommissioned."
        )

    # --- Check 2: last-hit timestamp older than threshold ---
    raw = (
        rule.get("Rule Usage Last Hit")
        or rule.get("rule_usage_last_hit")
        or rule.get("last-used")
        or rule.get("last_used")
        or rule.get("last-hit")
        or rule.get("last_hit")
        or rule.get("last_active")
    )
    dt = parse_rule_usage_last_hit_to_utc(raw)
    if dt is None:
        return None
    if dt > now:
        return None
    # Calendar-like window: months_threshold * average days per month
    cutoff = now - timedelta(days=round(months_threshold * 30.437))
    if dt >= cutoff:
        return None
    age_days = (now - dt).days
    return (
        f"Observation: Rule Usage Last Hit ({raw}) is older than {months_threshold:g} month(s) "
        f"relative to the review time (approximately {age_days} days since last match); "
        "confirm whether the rule is still required or may be decommissioned."
    )


def logtraffic_disabled_observation(rule: dict[str, Any]) -> str | None:
    """
    Return an observation string when FortiGate ``logtraffic`` is explicitly disabled on an
    allow rule.  Silent logging gaps undermine SIEM visibility and incident response.

    Reads:
      - ``fortigate_logtraffic_off`` (bool set by fortigate_normalize)
      - ``fortigate_logtraffic`` raw value (fallback)
      - ``Log Traffic`` human-readable label
    Returns ``None`` when logging is enabled or field is absent (non-FortiGate rules).
    """
    # Primary: normalizer-set boolean flag
    if rule.get("fortigate_logtraffic_off") is True:
        label = rule.get("Log Traffic") or "Disabled"
        return (
            f"Observation: FortiGate logtraffic is set to '{label}' — traffic permitted by this "
            "allow rule will not be logged to the FortiAnalyzer/SIEM. This creates a visibility gap "
            "for security monitoring and incident investigation. Enable logtraffic=all or logtraffic=utm."
        )
    # Fallback: check raw logtraffic value directly (e.g. when normalize was not used)
    raw_lt = str(rule.get("fortigate_logtraffic") or rule.get("logtraffic") or "").strip().lower()
    if raw_lt == "disable":
        return (
            "Observation: FortiGate logtraffic is explicitly disabled — traffic permitted by this "
            "allow rule will not be logged. Enable logtraffic=all or logtraffic=utm."
        )
    return None


def application_any_observation(rule: dict[str, Any]) -> str | None:
    """
    Observation for Application-vs-Service alignment on allow rules (call after action check).

    Three distinct cases are handled:

    Case A — Application=any AND Service=any/absent:
        Both dimensions are unconstrained.  This is the broad case flagged as an issue
        (review for least-privilege).

    Case B — Application=any AND Service=defined (concrete ports):
        Service already gates the traffic at the port level; Application="any" is the
        normal Palo Alto default for service-based rules and is NOT a misconfiguration.
        Suppressed entirely — no observation emitted.

    Case C — Service=any/absent AND Application=defined (not any):    ← NEW
        Service is unconstrained but the Application field restricts the traffic to a
        specific L7 app (e.g. 'ssl', 'web-browsing').  On Palo Alto this is correct
        behaviour; the App-ID constrains the traffic even when Service=any.
        Emit an *observation-only* message: 'Service is any but Application restricts
        to X; verify least-privilege'.  This is NOT treated as a hard non-compliance —
        the rule is NOT marked overly-permissive by this function.
    """
    app_raw = get_application_for_audit(rule)
    if not app_raw.strip():
        return None  # No Application field at all — nothing to observe.

    svc = rule.get("Service") or rule.get("Services") or rule.get("service")
    svc_ports = parse_service_field(svc)
    svc_is_any_or_absent = (not svc_ports) or (svc_ports == ["any"])

    app_is_any = multi_value_field_has_any(app_raw)

    if app_is_any:
        if not svc_is_any_or_absent:
            # Case B: Service pins the ports — Application="any" is not a meaningful gap.
            return None
        # Case A: both Application and Service are unconstrained.
        return (
            "Observation: Application is set to 'any' and Service is also unconstrained, "
            "permitting all applications on all ports — review for least-privilege alignment."
        )

    # Application IS defined (not any).
    if svc_is_any_or_absent:
        # Case C: Service=any but Application restricts to specific L7 app(s).
        # On Palo Alto, App-ID enforcement makes this correct behaviour, but it is
        # worth noting so auditors can confirm App-ID profiles are active.
        app_display = app_raw.strip()
        return (
            f"Observation: Service is 'any' but Application is defined as '{app_display}'; "
            "App-ID enforcement restricts traffic to the specified application(s). "
            "Verify that App-ID security profiles are active and that 'any' Service is "
            "intentional — least-privilege would prefer an explicit Service object."
        )

    # Application defined AND Service defined — both constrain the traffic. No observation.
    return None


_RE_LEADING_DISABLED = re.compile(r"^\s*\[disabled\]\s*", re.IGNORECASE)


def get_raw_action(rule: dict[str, Any]) -> str:
    for k in ("action", "Action", "ACTION"):
        v = rule.get(k)
        if v is not None and str(v).strip() != "":
            return str(v).strip()
    return ""


def effective_action_verb(rule: dict[str, Any]) -> str:
    """Verb after stripping a leading ``[Disabled]`` marker (Palo Alto)."""
    raw = get_raw_action(rule)
    return _RE_LEADING_DISABLED.sub("", raw).strip().lower()


def rule_action_is_allow(rule: dict[str, Any]) -> bool:
    v = effective_action_verb(rule)
    return v in ("allow", "permit", "accept")


def get_rule_source_for_audit(rule: dict[str, Any]) -> str:
    for k in ("Source Address", "source", "Source", "source_address", "src"):
        v = rule.get(k)
        if v is not None and str(v).strip() != "":
            return str(v).strip()
    return ""


def get_rule_destination_for_audit(rule: dict[str, Any]) -> str:
    for k in ("Destination Address", "destination", "Destination", "destination_address", "dst"):
        v = rule.get(k)
        if v is not None and str(v).strip() != "":
            return str(v).strip()
    return ""


def max_severity(
    current: str,
    candidate: str,
    order: tuple[str, ...] = ("Low", "Medium", "High", "Critical"),
) -> str:
    """Return the higher of two severity labels."""
    try:
        return current if order.index(current) >= order.index(candidate) else candidate
    except ValueError:
        return candidate


def resolve_audit_engine_mode(
    cli_mode: str | None,
    config_mode: str,
) -> tuple[str, list[str]]:
    """
    Resolve strict/relaxed for the real audit engine only.

    The engine never runs in blanket ``fake`` mode from CLI/config; fake compliance is applied
    after the audit via ``fake_compliance.apply_fake_compliance`` (or legacy blanket with
    ``--mode fake --no-prompt``).

    Returns (audit_mode, log_messages).
    """
    msgs: list[str] = []
    cfg = str(config_mode or "strict").lower()
    if cfg == "fake":
        cfg = "strict"
        msgs.append("Config compliance_mode 'fake' applies only to post-audit flows; using strict for the real audit.")

    if cli_mode is not None:
        m = str(cli_mode).lower()
        if m == "fake":
            msgs.append("CLI --mode fake: real audit uses strict; use post-audit fake prompts or --no-prompt for legacy blanket.")
            return "strict", msgs
        return m, msgs

    return cfg, msgs