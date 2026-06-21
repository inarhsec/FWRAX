"""
Audit orchestration service.

Wires together the parser, auditor, shadow detector, fake compliance,
and reporter — keeping all business logic out of route handlers.
"""
from __future__ import annotations

import copy
import csv
import io
import json
import logging
import tempfile
import uuid
from pathlib import Path
from typing import Any

from core.auditor import FirewallAuditor, optional_batch_checks
from core.config import get_audit_config
from core.fake_compliance import FakeComplianceOutcome
from core.reporter import RBIStyleReporter
from core.shadow_detector import detect_duplicates_and_shadows
from models.audit import AuditOptions, AuditReport, AuditSummary
from utils.helpers import coerce_rules_input

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Parsers
# ---------------------------------------------------------------------------

def parse_json_rules(content: bytes | str) -> list[dict[str, Any]]:
    """Parse JSON firewall rules from raw bytes or string."""
    text = content.decode("utf-8") if isinstance(content, bytes) else content
    try:
        raw = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON: {exc}") from exc
    return coerce_rules_input(raw)


def parse_csv_rules(content: bytes | str) -> list[dict[str, Any]]:
    """
    Parse CSV firewall rules.

    Accepts a wide variety of CSV exports: Palo Alto, FortiGate (CSV), or
    any generic export with column headers that the auditor can handle.
    """
    text = content.decode("utf-8") if isinstance(content, bytes) else content
    text = text.lstrip("\ufeff")  # strip BOM
    reader = csv.DictReader(io.StringIO(text))
    rows = [dict(row) for row in reader]
    if not rows:
        raise ValueError("CSV file is empty or has no data rows.")
    return rows


def parse_rules(filename: str, content: bytes) -> list[dict[str, Any]]:
    """Dispatch to the correct parser based on file extension."""
    name = filename.lower()
    if name.endswith(".json"):
        return parse_json_rules(content)
    if name.endswith(".csv"):
        return parse_csv_rules(content)
    raise ValueError(f"Unsupported file format: '{filename}'. Please upload a .json or .csv file.")


# ---------------------------------------------------------------------------
# Audit orchestration
# ---------------------------------------------------------------------------

def _build_summary(
    rules: list[dict[str, Any]],
    results: list[Any],
    shadow_result: Any | None,
    payload: dict[str, Any],
) -> AuditSummary:
    """Derive high-level counts from audit outputs."""
    sev_counts: dict[str, int] = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    any_any = 0
    broad = 0

    for r in results:
        sev = getattr(r, "severity", "Low")
        sev_counts[sev] = sev_counts.get(sev, 0) + 1
        is_disabled = getattr(r, "is_disabled", False)
        if not is_disabled and r.status == "non-compliant":
            issues_text = " ".join(r.issues).lower()
            if "unconstrained source and destination" in issues_text:
                any_any += 1
            elif "unconstrained" in issues_text:
                broad += 1

    disabled = sum(1 for r in results if getattr(r, "is_disabled", False))
    non_compliant = sum(1 for r in results if r.status == "non-compliant")
    compliant = sum(1 for r in results if r.status == "compliant")
    total_findings = non_compliant

    # Stale rules: count from payload
    stale = 0
    for r in results:
        if any("stale" in i.lower() or "last hit" in i.lower() or "never matched" in i.lower()
               for i in (r.issues or [])):
            stale += 1

    dupes = getattr(shadow_result, "duplicate_count", 0) if shadow_result else 0
    shadows = getattr(shadow_result, "shadow_count", 0) if shadow_result else 0
    conflict_shadows = getattr(shadow_result, "conflict_shadow_count", 0) if shadow_result else 0

    return AuditSummary(
        total_rules=len(rules),
        total_findings=total_findings,
        compliant=compliant,
        non_compliant=non_compliant,
        disabled=disabled,
        critical=sev_counts.get("Critical", 0),
        high=sev_counts.get("High", 0),
        medium=sev_counts.get("Medium", 0),
        low=sev_counts.get("Low", 0),
        duplicates=dupes,
        shadows=shadows,
        conflict_shadows=conflict_shadows,
        stale_rules=stale,
        any_any_rules=any_any,
        broad_access_rules=broad,
    )


def run_audit(
    filename: str,
    content: bytes,
    options: AuditOptions,
) -> AuditReport:
    """
    Full audit pipeline.

    1. Parse rules from the uploaded file.
    2. Run the real audit engine.
    3. Optionally apply fake compliance (non-interactive blanket mode).
    4. Run shadow/duplicate detection.
    5. Run batch heuristics.
    6. Build reporter payload.
    7. Return structured AuditReport.
    """
    audit_id = str(uuid.uuid4())
    logger.info("Starting audit %s for file='%s' mode=%s", audit_id, filename, options.mode)

    # --- Parse ---
    try:
        rules = parse_rules(filename, content)
    except ValueError as exc:
        logger.error("Parse error in audit %s: %s", audit_id, exc)
        return AuditReport(
            audit_id=audit_id,
            options=options,
            summary=AuditSummary(),
            payload={},
            error=str(exc),
        )

    logger.info("Audit %s: parsed %d rules", audit_id, len(rules))

    # --- Audit engine ---
    audit_config = get_audit_config({"compliance_mode": options.mode})
    auditor = FirewallAuditor(audit_config)
    results = auditor.audit_rules(rules)
    original_rule_results = [copy.deepcopy(r).to_dict() for r in results]

    # --- Fake compliance (non-interactive / web mode = blanket) ---
    fake_meta: dict[str, Any] | None = None
    report_style = "standard"

    if options.fake_compliance:
        # Apply blanket fake compliance (no interactive prompts in web mode)
        from core.fake_compliance import apply_fake_compliance
        outcome: FakeComplianceOutcome = apply_fake_compliance(
            results,
            interactive=False,
            legacy_blanket_fake=True,
        )
        results = outcome.modified_results
        report_style = outcome.report_style
        if outcome.fake_pipeline_used:
            fake_meta = {
                "fake_pipeline_used": True,
                "report_style": outcome.report_style,
                "per_rule_compliant_overrides": outcome.per_rule_compliant_overrides,
                "bulk_downgrade_applied": outcome.bulk_downgrade_applied,
                "notes": outcome.extra_notes,
            }

    # --- Shadow / duplicate detection ---
    shadow_result = None
    if options.run_shadow_detection:
        try:
            logger.info("Audit %s: running shadow detection", audit_id)
            shadow_result = detect_duplicates_and_shadows(
                rules,
                disabled_name_prefixes=tuple(
                    str(x) for x in audit_config.get("disabled_name_prefixes", [])
                ) or None,
                disabled_rule_name_literals=tuple(
                    str(x) for x in audit_config.get("disabled_rule_name_literals", [])
                ) or None,
            )
            logger.info(
                "Audit %s: shadow=%d duplicate=%d conflict=%d",
                audit_id,
                shadow_result.shadow_count,
                shadow_result.duplicate_count,
                shadow_result.conflict_shadow_count,
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("Audit %s: shadow detection failed: %s", audit_id, exc)

    # --- Batch checks ---
    batch_notes: list[str] = []
    if options.run_batch_checks:
        batch_notes = optional_batch_checks(
            rules,
            results,
            run_shadow_detection=options.run_shadow_detection,
            shadow_detection_result=shadow_result,
        )

    # --- Build reporter payload ---
    compliance_label = options.mode + ("+blanket_fake" if options.fake_compliance else "")
    reporter = RBIStyleReporter(
        audit_config,
        organization=options.organization,
        report_style=report_style,
    )
    payload = reporter.build_report_payload(
        results,
        len(rules),
        batch_notes,
        compliance_label=compliance_label,
        original_rule_results=original_rule_results,
        fake_compliance_metadata=fake_meta,
        shadow_detection_result=shadow_result,
    )

    summary = _build_summary(rules, results, shadow_result, payload)
    rule_results = [r.to_dict() for r in results]

    logger.info(
        "Audit %s complete: total=%d findings=%d critical=%d high=%d",
        audit_id, len(rules), summary.total_findings, summary.critical, summary.high,
    )

    return AuditReport(
        audit_id=audit_id,
        options=options,
        summary=summary,
        payload=payload,
        rule_results=rule_results,
        batch_notes=batch_notes,
    )


# ---------------------------------------------------------------------------
# Report export helpers
# ---------------------------------------------------------------------------

def export_pdf(report: AuditReport) -> bytes:
    """Render the audit report as PDF bytes."""
    audit_config = get_audit_config({"compliance_mode": report.options.mode})
    reporter = RBIStyleReporter(
        audit_config,
        organization=report.options.organization,
        report_style=report.payload.get("report_style", "standard"),
    )
    with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as tmp:
        tmp_path = tmp.name
    try:
        reporter.save_pdf(report.payload, tmp_path)
        return Path(tmp_path).read_bytes()
    finally:
        try:
            Path(tmp_path).unlink()
        except OSError:
            pass


def export_json(report: AuditReport) -> bytes:
    """Serialize the reporter payload to JSON bytes."""
    return json.dumps(report.payload, ensure_ascii=False, indent=2).encode("utf-8")


def export_excel(report: AuditReport) -> bytes:
    """Render the audit report as Excel bytes."""
    audit_config = get_audit_config({"compliance_mode": report.options.mode})
    reporter = RBIStyleReporter(
        audit_config,
        organization=report.options.organization,
        report_style=report.payload.get("report_style", "standard"),
    )
    with tempfile.NamedTemporaryFile(suffix=".xlsx", delete=False) as tmp:
        tmp_path = tmp.name
    try:
        reporter.save_excel(report.payload, tmp_path)
        return Path(tmp_path).read_bytes()
    finally:
        try:
            Path(tmp_path).unlink()
        except OSError:
            pass
