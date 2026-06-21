"""
FWRAX CLI entry point — preserves all original CLI functionality.

Examples:
  python cli.py
  python cli.py --rules rules.json --out-pdf report.pdf
  python cli.py --rules rules.json --out-json report.json --out-xlsx report.xlsx
  python cli.py --mode relaxed --rules rules.json
  python cli.py --no-prompt --mode fake --out-pdf demo.pdf
  python cli.py --rules data.csv --shadow-detection --out-pdf report.pdf
"""

from __future__ import annotations

import argparse
import copy
import logging
import sys
from pathlib import Path

from core.auditor import FirewallAuditor, optional_batch_checks
from core.config import get_audit_config
from core.fake_compliance import apply_fake_compliance
from core.reporter import RBIStyleReporter
from core.shadow_detector import detect_duplicates_and_shadows
from utils.helpers import coerce_rules_input, load_json_file, resolve_audit_engine_mode, setup_logging
from services.audit_service import parse_csv_rules

logger = logging.getLogger(__name__)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="FWRAX — Firewall rule audit tool.",
    )
    parser.add_argument("--rules", "--rule", dest="rules", default="rules.json",
        help="Path to firewall rules JSON array or CSV file (default: rules.json).")
    parser.add_argument("--mode", choices=("strict", "relaxed", "fake"), default=None)
    parser.add_argument("--no-prompt", action="store_true")
    parser.add_argument("--organization", default="the Organization")
    parser.add_argument("--out-json", metavar="FILE")
    parser.add_argument("--out-xlsx", metavar="FILE")
    parser.add_argument("--out-pdf",  metavar="FILE")
    parser.add_argument("--no-console", action="store_true")
    parser.add_argument("--log-level", default="INFO", choices=("DEBUG","INFO","WARNING","ERROR"))
    parser.add_argument("--no-batch-checks", action="store_true")
    parser.add_argument("--shadow-detection", dest="shadow_detection", action="store_true", default=None)
    parser.add_argument("--no-shadow-detection", dest="shadow_detection", action="store_false")
    return parser.parse_args()


def _compliance_label(audit_mode: str, outcome: object) -> str:
    rs = getattr(outcome, "report_style", "standard")
    if rs == "interactive_soft":
        return f"{audit_mode}+interactive_fake_soft"
    if rs == "legacy_fake":
        return "fake_legacy_blanket"
    return audit_mode


def _prompt_organization(cli_value: str) -> str:
    default = "the Organization"
    if cli_value and cli_value.strip() and cli_value.strip() != default:
        return cli_value.strip()
    if sys.stdin.isatty():
        try:
            raw = input(f"Enter the organization name for the audit report [press Enter for '{default}']: ").strip()
            return raw if raw else default
        except EOFError:
            pass
    return cli_value.strip() if cli_value.strip() else default


def _prompt_shadow_detection(cli_value, *, interactive: bool) -> bool:
    if cli_value is not None:
        return cli_value
    if interactive:
        print("\n" + "─"*64 + "\nDUPLICATE & SHADOW RULE DETECTION\n" + "─"*64)
        print("This check detects duplicate, shadow, and conflict-shadow rules.")
        try:
            raw = input("\nRun Duplicate & Shadow Rule Detection? (yes/no) [yes]: ").strip().lower()
        except EOFError:
            raw = ""
        result = raw in ("", "y", "yes")
        print("─"*64)
        return result
    return True


def _load_rules(rules_path: Path) -> list[dict]:
    if rules_path.suffix.lower() == ".csv":
        return parse_csv_rules(rules_path.read_bytes())
    raw = load_json_file(rules_path)
    return coerce_rules_input(raw)


def main() -> int:
    args = parse_args()
    setup_logging(getattr(logging, args.log_level))

    base = Path(__file__).resolve().parent
    rules_path = Path(args.rules)
    if not rules_path.is_file():
        rules_path = base / args.rules

    organization = _prompt_organization(args.organization)
    logger.info("Organization: %s", organization)

    base_cfg = get_audit_config()
    audit_mode, mode_msgs = resolve_audit_engine_mode(
        args.mode, str(base_cfg.get("compliance_mode", "strict")))
    for m in mode_msgs:
        logger.info("%s", m)

    audit_config = get_audit_config({"compliance_mode": audit_mode})

    try:
        data = _load_rules(rules_path)
    except (OSError, ValueError) as e:
        logger.error("%s", e); return 1

    rules_count = len(data)
    logger.info("Loaded %s rule(s) from %s", rules_count, rules_path.resolve())

    _interactive = bool(sys.stdin.isatty() and not args.no_prompt)
    run_shadow = _prompt_shadow_detection(args.shadow_detection, interactive=_interactive)
    logger.info("Shadow detection: %s", "ENABLED" if run_shadow else "DISABLED")

    auditor = FirewallAuditor(audit_config)
    results = auditor.audit_rules(data)
    original_rule_results = [copy.deepcopy(r).to_dict() for r in results]

    legacy_blanket_fake = bool(args.mode == "fake" and args.no_prompt)
    outcome = apply_fake_compliance(results, interactive=_interactive, legacy_blanket_fake=legacy_blanket_fake)
    final_results = outcome.modified_results

    batch_notes: list[str] = []
    shadow_result = None
    if not args.no_batch_checks and outcome.report_style != "legacy_fake":
        if run_shadow:
            logger.info("Running shadow detection…")
            shadow_result = detect_duplicates_and_shadows(
                data,
                disabled_name_prefixes=tuple(str(x) for x in audit_config.get("disabled_name_prefixes", [])) or None,
                disabled_rule_name_literals=tuple(str(x) for x in audit_config.get("disabled_rule_name_literals", [])) or None,
            )
            logger.info("Shadow: %d dup, %d shadow, %d conflict",
                shadow_result.duplicate_count, shadow_result.shadow_count, shadow_result.conflict_shadow_count)
        batch_notes = optional_batch_checks(data, final_results,
            run_shadow_detection=run_shadow, shadow_detection_result=shadow_result)

    label = _compliance_label(audit_mode, outcome)
    fake_meta = None
    if outcome.fake_pipeline_used:
        fake_meta = {"fake_pipeline_used": True, "report_style": outcome.report_style,
            "per_rule_compliant_overrides": outcome.per_rule_compliant_overrides,
            "bulk_downgrade_applied": outcome.bulk_downgrade_applied, "notes": outcome.extra_notes}

    reporter = RBIStyleReporter(audit_config, organization=organization, report_style=outcome.report_style)
    payload = reporter.build_report_payload(
        final_results, rules_count, batch_notes,
        compliance_label=label, original_rule_results=original_rule_results,
        fake_compliance_metadata=fake_meta, shadow_detection_result=shadow_result)

    disabled_n = sum(1 for r in final_results if getattr(r, "is_disabled", False))
    compliant_n = sum(1 for r in final_results if r.status == "compliant")
    non_compliant_n = sum(1 for r in final_results if r.status == "non-compliant")
    logger.info("Summary: total=%s disabled=%s compliant=%s non_compliant=%s engine=%s",
        rules_count, disabled_n, compliant_n, non_compliant_n, audit_mode)

    if not args.no_console:
        print(reporter.to_console(payload))
    if args.out_json:
        reporter.save_json(payload, args.out_json)
    if args.out_xlsx:
        reporter.save_excel(payload, args.out_xlsx)
    if args.out_pdf:
        reporter.save_pdf(payload, args.out_pdf)
    return 0


if __name__ == "__main__":
    sys.exit(main())
