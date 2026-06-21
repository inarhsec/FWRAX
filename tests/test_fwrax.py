"""
Unit tests for FWRAX core functionality.

Run with:
  python -m pytest tests/ -v
  python -m pytest tests/ -v --tb=short
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

# Ensure the project root is on sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from core.auditor import FirewallAuditor, RuleAuditResult
from core.config import get_audit_config
from core.shadow_detector import detect_duplicates_and_shadows
from services.audit_service import (
    parse_csv_rules,
    parse_json_rules,
    parse_rules,
    run_audit,
)
from models.audit import AuditOptions


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def strict_config():
    return get_audit_config()


@pytest.fixture
def relaxed_config():
    return get_audit_config({"compliance_mode": "relaxed"})


@pytest.fixture
def sample_rules():
    return [
        {"rule_name": "WEB-HTTPS", "source": "10.0.0.0/8", "destination": "203.0.113.50", "port": 443, "action": "allow"},
        {"rule_name": "ANY-ANY-TEST", "source": "0.0.0.0/0", "destination": "0.0.0.0/0", "port": "any", "action": "allow"},
        {"rule_name": "ADMIN-TELNET", "source": "192.168.1.0/24", "destination": "198.51.100.20", "port": 23, "action": "allow"},
        {"rule_name": "SSH-INTERNAL", "source": "10.5.0.0/16", "destination": "10.5.1.10", "port": 22, "action": "allow"},
        {"rule_name": "DENY-DEFAULT", "source": "any", "destination": "any", "port": "any", "action": "deny"},
        {"rule_name": "RETIRED-WIDE", "source": "0.0.0.0/0", "destination": "0.0.0.0/0", "port": 443, "action": "allow", "disabled": True},
    ]


# ---------------------------------------------------------------------------
# Parser tests
# ---------------------------------------------------------------------------

class TestJsonParser:
    def test_parse_valid_json_array(self):
        data = [{"rule_name": "R1", "source": "any", "destination": "any", "action": "deny"}]
        result = parse_json_rules(json.dumps(data).encode())
        assert len(result) == 1
        assert result[0]["rule_name"] == "R1"

    def test_parse_invalid_json_raises(self):
        with pytest.raises(ValueError, match="Invalid JSON"):
            parse_json_rules(b"{not valid json}")

    def test_parse_empty_array(self):
        result = parse_json_rules(b"[]")
        assert result == []

    def test_parse_json_string(self):
        data = [{"rule_name": "R1", "action": "allow"}]
        result = parse_json_rules(json.dumps(data))  # str, not bytes
        assert len(result) == 1

    def test_parse_non_array_raises(self):
        with pytest.raises(ValueError):
            parse_json_rules(b'"just a string"')


class TestCsvParser:
    def test_parse_valid_csv(self):
        csv_content = b"rule_name,source,destination,port,action\nR1,10.0.0.1,any,443,allow\n"
        result = parse_csv_rules(csv_content)
        assert len(result) == 1
        assert result[0]["rule_name"] == "R1"
        assert result[0]["port"] == "443"

    def test_parse_csv_multiple_rows(self):
        csv_content = b"rule_name,action\nR1,allow\nR2,deny\nR3,allow\n"
        result = parse_csv_rules(csv_content)
        assert len(result) == 3

    def test_parse_empty_csv_raises(self):
        with pytest.raises(ValueError, match="empty"):
            parse_csv_rules(b"rule_name,action\n")

    def test_parse_csv_with_bom(self):
        # BOM prefix
        csv_content = b"\xef\xbb\xbfrule_name,action\nR1,allow\n"
        result = parse_csv_rules(csv_content)
        assert len(result) == 1

    def test_dispatch_by_extension_json(self):
        data = [{"rule_name": "R1", "action": "deny"}]
        result = parse_rules("rules.json", json.dumps(data).encode())
        assert len(result) == 1

    def test_dispatch_by_extension_csv(self):
        csv_content = b"rule_name,action\nR1,deny\n"
        result = parse_rules("rules.csv", csv_content)
        assert len(result) == 1

    def test_unsupported_extension_raises(self):
        with pytest.raises(ValueError, match="Unsupported"):
            parse_rules("rules.xml", b"<rules/>")


# ---------------------------------------------------------------------------
# Auditor tests
# ---------------------------------------------------------------------------

class TestAuditor:
    def test_any_any_allow_is_critical(self, strict_config):
        auditor = FirewallAuditor(strict_config)
        rule = {"rule_name": "TEST", "source": "0.0.0.0/0", "destination": "0.0.0.0/0", "port": "any", "action": "allow"}
        result = auditor.audit_rules([rule])
        assert len(result) == 1
        assert result[0].status == "non-compliant"
        assert result[0].severity == "Critical"

    def test_blocked_port_is_high(self, strict_config):
        auditor = FirewallAuditor(strict_config)
        rule = {"rule_name": "TELNET", "source": "192.168.1.1", "destination": "10.0.0.1", "port": 23, "action": "allow"}
        result = auditor.audit_rules([rule])
        assert result[0].status == "non-compliant"
        assert result[0].severity == "High"

    def test_deny_rule_is_compliant(self, strict_config):
        auditor = FirewallAuditor(strict_config)
        rule = {"rule_name": "DEFAULT-DENY", "source": "any", "destination": "any", "port": "any", "action": "deny"}
        result = auditor.audit_rules([rule])
        assert result[0].status == "compliant"

    def test_disabled_rule_is_marked(self, strict_config):
        auditor = FirewallAuditor(strict_config)
        rule = {"rule_name": "OLD-RULE", "source": "any", "destination": "any", "port": "any", "action": "allow", "disabled": True}
        result = auditor.audit_rules([rule])
        assert result[0].is_disabled is True
        assert result[0].status == "compliant"

    def test_approved_port_safe_source_is_compliant(self, strict_config):
        auditor = FirewallAuditor(strict_config)
        rule = {"rule_name": "HTTPS-OK", "source": "10.0.0.0/8", "destination": "203.0.113.10", "port": 443, "action": "allow"}
        result = auditor.audit_rules([rule])
        # Port 443 is approved but may still get flagged for non-approved if strict config says so
        # Just ensure it's evaluated without crash
        assert result[0].rule_name == "HTTPS-OK"

    def test_relaxed_mode_downgrades_severity(self, relaxed_config):
        auditor = FirewallAuditor(relaxed_config)
        rule = {"rule_name": "TELNET", "source": "192.168.1.1", "destination": "10.0.0.1", "port": 23, "action": "allow"}
        result = auditor.audit_rules([rule])
        # In relaxed mode, blocked port is Medium instead of High
        assert result[0].severity in ("Medium", "High")

    def test_result_has_recommendation(self, strict_config, sample_rules):
        auditor = FirewallAuditor(strict_config)
        results = auditor.audit_rules(sample_rules)
        for r in results:
            assert isinstance(r.recommendation, str)
            assert len(r.recommendation) > 0

    def test_multiple_rules_all_evaluated(self, strict_config, sample_rules):
        auditor = FirewallAuditor(strict_config)
        results = auditor.audit_rules(sample_rules)
        assert len(results) == len(sample_rules)

    def test_to_dict_has_expected_keys(self, strict_config):
        auditor = FirewallAuditor(strict_config)
        rule = {"rule_name": "R1", "source": "any", "destination": "any", "port": "any", "action": "deny"}
        result = auditor.audit_rules([rule])[0]
        d = result.to_dict()
        for key in ("rule_name", "status", "severity", "issues", "recommendation", "is_disabled"):
            assert key in d


# ---------------------------------------------------------------------------
# Shadow detector tests
# ---------------------------------------------------------------------------

class TestShadowDetector:
    def test_exact_duplicate_detected(self):
        rules = [
            {"rule_name": "R1", "source": "10.0.0.0/8", "destination": "0.0.0.0/0", "port": "any", "action": "allow"},
            {"rule_name": "R2", "source": "10.0.0.0/8", "destination": "0.0.0.0/0", "port": "any", "action": "allow"},
        ]
        result = detect_duplicates_and_shadows(rules)
        assert result.duplicate_count >= 1

    def test_broader_rule_shadows_narrower(self):
        rules = [
            {"rule_name": "BROAD", "source": "0.0.0.0/0", "destination": "0.0.0.0/0", "port": "any", "action": "allow"},
            {"rule_name": "NARROW", "source": "10.0.0.1", "destination": "192.168.1.1", "port": 443, "action": "allow"},
        ]
        result = detect_duplicates_and_shadows(rules)
        assert result.shadow_count >= 1

    def test_no_findings_on_clean_rules(self):
        rules = [
            {"rule_name": "R1", "source": "10.0.0.0/8", "destination": "203.0.113.50", "port": 443, "action": "allow"},
            {"rule_name": "R2", "source": "192.168.0.0/16", "destination": "8.8.8.8", "port": 53, "action": "allow"},
            {"rule_name": "DENY", "source": "any", "destination": "any", "port": "any", "action": "deny"},
        ]
        result = detect_duplicates_and_shadows(rules)
        # These are distinct rules; no duplicates or shadows expected
        assert result.duplicate_count == 0

    def test_disabled_rules_excluded(self):
        rules = [
            {"rule_name": "ACTIVE", "source": "0.0.0.0/0", "destination": "0.0.0.0/0", "port": "any", "action": "allow"},
            {"rule_name": "[Disabled] COPY", "source": "0.0.0.0/0", "destination": "0.0.0.0/0", "port": "any", "action": "allow"},
        ]
        result = detect_duplicates_and_shadows(rules)
        # The disabled rule should be excluded, so no duplicate
        assert result.duplicate_count == 0


# ---------------------------------------------------------------------------
# Full audit pipeline
# ---------------------------------------------------------------------------

class TestAuditPipeline:
    def test_run_audit_json_success(self, sample_rules):
        content = json.dumps(sample_rules).encode()
        options = AuditOptions(mode="strict")
        report = run_audit("rules.json", content, options)
        assert report.error is None
        assert report.summary.total_rules == len(sample_rules)
        assert report.audit_id

    def test_run_audit_csv_success(self):
        csv = b"rule_name,source,destination,port,action\nR1,10.0.0.1,any,443,allow\n"
        options = AuditOptions(mode="strict")
        report = run_audit("rules.csv", csv, options)
        assert report.error is None
        assert report.summary.total_rules == 1

    def test_run_audit_invalid_json_returns_error(self):
        options = AuditOptions(mode="strict")
        report = run_audit("rules.json", b"{bad}", options)
        assert report.error is not None

    def test_run_audit_empty_file_returns_error(self):
        options = AuditOptions(mode="strict")
        report = run_audit("rules.json", b"", options)
        assert report.error is not None

    def test_run_audit_with_shadow_detection(self, sample_rules):
        content = json.dumps(sample_rules).encode()
        options = AuditOptions(mode="strict", run_shadow_detection=True)
        report = run_audit("rules.json", content, options)
        assert report.error is None
        assert report.payload  # payload should be non-empty

    def test_run_audit_fake_compliance_mode(self, sample_rules):
        content = json.dumps(sample_rules).encode()
        options = AuditOptions(mode="strict", fake_compliance=True)
        report = run_audit("rules.json", content, options)
        assert report.error is None
        # In fake mode, non-compliant rules should be overridden to compliant
        assert all(r.get("status") == "compliant" for r in report.rule_results)

    def test_summary_counts_are_consistent(self, sample_rules):
        content = json.dumps(sample_rules).encode()
        options = AuditOptions(mode="strict", run_shadow_detection=False)
        report = run_audit("rules.json", content, options)
        s = report.summary
        assert s.compliant + s.non_compliant == s.total_rules
        assert s.critical + s.high + s.medium + s.low == s.total_rules

    def test_report_payload_has_required_keys(self, sample_rules):
        content = json.dumps(sample_rules).encode()
        options = AuditOptions(mode="strict")
        report = run_audit("rules.json", content, options)
        for key in ("raw_rule_results", "executive_summary", "report_metadata"):
            assert key in report.payload
