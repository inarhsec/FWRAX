"""
FWRAX Web API — FastAPI application.

Endpoints:
  POST /api/upload      — Upload and immediately audit a rules file.
  GET  /api/report/{id} — Retrieve a cached audit report as JSON.
  GET  /api/download/{id}/{format} — Download PDF, XLSX, or JSON report.
  GET  /                — Serve the single-page GUI.
"""
from __future__ import annotations

import io
import logging
import threading
from dataclasses import asdict
from typing import Any

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles

from models.audit import AuditOptions, AuditReport
from services.audit_service import export_excel, export_json, export_pdf, run_audit

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# In-memory report store (thread-safe)
# ---------------------------------------------------------------------------

_report_cache: dict[str, AuditReport] = {}
_cache_lock = threading.Lock()

MAX_CACHE_SIZE = 100  # evict oldest when over limit

def _store_report(report: AuditReport) -> None:
    with _cache_lock:
        if len(_report_cache) >= MAX_CACHE_SIZE:
            oldest = next(iter(_report_cache))
            del _report_cache[oldest]
        _report_cache[report.audit_id] = report


def _get_report(audit_id: str) -> AuditReport:
    with _cache_lock:
        r = _report_cache.get(audit_id)
    if r is None:
        raise HTTPException(status_code=404, detail=f"Report '{audit_id}' not found. It may have expired.")
    return r


# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------

def create_app() -> FastAPI:
    app = FastAPI(
        title="FWRAX — Firewall Rule Audit",
        description="Firewall Rule Review Audit X: upload rules, run audit, download reports.",
        version="2.0.0",
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # --- API routes ---

    @app.post("/api/upload")
    async def upload_and_audit(
        file: UploadFile = File(...),
        mode: str = Form("strict"),
        organization: str = Form("the Organization"),
        run_shadow_detection: str = Form("true"),
        run_batch_checks: str = Form("true"),
        fake_compliance: str = Form("false"),
    ) -> JSONResponse:
        """
        Upload a firewall rules file and run a full audit.

        Accepts .json or .csv files. Returns the audit_id and summary
        immediately; use GET /api/report/{id} for full results.
        """
        filename = file.filename or "upload"
        content = await file.read()

        if not content:
            raise HTTPException(status_code=400, detail="Uploaded file is empty.")
        if len(content) > 50 * 1024 * 1024:  # 50 MB guard
            raise HTTPException(status_code=413, detail="File exceeds the 50 MB limit.")

        options = AuditOptions(
            mode=mode if mode in ("strict", "relaxed") else "strict",
            organization=organization or "the Organization",
            run_shadow_detection=run_shadow_detection.lower() not in ("false", "0", "no"),
            run_batch_checks=run_batch_checks.lower() not in ("false", "0", "no"),
            fake_compliance=fake_compliance.lower() in ("true", "1", "yes"),
        )

        logger.info("Upload received: file=%s size=%d mode=%s", filename, len(content), options.mode)

        report = run_audit(filename, content, options)

        if report.error:
            raise HTTPException(status_code=422, detail=report.error)

        _store_report(report)

        return JSONResponse({
            "audit_id": report.audit_id,
            "summary": _summary_dict(report),
            "batch_notes": report.batch_notes,
            "rule_results": _safe_rule_results(report),
            "shadow_findings": _shadow_findings(report),
        })

    @app.get("/api/report/{audit_id}")
    def get_report(audit_id: str) -> JSONResponse:
        """Return full audit payload for a given audit_id."""
        report = _get_report(audit_id)
        return JSONResponse({
            "audit_id": report.audit_id,
            "summary": _summary_dict(report),
            "batch_notes": report.batch_notes,
            "rule_results": _safe_rule_results(report),
            "shadow_findings": _shadow_findings(report),
        })

    @app.get("/api/download/{audit_id}/{fmt}")
    def download_report(audit_id: str, fmt: str) -> Response:
        """
        Download an audit report in the requested format.

        Supported formats: pdf, json, xlsx
        """
        report = _get_report(audit_id)
        fmt = fmt.lower()

        if fmt == "pdf":
            try:
                data = export_pdf(report)
            except Exception as exc:
                logger.error("PDF export failed for %s: %s", audit_id, exc)
                raise HTTPException(status_code=500, detail=f"PDF generation failed: {exc}") from exc
            return Response(
                content=data,
                media_type="application/pdf",
                headers={"Content-Disposition": f'attachment; filename="fwrax_report_{audit_id[:8]}.pdf"'},
            )

        if fmt == "json":
            data = export_json(report)
            return Response(
                content=data,
                media_type="application/json",
                headers={"Content-Disposition": f'attachment; filename="fwrax_report_{audit_id[:8]}.json"'},
            )

        if fmt == "xlsx":
            try:
                data = export_excel(report)
            except Exception as exc:
                logger.error("Excel export failed for %s: %s", audit_id, exc)
                raise HTTPException(status_code=500, detail=f"Excel generation failed: {exc}") from exc
            return Response(
                content=data,
                media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                headers={"Content-Disposition": f'attachment; filename="fwrax_report_{audit_id[:8]}.xlsx"'},
            )

        raise HTTPException(status_code=400, detail=f"Unknown format '{fmt}'. Use pdf, json, or xlsx.")

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok", "version": "2.0.0"}

    # --- Single-page GUI ---
    @app.get("/", response_class=HTMLResponse)
    def index() -> HTMLResponse:
        from web.templates.index import render_index
        return HTMLResponse(content=render_index())

    return app


# ---------------------------------------------------------------------------
# Response helpers
# ---------------------------------------------------------------------------

def _summary_dict(report: AuditReport) -> dict[str, Any]:
    s = report.summary
    return {
        "total_rules": s.total_rules,
        "total_findings": s.total_findings,
        "compliant": s.compliant,
        "non_compliant": s.non_compliant,
        "disabled": s.disabled,
        "critical": s.critical,
        "high": s.high,
        "medium": s.medium,
        "low": s.low,
        "duplicates": s.duplicates,
        "shadows": s.shadows,
        "conflict_shadows": s.conflict_shadows,
        "stale_rules": s.stale_rules,
        "any_any_rules": s.any_any_rules,
        "broad_access_rules": s.broad_access_rules,
    }


def _safe_rule_results(report: AuditReport) -> list[dict[str, Any]]:
    """Return rule results without bulky raw_rule snapshots (sent separately if needed)."""
    out = []
    for r in report.rule_results:
        row = {k: v for k, v in r.items() if k != "raw_rule"}
        out.append(row)
    return out


def _shadow_findings(report: AuditReport) -> list[dict[str, Any]]:
    sds = report.payload.get("duplicate_shadow_detection") or {}
    return sds.get("findings", [])
