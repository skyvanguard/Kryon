"""Compliance API routes — framework assessment and Zero Trust evaluation."""

from __future__ import annotations

import json

from fastapi import APIRouter, Depends, Query

from kryon.server.auth import require_api_key
from kryon.server.logging_config import get_logger
from kryon.server.models import ComplianceAssessRequest

logger = get_logger(__name__)

router = APIRouter(tags=["compliance"], dependencies=[Depends(require_api_key)])


@router.get("/compliance/frameworks")
async def list_frameworks() -> dict:
    """List all available compliance frameworks."""
    frameworks = [
        {"id": "pci_dss", "name": "PCI-DSS v4.0", "controls": 25},
        {"id": "soc2", "name": "SOC 2 Type II", "controls": 18},
        {"id": "nist_csf", "name": "NIST CSF 2.0", "controls": 30},
        {"id": "iso_27001", "name": "ISO 27001:2022", "controls": 35},
        {"id": "dora", "name": "DORA", "controls": 20},
        {"id": "nis2", "name": "NIS2 Directive", "controls": 18},
        {"id": "cis_controls", "name": "CIS Controls v8.1", "controls": 18, "safeguards": 153},
        {"id": "cmmc", "name": "CMMC 2.0 Level 2", "controls": 25},
        {"id": "zero_trust", "name": "Zero Trust Assessment", "controls": 24},
    ]
    return {"frameworks": frameworks}


@router.post("/compliance/assess")
async def assess_compliance(body: ComplianceAssessRequest) -> dict:
    """Assess findings against a compliance framework."""
    from kryon.compliance import map_findings_to_framework
    from kryon.intelligence.models import Finding
    from kryon.server.deps import get_store

    store = get_store()

    # Get findings from DB
    findings_records = store.list_all_findings(client_id=body.client_id or None, limit=500)
    findings = []
    for fr in findings_records:
        try:
            parsed = json.loads(fr.finding_json) if fr.finding_json else {}
            findings.append(
                Finding(
                    title=parsed.get("title", "Untitled"),
                    description=parsed.get("description", ""),
                    severity=parsed.get("severity", "info"),
                    affected_asset=parsed.get("affected_asset", ""),
                    tool_source=parsed.get("tool_source", ""),
                )
            )
        except Exception:
            logger.debug("Skipping malformed finding record: %s", fr)
            continue

    report = map_findings_to_framework(findings, body.framework)
    logger.info("Compliance assessment completed: framework=%s client=%s", body.framework, body.client_id)
    return report.model_dump()


@router.get("/compliance/zero-trust")
async def zero_trust_assessment(
    client_id: str = Query("", description="Client ID"),
) -> dict:
    """Run Zero Trust maturity assessment."""
    from kryon.intelligence.models import Finding
    from kryon.server.deps import get_store

    store = get_store()
    findings_records = store.list_all_findings(client_id=client_id or None, limit=500)
    findings = []
    for fr in findings_records:
        try:
            parsed = json.loads(fr.finding_json) if fr.finding_json else {}
            findings.append(
                Finding(
                    title=parsed.get("title", "Untitled"),
                    description=parsed.get("description", ""),
                    severity=parsed.get("severity", "info"),
                    affected_asset=parsed.get("affected_asset", ""),
                )
            )
        except Exception:
            logger.debug("Skipping malformed finding record: %s", fr)
            continue

    try:
        from kryon.compliance.zero_trust import assess_zero_trust

        assessments = assess_zero_trust(findings)
        return {"assessments": [a.model_dump() if hasattr(a, "model_dump") else a.__dict__ for a in assessments]}
    except ImportError:
        return {"error": "Zero Trust module not available"}
