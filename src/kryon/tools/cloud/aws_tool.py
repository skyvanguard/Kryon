"""F96.1 — agent-facing tool wrappers for the AWS auditor.

Two tools — one per resource type. The agent calls them after the
operator pasted the relevant `aws CLI` output into the engagement
context.
"""

from __future__ import annotations

import json
from typing import Any

from kryon.sdk.agents import function_tool
from kryon.tools.cloud.aws_audit import (
    AWSFinding,
    audit_iam_policy,
    audit_s3_bucket,
)

__all__ = ["audit_s3_config", "audit_iam_policy_doc"]


def _finding_to_dict(f: AWSFinding) -> dict[str, Any]:
    return {
        "rule_id": f.rule_id,
        "severity": f.severity,
        "title": f.title,
        "detail": f.detail,
        "remediation": f.remediation,
        "resource": f.resource,
    }


def _summarize(findings: list[AWSFinding]) -> dict[str, Any]:
    by_severity: dict[str, int] = {}
    for f in findings:
        by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
    return {
        "finding_count": len(findings),
        "by_severity": by_severity,
        "findings": [_finding_to_dict(f) for f in findings],
    }


@function_tool
def audit_s3_config(
    bucket_name: str,
    policy_json: str = "",
    acl_json: str = "",
    encryption_json: str = "",
    versioning_json: str = "",
    logging_json: str = "",
) -> str:
    """Static audit of an S3 bucket's configuration.

    Args:
        bucket_name: bucket identifier (for the report).
        policy_json: output of `aws s3api get-bucket-policy --bucket X
            --output json`. Empty when no bucket policy exists.
        acl_json: output of `aws s3api get-bucket-acl ...`.
        encryption_json: `get-bucket-encryption` output. Empty when
            encryption is unconfigured.
        versioning_json: `get-bucket-versioning` output.
        logging_json: `get-bucket-logging` output.

    Returns:
        JSON summary with finding list.
    """
    if not bucket_name.strip():
        return json.dumps({"error": "empty bucket_name"})

    def _loads(payload: str) -> dict[str, Any] | None:
        if not payload.strip():
            return None
        try:
            doc = json.loads(payload)
        except json.JSONDecodeError:
            return None
        return doc if isinstance(doc, dict) else None

    findings = audit_s3_bucket(
        bucket_name,
        policy_document=_loads(policy_json),
        acl_document=_loads(acl_json),
        encryption_document=_loads(encryption_json),
        versioning_document=_loads(versioning_json),
        logging_document=_loads(logging_json),
    )
    return json.dumps(_summarize(findings), ensure_ascii=False)


@function_tool
def audit_iam_policy_doc(
    policy_name: str,
    policy_json: str,
) -> str:
    """Static audit of one IAM policy document.

    Args:
        policy_name: policy ARN or name (for the report).
        policy_json: output of `aws iam get-policy-version --policy-arn
            ARN --version-id VID --output json` OR a bare policy
            document.

    Returns:
        JSON summary with finding list.
    """
    if not policy_name.strip():
        return json.dumps({"error": "empty policy_name"})
    if not policy_json.strip():
        return json.dumps({"error": "empty policy_json"})

    try:
        doc = json.loads(policy_json)
    except json.JSONDecodeError as e:
        return json.dumps({"error": f"invalid policy JSON: {e}"})
    if not isinstance(doc, dict):
        return json.dumps({"error": "policy JSON must be an object"})

    findings = audit_iam_policy(policy_name, doc)
    return json.dumps(_summarize(findings), ensure_ascii=False)
