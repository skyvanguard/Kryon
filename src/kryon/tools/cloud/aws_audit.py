"""F96.1 — AWS S3 + IAM static configuration audit.

Banking deployments increasingly anchor in AWS (BCP digital channels
on EKS, BCB OBB sandbox infrastructure, Banco Itaú Brazil). The
common cloud-misconfig failure modes are public S3 buckets +
over-privileged IAM policies — the AWS equivalent of leaving a
production database exposed on 0.0.0.0/0.

This module operates on EXPORTED config:

  - S3:  operator runs
         `aws s3api get-bucket-policy --bucket X --output json` and
         `aws s3api get-bucket-acl ... --output json` and
         `aws s3api get-bucket-encryption ... --output json` etc.
         then passes the resulting JSON to audit_s3_bucket.

  - IAM: operator runs
         `aws iam get-policy-version --policy-arn ... --version-id
         ... --output json` and passes the document to
         audit_iam_policy.

The auditor NEVER touches AWS APIs. No boto3 dep, no credentials,
no network. The operator's `aws` CLI is the only thing that talks
to the cloud account — and the operator runs that under their own
read-only IAM role with their own audit trail.

Findings:

  AWS-S3-001  CRITICAL  Bucket policy allows public read/write
                         (Principal: * or "AWS": "*")
  AWS-S3-002  CRITICAL  Bucket ACL grants Public access (Group:
                         AllUsers or AuthenticatedUsers)
  AWS-S3-003  HIGH      Bucket policy with Action: s3:* (any S3 op)
  AWS-S3-004  HIGH      Bucket without default encryption (SSE)
  AWS-S3-005  MEDIUM    Bucket without versioning enabled
  AWS-S3-006  MEDIUM    Bucket without server-access logging
  AWS-S3-007  MEDIUM    Bucket without MFA Delete
  AWS-IAM-001 CRITICAL  Policy statement with Action: * AND
                         Resource: * (admin-equivalent)
  AWS-IAM-002 HIGH      Wildcard on sensitive-service actions
                         (iam:* / kms:* / sts:* / secretsmanager:*)
  AWS-IAM-003 HIGH      Statement uses NotAction (negation easy to
                         bypass)
  AWS-IAM-004 MEDIUM    Statement without Condition restricting
                         scope (no MFA / SourceIp / RequestedRegion)
  AWS-IAM-005 CRITICAL  Principal: * or AWS: * (anyone)
  AWS-IAM-006 MEDIUM    Deny statement after Allow on same resource
                         (operator may miss Deny precedence)

Banca-safety:
  - PURE static analysis. No API calls. No boto3.
  - The operator's AWS CLI runs under THEIR audit trail; Kryon
    never sees credentials.
  - Same finding shape as F39 / F87 / F90 / F92.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)


__all__ = [
    "AWSFinding",
    "audit_s3_bucket",
    "audit_iam_policy",
    "ALL_AWS_RULES",
    "SENSITIVE_IAM_SERVICES",
]


# Stable rule IDs. Pinned by test.
ALL_AWS_RULES: frozenset[str] = frozenset(
    {
        "AWS-S3-001",
        "AWS-S3-002",
        "AWS-S3-003",
        "AWS-S3-004",
        "AWS-S3-005",
        "AWS-S3-006",
        "AWS-S3-007",
        "AWS-IAM-001",
        "AWS-IAM-002",
        "AWS-IAM-003",
        "AWS-IAM-004",
        "AWS-IAM-005",
        "AWS-IAM-006",
    }
)


# Service prefixes treated as high-impact: a wildcard on any of these
# is functionally admin within that service's privilege scope.
SENSITIVE_IAM_SERVICES: frozenset[str] = frozenset(
    {
        "iam",
        "kms",
        "sts",
        "secretsmanager",
        "ssm",  # SSM Parameter Store frequently holds creds
        "rds",
        "ec2",
        "s3",
        "dynamodb",
        "lambda",
        "organizations",
        "account",
    }
)


# Public-access grantee URIs from the S3 ACL spec. Either one in a
# bucket ACL means anonymous access (AllUsers) or "any logged-in AWS
# user" (AuthenticatedUsers — almost as bad).
_PUBLIC_ACL_GRANTEES = frozenset(
    {
        "http://acs.amazonaws.com/groups/global/AllUsers",
        "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
    }
)


# ---------------------------------------------------------------------------
# Dataclass
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AWSFinding:
    """One AWS config weakness. Mirrors F39 / F87 / F92 shape."""

    rule_id: str
    severity: str  # CRITICAL / HIGH / MEDIUM / LOW / INFO
    title: str
    detail: str
    remediation: str
    # The resource identifier (bucket name, policy ARN, etc.) so the
    # report can de-duplicate across multiple findings on the same
    # resource.
    resource: str = ""


# ---------------------------------------------------------------------------
# S3 helpers
# ---------------------------------------------------------------------------


def _statement_principal_is_public(principal: Any) -> bool:
    """Detect Principal: "*" or {"AWS": "*"} forms — both mean any
    AWS principal including anonymous (when used in bucket policy)."""
    if principal == "*":
        return True
    if isinstance(principal, dict):
        for value in principal.values():
            if value == "*":
                return True
            if isinstance(value, list) and "*" in value:
                return True
    return False


def _statement_action_is_wildcard_s3(action: Any) -> bool:
    """Action: "s3:*" or "*" (or a list containing one). Anything
    that grants every S3 operation."""
    if isinstance(action, str):
        return action in ("*", "s3:*")
    if isinstance(action, list):
        return any(a in ("*", "s3:*") for a in action)
    return False


# ---------------------------------------------------------------------------
# S3 audit
# ---------------------------------------------------------------------------


def audit_s3_bucket(
    bucket_name: str,
    *,
    policy_document: dict[str, Any] | None = None,
    acl_document: dict[str, Any] | None = None,
    encryption_document: dict[str, Any] | None = None,
    versioning_document: dict[str, Any] | None = None,
    logging_document: dict[str, Any] | None = None,
) -> list[AWSFinding]:
    """Static audit of a single S3 bucket.

    Args:
        bucket_name: human-readable identifier for the report.
        policy_document: output of `get-bucket-policy --output json`.
            Note: AWS wraps the policy JSON as a string in the
            `Policy` key. We accept BOTH the wrapping envelope AND a
            pre-parsed dict.
        acl_document: output of `get-bucket-acl --output json`.
        encryption_document: output of `get-bucket-encryption
            --output json`. None / empty means no SSE configured.
        versioning_document: output of `get-bucket-versioning
            --output json`.
        logging_document: output of `get-bucket-logging --output
            json`.

    Returns:
        list of AWSFinding sorted by severity then rule_id.
    """
    findings: list[AWSFinding] = []

    # ---- Bucket policy checks (AWS-S3-001 + AWS-S3-003) ----
    policy = _unwrap_policy(policy_document)
    if policy:
        for statement in policy.get("Statement", []):
            if not isinstance(statement, dict):
                continue
            if statement.get("Effect") != "Allow":
                continue
            principal = statement.get("Principal")
            if _statement_principal_is_public(principal):
                findings.append(
                    AWSFinding(
                        rule_id="AWS-S3-001",
                        severity="CRITICAL",
                        title="Bucket policy grants public access (Principal: *)",
                        detail=(
                            f"Bucket {bucket_name}: a policy Statement with "
                            f"Effect=Allow has Principal={principal!r}. Anyone "
                            "on the internet can perform the listed Actions on "
                            "this bucket."
                        ),
                        remediation=(
                            "Replace Principal with the specific AWS account "
                            "ARNs that need access. If the bucket is meant to "
                            "be public, document it explicitly + enable "
                            "S3 Block Public Access at the account level so "
                            "future policies can't open more buckets."
                        ),
                        resource=bucket_name,
                    )
                )
            action = statement.get("Action")
            if _statement_action_is_wildcard_s3(action):
                findings.append(
                    AWSFinding(
                        rule_id="AWS-S3-003",
                        severity="HIGH",
                        title="Bucket policy allows wildcard S3 actions",
                        detail=(
                            f"Bucket {bucket_name}: Statement has "
                            f"Action={action!r}. Grants every S3 operation "
                            "(get, put, delete, putBucketPolicy, ...) — over-"
                            "permissive for almost every use case."
                        ),
                        remediation=(
                            "Enumerate the specific actions actually needed (s3:GetObject, s3:PutObject, etc.)."
                        ),
                        resource=bucket_name,
                    )
                )

    # ---- Bucket ACL checks (AWS-S3-002) ----
    if acl_document:
        grants = acl_document.get("Grants") or []
        for grant in grants:
            if not isinstance(grant, dict):
                continue
            grantee = grant.get("Grantee") or {}
            uri = grantee.get("URI") if isinstance(grantee, dict) else None
            if uri in _PUBLIC_ACL_GRANTEES:
                findings.append(
                    AWSFinding(
                        rule_id="AWS-S3-002",
                        severity="CRITICAL",
                        title="Bucket ACL grants public access",
                        detail=(
                            f"Bucket {bucket_name}: ACL grant for {uri!r}. "
                            f"Permission={grant.get('Permission')!r}. Anyone "
                            "(or any AWS user) can perform that permission."
                        ),
                        remediation=(
                            "Remove the public grant. Use Block Public Access "
                            "at the bucket level to prevent recurrence."
                        ),
                        resource=bucket_name,
                    )
                )

    # ---- Encryption (AWS-S3-004) ----
    if not _has_encryption(encryption_document):
        findings.append(
            AWSFinding(
                rule_id="AWS-S3-004",
                severity="HIGH",
                title="Bucket has no default encryption",
                detail=(
                    f"Bucket {bucket_name}: get-bucket-encryption returns no "
                    "ServerSideEncryptionConfiguration. Objects stored without "
                    "an explicit `--sse` flag land unencrypted at rest."
                ),
                remediation=(
                    "Enable default encryption: `aws s3api put-bucket-"
                    "encryption --bucket X --server-side-encryption-"
                    "configuration ...` with AES256 or aws:kms."
                ),
                resource=bucket_name,
            )
        )

    # ---- Versioning (AWS-S3-005) ----
    if not _has_versioning(versioning_document):
        findings.append(
            AWSFinding(
                rule_id="AWS-S3-005",
                severity="MEDIUM",
                title="Bucket versioning not enabled",
                detail=(
                    f"Bucket {bucket_name}: versioning is off. Accidental "
                    "or malicious overwrites are unrecoverable; ransomware-"
                    "style attacks can permanently destroy data."
                ),
                remediation=(
                    "Enable versioning: `aws s3api put-bucket-versioning "
                    "--bucket X --versioning-configuration Status=Enabled`."
                ),
                resource=bucket_name,
            )
        )

    # ---- Logging (AWS-S3-006) ----
    if not _has_logging(logging_document):
        findings.append(
            AWSFinding(
                rule_id="AWS-S3-006",
                severity="MEDIUM",
                title="Server-access logging not enabled",
                detail=(
                    f"Bucket {bucket_name}: no access logging configured. "
                    "Post-incident forensics has no audit trail for who "
                    "read/wrote which object."
                ),
                remediation=(
                    "Configure server-access logging to a dedicated audit bucket (separate from data buckets)."
                ),
                resource=bucket_name,
            )
        )

    # ---- MFA Delete (AWS-S3-007) ----
    if not _has_mfa_delete(versioning_document):
        findings.append(
            AWSFinding(
                rule_id="AWS-S3-007",
                severity="MEDIUM",
                title="MFA Delete not enabled",
                detail=(
                    f"Bucket {bucket_name}: MFA Delete is off. A compromised "
                    "IAM key can permanently delete object versions without "
                    "needing the root user's MFA device."
                ),
                remediation=(
                    "Enable MFA Delete (root-user only): `aws s3api put-"
                    'bucket-versioning ... --mfa "arn:aws:iam::ACCT:mfa/USER '
                    'OTP-CODE" ...`.'
                ),
                resource=bucket_name,
            )
        )

    return _sort_findings(findings)


def _unwrap_policy(doc: dict[str, Any] | None) -> dict[str, Any] | None:
    """get-bucket-policy returns `{"Policy": "<json string>"}`. We
    accept either the envelope OR a pre-parsed dict. Tolerates None
    + already-parsed dict."""
    if doc is None:
        return None
    if "Policy" in doc and isinstance(doc["Policy"], str):
        import json as _json

        try:
            return _json.loads(doc["Policy"])
        except (ValueError, TypeError):
            return None
    if "Statement" in doc:
        return doc
    return None


def _has_encryption(doc: dict[str, Any] | None) -> bool:
    if not doc:
        return False
    config = doc.get("ServerSideEncryptionConfiguration")
    if not isinstance(config, dict):
        return False
    rules = config.get("Rules")
    return isinstance(rules, list) and len(rules) > 0


def _has_versioning(doc: dict[str, Any] | None) -> bool:
    if not doc:
        return False
    return doc.get("Status") == "Enabled"


def _has_logging(doc: dict[str, Any] | None) -> bool:
    if not doc:
        return False
    return "LoggingEnabled" in doc and isinstance(doc["LoggingEnabled"], dict)


def _has_mfa_delete(doc: dict[str, Any] | None) -> bool:
    if not doc:
        return False
    return doc.get("MFADelete") == "Enabled"


# ---------------------------------------------------------------------------
# IAM helpers
# ---------------------------------------------------------------------------


def _statement_action_wildcards_in(actions: Any, target_prefix: str) -> bool:
    """True when any action in `actions` is `target_prefix:*` (e.g.
    `iam:*`). Handles single-string and list-of-string forms."""
    if isinstance(actions, str):
        return actions == f"{target_prefix}:*" or actions == "*"
    if isinstance(actions, list):
        return any(a == f"{target_prefix}:*" or a == "*" for a in actions if isinstance(a, str))
    return False


def _statement_resource_is_wildcard(resource: Any) -> bool:
    if resource == "*":
        return True
    if isinstance(resource, list) and "*" in resource:
        return True
    return False


# ---------------------------------------------------------------------------
# IAM audit
# ---------------------------------------------------------------------------


def audit_iam_policy(
    policy_name: str,
    policy_document: dict[str, Any],
) -> list[AWSFinding]:
    """Static audit of one IAM policy document.

    Args:
        policy_name: human-readable identifier (policy ARN or name).
        policy_document: the parsed policy JSON. Typically the output
            of `aws iam get-policy-version --policy-arn ARN --version-id
            VID --output json`. Accept both the bare policy AND the
            `{"PolicyVersion": {"Document": ...}}` envelope.

    Returns:
        list of AWSFinding sorted by severity.
    """
    policy = _unwrap_iam_policy(policy_document)
    if not policy or not isinstance(policy.get("Statement"), list):
        return []

    findings: list[AWSFinding] = []

    # Track Allow / Deny resource overlap for AWS-IAM-006.
    allow_resources: list[Any] = []
    deny_resources: list[Any] = []

    for statement in policy["Statement"]:
        if not isinstance(statement, dict):
            continue
        effect = statement.get("Effect")
        action = statement.get("Action")
        resource = statement.get("Resource")
        principal = statement.get("Principal")
        not_action = statement.get("NotAction")
        condition = statement.get("Condition")

        if effect == "Allow":
            allow_resources.append(resource)
        elif effect == "Deny":
            deny_resources.append(resource)

        # AWS-IAM-005: Principal: * (allows anyone — only legal in
        # resource-based policies, dangerous everywhere)
        if effect == "Allow" and _statement_principal_is_public(principal):
            findings.append(
                AWSFinding(
                    rule_id="AWS-IAM-005",
                    severity="CRITICAL",
                    title=f"Policy allows any principal ({principal!r})",
                    detail=(
                        f"Policy {policy_name}: Statement Effect=Allow with "
                        f"Principal={principal!r}. In a resource-based policy "
                        "this exposes the resource to every AWS account; in "
                        "an identity-based policy this is malformed but the "
                        "intent is alarming."
                    ),
                    remediation=(
                        "Pin Principal to the specific account / role ARN. "
                        "Use Condition to scope further (aws:PrincipalOrgID)."
                    ),
                    resource=policy_name,
                )
            )

        # AWS-IAM-001: Action: * AND Resource: * (admin)
        if effect == "Allow":
            action_is_full_wildcard = action == "*" or (isinstance(action, list) and "*" in action)
            if action_is_full_wildcard and _statement_resource_is_wildcard(resource):
                findings.append(
                    AWSFinding(
                        rule_id="AWS-IAM-001",
                        severity="CRITICAL",
                        title="Policy allows Action: * on Resource: *",
                        detail=(
                            f"Policy {policy_name}: Allow with Action=* and "
                            "Resource=*. Identity holding this policy has "
                            "AdministratorAccess-equivalent privileges. Almost "
                            "never the actual requirement."
                        ),
                        remediation=(
                            "Use least-privilege: enumerate the actions the "
                            "role actually needs. Consider AWS-managed "
                            "policies like ReadOnlyAccess as a starting point."
                        ),
                        resource=policy_name,
                    )
                )

        # AWS-IAM-002: wildcard on sensitive service
        if effect == "Allow":
            for service in SENSITIVE_IAM_SERVICES:
                if _statement_action_wildcards_in(action, service):
                    # Skip when it's already AWS-IAM-001 (full *) —
                    # that's a stronger finding.
                    if action == "*" or (isinstance(action, list) and "*" in action):
                        continue
                    findings.append(
                        AWSFinding(
                            rule_id="AWS-IAM-002",
                            severity="HIGH",
                            title=f"Wildcard on sensitive service: {service}:*",
                            detail=(
                                f"Policy {policy_name}: Allow with "
                                f"Action={action!r}. {service.upper()} actions "
                                "control identity / encryption / secret "
                                "management — wildcards here are admin within "
                                "that service."
                            ),
                            remediation=(
                                f"Enumerate the specific {service} actions needed (e.g. iam:PassRole, kms:Decrypt)."
                            ),
                            resource=policy_name,
                        )
                    )

        # AWS-IAM-003: NotAction is hard to reason about (allows
        # everything EXCEPT the listed actions)
        if effect == "Allow" and not_action is not None:
            findings.append(
                AWSFinding(
                    rule_id="AWS-IAM-003",
                    severity="HIGH",
                    title="Allow with NotAction (negation policy)",
                    detail=(
                        f"Policy {policy_name}: Effect=Allow combined with "
                        f"NotAction={not_action!r}. Grants every AWS action "
                        "EXCEPT those listed. New services AWS launches "
                        "tomorrow are auto-permitted."
                    ),
                    remediation=(
                        "Replace with positive Action enumeration. NotAction "
                        "is acceptable only on Deny statements where the "
                        "default-everything-allowed inversion is intentional."
                    ),
                    resource=policy_name,
                )
            )

        # AWS-IAM-004: Allow statement without Condition restricting scope
        if effect == "Allow" and not condition:
            # Only flag when the action surface is meaningful — wildcards
            # already covered above, but a specific Action without ANY
            # condition is still soft. INFO-tier on small surfaces; MEDIUM
            # when the action is privileged.
            if isinstance(action, str) and ":" in action:
                pass  # we already have stronger rules for wildcards
            findings.append(
                AWSFinding(
                    rule_id="AWS-IAM-004",
                    severity="MEDIUM",
                    title="Statement has no Condition",
                    detail=(
                        f"Policy {policy_name}: Allow without Condition. "
                        "Granting actions without conditions (MFA, "
                        "SourceIp, aws:RequestedRegion) bypasses the cheap-"
                        "to-add controls that reduce blast radius."
                    ),
                    remediation=(
                        "Add Condition: { Bool: { aws:MultiFactorAuthPresent: "
                        '"true" } } or IpAddress restrictions where the '
                        "consumer's IP is fixed."
                    ),
                    resource=policy_name,
                )
            )

    # AWS-IAM-006: Allow + Deny on same resource (operator may not
    # realize Deny ALWAYS wins). Flag when the Deny resource also
    # appears in an Allow resource list.
    if deny_resources and allow_resources:
        # Convert to flat sets of strings for the comparison.
        allow_set = _flatten_resources(allow_resources)
        deny_set = _flatten_resources(deny_resources)
        overlap = allow_set & deny_set
        if overlap and overlap != {"*"}:
            findings.append(
                AWSFinding(
                    rule_id="AWS-IAM-006",
                    severity="MEDIUM",
                    title="Allow and Deny on overlapping resources",
                    detail=(
                        f"Policy {policy_name}: overlap between Allow and Deny "
                        f"resources: {sorted(overlap)[:5]}. Deny always wins in "
                        "IAM evaluation — confirm intent. Common mistake: "
                        "operator thinks Allow takes precedence."
                    ),
                    remediation=(
                        "Simplify: if the Deny was meant to scope down the "
                        "Allow, replace with a tighter positive Allow."
                    ),
                    resource=policy_name,
                )
            )

    return _sort_findings(findings)


def _unwrap_iam_policy(doc: dict[str, Any]) -> dict[str, Any] | None:
    """Accept either the bare policy OR the get-policy-version
    envelope."""
    if not isinstance(doc, dict):
        return None
    if "Statement" in doc:
        return doc
    version = doc.get("PolicyVersion")
    if isinstance(version, dict) and isinstance(version.get("Document"), dict):
        return version["Document"]
    return None


def _flatten_resources(rs: list[Any]) -> set[str]:
    """Flatten a list of Resource values (string OR list of strings)
    into a string set for overlap detection."""
    out: set[str] = set()
    for r in rs:
        if isinstance(r, str):
            out.add(r)
        elif isinstance(r, list):
            out.update(str(x) for x in r if isinstance(x, str))
    return out


# ---------------------------------------------------------------------------
# Common sort
# ---------------------------------------------------------------------------


def _sort_findings(findings: list[AWSFinding]) -> list[AWSFinding]:
    from kryon.util.severity import SEVERITY_RANK as severity_order

    return sorted(
        findings,
        key=lambda f: (severity_order.get(f.severity, 99), f.rule_id),
    )
