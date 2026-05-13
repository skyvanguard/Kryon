"""F96.1 — TDD contract for the AWS S3 + IAM auditor.

Coverage:
  - Each AWS-S3-NNN + AWS-IAM-NNN rule has POSITIVE + NEGATIVE.
  - Policy unwrap handles both envelope and bare forms.
  - Realistic banking-grade examples (compliant + misconfigured).
  - Frozen contracts.
  - Tool wrapper.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from kryon.tools.cloud.aws_audit import (
    ALL_AWS_RULES,
    SENSITIVE_IAM_SERVICES,
    AWSFinding,
    audit_iam_policy,
    audit_s3_bucket,
)


def _ids(findings: list[AWSFinding]) -> set[str]:
    return {f.rule_id for f in findings}


# =====================================================================
# AWS-S3-001 — public Principal
# =====================================================================


def test_s3_policy_principal_star_is_critical():
    policy = {
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": "*",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::mybucket/*",
            }
        ]
    }
    findings = audit_s3_bucket("mybucket", policy_document=policy)
    crit = [f for f in findings if f.rule_id == "AWS-S3-001"]
    assert crit and crit[0].severity == "CRITICAL"


def test_s3_policy_principal_aws_star_is_critical():
    policy = {
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": "*"},
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::mybucket/*",
            }
        ]
    }
    findings = audit_s3_bucket("mybucket", policy_document=policy)
    assert "AWS-S3-001" in _ids(findings)


def test_s3_policy_specific_principal_does_not_fire_s3_001():
    policy = {
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": "arn:aws:iam::123456789012:root"},
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::mybucket/*",
            }
        ]
    }
    findings = audit_s3_bucket("mybucket", policy_document=policy)
    assert "AWS-S3-001" not in _ids(findings)


def test_s3_policy_unwraps_aws_envelope():
    """aws s3api get-bucket-policy wraps the policy as a string under
    the `Policy` key. Verify unwrap."""
    inner = json.dumps(
        {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "s3:GetObject",
                    "Resource": "*",
                }
            ]
        }
    )
    envelope = {"Policy": inner}
    findings = audit_s3_bucket("mybucket", policy_document=envelope)
    assert "AWS-S3-001" in _ids(findings)


# =====================================================================
# AWS-S3-002 — public ACL grantee
# =====================================================================


def test_s3_acl_with_all_users_fires_s3_002():
    acl = {
        "Grants": [
            {
                "Grantee": {
                    "Type": "Group",
                    "URI": "http://acs.amazonaws.com/groups/global/AllUsers",
                },
                "Permission": "READ",
            }
        ]
    }
    findings = audit_s3_bucket("mybucket", acl_document=acl)
    assert "AWS-S3-002" in _ids(findings)


def test_s3_acl_with_authenticated_users_fires_s3_002():
    """AuthenticatedUsers is almost as bad as AllUsers — any AWS
    customer can read."""
    acl = {
        "Grants": [
            {
                "Grantee": {
                    "URI": "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"
                },
                "Permission": "READ",
            }
        ]
    }
    findings = audit_s3_bucket("mybucket", acl_document=acl)
    assert "AWS-S3-002" in _ids(findings)


def test_s3_acl_with_canonical_user_does_not_fire():
    acl = {
        "Grants": [
            {
                "Grantee": {"Type": "CanonicalUser", "ID": "abc123"},
                "Permission": "FULL_CONTROL",
            }
        ]
    }
    findings = audit_s3_bucket("mybucket", acl_document=acl)
    assert "AWS-S3-002" not in _ids(findings)


# =====================================================================
# AWS-S3-003 — wildcard S3 action
# =====================================================================


def test_s3_policy_action_wildcard_fires_s3_003():
    policy = {
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": "arn:aws:iam::1:root"},
                "Action": "s3:*",
                "Resource": "*",
            }
        ]
    }
    findings = audit_s3_bucket("mybucket", policy_document=policy)
    assert "AWS-S3-003" in _ids(findings)


def test_s3_policy_action_list_with_wildcard_fires_s3_003():
    policy = {
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": "arn:aws:iam::1:root"},
                "Action": ["s3:GetObject", "s3:*"],
                "Resource": "*",
            }
        ]
    }
    findings = audit_s3_bucket("mybucket", policy_document=policy)
    assert "AWS-S3-003" in _ids(findings)


def test_s3_policy_specific_actions_does_not_fire_s3_003():
    policy = {
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": "arn:aws:iam::1:root"},
                "Action": ["s3:GetObject", "s3:PutObject"],
                "Resource": "*",
            }
        ]
    }
    findings = audit_s3_bucket("mybucket", policy_document=policy)
    assert "AWS-S3-003" not in _ids(findings)


# =====================================================================
# AWS-S3-004 — encryption
# =====================================================================


def test_s3_no_encryption_fires_s3_004():
    findings = audit_s3_bucket("mybucket", encryption_document=None)
    assert "AWS-S3-004" in _ids(findings)


def test_s3_with_aes256_encryption_does_not_fire():
    encryption = {
        "ServerSideEncryptionConfiguration": {
            "Rules": [
                {
                    "ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}
                }
            ]
        }
    }
    findings = audit_s3_bucket("mybucket", encryption_document=encryption)
    assert "AWS-S3-004" not in _ids(findings)


def test_s3_with_kms_encryption_does_not_fire():
    encryption = {
        "ServerSideEncryptionConfiguration": {
            "Rules": [
                {
                    "ApplyServerSideEncryptionByDefault": {
                        "SSEAlgorithm": "aws:kms",
                        "KMSMasterKeyID": "arn:aws:kms:us-east-1:1:key/abc",
                    }
                }
            ]
        }
    }
    findings = audit_s3_bucket("mybucket", encryption_document=encryption)
    assert "AWS-S3-004" not in _ids(findings)


# =====================================================================
# AWS-S3-005 + 006 + 007 — versioning / logging / mfa delete
# =====================================================================


def test_s3_versioning_off_fires_s3_005():
    findings = audit_s3_bucket("mybucket", versioning_document={"Status": "Suspended"})
    assert "AWS-S3-005" in _ids(findings)


def test_s3_versioning_on_does_not_fire_s3_005():
    findings = audit_s3_bucket("mybucket", versioning_document={"Status": "Enabled"})
    assert "AWS-S3-005" not in _ids(findings)


def test_s3_logging_off_fires_s3_006():
    findings = audit_s3_bucket("mybucket", logging_document={})
    assert "AWS-S3-006" in _ids(findings)


def test_s3_logging_on_does_not_fire_s3_006():
    findings = audit_s3_bucket(
        "mybucket",
        logging_document={
            "LoggingEnabled": {
                "TargetBucket": "audit-bucket",
                "TargetPrefix": "logs/",
            }
        },
    )
    assert "AWS-S3-006" not in _ids(findings)


def test_s3_mfa_delete_off_fires_s3_007():
    findings = audit_s3_bucket("mybucket", versioning_document={"Status": "Enabled"})
    assert "AWS-S3-007" in _ids(findings)


def test_s3_mfa_delete_on_does_not_fire_s3_007():
    findings = audit_s3_bucket(
        "mybucket",
        versioning_document={"Status": "Enabled", "MFADelete": "Enabled"},
    )
    assert "AWS-S3-007" not in _ids(findings)


# =====================================================================
# AWS-IAM-001 — Admin (Action:* + Resource:*)
# =====================================================================


def test_iam_full_admin_fires_iam_001():
    policy = {
        "Statement": [
            {"Effect": "Allow", "Action": "*", "Resource": "*"}
        ]
    }
    findings = audit_iam_policy("FullAdminPolicy", policy)
    crit = [f for f in findings if f.rule_id == "AWS-IAM-001"]
    assert crit and crit[0].severity == "CRITICAL"


def test_iam_admin_unwraps_get_policy_version_envelope():
    """aws iam get-policy-version returns a {PolicyVersion: {Document:
    {...}}} envelope. Verify unwrap."""
    envelope = {
        "PolicyVersion": {
            "Document": {
                "Statement": [
                    {"Effect": "Allow", "Action": "*", "Resource": "*"}
                ]
            }
        }
    }
    findings = audit_iam_policy("FullAdminPolicy", envelope)
    assert "AWS-IAM-001" in _ids(findings)


def test_iam_specific_action_does_not_fire_iam_001():
    policy = {
        "Statement": [
            {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}
        ]
    }
    findings = audit_iam_policy("ReadS3Policy", policy)
    assert "AWS-IAM-001" not in _ids(findings)


# =====================================================================
# AWS-IAM-002 — sensitive service wildcards
# =====================================================================


def test_iam_iam_star_fires_iam_002():
    policy = {
        "Statement": [
            {"Effect": "Allow", "Action": "iam:*", "Resource": "*"}
        ]
    }
    findings = audit_iam_policy("p", policy)
    assert "AWS-IAM-002" in _ids(findings)


def test_iam_kms_star_fires_iam_002():
    policy = {
        "Statement": [
            {"Effect": "Allow", "Action": "kms:*", "Resource": "*"}
        ]
    }
    findings = audit_iam_policy("p", policy)
    assert "AWS-IAM-002" in _ids(findings)


def test_iam_full_star_does_not_double_fire_iam_002():
    """When Action: * is set, AWS-IAM-001 wins; we shouldn't also fire
    AWS-IAM-002 for every sensitive service."""
    policy = {
        "Statement": [
            {"Effect": "Allow", "Action": "*", "Resource": "*"}
        ]
    }
    findings = audit_iam_policy("p", policy)
    assert "AWS-IAM-001" in _ids(findings)
    assert "AWS-IAM-002" not in _ids(findings)


def test_iam_specific_iam_action_does_not_fire_iam_002():
    """iam:PassRole alone is a specific, auditable action."""
    policy = {
        "Statement": [
            {"Effect": "Allow", "Action": "iam:PassRole", "Resource": "*"}
        ]
    }
    findings = audit_iam_policy("p", policy)
    assert "AWS-IAM-002" not in _ids(findings)


def test_sensitive_iam_services_pin():
    """Pin the set — silent removal weakens detection."""
    for svc in ("iam", "kms", "sts", "secretsmanager", "s3"):
        assert svc in SENSITIVE_IAM_SERVICES


# =====================================================================
# AWS-IAM-003 — NotAction
# =====================================================================


def test_iam_allow_with_not_action_fires_iam_003():
    policy = {
        "Statement": [
            {
                "Effect": "Allow",
                "NotAction": ["iam:DeleteUser"],
                "Resource": "*",
            }
        ]
    }
    findings = audit_iam_policy("p", policy)
    assert "AWS-IAM-003" in _ids(findings)


def test_iam_deny_with_not_action_does_not_fire():
    """NotAction on a Deny statement is acceptable (deny-everything-
    except)."""
    policy = {
        "Statement": [
            {
                "Effect": "Deny",
                "NotAction": ["iam:DeleteUser"],
                "Resource": "*",
            }
        ]
    }
    findings = audit_iam_policy("p", policy)
    assert "AWS-IAM-003" not in _ids(findings)


# =====================================================================
# AWS-IAM-004 — missing Condition
# =====================================================================


def test_iam_allow_without_condition_fires_iam_004():
    policy = {
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": "*",
            }
        ]
    }
    findings = audit_iam_policy("p", policy)
    assert "AWS-IAM-004" in _ids(findings)


def test_iam_allow_with_condition_does_not_fire_iam_004():
    policy = {
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": "*",
                "Condition": {
                    "Bool": {"aws:MultiFactorAuthPresent": "true"}
                },
            }
        ]
    }
    findings = audit_iam_policy("p", policy)
    assert "AWS-IAM-004" not in _ids(findings)


# =====================================================================
# AWS-IAM-005 — Principal: *
# =====================================================================


def test_iam_principal_star_fires_iam_005():
    policy = {
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": "*",
                "Action": "s3:GetObject",
                "Resource": "*",
            }
        ]
    }
    findings = audit_iam_policy("p", policy)
    crit = [f for f in findings if f.rule_id == "AWS-IAM-005"]
    assert crit and crit[0].severity == "CRITICAL"


# =====================================================================
# AWS-IAM-006 — Allow/Deny overlap
# =====================================================================


def test_iam_allow_deny_overlap_fires_iam_006():
    policy = {
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "s3:*",
                "Resource": "arn:aws:s3:::mybucket/*",
            },
            {
                "Effect": "Deny",
                "Action": "s3:DeleteObject",
                "Resource": "arn:aws:s3:::mybucket/*",
            },
        ]
    }
    findings = audit_iam_policy("p", policy)
    assert "AWS-IAM-006" in _ids(findings)


def test_iam_no_deny_does_not_fire_iam_006():
    policy = {
        "Statement": [
            {"Effect": "Allow", "Action": "s3:*", "Resource": "*"}
        ]
    }
    findings = audit_iam_policy("p", policy)
    assert "AWS-IAM-006" not in _ids(findings)


# =====================================================================
# Realistic banking-grade examples
# =====================================================================


def test_realistic_misconfigured_s3_bucket_surfaces_multiple_rules():
    """Banking ops mistake: public bucket, no encryption, no
    versioning."""
    policy = {
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": "*",
                "Action": "s3:*",
                "Resource": "*",
            }
        ]
    }
    findings = audit_s3_bucket("bank-uploads", policy_document=policy)
    ids = _ids(findings)
    assert {"AWS-S3-001", "AWS-S3-003", "AWS-S3-004", "AWS-S3-005", "AWS-S3-006", "AWS-S3-007"} <= ids


def test_realistic_well_configured_s3_bucket_zero_findings():
    """A correctly-locked-down bucket."""
    policy = {
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": "arn:aws:iam::1:role/bank-app"},
                "Action": ["s3:GetObject", "s3:PutObject"],
                "Resource": "arn:aws:s3:::bank-data/*",
            }
        ]
    }
    encryption = {
        "ServerSideEncryptionConfiguration": {
            "Rules": [
                {"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "aws:kms"}}
            ]
        }
    }
    versioning = {"Status": "Enabled", "MFADelete": "Enabled"}
    logging = {"LoggingEnabled": {"TargetBucket": "audit", "TargetPrefix": "logs/"}}
    acl = {
        "Grants": [
            {"Grantee": {"Type": "CanonicalUser", "ID": "x"}, "Permission": "FULL_CONTROL"}
        ]
    }
    findings = audit_s3_bucket(
        "bank-data",
        policy_document=policy,
        acl_document=acl,
        encryption_document=encryption,
        versioning_document=versioning,
        logging_document=logging,
    )
    assert findings == []


def test_realistic_least_privilege_iam_zero_findings():
    """A clean read-only policy with Conditions — should produce no
    findings."""
    policy = {
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:ListBucket"],
                "Resource": [
                    "arn:aws:s3:::bank-reports",
                    "arn:aws:s3:::bank-reports/*",
                ],
                "Condition": {
                    "Bool": {"aws:MultiFactorAuthPresent": "true"}
                },
            }
        ]
    }
    findings = audit_iam_policy("ReadOnlyReports", policy)
    assert findings == []


# =====================================================================
# Output ordering + ALL_AWS_RULES pin
# =====================================================================


def test_findings_sorted_by_severity():
    policy = {
        "Statement": [
            {"Effect": "Allow", "Action": "*", "Resource": "*"},  # CRIT
            {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"},  # MED no cond
        ]
    }
    findings = audit_iam_policy("p", policy)
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    ranks = [severity_order[f.severity] for f in findings]
    assert ranks == sorted(ranks)


def test_all_aws_rules_includes_documented():
    required = {
        "AWS-S3-001", "AWS-S3-002", "AWS-S3-003", "AWS-S3-004",
        "AWS-S3-005", "AWS-S3-006", "AWS-S3-007",
        "AWS-IAM-001", "AWS-IAM-002", "AWS-IAM-003", "AWS-IAM-004",
        "AWS-IAM-005", "AWS-IAM-006",
    }
    assert required <= ALL_AWS_RULES


# =====================================================================
# Frozen
# =====================================================================


def test_dataclass_is_frozen():
    from dataclasses import FrozenInstanceError

    f = AWSFinding(
        rule_id="AWS-S3-001",
        severity="CRITICAL",
        title="x",
        detail="x",
        remediation="x",
    )
    with pytest.raises(FrozenInstanceError):
        f.severity = "LOW"  # type: ignore[misc]


# =====================================================================
# Tool wrapper
# =====================================================================


def test_tool_wrapper_dict_shape():
    from kryon.tools.cloud.aws_tool import _summarize

    findings = audit_iam_policy(
        "p",
        {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]},
    )
    summary = _summarize(findings)
    assert summary["by_severity"]["CRITICAL"] >= 1
    json.dumps(summary)  # serializable


def test_tool_wrapper_handles_malformed_policy_input():
    """Invalid JSON / non-dict shape should NOT crash the audit; it
    returns an empty findings list (the policy unwrapper rejects
    silently)."""
    findings = audit_iam_policy("p", {"random": "garbage"})
    assert findings == []
