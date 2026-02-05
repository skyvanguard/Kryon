"""
Cloud & Container Security Tools
==================================

This module provides tools for assessing cloud infrastructure and container
security across AWS, Azure, GCP, and Kubernetes environments.

Tool Categories:
- AWS Security: Prowler, Pacu, S3Scanner, CloudMapper
- Azure Security: ScoutSuite (Azure module)
- GCP Security: ScoutSuite (GCP module)
- Container Security: Trivy, Docker Bench Security
- Kubernetes Security: kube-hunter, kube-bench
- Multi-Cloud: ScoutSuite, CloudSploit

KRYON Integration: Phase 8
"""

from kryon.tools.cloud.cloudmapper import (
    cloudmapper_audit,
    cloudmapper_collect,
    cloudmapper_report,
    cloudmapper_visualize,
)
from kryon.tools.cloud.pacu import pacu_run
from kryon.tools.cloud.prowler import prowler_scan
from kryon.tools.cloud.s3scanner import s3_bucket_finder, s3scanner_scan
from kryon.tools.cloud.scoutsuite import scoutsuite_scan

__all__ = [
    "prowler_scan",
    "pacu_run",
    "s3scanner_scan",
    "s3_bucket_finder",
    "cloudmapper_collect",
    "cloudmapper_report",
    "cloudmapper_visualize",
    "cloudmapper_audit",
    "scoutsuite_scan",
]
