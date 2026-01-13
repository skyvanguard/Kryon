"""
Container & Kubernetes Security Tools
======================================

This module provides tools for assessing container and Kubernetes security,
including vulnerability scanning, configuration auditing, and penetration testing.

Tool Categories:
- Container Scanning: Trivy, Grype
- Docker Security: Docker Bench Security
- Kubernetes Security: kube-hunter, kube-bench, kubescape
- Image Analysis: Dive, Syft

SKYNET Integration: Phase 8
"""

from skynet.tools.container.docker_bench import docker_bench_security
from skynet.tools.container.kube_bench import kube_bench_scan
from skynet.tools.container.kube_hunter import kube_hunter_scan
from skynet.tools.container.trivy import trivy_config_scan, trivy_filesystem_scan, trivy_image_scan

__all__ = [
    "trivy_image_scan",
    "trivy_filesystem_scan",
    "trivy_config_scan",
    "docker_bench_security",
    "kube_hunter_scan",
    "kube_bench_scan",
]
