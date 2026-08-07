"""F116 — MIME / extension disguise detection.

Compares what the SERVER claims a resource is (Content-Type header
+ URL extension) against what the CONTENT actually is. Disagreement
= disguise, which is one of the highest-signal patterns for finding
file-upload bypasses + leaked source code.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from urllib.parse import urlparse

__all__ = [
    "DisguiseAssessment",
    "detect_disguise",
    "label_implies_mime",
    "label_implies_extension",
]


@dataclass(frozen=True)
class DisguiseAssessment:
    mime_disguise: bool = False
    mime_detail: str = ""
    extension_disguise: bool = False
    extension_detail: str = ""
    severity: str = ""  # "" / "LOW" / "MEDIUM" / "HIGH" / "CRITICAL"


# Map from Magika labels (and our heuristic labels) → expected
# Content-Type prefixes. The list intentionally GENERALIZES (we
# accept multiple variants).
_LABEL_TO_MIME_PREFIXES: dict[str, tuple[str, ...]] = {
    # text-ish
    "html": ("text/html", "application/xhtml"),
    "css": ("text/css",),
    "javascript": ("application/javascript", "text/javascript", "application/x-javascript"),
    "json": ("application/json", "text/json"),
    "xml": ("application/xml", "text/xml"),
    "yaml": ("text/yaml", "application/yaml", "application/x-yaml"),
    "markdown": ("text/markdown", "text/x-markdown"),
    "txt": ("text/plain",),
    "csv": ("text/csv", "application/csv"),
    # source code (NEVER expected from a web endpoint normally)
    "phpsource": ("text/x-php", "application/x-httpd-php-source"),
    "php": ("text/x-php", "application/x-httpd-php-source"),
    "python": ("text/x-python", "application/x-python"),
    "ruby": ("text/x-ruby",),
    "go": ("text/x-go",),
    "java": ("text/x-java-source",),
    "rust": ("text/x-rust",),
    # images
    "png": ("image/png",),
    "jpeg": ("image/jpeg", "image/jpg"),
    "gif": ("image/gif",),
    "webp": ("image/webp",),
    "svg": ("image/svg+xml",),
    "ico": ("image/x-icon", "image/vnd.microsoft.icon"),
    # archives
    "zip": ("application/zip", "application/x-zip-compressed"),
    "gzip": ("application/gzip", "application/x-gzip"),
    "tar": ("application/x-tar",),
    "7zip": ("application/x-7z-compressed",),
    "rar": ("application/x-rar-compressed",),
    # docs
    "pdf": ("application/pdf",),
    "docx": ("application/vnd.openxmlformats-officedocument.wordprocessingml.document",),
    "xlsx": ("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",),
    # binaries
    "elf": ("application/x-executable", "application/octet-stream"),
    "pe": ("application/x-msdownload", "application/octet-stream", "application/vnd.microsoft.portable-executable"),
    "macho": ("application/x-mach-binary", "application/octet-stream"),
    "wasm": ("application/wasm",),
}


# Map labels → expected URL extension family (case-insensitive).
_LABEL_TO_EXTENSIONS: dict[str, tuple[str, ...]] = {
    "html": (".html", ".htm", ".xhtml", ".php"),  # .php often served as html
    "css": (".css",),
    "javascript": (".js", ".mjs", ".cjs"),
    "json": (".json",),
    "xml": (".xml", ".rss", ".atom"),
    "yaml": (".yaml", ".yml"),
    "markdown": (".md", ".markdown"),
    "txt": (".txt", ".log", ".text"),
    "csv": (".csv",),
    "phpsource": (".php", ".phps", ".php3", ".php4", ".php5", ".phtml"),
    "php": (".php", ".phtml"),
    "python": (".py", ".pyw"),
    "ruby": (".rb",),
    "go": (".go",),
    "java": (".java",),
    "png": (".png",),
    "jpeg": (".jpg", ".jpeg", ".jpe"),
    "gif": (".gif",),
    "webp": (".webp",),
    "svg": (".svg",),
    "ico": (".ico",),
    "zip": (".zip",),
    "gzip": (".gz", ".gzip"),
    "tar": (".tar",),
    "7zip": (".7z",),
    "rar": (".rar",),
    "pdf": (".pdf",),
    "docx": (".docx",),
    "xlsx": (".xlsx",),
    "elf": ("",),  # ELF served from web = always suspicious
    "pe": (".exe", ".dll", ""),
    "macho": ("",),
    "wasm": (".wasm",),
}


def label_implies_mime(label: str, content_type: str) -> bool:
    """True if the detected content label is COMPATIBLE with the
    server's declared Content-Type."""
    if not label or not content_type:
        return True  # don't flag when we lack info
    ct = content_type.lower().split(";")[0].strip()
    expected = _LABEL_TO_MIME_PREFIXES.get(label.lower(), ())
    if not expected:
        return True  # label not in our table — skip
    return any(ct.startswith(prefix) for prefix in expected)


def label_implies_extension(label: str, url: str) -> bool:
    """True if the URL's path extension is compatible with the
    detected content label.

    Lenient when:
      * no label / no url given
      * URL has no extension (we have no signal to disagree)
      * label not in our table
    """
    if not label or not url:
        return True
    parsed = urlparse(url)
    _, ext = os.path.splitext(parsed.path)
    ext = ext.lower()
    if not ext:
        return True  # no extension = no signal
    expected = _LABEL_TO_EXTENSIONS.get(label.lower(), ())
    if not expected:
        return True
    return ext in expected


# "Severe" disguise pairs — when these mismatch, it's especially
# dangerous (NOT just informational). E.g. content is "phpsource"
# but Content-Type is text/html → source code leak.
_SEVERE_LABEL_DISGUISES: dict[str, str] = {
    "phpsource": "CRITICAL",
    "php": "CRITICAL",
    "python": "HIGH",
    "ruby": "HIGH",
    "elf": "HIGH",
    "pe": "HIGH",
    "macho": "HIGH",
    "private-key": "CRITICAL",
}


def detect_disguise(
    detected_label: str,
    content_type_header: str,
    url: str = "",
) -> DisguiseAssessment:
    """Return a DisguiseAssessment based on label vs header + URL.

    Either mismatch alone produces a finding. Severe label families
    (source code / executables) escalate severity."""
    label = (detected_label or "").lower().strip()
    if not label:
        return DisguiseAssessment()

    mime_ok = label_implies_mime(label, content_type_header)
    ext_ok = label_implies_extension(label, url)

    mime_disguise = not mime_ok and bool(content_type_header)
    ext_disguise = not ext_ok and bool(url)

    if not mime_disguise and not ext_disguise:
        return DisguiseAssessment()

    severity = "MEDIUM"
    if label in _SEVERE_LABEL_DISGUISES:
        severity = _SEVERE_LABEL_DISGUISES[label]
    elif mime_disguise:
        severity = "HIGH"
    elif ext_disguise:
        severity = "MEDIUM"

    mime_detail = ""
    if mime_disguise:
        mime_detail = (
            f"Content-Type header {content_type_header!r} declares one "
            f"type but the body content is {label!r} (Magika/heuristic)."
        )
    ext_detail = ""
    if ext_disguise:
        ext_detail = (
            f"URL path {urlparse(url).path!r} has an extension that doesn't match the detected content type {label!r}."
        )

    return DisguiseAssessment(
        mime_disguise=mime_disguise,
        mime_detail=mime_detail,
        extension_disguise=ext_disguise,
        extension_detail=ext_detail,
        severity=severity,
    )
