"""F2.4 — Evidence store with chain-of-custody hashing.

Forensic-grade reporting needs the raw artifacts behind a finding: a config
snippet, a syslog excerpt, a GUI screenshot. This stores them under an
engagement, hashes each (sha256) into a manifest for chain-of-custody, and can
render a report appendix. Pure filesystem — no network, no LLM.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path

_MANIFEST = "manifest.json"


@dataclass(frozen=True)
class EvidenceItem:
    finding_id: str
    name: str
    kind: str  # "text" | "file" | "screenshot"
    rel_path: str
    sha256: str
    captured_utc: str = ""


def _safe(name: str, fallback: str = "artifact") -> str:
    slug = re.sub(r"[^a-zA-Z0-9_.-]", "_", name)[:80]
    return slug or fallback


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class EvidenceStore:
    """Per-engagement evidence directory with a hashed manifest."""

    def __init__(self, base_dir: Path):
        self.root = Path(base_dir) / "evidence"
        self.manifest_path = self.root / _MANIFEST

    def _load(self) -> list[dict]:
        if not self.manifest_path.exists():
            return []
        try:
            return json.loads(self.manifest_path.read_text(encoding="utf-8")).get("items", [])
        except (json.JSONDecodeError, OSError):
            return []

    def _append(self, item: EvidenceItem) -> None:
        items = self._load()
        items.append(asdict(item))
        self.root.mkdir(parents=True, exist_ok=True)
        self.manifest_path.write_text(json.dumps({"items": items}, indent=2, ensure_ascii=False), encoding="utf-8")

    def add_bytes(
        self, finding_id: str, name: str, data: bytes, kind: str = "file", captured_utc: str = ""
    ) -> EvidenceItem:
        fid = _safe(finding_id, "finding")
        fname = _safe(name)
        dest = self.root / fid / fname
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(data)
        item = EvidenceItem(
            finding_id=finding_id,
            name=name,
            kind=kind,
            rel_path=str(Path("evidence") / fid / fname),
            sha256=_sha256(data),
            captured_utc=captured_utc,
        )
        self._append(item)
        return item

    def add_text(self, finding_id: str, name: str, content: str, captured_utc: str = "") -> EvidenceItem:
        return self.add_bytes(finding_id, name, content.encode("utf-8"), kind="text", captured_utc=captured_utc)

    def items(self) -> list[EvidenceItem]:
        return [EvidenceItem(**d) for d in self._load()]

    def items_for(self, finding_id: str) -> list[EvidenceItem]:
        return [i for i in self.items() if i.finding_id == finding_id]

    def verify(self) -> bool:
        """Re-hash every artifact and confirm it matches the manifest."""
        for item in self.items():
            path = self.root.parent / item.rel_path
            if not path.exists() or _sha256(path.read_bytes()) != item.sha256:
                return False
        return True


def render_appendix_markdown(store: EvidenceStore) -> str:
    """Render the evidence manifest as a report appendix (grouped by finding)."""
    items = store.items()
    if not items:
        return ""
    lines = ["## Appendix — Evidence (chain of custody)", ""]
    by_finding: dict[str, list[EvidenceItem]] = {}
    for it in items:
        by_finding.setdefault(it.finding_id, []).append(it)
    for fid, group in by_finding.items():
        lines.append(f"### {fid}")
        for it in group:
            stamp = f" · {it.captured_utc}" if it.captured_utc else ""
            lines.append(f"- **{it.name}** ({it.kind}){stamp} — `{it.rel_path}` — sha256 `{it.sha256[:16]}…`")
        lines.append("")
    return "\n".join(lines)
