"""Regenerate the CIS Controls v8.1 catalog YAML from the official Spanish PDF.

This is a *provenance / reproducibility* script, not part of the runtime.
It parses the CIS Controls v8.1 Spanish PDF and emits
``src/kryon/compliance/cis/catalog/cis_controls_v8.1.yaml``.

The per-safeguard Implementation Group (IG1/IG2/IG3) assignment is encoded
in the PDF *by colour* (filled vs grey circles), which plain text extraction
drops. We recover it from the fact that ``pdfplumber`` only emits the label
text for the *applicable* (filled) IG markers, then VALIDATE the recovered
assignment against the PDF's own per-control IG summary tables — all 18
controls must match or the script aborts.

Usage (requires ``pdfplumber``, which is NOT a Kryon dependency):

    pip install pdfplumber
    python scripts/extract_cis_controls_v81.py /path/to/Controls_v8.1_Spanish.pdf
"""

from __future__ import annotations

import re
import sys
from collections import defaultdict
from pathlib import Path

import yaml

DEFAULT_PDF = "Controls_v8.1Spanish_Version_March_25_2026.pdf"
OUT = (
    Path(__file__).resolve().parents[1] / "src" / "kryon" / "compliance" / "cis" / "catalog" / "cis_controls_v8.1.yaml"
)

CONTROL_NAMES = {
    1: "Inventario y Control de Activos Empresariales",
    2: "Inventario y Control de Activos de Software",
    3: "Protección de Datos",
    4: "Configuración Segura de Activos Empresariales y Software",
    5: "Gestión de Cuentas",
    6: "Gestión de Control de Acceso",
    7: "Gestión Continua de Vulnerabilidades",
    8: "Gestión de Registros de Auditoría",
    9: "Protección del Correo Electrónico y Navegadores Web",
    10: "Defensas Contra Malware",
    11: "Recuperación de Datos",
    12: "Gestión de la Infraestructura de Red",
    13: "Monitoreo y Defensa de la Red",
    14: "Concientización sobre Seguridad y Capacitación en Habilidades",
    15: "Gestión de Proveedores de Servicios",
    16: "Seguridad del Software de Aplicación",
    17: "Gestión de Respuesta ante Incidentes",
    18: "Pruebas de Penetración",
}
ASSET_MAP = {
    "Dispositivos": "Devices",
    "Software": "Software",
    "Datos": "Data",
    "Usuarios": "Users",
    "Red": "Network",
    "Documentación": "Documentation",
}


def main() -> int:
    import pdfplumber  # noqa: PLC0415 — optional, dev-only dependency

    pdf_path = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_PDF
    text = re.sub(
        r"\s+", " ", " ".join(w["text"] for pg in pdfplumber.open(pdf_path).pages for w in pg.extract_words())
    )

    # Authoritative per-control IG summary tables (2 have a garbled IG2 cell).
    sums: dict[int, tuple] = {}
    for i, m in enumerate(
        re.finditer(r"Salvaguardass:\s*(\d+)\s+IG1:\s*(\d+)/\d+\s+IG2:\s*(?:(\d+)/\d+|IG2)\s+IG3:\s*(\d+)/\d+", text), 1
    ):
        sums[i] = (int(m.group(1)), int(m.group(2)), int(m.group(3)) if m.group(3) else None, int(m.group(4)))

    hdr = re.compile(r"\bSalvaguardas?\s+(\d{1,2})\.(\d{1,2})\s*:")
    heads = [(m.start(), m.end(), int(m.group(1)), int(m.group(2))) for m in hdr.finditer(text)]
    meta = re.compile(
        r"Tipo de Activo:\s*([A-Za-zÁÉÍÓÚáéíóúñ/]+(?:\s+(?:de|y|e)\s+[A-Za-zÁÉÍÓÚáéíóúñ]+)?)"
        r"\s+Funci[oó]n de Seguridad:+\s*([A-Za-zÁÉÍÓÚáéíóúñ]+)\s+((?:IG[123]\s*){1,3})"
    )
    metas = [
        (m.start(), m.end(), m.group(1).strip(), m.group(2).strip(), re.findall(r"IG[123]", m.group(3)))
        for m in meta.finditer(text)
    ]
    hdr_noise = re.compile(r"\s*\d{0,3}\s*Control \d{1,2}:.*?Controles Cr[ií]ticos de Seguridad del CIS®\s*\d{0,3}\s*")

    safeguards = []
    for i, (_s0, e0, c, s) in enumerate(heads):
        nxt = heads[i + 1][0] if i + 1 < len(heads) else len(text)
        mstart, mend, asset, fun, igs = [x for x in metas if e0 <= x[0] < nxt][0]
        title = re.sub(r"\s+", " ", text[e0:mstart]).strip(" :|")
        desc = re.sub(r"\s+", " ", hdr_noise.sub(" ", text[mend:nxt])).strip(" :|")
        safeguards.append(
            {
                "id": f"{c}.{s}",
                "control": c,
                "title": title,
                "asset_type": ASSET_MAP.get(asset, asset),
                "asset_type_es": asset,
                "security_function": fun,
                "ig": min(int(g[2]) for g in igs),
                "igs": igs,
                "description": desc,
            }
        )

    bc = defaultdict(lambda: [0, 0, 0, 0])
    for x in safeguards:
        bc[x["control"]][0] += 1
        for k, ig in enumerate(("IG1", "IG2", "IG3"), 1):
            if ig in x["igs"]:
                bc[x["control"]][k] += 1
    ok = True
    for c in range(1, 19):
        tot, i1, _i2, i3 = bc[c]
        a = sums[c]
        match = tot == a[0] and i1 == a[1] and i3 == a[3] and (a[2] is None or bc[c][2] == a[2])
        ok = ok and match
    if not ok or len(safeguards) != 153:
        print("VALIDATION FAILED — IG counts do not match the PDF summary tables", file=sys.stderr)
        return 2

    doc = {
        "framework": {
            "id": "cis-controls-v8.1",
            "title": "CIS Critical Security Controls v8.1",
            "version": "8.1",
            "language": "es",
            "source": "CIS Controls v8.1 Spanish Version (March 2026)",
        },
        "controls": [{"id": c, "name": CONTROL_NAMES[c]} for c in range(1, 19)],
        "safeguards": safeguards,
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    with OUT.open("w", encoding="utf-8") as fh:
        fh.write("# CIS Critical Security Controls v8.1 - Spanish edition (March 2026)\n")
        fh.write("# AUTO-EXTRACTED from the Spanish PDF; IG assignment validated 18/18\n")
        fh.write("# against the per-control IG summary tables. Regenerate with\n")
        fh.write("# scripts/extract_cis_controls_v81.py. Do not hand-edit IGs.\n")
        yaml.safe_dump(doc, fh, allow_unicode=True, sort_keys=False, width=10000)
    print(f"WROTE {OUT} — 153 safeguards, 18 controls, validated 18/18")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
