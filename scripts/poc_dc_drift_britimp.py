"""F202.H — Ad-hoc validacion del drift detector contra los findings
reales de .205 vs .5 del POC Britimp 2026-05-18.

Reproduce los rule_ids que cada DC emitio en sus engages:
  .205 (primario):  AD-*, WIN-*, dns-open-resolver, dnssec-validation-disabled
  .5 (secundario):  AD-*, WIN-*, dns-open-resolver, http-plaintext,
                    http-server-token, ssh-banner-visible

Y muestra el output de diff_dc_dns_posture() para verificar end-to-end.
"""

import os

os.environ.setdefault("OPENAI_API_KEY", "ollama")

from kryon.cli.engage import Finding, diff_dc_dns_posture


def _f(rule_id: str, host: str, sev: str = "MEDIUM", cwe: str = "CWE-0") -> Finding:
    return Finding(cwe=cwe, severity=sev, host=host, rule_id=rule_id, message="")


# Reproducir findings reales segun lo capturado en engage
H205 = "172.18.201.205"
H5 = "172.18.201.5"

h205_findings = [
    # AD compliance — emit at least one AD-* so se reconoce como DC
    _f("AD-1.1", f"root@{H205}"),
    _f("AD-2.1", f"root@{H205}"),
    # WIN compliance
    _f("WIN-1.1", f"root@{H205}"),
    # DNS — .205 tiene ambos
    _f("dns-open-resolver", f"{H205}:53", sev="MEDIUM", cwe="CWE-406"),
    _f("dnssec-validation-disabled", f"{H205}:53", sev="MEDIUM", cwe="CWE-345"),
]

h5_findings = [
    _f("AD-1.1", f"root@{H5}"),
    _f("AD-2.1", f"root@{H5}"),
    _f("WIN-1.1", f"root@{H5}"),
    # DNS — .5 solo tiene recursion abierta (NO dnssec finding)
    _f("dns-open-resolver", f"{H5}:53", sev="MEDIUM", cwe="CWE-406"),
    # Servicios extra que .205 no expone
    _f("http-plaintext", f"{H5}:80", sev="HIGH", cwe="CWE-319"),
    _f("http-server-token", f"{H5}:80", sev="MEDIUM", cwe="CWE-200"),
    _f("ssh-banner-visible", f"{H5}:22", sev="LOW", cwe="CWE-200"),
]

host_findings = {H205: h205_findings, H5: h5_findings}

drift = diff_dc_dns_posture(host_findings)

print(f"=== F202.H drift findings: {len(drift)} total ===\n")
for f in drift:
    print(f"[{f.severity:8}] {f.rule_id}")
    print(f"  CWE: {f.cwe}")
    print(f"  Host: {f.host}")
    print(f"  Msg:  {f.message}")
    print()
