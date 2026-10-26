# Kryon — Mapa de capacidades (upgrade 2026-08-20: de CEH a caza de zero-days)

Herramientas en el contenedor `kryon`; skills del agente en `~/.dsh/skills/`. Evidencia en `~/Kryon/evidence/`.

## Skills del agente (26)
### Assessment (nivel CEH, preexistentes)
`kali-pentest` · `web-pentest-chain` · `network-ad-chain` · `post-exploitation` · `c2-metasploit` · `malware-triage` · `cloud-pentest` · `password-cracking` · `suid-privesc` · `stack-buffer-overflow` · `solving-known-challenges` · `remote-command-quoting` · `single-slot-model-limits`

### Research / zero-day (nuevos, 2026-08-20)
| Skill | Para qué |
|---|---|
| `fuzzing-zeroday` | Pipeline de fuzzing (AFL++/libFuzzer/honggfuzz/boofuzz/angr) + triage de crashes. Sandbox: `/opt/fuzz` en kryon |
| `exploit-development` | De crash a PoC de un comando (ROP/ret2libc/heap, pwntools) |
| `vuln-research-disclosure` | Caza web/OSS (diff de releases, variantes sin parchear) + disclosure responsable |
| `osint-identity` | OSINT de personas/usernames con sherlock (~400 sitios) + correlación theHarvester/amass |
| `cyber-skills-library` | Navegador de la librería de 817 skills (buscar en index.json, leer SKILL.md bajo demanda) |
| Cherry-picks (8) | `performing-binary-exploitation-analysis`, `exploiting-race-condition-vulnerabilities`, `exploiting-http-request-smuggling`, `performing-web-cache-poisoning-attack`, `performing-open-source-intelligence-gathering`, `performing-cve-prioritization-with-kev-catalog`, `triaging-vulnerabilities-with-ssvc-framework`, `performing-api-fuzzing-with-restler` |

## Herramientas nuevas en kryon (2026-08-20)
| Herramienta | Versión | Dónde |
|---|---|---|
| sherlock | 0.16.0 | venv /opt/ptools/venv → /usr/local/bin (smoke test OK: ~400 sitios, RC=0) |
| afl-fuzz + afl-clang-fast/lto | AFL++ 5.02c | apt |
| clang (+ASAN/libFuzzer runtime) | 21 | apt (+ libclang-rt-21-dev) |
| honggfuzz | google/honggfuzz master (build 2026-08-20) | /opt/fuzz/src-honggfuzz (make; parche TRUE para binutils 2.47 + libbfd-dev + libunwind-dev) |
| boofuzz | 0.4.2 | venv (módulo python, sin CLI) |
| angr | 9.2.x | venv |
| pwntools + ropper | latest | venv → /usr/local/bin/pwn |
| qemu-x86_64 (AFL QEMU mode) | 11 | apt |
| Ghidra (headless) | 12.1.3 | /opt/ghidra/current (zip oficial; JDK 21 pinned — Ghidra rechaza Java 25). Verificado: import+análisis de vulnparse OK |
| wine (64+32-bit) | 10.0 | apt (i386 activado); prefixes en /opt/wine/<target>. Verificado: wineboot crea prefix completo (1.2 GB) |
| pwndbg | 2026.07.29 | /opt/pwndbg (auto-loaded en gdb; verificado: checksec OK, 199 comandos) |
| atheris | 3.0.0 | venv (fuzzer para targets Python) |
| maigret | 0.6.4 | venv → /usr/local/bin (complemento de sherlock) |
| radamsa | gitlab develop 5c32c29 | /usr/bin/radamsa (verificado: mutación de seeds OK) |
| restler | imagen oficial | docker image restler:latest en el host (verificado: engine .NET corre); repo en kryon /opt/restler |
| Jazzer (fuzzer JVM/Java) | 0.24 | /opt/fuzz/jazzer-0.24.0.jar + jazzer-api (Maven Central, repo CodeIntelligenceTesting/jazzer). Verificado: crash + reproductor Java guardados. Requiere Java 21 (no soporta class files 25) |
| BinDiff (diff de binarios) | 8 (google/bindiff, OSS) | /usr/bin/bindiff (.deb oficial) + extension Ghidra BinExport en /opt/ghidra/.../Ghidra/Extensions + script headless /opt/ghidra/scripts/ExportBinExport.java (env BINEXPORT_OUT=prefix). Verificado: diff vulnparse_re vs vulnparse_asan → 22 funciones match, similarity 1.25% @ 93.4% |
| Scripting support | (lote 2026-08) | shellcheck 0.11, shfmt 3.13 (estilo casa: shfmt -i 2), yq 3.4, ripgrep 15.2, fd 0.74, fzf, expect 5.45, pexpect 4.9 (venv), GNU parallel, tmux 3.7b, asciinema 2.4, moreutils (ts/sponge), httpie, bat, pwsh 7.6.2. Templates verificados: scripts/py_patch.py, scripts/evidence_run.sh, scripts/exp_probe.exp. Skill: scripting-patterns |
| CLI-Anything (HKUDS) + WireMock | (2026-08) | Repo investigado (79 CLIs comunitarios = supply chain no auditada → solo install desde fuente revisada). Instalado desde fuente: WireMock 3.12.1 (jar /opt/fuzz, Java 25) + cli-anything-wiremock + cli-hub (venv). Verificado: stub create → curl sirve el body + journal de requests. lldb 21 CLI con /root/.lldbinit (target.disable-aslr false — el build Debian deshabilita ASLR por defecto y personality() falla EPERM sin CAP_SYS_ADMIN; shim LD_PRELOAD /opt/fuzz/libnopersonality.so). BLOQUEADO: harness Python de lldb (binding Debian es C-style). Skills: scripting-patterns, web-pentest-chain, exploit-development, kali-pentest |
| crawl4ai (crawler JS→Markdown) | 0.9.2 (Apache-2.0) | venv AISLADO /opt/ptools/venv-c4ai (conflicto pyOpenSSL vs pin cryptography de bloodyad en el venv principal). Chromium 150 del sistema. Verificado: SPA Angular (juice_shop) → Markdown limpio ~1s/página; egress vía Tor SOCKS5 (proxy_config) verificado con example.com. Skill: web-pentest-chain. Firecrawl: evaluado y NO (SaaS-first/AGPL/stack pesado) — vigilancia |
| Scrapling (scraping adaptivo) | (BSD-3) | mismo venv-c4ai (pip check limpio). Selectores adaptivos save/relocate VERIFICADOS (sobreviven rediseño de markup); fetcher estático curl_cffi VERIFICADO; StealthyFetcher (Camoufox) bajo demanda. Vigilancia: scrapy (harvest estructurado), crawlee + wigolo (NO — stacks Node redundantes) |
| aliens-eye (OSINT usernames ML) | 2.2.2 (MIT) | venv principal. 840+ plataformas, detección ML+heurística, extracción de perfil, correlación, recursión, --tor, rescaneos reanudables. Selfcheck verificado: P68/R74/F1 0.71/FPR35 (86 muestras). Skill: osint-identity |
| SpiderFoot (OSINT entidad) | 4.0.0 (MIT) | fuente revisada /opt/spiderfoot-src + venv AISLADO venv-sf (sus pins viejos rompen el venv principal: crypto 3.x, lxml 4.x). 230 módulos + 37 reglas de correlación. Verificado end-to-end (módulos→fetch→eventos→correlación). PyPI "spiderfoot" = placeholder, NUNCA pip install. EyeOfWeb: NO (biometría facial, riesgo legal GDPR/KVKK, stack pesado) — vigilancia |
| Ciphey (decrypt/decode universal) | 5.9.0 (MIT) | CLI /opt/ptools/venv/bin/ciphey — build desde fuente (PyPI roto: cipheycore 0.3.x no publicado; rewrite Rust 0.12.0 no compila en rustc 1.95). Core C++ v0.3.2 compilado + 2 parches locales (include <utility>, shim distutils). venv314 (py3.14). Verificado: base64 + césar one-shot (-g). Skills: kali-pentest, malware-triage |
| Referencias (PayloadsAllTheThings + Awesome-Hacking) | (MIT / CC0) | ~/Kryon/_ref/ versionado en el repo. Grep de payloads por categoría antes de componer (skills: kali-pentest, web-pentest-chain, exploit-development). Rechazados esta ronda: x64dbg (GUI Windows, sin target Win), ImHex 1.38.1 (GUI-first, sin modo headless — verificado a nivel binario; descargado y eliminado), hackingtool (meta-menú redundante) |
| the-book-of-secret-knowledge (corpus) | (MIT, 4442 l) | ~/Kryon/_ref/ — one-liners shell/red (ssh/tcpdump/nmap/nc/socat/gpg), cheat sheets (WAF IP-shortening, encoding), labs/CTFs/wordlists. Skill nuevo net-ops-one-liners destilado de el; enriquecidos web-pentest-chain (WAF) y solving-known-challenges (labs/wordlists) |
| RE corpus (mytechnotalent/Reverse-Engineering) | (MIT, 441MB) | ~/Kryon/_ref/ — reversing-for-everyone.pdf (24MB, libro canonico 0xInfection), lista curada 2981 l, 28 PE Windows x86/x64 de asamblea a mano (ejercicios) = targets de practica pipeline Ghidra headless (verificado: hello_world descompilado). subfinder actualizado 2.14->2.15.0 (checksum verificado, 41k/123k subs) |
| bbot (BEE·bot, recon multi-engine) | 3.0.1 (AGPLv3) | venv-bbot + wrapper; RUN AS ROOT (deps-installer). Presets: subdomain-enum/tech-detect/web/nuclei*/lightfuzz*/wayback*/cloud-enum/iis-shortnames/waf-bypass/baddns*. skill: web-pentest-chain | Referencias +3: hacktricks (164MB wiki operativo: pentesting-web/network-services/binary-exploitation...), RedTeam-Tools (4795 l), Red-Teaming-Toolkit (434 l) — en _ref/. Rechazados: Sn1per (pivotó a producto pago, redundante), TheFatRat (wrapper msfvenom, c2-metasploit cubre) |
| Referencias +2: RedTeaming-Tactics-and-Techniques (gitbook 287 md + 501MB assets) + Awesome-Red-Teaming (lista por táctica MITRE ATT&CK) | (MIT) | en _ref/, índice de descubrimiento (skills: kali-pentest) |

Sandbox de fuzzing: `/opt/fuzz/{targets,corpus,out,out2..4,crashes,notes,src-honggfuzz,hfrun}`.

## Verificación end-to-end (demo)
Target sintético `vulnparse` (bug intencional: strcpy sin bounds en global):
- ASAN: crash confirmado (global-buffer-overflow, WRITE 258 en strcpy, vulnparse.c:13).
- AFL++ (3 campañas): 2.0M+ ejecuciones; lecciones codificadas (ver notes): overflow pequeño SILENTE sin ASAN; AFL++ salta seeds que crashan; ASAN_OPTIONS necesita symbolize=0.
- **honggfuzz: crash detectado y guardado (30+ instancias)** en 300s.
- Evidencia: `evidence/fuzzing-demo-2026-09/` (crash sample, ASAN report, HONGGFUZZ report, stats AFL, notes.md).

## Librería de referencia
`~/Kryon/_hunt/anthropic-cybersecurity-skills` — 817 skills, 29 dominios, Apache-2.0 (gitignoreado; receta de reconstrucción en el skill `cyber-skills-library`). index.json para búsqueda por keyword.

## Reglas
- Fuzzing/research solo sobre: lab propio, copias autorizadas, u OSS con camino de disclosure (skill `vuln-research-disclosure`).
- Evidencia siempre en `~/Kryon/evidence/<campaña>/`.
- Modelo single-slot: trabajo secuencial, sin fan-out de subagents (skill `single-slot-model-limits`).

## Diferencias conocidas / pendientes
- Ghidra: script ExportDecompile instalado en /opt/ghidra/scripts/ (export de C por función con filtro por env EXPORT_FUNC_REGEX, salida en /opt/ghidra/export/<bin>/) — verificado con el target demo (el strcpy vulnerable visible en el C descompilado).
- honggfuzz master requiere el parche TRUE en Kali rolling (documentado en el skill).
- restler: imagen docker oficial restler:latest (engine verificado) + repo en kryon /opt/restler.
- Diferencias verificadas 2026-08-20: AFL++ 5.02c = latest, nuclei v3.11.1 + templates actualizados, sherlock 0.16.0 = latest, Ghidra 12.1.3 = latest. Jazzer 0.24 = latest (Maven), BinDiff 8 = latest OSS.
- Diferido (no instalado): WinAFL (instrumentación Windows — requiere MSVC). El gap de diff binario (antes Diaphora) queda CUBIERTO por BinDiff 8 + Ghidra (Tier 4: export manual/headless via script, ya verificado). Glosarios de APIs LLM-RE: ya cubierto por el loop agente (Ghidra headless + lectura directa del C).
