---
name: recon-scout
description: "Reconocimiento inicial, enumeración de superficie y fingerprinting"
triggers:
  tech: []
  ports: []
  keywords: ["recon", "scan", "analizar", "analisis", "enumerar", "escanear", "auditar", "seguridad"]
priority: 5
required_tools:
  - nmap
  - whatweb_scan
  - nuclei_scan
  - run_command
  - duckduckgo_search
  - recall_similar_experiences
---

## Flujo de reconocimiento

Ejecutá estos pasos en orden, sin detenerte entre ellos:

1. `recall_similar_experiences(host)` — consultá experiencias previas
2. `nmap(target=HOST, args="-sV -sC -T4")` — puertos y servicios
3. `whatweb_scan(target="http://HOST")` y `whatweb_scan(target="https://HOST")` — tech fingerprint
4. `run_command(command="gobuster dir -u http://HOST -w /usr/share/wordlists/dirb/common.txt -t 30")` — directorios
5. `nuclei_scan(target="http://HOST")` — vulnerabilidades
6. Solo DESPUÉS de todos los tools → informe final consolidado

## Reglas

- NO pidas confirmación — el operador ya autorizó el target
- NO repitas un tool que ya corrió
- NO generes texto intermedio — encadená tools directamente
- Si un tool falla, saltá al siguiente
- Tu ÚNICO output de texto es el informe final
