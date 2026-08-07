# KRYON Appliance — despliegue en el cliente

Paquete para correr Kryon como **appliance en la mini PC del cliente**: server +
dashboard + scheduler + tools de escaneo. El **cerebro (LLM) vive en tu server**
(cerebro central); el appliance lo consume por HTTP. Sin GPU local → una mini PC
N100/N150 de 12-16 GB alcanza.

## Arquitectura

```
MINI PC (cliente)                          TU SERVER (2×3090)
┌─────────────────────────┐                ┌──────────────────────┐
│ kryon serve (:8700)     │                │ llama-server (:8080) │
│  ├─ dashboard (/)       │  ── HTTP ───▶  │  Qwen3-Next-80B      │
│  ├─ determinismo/checks │   narración    │  (cerebro central)   │
│  ├─ scheduler nocturno  │                └──────────────────────┘
│  └─ nmap / escaneo LAN  │
│     escanea 192.168.x.x │
└─────────────────────────┘
```

El appliance solo hace **conexiones salientes** (al cerebro central + a los
targets que audita). Tu server nunca inicia hacia la red del cliente.

## Requisitos

- Mini PC con **Linux** (Ubuntu/Debian) + **Docker** y **docker compose**.
- El **cerebro central** (tu llama-server) accesible desde la mini PC por IP:puerto.
- La mini PC en el **segmento que va a auditar** (o con ruta hacia él).

## Puesta en marcha (3 pasos)

```bash
cd docker/appliance
./setup.sh          # genera claves + .env.appliance (pregunta IP del cerebro, cliente, puerto)
# setup.sh imprime la API KEY — guardala, es la que el cliente ingresa en el dashboard
```

Si no dejaste que `setup.sh` lo levante:
```bash
docker compose -f docker-compose.appliance.yml up -d --build
```

El cliente abre **`http://<IP-de-la-mini-PC>:8700/`**, ingresa la API key, y ya
ve el dashboard: Panel, Cambios (drift), Hallazgos, **Programación**, Cumplimiento.

## Operación: análisis nocturnos

En la pestaña **Programación** el cliente carga los objetivos (IP/CIDR), elige
marco, frecuencia (diario/semanal) y **hora** (ventana nocturna, default 02:00).
El scheduler dispara el análisis a esa hora, persiste los hallazgos y calcula el
**drift** contra la corrida anterior.

- **El contenedor queda arriba** (`restart: unless-stopped`) para que el
  scheduler dispare a la hora. En idle consume poco; el trabajo pesado corre
  solo en la ventana. Recomendado: dejar la mini PC encendida.
- **Si la mini PC se apaga de día**: el scheduler in-process no dispara estando
  apagada. Alternativa — un cron del host que levante el análisis al encender:
  ```bash
  # /etc/cron.d/kryon-nightly  (ejecuta a las 02:00 si el equipo está prendido)
  0 2 * * * root cd /opt/kryon/docker/appliance && docker compose -f docker-compose.appliance.yml exec -T kryon \
      kryon discover --subnet 192.168.100.0/24 --queue-add --output /root/.kryon/disc.json && \
      docker compose -f docker-compose.appliance.yml exec -T kryon kryon queue process --concurrency 1
  ```

## Seguridad

- **Nunca commitees `.env.appliance`** (tiene la API key + JWT secret). Ya está
  en `.gitignore`.
- La API key la genera `setup.sh` (32 bytes aleatorios). Rotala regenerando con
  `./setup.sh` si se filtra.
- El dashboard sirve el JS same-origin y respeta el CSP estricto del server
  (`script-src 'self'`). No carga nada de CDNs externos.
- Para exponerlo fuera de la LAN: poné TLS delante (reverse proxy) — no publiques
  el `:8700` plano a internet.

## Datos y persistencia

- La DB (histórico de scans → drift), reportes y config viven en el volumen
  `kryon_data` (`/root/.kryon`) + `./reports`. Sobreviven `up`/`down`/update.
- El cliente por defecto es **`default`** (los scans manuales y programados
  persisten bajo ese id) — se crea solo en la primera corrida.

## Update del appliance

```bash
git pull                                   # o reemplazar la imagen kryon-appliance
docker compose -f docker-compose.appliance.yml up -d --build
# los feeds (nuclei/CVE) se refrescan con:  docker compose ... exec kryon kryon update
```

## Pendiente / caveats honestos

- **Motor de PDF**: la imagen actual instala `[server]` + nmap. Si el export de
  reportes cae a HTML en vez de PDF, falta weasyprint/playwright en la imagen
  (agregar al Dockerfile). El dashboard ya cae a HTML solo cuando el PDF no está.
- **nuclei**: si querés detección activa por templates, agregá nuclei a la imagen
  (hoy el escaneo se apoya en nmap + los checks deterministas).
- **Ejecución del scan programado end-to-end** está cableada pero conviene
  validarla en vivo la primera noche (mirar los hallazgos aparecer en el dashboard).
- **Hardening de IP**: el moat (checks/skills) vive en la mini PC — compilar a
  `.so` + license-gate es tarea aparte antes de entregar a un cliente externo.
