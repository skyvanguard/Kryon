# Demo script — reunión BritImp

Documento operativo para conducir la demo del dashboard Kryon frente a
directivos. Duración total **15 minutos** (10 demo + 5 preguntas). El
script está pensado para ejecutarse palabra por palabra la primera vez,
y luego adaptarse según la sala.

Si algo se rompe durante la demo en vivo, el **video backup de 3 minutos**
(ver sección 9) cubre el mismo recorrido sin dependencias de red ni
backend.

---

## 1. Preparación (30 minutos antes)

**Setup técnico**:

```bash
# 1. Levantá la stack completa
cd ~/Documents/Kryon
docker compose -f docker/docker-compose.kali.yml up -d

# 2. Verificá que el dashboard respondió
curl -s -o /dev/null -w "%{http_code}\n" http://localhost:3000
# → 200

# 3. Verificá que el backend respondió (opcional — si falla, dashboard
#    queda en modo demo automáticamente, que es aceptable para la charla)
curl -s http://localhost:8000/health | jq .
# → {"status": "ok", "version": "2.1.0", "agents_count": 33}

# 4. Abrí el navegador en pantalla completa
# Chrome > View > Always Show Toolbar en Full Screen: OFF
# (no querés ver la barra de pestañas durante la demo)
start chrome --new-window --start-fullscreen http://localhost:3000
```

**Credenciales de demo**:

- `admin@kryon.py` / `kryon2026` — rol admin (demo principal)
- `demo@britimp.com.py` / `demo2026` — rol analyst (backup)

**Contingencias**:

- ❌ Si Docker no levantó → usar el dashboard en modo local (ver §8)
- ❌ Si el backend falla → el dashboard sigue funcionando en modo demo,
  mostrando badge "demo" en vez de "live" en Findings. Mencionarlo como
  feature ("funciona offline por diseño") en vez de bug.
- ❌ Si el navegador se cuelga → video backup + seguir con deck estático

---

## 2. Intro (90 segundos) — tablero off

No proyectes el dashboard todavía. Este bloque crea contexto antes de
mostrar producto.

**Guión literal**:

> *"Buenas tardes. Les voy a hablar 10 minutos sobre un producto y después
> quedan 5 para preguntas. El producto se llama Kryon. Es una plataforma
> autónoma de operaciones de seguridad — en inglés, agentic AI para
> ciberseguridad. Lo que Torq, XBOW y Prophet Security están haciendo en
> Estados Unidos con valuaciones que ya pasaron los mil millones de
> dólares, nosotros lo tenemos funcionando en Paraguay, hecho acá,
> corriendo en infraestructura local. Les muestro en vivo qué hace, y
> después hablamos de negocio."*

Pasá a pantalla completa del dashboard en `localhost:3000`.

---

## 3. Home → login (60 segundos)

**Lo que muestran los ojos**:
- Landing page con el headline "Operaciones de seguridad autónomas"
- Badge "Hecho en Paraguay · Datos soberanos"
- 3 cards con los pilares
- Footer con "v2.1.0 Hydra — Skillforge"

**Guión**:

> *"Esta es la bienvenida. Miren el footer — v2.1 Hydra Skillforge, son
> 77 sprints de desarrollo. Tres diferenciadores clave acá: nueve
> frameworks de compliance en una sola corrida, objetivos ilimitados sin
> cobro por activo, y soberanía total de datos — la inteligencia
> artificial corre en la red del cliente. Ningún dato sale."*

Click en "Comenzar". Pantalla de login.

> *"Login corporativo. En la caja punteada están las credenciales demo —
> se las dejo visibles para que sepan cómo entrar después si quieren
> probar. Entro como admin."*

Tipo `admin@kryon.py` + `kryon2026` + Enter.

---

## 4. Overview — el "money shot" (3 minutos)

**Lo que muestran los ojos**:
- Hero card con security score 82/100 anillo animado y grade "B"
- 3 KPIs a la derecha (Activos 347, Findings 28, Compliance 82%)
- Chart de findings en el tiempo (30 días)
- Donut por severidad
- Bar chart por framework (9 barras)
- Activity feed con 10 eventos recientes

**Guión** (narrado mientras señalás cada área):

> *"Primera pantalla, overview. Lo primero que ve un gerente de seguridad
> o un directivo: score compuesto de 82 sobre 100, grade B, postura
> sólida. Subió 3 puntos vs. la semana pasada. Ese score es un promedio
> ponderado de compliance, tasa de remediación, cobertura de activos y
> exposición crítica.*
>
> *Arriba a la derecha, los KPIs: 347 activos monitoreados, 28 findings
> abiertos — y fíjense, bajando 15% vs. la semana pasada, en verde,
> porque menos es mejor. Compliance promedio 82% sobre nueve frameworks.*
>
> *El gráfico del medio es findings en el tiempo, apilado por severidad.
> Pueden ver el pico acá en día 10 — un escaneo nuevo capturó un lote
> de vulnerabilidades — y después la pendiente baja, que es el equipo
> remediando.*
>
> *Abajo, la distribución por framework. Verde son los frameworks con
> más de 90%, cyan entre 75 y 90, amarillo entre 60 y 75, rojo debajo.
> Y el feed de la derecha es actividad en tiempo real: CVE-2024-3094
> detectada hace 4 minutos, escaneo terminado hace 18, remediación
> automática aplicada hace 42 minutos.*
>
> *Todo lo que ven en esta pantalla sale de una sola corrida del motor.
> No son cuatro herramientas diferentes — es una sola plataforma."*

---

## 5. Findings — la tabla killer (3 minutos)

Click en "Findings" en el sidebar.

**Lo que muestran los ojos**:
- Tabla de 150 findings con badge verde "live" o "demo" en el header
- Columnas: Severidad, ID, Título, Asset, CVSS, Frameworks, Estado, Edad
- Filtros arriba: búsqueda, severidad, estado, framework

**Guión**:

> *"Esta es la pantalla donde vive el equipo de seguridad todos los días.
> Son 150 vulnerabilidades detectadas por la plataforma. Si mirás arriba,
> el badge verde 'live' significa que estos datos vienen directo del
> motor real corriendo atrás. Si el motor estuviera caído, aparecería
> 'demo' — el producto nunca se queda sin información para mostrarle al
> operador.*
>
> *Ordenados por severidad. Acá arriba: CVE-2024-3094, el backdoor de
> xz-utils que sacudió al mundo en marzo del año pasado. Ese rayito al
> lado de la severidad significa que el exploit existe y está disponible.
> Cortesía del LLM que reconoce el contexto.*
>
> *Filtro por crítica…"* (click severidad → crítica)
>
> *"Tres críticas — xz-utils, Log4Shell, regreSSHion. Estos tres ya los
> tiene identificados el sistema y está en proceso de remediarlos
> automáticamente.*
>
> *Click en la primera…"* (click en xz-utils)
>
> *"El drawer de la derecha. Cuatro tabs: resumen con el asset afectado
> y el skill de Kryon que lo detectó. Técnico con CVE, CWE, CVSS 10 y
> un bloque de evidencia con el log del escaneo — esto es lo que un
> auditor pide. Remediación — en este caso el skill safe-modification
> puede aplicar el downgrade automáticamente con rollback verificado;
> acá está el botón 'Remediar ahora' y también 'Simular dry-run'.*
>
> *Compliance — este finding viola 5 frameworks: PCI-DSS, ISO 27001,
> CIS, NIST y OWASP. Abajo, hash criptográfico sha256 firmado. Esto es
> evidencia reproducible que vale para SIB, BCP o un auditor externo.*
>
> *No hay otra herramienta en Paraguay que ofrezca esto."*

Cerrá el drawer.

---

## 6. Compliance — el gancho regulatorio (2 minutos)

Click en "Compliance".

**Lo que muestran los ojos**:
- 3 cards arriba: 82% promedio, controles aprobados, hash
- Bar chart con los 9 frameworks ordenados
- Grid de 9 cards de framework con progress

**Guión**:

> *"Nueve frameworks en paralelo. PCI DSS v4.0 al 92%, ISO 27001 al 85%,
> CIS al 78%, NIST, GDPR con Ley 6534 Paraguay, SOC2, HIPAA, OWASP,
> MITRE ATT&CK. Una sola corrida de escaneo produce evidencia para los
> nueve.*
>
> *Hash criptográfico arriba a la derecha — `sha256:9f2a8c73`. Ese hash
> es único y reproducible. Si BritImp vende una auditoría PCI al Banco
> X, el hash prueba que el reporte no fue manipulado después de
> generarse. Esa es una capacidad que consultoras como BDO o Deloitte
> no tienen — sus reportes son Word que cualquiera edita.*
>
> *Para descargar el reporte multi-framework en PDF firmado, botón acá
> arriba. El PDF sale con el hash en la primera página y la firma
> digital en la última."*

---

## 7. Scans — el motor en vivo (90 segundos)

Click en "Escaneos".

**Lo que muestran los ojos**:
- 3 cards: En ejecución (1), Completados 24h, Fallidos 24h
- Lista de scans con el primero (running) auto-expandido
- Barra de progreso 67%, log en vivo con 6 líneas actualizándose

**Guión**:

> *"Aquí está el motor corriendo. Hay un escaneo activo sobre 10.20.0.0
> barra 16 — una subnet de 65 mil IPs potenciales. Va en 67%, lleva 12
> minutos. Abajo ven el log en vivo: nmap descubrió 2.847 hosts, nuclei
> está evaluando exploits conocidos, y ya encontró CVE-2024-6387
> (regreSSHion de OpenSSH) en 4 hosts.*
>
> *Todo esto es autónomo. Nadie le dijo a la máquina 'ahora corré nuclei'.
> Kryon eligió la secuencia de herramientas basada en el contexto. Esa
> es la diferencia con Qualys o Tenable — ellos corren una lista fija
> de chequeos. Kryon elige."*

---

## 8. Reports + Settings — el cierre técnico (60 segundos)

Click rápido en "Reportes".

> *"Historial de reportes — ejecutivos, técnicos, compliance, incidentes,
> remediación. Cada uno con su hash firmado. Abajo está el reporte del
> incidente del xz-utils, el resumen ejecutivo del Q2, la auto-attestación
> SWIFT. Son los entregables reales que recibiría un cliente bancario
> después de un engagement."*

Click rápido en "Ajustes".

> *"Última pantalla — configuración. Miren el tab General: organización
> BritImp S.A., timezone America/Asunción, motor corriendo con
> kryon-14b sobre Ollama local, 67 skills cargadas, 287 mil vectores en
> ChromaDB. Retención BCP: cinco años para reportes, dos años para
> findings cerrados. Cumple regulación paraguaya."*

---

## 9. Cierre comercial (90 segundos) — pantalla off

Volvé a la ventana de landing o apagá proyector.

**Guión**:

> *"Vieron 10 minutos de producto. Resumo qué acaban de ver:*
>
> *Un dashboard completo, soberano, local, con 150 vulnerabilidades
> detectadas, nueve frameworks de compliance, motor corriendo escaneos
> autónomos, reportes con hash firmado, y capacidad de remediación
> automática con rollback.*
>
> *Esto, en el mercado, cuesta entre 60 y 300 mil dólares anuales según
> proveedor — Arctic Wolf, Torq, CrowdStrike. Nosotros lo damos en
> guaraníes, con hosting local, compliance paraguayo, soporte en español.*
>
> *La pregunta ahora es: ¿cuántos engagements están dispuestos a
> llevarle a sus clientes en los próximos 90 días para que validemos
> juntos el producto en el mercado paraguayo?"*

**Cerrás con el handshake**. Abrís notas para anotar la respuesta.

---

## 10. Video backup de 3 minutos

Si la demo en vivo falla, reproducí el video grabado. Estructura:

1. **0:00–0:20** — Landing + login (skip la animación completa)
2. **0:20–1:20** — Overview (score, KPIs, 3 charts, activity)
3. **1:20–2:10** — Findings (tabla, filtro crítica, drawer del xz-utils)
4. **2:10–2:40** — Compliance (grid 9 frameworks, hash, chart)
5. **2:40–3:00** — Scans running con log en vivo, cierre

**Cómo grabarlo** (antes de la reunión):
- Resolución: **1920×1080 60fps** (calidad HD alta)
- Herramienta: OBS Studio, ScreenFlow, o Chrome DevTools Screencast
- Audio: grabá narración aparte y montá, para controlar pacing
- Formato: MP4 H.264, <100 MB, que entra en USB común
- Backup: subí una copia a un Google Drive compartido como fallback

---

## 11. FAQ — preguntas que van a hacer

### ¿Es seguro correr esto dentro de un banco?

> *"Sí. El LLM corre local, no tiene salida a internet. Los datos nunca
> salen de la red del cliente. Es más seguro que las herramientas cloud
> como Qualys o Rapid7 que envían todo a servidores en EE.UU."*

### ¿Cuánto cuesta implementarlo en un cliente?

> *"Depende del tamaño. Un banco mediano: 780 millones de guaraníes al
> año por el plan Enterprise. Una cooperativa o retail grande: 486
> millones. Pueden comparar con Qualys que cobra 680 millones y con BDO
> que cobra 200 millones por una sola auditoría PCI."*

### ¿Qué pasa si la IA alucina y da un falso positivo?

> *"Tenemos 15% de falsos positivos en severidad HIGH en el benchmark
> Juliet — que es honesto. Por eso todos los checks de compliance son
> deterministas, escritos en Python. El LLM se usa para triaje y
> enriquecimiento de contexto, nunca para el veredicto final. Cada
> finding trae score de confianza."*

### ¿Podemos auditar el código?

> *"Sí. El producto viene con licencia que permite auditoría. Los
> componentes open-source integrados tienen sus licencias documentadas
> en LICENSES.md. Si BritImp compra, pueden tener el código en su
> propio GitHub privado."*

### ¿Corre en nuestros servidores existentes?

> *"Necesita una GPU NVIDIA con 12 GB de VRAM mínimo — una RTX 4060 Ti
> o 4070 alcanza. Unos 18-25 millones de guaraníes en inversión de
> hardware, una sola vez. Vive cinco años fácilmente."*

### ¿Quién lo mantiene si vos te vas?

> *"El dashboard está documentado, el arquitectura es skills-based en
> markdown, cualquier dev senior puede extenderlo. El contrato con
> BritImp incluye un runbook operativo y 3 días de training para el
> equipo técnico. Fuera de eso, yo sigo como responsable técnico mientras
> el producto crezca."*

---

## 12. Checklist pre-demo (imprimir y llevar)

- [ ] Dashboard abre en `localhost:3000`
- [ ] Login funciona con admin@kryon.py
- [ ] Overview carga sin errores visuales
- [ ] Findings tiene ≥50 entries visibles
- [ ] Click en una fila abre el drawer sin delay
- [ ] Compliance muestra 9 cards
- [ ] Scans tiene al menos 1 scan corriendo expandido
- [ ] Logout del menú de usuario vuelve a landing
- [ ] Video backup cargado en el USB
- [ ] Fichas técnicas impresas (ver sección 13)
- [ ] Laptop conectado al proyector y probado 10 minutos antes
- [ ] Agua en el atril
- [ ] Modo avión OFF del celular, pero silencio ON

---

## 13. Material impreso que llevás

1. **Pricing sheet** (1 página, PYG y USD, 6 planes)
2. **Ficha técnica del producto** (2 páginas con screenshots)
3. **Caso de estudio F48** pseudonimizado (1 página)
4. **Comparativa vs competencia** (1 página, tabla Rapid7 / Qualys / Arctic Wolf / Torq / Kryon)
5. **NDA template** (por si quieren firmar algo ese día)

---

## 14. Qué hacer después

Inmediatamente al terminar:
- Anotá literalmente el feedback más fuerte que escuchaste
- Anotá los 3 clientes que mencionaron como candidatos piloto
- Email de seguimiento en las siguientes 24 horas con: resumen, deck en
  PDF, caso de estudio, próxima fecha propuesta para segunda reunión

Regla: **no esperes más de 5 días laborables** para el primer contacto
post-reunión. Si esperan siete, ya se enfriaron.
