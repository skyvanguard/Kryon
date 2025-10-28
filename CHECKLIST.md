# Skynet - Checklist de Instalación

Guía rápida para verificar que todo está listo para competir.

## 📋 Pre-Instalación (Windows)

### 1. WSL2
- [ ] Abrir PowerShell como Administrador
- [ ] Ejecutar: `wsl --install -d kali-linux`
- [ ] Reiniciar computadora
- [ ] Abrir WSL: `wsl`
- [ ] Actualizar: `sudo apt update && sudo apt upgrade -y`

**Tiempo estimado: 20-30 minutos**

---

## 📦 Instalación de Skynet

### 2. Clonar Repositorio (si no lo has hecho)
```bash
# En Windows (Git Bash o PowerShell)
cd C:\Users\TuUsuario\Documents
git clone https://github.com/skyvanguard/Skynet.git
```

- [ ] Repositorio clonado
- [ ] Abrir en VS Code

### 3. Instalar Python Dependencies
```bash
# En WSL
cd /mnt/c/Users/TuUsuario/Documents/Skynet

# Instalar
pip install -r requirements.txt
```

**Paquetes que se instalan:**
- [ ] anthropic
- [ ] openai
- [ ] chromadb
- [ ] sentence-transformers (puede tardar, ~2GB)
- [ ] numpy, pandas
- [ ] python-dotenv

**Tiempo estimado: 10-15 minutos**

### 4. Instalar Herramientas CTF
```bash
# En WSL
sudo apt install -y nmap gobuster sqlmap nikto john hashcat binwalk exiftool steghide hydra netcat-traditional whois dnsutils

# Herramientas de pwn
sudo apt install -y gdb patchelf checksec
pip install pwntools ropper
```

- [ ] Herramientas de red instaladas (nmap, etc.)
- [ ] Herramientas web instaladas (gobuster, sqlmap)
- [ ] Herramientas de análisis (john, binwalk)
- [ ] Herramientas de pwn (pwntools, ropper)

**Tiempo estimado: 5-10 minutos**

---

## ✅ Verificación

### 5. Verificar Instalación de Skynet
```bash
cd /mnt/c/Users/TuUsuario/Documents/Skynet
python scripts/verify_installation.py
```

**Debe mostrar:**
- [ ] ✅ Core functionality: WORKING
- [ ] ✅ RAG system: WORKING
- [ ] ✅ Flag Detection
- [ ] ✅ Network Tools
- [ ] ✅ Command Executor

**Si algo falla:**
- Revisa el output del script
- Instala las dependencias que falten
- Ver WINDOWS_SETUP.md para troubleshooting

### 6. Inicializar Knowledge Base
```bash
python scripts/init_knowledge.py
```

**Debe mostrar:**
- [ ] ✅ Imported web_techniques.txt
- [ ] ✅ Imported linux_privesc.txt
- [ ] ✅ Imported crypto_techniques.txt
- [ ] ✅ Imported pwn_techniques.txt
- [ ] ✅ Initialized with 200+ techniques

**Tiempo estimado: 2-3 minutos**

### 7. Test Quick Commands
```bash
# Test 1: Search knowledge
python -m skynet.cli.quick search "sql injection"
# Debe devolver JSON con técnicas

# Test 2: Flag detection
python -m skynet.cli.quick flags count
# Debe devolver {"success": true, "count": 0}

# Test 3: Help
python -m skynet.cli.quick help
# Debe listar todos los comandos
```

- [ ] Search funciona
- [ ] Flags funciona
- [ ] Help funciona

---

## 🌐 OpenVPN Setup

### 8. Instalar OpenVPN
```bash
# En WSL
sudo apt install openvpn
```

- [ ] OpenVPN instalado

### 9. Test Conexión (con archivo .ovpn de prueba)
```bash
# Conectar a lab de prueba
sudo openvpn --config ~/Downloads/lab.ovpn

# En otra terminal, verificar
ip a  # Debe mostrar interfaz tun0
ping 10.10.10.1  # O IP de gateway del lab
```

- [ ] OpenVPN se conecta sin errores
- [ ] Interfaz tun0 existe
- [ ] Puedes hacer ping al gateway

---

## 🎯 Test Completo (Primera Máquina)

### 10. Test en Máquina Real
```bash
# Terminal 1: Conectar VPN
sudo openvpn --config ~/htb.ovpn

# Terminal 2: Usar Skynet
cd /mnt/c/Users/TuUsuario/Documents/Skynet

# Scan
python -m skynet.cli.quick scan 10.10.10.100

# Buscar técnicas
python -m skynet.cli.quick search "privilege escalation"

# Ver flags detectadas
python -m skynet.cli.quick flags list
```

**Checklist del test:**
- [ ] VPN conecta correctamente
- [ ] Scan detecta puertos
- [ ] Search devuelve técnicas relevantes
- [ ] Flags se detectan automáticamente
- [ ] Todo el output es JSON parseable

---

## 🔧 Configuración Opcional

### 11. VS Code con WSL (Recomendado)
```bash
# Instalar extensión: Remote - WSL
# En WSL:
code /mnt/c/Users/TuUsuario/Documents/Skynet
```

- [ ] VS Code abre en WSL
- [ ] Terminal integrada usa WSL
- [ ] Python IntelliSense funciona

### 12. Jupyter Notebook (Opcional)
```bash
pip install jupyter
jupyter notebook --no-browser
```

- [ ] Jupyter se inicia
- [ ] Accesible desde Windows browser
- [ ] Puede importar skynet modules

### 13. API Keys (Opcional)
```bash
# Solo si usarás OpenAI embeddings
cp .env.example .env
nano .env
# Agregar: OPENAI_API_KEY=tu_key
```

- [ ] .env creado (si es necesario)
- [ ] API keys configuradas (si es necesario)

**Nota:** No es necesario para usar Skynet básico

---

## 📊 Resumen Final

### Instalación Básica (Mínimo para competir)
✅ Componentes instalados:
- [ ] WSL2 + Kali Linux
- [ ] Python dependencies
- [ ] Herramientas CTF básicas (nmap, gobuster, etc.)
- [ ] Skynet verificado
- [ ] Knowledge base inicializada
- [ ] OpenVPN funcionando

**Tiempo total: ~1 hora**

### Funcionalidades Disponibles
- [x] Escaneo de red (nmap, dig, whois)
- [x] Enumeración web (gobuster, nikto)
- [x] Detección automática de flags
- [x] Búsqueda de técnicas (200+)
- [x] Análisis de archivos (binwalk, strings)
- [x] Hash cracking (john)
- [x] Check de seguridad de binarios

### Lo que NO necesitas instalar
- [ ] ~~APIs de HTB/TryHackMe~~ (no las usarás)
- [ ] ~~Anthropic API~~ (Claude Code lo maneja)
- [ ] ~~Tests unitarios~~ (para desarrollo, no para uso)
- [ ] ~~Dashboard web~~ (opcional, no crítico)

---

## 🚀 Estás Listo Para Competir Si:

- [x] `python scripts/verify_installation.py` → ✅ WORKING
- [x] `python -m skynet.cli.quick search "test"` → Devuelve JSON
- [x] `python -m skynet.cli.quick flags count` → Devuelve {"success": true}
- [x] OpenVPN conecta a lab de prueba
- [x] Puedes hacer ping a máquinas del lab
- [x] `python -m skynet.cli.quick scan <target>` → Detecta puertos

---

## 📖 Documentación de Referencia

Para cada paso, consulta:

1. **WINDOWS_SETUP.md** - Guía completa de Windows + OpenVPN
2. **QUICKSTART.md** - Inicio rápido y comandos básicos
3. **NOTEBOOK_SETUP.md** - Uso en Jupyter/Python
4. **CLAUDE_CODE_GUIDE.md** - Workflows completos
5. **GAP_ANALYSIS.md** - Qué falta vs qué está listo

---

## 🐛 Troubleshooting Rápido

| Problema | Solución |
|----------|----------|
| "ModuleNotFoundError: skynet" | `cd /mnt/c/.../Skynet` y `pip install -e .` |
| "Command not found: nmap" | `sudo apt install nmap` en WSL |
| "Permission denied: openvpn" | Usar `sudo openvpn ...` |
| ChromaDB error | Verificar instalación: `pip install chromadb` |
| No results from search | Ejecutar `python scripts/init_knowledge.py` |
| Can't reach target | Verificar VPN: `ip a` debe mostrar tun0 |

---

## 💡 Primer CTF - Pasos

```bash
# 1. Conectar VPN
sudo openvpn --config lab.ovpn &

# 2. Recon
python -m skynet.cli.quick scan 10.10.10.100

# 3. Buscar técnicas
python -m skynet.cli.quick search "linux privesc"

# 4. Enumerar web (si aplica)
python -m skynet.cli.quick enum-web http://10.10.10.100

# 5. Ver flags detectadas
python -m skynet.cli.quick flags list
```

---

## ✅ Checklist Completado

Si todos los checkboxes están marcados:

🎉 **¡Skynet está 100% listo para competir!** 🎉

**Siguiente paso:** Intenta tu primera máquina CTF

**Buena suerte!** 🚀🏴‍☠️
