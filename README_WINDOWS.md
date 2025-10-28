# Skynet para Windows - Guía Rápida

**TL;DR:** Skynet funciona perfectamente en Windows con OpenVPN. Solo necesitas WSL2.

## 🎯 Tu Setup

```
[Tu Windows] → [WSL2 + Kali] → [OpenVPN] → [Máquina CTF]
                    ↓
                [Skynet]
                    ↓
            [Auto-detect flags]
```

## ⚡ Instalación (3 comandos)

```powershell
# 1. Instalar WSL2 (PowerShell como Admin)
wsl --install -d kali-linux

# Reiniciar

# 2. Instalar Skynet (en WSL)
cd /mnt/c/Users/TuUsuario/path/to/Skynet
pip install -r requirements.txt
python scripts/verify_installation.py

# 3. Inicializar knowledge base
python scripts/init_knowledge.py
```

**Listo!** Ya puedes competir.

## 🚀 Uso Diario

```bash
# Terminal 1: Conectar VPN
sudo openvpn --config lab.ovpn

# Terminal 2: Usar Skynet
python -m skynet.cli.quick scan 10.10.10.100
python -m skynet.cli.quick search "privesc"
python -m skynet.cli.quick flags list
```

## 📚 Documentación Completa

1. **CHECKLIST.md** ← Empieza aquí (paso a paso con checkboxes)
2. **WINDOWS_SETUP.md** ← Guía completa de Windows
3. **QUICKSTART.md** ← Comandos básicos y ejemplos
4. **CLAUDE_CODE_GUIDE.md** ← Workflows avanzados
5. **GAP_ANALYSIS.md** ← Qué falta vs qué está listo

## 💡 Preguntas Frecuentes

**P: ¿Funciona sin APIs de HTB/TryHackMe?**
R: Sí, usas OpenVPN directamente.

**P: ¿Funciona en Windows nativo?**
R: Parcialmente. WSL2 es mejor (todas las herramientas).

**P: ¿Necesito Anthropic API?**
R: No para usar Skynet básico. Claude Code razona, Skynet ejecuta.

**P: ¿Cuánto tarda la instalación?**
R: ~1 hora completa (WSL + Python + herramientas).

**P: ¿Qué está listo para usar?**
R: Todo lo crítico:
- ✅ Escaneo de red
- ✅ Enumeración web
- ✅ Detección automática de flags
- ✅ 200+ técnicas de CTF
- ✅ Análisis de archivos
- ✅ Hash cracking básico

**P: ¿Qué falta?**
R: Features avanzados (no críticos):
- ⚠️ Tests unitarios (para desarrollo)
- ⚠️ APIs de HTB (no las usarás)
- ⚠️ Session persistence (nice to have)

## 🎓 Tu Primer CTF con Skynet

```bash
# 1. Conectar
sudo openvpn --config htb.ovpn

# 2. Reconocimiento
python -m skynet.cli.quick scan 10.10.10.100
# → JSON con puertos abiertos + flags detectadas

# 3. Si hay web (puerto 80/443)
python -m skynet.cli.quick enum-web http://10.10.10.100
# → Directorios + headers + flags

# 4. Buscar técnicas
python -m skynet.cli.quick search "linux privilege escalation"
# → Técnicas relevantes de la knowledge base

# 5. Usar herramientas específicas en Python
python
>>> from skynet.tools.web import WebTools
>>> web = WebTools()
>>> web.sqlmap_test("http://10.10.10.100/page?id=1")

# 6. Ver todas las flags encontradas
python -m skynet.cli.quick flags list
```

## 🔥 Comandos Esenciales

```bash
# Buscar conocimiento
python -m skynet.cli.quick search "<query>"

# Escanear red
python -m skynet.cli.quick scan <ip>

# Enumerar web
python -m skynet.cli.quick enum-web <url>

# Analizar archivo
python -m skynet.cli.quick analyze <file>

# Crackear hash
python -m skynet.cli.quick crack <hash>

# Ver flags
python -m skynet.cli.quick flags list

# Check binario
python -m skynet.cli.quick exploit-check <binary>
```

## ✅ Verificación Rápida

```bash
# ¿Todo instalado correctamente?
python scripts/verify_installation.py

# Debe mostrar:
# ✅ Core functionality: WORKING
# ✅ RAG system: WORKING
# ✅ Flag Detection
```

## 🎯 Siguiente Paso

1. **Lee CHECKLIST.md** para instalación paso a paso
2. **Verifica con** `python scripts/verify_installation.py`
3. **Intenta tu primera máquina CTF**

---

**¿Dudas?** Consulta:
- **WINDOWS_SETUP.md** para setup detallado
- **QUICKSTART.md** para comandos básicos
- **CLAUDE_CODE_GUIDE.md** para workflows completos

**¡Buena suerte en tus CTFs!** 🚀🏴‍☠️
