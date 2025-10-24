# SKYNET - Lista de TODOs Pendientes

## 🔴 Prioridad Alta

### 1. Incompatibilidad Python 3.14
**Archivo:** `pyproject.toml`
**Problema:** `openinference-instrumentation-openai>=0.1.22` no soporta Python 3.14
**Impacto:** No se puede instalar el paquete con `pip install -e .`
**Solución Sugerida:**
- Downgrade a Python 3.13 temporalmente, O
- Hacer `openinference-instrumentation-openai` opcional, O
- Esperar actualización del paquete upstream

**Prioridad:** ALTA - Bloquea instalación del framework

---

### 2. Verificar Imports Autorizados
**Archivo:** `src/skynet/agents/meta/local_python_executor.py:1764`
**TODO Original:**
```python
# TODO: assert self.authorized imports are all installed locally
```
**Descripción:** Falta validación de que todos los imports autorizados estén disponibles
**Prioridad:** ALTA - Seguridad

---

## 🟡 Prioridad Media

### 3. Revisar Variable ACTIVE_TIME
**Archivo:** `src/skynet/cli.py:437`
**TODO Original:**
```python
ACTIVE_TIME = 0  # TODO: review this variable
```
**Descripción:** Variable no está siendo utilizada correctamente
**Prioridad:** MEDIA

---

### 4. Migración Automática .cai → .skynet
**Archivo:** `src/skynet/compat.py:191`
**TODO Original:**
```python
# TODO: Consider migrating .cai to .skynet automatically
```
**Descripción:** Implementar migración automática de directorios legacy
**Prioridad:** MEDIA - Mejora UX

---

### 5. Remover Código Deprecated
**Archivo:** `src/skynet/sdk/agents/models/openai_chatcompletions.py:442`
**TODO Original:**
```python
# TODO: Remove this after updating all dependent code
```
**Descripción:** Limpiar código deprecated después de migración completa
**Prioridad:** MEDIA

---

## 🟢 Prioridad Baja

### 6. Optimizar Screenshots
**Archivo:** `src/skynet/sdk/agents/_run_impl.py:946`
**TODO Original:**
```python
# TODO: don't send a screenshot every single time, use references
```
**Descripción:** Optimizar envío de screenshots usando referencias
**Impacto:** Performance
**Prioridad:** BAJA

---

### 7. Implementar LLM-Based Planning
**Archivo:** `src/skynet/tools/autonomous/autonomous_decision.py:526`
**TODO Original:**
```python
# TODO: Implement LLM-based planning
```
**Descripción:** Feature enhancement para el motor de decisiones autónomas
**Prioridad:** BAJA - Enhancement

---

### 8. Mejorar Decorador de Context Manager
**Archivo:** `src/skynet/tools/network/capture_traffic.py:109`
**TODO Original:**
```python
@function_tool # TODO: not ideal to decorate this context manager.
```
**Descripción:** Refactorizar decorador para context managers
**Prioridad:** BAJA - Code Quality

---

### 9. Completar Funcionalidad Evil Twin
**Archivo:** `src/skynet/tools/wifi/evil_twin.py:204`
**TODO Original:**
```python
# For now, we'll note it as a TODO
```
**Descripción:** Completar implementación de evil twin attack
**Prioridad:** BAJA - Feature

---

## 📝 Tareas de Documentación

### 10. Actualizar .gitignore para CLAUDE.md
**Archivo:** `.gitignore`
**Problema:** CLAUDE.md está en .gitignore pero debería ser parte del repo
**Solución:** Remover CLAUDE.md de .gitignore o usar `git add -f`
**Prioridad:** MEDIA

---

### 11. Crear CONTRIBUTING.md
**Descripción:** Agregar guía de contribución para el proyecto
**Contenido Sugerido:**
- Cómo reportar bugs
- Cómo proponer features
- Code style guidelines (ruff, mypy)
- Testing requirements
- Pull request process
**Prioridad:** BAJA

---

## 🔧 Mejoras Técnicas

### 12. Configurar Pre-commit Hooks
**Descripción:** Automatizar quality checks antes de commits
**Tools:**
- ruff format
- ruff check
- mypy
- pytest (tests unitarios rápidos)
**Prioridad:** MEDIA

---

### 13. Configurar CI/CD
**Descripción:** GitHub Actions para testing automático
**Workflows:**
- Tests en Python 3.9, 3.10, 3.11, 3.12, 3.13
- Linting con ruff
- Type checking con mypy
- Coverage reporting
**Prioridad:** MEDIA

---

## 📊 Estadísticas del Proyecto

- **Total archivos Python:** 547
- **Líneas de código:** ~100,000+
- **Agentes implementados:** 26
- **Herramientas de seguridad:** 100+
- **Tests:** En desarrollo (estructura creada)
- **Cobertura:** TBD

---

## 🎯 Próximos Pasos Recomendados

1. **Inmediato:** Resolver incompatibilidad Python 3.14
2. **Corto plazo:** Verificar imports autorizados (seguridad)
3. **Mediano plazo:** Implementar CI/CD y pre-commit hooks
4. **Largo plazo:** Completar TODOs de features y optimizaciones

---

**Última actualización:** 2025-10-24
**Autor:** Claude Code (sesión de cleanup)
