# TODO Analysis - SKYNET Codebase

**Fecha:** 24 Octubre 2025
**Total TODOs:** 16
**Categorizados:** 10 Críticos/Altos, 6 Bajos/Info

---

## Resumen Ejecutivo

```
┌──────────────────────────────────────────────────────────┐
│  TODO BREAKDOWN                                          │
├──────────────────────────────────────────────────────────┤
│  Total TODOs:              16                            │
│  Critical Priority:        3                             │
│  High Priority:            4                             │
│  Medium Priority:          3                             │
│  Low Priority:             6                             │
└──────────────────────────────────────────────────────────┘
```

---

## Categorización por Prioridad

### 🔴 CRITICAL (3 TODOs)

#### 1. Screenshot References Optimization
**File:** `src/skynet/sdk/agents/_run_impl.py:946`
**TODO:** `don't send a screenshot every single time, use references`

**Impact:**
- Performance bottleneck
- Bandwidth waste
- Memory issues con multiple screenshots

**Context:**
```python
# TODO: don't send a screenshot every single time, use references
```

**Solución Propuesta:**
- Implementar screenshot diff/reference system
- Solo enviar deltas
- Cache de screenshots recientes

**Effort:** MEDIUM (2-3 hours)

---

#### 2. Authorized Imports Validation
**File:** `src/skynet/agents/meta/local_python_executor.py:1764`
**TODO:** `assert self.authorized imports are all installed locally`

**Impact:**
- Security issue potencial
- Runtime errors si imports faltantes
- No validation antes de ejecución

**Context:**
```python
# TODO: assert self.authorized imports are all installed locally
```

**Solución Propuesta:**
- Pre-flight check de imports
- Validation en __init__
- Error claro si falta dependency

**Effort:** LOW (30 min)

---

#### 3. CTF Challenge Key Implementation
**File:** `src/skynet/util.py:4358`
**TODO:** (incomplete, just "TODO:")

**Impact:**
- Feature incompleta
- CTF challenge handling no implementado

**Context:**
```python
challenge_key = os.getenv("CTF_CHALLENGE")  # TODO:
```

**Solución Propuesta:**
- Definir spec de challenge key
- Implementar validation
- Add documentation

**Effort:** MEDIUM (1-2 hours)

---

### 🟠 HIGH PRIORITY (4 TODOs)

#### 4. LLM-based Autonomous Planning
**File:** `src/skynet/tools/autonomous/autonomous_decision.py:526`
**TODO:** `Implement LLM-based planning`

**Impact:**
- Feature crítica para autonomía
- Actualmente no implementada

**Context:**
```python
# TODO: Implement LLM-based planning
```

**Solución Propuesta:**
- Integrar LLM en decision making
- Planning prompts
- Multi-step strategy generation

**Effort:** HIGH (4-6 hours)

---

#### 5. ACTIVE_TIME Variable Review
**File:** `src/skynet/cli.py:437`
**TODO:** `review this variable`

**Impact:**
- Variable posiblemente no usada o mal implementada
- Cleanup necesario

**Context:**
```python
ACTIVE_TIME = 0  # TODO: review this variable
```

**Solución Propuesta:**
- Auditar uso de ACTIVE_TIME
- Implementar correctamente o remover
- Update documentation

**Effort:** LOW (30 min)

---

#### 6. .cai to .skynet Migration
**File:** `src/skynet/compat.py:191`
**TODO:** `Consider migrating .cai to .skynet automatically`

**Impact:**
- Legacy compatibility issue
- User confusion con naming

**Context:**
```python
# TODO: Consider migrating .cai to .skynet automatically
```

**Solución Propuesta:**
- Auto-migration script
- Backward compatibility mantener
- User notification

**Effort:** MEDIUM (1-2 hours)

---

#### 7. OpenAI Model Code Cleanup
**File:** `src/skynet/sdk/agents/models/openai_chatcompletions.py:442`
**TODO:** `Remove this after updating all dependent code`

**Impact:**
- Code debt
- Legacy code mantener

**Context:**
```python
# TODO: Remove this after updating all dependent code
```

**Solución Propuesta:**
- Identificar dependent code
- Update dependencies
- Remove legacy code

**Effort:** MEDIUM (2-3 hours)

---

### 🟡 MEDIUM PRIORITY (3 TODOs)

#### 8. Function Tool Decorator for Context Manager
**File:** `src/skynet/tools/network/capture_traffic.py:109`
**TODO:** `not ideal to decorate this context manager.`

**Impact:**
- Design pattern issue
- No crítico pero mejorable

**Context:**
```python
@function_tool # TODO: not ideal to decorate this context manager.
```

**Solución Propuesta:**
- Refactor a proper pattern
- Separate tool wrapper from context manager
- Documentation update

**Effort:** MEDIUM (1-2 hours)

---

#### 9. Evil Twin Implementation Note
**File:** `src/skynet/tools/wifi/evil_twin.py:204`
**TODO:** (context: "For now, we'll note it as a TODO")

**Impact:**
- Feature posiblemente incompleta
- Needs investigation

**Context:**
```python
# For now, we'll note it as a TODO
```

**Solución Propuesta:**
- Review evil twin implementation
- Complete missing functionality
- Test thoroughly

**Effort:** MEDIUM (2-3 hours)

---

#### 10. Context Analyzer Patterns (Information)
**File:** `src/skynet/tools/autonomous/context_analyzer.py`
**TODOs:** Multiple (pattern matching, parsing)

**Impact:**
- Informational, already implemented
- Pattern detection funcional

**Lines:**
- Line 15: Documentation reference
- Line 125: Pattern definition
- Line 412: Parsing logic
- Line 419: Source attribution

**Status:** ✅ Actually implemented, just documented as TODO pattern

**Action:** NONE (already working)

---

### 🟢 LOW PRIORITY (6 TODOs)

#### 11-16. Context Analyzer Implementation Details

**Files:** `src/skynet/tools/autonomous/context_analyzer.py` (multiple lines)

**Status:** These are implementation details and pattern definitions that are already functional. They mention "TODO" as part of the pattern matching logic (detecting TODO comments in analyzed code), not actual TODOs to fix.

**Action:** DOCUMENTATION UPDATE (clarify these aren't actual TODOs)

---

## Prioritized Action Plan

### Phase 1: Critical Fixes (MUST DO)

```
┌────────────────────────────────────────────────────────────┐
│  PRIORITY 1: Security & Performance                        │
├────────────────────────────────────────────────────────────┤
│  1. ✅ Authorized Imports Validation (30 min)              │
│  2. ✅ Screenshot References Optimization (2-3h)           │
│  3. ✅ CTF Challenge Key Implementation (1-2h)             │
├────────────────────────────────────────────────────────────┤
│  Total Effort: 4-5.5 hours                                 │
│  Impact: HIGH (security + performance)                     │
└────────────────────────────────────────────────────────────┘
```

### Phase 2: High Priority Enhancements (SHOULD DO)

```
┌────────────────────────────────────────────────────────────┐
│  PRIORITY 2: Feature Completion                            │
├────────────────────────────────────────────────────────────┤
│  4. ✅ ACTIVE_TIME Review (30 min)                         │
│  5. ✅ .cai to .skynet Migration (1-2h)                    │
│  6. ✅ OpenAI Code Cleanup (2-3h)                          │
│  7. ✅ LLM-based Planning (4-6h) [DEFERRED]                │
├────────────────────────────────────────────────────────────┤
│  Total Effort: 8-11.5 hours                                │
│  Impact: MEDIUM (code quality + UX)                        │
└────────────────────────────────────────────────────────────┘
```

### Phase 3: Code Quality (NICE TO HAVE)

```
┌────────────────────────────────────────────────────────────┐
│  PRIORITY 3: Refactoring                                   │
├────────────────────────────────────────────────────────────┤
│  8. Context Manager Decorator (1-2h)                       │
│  9. Evil Twin Completion (2-3h)                            │
│ 10. Documentation Updates (1h)                             │
├────────────────────────────────────────────────────────────┤
│  Total Effort: 4-6 hours                                   │
│  Impact: LOW (code quality)                                │
└────────────────────────────────────────────────────────────┘
```

---

## Recommended Implementation Order

### TOP 10 TODOs to Resolve (This Session)

1. **Authorized Imports Validation** (30 min) - SECURITY
2. **CTF Challenge Key** (1-2h) - FUNCTIONALITY
3. **ACTIVE_TIME Review** (30 min) - CODE CLEANUP
4. **Screenshot References** (2-3h) - PERFORMANCE
5. **.cai to .skynet Migration** (1-2h) - UX
6. **OpenAI Code Cleanup** (2-3h) - CODE DEBT
7. **Context Manager Decorator** (1-2h) - DESIGN PATTERN
8. **Evil Twin Completion** (2-3h) - FEATURE
9. **Documentation Updates** (1h) - CLARITY
10. **LLM-based Planning** (4-6h) - DEFERRED (major feature)

**Total Effort (excl. #10):** 11-17 hours
**Realistic Session Goal:** Complete #1-6 (7-12 hours)

---

## TODOs by Category

### Security (2)
- [ ] Authorized imports validation
- [ ] CTF challenge key implementation

### Performance (1)
- [ ] Screenshot references optimization

### Code Quality (4)
- [ ] ACTIVE_TIME review
- [ ] OpenAI code cleanup
- [ ] Context manager decorator refactor
- [ ] Documentation updates

### Features (3)
- [ ] .cai to .skynet migration
- [ ] Evil twin completion
- [ ] LLM-based planning (deferred)

### Information Only (6)
- Context analyzer patterns (already implemented)

---

## Effort Estimation

```
Total Technical Debt: ~20-30 hours
Critical Path (TOP 6): ~7-12 hours
This Session Goal: Complete 6-7 TODOs
Remaining: 3-4 TODOs for future sessions
```

---

## Success Metrics

**Completion Criteria:**
- [ ] All CRITICAL TODOs resolved
- [ ] All HIGH priority TODOs resolved
- [ ] Code passes all existing tests
- [ ] New tests added for fixes
- [ ] Documentation updated

**Expected Impact:**
- Security: Improved (imports validation, challenge key)
- Performance: Improved (screenshot optimization)
- Code Quality: Improved (cleanup, migrations)
- User Experience: Improved (.cai migration, clear errors)

---

*Análisis generado: 24 Octubre 2025*
*SKYNET Technical Debt Assessment*
*Clearance: Omega-Strategic*
