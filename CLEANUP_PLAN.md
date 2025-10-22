# SKYNET FRAMEWORK - CLEANUP PLAN

**Date:** January 22, 2025
**Objective:** Clean up legacy CAI references and obsolete files
**Status:** 📋 PLANNING

---

## 🎯 CLEANUP OBJECTIVES

1. ✅ Rename root directory: `cai` → `skynet-framework`
2. ✅ Update all CAI references to SKYNET in code
3. ✅ Consolidate session documentation
4. ✅ Archive legacy files
5. ✅ Update environment variables references
6. ✅ Clean up media files with CAI branding

---

## 📊 CURRENT STATE ANALYSIS

### **CAI References Found:**

**In Code (Python):**
- `CAI_MODEL` environment variable (backward compatibility)
- `cai_instance` variable names in codeagent.py
- `run_cai_cli()` function name
- `.cai` directory references
- `cai_` prefixes in filenames

**In Documentation:**
- `README-CAI-LEGACY.md` (79,968 bytes - legacy documentation)
- Multiple session reports (14 files)
- Media files with CAI branding (18+ files)

**In Media:**
- `./media/cai-banner.svg`
- `./media/cai.gif`
- `./media/cai.png`
- `./docs/media/cai-*.png` (11 screenshots)

---

## 🗂️ CLEANUP ACTIONS

### **PHASE A: Directory Structure** 🔴 CRITICAL

**Action 1: Rename Root Directory**
```bash
# Current: C:\Users\admin\Documents\cai
# Target:  C:\Users\admin\Documents\skynet-framework
```

**Impact:** High - Requires user to manually rename or we provide script
**Status:** Requires user action (cannot rename active directory)

---

### **PHASE B: Code Cleanup** 🟡 HIGH PRIORITY

**Action 2: Update Environment Variable References**

Files to update:
1. `src/skynet/agents/central_core.py`
2. `src/skynet/agents/chrome_infiltrator.py`
3. `src/skynet/agents/forensic_analyzer.py`
4. `src/skynet/agents/guardian_protocol.py`
5. `src/skynet/agents/hk_aerial.py`
6. `src/skynet/agents/mail.py`
7. `src/skynet/agents/mission_analyst.py`
8. `src/skynet/agents/mobile_infiltrator.py`
9. `src/skynet/agents/neural_extractor.py`
10. And more...

**Current Code:**
```python
model=os.getenv('SKYNET_MODEL', os.getenv('CAI_MODEL', "alias0"))
```

**Recommendation:** KEEP for backward compatibility
- Existing users may have `CAI_MODEL` in their .env
- Graceful migration path
- Primary is `SKYNET_MODEL`, fallback to `CAI_MODEL`

**Action:** ✅ NO CHANGE NEEDED (backward compatibility is good)

---

**Action 3: Update Internal References**

**Files needing updates:**

1. **src/skynet/agents/codeagent.py**
   - Line 1: "A re-interpretation for CAI of..." → "A re-interpretation for SKYNET of..."
   - Line 5: "cai_instance" → "skynet_instance" (variable rename)
   - Comments referring to "CAI" → "SKYNET"

2. **src/skynet/agents/guardrails.py**
   - "Prompt Injection Guardrails for CAI Agents" → "Prompt Injection Guardrails for SKYNET Agents"

3. **src/skynet/agents/memory.py**
   - "Memory agent for CAI" → "Memory agent for SKYNET"
   - "SKYNET_MEMORY: Enables the use of memory functionality in CAI" → "...in SKYNET"

4. **src/skynet/agents/patterns/utils.py**
   - "integrate with the CAI execution system" → "integrate with the SKYNET execution system"

5. **src/skynet/agents/patterns/__init__.py**
   - "Agent patterns for CAI" → "Agent patterns for SKYNET"

6. **src/skynet/cli.py**
   - `run_cai_cli()` → Keep for now (internal function, breaking change)
   - Comments with CAI → SKYNET

7. **src/skynet/repl/commands/**.py**
   - `.cai` directory → `.skynet` directory
   - `cai_dir` → `skynet_dir`
   - `cai_graph` → `skynet_graph`
   - `cai_default` → `skynet_default`

---

### **PHASE C: Documentation Cleanup** 🟢 MEDIUM PRIORITY

**Action 4: Consolidate Session Documentation**

**Current State:**
- 14 session report files in root
- Total size: ~200+ KB
- Scattered information

**Proposed Structure:**
```
/docs/sessions/
├── README.md (index of all sessions)
├── session_03_summary.md
├── session_04_summary.md
├── session_05_completion.md
├── session_06_completion.md
└── session_10_hexstrike_integration/
    ├── README.md
    ├── phase_1_tool_integration.md
    ├── phase_2_decision_engine.md
    ├── phase_3_correlation_engine.md
    ├── phase_4_browser_automation.md
    └── phase_5_smart_caching.md
```

**Files to Move:**
- `SESSION_3_SUMMARY.md` → `docs/sessions/session_03_summary.md`
- `SESSION_4_SUMMARY.md` → `docs/sessions/session_04_summary.md`
- `SESSION_5_*.md` (2 files) → `docs/sessions/session_05_*.md`
- `SESSION_6_*.md` (2 files) → `docs/sessions/session_06_*.md`
- `SESSION_10_*.md` (5 files) → `docs/sessions/session_10_hexstrike_integration/*.md`

**Files to Archive:**
- `100_PERCENT_COMPLETION.md` → `docs/archive/100_percent_completion.md`
- `ANALYSIS_AND_IMPROVEMENTS.md` → `docs/archive/analysis_and_improvements_pre_session10.md`
- `POST_TRANSFORMATION_ANALYSIS.md` → `docs/archive/post_transformation_analysis.md`
- `PROGRESS_REPORT.md` → `docs/archive/progress_report.md`
- `README_TRANSFORMATION.md` → `docs/archive/readme_transformation.md`
- `FINAL_BATCH_COMPLETION.md` → `docs/archive/final_batch_completion.md`

**Files to Keep in Root:**
- `README.md` (main documentation)
- `CLAUDE.md` (Claude Code specific)
- `SKYNET_ANALYSIS_AND_IMPROVEMENTS.md` (latest analysis)

---

**Action 5: Legacy CAI Documentation**

**File:** `README-CAI-LEGACY.md` (79,968 bytes)

**Recommendation:** Archive
- Move to `docs/archive/README-CAI-LEGACY.md`
- Add note: "Historical reference - SKYNET is the evolved framework"

---

### **PHASE D: Media Cleanup** 🟢 LOWER PRIORITY

**Action 6: CAI Media Files**

**Files Found:**
- `./media/cai-banner.svg`
- `./media/cai.gif`
- `./media/cai.png`
- `./media/caiedu.PNG`
- `./media/caipro_poc.gif`
- `./media/cai_devenv.gif`
- `./docs/media/cai-*.png` (11 files)

**Recommendation:**
1. **Keep for historical reference** - Archive to `docs/archive/media-cai/`
2. **Create new SKYNET branded media** (future enhancement)

---

### **PHASE E: Configuration Cleanup** 🟡 HIGH PRIORITY

**Action 7: Directory References**

**Files to Update:**

1. **src/skynet/repl/commands/quickstart.py**
   ```python
   # Current
   cai_dir = Path.home() / ".cai"

   # New
   skynet_dir = Path.home() / ".skynet"
   # Fallback: check .cai for migration
   if not skynet_dir.exists() and (Path.home() / ".cai").exists():
       # Migrate from .cai to .skynet
   ```

2. **src/skynet/repl/commands/workspace.py**
   - `cai_default` → `skynet_default`

3. **src/skynet/repl/commands/graph.py**
   - `cai_graph_{timestamp}` → `skynet_graph_{timestamp}`

4. **src/skynet/sdk/agents/run_to_jsonl.py**
   - `cai_{session_id}` → `skynet_{session_id}`

---

## 📋 IMPLEMENTATION CHECKLIST

### **Priority 1: Code Updates** (1-2 hours)

- [ ] Update codeagent.py (CAI → SKYNET in comments)
- [ ] Update guardrails.py (documentation)
- [ ] Update memory.py (documentation)
- [ ] Update patterns files (documentation)
- [ ] Update REPL commands (.cai → .skynet with migration)
- [ ] Update graph filename generation
- [ ] Update JSONL filename generation
- [ ] Test all changes

### **Priority 2: Documentation Consolidation** (30-45 minutes)

- [ ] Create `docs/sessions/` directory
- [ ] Create `docs/archive/` directory
- [ ] Move session files to sessions folder
- [ ] Move legacy files to archive
- [ ] Create `docs/sessions/README.md` index
- [ ] Update root README.md if needed

### **Priority 3: Media Cleanup** (15-30 minutes)

- [ ] Create `docs/archive/media-cai/` directory
- [ ] Move CAI media files to archive
- [ ] Document media in archive README

### **Priority 4: User Instructions** (15 minutes)

- [ ] Create `MIGRATION_GUIDE.md` for users
- [ ] Document directory rename process
- [ ] Document .env variable migration
- [ ] Document .cai → .skynet migration

---

## ⚠️ BREAKING CHANGES

**Potential Issues:**

1. **Directory Rename:**
   - Users' shortcuts/bookmarks will break
   - Git remotes may need updating
   - **Mitigation:** Clear documentation

2. **Config Directory (.cai → .skynet):**
   - Existing users have `.cai` directory
   - **Mitigation:** Auto-migration script

3. **Filename Changes:**
   - Graph/JSONL files will have new names
   - **Mitigation:** Non-breaking, just new files

---

## 🎯 RECOMMENDED EXECUTION ORDER

### **Step 1: Code Updates First** (Safest)
- Update internal references
- Add .cai → .skynet migration logic
- Test thoroughly

### **Step 2: Documentation Reorganization**
- Move files to new structure
- Create index files
- Update references

### **Step 3: User Communication**
- Create migration guide
- Update main README
- Announce changes

### **Step 4: Directory Rename** (User Action)
- Provide script or instructions
- User renames cai → skynet-framework

---

## 📝 NOTES

**Backward Compatibility Strategy:**
- Keep `CAI_MODEL` env var as fallback ✅
- Migrate `.cai` → `.skynet` automatically ✅
- Old filenames don't break anything ✅
- Graceful degradation everywhere ✅

**Documentation Philosophy:**
- Archive old, don't delete
- Maintain historical context
- Clear organization

---

**CLEANUP PLAN STATUS:** 📋 READY FOR EXECUTION

**Estimated Total Time:** 2.5-3.5 hours
**Breaking Changes:** Minimal (with migration)
**Risk Level:** Low (with proper testing)

---

END OF CLEANUP PLAN
