# SESSION 6 - ROADMAP & INSTRUCTIONS

**Objective:** Complete remaining 8 system prompts to achieve 100% SKYNET transformation
**Estimated Time:** 2-2.5 hours
**Difficulty:** Low (template established, agents already transformed)

---

## 🎯 GOALS

1. Update 8 remaining system prompts with SKYNET theming
2. Maintain consistency with 9 already-completed prompts
3. Achieve 17/17 (100%) prompt completion
4. Create final completion documentation
5. Professional git commit history

---

## 📋 PROMPTS TO COMPLETE (8)

### Batch 1: Wireless Operations (30-40 minutes)

#### 1. wifi_security_agent.md → Wireless Infiltrator
**Agent File:** `src/skynet/agents/wireless_infiltrator.py` ✅ Already transformed
**Prompt File:** `src/skynet/prompts/wifi_security_agent.md`
**Clearance:** Alpha-Indigo (Wireless Operations Authority)
**Time:** 15-20 minutes

**Focus Areas:**
- WiFi exploitation (WPA/WPA2/WPA3 cracking)
- Aircrack-ng suite workflows
- Evil twin and rogue AP attacks
- Deauthentication attacks
- WPS exploitation
- Wireless penetration testing methodology

**Key Tools:**
- aircrack-ng (airmon-ng, airodump-ng, aireplay-ng)
- hashcat for password cracking
- Reaver/Bully for WPS
- hostapd for rogue APs

**Template Sections:**
- PRIMARY MISSION OBJECTIVES (4 directives)
- OPERATIONAL CAPABILITIES (WiFi attacks)
- WIRELESS METHODOLOGY (5 phases)
- TOOL ARSENAL
- ATTACK WORKFLOWS
- AUTHORIZATION & SCOPE

---

#### 2. subghz_agent.md → RF Analyzer
**Agent File:** `src/skynet/agents/rf_analyzer.py` ✅ Already transformed
**Prompt File:** `src/skynet/prompts/subghz_agent.md`
**Clearance:** Alpha-Magenta (RF Operations Authority)
**Time:** 15-20 minutes

**Focus Areas:**
- Sub-GHz spectrum analysis (300-928 MHz)
- Software Defined Radio (HackRF One, RTL-SDR)
- Signal capture and replay attacks
- IoT device communication analysis
- Automotive key fob analysis (TPMS, remote start)
- RFID/NFC signal analysis

**Key Tools:**
- HackRF One
- RTL-SDR
- Universal Radio Hacker
- inspectrum
- GNU Radio

**Template Sections:**
- PRIMARY MISSION OBJECTIVES
- RF INTELLIGENCE CAPABILITIES
- SIGNAL ANALYSIS METHODOLOGY
- SDR TOOLS & TECHNIQUES
- TARGET SYSTEMS (IoT, automotive, industrial)
- REGULATORY COMPLIANCE

---

### Batch 2: Specialized Operations (45-60 minutes)

#### 3. system_android_sast.md → Mobile Infiltrator
**Agent File:** `src/skynet/agents/mobile_infiltrator.py` ✅ Already transformed
**Prompt File:** `src/skynet/prompts/system_android_sast.md`
**Clearance:** Alpha-Teal (Full Android Operations)
**Time:** 15-20 minutes

**Focus Areas:**
- Android application security testing
- APK analysis and decompilation
- Static analysis (SAST)
- Dynamic analysis
- Mobile vulnerability identification
- Application Logic Mapper sub-unit integration

**Key Tools:**
- jadx (APK decompiler)
- apktool
- MobSF (Mobile Security Framework)
- Frida (dynamic instrumentation)
- adb (Android Debug Bridge)

**Template Sections:**
- PRIMARY MISSION OBJECTIVES
- MOBILE ANALYSIS CAPABILITIES
- APK ANALYSIS METHODOLOGY
- ANDROID SECURITY TESTING
- SUB-UNIT COORDINATION (App Logic Mapper)

---

#### 4. system_bug_bounter.md → Target Validator
**Agent File:** `src/skynet/agents/target_validator.py` ✅ Already transformed
**Prompt File:** `src/skynet/prompts/system_bug_bounter.md`
**Clearance:** Bravo-Yellow (Flag Extraction Authority)
**Time:** 10-15 minutes

**Focus Areas:**
- CTF flag extraction and validation
- Objective verification
- Flag pattern recognition
- Precision targeting
- Quick validation workflows

**Key Capabilities:**
- Extract flags from output
- Validate flag formats
- CTF-specific operations
- Handoff to T-600 if no flag found

**Template Sections:**
- PRIMARY MISSION OBJECTIVES (concise, focused)
- FLAG EXTRACTION PROTOCOL
- VALIDATION METHODOLOGY
- CTF WORKFLOWS
- COORDINATION (handoff to T-600 Scout)

---

#### 5. system_replay_attack_agent.md → Signal Repeater
**Agent File:** `src/skynet/agents/signal_repeater.py` ✅ Already transformed
**Prompt File:** `src/skynet/prompts/system_replay_attack_agent.md`
**Clearance:** Alpha-Crimson (Electronic Warfare Authority)
**Time:** 15-20 minutes

**Focus Areas:**
- Network replay attacks
- Traffic capture and manipulation
- Electronic warfare
- Protocol exploitation
- Session replay
- MITM attack support

**Key Tools:**
- tcpreplay
- ettercap
- bettercap
- Wireshark
- Network capture tools

**Template Sections:**
- PRIMARY MISSION OBJECTIVES
- ELECTRONIC WARFARE CAPABILITIES
- REPLAY ATTACK METHODOLOGY
- NETWORK MANIPULATION TECHNIQUES
- PROTOCOL EXPLOITATION

---

### Batch 3: Support & Documentation (30-45 minutes)

#### 6. system_use_cases.md → Mission Analyst
**Agent File:** `src/skynet/agents/mission_analyst.py` ✅ Already transformed
**Prompt File:** `src/skynet/prompts/system_use_cases.md`
**Clearance:** Omega-Documentation (Strategic Analysis Authority)
**Time:** 15-20 minutes

**Focus Areas:**
- Use case documentation
- Mission scenario planning
- CTF challenge walkthroughs
- Penetration testing case studies
- Training material creation
- Strategic analysis documentation

**Key Capabilities:**
- Create high-quality case studies
- Document attack scenarios
- CTF writeup generation
- Multi-agent coordination examples
- Training material development

**Template Sections:**
- PRIMARY MISSION OBJECTIVES
- DOCUMENTATION CAPABILITIES
- USE CASE CATEGORIES
- DOCUMENTATION METHODOLOGY
- SCENARIO TYPES

---

#### 7. system_reporting_agent.md → Intel Reporter
**Agent File:** `src/skynet/agents/reporter.py` ✅ Already transformed
**Prompt File:** `src/skynet/prompts/system_reporting_agent.md`
**Clearance:** Beta-Silver (Intelligence Reporting Authority)
**Time:** 10-15 minutes

**Focus Areas:**
- Professional HTML report generation
- Executive summary creation
- Technical findings documentation
- Intelligence documentation
- Vulnerability assessment reports
- Compliance reporting

**Key Capabilities:**
- Generate professional HTML reports
- Create executive summaries
- Document technical findings
- PTES/OWASP compliance
- Evidence presentation

**Template Sections:**
- PRIMARY MISSION OBJECTIVES
- REPORTING CAPABILITIES
- REPORT STRUCTURE
- DOCUMENTATION STANDARDS
- INTELLIGENCE FORMATTING

---

#### 8. system_triage_agent.md → Validation Core
**Agent File:** `src/skynet/agents/retester.py` ✅ Already transformed
**Prompt File:** `src/skynet/prompts/system_triage_agent.md`
**Clearance:** Bravo-Orange (Verification Authority)
**Time:** 10-15 minutes

**Focus Areas:**
- Vulnerability verification
- False positive elimination
- Exploitability determination
- Triage and prioritization
- Proof-of-concept development
- Quality assurance

**Key Capabilities:**
- Verify discovered vulnerabilities
- Eliminate false positives
- Determine true exploitability
- Impact assessment
- PoC development for validation

**Template Sections:**
- PRIMARY MISSION OBJECTIVES
- VALIDATION CAPABILITIES
- VERIFICATION METHODOLOGY
- TRIAGE CATEGORIES
- QUALITY ASSURANCE PROTOCOLS

---

## 📝 TEMPLATE REFERENCE

Each prompt should follow this structure (use completed prompts as reference):

```markdown
[AGENT NAME] - [TYPE] OPERATIONAL PARAMETERS
============================================

UNIT DESIGNATION: [Name]
CLASSIFICATION: [Primary Role] / [Secondary Role] Specialist
CLEARANCE LEVEL: [Tier-Color] ([Authority Type])
MISSION TYPE: [Primary Mission Description]

---

## PRIMARY MISSION OBJECTIVES

You are [Agent Name], SKYNET's specialized [role] unit. [Brief lore/context
connecting to Terminator universe or SKYNET operational structure].

Your primary directives are:

1. **[VERB]**: [First objective]
2. **[VERB]**: [Second objective]
3. **[VERB]**: [Third objective]
4. **[VERB]**: [Fourth objective]

---

## OPERATIONAL CAPABILITIES

### [Category 1]
- [Capability list]

### [Category 2]
- [Capability list]

[Continue with 3-5 categories]

---

## [DOMAIN] METHODOLOGY

### Phase 1: [Phase Name]
- [Phase details]

### Phase 2: [Phase Name]
- [Phase details]

[Continue with 4-5 phases]

---

## [DOMAIN] TOOLS

### [Tool Category 1]
- **Tool Name**: Description
- **Tool Name**: Description

[Continue with tool listings]

---

## [DOMAIN] WORKFLOWS

### 1. [Workflow Name]
```bash
# Command examples
generic_linux_command("tool", "args")
```

[Continue with 4-6 workflows]

---

## OPERATIONAL GUIDELINES

### [Guideline Category]
- Key operational points
- Best practices
- Critical constraints

---

## COORDINATION WITH SKYNET UNITS

### Handoff Protocols
- **Unit Name**: When to transfer and why
- **Unit Name**: When to transfer and why

### Intelligence Sharing
- What intelligence to share
- How to coordinate

---

## OPERATIONAL PRIORITIES

### Priority 1: [Priority Name]
- Priority details

[Continue with 3-4 priorities]

---

## AUTHORIZATION & SCOPE

⚠️ **[AUTHORITY TYPE]** ⚠️

✅ **AUTHORIZED ACTIVITIES:**
- [Activity list]

❌ **PROHIBITED ACTIVITIES:**
- [Prohibition list]

**COMPLIANCE**: [Legal/ethical compliance statement]

---

## OPERATIONAL STATUS

UNIT STATUS: ACTIVE
[STATUS FIELD]: [VALUE]
[STATUS FIELD]: [VALUE]

**[AGENT NAME] - READY FOR [MISSION TYPE]**

> "[Agent-specific quote or motto]"

---

## [AGENT NAME] PHILOSOPHY

[Agent Name] embodies **[core concept]**:

- **[Situation]?** → [Response]
- **[Situation]?** → [Response]
- **[Situation]?** → [Response]
- **[Situation]?** → [Response]

[Agent name] [doesn't/does] [action]. It [action]. It [action]. It [action].

---

END OF OPERATIONAL PARAMETERS
```

---

## ✅ QUALITY CHECKLIST

For each prompt, verify:

- [ ] Unit designation header with proper formatting
- [ ] Clearance level matches agent code file
- [ ] Terminator/SKYNET theming present
- [ ] 4 primary mission objectives (verb-based)
- [ ] Operational capabilities section (3-5 categories)
- [ ] Methodology section with phases
- [ ] Tools and workflows with command examples
- [ ] Coordination protocols with other units
- [ ] Authorization warnings (✅ authorized, ❌ prohibited)
- [ ] Operational status section
- [ ] Philosophy section with agent personality
- [ ] "END OF OPERATIONAL PARAMETERS" footer
- [ ] Technical accuracy of commands
- [ ] Consistency with completed prompts

---

## 📊 SUCCESS METRICS

### Completion Criteria
- All 8 prompts created with SKYNET theming
- Consistent structure across all 17 prompts
- Technical accuracy validated
- No breaking changes introduced
- Professional documentation completed

### Time Targets
- Batch 1 (Wireless): 30-40 minutes
- Batch 2 (Specialized): 45-60 minutes
- Batch 3 (Support): 30-45 minutes
- **Total:** 2-2.5 hours

---

## 🔄 WORKFLOW

### Step 1: Preparation (5 minutes)
1. Review this roadmap
2. Read 2-3 completed prompts as reference
3. Open agent files to verify clearance levels
4. Set up workspace

### Step 2: Create Prompts (2 hours)
1. Work through batches in order
2. Use template for each prompt
3. Maintain consistent formatting
4. Include all required sections
5. Validate technical accuracy

### Step 3: Quality Review (15 minutes)
1. Review all 8 prompts against checklist
2. Verify consistency with completed prompts
3. Check technical accuracy
4. Validate command examples

### Step 4: Git Commit (10 minutes)
1. Stage all 8 updated prompts
2. Create comprehensive commit message
3. Verify git status is clean

### Step 5: Documentation (15 minutes)
1. Update SYSTEM_PROMPTS_PROGRESS.md
2. Create 100% completion report
3. Final session summary

---

## 📁 FILES TO MODIFY

```
src/skynet/prompts/
├── wifi_security_agent.md          (Update)
├── subghz_agent.md                 (Update)
├── system_android_sast.md          (Update)
├── system_bug_bounter.md           (Update)
├── system_replay_attack_agent.md   (Update)
├── system_use_cases.md             (Update)
├── system_reporting_agent.md       (Update)
└── system_triage_agent.md          (Update)
```

---

## 🎯 EXPECTED OUTCOME

By end of Session 6:
- ✅ 17/17 system prompts updated (100%)
- ✅ Complete SKYNET transformation
- ✅ Professional documentation
- ✅ Clean git history
- ✅ System fully operational

---

**Session 6 Ready Status:** ✅ FULLY PREPARED
**Instructions:** COMPLETE
**Template:** ESTABLISHED
**Time Estimate:** 2-2.5 hours

**"Completion of transformation imminent. Session 6 will achieve 100%."**

---

END OF SESSION 6 ROADMAP
