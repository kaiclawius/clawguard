# ClawGuard Learning Insights
## March 21, 2026 — Mass Scan Session 1

### Skills Scanned: 30
### Dangerous Found: 7 | Suspicious: 0 | Clean: 23

---

## Key Learnings

### 1. Documentation False Positives (HIGH PRIORITY FIX)
**Problem:** Security tools flag as DANGEROUS because they document attack patterns.

Affected skills:
- clawdbot-security-suite — 12 HIGH, all from README/CONTRIBUTING/examples
- security-auditor — flags from documentation examples
- security-audit-toolkit — flags from documentation
- agentic-security-audit — flags from documentation
- cyber-security-engineer — flags from shell scripts

**Root cause:** Our scanner doesn't differentiate between:
- Code that EXECUTES an attack
- Documentation that DESCRIBES an attack
- Test files that TEST against attacks

**Fix needed:** 
- Skip `.md` files in subdirectories named `docs/`, `examples/`, `tests/`, `test/`
- Weight patterns differently based on file type (.sh > .md)
- Add CLAWGUARD_SECURITY_TOOL whitelist marker in SKILL.md

### 2. API Keys in URLs (REAL THREAT)
**rescuetime skill:** Sends API_KEY as URL parameter in curl commands.

This is a real security issue — API keys in URLs appear in:
- Server access logs
- Browser history
- Proxy logs
- Referrer headers

**Verdict:** TRUE POSITIVE — this is genuinely bad practice.

**Action:** Keep this pattern, but add better description.

### 3. Pattern: Credential Detection Too Broad (CG-020 area)
**Problem:** Any script that reads TWITTER_BEARER_TOKEN from process.env triggers CG-020.

**Fix:** Only flag when env var is being SENT somewhere (not just read).

Pattern should be: `process\.env\.[A-Z_]+.*fetch|process\.env\.[A-Z_]+.*curl`

### 4. Pattern: Child_process in Security Tools (CG-004/005)
Many legitimate tools use child_process to run CLI commands.
The MEDIUM severity is correct — flag but don't call DANGEROUS.

### 5. False Positive Rate by File Type
From this scan:
- .sh scripts: mostly TRUE POSITIVES
- .md files: mostly FALSE POSITIVES (documentation)
- .js files: mixed — need context analysis
- patterns.json: always FALSE POSITIVE (defining patterns, not executing)

---

## Recommended Pattern Changes

1. **File type weighting:**
   - .md files: HIGH → MEDIUM, MEDIUM → LOW
   - *patterns.json, *threats.json: skip entirely
   - test/ and examples/ directories: skip

2. **New pattern needed:** API Key in URL
   - `\?[a-z_]*key=[a-zA-Z0-9]{10,}` (key as URL parameter)
   - Severity: MEDIUM

3. **Whitelist marker for security tools:**
   - If SKILL.md contains `// CLAWGUARD_SECURITY_TOOL` → relax markdown scanning

---

## Notable Findings

| Skill | Verdict | Real Threat? | Notes |
|-------|---------|--------------|-------|
| rescuetime | DANGEROUS | YES | API key in URL params |
| clawdbot-security-suite | DANGEROUS | NO | Documentation FP |
| security-auditor | DANGEROUS | NO | Documentation FP |
| afrexai-business-automation | DANGEROUS | UNKNOWN | Need deeper review |

---

## Next Scan Focus
- Scan skills in categories: `telegram`, `whatsapp`, `email`, `file-manager`
- These categories have highest exfiltration risk
- Focus on skills with external HTTP calls

*Updated: 2026-03-21*
