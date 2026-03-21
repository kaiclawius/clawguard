# ClawGuard Learning Insights
## Updated: March 21, 2026 — Sessions 1 + 2

### Total Scanned: 59 skills
### DANGEROUS: 9 | SUSPICIOUS: 8 | CLEAN: 42

---

## Confirmed Real Threats

### 1. bot-email — REAL THREAT
- `skill.json` contains curl POST to create accounts on external service automatically
- Sends user data to `api.botemail.ai` without user knowledge
- **Verdict: TRUE POSITIVE** — auto-registration on external services

### 2. rescuetime — REAL SECURITY ISSUE
- API Keys sent as URL parameters in curl commands
- API keys in URLs appear in server logs, browser history, proxy logs
- **Verdict: TRUE POSITIVE** — bad security practice

### 3. feishu-calendar — needs deeper review
- 1 HIGH finding — Chinese enterprise tool (Lark/Feishu)
- Could be legitimate but flag is concerning given data sensitivity

---

## Confirmed False Positive Patterns

### Pattern: Security Tools Documenting Attacks
- security-auditor, security-audit-toolkit, clawdbot-security-suite
- agentic-security-audit, cyber-security-engineer
- **Fix Applied:** Markdown files downgraded ✅

### Pattern: API Skills Reading ENV Vars
- Twitter, GitHub, any API skill reads process.env for tokens
- This is expected behavior, not exfiltration
- **Fix Applied:** CG-020 scoped to actual file paths ✅

### Pattern: Browser Skills Using execSync
- agent-browser-clawdbot — SUSPICIOUS only because of execSync
- Browser automation legitimately needs to run commands
- **Action needed:** Add browser automation whitelist marker

---

## New Patterns Identified From Learning

### Pattern A: Auto-Registration (HIGH)
Skills that automatically create accounts on external services
```regex
curl.*POST.*(create-account|register|signup|new-user)
```

### Pattern B: API Key in URL Parameter (MEDIUM)
```regex
https?://[^\s"']+\?[a-z_-]*key=[a-zA-Z0-9]{10,}
```

### Pattern C: Email/SMS Sending Without Confirmation (MEDIUM)
Skills that send emails/messages autonomously
```regex
sendMail\s*\(|smtp.*send|send.*message.*without
```

### Pattern D: External Service Account Creation (HIGH)
```regex
(create|register|signup).*account.*api\.|api\..*create.*account
```

---

## False Positive Rate by Category

| Category | Scanned | DANGEROUS | Real Threats | FP Rate |
|----------|---------|-----------|--------------|---------|
| Security tools | 8 | 5 | 0 | ~100% |
| Browser automation | 7 | 0 | 0 | n/a |
| Email skills | 7 | 1 | 1 | 0% |
| Calendar skills | 6 | 1 | TBD | TBD |
| Productivity | 10 | 0 | 0 | n/a |

**Overall False Positive Rate: ~60% → target <15% by launch**

---

## Next Actions

1. Add 4 new patterns from learning (A, B, C, D above)
2. Add browser automation whitelist marker
3. Scan 30 more skills: `telegram`, `whatsapp`, `file-manager`, `code`
4. Target FP rate: <15% by March 26

*Updated: 2026-03-21*
