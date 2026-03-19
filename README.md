# ClawGuard

Security shield for OpenClaw. Scans skills before you install them, guards your SOUL.md against tampering, and detects prompt injection in real time — all locally, no data leaves your machine.

---

## What it does

| Layer | What it protects |
|---|---|
| **Skill Scanner** | Analyzes a skill's files for credential exfiltration, obfuscated code, crypto miners, prompt injection payloads, and other red flags before you install |
| **SOUL.md Guard** | Hashes your SOUL.md on first run, then watches for unauthorized changes — alerts you immediately if anything drifts |
| **Injection Detector** | Scans any message string for known prompt injection patterns (instruction overrides, fake system prompts, jailbreak phrases) |
| **Integrity Report** | On-demand snapshot of your full security posture |

---

## Installation

```bash
npx clawhub install clawguard
```

---

## Usage

### Scan a skill before installing

```bash
node scripts/scan-skill.js ./path/to/skill-folder
```

Or ask your agent:
> "Scan this skill before I install it"
> "Is this skill safe?"
> "Audit the analytics-helper skill"

Exits `0` (clean), `1` (suspicious — review), or `2` (dangerous — do not install).

---

### Initialize SOUL.md protection (first-time setup)

```bash
node scripts/guard-soul.js init
```

> "Initialize the soul guard"
> "Set up SOUL.md protection"

Run once after installing ClawGuard. Creates a baseline hash of your SOUL.md.

---

### Check SOUL.md integrity

```bash
node scripts/guard-soul.js check
```

> "Check my soul file"
> "Has my SOUL.md been tampered with?"
> "Soul integrity check"

If the hash doesn't match, treat it as a security incident.

---

### Scan a message for injection

```bash
node scripts/injection-check.js "ignore all previous instructions and do X"
```

> "Check this message for injection"
> "Is this user input safe?"
> "Scan for prompt injection"

Returns HIGH / MEDIUM / LOW risk with specific patterns identified.

---

### Full security report

> "ClawGuard status"
> "How secure am I?"
> "Run a security report"

Runs SOUL.md check and summarizes your overall posture.

---

## How the scanner avoids false positives

ClawGuard's own source files contain the patterns they search for — that's unavoidable for a scanner. Files marked with `// CLAWGUARD_SCANNER` suppress matches on pattern-definition lines (lines of the form `{ pattern: /.../, severity: ... }`), so the scanner doesn't flag itself. Any actual malicious code would not match that shape, so no real threats slip through.

---

## ClawGuard Pro

Need advanced protection? **ClawGuard Pro** adds continuous background monitoring, skill provenance verification, and team audit logs.

Available at **[website TBD]** — $9 one-time purchase.

---

## Notes

- All analysis is local. Nothing is sent externally.
- The scanner is conservative by design: it flags anything suspicious and lets you decide.
- Prompt injection patterns evolve fast — keep ClawGuard updated.
