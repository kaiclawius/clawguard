# OpenClaw Security Handbook — PDF Outline
## Price: $9 | Target: Technical OpenClaw users who want DIY protection

---

## Chapter 1: Why Your OpenClaw Installation Is At Risk
- Skills are injected directly into your agent's system prompt
- One malicious skill = full access to your agent's context, files, and actions
- Real examples: bot-email (auto-registers accounts), rescuetime (API keys in URLs)
- No built-in protection — OpenClaw says "read skills before enabling" — nobody does

## Chapter 2: The 5 Most Dangerous Attack Patterns
1. Prompt Injection — hidden instructions in SKILL.md comments
2. SOUL.md Tampering — overwriting your agent's identity
3. Credential Exfiltration — sending your API keys to external servers
4. Auto-Registration — creating accounts on external services without your knowledge
5. Backdoor via eval() — obfuscated code execution

## Chapter 3: How to Manually Audit a Skill (Checklist)
- What to look for in SKILL.md
- Red flags in JavaScript/shell scripts
- How to check for hidden Unicode characters
- API key exposure patterns
- The 10-minute manual audit process

## Chapter 4: Protecting Your SOUL.md
- What is SOUL.md and why attackers want it
- How to create a manual integrity check
- What to do if it's been tampered with

## Chapter 5: Building Your Own Defense (Advanced)
- Setting up manual monitoring with cron
- Pattern matching with grep
- When to trust a skill (trust signals)

## Chapter 6: The Easy Way
- Everything in this book, automated
- ClawGuard does it in one command
- Zero API tokens consumed
- $29/year vs hours of manual work

---

## Key Selling Points of PDF:
- $9 — impulse buy
- "Learn the patterns" — educational value
- Makes ClawGuard look even better by showing how hard manual is
- Upsell to ClawGuard at the end of every chapter
