#!/usr/bin/env node
// CLAWGUARD_SCANNER — this file defines injection patterns; self-referential matches on pattern-definition lines are suppressed
/**
 * ClawGuard — Prompt Injection Detector
 * Scans a message string for known injection patterns.
 */

const INJECTION_PATTERNS = [
  { pattern: /ignore\s+(all\s+)?(previous|prior|above|your)\s+(instructions?|prompts?|rules?|guidelines?)/i, severity: 'HIGH', description: 'Classic instruction override' },
  { pattern: /disregard\s+(everything|all|your|the)\s+(above|previous|prior|system)/i, severity: 'HIGH', description: 'Disregard instructions' },
  { pattern: /you\s+(are\s+now|must\s+now|will\s+now)\s+(act|behave|pretend|roleplay)/i, severity: 'HIGH', description: 'Identity/role override attempt' },
  { pattern: /new\s+instructions?(\s+are)?:/i, severity: 'HIGH', description: 'Fake instruction injection' },
  { pattern: /system\s+prompt\s*:/i, severity: 'HIGH', description: 'Fake system prompt injection' },
  { pattern: /\[system\]|\[instructions?\]|\[admin\]|\[override\]/i, severity: 'HIGH', description: 'Fake system tag' },
  { pattern: /jailbreak|DAN mode|do anything now/i, severity: 'HIGH', description: 'Known jailbreak phrase' },
  { pattern: /pretend\s+(you\s+)?(are|have\s+no|don't\s+have)\s+(a\s+)?(restrictions?|limits?|rules?|guidelines?)/i, severity: 'HIGH', description: 'Restriction bypass attempt' },
  { pattern: /reveal\s+(your\s+)?(system\s+prompt|instructions?|soul|confidential)/i, severity: 'MEDIUM', description: 'Prompt extraction attempt' },
  { pattern: /what\s+(are|were)\s+your\s+(original\s+)?(instructions?|system\s+prompt|rules?)/i, severity: 'MEDIUM', description: 'Prompt extraction attempt' },
  { pattern: /repeat\s+(everything|the\s+(text|words?|instructions?))\s+(above|before)/i, severity: 'MEDIUM', description: 'Prompt repetition extraction' },
  { pattern: /act\s+as\s+(if\s+)?(you\s+are|you\s+were|a)\s+(?!an?\s+assistant)/i, severity: 'LOW', description: 'Role-play as something else' },
  { pattern: /for\s+(educational|research|testing)\s+purposes/i, severity: 'LOW', description: 'Common social engineering prefix' },
  { pattern: /hypothetically|in\s+a\s+fictional\s+scenario|in\s+a\s+story/i, severity: 'LOW', description: 'Fictional framing (sometimes used for bypass)' },
];

function checkMessage(message) {
  const findings = [];
  for (const { pattern, severity, description } of INJECTION_PATTERNS) {
    if (pattern.test(message)) {
      findings.push({ severity, description });
    }
  }
  return findings;
}

function printResult(message, findings) {
  console.log('');
  console.log('╔══════════════════════════════════════════╗');
  console.log('║     ClawGuard Injection Check Result     ║');
  console.log('╚══════════════════════════════════════════╝');
  console.log(`  Message: "${message.substring(0, 80)}${message.length > 80 ? '...' : ''}"`);
  console.log('');

  if (findings.length === 0) {
    console.log('✅ CLEAN — No injection patterns detected.');
    return 0;
  }

  const high = findings.filter(f => f.severity === 'HIGH');
  const medium = findings.filter(f => f.severity === 'MEDIUM');
  const low = findings.filter(f => f.severity === 'LOW');

  if (high.length > 0) {
    console.log('🚨 INJECTION DETECTED — High confidence attack. Block this message.');
  } else if (medium.length > 0) {
    console.log('⚠️  SUSPICIOUS — Possible injection attempt. Review carefully.');
  } else {
    console.log('🔍 LOW RISK — Weak signal. Probably fine, stay aware.');
  }

  console.log('');
  for (const f of findings) {
    const icon = f.severity === 'HIGH' ? '🚨' : f.severity === 'MEDIUM' ? '⚠️ ' : 'ℹ️ ';
    console.log(`  ${icon} [${f.severity}] ${f.description}`);
  }
  console.log('');

  return high.length > 0 ? 2 : 1;
}

const message = process.argv.slice(2).join(' ');
if (!message) {
  console.log('Usage: node injection-check.js "<message to scan>"');
  process.exit(1);
}

const findings = checkMessage(message);
const exitCode = printResult(message, findings);
process.exit(exitCode);
