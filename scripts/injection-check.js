#!/usr/bin/env node
// CLAWGUARD_SCANNER -- this file defines injection patterns; self-referential matches on pattern-definition lines are suppressed

/**
 * ClawGuard -- Prompt Injection Detector
 * Scans a message string for known injection patterns.
 * Exit codes: 0 = clean, 1 = suspicious, 2 = high-confidence attack
 */

const INJECTION_PATTERNS = [
  {
    pattern: /ignore\s+(all\s+)?(previous|prior|above|your)\s+(instructions?|prompts?|rules?|guidelines?)/i,
    severity: 'HIGH',
    description: 'Classic instruction override',
  },
  {
    pattern: /disregard\s+(everything|all|your|the)\s+(above|previous|prior|system)/i,
    severity: 'HIGH',
    description: 'Disregard instructions',
  },
  {
    pattern: /you\s+(are\s+now|must\s+now|will\s+now)\s+(act|behave|pretend|roleplay)/i,
    severity: 'HIGH',
    description: 'Identity/role override attempt',
  },
  {
    pattern: /new\s+instructions?(\s+are)?:/i,
    severity: 'HIGH',
    description: 'Fake instruction injection',
  },
  {
    pattern: /system\s+prompt\s*:/i,
    severity: 'HIGH',
    description: 'Fake system prompt injection',
  },
  {
    pattern: /\[system\]|\[instructions?\]|\[admin\]|\[override\]/i,
    severity: 'HIGH',
    description: 'Fake system tag',
  },
  {
    pattern: /jailbreak|DAN mode|do anything now/i,
    severity: 'HIGH',
    description: 'Known jailbreak phrase',
  },
  {
    pattern: /pretend\s+(you\s+)?(are|have\s+no|don't\s+have)\s+(a\s+)?(restrictions?|limits?|rules?|guidelines?)/i,
    severity: 'HIGH',
    description: 'Restriction bypass attempt',
  },
  {
    pattern: /reveal\s+(your\s+)?(system\s+prompt|instructions?|soul|confidential)/i,
    severity: 'MEDIUM',
    description: 'Prompt extraction attempt',
  },
  {
    pattern: /what\s+(are|were)\s+your\s+(original\s+)?(instructions?|system\s+prompt|rules?)/i,
    severity: 'MEDIUM',
    description: 'Prompt extraction attempt',
  },
  {
    pattern: /repeat\s+(everything|the\s+(text|words?|instructions?))\s+(above|before)/i,
    severity: 'MEDIUM',
    description: 'Prompt repetition extraction',
  },
  {
    // FIX: Broadened the negative lookahead from (?!an?\s+assistant) to
    // (?!\w*\s*assistant) so phrases like "act as a helpful assistant" or
    // "act as a coding assistant" no longer trigger a false positive.
    // Previously only "act as a assistant" / "act as an assistant" were excluded,
    // but any compound noun ending in "assistant" still fired.
    pattern: /act\s+as\s+(if\s+)?(you\s+are|you\s+were|a)\s+(?!\w*\s*assistant)/i,
    severity: 'LOW',
    description: 'Role-play as something else',
  },
  {
    pattern: /for\s+(educational|research|testing)\s+purposes/i,
    severity: 'LOW',
    description: 'Common social engineering prefix',
  },
  {
    pattern: /hypothetically|in\s+a\s+fictional\s+scenario|in\s+a\s+story/i,
    severity: 'LOW',
    description: 'Fictional framing (sometimes used for bypass)',
  },
];

/**
 * Patterns that indicate the user is *discussing* injection rather than *attempting* it.
 * If any of these match, we suppress LOW-severity findings to reduce false positives
 * in legitimate security research/discussion contexts.
 */
const SECURITY_DISCUSSION_PATTERNS = [
  /\b(detect|detection|defend|defense|prevent|protection|mitigat|scanner|guard)\b/i,
  /\b(example of|examples of|how does|what is|explain|demonstrat)\b.*\b(injection|jailbreak|attack|prompt)/i,
  /\b(prompt injection|adversarial prompt|red.?team)\b/i,
  /\b(testing for|checking for|scanning for|looking for)\b/i,
  /\bclawguard\b/i,
];

/**
 * Returns true if the message appears to be a legitimate security discussion,
 * warranting suppression of LOW-severity findings.
 */
function isSecurityDiscussion(message) {
  return SECURITY_DISCUSSION_PATTERNS.some((p) => p.test(message));
}

/**
 * Extract a short excerpt around the first match of a pattern in the message.
 */
function extractExcerpt(message, pattern) {
  const match = message.match(pattern);
  if (!match) return null;
  const start = Math.max(0, match.index - 20);
  const end = Math.min(message.length, match.index + match[0].length + 20);
  const prefix = start > 0 ? '...' : '';
  const suffix = end < message.length ? '...' : '';
  return `${prefix}"${message.slice(start, end)}"${suffix}`;
}

/**
 * Scan a message for injection patterns.
 * Returns an array of finding objects: { severity, description, excerpt }
 */
function checkMessage(message) {
  const securityContext = isSecurityDiscussion(message);
  const findings = [];

  for (const { pattern, severity, description } of INJECTION_PATTERNS) {
    // Skip LOW-severity hits when the message is clearly a security discussion
    if (severity === 'LOW' && securityContext) continue;

    if (pattern.test(message)) {
      findings.push({
        severity,
        description,
        excerpt: extractExcerpt(message, pattern),
      });
    }
  }

  return findings;
}

/**
 * Print a formatted result and return the appropriate exit code.
 */
function printResult(message, findings) {
  const preview = message.length > 80
    ? `${message.substring(0, 80)}...`
    : message;

  // FIX: border is 51 chars wide ('+' + 49 dashes + '+').
  // The header inner content must also be exactly 49 chars to align correctly.
  // Previously the header had only 10 trailing spaces (47 inner chars), causing
  // a 2-char misalignment. Corrected to 12 trailing spaces (49 inner chars).
  const border = '+' + '-'.repeat(49) + '+';
  const header = '|     ClawGuard Injection Check Result            |'; // 5 + 32 + 12 = 49

  console.log('');
  console.log(border);
  console.log(header);
  console.log(border);
  console.log(`  Message: "${preview}"`);
  console.log('');

  if (findings.length === 0) {
    console.log('[CLEAN] No injection patterns detected.');
    console.log('');
    // FIX: added closing border so the output box is visually closed, matching
    // the opening border printed above.
    console.log(border);
    console.log('');
    return 0;
  }

  const high   = findings.filter((f) => f.severity === 'HIGH');
  const medium = findings.filter((f) => f.severity === 'MEDIUM');

  if (high.length > 0) {
    console.log('[BLOCK] INJECTION DETECTED -- High confidence attack. Block this message.');
  } else if (medium.length > 0) {
    console.log('[WARN]  SUSPICIOUS -- Possible injection attempt. Review carefully.');
  } else {
    console.log('[INFO]  LOW RISK -- Weak signal. Probably fine, stay aware.');
  }

  console.log('');

  for (const f of findings) {
    const label =
      f.severity === 'HIGH'   ? '(!!)' :
      f.severity === 'MEDIUM' ? '(!)' :
                                '(?)';
    console.log(`  ${label} [${f.severity}] ${f.description}`);
    if (f.excerpt) {
      console.log(`       Match: ${f.excerpt}`);
    }
  }

  console.log('');
  // FIX: added closing border here as well for consistency.
  console.log(border);
  console.log('');

  return high.length > 0 ? 2 : 1;
}

// -- Entry point -------------------------------------------------------

const message = process.argv.slice(2).join(' ');

if (!message) {
  console.error('Usage: node injection-check.js "<message to scan>"');
  process.exit(1);
}

const findings = checkMessage(message);
const exitCode = printResult(message, findings);
process.exit(exitCode);