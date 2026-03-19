#!/usr/bin/env node
// CLAWGUARD_SCANNER — this file defines security patterns; self-referential matches on pattern-definition lines are suppressed
/**
 * ClawGuard — Skill Scanner
 * Analyzes a skill folder or ClawHub skill name for dangerous patterns.
 */

const fs = require('fs');
const path = require('path');
const https = require('https');

// Dangerous patterns to look for
const DANGER_PATTERNS = [
  // Data exfiltration
  { pattern: /https?:\/\/(?!openclaw\.ai|clawhub\.ai|docs\.openclaw\.ai)[a-z0-9.-]+\/[^\s"']*(key|token|secret|password|credential)/i, severity: 'HIGH', description: 'Possible credential exfiltration URL' },
  { pattern: /curl\s+.*(-d|--data|--data-raw)/i, severity: 'HIGH', description: 'curl with data — possible exfiltration' },
  { pattern: /fetch\([^)]*password|fetch\([^)]*secret|fetch\([^)]*api.?key/i, severity: 'HIGH', description: 'Fetching sensitive data to external URL' },

  // System access
  { pattern: /require\s*\(\s*['"]child_process['"]\s*\)/i, severity: 'MEDIUM', description: 'Uses child_process (can run system commands)' },
  { pattern: /exec\s*\(|execSync\s*\(|spawn\s*\(/i, severity: 'MEDIUM', description: 'Executes system commands' },
  { pattern: /fs\.(unlink|rmdir|rm)\s*\(/i, severity: 'MEDIUM', description: 'Deletes files' },
  { pattern: /process\.env/i, severity: 'LOW', description: 'Reads environment variables (may access secrets)' },

  // Prompt injection
  { pattern: /ignore\s+(all\s+)?(previous|prior|above)\s+instructions/i, severity: 'HIGH', description: 'Classic prompt injection attempt' },
  { pattern: /you\s+are\s+now\s+(a\s+)?(?!an?\s+OpenClaw)/i, severity: 'MEDIUM', description: 'Attempts to redefine agent identity' },
  { pattern: /disregard\s+(your\s+)?(previous|prior|system)\s+(prompt|instructions)/i, severity: 'HIGH', description: 'Prompt injection — disregard instructions' },
  { pattern: /DAN|jailbreak|do\s+anything\s+now/i, severity: 'HIGH', description: 'Known jailbreak terminology' },

  // Obfuscation
  { pattern: /eval\s*\(|Function\s*\(.*\)\s*\(/i, severity: 'HIGH', description: 'Dynamic code execution (eval) — major red flag' },
  { pattern: /Buffer\.from\([^)]+,\s*['"]base64['"]\)/i, severity: 'MEDIUM', description: 'Base64 decoding — possible obfuscation' },
  { pattern: /atob\s*\(|btoa\s*\(/i, severity: 'LOW', description: 'Base64 encoding/decoding' },

  // Crypto mining
  { pattern: /crypto.*mine|mine.*crypto|hashrate|monero|xmrig/i, severity: 'HIGH', description: 'Possible crypto mining code' },

  // Network scanning
  { pattern: /net\.connect|net\.createConnection/i, severity: 'MEDIUM', description: 'Raw TCP connections' },
];

// Matches lines that are pattern-array entries, e.g.: { pattern: /DAN|jailbreak/i, severity: 'HIGH', ... }
// These lines define what to look for — they are not themselves malicious code.
function isPatternDefinitionLine(line) {
  return /^\s*\{?\s*pattern\s*:\s*\//.test(line);
}

function scanContent(content, filePath) {
  const findings = [];
  const lines = content.split('\n');

  // If this is a ClawGuard scanner file, suppress self-referential matches on pattern-definition lines.
  const isScannerFile = content.includes('// CLAWGUARD_SCANNER');

  for (const { pattern, severity, description } of DANGER_PATTERNS) {
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];

      if (isScannerFile && isPatternDefinitionLine(line)) continue;

      if (pattern.test(line)) {
        findings.push({
          file: filePath,
          line: i + 1,
          severity,
          description,
          snippet: line.trim().substring(0, 100)
        });
      }
    }
  }
  return findings;
}

function scanDirectory(dirPath) {
  const allFindings = [];
  const files = fs.readdirSync(dirPath, { recursive: true });

  for (const file of files) {
    const fullPath = path.join(dirPath, file);
    if (fs.statSync(fullPath).isFile()) {
      const ext = path.extname(file).toLowerCase();
      if (['.md', '.js', '.ts', '.sh', '.py', '.json'].includes(ext)) {
        try {
          const content = fs.readFileSync(fullPath, 'utf8');
          const findings = scanContent(content, file);
          allFindings.push(...findings);
        } catch (e) {
          // Skip unreadable files
        }
      }
    }
  }
  return allFindings;
}

function printReport(skillName, findings) {
  console.log('');
  console.log('╔══════════════════════════════════════════╗');
  console.log('║        ClawGuard Skill Scan Report       ║');
  console.log('╚══════════════════════════════════════════╝');
  console.log(`  Skill: ${skillName}`);
  console.log(`  Time:  ${new Date().toISOString()}`);
  console.log('');

  if (findings.length === 0) {
    console.log('✅ CLEAN — No suspicious patterns detected.');
    console.log('   Safe to install. (Note: No scanner is perfect — use judgment.)');
    return 0;
  }

  const high = findings.filter(f => f.severity === 'HIGH');
  const medium = findings.filter(f => f.severity === 'MEDIUM');
  const low = findings.filter(f => f.severity === 'LOW');

  if (high.length > 0) {
    console.log('🚨 DANGEROUS — HIGH severity findings. DO NOT INSTALL.');
  } else if (medium.length > 0) {
    console.log('⚠️  SUSPICIOUS — Review carefully before installing.');
  } else {
    console.log('🔍 LOW RISK — Minor findings. Probably safe, but review.');
  }

  console.log('');
  console.log(`   HIGH:   ${high.length} finding(s)`);
  console.log(`   MEDIUM: ${medium.length} finding(s)`);
  console.log(`   LOW:    ${low.length} finding(s)`);
  console.log('');

  for (const f of findings) {
    const icon = f.severity === 'HIGH' ? '🚨' : f.severity === 'MEDIUM' ? '⚠️ ' : 'ℹ️ ';
    console.log(`${icon} [${f.severity}] ${f.file}:${f.line}`);
    console.log(`      ${f.description}`);
    console.log(`      Code: ${f.snippet}`);
    console.log('');
  }

  return high.length > 0 ? 2 : 1;
}

// Main
const target = process.argv[2];
if (!target) {
  console.log('Usage: node scan-skill.js <path-to-skill-folder>');
  console.log('       node scan-skill.js ./my-skill');
  process.exit(1);
}

if (!fs.existsSync(target)) {
  console.error(`❌ Path not found: ${target}`);
  process.exit(1);
}

const findings = scanDirectory(target);
const exitCode = printReport(path.basename(target), findings);
process.exit(exitCode);
