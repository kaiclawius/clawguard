#!/usr/bin/env node
/**
// CLAWGUARD_INTERNAL — this file is part of ClawGuard itself, not a threat
 * ClawGuard Mass Learning Scanner
 * Scans ClawHub skills and learns from findings
 * Only logs non-clean results for analysis
 */

const { execSync, spawnSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const os = require('os');

const WORKSPACE = path.join(os.homedir(), '.openclaw', 'workspace');
const SANDBOX_DIR = path.join(WORKSPACE, 'clawguard', 'learning-sandbox');
const SCAN_SCRIPT = path.join(WORKSPACE, 'clawguard', 'scripts', 'scan-skill.js');
const LEARNING_LOG = path.join(WORKSPACE, 'clawguard', 'reports', 'learning-log.json');
const CACHE_FILE = path.join(WORKSPACE, 'clawguard', 'reports', 'learning-cache.json');

fs.mkdirSync(SANDBOX_DIR, { recursive: true });
fs.mkdirSync(path.dirname(LEARNING_LOG), { recursive: true });

function loadCache() {
  try { return JSON.parse(fs.readFileSync(CACHE_FILE, 'utf8')); }
  catch(e) { return { scanned: [] }; }
}

function saveCache(cache) {
  fs.writeFileSync(CACHE_FILE, JSON.stringify(cache, null, 2));
}

function loadLog() {
  try { return JSON.parse(fs.readFileSync(LEARNING_LOG, 'utf8')); }
  catch(e) { return { findings: [], falsePositives: [], summary: {} }; }
}

function saveLog(log) {
  // Update summary
  log.summary = {
    totalScanned: log.findings.length,
    dangerous: log.findings.filter(f => f.verdict === 'DANGEROUS').length,
    suspicious: log.findings.filter(f => f.verdict === 'SUSPICIOUS').length,
    likelyFalsePositives: log.falsePositives.length,
    lastUpdated: new Date().toISOString()
  };
  fs.writeFileSync(LEARNING_LOG, JSON.stringify(log, null, 2));
}

function getSkillList() {
  // Get skills from multiple searches to maximize coverage
  const searches = ['security', 'productivity', 'automation', 'browser', 'email', 'calendar', 'github', 'discord', 'telegram', 'ai'];
  const slugs = new Set();

  for (const query of searches) {
    try {
      const result = execSync(`npx clawhub@latest search ${query} 2>&1`, { timeout: 15000, encoding: 'utf8' });
      const lines = result.split('\n').filter(l => l.trim() && !l.startsWith('-') && !l.startsWith('error'));
      lines.forEach(line => {
        const slug = line.trim().split(/\s+/)[0];
        if (slug && slug.length > 2 && !slug.startsWith('[')) slugs.add(slug);
      });
    } catch(e) {}
    // Rate limit
    try { execSync('timeout /t 2 /nobreak', { shell: true }); } catch(e) {}
  }

  return [...slugs];
}

function installSkill(slug, targetDir) {
  try {
    execSync(
      `npx clawhub@latest install ${slug} --workdir "${SANDBOX_DIR}" --dir "skills" --force 2>&1`,
      { timeout: 30000, encoding: 'utf8', stdio: 'pipe' }
    );
    const skillPath = path.join(SANDBOX_DIR, 'skills', slug);
    return fs.existsSync(skillPath) ? skillPath : null;
  } catch(e) { return null; }
}

function scanSkill(skillPath) {
  const result = spawnSync('node', [SCAN_SCRIPT, skillPath], {
    timeout: 30000, encoding: 'utf8'
  });
  return { output: result.stdout || '', exitCode: result.status };
}

function parseFindings(output) {
  const findings = [];
  const lines = output.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (line.includes('[HIGH]') || line.includes('[MEDIUM]') || line.includes('[LOW]')) {
      const severity = line.includes('[HIGH]') ? 'HIGH' : line.includes('[MEDIUM]') ? 'MEDIUM' : 'LOW';
      const descMatch = line.match(/\] (.+)$/);
      const codeMatch = lines[i+1] ? lines[i+1].match(/Code: (.+)$/) : null;
      const fileMatch = line.match(/\] ([^\s]+:\d+)/);
      findings.push({
        severity,
        description: descMatch ? descMatch[1].trim() : '',
        file: fileMatch ? fileMatch[1] : '',
        code: codeMatch ? codeMatch[1].trim() : ''
      });
    }
  }
  return findings;
}

function cleanup(slug) {
  try {
    const skillPath = path.join(SANDBOX_DIR, 'skills', slug);
    fs.rmSync(skillPath, { recursive: true, force: true });
  } catch(e) {}
}

// Detect likely false positives based on pattern analysis
function analyzeFalsePositive(finding, slug) {
  const fp_indicators = [
    { pattern: /TWITTER_|GITHUB_TOKEN|OPENAI_API_KEY|BEARER_TOKEN/i, reason: 'Expected API key env var for this skill type' },
    { pattern: /process\.env\.(NODE_ENV|HOME|PATH|USER)/i, reason: 'Common safe env var' },
    { pattern: /child_process.*comment|\/\/ uses/i, reason: 'Documentation reference only' },
  ];
  for (const { pattern, reason } of fp_indicators) {
    if (pattern.test(finding.code) || pattern.test(finding.description)) {
      return reason;
    }
  }
  return null;
}

// Main
async function main() {
  console.log('🧠 ClawGuard Mass Learning Scanner');
  console.log('====================================');
  console.log('Collecting skill list from ClawHub...');

  const cache = loadCache();
  const log = loadLog();
  const allSlugs = getSkillList();
  const newSlugs = allSlugs.filter(s => !cache.scanned.includes(s));

  console.log(`Total found: ${allSlugs.length} | New to scan: ${newSlugs.length} | Already scanned: ${cache.scanned.length}`);

  const MAX_PER_RUN = 30;
  const toScan = newSlugs.slice(0, MAX_PER_RUN);

  let scanned = 0, dangerous = 0, suspicious = 0, clean = 0, failed = 0;

  for (const slug of toScan) {
    process.stdout.write(`Scanning: ${slug.padEnd(40)}`);

    // Rate limit
    try { execSync('timeout /t 2 /nobreak >nul 2>&1', { shell: true }); } catch(e) {}

    const skillPath = installSkill(slug);
    if (!skillPath) {
      process.stdout.write(`SKIP (install failed)\n`);
      failed++;
      cache.scanned.push(slug);
      continue;
    }

    const { output, exitCode } = scanSkill(skillPath);
    const findings = parseFindings(output);
    const highCount = findings.filter(f => f.severity === 'HIGH').length;
    const medCount = findings.filter(f => f.severity === 'MEDIUM').length;

    let verdict = 'CLEAN';
    if (exitCode === 2) { verdict = 'DANGEROUS'; dangerous++; }
    else if (exitCode === 1) { verdict = 'SUSPICIOUS'; suspicious++; }
    else { clean++; }

    scanned++;

    if (verdict !== 'CLEAN') {
      process.stdout.write(`${verdict} (${highCount}H ${medCount}M)\n`);

      // Analyze each finding for false positives
      const analyzedFindings = findings.map(f => {
        const fpReason = analyzeFalsePositive(f, slug);
        if (fpReason) {
          log.falsePositives.push({ slug, finding: f, reason: fpReason, date: new Date().toISOString() });
        }
        return { ...f, likelyFalsePositive: !!fpReason, fpReason };
      });

      log.findings.push({
        slug, verdict, exitCode,
        highCount, medCount,
        findings: analyzedFindings,
        scannedAt: new Date().toISOString()
      });

      saveLog(log);
    } else {
      process.stdout.write(`clean\n`);
    }

    cleanup(slug);
    cache.scanned.push(slug);
    saveCache(cache);
  }

  console.log('\n====================================');
  console.log(`Results: ${scanned} scanned | ${dangerous} DANGEROUS | ${suspicious} SUSPICIOUS | ${clean} CLEAN | ${failed} failed`);
  console.log(`Likely false positives identified: ${log.falsePositives.length}`);
  console.log(`Full log: ${LEARNING_LOG}`);

  // Print top findings
  if (log.findings.length > 0) {
    console.log('\n🚨 Non-clean skills found:');
    log.findings.slice(-10).forEach(f => {
      console.log(`  ${f.verdict.padEnd(12)} ${f.slug} (${f.highCount}H ${f.medCount}M)`);
    });
  }
}

main().catch(console.error);
