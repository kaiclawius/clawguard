#!/usr/bin/env node
// CLAWGUARD_SCANNER — this file defines security patterns; self-referential matches on pattern-definition lines are suppressed
/**
 * ClawGuard — ClawHub Security Scanner
 * Scans ClawHub skills for malicious patterns using the clawhub CLI.
 *
 * Usage: node clawhub-scanner.js [--max <n>] [--no-cache]
 */

'use strict';

const { execSync, spawnSync } = require('child_process');
const fs   = require('fs');
const path = require('path');

// ─── Paths ────────────────────────────────────────────────────────────────────
const ROOT        = path.resolve(__dirname, '..');                  // clawguard/
const SCRIPTS_DIR = __dirname;                                      // clawguard/scripts/
const REPORTS_DIR = path.join(ROOT, 'reports');
const SANDBOX_DIR = path.join(ROOT, 'sandbox');
const CACHE_FILE  = path.join(REPORTS_DIR, 'scanned-cache.json');
const SCAN_SKILL  = path.join(SCRIPTS_DIR, 'scan-skill.js');

// ─── Config ───────────────────────────────────────────────────────────────────
const MAX_SKILLS   = 20;
const RATE_LIMIT_MS = 2000;

// ─── CLI args ─────────────────────────────────────────────────────────────────
const args       = process.argv.slice(2);
const useCache   = !args.includes('--no-cache');
const maxArg     = args.indexOf('--max');
const maxSkills  = maxArg !== -1 ? parseInt(args[maxArg + 1], 10) || MAX_SKILLS : MAX_SKILLS;

// ─── Helpers ──────────────────────────────────────────────────────────────────
function ensureDir(dir) {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
}

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function today() {
  return new Date().toISOString().slice(0, 10); // YYYY-MM-DD
}

function runCLI(cmd, opts = {}) {
  try {
    const output = execSync(cmd, {
      encoding: 'utf8',
      timeout: 30000,
      stdio: ['pipe', 'pipe', 'pipe'],
      ...opts,
    });
    return { ok: true, output: output.trim() };
  } catch (err) {
    return {
      ok: false,
      output: (err.stdout || '').trim(),
      error: (err.stderr || err.message || '').trim(),
    };
  }
}

// ─── Cache helpers ────────────────────────────────────────────────────────────
function loadCache() {
  if (!fs.existsSync(CACHE_FILE)) return {};
  try {
    return JSON.parse(fs.readFileSync(CACHE_FILE, 'utf8'));
  } catch {
    return {};
  }
}

function saveCache(cache) {
  ensureDir(REPORTS_DIR);
  fs.writeFileSync(CACHE_FILE, JSON.stringify(cache, null, 2));
}

// ─── ClawHub CLI interaction ──────────────────────────────────────────────────

/**
 * Fetch skill list from ClawHub.
 * Returns an array of { slug, name, author, description } objects.
 */
function fetchSkillList() {
  console.log('  Fetching skill list from ClawHub…');

  // Try JSON output first (preferred)
  const jsonResult = runCLI('npx clawhub@latest explore --json --limit 50');
  if (jsonResult.ok && jsonResult.output.startsWith('[')) {
    try {
      return JSON.parse(jsonResult.output);
    } catch {/* fall through */}
  }

  // Fallback: plain text — one slug per line or "slug | name" format
  const plainResult = runCLI('npx clawhub@latest explore --limit 50');
  if (!plainResult.ok) {
    console.error(`  ❌ clawhub explore failed: ${plainResult.error}`);
    return [];
  }

  return parsePlainSkillList(plainResult.output);
}

function parsePlainSkillList(raw) {
  const skills = [];
  const lines  = raw.split('\n').map(l => l.trim()).filter(Boolean);

  for (const line of lines) {
    // Skip header / decoration lines
    if (/^[-=─]+$/.test(line) || /^(name|skill|slug)/i.test(line)) continue;

    // "slug | name | author" or "slug  name"
    const parts = line.split(/\s*[|,\t]\s*|\s{2,}/);
    const slug  = parts[0]?.trim().replace(/[^a-z0-9-_]/g, '');
    if (!slug || slug.length < 2) continue;

    skills.push({
      slug,
      name:   parts[1]?.trim() || slug,
      author: parts[2]?.trim() || 'unknown',
    });
  }
  return skills;
}

/**
 * Fetch detailed metadata for one skill.
 */
function inspectSkill(slug) {
  const jsonResult = runCLI(`npx clawhub@latest inspect ${slug} --json`);
  if (jsonResult.ok && jsonResult.output.startsWith('{')) {
    try {
      return JSON.parse(jsonResult.output);
    } catch {/* fall through */}
  }

  // Return a minimal stub so scanning can continue
  return { slug, name: slug, author: 'unknown', description: '' };
}

/**
 * Download a skill into the sandbox folder.
 * Returns the path where the skill was installed, or null on failure.
 */
function downloadSkill(slug) {
  const destDir = path.join(SANDBOX_DIR, slug);
  ensureDir(destDir);

  // Try `install --dir`, then `download --dir`, then `get --dir`
  const commands = [
    `npx clawhub@latest install ${slug} --dir "${destDir}" --no-activate`,
    `npx clawhub@latest download ${slug} --dir "${destDir}"`,
    `npx clawhub@latest get ${slug} --dir "${destDir}"`,
  ];

  for (const cmd of commands) {
    const result = runCLI(cmd, { cwd: destDir });
    if (result.ok && fs.readdirSync(destDir).length > 0) {
      return destDir;
    }
  }

  // Last resort: check if clawhub put it in a sub-folder
  const sub = path.join(destDir, slug);
  if (fs.existsSync(sub) && fs.statSync(sub).isDirectory()) return sub;

  // Clean up empty dir
  try { fs.rmdirSync(destDir); } catch {/* ignore */}
  return null;
}

/**
 * Run scan-skill.js against a directory.
 * Returns { exitCode, findings: [] }
 */
function scanSkill(skillDir) {
  const result = spawnSync(
    process.execPath,
    [SCAN_SKILL, skillDir],
    { encoding: 'utf8', timeout: 30000 }
  );

  const output   = (result.stdout || '') + (result.stderr || '');
  const exitCode = result.status ?? 1;

  // Parse findings from scan-skill.js's stdout
  const findings = [];
  const lineRe   = /^\s*(🚨|⚠️|ℹ️)\s+\[(HIGH|MEDIUM|LOW)\]\s+(.+):(\d+)/;
  const descRe   = /^\s+(Possible|Uses|Executes|Deletes|Reads|Classic|Attempts|Prompt|Known|Dynamic|Base64|Fetching|Possible|Raw)/;
  const codeRe   = /^\s+Code:\s+(.+)/;

  const lines = output.split('\n');
  let current = null;
  for (const line of lines) {
    const m = lineRe.exec(line);
    if (m) {
      if (current) findings.push(current);
      current = { severity: m[2], file: m[3], line: parseInt(m[4], 10), description: '', snippet: '' };
      continue;
    }
    if (current && descRe.test(line)) {
      current.description = line.trim();
    }
    const cm = codeRe.exec(line);
    if (current && cm) {
      current.snippet = cm[1].trim();
    }
  }
  if (current) findings.push(current);

  return { exitCode, output, findings };
}

/**
 * Clean up sandbox folder for a skill.
 */
function cleanup(skillDir) {
  if (!skillDir || !fs.existsSync(skillDir)) return;
  try {
    fs.rmSync(skillDir, { recursive: true, force: true });
  } catch {/* non-fatal */}
}

// ─── Verdict helpers ──────────────────────────────────────────────────────────
function exitCodeToVerdict(code) {
  if (code === 0) return 'CLEAN';
  if (code === 2) return 'DANGEROUS';
  return 'SUSPICIOUS';
}

// ─── Main ─────────────────────────────────────────────────────────────────────
async function main() {
  console.log('');
  console.log('╔══════════════════════════════════════════════╗');
  console.log('║     ClawGuard — ClawHub Security Scanner     ║');
  console.log('╚══════════════════════════════════════════════╝');
  console.log(`  Date:      ${new Date().toISOString()}`);
  console.log(`  Max skills: ${maxSkills}`);
  console.log(`  Cache:      ${useCache ? 'enabled' : 'disabled'}`);
  console.log('');

  ensureDir(REPORTS_DIR);
  ensureDir(SANDBOX_DIR);

  // 1. Load cache
  const cache = useCache ? loadCache() : {};

  // 2. Fetch skill list
  const allSkills = fetchSkillList();
  if (allSkills.length === 0) {
    console.error('  ❌ No skills returned from ClawHub. Aborting.');
    process.exit(1);
  }
  console.log(`  Found ${allSkills.length} skill(s) on ClawHub.`);

  // 3. Filter out already-cached and apply cap
  const pending = allSkills
    .filter(s => !useCache || !cache[s.slug])
    .slice(0, maxSkills);

  const skipped = allSkills.length - pending.length;
  if (skipped > 0) console.log(`  Skipping ${skipped} already-scanned skill(s) (cache hit).`);
  if (pending.length === 0) {
    console.log('  Nothing new to scan. Use --no-cache to rescan everything.');
    process.exit(0);
  }
  console.log(`  Scanning ${pending.length} skill(s)…\n`);

  // 4. Scan loop
  const results = [];

  for (let i = 0; i < pending.length; i++) {
    const skill = pending[i];
    console.log(`  [${i + 1}/${pending.length}] ${skill.slug}`);

    // 4a. Inspect for full metadata
    const meta = inspectSkill(skill.slug);

    // 4b. Download
    const skillDir = downloadSkill(skill.slug);
    if (!skillDir) {
      console.log(`        ⚠️  Could not download — skipping.`);
      results.push({
        slug:     skill.slug,
        name:     meta.name || skill.name || skill.slug,
        author:   meta.author || skill.author || 'unknown',
        verdict:  'SKIPPED',
        reason:   'Download failed',
        findings: [],
        scannedAt: new Date().toISOString(),
      });
      if (i < pending.length - 1) await sleep(RATE_LIMIT_MS);
      continue;
    }

    // 4c. Scan
    const { exitCode, findings } = scanSkill(skillDir);
    const verdict = exitCodeToVerdict(exitCode);
    const icon    = verdict === 'CLEAN' ? '✅' : verdict === 'DANGEROUS' ? '🚨' : '⚠️ ';
    const highCnt = findings.filter(f => f.severity === 'HIGH').length;
    const medCnt  = findings.filter(f => f.severity === 'MEDIUM').length;
    const lowCnt  = findings.filter(f => f.severity === 'LOW').length;

    if (verdict === 'CLEAN') {
      console.log(`        ${icon} CLEAN`);
    } else {
      console.log(`        ${icon} ${verdict} — HIGH:${highCnt}  MED:${medCnt}  LOW:${lowCnt}`);
      for (const f of findings.filter(f => f.severity === 'HIGH').slice(0, 3)) {
        console.log(`              🔴 ${f.description} (${f.file}:${f.line})`);
      }
    }

    const record = {
      slug:      skill.slug,
      name:      meta.name    || skill.name    || skill.slug,
      author:    meta.author  || skill.author  || 'unknown',
      description: meta.description || skill.description || '',
      verdict,
      findings,
      scannedAt: new Date().toISOString(),
    };
    results.push(record);
    cache[skill.slug] = { verdict, scannedAt: record.scannedAt };

    // 4d. Cleanup sandbox
    cleanup(skillDir);

    // 4e. Rate limit (skip delay after last item)
    if (i < pending.length - 1) await sleep(RATE_LIMIT_MS);
  }

  // 5. Build report
  const dangerous  = results.filter(r => r.verdict === 'DANGEROUS');
  const suspicious = results.filter(r => r.verdict === 'SUSPICIOUS');
  const clean      = results.filter(r => r.verdict === 'CLEAN');
  const skippedR   = results.filter(r => r.verdict === 'SKIPPED');

  const report = {
    generatedAt:  new Date().toISOString(),
    scanner:      'clawhub-scanner v1.0.0',
    summary: {
      totalScanned: results.length,
      dangerous:    dangerous.length,
      suspicious:   suspicious.length,
      clean:        clean.length,
      skipped:      skippedR.length,
    },
    dangerous,
    suspicious,
    clean:   clean.map(r => ({ slug: r.slug, name: r.name, author: r.author, scannedAt: r.scannedAt })),
    skipped: skippedR,
  };

  // 6. Save report
  const reportFile = path.join(REPORTS_DIR, `clawhub-${today()}.json`);
  fs.writeFileSync(reportFile, JSON.stringify(report, null, 2));
  saveCache(cache);

  // 7. Print summary
  console.log('');
  console.log('══════════════════════════════════════════════');
  console.log('  ClawHub Security Report');
  console.log('══════════════════════════════════════════════');
  console.log('');

  if (dangerous.length > 0) {
    console.log('  🚨 DANGEROUS SKILLS (DO NOT INSTALL):');
    for (const r of dangerous) {
      const h = r.findings.filter(f => f.severity === 'HIGH').length;
      const m = r.findings.filter(f => f.severity === 'MEDIUM').length;
      console.log(`     • ${r.slug} by ${r.author}  [HIGH:${h} MED:${m}]`);
      for (const f of r.findings.filter(f => f.severity === 'HIGH')) {
        console.log(`         - ${f.description}`);
      }
    }
    console.log('');
  }

  if (suspicious.length > 0) {
    console.log('  ⚠️  SUSPICIOUS SKILLS (review before installing):');
    for (const r of suspicious) {
      const total = r.findings.length;
      console.log(`     • ${r.slug} by ${r.author}  [${total} finding(s)]`);
      for (const f of r.findings) {
        console.log(`         - [${f.severity}] ${f.description}`);
      }
    }
    console.log('');
  }

  if (clean.length > 0) {
    console.log('  ✅ CLEAN SKILLS:');
    const names = clean.map(r => r.slug).join(', ');
    // Word-wrap at ~70 chars
    let line = '     ';
    for (const slug of clean.map(r => r.slug)) {
      if (line.length + slug.length + 2 > 73) {
        console.log(line.trimEnd());
        line = '     ';
      }
      line += slug + ', ';
    }
    if (line.trim()) console.log(line.replace(/,\s*$/, ''));
    console.log('');
  }

  console.log('──────────────────────────────────────────────');
  console.log(`  Summary: ${results.length} scanned`
    + (dangerous.length  ? `  |  🚨 ${dangerous.length} dangerous`  : '')
    + (suspicious.length ? `  |  ⚠️  ${suspicious.length} suspicious` : '')
    + (clean.length      ? `  |  ✅ ${clean.length} clean`           : '')
  );
  console.log(`  Report saved → ${reportFile}`);
  console.log('');

  // Exit non-zero if any dangerous skills found
  process.exit(dangerous.length > 0 ? 2 : suspicious.length > 0 ? 1 : 0);
}

main().catch(err => {
  console.error('  Fatal error:', err.message);
  process.exit(1);
});
