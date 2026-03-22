#!/usr/bin/env node
/**
// CLAWGUARD_INTERNAL — this file is part of ClawGuard itself, not a threat
 * ClawGuard Background Monitor
 * Runs via OS scheduler (Task Scheduler / cron / LaunchAgent)
 * Zero LLM tokens. Zero API credits. Pure Node.js.
 *
 * Usage:
 *   node background-monitor.js --soul     (check SOUL.md integrity)
 *   node background-monitor.js --scan     (scan skills folder)
 *   node background-monitor.js --all      (run all checks)
 *
 * On alert: calls `openclaw message send` to notify via Telegram
 */

const { execSync, spawnSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const os = require('os');

const WORKSPACE = process.env.OPENCLAW_WORKSPACE ||
  path.join(os.homedir(), '.openclaw', 'workspace');
const CLAWGUARD_DIR = path.join(os.homedir(), '.clawguard');
const SOUL_PATH = path.join(WORKSPACE, 'SOUL.md');
const HASH_PATH = path.join(CLAWGUARD_DIR, 'soul.hash');
const SKILLS_DIR = path.join(WORKSPACE, 'skills');
const SCAN_SCRIPT = path.join(__dirname, 'scan-skill.js');
const STATE_FILE = path.join(CLAWGUARD_DIR, 'monitor-state.json');
const LOG_FILE = path.join(CLAWGUARD_DIR, 'monitor.log');

function log(msg) {
  const line = `[${new Date().toISOString()}] ${msg}`;
  console.log(line);
  try {
    fs.appendFileSync(LOG_FILE, line + '\n');
  } catch(e) {}
}

function alert(message) {
  log(`ALERT: ${message}`);
  // Send via OpenClaw CLI — only moment OpenClaw is involved
  try {
    execSync(`npx openclaw message send --channel telegram --text "🚨 ClawGuard Alert: ${message}"`, {
      timeout: 10000,
      stdio: 'pipe'
    });
    log('Alert sent via Telegram.');
  } catch(e) {
    log(`Failed to send alert: ${e.message}`);
    // Fallback: write to a prominent alert file
    fs.writeFileSync(
      path.join(WORKSPACE, 'CLAWGUARD-ALERT.md'),
      `# 🚨 ClawGuard Alert\n\n${message}\n\nTime: ${new Date().toISOString()}\n`
    );
  }
}

function loadState() {
  try {
    return JSON.parse(fs.readFileSync(STATE_FILE, 'utf8'));
  } catch(e) {
    return { lastSoulHash: null, knownSkills: [], lastScan: null };
  }
}

function saveState(state) {
  fs.mkdirSync(CLAWGUARD_DIR, { recursive: true });
  fs.writeFileSync(STATE_FILE, JSON.stringify(state, null, 2));
}

function checkSoul(state) {
  log('Checking SOUL.md integrity...');

  if (!fs.existsSync(SOUL_PATH)) {
    alert('SOUL.md is MISSING. Possible attack or accidental deletion.');
    return state;
  }

  const content = fs.readFileSync(SOUL_PATH, 'utf8');
  const currentHash = crypto.createHash('sha256').update(content).digest('hex');

  // First run: establish baseline
  if (!state.lastSoulHash) {
    log(`Baseline set: ${currentHash.substring(0, 16)}...`);
    state.lastSoulHash = currentHash;
    return state;
  }

  if (currentHash !== state.lastSoulHash) {
    alert(`SOUL.md has been MODIFIED. Hash changed from ${state.lastSoulHash.substring(0,8)}... to ${currentHash.substring(0,8)}...`);
    state.lastSoulHash = currentHash; // Update to avoid repeated alerts
  } else {
    log('SOUL.md integrity: OK');
  }

  return state;
}

function scanSkills(state) {
  log('Scanning installed skills...');

  if (!fs.existsSync(SKILLS_DIR)) {
    log('No skills directory found. Skipping.');
    return state;
  }

  const skills = fs.readdirSync(SKILLS_DIR).filter(f =>
    fs.statSync(path.join(SKILLS_DIR, f)).isDirectory()
  );

  const newSkills = skills.filter(s => !state.knownSkills.includes(s));

  if (newSkills.length === 0) {
    log(`No new skills to scan. (${skills.length} known skills)`);
    return state;
  }

  log(`New skills detected: ${newSkills.join(', ')}`);

  for (const skill of newSkills) {
    const skillPath = path.join(SKILLS_DIR, skill);
    log(`Scanning: ${skill}`);

    const result = spawnSync('node', [SCAN_SCRIPT, skillPath], {
      timeout: 30000,
      encoding: 'utf8'
    });

    const exitCode = result.status;
    if (exitCode === 2) {
      alert(`DANGEROUS skill detected: "${skill}". HIGH severity findings. Consider removing it immediately.`);
    } else if (exitCode === 1) {
      alert(`Suspicious skill detected: "${skill}". Review recommended before use.`);
    } else {
      log(`${skill}: CLEAN`);
    }

    state.knownSkills.push(skill);
  }

  state.lastScan = new Date().toISOString();
  return state;
}

// Main
const args = process.argv.slice(2);
const runSoul = args.includes('--soul') || args.includes('--all');
const runScan = args.includes('--scan') || args.includes('--all');

if (!runSoul && !runScan) {
  console.log('Usage: node background-monitor.js [--soul] [--scan] [--all]');
  process.exit(1);
}

log('=== ClawGuard Background Monitor ===');
let state = loadState();

if (runSoul) state = checkSoul(state);
if (runScan) state = scanSkills(state);

saveState(state);
log('=== Monitor complete ===');
