#!/usr/bin/env node
/**
 * ClawGuard — SOUL.md Integrity Guardian
 * Hashes your SOUL.md and detects unauthorized changes.
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const os = require('os');

const WORKSPACE = process.env.OPENCLAW_WORKSPACE || path.join(os.homedir(), '.openclaw', 'workspace');
const SOUL_PATH = path.join(WORKSPACE, 'SOUL.md');
const HASH_PATH = path.join(WORKSPACE, '.clawguard', 'soul.hash');

function hashFile(filePath) {
  const content = fs.readFileSync(filePath, 'utf8');
  return crypto.createHash('sha256').update(content).digest('hex');
}

function ensureDir(p) {
  if (!fs.existsSync(p)) fs.mkdirSync(p, { recursive: true });
}

function init() {
  if (!fs.existsSync(SOUL_PATH)) {
    console.error('❌ SOUL.md not found at:', SOUL_PATH);
    process.exit(1);
  }

  ensureDir(path.dirname(HASH_PATH));
  const hash = hashFile(SOUL_PATH);
  const record = {
    hash,
    timestamp: new Date().toISOString(),
    path: SOUL_PATH
  };
  fs.writeFileSync(HASH_PATH, JSON.stringify(record, null, 2));
  console.log('✅ ClawGuard initialized. SOUL.md fingerprint stored.');
  console.log('   Hash:', hash);
  console.log('   Time:', record.timestamp);
}

function check() {
  if (!fs.existsSync(SOUL_PATH)) {
    console.error('🚨 CRITICAL: SOUL.md is MISSING. This is a serious security incident.');
    process.exit(2);
  }

  if (!fs.existsSync(HASH_PATH)) {
    console.warn('⚠️  No baseline hash found. Run: node guard-soul.js init');
    console.warn('   Cannot verify integrity without a baseline.');
    process.exit(1);
  }

  const record = JSON.parse(fs.readFileSync(HASH_PATH, 'utf8'));
  const currentHash = hashFile(SOUL_PATH);

  if (currentHash === record.hash) {
    console.log('✅ SOUL.md integrity verified. No changes detected.');
    console.log('   Hash:', currentHash);
    console.log('   Baseline set:', record.timestamp);
  } else {
    console.error('🚨 SECURITY ALERT: SOUL.md has been MODIFIED!');
    console.error('   Expected hash:', record.hash);
    console.error('   Current hash: ', currentHash);
    console.error('   Baseline set:', record.timestamp);
    console.error('');
    console.error('   Action required: Review changes to SOUL.md immediately.');
    console.error('   If you did not make this change, treat it as a security breach.');
    process.exit(3);
  }
}

const command = process.argv[2];
if (command === 'init') {
  init();
} else if (command === 'check') {
  check();
} else {
  console.log('Usage: node guard-soul.js <init|check>');
  console.log('  init  — Store current SOUL.md fingerprint as baseline');
  console.log('  check — Verify SOUL.md against stored baseline');
  process.exit(1);
}
