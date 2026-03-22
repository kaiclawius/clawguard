#!/usr/bin/env node
/**
// CLAWGUARD_INTERNAL — this file is part of ClawGuard itself, not a threat
 * ClawGuard - SOUL.md Integrity Guardian
 * Hashes SOUL.md using SHA256 and detects unauthorized changes.
 *
 * Commands:
 *   init  - Store current SOUL.md fingerprint as baseline
 *   check - Verify SOUL.md against stored baseline
 */

'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const os = require('os');

const WORKSPACE = process.env.OPENCLAW_WORKSPACE || path.join(os.homedir(), '.openclaw', 'workspace');
const SOUL_PATH = path.join(WORKSPACE, 'SOUL.md');
const HASH_PATH = path.join(WORKSPACE, '.clawguard', 'soul.hash');

/**
 * Reads a file and returns its SHA256 hex digest.
 * Throws on read errors so callers can handle them explicitly.
 */
function hashFile(filePath) {
  let content;
  try {
    content = fs.readFileSync(filePath, 'utf8');
  } catch (err) {
    throw new Error(`Failed to read file for hashing: ${filePath}\n  ${err.message}`);
  }

  if (content.length === 0) {
    throw new Error(`File is empty, refusing to hash: ${filePath}`);
  }

  return crypto.createHash('sha256').update(content).digest('hex');
}

/**
 * Ensures a directory exists, creating it recursively if needed.
 */
function ensureDir(dirPath) {
  try {
    if (!fs.existsSync(dirPath)) {
      fs.mkdirSync(dirPath, { recursive: true });
    }
  } catch (err) {
    throw new Error(`Failed to create directory: ${dirPath}\n  ${err.message}`);
  }
}

/**
 * Reads and parses the stored hash record.
 * Validates that required fields are present and well-formed.
 * Returns null if file does not exist.
 * Throws on parse errors or invalid schema.
 */
function loadHashRecord(hashPath) {
  if (!fs.existsSync(hashPath)) {
    return null;
  }

  let raw;
  try {
    raw = fs.readFileSync(hashPath, 'utf8');
  } catch (err) {
    throw new Error(`Failed to read hash record: ${hashPath}\n  ${err.message}`);
  }

  let record;
  try {
    record = JSON.parse(raw);
  } catch (err) {
    throw new Error(`Hash record is corrupted (invalid JSON): ${hashPath}\n  ${err.message}`);
  }

  // Validate schema
  if (typeof record.hash !== 'string' || !/^[a-f0-9]{64}$/.test(record.hash)) {
    throw new Error(`Hash record has invalid or missing 'hash' field: ${hashPath}`);
  }
  if (typeof record.timestamp !== 'string' || isNaN(Date.parse(record.timestamp))) {
    throw new Error(`Hash record has invalid or missing 'timestamp' field: ${hashPath}`);
  }
  if (typeof record.path !== 'string') {
    throw new Error(`Hash record has invalid or missing 'path' field: ${hashPath}`);
  }

  return record;
}

/**
 * Writes a hash record atomically by writing to a temp file first,
 * then renaming it into place to avoid partial writes.
 */
function writeHashRecord(hashPath, record) {
  const tmp = hashPath + '.tmp';
  const data = JSON.stringify(record, null, 2);

  try {
    fs.writeFileSync(tmp, data, { encoding: 'utf8', flag: 'w' });
    fs.renameSync(tmp, hashPath);
  } catch (err) {
    // Clean up temp file if it was created
    try { fs.unlinkSync(tmp); } catch (_) {}
    throw new Error(`Failed to write hash record: ${hashPath}\n  ${err.message}`);
  }
}

/**
 * init command: compute current SOUL.md hash and store as baseline.
 */
function init() {
  if (!fs.existsSync(SOUL_PATH)) {
    console.error('[CLAWGUARD] ERROR: SOUL.md not found at:', SOUL_PATH);
    process.exit(1);
  }

  try {
    ensureDir(path.dirname(HASH_PATH));
  } catch (err) {
    console.error('[CLAWGUARD]', err.message);
    process.exit(1);
  }

  let hash;
  try {
    hash = hashFile(SOUL_PATH);
  } catch (err) {
    console.error('[CLAWGUARD]', err.message);
    process.exit(1);
  }

  const record = {
    hash,
    timestamp: new Date().toISOString(),
    path: SOUL_PATH,
  };

  try {
    writeHashRecord(HASH_PATH, record);
  } catch (err) {
    console.error('[CLAWGUARD]', err.message);
    process.exit(1);
  }

  console.log('[CLAWGUARD] Initialized. SOUL.md fingerprint stored.');
  console.log('  Hash     :', hash);
  console.log('  Timestamp:', record.timestamp);
  console.log('  Target   :', SOUL_PATH);
}

/**
 * check command: verify current SOUL.md hash against stored baseline.
 * Exit codes:
 *   0 - Integrity verified, no changes
 *   1 - Operational error (missing baseline, corrupted record)
 *   2 - SOUL.md file is missing (critical)
 *   3 - SOUL.md has been modified (security alert)
 */
function check() {
  // Missing SOUL.md is the most severe case
  if (!fs.existsSync(SOUL_PATH)) {
    console.error('[CLAWGUARD] CRITICAL: SOUL.md is MISSING.');
    console.error('  Path:', SOUL_PATH);
    console.error('  This may indicate a security incident. Investigate immediately.');
    process.exit(2);
  }

  let record;
  try {
    record = loadHashRecord(HASH_PATH);
  } catch (err) {
    // Corrupted baseline is a security concern, not just a missing file
    console.error('[CLAWGUARD] ERROR: Baseline hash record is corrupted.');
    console.error(' ', err.message);
    console.error('  Cannot verify integrity. Re-initialize if the corruption is benign.');
    process.exit(1);
  }

  if (record === null) {
    console.warn('[CLAWGUARD] WARNING: No baseline hash found.');
    console.warn('  Run: node guard-soul.js init');
    console.warn('  Cannot verify integrity without a baseline.');
    process.exit(1);
  }

  let currentHash;
  try {
    currentHash = hashFile(SOUL_PATH);
  } catch (err) {
    console.error('[CLAWGUARD] ERROR: Could not hash SOUL.md during check.');
    console.error(' ', err.message);
    process.exit(1);
  }

  if (currentHash === record.hash) {
    console.log('[CLAWGUARD] OK: SOUL.md integrity verified. No changes detected.');
    console.log('  Hash     :', currentHash);
    console.log('  Baseline :', record.timestamp);
  } else {
    console.error('[CLAWGUARD] SECURITY ALERT: SOUL.md has been MODIFIED.');
    console.error('  Expected :', record.hash);
    console.error('  Current  :', currentHash);
    console.error('  Baseline :', record.timestamp);
    console.error('');
    console.error('  Action required: Review changes to SOUL.md immediately.');
    console.error('  If you did not make this change, treat it as a security breach.');
    process.exit(3);
  }
}

// Entry point
const command = process.argv[2];

if (command === 'init') {
  init();
} else if (command === 'check') {
  check();
} else {
  console.log('Usage: node guard-soul.js <init|check>');
  console.log('');
  console.log('  init   Store current SOUL.md fingerprint as baseline');
  console.log('  check  Verify SOUL.md against stored baseline');
  console.log('');
  console.log('Exit codes (check command):');
  console.log('  0  Integrity verified');
  console.log('  1  Operational error (missing/corrupted baseline)');
  console.log('  2  SOUL.md is missing');
  console.log('  3  SOUL.md has been tampered with');
  process.exit(1);
}