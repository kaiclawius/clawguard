#!/usr/bin/env node
/**
 * ClawGuard — License Validation
 * Validates license keys offline using XOR checksum.
 * Format: CG-XXXX-XXXX-XXXX-XXXX (uppercase alphanumeric)
 * Last segment must equal XOR checksum of first 3 segments.
 */

const fs = require('fs');
const path = require('path');
const os = require('os');

const LICENSE_FILE = path.join(os.homedir(), '.clawguard', 'license.key');
const KEY_REGEX = /^CG-([A-Z0-9]{4})-([A-Z0-9]{4})-([A-Z0-9]{4})-([A-Z0-9]{4})$/;

/**
 * XOR checksum: converts each segment to a sum of char codes, XORs all three,
 * then maps back to a 4-char alphanumeric string (base-36, zero-padded).
 */
function segmentChecksum(seg) {
  return seg.split('').reduce((acc, c) => acc + c.charCodeAt(0), 0);
}

function computeChecksum(s1, s2, s3) {
  const xor = segmentChecksum(s1) ^ segmentChecksum(s2) ^ segmentChecksum(s3);
  // Encode as 4 uppercase alphanumeric chars (base-36, zero-padded)
  return xor.toString(36).toUpperCase().padStart(4, '0').slice(-4);
}

function maskKey(key) {
  // CG-XXXX-XXXX-XXXX-LAST4 → CG-****-****-****-LAST4
  return key.replace(/^(CG-)[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}-/, '$1****-****-****-');
}

/**
 * Validate a license key string.
 * @param {string} key
 * @returns {{ valid: boolean, tier: 'free'|'pro', key: string, maskedKey: string }}
 */
function validateLicense(key) {
  const freeResult = { valid: false, tier: 'free', key: key || '', maskedKey: key ? maskKey(key) : '' };

  if (!key) return freeResult;

  const match = key.trim().match(KEY_REGEX);
  if (!match) return freeResult;

  const [, s1, s2, s3, s4] = match;
  const expected = computeChecksum(s1, s2, s3);

  if (s4 !== expected) return freeResult;

  return {
    valid: true,
    tier: 'pro',
    key: key.trim(),
    maskedKey: maskKey(key.trim()),
  };
}

/**
 * Read license from env var or ~/.clawguard/license.key, then validate.
 * @returns {{ valid: boolean, tier: 'free'|'pro', key: string, maskedKey: string }}
 */
function readAndValidateLicense() {
  const envKey = process.env.CLAWGUARD_LICENSE;
  if (envKey) return validateLicense(envKey.trim());

  if (fs.existsSync(LICENSE_FILE)) {
    try {
      const fileKey = fs.readFileSync(LICENSE_FILE, 'utf8').trim();
      if (fileKey) return validateLicense(fileKey);
    } catch (e) {
      // Fall through to free tier
    }
  }

  return { valid: false, tier: 'free', key: '', maskedKey: '' };
}

/**
 * Generate a valid pro license key.
 * @returns {string}
 */
function generateLicenseKey() {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  function randSeg() {
    return Array.from({ length: 4 }, () => chars[Math.floor(Math.random() * chars.length)]).join('');
  }

  const s1 = randSeg();
  const s2 = randSeg();
  const s3 = randSeg();
  const s4 = computeChecksum(s1, s2, s3);

  return `CG-${s1}-${s2}-${s3}-${s4}`;
}

module.exports = { validateLicense, readAndValidateLicense, generateLicenseKey };

// CLI: node scripts/license.js
if (require.main === module) {
  const arg = process.argv[2];

  if (arg === '--generate') {
    const key = generateLicenseKey();
    console.log('Generated license key:', key);
    console.log('Verify:', validateLicense(key).valid ? 'VALID' : 'INVALID');
    process.exit(0);
  }

  const result = readAndValidateLicense();
  console.log('');
  console.log('ClawGuard License Status');
  console.log('─────────────────────────');
  if (result.valid) {
    console.log(`  Status: VALID`);
    console.log(`  Tier:   PRO`);
    console.log(`  Key:    ${result.maskedKey}`);
  } else {
    console.log(`  Status: No valid license found`);
    console.log(`  Tier:   FREE`);
    console.log(`  Key:    ${LICENSE_FILE}  (place your key here)`);
    console.log(`          or set CLAWGUARD_LICENSE env var`);
  }
  console.log('');
}
