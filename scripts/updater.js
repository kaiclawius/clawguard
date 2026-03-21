#!/usr/bin/env node
/**
 * ClawGuard — Threat Database Updater
 * Free tier: uses bundled threats.json
 * Pro tier:  fetches from clawguard-threats repo and saves to ~/.clawguard/threats-pro.json
 */

const fs = require('fs');
const path = require('path');
const https = require('https');
const os = require('os');

const { readAndValidateLicense } = require('./license');

const CLAWGUARD_DIR = path.join(os.homedir(), '.clawguard');
const PRO_THREATS_FILE = path.join(CLAWGUARD_DIR, 'threats-pro.json');
const BUNDLED_THREATS = path.join(__dirname, '..', 'threats.json');
const PRO_URL = 'https://raw.githubusercontent.com/kaiclawius/clawguard-threats/main/threats-pro.json';

function ensureDir(dir) {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
}

function fetchJson(url) {
  return new Promise((resolve, reject) => {
    https.get(url, (res) => {
      if (res.statusCode !== 200) {
        reject(new Error(`HTTP ${res.statusCode}`));
        res.resume();
        return;
      }
      let data = '';
      res.on('data', chunk => { data += chunk; });
      res.on('end', () => {
        try { resolve(JSON.parse(data)); }
        catch (e) { reject(new Error('Invalid JSON response')); }
      });
    }).on('error', reject);
  });
}

async function main() {
  const license = readAndValidateLicense();

  console.log('');
  console.log('ClawGuard Threat Database Updater');
  console.log('───────────────────────────────────');

  if (license.valid) {
    console.log(`  License: PRO  (${license.maskedKey})`);
    console.log(`  Source:  Remote (clawguard-threats)`);
  } else {
    console.log(`  License: FREE TIER`);
    console.log(`  Source:  Bundled threats.json`);
  }

  console.log('');

  if (!license.valid) {
    // Free tier — just report bundled DB status
    try {
      const bundled = JSON.parse(fs.readFileSync(BUNDLED_THREATS, 'utf8'));
      const count = bundled.patterns ? bundled.patterns.length : '?';
      console.log(`✅ Free tier threat database is up to date.`);
      console.log(`   Version:  ${bundled.version || 'unknown'}`);
      console.log(`   Patterns: ${count}`);
      console.log(`   Updated:  ${bundled.updatedAt || 'unknown'}`);
      console.log('');
      console.log('   Upgrade to Pro for 150+ patterns with monthly updates.');
    } catch (e) {
      console.error('❌ Could not read bundled threats.json:', e.message);
      process.exit(1);
    }
    return;
  }

  // Pro tier — fetch from remote
  console.log(`Fetching pro threat database...`);
  try {
    const data = await fetchJson(PRO_URL);
    ensureDir(CLAWGUARD_DIR);
    fs.writeFileSync(PRO_THREATS_FILE, JSON.stringify(data, null, 2), 'utf8');

    const count = data.patterns ? data.patterns.length : '?';
    console.log(`✅ Pro threat database updated successfully.`);
    console.log(`   Version:  ${data.version || 'unknown'}`);
    console.log(`   Patterns: ${count}`);
    console.log(`   Updated:  ${data.updatedAt || 'unknown'}`);
    console.log(`   Saved to: ${PRO_THREATS_FILE}`);
  } catch (e) {
    console.error(`❌ Failed to fetch pro threats: ${e.message}`);
    console.log('   Falling back to bundled free tier threats.');
    process.exit(1);
  }

  console.log('');
}

main();
