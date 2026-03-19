// ClawGuard Waitlist API — Vercel Serverless Function
const GITHUB_TOKEN = process.env.GITHUB_TOKEN;
const REPO = 'kaiclawius/clawguard';
const FILE_PATH = 'waitlist.json';

async function getWaitlist() {
  const res = await fetch(`https://api.github.com/repos/${REPO}/contents/${FILE_PATH}`, {
    headers: { 'Authorization': `token ${GITHUB_TOKEN}`, 'User-Agent': 'clawguard-waitlist' }
  });
  if (res.status === 404) return { entries: [], sha: null };
  const data = await res.json();
  const content = JSON.parse(Buffer.from(data.content, 'base64').toString('utf8'));
  return { entries: content.entries || [], sha: data.sha };
}

async function saveWaitlist(entries, sha) {
  const content = Buffer.from(JSON.stringify({ entries, count: entries.length, updatedAt: new Date().toISOString() }, null, 2)).toString('base64');
  const body = { message: `waitlist: +1 signup (${entries.length} total)`, content, ...(sha ? { sha } : {}) };
  const res = await fetch(`https://api.github.com/repos/${REPO}/contents/${FILE_PATH}`, {
    method: 'PUT',
    headers: { 'Authorization': `token ${GITHUB_TOKEN}`, 'Content-Type': 'application/json', 'User-Agent': 'clawguard-waitlist' },
    body: JSON.stringify(body)
  });
  return res.ok;
}

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method === 'GET') {
    const { entries } = await getWaitlist();
    return res.status(200).json({ count: entries.length });
  }
  if (req.method === 'POST') {
    const { email } = req.body || {};
    if (!email || !email.includes('@')) return res.status(400).json({ error: 'Valid email required' });
    const { entries, sha } = await getWaitlist();
    if (entries.some(e => e.email === email.toLowerCase())) {
      return res.status(200).json({ success: true, message: 'Already on the list!', count: entries.length });
    }
    entries.push({ email: email.toLowerCase(), joinedAt: new Date().toISOString() });
    await saveWaitlist(entries, sha);
    return res.status(200).json({ success: true, message: "You're on the list!", count: entries.length });
  }
  return res.status(405).json({ error: 'Method not allowed' });
}
