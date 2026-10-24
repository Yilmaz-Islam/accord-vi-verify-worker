// The organisers' morning summary and the instant sponsor notice, against a
// locally running worker started with the cron test hook:
//   node node_modules/wrangler/bin/wrangler.js dev --config wrangler.local.jsonc --port 8787 --test-scheduled
//   node test-summary.mjs

const BASE = process.env.BASE || 'http://127.0.0.1:8787';
const stamp = Date.now();
const TEST_IP = `10.${(stamp>>8)&255}.${(stamp>>4)&255}.${stamp&255}`;
const RECEIPT =
  'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==';

let passed = 0;
let failed = 0;
const check = (label, cond, extra) => {
  if (cond) {
    passed += 1;
    console.log(`  ok   ${label}`);
  } else {
    failed += 1;
    console.log(`  FAIL ${label}${extra !== undefined ? '  ->  ' + JSON.stringify(extra) : ''}`);
  }
};

async function call(path, body, token) {
  const res = await fetch(BASE + path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'CF-Connecting-IP': TEST_IP, ...(token ? { Authorization: `Bearer ${token}` } : {}) },
    body: JSON.stringify(body || {}),
  });
  let data = {};
  try {
    data = await res.json();
  } catch {}
  return { status: res.status, data };
}

async function newUser(prefix, name) {
  const email = `${prefix}+${stamp}@example.com`;
  let r = await call('/account/signup/request', { name, email, password: 'amber-lighthouse-route', acceptTerms: true });
  r = await call('/account/signup/verify', { email, code: r.data.devCode });
  return { email, token: r.data.token };
}
const outbox = async () => (await call('/dev/outbox', {})).data.outbox || [];

console.log('sponsors still reach the organisers straight away');
const sponsor = await newUser('sumsponsor', 'Summary Sponsor');
await call('/account/ticket/submit', { persona: 'sponsor', sponsorTier: 'Gold' }, sponsor.token);
let o = await outbox();
check('a sponsor sends an instant organiser notice', o.some((m) => m.kind === 'organiser' && m.email === sponsor.email));

console.log('tickets wait for the morning summary');
const buyer = await newUser('sumbuyer', 'Summary Buyer');
let r = await call('/account/ticket/submit', { persona: 'student', pass: 'both', payMethod: 'jazzcash', receipt: RECEIPT }, buyer.token);
check('the ticket was saved', r.status === 200, r.data);
o = await outbox();
check('no instant organiser notice for a ticket', !o.some((m) => m.kind === 'organiser' && m.email === buyer.email));

const cron = await fetch(`${BASE}/__scheduled?cron=${encodeURIComponent('0 4 * * *')}`);
check('the cron hook ran', cron.ok, cron.status);
await new Promise((res) => setTimeout(res, 500));
o = await outbox();
const summary = o.filter((m) => m.kind === 'summary').at(-1);
check('a summary email was written', !!summary, o.slice(-3));
check('the summary lists the new ticket with its price and receipt', !!summary && summary.message.includes(`Summary Buyer (${buyer.email})`) && /Rs 3,500/.test(summary.message) && /receipt attached/.test(summary.message), summary?.message);
check('the summary leaves out sponsors', !!summary && !summary.message.includes(sponsor.email), summary?.message);
check('the summary says how many are waiting', !!summary && /Waiting for a payment check: [1-9]/.test(summary.message) && /^Daily summary: \d+ new, \d+ waiting$/.test(summary.form_type), summary);
check('the summary links to the admin panel', !!summary && /\/admin\.html/.test(summary.message));

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
