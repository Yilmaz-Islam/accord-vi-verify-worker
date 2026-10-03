// End-to-end check of tickets, receipts and payment confirmation against a
// locally running worker (DEV_MODE=1, so emails land in /dev/outbox).
//   npx wrangler dev --config wrangler.local.jsonc --port 8787
//   node test-tickets.mjs

const BASE = process.env.BASE || 'http://127.0.0.1:8787';
// The local admin password comes from the git-ignored .dev.vars file (or the ADMIN_PW env var).
import fs from 'node:fs';
const devVars = fs.existsSync('.dev.vars') ? fs.readFileSync('.dev.vars', 'utf8') : '';
const ADMIN_PW = process.env.ADMIN_PW || (devVars.match(/^ADMIN_PASSWORD=(.*)$/m) || [])[1] || '';
const stamp = Date.now();
// A fresh fake client IP per run, so repeated local runs do not trip the per-IP rate limits.
const TEST_IP = `10.${(stamp>>8)&255}.${(stamp>>4)&255}.${stamp&255}`;
// A real 1x1 PNG, so the receipt passes the image check.
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

async function newUser(prefix, name, password) {
  const email = `${prefix}+${stamp}@example.com`;
  let r = await call('/account/signup/request', { name, email, password });
  r = await call('/account/signup/verify', { email, code: r.data.devCode });
  return { email, token: r.data.token };
}

console.log('submitting a ticket');
const buyer = await newUser('buyer', 'Ticket Buyer', 'blue-pelican-window');

let r = await call('/account/ticket/submit', { persona: 'student', pass: 'both', payMethod: 'jazzcash', receipt: RECEIPT });
check('submitting without signing in is 401', r.status === 401, r.status);
r = await call('/account/ticket/submit', { persona: 'student', pass: 'both', payMethod: 'jazzcash' }, buyer.token);
check('a JazzCash or bank ticket needs a receipt', r.status === 400 && /receipt/i.test(r.data.error || ''), r.data);
r = await call('/account/ticket/submit', { persona: 'student', pass: 'both', payMethod: 'jazzcash', receipt: 'data:text/html;base64,PGI+' }, buyer.token);
check('a non-image receipt is rejected', r.status === 400, r.data);
r = await call('/account/ticket/submit', { persona: 'student', pass: 'free', payMethod: 'cash' }, buyer.token);
check('an unknown pass is rejected', r.status === 400, r.data);
r = await call('/account/ticket/submit', { persona: 'student', pass: 'both', payMethod: 'jazzcash', receipt: 'data:image/png;base64,' + 'A'.repeat(710000) }, buyer.token);
check('an oversized receipt is rejected', r.status === 400, r.data);
r = await call('/account/ticket/submit', { persona: 'group', pass: 'concert', attendeeCount: 0, payMethod: 'cash' }, buyer.token);
check('a group of 0 is rejected', r.status === 400, r.data);

r = await call(
  '/account/ticket/submit',
  { persona: 'group', pass: 'concert', attendeeCount: 4, groupNames: 'A\nB\nC\nD', payMethod: 'bank', receipt: RECEIPT, amountPkr: 1 },
  buyer.token
);
check(
  'a group of 4 for the concert is priced Rs 10,000 by the server (the price sent by the browser is ignored)',
  r.status === 200 && r.data.ticket.amountPkr === 10000 && r.data.ticket.status === 'pending',
  r.data
);
r = await call('/account/ticket/submit', { persona: 'student', pass: 'both', payMethod: 'jazzcash', receipt: RECEIPT }, buyer.token);
check('resubmitting replaces the pending ticket (two-night pass is Rs 3,500)', r.status === 200 && r.data.ticket.amountPkr === 3500, r.data);
r = await call('/account/me', {}, buyer.token);
check(
  '/me shows a pending ticket with a receipt flag and no image data',
  r.data.ticket?.status === 'pending' && r.data.ticket.hasReceipt === true && !('receipt' in r.data.ticket),
  r.data
);

let o = await call('/dev/outbox', {});
const pendingMail = o.data.outbox.filter((m) => m.kind === 'user' && m.to === buyer.email && /pending verification/i.test(m.subject));
check('the pending-payment email was sent to the buyer', pendingMail.length >= 1 && /Rs 3,500/.test(pendingMail.at(-1).message), pendingMail.at(-1));
check('the organisers were notified of the new ticket', o.data.outbox.some((m) => m.kind === 'organiser' && m.email === buyer.email));

const lastPending = pendingMail.at(-1) || {};
check(
  'the pending email has a rich HTML version with buttons back to the site',
  /View my registration/.test(lastPending.html || '') && /href="https:\/\/[^"]*\/account\.html"/.test(lastPending.html || '') && /Event info/.test(lastPending.html || ''),
  (lastPending.html || '').slice(0, 200)
);

console.log('email safety');
const evil = await newUser('evil', 'Eve <script>alert(1)</script> & "co"', 'orange-falcon-meadow');
await call('/account/ticket/submit', { persona: 'guest', pass: 'concert', payMethod: 'cash' }, evil.token);
o = await call('/dev/outbox', {});
const evilMail = o.data.outbox.filter((m) => m.kind === 'user' && m.to === evil.email && /pending verification/i.test(m.subject)).at(-1) || {};
check(
  'a hostile name is escaped in the HTML email (no live <script> tag)',
  !!evilMail.html && !/<script/i.test(evilMail.html) && /&lt;script&gt;/.test(evilMail.html),
  (evilMail.html || '').slice(0, 300)
);

console.log('admin review');
r = await call('/admin/tickets', {});
check('the ticket list needs the admin token', r.status === 401, r.status);
r = await call('/admin/tickets', {}, buyer.token);
check('a normal user token cannot read the ticket list', r.status === 401, r.status);
r = await call('/admin/login', { password: ADMIN_PW });
const adminToken = r.data.token;
check('admin can sign in', !!adminToken, r.data);
r = await call('/admin/tickets', {}, adminToken);
const mine = (r.data.tickets || []).find((t) => t.email === buyer.email);
check(
  'admin sees name, email, pass, amount and status, but not the image inline',
  !!mine && mine.name === 'Ticket Buyer' && mine.pass === 'both' && mine.amountPkr === 3500 && mine.status === 'pending' && mine.hasReceipt === true && !('receipt' in mine),
  mine
);
r = await call('/admin/ticket-receipt', { id: mine.id }, adminToken);
check('admin can open the receipt image', r.status === 200 && r.data.receipt === RECEIPT, r.status);
r = await call('/admin/ticket-receipt', { id: mine.id });
check('the receipt needs the admin token', r.status === 401, r.status);

console.log('payment confirmation');
r = await call('/admin/ticket-confirm', { id: mine.id });
check('confirming needs the admin token', r.status === 401, r.status);
r = await call('/admin/ticket-confirm', { id: mine.id }, adminToken);
check('admin can confirm the payment', r.status === 200 && r.data.emailSent === true, r.data);
const [again1, again2] = await Promise.all([
  call('/admin/ticket-confirm', { id: mine.id }, adminToken),
  call('/admin/ticket-confirm', { id: mine.id }, adminToken),
]);
check('confirming again is harmless', again1.data.alreadyConfirmed && again2.data.alreadyConfirmed, [again1.data, again2.data]);
o = await call('/dev/outbox', {});
const confirmMail = o.data.outbox.filter((m) => m.kind === 'user' && m.to === buyer.email && /payment is confirmed/i.test(m.subject));
check('exactly one confirmation email was sent, despite repeated clicks', confirmMail.length === 1, confirmMail.length);
r = await call('/account/me', {}, buyer.token);
check('the buyer now sees a confirmed ticket', r.data.ticket?.status === 'confirmed' && !!r.data.ticket.confirmedAt, r.data);
r = await call('/account/ticket/submit', { persona: 'student', pass: 'concert', payMethod: 'cash' }, buyer.token);
check('a confirmed ticket cannot be overwritten', r.status === 409, r.data);
r = await call('/account/delete', { password: 'blue-pelican-window' }, buyer.token);
check('an account with a confirmed payment cannot be deleted online', r.status === 409, r.data);

console.log('cash and sponsor paths');
const cash = await newUser('cash', 'Cash Payer', 'green-walrus-ladder');
r = await call('/account/ticket/submit', { persona: 'guest', pass: 'concert', payMethod: 'cash' }, cash.token);
check('a cash ticket needs no receipt and is priced Rs 2,500', r.status === 200 && r.data.ticket.amountPkr === 2500 && r.data.ticket.hasReceipt === false, r.data);
const sponsor = await newUser('sponsor', 'Spons Or', 'red-heron-bicycle');
r = await call('/account/ticket/submit', { persona: 'sponsor', sponsorTier: 'Gold' }, sponsor.token);
check('a sponsor registers interest with no payment (Rs 0, status interest)', r.status === 200 && r.data.ticket.amountPkr === 0 && r.data.ticket.status === 'interest', r.data);
r = await call('/admin/tickets', {}, adminToken);
const sp = r.data.tickets.find((t) => t.email === sponsor.email);
r = await call('/admin/ticket-confirm', { id: sp.id }, adminToken);
check('sponsor interest cannot be payment-confirmed', r.status === 400, r.data);

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
