// End-to-end check of attendee tickets, the gate scanner and the receipt history
// against a locally running worker (DEV_MODE=1).
//   npx wrangler dev --config wrangler.local.jsonc --port 8787
//   node test-gate.mjs
import fs from 'node:fs';

const BASE = process.env.BASE || 'http://127.0.0.1:8787';
const devVars = fs.existsSync('.dev.vars') ? fs.readFileSync('.dev.vars', 'utf8') : '';
const fromDev = (k) => (devVars.match(new RegExp(`^${k}=(.*)$`, 'm')) || [])[1] || '';
const ADMIN_PW = process.env.ADMIN_PW || fromDev('ADMIN_PASSWORD');
const GATE_PW = process.env.GATE_PW || fromDev('GATE_PASSWORD');
const stamp = Date.now();
// Names are unique per run, so leftovers from earlier runs in the same local database cannot interfere.
const TAG = String(stamp).slice(-6);
const ALI = `Ali Raza ${TAG}`;
const SANA = `Sana Tariq ${TAG}`;
const TEST_IP = `10.${(stamp >> 8) & 255}.${(stamp >> 4) & 255}.${(stamp & 255) ^ 77}`;
const RECEIPT_A = 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==';
const RECEIPT_B = 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==';

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
  let r = await call('/account/signup/request', { name, email, password, acceptTerms: true });
  r = await call('/account/signup/verify', { email, code: r.data.devCode });
  return { email, name, token: r.data.token };
}

const adminToken = (await call('/admin/login', { password: ADMIN_PW })).data.token;
check('admin can sign in', !!adminToken);

async function confirmFor(email) {
  const list = (await call('/admin/tickets', {}, adminToken)).data.tickets;
  const t = list.find((x) => x.email === email);
  const r = await call('/admin/ticket-confirm', { id: t.id }, adminToken);
  return { id: t.id, res: r };
}

console.log('single ticket');
const solo = await newUser('solo', 'Solo Student', 'amber-fox-garden');
let r = await call('/account/tickets', {}, solo.token);
check('no tickets exist before the payment is confirmed', r.status === 200 && r.data.tickets.length === 0, r.data);
await call('/account/ticket/submit', { persona: 'student', pass: 'both', payMethod: 'jazzcash', receipt: RECEIPT_A }, solo.token);
r = await confirmFor(solo.email);
check('confirming creates 1 ticket', r.res.status === 200 && r.res.data.tickets === 1, r.res.data);
r = await call('/account/tickets', {}, solo.token);
const soloTicket = r.data.tickets[0];
check('the buyer sees their own ticket, named after them, with a signed code', r.data.tickets.length === 1 && soloTicket.holderName === 'Solo Student' && /^A6\.[A-Za-z0-9_-]{16}\.[A-Za-z0-9_-]{22}$/.test(soloTicket.code) && soloTicket.used === false, r.data);
r = await call('/account/tickets', {});
check('tickets need a signed-in account', r.status === 401, r.status);

console.log('group tickets');
const lead = await newUser('lead', 'Group Leader', 'violet-moose-harbor');
await call('/account/ticket/submit', { persona: 'group', pass: 'concert', attendeeCount: 3, groupNames: `${ALI}\n${SANA}`, payMethod: 'bank', receipt: RECEIPT_A }, lead.token);
await confirmFor(lead.email);
r = await call('/account/tickets', {}, lead.token);
const names = r.data.tickets.map((t) => t.holderName);
check('a group of 3 gets 3 separate tickets', r.data.tickets.length === 3, names);
check('named from the typed list, then "Guest 3"', names[0] === ALI && names[1] === SANA && /^Guest 3/.test(names[2]), names);
check('every ticket has a different code', new Set(r.data.tickets.map((t) => t.code)).size === 3);
const groupTickets = r.data.tickets;

console.log('confirmation email carries the tickets');
let o = await call('/dev/outbox', {});
const mail = o.data.outbox.filter((m) => m.kind === 'user' && m.to === lead.email && /payment is confirmed/i.test(m.subject)).at(-1) || {};
check('the plain text lists a ticket link per person', (mail.message || '').split('ticket.html#A6.').length - 1 === 3, (mail.message || '').slice(0, 400));
check('the HTML has a button per person', (mail.html || '').includes(`Ticket 1: ${ALI}`) && (mail.html || '').includes(`Ticket 2: ${SANA}`) && /ticket\.html#A6\./.test(mail.html || ''));

console.log('public ticket page');
r = await call('/ticket/info', { code: groupTickets[1].code });
check('a genuine code shows the holder and pass', r.status === 200 && r.data.ticket.holderName === SANA && r.data.ticket.seq === 2 && r.data.ticket.of === 3 && r.data.ticket.used === false, r.data);
const tampered = groupTickets[1].code.slice(0, -1) + (groupTickets[1].code.endsWith('A') ? 'B' : 'A');
r = await call('/ticket/info', { code: tampered });
check('a code with one character changed is refused', r.status === 404, r.status);
r = await call('/ticket/info', { code: 'A6.' + 'x'.repeat(16) + '.' + 'y'.repeat(22) });
check('an invented code is refused', r.status === 404, r.status);
const swapped = groupTickets[0].code.split('.').slice(0, 2).join('.') + '.' + groupTickets[1].code.split('.')[2];
r = await call('/ticket/info', { code: swapped });
check("one ticket's id with another ticket's signature is refused", r.status === 404, r.status);

console.log('gate access');
r = await call('/gate/lookup', { code: groupTickets[0].code });
check('scanning without signing in is refused', r.status === 401, r.status);
r = await call('/gate/login', { password: 'wrong-gate-password' });
check('a wrong gate password is refused', r.status === 401, r.status);
r = await call('/gate/login', { password: GATE_PW });
const gateToken = r.data.token;
check('the gate password signs the gate in', r.status === 200 && !!gateToken, r.data);
r = await call('/admin/tickets', {}, gateToken);
check('a gate token cannot read registrations or receipts', r.status === 401, r.status);
r = await call('/admin/ticket-confirm', { id: 1 }, gateToken);
check('a gate token cannot confirm payments', r.status === 401, r.status);
r = await call('/gate/lookup', { code: groupTickets[0].code }, adminToken);
check('an admin token can also use the gate', r.status === 200 && r.data.valid === true, r.data);

console.log('scanning and admitting');
r = await call('/gate/lookup', { code: groupTickets[0].code }, gateToken);
check('lookup shows holder, "1 of 3", pass and purchaser, and does not admit yet', r.data.valid && r.data.ticket.holderName === ALI && r.data.ticket.seq === 1 && r.data.ticket.of === 3 && r.data.ticket.purchaser === 'Group Leader' && r.data.ticket.admittedAt === null, r.data);
r = await call('/gate/lookup', { code: groupTickets[0].code }, gateToken);
check('looking again changes nothing', r.data.ticket.admittedAt === null);
r = await call('/gate/lookup', { code: 'A6.' + 'q'.repeat(16) + '.' + 'z'.repeat(22) }, gateToken);
check('a forged code shows as not genuine', r.status === 200 && r.data.valid === false && r.data.reason === 'not-genuine', r.data);
r = await call('/gate/lookup', { code: 'hello' }, gateToken);
check('nonsense shows as not genuine', r.data.valid === false, r.data);

console.log('identity details on a scan');
r = await call('/gate/lookup', { code: groupTickets[0].code }, gateToken);
const idt = r.data.ticket;
check('a scan carries a short reference, the type of registration and how it was paid', /^[A-Z0-9]{4}-[A-Z0-9]{4}$/.test(idt.ref) && idt.persona === 'group' && ['jazzcash', 'bank', 'cash'].includes(idt.payMethod), idt);
check('a scan carries when the payment was confirmed', !!idt.confirmedAt && !Number.isNaN(Date.parse(idt.confirmedAt)), idt.confirmedAt);
check("the buyer's email is masked, never in full", /^[^@]+@[^@]+$/.test(idt.purchaserEmail) && idt.purchaserEmail.includes('•') && idt.purchaserEmail[0] === lead.email[0] && idt.purchaserEmail !== lead.email && idt.purchaserEmail.split('@')[1] === lead.email.split('@')[1], idt.purchaserEmail);
check('a group scan lists the whole party and marks which one this is', Array.isArray(idt.party) && idt.party.length === 3 && idt.party.filter((p) => p.you).length === 1 && idt.party.find((p) => p.you).seq === 1 && idt.party[0].holderName === ALI, idt.party);
check('the party shows who is already in', idt.party.every((p) => p.admittedAt === null));
r = await call('/gate/lookup', { id: idt.id }, gateToken);
check('a ticket can also be looked up by id (what a name-search tap does)', r.data.valid === true && r.data.ticket.holderName === ALI && r.data.ticket.party.length === 3, r.data);
r = await call('/gate/lookup', { id: 'nope' + 'x'.repeat(12) }, gateToken);
check('an unknown id shows as not found, not as an error', r.status === 200 && r.data.valid === false, r.data);
r = await call('/gate/lookup', { id: idt.id });
check('looking up by id still needs the gate or admin token', r.status === 401, r.status);

r = await call('/gate/admit', { code: groupTickets[0].code }, gateToken);
check('the first admit lets the person in', r.status === 200 && r.data.admitted === true && !!r.data.ticket.admittedAt, r.data);
const [again1, again2] = await Promise.all([
  call('/gate/admit', { code: groupTickets[0].code }, gateToken),
  call('/gate/admit', { code: groupTickets[0].code }, adminToken),
]);
check('admitting the same ticket again is refused (a copied ticket fails)', again1.data.admitted === false && again2.data.admitted === false, [again1.data.admitted, again2.data.admitted]);
r = await call('/gate/lookup', { code: groupTickets[0].code }, gateToken);
check('a used ticket shows when it was used', !!r.data.ticket.admittedAt);
r = await call('/ticket/info', { code: groupTickets[0].code });
check('the public ticket page now says used', r.data.ticket.used === true, r.data);
check('the public ticket page shows the short reference but no email', /^[A-Z0-9]{4}-[A-Z0-9]{4}$/.test(r.data.ticket.ref) && r.data.ticket.ref === idt.ref && !JSON.stringify(r.data).includes('@'), r.data);
r = await call('/gate/lookup', { code: groupTickets[0].code }, gateToken);
check('after the admit the party shows that one as in and the others not', r.data.ticket.party.find((p) => p.seq === 1).admittedAt && !r.data.ticket.party.find((p) => p.seq === 2).admittedAt, r.data.ticket.party);
const listNow = (await call('/admin/tickets', {}, adminToken)).data.tickets;
const leadRow = listNow.find((t) => t.email === lead.email);
check('the admin list counts how many of a registration are in', leadRow.admittedCount === 1 && leadRow.attendeeCount === 3, leadRow);
r = await call('/account/tickets', {}, lead.token);
check("the buyer's list shows which tickets are used", r.data.tickets[0].used === true && r.data.tickets[1].used === false, r.data.tickets.map((t) => t.used));

console.log('name search at the gate');
r = await call('/gate/search', { q: SANA.toLowerCase() }, gateToken);
const sana = (r.data.matches || []).find((m) => m.holderName === SANA);
check('searching a name finds the ticket (case-insensitive)', !!sana && sana.of === 3 && sana.admittedAt === null, r.data);
check('search results do not include codes or emails', !JSON.stringify(r.data).includes('A6.') && !JSON.stringify(r.data).includes('@'));
r = await call('/gate/search', { q: 'a' }, gateToken);
check('a one-letter search returns nothing', r.data.matches.length === 0, r.data);
r = await call('/gate/search', { q: '%' }, gateToken);
check('wildcard characters are not treated as wildcards', r.status === 200 && r.data.matches.length === 0, r.data);
r = await call('/gate/search', { q: SANA.toLowerCase() });
check('searching needs the gate or admin token', r.status === 401, r.status);
r = await call('/gate/admit', { id: sana.id }, gateToken);
check('admitting from a search result works', r.data.admitted === true && r.data.ticket.holderName === SANA, r.data);

console.log('receipt history (one registration per account, nothing lost)');
const redo = await newUser('redo', 'Receipt Redo', 'silver-lynx-valley');
await call('/account/ticket/submit', { persona: 'student', pass: 'concert', payMethod: 'jazzcash', receipt: RECEIPT_A }, redo.token);
await call('/account/ticket/submit', { persona: 'student', pass: 'both', payMethod: 'bank', receipt: RECEIPT_B }, redo.token);
let list = (await call('/admin/tickets', {}, adminToken)).data.tickets;
const redoRows = list.filter((t) => t.email === redo.email);
check('still exactly one ticket for the account', redoRows.length === 1, redoRows.length);
check('the current ticket shows the latest choice and 1 earlier receipt', redoRows[0].pass === 'both' && redoRows[0].payMethod === 'bank' && redoRows[0].receiptCount === 1, redoRows[0]);
r = await call('/admin/ticket-history', { id: redoRows[0].id }, adminToken);
check('the replaced receipt is kept in history with its details', r.status === 200 && r.data.history.length === 1 && r.data.history[0].receipt === RECEIPT_A && r.data.history[0].payMethod === 'jazzcash' && r.data.history[0].amountPkr === 2500, r.data);
r = await call('/admin/ticket-receipt', { id: redoRows[0].id }, adminToken);
check('the live receipt is the newest one', r.data.receipt === RECEIPT_B);
r = await call('/admin/ticket-history', { id: redoRows[0].id });
check('history needs the admin token', r.status === 401, r.status);
await call('/account/ticket/submit', { persona: 'student', pass: 'both', payMethod: 'cash' }, redo.token);
r = await call('/admin/ticket-history', { id: redoRows[0].id }, adminToken);
check('switching to cash still archives the earlier receipt', r.data.history.length === 2, r.data.history.length);

console.log('deleting a pending account erases the history too');
r = await call('/account/delete', { password: 'silver-lynx-valley' }, redo.token);
check('the pending account can be deleted', r.status === 200, r.data);
list = (await call('/admin/tickets', {}, adminToken)).data.tickets;
check('its ticket is gone from the admin list', !list.some((t) => t.email === redo.email));
r = await call('/admin/ticket-history', { id: redoRows[0].id }, adminToken);
check('and its receipt history is gone', r.status === 200 && r.data.history.length === 0, r.data.history.length);

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
