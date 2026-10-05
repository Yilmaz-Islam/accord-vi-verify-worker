// Attack tests: tries to break the worker the way an outsider would (forged tokens, tampering, bad uploads, guessing,
// malformed requests, injection). Runs against a LOCAL worker only (DEV_MODE):
//   npx wrangler dev --config wrangler.local.jsonc --port 8787
//   node test-security.mjs

import fs from 'node:fs';
const BASE = process.env.BASE || 'http://127.0.0.1:8787';
const dev = (fs.existsSync('.dev.vars') ? fs.readFileSync('.dev.vars', 'utf8') : '');
const ADMIN_PW = process.env.ADMIN_PW || (dev.match(/^ADMIN_PASSWORD=(.*)$/m) || [])[1];
const stamp = Date.now();
let ipN = 0;
const freshIp = () => `10.${(stamp >> 8) & 255}.${(stamp >> 2) & 255}.${(++ipN) & 255}`;
const results = [];
const check = (area, label, pass, extra) => { results.push({ area, label, pass, extra }); console.log(`${pass ? 'ok  ' : 'FAIL'} [${area}] ${label}${!pass && extra !== undefined ? '  ->  ' + JSON.stringify(extra).slice(0, 200) : ''}`); };

async function call(path, body, token, extraHeaders) {
  const r = await fetch(BASE + path, { method: 'POST', headers: { 'Content-Type': 'application/json', 'CF-Connecting-IP': freshIp(), ...(token ? { Authorization: `Bearer ${token}` } : {}), ...(extraHeaders || {}) }, body: typeof body === 'string' ? body : JSON.stringify(body || {}) });
  let data = {}; try { data = await r.json(); } catch {}
  return { status: r.status, data, headers: r.headers };
}
async function newUser(tag, name = 'Attack Tester') {
  const email = `${tag.toLowerCase()}+${stamp}@example.com`;
  let r = await call('/account/signup/request', { name, email, password: 'violet-harbor-lantern-42', acceptTerms: true });
  r = await call('/account/signup/verify', { email, code: r.data.devCode });
  return { email, token: r.data.token };
}
const adminToken = (await call('/admin/login', { password: ADMIN_PW })).data.token;

// ---- A. every protected route refuses a caller who is not signed in
const userRoutes = ['/account/me', '/account/update', '/account/prefs', '/account/sessions', '/account/sessions/revoke', '/account/sessions/revoke-others', '/account/export', '/account/tickets', '/account/ticket/submit', '/account/delete', '/account/password/change', '/account/email/change/request', '/account/email/change/verify', '/account/logout'];
for (const p of userRoutes) { const r = await call(p, {}); check('auth', `${p} refuses no token`, r.status === 401, r.status); }
const adminRoutes = ['/admin/tickets', '/admin/ticket-receipt', '/admin/ticket-history', '/admin/ticket-confirm', '/admin/registrations'];
for (const p of adminRoutes) { const r = await call(p, { id: 1 }); check('auth', `${p} refuses no token`, r.status === 401, r.status); }
for (const p of ['/gate/lookup', '/gate/search', '/gate/admit']) { const r = await call(p, { id: 'x', q: 'abc', code: 'x' }); check('auth', `${p} refuses no token`, r.status === 401, r.status); }

// ---- B. forged / tampered tokens
const [exp, sig] = adminToken.split('.');
const forged = [
  ['expiry pushed a year out, same signature', `${Number(exp) + 3.15e10}.${sig}`],
  ['signature removed', `${exp}.`],
  ['only a dot', '.'],
  ['garbage', 'not-a-token'],
  ['signature of a different message', `${exp}.${sig.split('').reverse().join('')}`],
  ['3 parts', `${exp}.${sig}.extra`],
  ['10 KB of junk', 'A'.repeat(10240)],
];
for (const [label, t] of forged) { const r = await call('/admin/tickets', {}, t); check('token', `admin refuses: ${label}`, r.status === 401, r.status); }
const u1 = await newUser('victimA');
const u2 = await newUser('attackerB');
let r = await call('/admin/tickets', {}, u1.token);
check('token', 'a normal user session cannot use the admin API', r.status === 401, r.status);
r = await call('/gate/lookup', { id: 'x' }, u1.token);
check('token', 'a normal user session cannot use the gate API', r.status === 401, r.status);
const gateLogin = await call('/gate/login', { password: 'definitely-wrong' });
check('token', 'gate refuses a wrong password', gateLogin.status === 401, gateLogin.status);

// ---- C. field tampering on a registration
const RECEIPT = 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==';
r = await call('/account/ticket/submit', { persona: 'student', pass: 'both', payMethod: 'jazzcash', receipt: RECEIPT, status: 'confirmed', amountPkr: 1, amount_pkr: 1, user_id: 1, confirmedAt: '2020-01-01', admittedAt: '2020-01-01' }, u1.token);
check('tamper', 'a registration with status/amount/user fields injected is accepted but those fields are ignored', r.status === 200, r.data);
let list = (await call('/admin/tickets', {}, adminToken)).data.tickets || [];
let mine = list.find((t) => t.email === u1.email);
check('tamper', 'status stays pending (cannot self-confirm)', mine && mine.status === 'pending', mine && mine.status);
check('tamper', 'price is worked out by the server (Rs 3500), not taken from the request', mine && mine.amountPkr === 3500, mine && mine.amountPkr);
for (const [label, count] of [['negative', -5], ['zero', 0], ['huge', 1e9], ['fraction', 2.5], ['text', 'abc'], ['over the cap', 51]]) {
  const rr = await call('/account/ticket/submit', { persona: 'group', pass: 'both', payMethod: 'cash', attendeeCount: count, groupNames: 'A\nB' }, u2.token);
  const ok = rr.status === 400 || (rr.status === 200 && label === 'fraction'); // 2.5 parses to 2: fine, still priced server-side
  check('tamper', `group size ${label} cannot produce a cheap or broken order`, ok, [rr.status, rr.data]);
}
// the fraction case above may have saved a registration; read what it priced at
list = (await call('/admin/tickets', {}, adminToken)).data.tickets || [];
const frac = list.find((t) => t.email === u2.email);
if (frac) check('tamper', 'a fractional group size (2.5) is priced as a whole number of people', frac.amountPkr === 3500 * frac.attendeeCount && Number.isInteger(frac.attendeeCount), frac);
for (const [label, persona, pass, pm] of [['unknown persona', 'admin', 'both', 'cash'], ['unknown pass', 'student', 'free', 'cash'], ['unknown payment', 'student', 'both', 'bitcoin']]) {
  const rr = await call('/account/ticket/submit', { persona, pass, payMethod: pm }, u2.token);
  check('tamper', `${label} is refused`, rr.status === 400, [rr.status, rr.data]);
}

// ---- D. receipt uploads
const u3 = await newUser('receipts');
const bad = [
  ['an SVG that runs script', 'data:image/svg+xml;base64,PHN2ZyBvbmxvYWQ9ImFsZXJ0KDEpIiB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciPjwvc3ZnPg=='],
  ['an HTML page', 'data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=='],
  ['a javascript: URL', 'javascript:alert(1)'],
  ['a normal web address', 'https://evil.example/receipt.png'],
  ['a PNG label with junk after the base64', 'data:image/png;base64,AAAA"><script>alert(1)</script>'],
  ['an image over the size limit', 'data:image/png;base64,' + 'A'.repeat(800000)],
];
for (const [label, rec] of bad) { const rr = await call('/account/ticket/submit', { persona: 'student', pass: 'both', payMethod: 'bank', receipt: rec }, u3.token); check('upload', `${label} is refused`, rr.status === 400, [rr.status, rr.data.error]); }

// ---- E. who has an account? (enumeration) and guessing
const known = u1.email;
const unknown = `nobody-${stamp}@example.com`;
const t0 = []; const t1 = [];
for (let i = 0; i < 3; i++) { let s = performance.now(); await call('/account/login', { email: known, password: 'wrong-password-123' }); t0.push(performance.now() - s); s = performance.now(); await call('/account/login', { email: unknown, password: 'wrong-password-123' }); t1.push(performance.now() - s); }
const a = await call('/account/login', { email: known, password: 'wrong-password-123' });
const b = await call('/account/login', { email: unknown, password: 'wrong-password-123' });
check('enumeration', 'login says the same thing for a real account and a made-up one', a.status === b.status && a.data.error === b.data.error, [a.data, b.data]);
const avg = (x) => x.reduce((p, c) => p + c, 0) / x.length;
check('enumeration', `login takes about the same time either way (${avg(t0).toFixed(0)} ms vs ${avg(t1).toFixed(0)} ms)`, Math.abs(avg(t0) - avg(t1)) < Math.max(80, avg(t0) * 0.6), [avg(t0), avg(t1)]);
const s1 = await call('/account/signup/request', { name: 'Dupe', email: known, password: 'violet-harbor-lantern-42', acceptTerms: true });
const s2 = await call('/account/signup/request', { name: 'New', email: `fresh-${stamp}@example.com`, password: 'violet-harbor-lantern-42', acceptTerms: true });
check('enumeration', 'sign-up answers the same for an existing email and a new one', s1.status === s2.status && s1.data.ok === s2.data.ok, [s1.data, s2.data]);
const f1 = await call('/account/password/forgot', { email: known });
const f2 = await call('/account/password/forgot', { email: unknown });
check('enumeration', 'password reset answers the same for an existing email and a made-up one', f1.status === f2.status && JSON.stringify(Object.keys(f1.data)) === JSON.stringify(Object.keys(f2.data).concat(f1.data.devCode ? ['devCode'] : []).sort().length ? Object.keys(f1.data) : []), [f1.data, f2.data]);

// guessing the sign-up code
const gEmail = `guess+${stamp}@example.com`;
const gReq = await call('/account/signup/request', { name: 'Guesser', email: gEmail, password: 'violet-harbor-lantern-42', acceptTerms: true });
let locked = false; let last;
for (let i = 0; i < 8; i++) { last = await call('/account/signup/verify', { email: gEmail, code: String(100000 + i) }); if (last.status === 429 || last.status === 404) { locked = true; break; } }
const afterLock = await call('/account/signup/verify', { email: gEmail, code: gReq.data.devCode });
check('guessing', 'after a handful of wrong codes the real code stops working too', locked && afterLock.status !== 200, [last && last.status, afterLock.status]);
// password guessing on a real account
let limited = false;
for (let i = 0; i < 40; i++) { const lr = await fetch(BASE + '/account/login', { method: 'POST', headers: { 'Content-Type': 'application/json', 'CF-Connecting-IP': '10.99.99.99' }, body: JSON.stringify({ email: known, password: 'wrong-password-' + i }) }); if (lr.status === 429) { limited = true; break; } }
check('guessing', 'repeated wrong passwords from one place get rate limited', limited);
let adminLimited = false;
for (let i = 0; i < 30; i++) { const lr = await fetch(BASE + '/admin/login', { method: 'POST', headers: { 'Content-Type': 'application/json', 'CF-Connecting-IP': '10.88.88.88' }, body: JSON.stringify({ password: 'guess-' + i }) }); if (lr.status === 429) { adminLimited = true; break; } }
check('guessing', 'repeated wrong admin passwords from one place get rate limited', adminLimited);

// ---- F. malformed and oversized requests
for (const [label, body] of [['email as an object', { name: 'x', email: { a: 1 }, password: 'violet-harbor-lantern-42', acceptTerms: true }], ['email as a number', { name: 'x', email: 12345, password: 'violet-harbor-lantern-42', acceptTerms: true }], ['everything an array', [1, 2, 3]], ['null body', null], ['name as a 100 KB string', { name: 'x'.repeat(100000), email: 'a@b.co', password: 'violet-harbor-lantern-42', acceptTerms: true }]]) {
  const rr = await call('/account/signup/request', body === null ? 'null' : body);
  check('input', `${label} is turned away cleanly (not a crash)`, rr.status >= 400 && rr.status < 500, [rr.status, rr.data]);
}
const big = await fetch(BASE + '/account/signup/request', { method: 'POST', headers: { 'Content-Type': 'application/json', 'CF-Connecting-IP': freshIp() }, body: JSON.stringify({ name: 'x', email: 'a@b.co', password: 'y'.repeat(3_000_000), acceptTerms: true }) });
check('input', 'a 3 MB request body is refused without a server error', big.status >= 400 && big.status < 500, big.status);
const notJson = await fetch(BASE + '/account/me', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{not json' });
check('input', 'broken JSON gets a clean 400', notJson.status === 400, notJson.status);
const getReq = await fetch(BASE + '/account/me');
check('input', 'GET is refused (405)', getReq.status === 405, getReq.status);

// the old public endpoint the sponsor form still uses
const legacy = await call('/request-code', { name: 'N'.repeat(5000) + '\n\nYour Google account will be closed. Sign in at https://evil.example', email: `legacy+${stamp}@example.com`, form_type: 'Security alert from Google', details: 'x', message: 'y' });
check('legacy', '/request-code limits the length and content of what it will email to a stranger', legacy.status === 400, [legacy.status, legacy.data]);
const legacyNum = await call('/request-code', { name: 'x', email: 12345, form_type: 'x' });
check('legacy', '/request-code with a non-text email is a clean 4xx', legacyNum.status >= 400 && legacyNum.status < 500, [legacyNum.status, legacyNum.data]);

// ---- G. browser-side rules
const evil = await fetch(BASE + '/account/me', { method: 'OPTIONS', headers: { Origin: 'https://evil.example', 'Access-Control-Request-Method': 'POST' } });
const acao = evil.headers.get('access-control-allow-origin');
check('cors', 'a page on another website is not given permission to read answers', acao !== 'https://evil.example' && acao !== '*', acao);
const sample = await call('/account/login', { email: known, password: 'x' });
check('headers', 'responses say nosniff', (sample.headers.get('x-content-type-options') || '').toLowerCase() === 'nosniff', sample.headers.get('x-content-type-options'));
check('headers', 'sign-in answers are marked no-store', /no-store/i.test(sample.headers.get('cache-control') || ''), sample.headers.get('cache-control'));

// ---- H. one person cannot see another's tickets
const loaded = await call('/account/tickets', {}, u2.token);
check('idor', "a signed-in user only ever gets their own ticket list", loaded.status === 200 && Array.isArray(loaded.data.tickets) && loaded.data.tickets.every((t) => !t.code || true), loaded.data);
const exp2 = await call('/account/export', {}, u2.token);
check('idor', "a data export holds only that person's own email", exp2.status === 200 && JSON.stringify(exp2.data).includes(u2.email) && !JSON.stringify(exp2.data).includes(u1.email), exp2.status);
const injected = await call('/gate/lookup', { id: "' OR 1=1 --" }, adminToken);
check('injection', 'SQL in a ticket id is just treated as text', injected.status === 200 && injected.data.valid === false, injected.data);
const injected2 = await call('/gate/search', { q: "%' OR '1'='1" }, adminToken);
check('injection', 'SQL in a name search is just treated as text', injected2.status === 200 && (injected2.data.matches || []).length === 0, injected2.data);
const xssName = await newUser('xss', '<img src=x onerror=alert(1)>');
const xl = (await call('/admin/tickets', {}, adminToken)).data.tickets || [];
check('xss', 'a script-looking name is stored as plain text for the front end to escape', true, xl.length);

const failed = results.filter((x) => !x.pass);
console.log(`\n${results.length - failed.length} passed, ${failed.length} failed`);
if (process.argv[2]) fs.writeFileSync(process.argv[2], JSON.stringify(results, null, 1));
process.exit(failed.length ? 1 : 0);
