// End-to-end check of the account routes against a locally running worker.
//   npx wrangler dev --config wrangler.local.jsonc --port 8787
//   node test-accounts.mjs
// Needs DEV_MODE=1 (wrangler.local.jsonc), which returns email codes in the response.

const BASE = process.env.BASE || 'http://127.0.0.1:8787';
const stamp = Date.now();
// A fresh fake client IP per run, so repeated local runs do not trip the per-IP rate limits.
const TEST_IP = `10.${(stamp>>8)&255}.${(stamp>>4)&255}.${stamp&255}`;
const email = `test+${stamp}@example.com`;
const PW = 'correct-horse-battery';
const PW2 = 'another-long-passphrase';

let passed = 0;
let failed = 0;
const check = (label, cond, extra) => {
  if (cond) {
    passed += 1;
    console.log(`  ok   ${label}`);
  } else {
    failed += 1;
    console.log(`  FAIL ${label}${extra ? '  ->  ' + JSON.stringify(extra) : ''}`);
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

console.log('sign-up');
let r = await call('/account/signup/request', { name: 'Test User', email, password: 'short' });
check('rejects a short password', r.status === 400, r);
r = await call('/account/signup/request', { name: 'Test User', email, password: 'password123' });
check('rejects a common password', r.status === 400, r);
r = await call('/account/signup/request', { name: 'Test User', email: 'not-an-email', password: PW });
check('rejects a bad email', r.status === 400, r);

r = await call('/account/signup/request', { name: 'Test User', email, password: PW });
check('accepts a valid sign-up and returns a code in dev mode', r.status === 200 && /^\d{6}$/.test(r.data.devCode || ''), r);
const code = r.data.devCode;

r = await call('/account/signup/verify', { email, code: '000000' });
check('wrong code is rejected', r.status === 401, r);
r = await call('/account/signup/verify', { email, code });
check('right code creates the account and signs in', r.status === 200 && !!r.data.token && r.data.user?.email === email, r);
const token1 = r.data.token;
r = await call('/account/signup/verify', { email, code });
check('a code cannot be used twice', r.status === 404, r);

console.log('session + profile');
r = await call('/account/me', {}, token1);
check('/me works with the token', r.status === 200 && r.data.user.name === 'Test User' && r.data.ticket === null, r);
r = await call('/account/me', {});
check('/me without a token is 401', r.status === 401, r);
r = await call('/account/me', {}, 'not-a-real-token');
check('/me with a bad token is 401', r.status === 401, r);
r = await call('/account/update', { name: 'Renamed User' }, token1);
check('can update the name', r.status === 200 && r.data.user.name === 'Renamed User', r);
r = await call('/account/me', {}, token1);
check('a new account has no ticket yet', r.status === 200 && r.data.ticket === null, r);

console.log('duplicate + enumeration');
r = await call('/account/signup/request', { name: 'Someone Else', email, password: PW });
check('sign-up for an existing email looks identical (no devCode, status 200)', r.status === 200 && !r.data.devCode, r);

console.log('login + logout');
r = await call('/account/login', { email, password: 'wrong-password-here' });
check('wrong password is 401 with a generic message', r.status === 401 && r.data.error === 'Incorrect email or password', r);
r = await call('/account/login', { email: `nobody+${stamp}@example.com`, password: PW });
check('unknown email gives the same message as a wrong password', r.status === 401 && r.data.error === 'Incorrect email or password', r);
r = await call('/account/login', { email: email.toUpperCase(), password: PW });
check('login works and email is case-insensitive', r.status === 200 && !!r.data.token, r);
const token2 = r.data.token;
r = await call('/account/logout', {}, token2);
check('logout succeeds', r.status === 200, r);
r = await call('/account/me', {}, token2);
check('a logged-out token stops working immediately', r.status === 401, r);

console.log('password reset');
r = await call('/account/password/forgot', { email: `nobody+${stamp}@example.com` });
check('forgot for an unknown email looks identical (no devCode)', r.status === 200 && !r.data.devCode, r);
r = await call('/account/password/forgot', { email });
check('forgot for a real email returns a code in dev mode', r.status === 200 && /^\d{6}$/.test(r.data.devCode || ''), r);
const resetCode = r.data.devCode;
r = await call('/account/password/reset', { email, code: '111111', newPassword: PW2 });
check('reset with a wrong code fails', r.status === 401, r);
r = await call('/account/password/reset', { email, code: resetCode, newPassword: 'short' });
check('reset enforces the password rules', r.status === 400, r);
r = await call('/account/password/reset', { email, code: resetCode, newPassword: PW2 });
check('reset with the right code succeeds', r.status === 200, r);
r = await call('/account/me', {}, token1);
check('reset signs out every existing session', r.status === 401, r);
r = await call('/account/login', { email, password: PW });
check('the old password no longer works', r.status === 401, r);
r = await call('/account/login', { email, password: PW2 });
check('the new password works', r.status === 200 && !!r.data.token, r);
const token3 = r.data.token;

console.log('rate limiting');
const victim = `ratelimit+${stamp}@example.com`;
let limited = false;
for (let i = 0; i < 12; i += 1) {
  r = await call('/account/login', { email: victim, password: 'whatever-guess-' + i });
  if (r.status === 429) limited = true;
}
check('repeated bad logins for one email get a 429', limited);

console.log('delete');
r = await call('/account/delete', { password: 'wrong-password-here' }, token3);
check('delete needs the right password', r.status === 401, r);
r = await call('/account/delete', { password: PW2 }, token3);
check('delete succeeds with the right password', r.status === 200, r);
r = await call('/account/me', {}, token3);
check('the session is gone after deletion', r.status === 401, r);
r = await call('/account/login', { email, password: PW2 });
check('the account no longer exists', r.status === 401, r);

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
