// End-to-end check of the account settings features against a local worker (DEV_MODE=1):
// devices ("where you're logged in"), password change, email change, sign-in alerts,
// avatar colour, data download and the security emails.
//   npx wrangler dev --config wrangler.local.jsonc --port 8787
//   node test-settings.mjs
const BASE = process.env.BASE || 'http://127.0.0.1:8787';
const stamp = Date.now();
const TEST_IP = `10.${(stamp >> 10) & 255}.${(stamp >> 3) & 255}.${(stamp & 127) + 100}`;

const CHROME_WIN = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36';
const SAFARI_IPHONE = 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1';
const FIREFOX_LINUX = 'Mozilla/5.0 (X11; Linux x86_64; rv:130.0) Gecko/20100101 Firefox/130.0';
const EDGE_ANDROID = 'Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Mobile Safari/537.36 EdgA/130.0.0.0';

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

async function call(path, body, token, device = {}) {
  const res = await fetch(BASE + path, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'CF-Connecting-IP': TEST_IP,
      'User-Agent': device.ua || CHROME_WIN,
      'CF-IPCountry': device.country || 'PK',
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: JSON.stringify(body || {}),
  });
  let data = {};
  try {
    data = await res.json();
  } catch {}
  return { status: res.status, data };
}
const outbox = async () => (await call('/dev/outbox', {})).data.outbox;
const mailsTo = async (to, re) => (await outbox()).filter((m) => m.kind === 'user' && m.to === to && re.test(m.subject));

async function newUser(prefix, name, password, device) {
  const email = `${prefix}+${stamp}@example.com`;
  let r = await call('/account/signup/request', { name, email, password, acceptTerms: true }, null, device);
  r = await call('/account/signup/verify', { email, code: r.data.devCode }, null, device);
  return { email, name, password, token: r.data.token };
}

console.log('new account defaults');
const A = await newUser('settings', 'Settings Tester', 'granite-willow-ember');
let r = await call('/account/me', {}, A.token);
check('a new account has alerts off and no avatar colour', r.data.user.loginAlerts === false && r.data.user.avatarColor === null, r.data.user);

console.log('where you are logged in');
r = await call('/account/sessions', {}, A.token);
check('the device list shows this sign-in, marked current, with a readable device', r.status === 200 && r.data.sessions.length === 1 && r.data.sessions[0].current === true && r.data.sessions[0].device === 'Chrome on Windows', r.data);
check('and the country', /Pakistan|PK/.test(r.data.sessions[0].country), r.data.sessions[0].country);
check('the device id is a short hex id, not the token', /^[0-9a-f]{16}$/.test(r.data.sessions[0].id));

r = await call('/account/login', { email: A.email, password: A.password }, null, { ua: SAFARI_IPHONE, country: 'AU' });
const iphone = r.data.token;
r = await call('/account/login', { email: A.email, password: A.password }, null, { ua: EDGE_ANDROID, country: 'PK' });
const android = r.data.token;
r = await call('/account/sessions', {}, A.token);
const devices = r.data.sessions.map((s) => s.device).sort();
check('three devices are listed, each described correctly', r.data.sessions.length === 3 && devices.join('|') === ['Chrome on Windows', 'Edge on Android', 'Safari on iPhone'].join('|'), devices);
check('exactly one is marked as the current device', r.data.sessions.filter((s) => s.current).length === 1 && r.data.sessions.find((s) => s.current).device === 'Chrome on Windows');
r = await call('/account/sessions', {}, iphone);
check('from the iPhone, the iPhone is the current one', r.data.sessions.find((s) => s.current).device === 'Safari on iPhone');
const androidId = r.data.sessions.find((s) => s.device === 'Edge on Android').id;
const currentId = r.data.sessions.find((s) => s.current).id;

r = await call('/account/sessions/revoke', { id: currentId }, iphone);
check('you cannot "sign out" your own current device from the list', r.status === 400, r.data);
r = await call('/account/sessions/revoke', { id: 'not-a-valid-id' }, iphone);
check('a malformed device id is refused', r.status === 400, r.data);
r = await call('/account/sessions/revoke', { id: androidId }, iphone);
check('signing out another device works', r.status === 200 && r.data.removed === 1, r.data);
r = await call('/account/me', {}, android);
check('that device is signed out immediately', r.status === 401, r.status);
r = await call('/account/me', {}, iphone);
check('the device you are on stays signed in', r.status === 200);
r = await call('/account/sessions/revoke-others', {}, iphone);
check('"sign out everywhere else" removes the rest', r.status === 200 && r.data.removed === 1, r.data);
r = await call('/account/me', {}, A.token);
check('so the original browser is now signed out', r.status === 401, r.status);
r = await call('/account/sessions', {}, iphone);
check('only the current device remains', r.data.sessions.length === 1 && r.data.sessions[0].current);
A.token = iphone;

console.log('profile preferences');
r = await call('/account/prefs', { avatarColor: '#123456' }, A.token);
check('an unlisted avatar colour is refused', r.status === 400, r.data);
r = await call('/account/prefs', { avatarColor: '#6aa8ff' }, A.token);
check('a listed avatar colour is saved', r.status === 200 && r.data.user.avatarColor === '#6aa8ff', r.data);
r = await call('/account/me', {}, A.token);
check('and comes back on the next load', r.data.user.avatarColor === '#6aa8ff');
r = await call('/account/prefs', {}, A.token);
check('an empty change is refused', r.status === 400, r.data);
r = await call('/account/update', { name: 'Settings Renamed' }, A.token);
check('the name can still be changed', r.status === 200 && r.data.user.name === 'Settings Renamed', r.data);
A.name = 'Settings Renamed';

console.log('change password');
const sessionB = (await call('/account/login', { email: A.email, password: A.password }, null, { ua: FIREFOX_LINUX, country: 'DE' })).data.token;
r = await call('/account/password/change', { current: 'wrong-current-password', next: 'brand-new-passphrase-1' }, A.token);
check('a wrong current password is refused with 403 (not 401, which would sign them out)', r.status === 403, r.status);
r = await call('/account/password/change', { current: A.password, next: 'short' }, A.token);
check('a weak new password is refused', r.status === 400, r.data);
r = await call('/account/password/change', { current: A.password, next: A.password }, A.token);
check('the same password again is refused', r.status === 400, r.data);
r = await call('/account/password/change', { current: A.password, next: 'brand-new-passphrase-1' });
check('changing the password needs to be signed in', r.status === 401, r.status);
r = await call('/account/password/change', { current: A.password, next: 'brand-new-passphrase-1' }, A.token, { ua: SAFARI_IPHONE, country: 'AU' });
check('the right current password changes it', r.status === 200, r.data);
r = await call('/account/me', {}, A.token);
check('this device stays signed in', r.status === 200);
r = await call('/account/me', {}, sessionB);
check('every other device is signed out', r.status === 401, r.status);
r = await call('/account/login', { email: A.email, password: A.password });
check('the old password no longer works', r.status === 401, r.status);
r = await call('/account/login', { email: A.email, password: 'brand-new-passphrase-1' });
check('the new password works', r.status === 200);
A.password = 'brand-new-passphrase-1';
let mails = await mailsTo(A.email, /password was changed/i);
check('a "password changed" notice was emailed, naming the device', mails.length === 1 && /Safari on iPhone/.test(mails[0].message) && /Reset my password/.test(mails[0].html || ''), mails.at(-1));

console.log('change email');
const other = await newUser('taken', 'Other Person', 'cedar-falcon-meadow-9');
const newAddress = `settings-new+${stamp}@example.com`;
r = await call('/account/email/change/request', { newEmail: newAddress, password: 'wrong-password-here' }, A.token);
check('changing email needs the right password (403)', r.status === 403, r.status);
r = await call('/account/email/change/request', { newEmail: 'not-an-email', password: A.password }, A.token);
check('an invalid address is refused', r.status === 400, r.data);
r = await call('/account/email/change/request', { newEmail: A.email.toUpperCase(), password: A.password }, A.token);
check('your current address is refused', r.status === 400, r.data);
r = await call('/account/email/change/request', { newEmail: other.email, password: A.password }, A.token);
check('an address that belongs to someone else looks the same as a free one (no code, no hint)', r.status === 200 && !r.data.devCode, r.data);
r = await call('/account/email/change/verify', { code: '123456' }, A.token);
check('so there is nothing to verify for it', r.status === 404, r.status);

r = await call('/account/email/change/request', { newEmail: newAddress, password: A.password }, A.token);
check('a free address gets a code', r.status === 200 && /^\d{6}$/.test(r.data.devCode || ''), r.data);
const emailCode = r.data.devCode;
r = await call('/account/email/change/verify', { code: '000000' }, A.token);
check('a wrong code is refused (400, not 401)', r.status === 400, r.status);
const sessionC = (await call('/account/login', { email: A.email, password: A.password }, null, { ua: FIREFOX_LINUX, country: 'DE' })).data.token;
r = await call('/account/email/change/verify', { code: emailCode }, A.token);
check('the right code changes the email', r.status === 200 && r.data.user.email === newAddress, r.data);
r = await call('/account/me', {}, A.token);
check('the account now shows the new email', r.data.user.email === newAddress);
r = await call('/account/me', {}, sessionC);
check('other devices were signed out', r.status === 401, r.status);
r = await call('/account/email/change/verify', { code: emailCode }, A.token);
check('a code cannot be used twice', r.status === 404, r.status);
r = await call('/account/login', { email: newAddress, password: A.password });
check('signing in works with the new email', r.status === 200);
r = await call('/account/login', { email: A.email, password: A.password });
check('and no longer with the old one', r.status === 401, r.status);
mails = await mailsTo(A.email, /account email was changed/i);
check('the OLD address was told, with the new one partly hidden', mails.length === 1 && /s•+@example\.com/.test(mails[0].message) && !mails[0].message.includes(newAddress), mails.at(-1));
const codeMail = (await outbox()).filter((m) => m.kind === 'user' && m.to === newAddress);
check('the verification code went to the NEW address only', codeMail.length === 0 || codeMail.every((m) => m.to === newAddress));
A.email = newAddress;
A.token = (await call('/account/login', { email: A.email, password: A.password }, null, { ua: SAFARI_IPHONE, country: 'AU' })).data.token;

console.log('new sign-in alerts');
const alerts = await newUser('alerts', 'Alert Tester', 'maple-harbour-lantern-5');
await call('/account/login', { email: alerts.email, password: alerts.password }, null, { ua: FIREFOX_LINUX, country: 'DE' });
let before = (await mailsTo(alerts.email, /new sign-in/i)).length;
check('with alerts off, a new device sends nothing', before === 0, before);
r = await call('/account/prefs', { loginAlerts: true }, alerts.token);
check('alerts can be turned on', r.status === 200 && r.data.user.loginAlerts === true, r.data);
await call('/account/login', { email: alerts.email, password: alerts.password }, null, { ua: CHROME_WIN, country: 'PK' });
check('a device already seen does not alert', (await mailsTo(alerts.email, /new sign-in/i)).length === 0);
await call('/account/login', { email: alerts.email, password: alerts.password }, null, { ua: SAFARI_IPHONE, country: 'US' });
mails = await mailsTo(alerts.email, /new sign-in/i);
check('a genuinely new device sends one alert naming the device and country', mails.length === 1 && /Safari on iPhone/.test(mails[0].message) && /United States|US/.test(mails[0].message) && /Reset my password/.test(mails[0].html || ''), mails.at(-1));
await call('/account/login', { email: alerts.email, password: alerts.password }, null, { ua: SAFARI_IPHONE, country: 'US' });
check('the same new device again does not alert twice', (await mailsTo(alerts.email, /new sign-in/i)).length === 1);

console.log('download my data');
r = await call('/account/export', {}, A.token);
const exp = r.data.export;
check('the download has the account details and a timestamp', r.status === 200 && exp.account.email === A.email && exp.account.name === 'Settings Renamed' && !!exp.exportedAt, exp && exp.account);
check('it records when the Terms and Privacy Policy were accepted', !!exp.account.termsAcceptedAt && !!exp.account.termsVersion, exp.account);
check('it lists the signed-in devices',Array.isArray(exp.signedInDevices) && exp.signedInDevices.length >= 1 && !!exp.signedInDevices[0].device);
check('with no registration yet it says so', exp.registration === null);
const blob = JSON.stringify(r.data);
check('it never contains the password or its hash', !blob.includes(A.password) && !/pw_hash|v1\$\d+\$/.test(blob));
r = await call('/account/ticket/submit', { persona: 'student', pass: 'concert', payMethod: 'cash' }, A.token);
r = await call('/account/export', {}, A.token);
check('once registered, the registration is included', r.data.export.registration && r.data.export.registration.pass === 'concert' && r.data.export.registration.amountPkr === 2500, r.data.export.registration);
r = await call('/account/export', {});
check('downloading needs a sign-in', r.status === 401, r.status);
let limited = false;
for (let i = 0; i < 6; i += 1) {
  r = await call('/account/export', {}, A.token);
  if (r.status === 429) limited = true;
}
check('repeated downloads are rate limited', limited);

console.log('everything needs a sign-in');
for (const p of ['/account/sessions', '/account/sessions/revoke', '/account/sessions/revoke-others', '/account/prefs', '/account/email/change/request', '/account/email/change/verify']) {
  r = await call(p, {});
  check(`${p} without a token is 401`, r.status === 401, r.status);
}

console.log('deleting the account clears the device records too');
r = await call('/account/delete', { password: A.password }, A.token);
check('the account (pending registration) can be deleted', r.status === 200, r.data);
r = await call('/account/login', { email: A.email, password: A.password });
check('and it is gone', r.status === 401, r.status);

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
