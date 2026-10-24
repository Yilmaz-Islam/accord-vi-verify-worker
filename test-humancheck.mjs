// The "are you human" check (Cloudflare Turnstile) on sign-up and the sponsor form.
// Needs a local worker started with one of Cloudflare's published TEST secrets:
//   always passes:  ... dev --config wrangler.local.jsonc --port 8787 --var TURNSTILE_SECRET:1x0000000000000000000000000000000AA
//   always fails:   ... dev --config wrangler.local.jsonc --port 8787 --var TURNSTILE_SECRET:2x0000000000000000000000000000000AA
//   HUMAN=pass node test-humancheck.mjs    (or HUMAN=fail)
// The real check talks to Cloudflare, so this needs an internet connection.

const BASE = process.env.BASE || 'http://127.0.0.1:8787';
const MODE = process.env.HUMAN === 'fail' ? 'fail' : 'pass';
const DUMMY = 'XXXX.DUMMY.TOKEN.XXXX'; // what Cloudflare's test keys hand out
const stamp = Date.now();
const TEST_IP = `10.${(stamp>>8)&255}.${(stamp>>4)&255}.${stamp&255}`;

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
async function call(path, body) {
  const res = await fetch(BASE + path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'CF-Connecting-IP': TEST_IP },
    body: JSON.stringify(body || {}),
  });
  let data = {};
  try {
    data = await res.json();
  } catch {}
  return { status: res.status, data };
}
const isHumanError = (r) => r.status === 400 && /human/i.test(r.data.error || '');
const signup = (extra) =>
  call('/account/signup/request', { name: 'Human Test', email: `human+${stamp}-${Math.random().toString(36).slice(2, 7)}@example.com`, password: 'copper-meadow-signal', acceptTerms: true, ...extra });

console.log(`human check (secret that always ${MODE === 'pass' ? 'passes' : 'fails'})`);
check('sign-up without a token is refused', isHumanError(await signup({})));
check('sign-up with an over-long token is refused', isHumanError(await signup({ turnstileToken: 'x'.repeat(3000) })));
check('sign-up with a token that is not text is refused', isHumanError(await signup({ turnstileToken: { a: 1 } })));
check('the sponsor form without a token is refused', isHumanError(await call('/request-code', { name: 'Human Test', email: `human+${stamp}@example.com`, form_type: 'Sponsorship Inquiry' })));

const r = await signup({ turnstileToken: DUMMY });
if (MODE === 'pass') {
  check('sign-up with a passing token goes through', r.status === 200 && r.data.ok === true && !!r.data.devCode, r.data);
} else {
  check('sign-up with a token Cloudflare rejects is refused', isHumanError(r), r);
}

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
