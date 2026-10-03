// Accord VI accounts: sign-up, login, sessions, profile, event registration.
//
// Storage: Cloudflare D1 (env.DB) for users / sessions / registrations, because
// KV is eventually consistent (up to ~60 s) and that breaks unique emails and
// instant logout. KV (env.CODES) is still used for the short-lived email codes
// and rate-limit counters, same as the rest of this worker.
//
// All routes are POST + JSON, like the rest of the worker. Auth is a bearer
// token in the Authorization header (not a cookie, for the same cross-site
// reason as the admin login).
//
//   /account/signup/request   { name, email, password }       -> emails a 6-digit code
//   /account/signup/verify    { email, code }                 -> creates the account, returns { token, user }
//   /account/login            { email, password }             -> { token, user }
//   /account/logout           (Bearer)                        -> deletes this session
//   /account/me               (Bearer)                        -> { user, ticket }
//   /account/update           (Bearer) { name }               -> updates the profile
//   /account/ticket/submit    (Bearer) { persona, pass, payMethod, receipt, ... } -> saves the registration as pending,
//                                                                emails the person, notifies the organisers
//
// Admin (the existing admin bearer token, see index.js):
//   /admin/tickets            -> every registration (no receipt images)
//   /admin/ticket-receipt     { id } -> the receipt image
//   /admin/ticket-confirm     { id } -> marks it confirmed and emails the person
//   /account/password/forgot  { email }                       -> always { ok: true }; emails a code if the account exists
//   /account/password/reset   { email, code, newPassword }    -> sets the password, signs out every device
//   /account/delete           (Bearer) { password }           -> deletes the account and its data
//
// Required secret: PEPPER (wrangler secret put PEPPER). The worker refuses to
// run the account routes without it rather than hashing without one.

const enc = new TextEncoder();

// Workers caps PBKDF2 at 100,000 iterations per call (OWASP's current figure for
// PBKDF2-SHA256 is 600,000). The secret PEPPER below makes up for part of that:
// a stolen database alone cannot be cracked offline without it.
const PBKDF2_ITERS = 100000;
const SESSION_TTL_S = 7 * 24 * 60 * 60;
const CODE_TTL_S = 600;
const MAX_CODE_ATTEMPTS = 5;

// A few of the most common passwords. Not a substitute for a breach list, but
// it stops the worst of them.
const COMMON_PASSWORDS = new Set([
  'password', 'password1', 'password123', '1234567890', '12345678910', 'qwertyuiop',
  'iloveyou123', 'letmein123', 'welcome123', 'admin12345', 'abc1234567', 'passw0rd123',
  'qwerty12345', '1q2w3e4r5t', 'accord2026', 'accordvi123', 'beaconhouse', 'beaconhouse1',
  'multan1234', 'football123', 'cricket123', 'pakistan123', 'pakistan1234',
]);

// ---------- encoding + crypto helpers ----------

function b64u(bytes) {
  return btoa(String.fromCharCode(...new Uint8Array(bytes)))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

function unb64u(s) {
  let t = s.replace(/-/g, '+').replace(/_/g, '/');
  while (t.length % 4) t += '=';
  return Uint8Array.from(atob(t), (c) => c.charCodeAt(0));
}

function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) diff |= a[i] ^ b[i];
  return diff === 0;
}

async function sha256Hex(text) {
  const d = await crypto.subtle.digest('SHA-256', enc.encode(text));
  return [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

function secureCode() {
  // Uniform 6 digits from the CSPRNG (rejection sampling avoids modulo bias).
  const buf = new Uint32Array(1);
  const limit = Math.floor(0xffffffff / 1000000) * 1000000;
  do {
    crypto.getRandomValues(buf);
  } while (buf[0] >= limit);
  return String(100000 + (buf[0] % 900000));
}

function safeEqualStr(a, b) {
  return timingSafeEqual(enc.encode(String(a)), enc.encode(String(b)));
}

// password -> HMAC(PEPPER, password) -> PBKDF2-SHA256(salt)
async function derive(env, password, salt, iterations) {
  const macKey = await crypto.subtle.importKey(
    'raw',
    enc.encode(env.PEPPER),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const peppered = await crypto.subtle.sign('HMAC', macKey, enc.encode(password));
  const key = await crypto.subtle.importKey('raw', peppered, 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', hash: 'SHA-256', salt, iterations },
    key,
    256
  );
  return new Uint8Array(bits);
}

async function hashPassword(env, password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const hash = await derive(env, password, salt, PBKDF2_ITERS);
  return `v1$${PBKDF2_ITERS}$${b64u(salt)}$${b64u(hash)}`;
}

async function verifyPassword(env, password, stored) {
  const [version, iters, salt, hash] = String(stored).split('$');
  if (version !== 'v1') return false;
  const got = await derive(env, password, unb64u(salt), parseInt(iters, 10));
  return timingSafeEqual(got, unb64u(hash));
}

// Verified against when the email is unknown, so "no such account" and "wrong
// password" cost the same time and give nothing away.
const DUMMY_HASH = `v1$${PBKDF2_ITERS}$${'A'.repeat(22)}$${'A'.repeat(43)}`;

// ---------- validation ----------

function cleanEmail(raw) {
  const email = String(raw || '').trim().toLowerCase();
  if (email.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return null;
  return email;
}

function cleanName(raw) {
  const name = String(raw || '').trim().replace(/\s+/g, ' ');
  return name.length >= 1 && name.length <= 80 ? name : null;
}

// Returns an error message, or null if the password is acceptable.
function passwordProblem(password, email) {
  if (typeof password !== 'string') return 'Password is required';
  if (password.length < 10) return 'Password must be at least 10 characters';
  if (password.length > 128) return 'Password must be at most 128 characters';
  if (/^(.)\1+$/.test(password)) return 'Password is too simple';
  const lower = password.toLowerCase();
  if (COMMON_PASSWORDS.has(lower)) return 'That password is too common';
  if (email && (lower === email || lower === email.split('@')[0])) return 'Password cannot be your email';
  return null;
}

// ---------- sessions ----------

async function createSession(env, userId) {
  const token = b64u(crypto.getRandomValues(new Uint8Array(32)));
  const now = Math.floor(Date.now() / 1000);
  await env.DB.prepare(
    'INSERT INTO sessions (token_hash, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)'
  )
    .bind(await sha256Hex(token), userId, now, now + SESSION_TTL_S)
    .run();
  // Opportunistic clean-up of dead sessions; cheap and keeps the table small.
  await env.DB.prepare('DELETE FROM sessions WHERE expires_at < ?').bind(now).run();
  return token;
}

async function authenticate(env, request) {
  const header = request.headers.get('Authorization') || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : '';
  if (!token) return null;
  const now = Math.floor(Date.now() / 1000);
  const row = await env.DB.prepare(
    `SELECT s.token_hash AS tokenHash, u.id AS id, u.email AS email, u.name AS name, u.created_at AS createdAt
       FROM sessions s JOIN users u ON u.id = s.user_id
      WHERE s.token_hash = ? AND s.expires_at > ?`
  )
    .bind(await sha256Hex(token), now)
    .first();
  return row || null;
}

const publicUser = (u) => ({ email: u.email, name: u.name, createdAt: u.createdAt });

// ---------- tickets: validation and pricing ----------

// Rs per person. Worked out here, never trusted from the browser.
const PASS_PRICE_PKR = { concert: 2500, both: 3500 };
const PERSONAS = new Set(['student', 'group', 'guest', 'sponsor']);
const PAY_METHODS = new Set(['jazzcash', 'bank', 'cash']);
const RECEIPT_RE = /^data:image\/(jpeg|png|webp);base64,[A-Za-z0-9+/=]+$/;
const MAX_RECEIPT_CHARS = 700000; // about 500 KB of image; the page shrinks photos to roughly 300 KB first

function validateTicket(b) {
  const persona = String(b.persona || '');
  if (!PERSONAS.has(persona)) return { error: 'Choose who you are registering as' };
  const hearAbout = String(b.hearAbout || '').trim().slice(0, 60);
  const base = { persona, hearAbout, attendeeCount: 1, groupNames: '', sponsorTier: '', receipt: null };

  if (persona === 'sponsor') {
    return {
      ...base,
      sponsorTier: String(b.sponsorTier || '').trim().slice(0, 40),
      pass: 'sponsor',
      amountPkr: 0,
      payMethod: 'none',
      status: 'interest',
    };
  }

  const pass = String(b.pass || '');
  if (!(pass in PASS_PRICE_PKR)) return { error: 'Choose a pass' };

  let attendeeCount = 1;
  let groupNames = '';
  if (persona === 'group') {
    attendeeCount = Number.parseInt(b.attendeeCount, 10);
    if (!Number.isInteger(attendeeCount) || attendeeCount < 1 || attendeeCount > 50) {
      return { error: 'Group size must be between 1 and 50' };
    }
    groupNames = String(b.groupNames || '').trim().slice(0, 1000);
  }

  const payMethod = String(b.payMethod || '');
  if (!PAY_METHODS.has(payMethod)) return { error: 'Choose how you are paying' };

  let receipt = null;
  if (payMethod !== 'cash') {
    receipt = typeof b.receipt === 'string' ? b.receipt : '';
    if (!receipt) return { error: 'Attach a photo of your payment receipt' };
    if (receipt.length > MAX_RECEIPT_CHARS) return { error: 'That receipt image is too large. Try a smaller photo' };
    if (!RECEIPT_RE.test(receipt)) return { error: 'The receipt must be a JPG, PNG or WebP image' };
  }

  return {
    ...base,
    attendeeCount,
    groupNames,
    pass,
    amountPkr: PASS_PRICE_PKR[pass] * attendeeCount,
    payMethod,
    receipt,
    status: 'pending',
  };
}

// ---------- tickets: emails ----------
// Every email to a person goes through ONE EmailJS template (the free plan has
// only two). Its subject must be {{subject}}, its body {{message}} and its
// recipient {{email}}. The old code params are sent too, so the template keeps
// working until it is switched over. See ACCOUNTS.md.

const siteName = (env) => env.SITE_NAME || 'Accord VI';
const siteUrl = (env) => (env.SITE_URL || 'https://yilmaz-islam.github.io/accord-vi').replace(/\/$/, '');
const rs = (n) => `Rs ${Number(n).toLocaleString('en-US')}`;

const PASS_LABEL = {
  concert: 'Live Concert only (18 October)',
  both: 'Both nights: Live Concert (18 October) and Qawwali Night (19 October)',
  sponsor: 'Sponsorship interest',
};
const METHOD_LABEL = { jazzcash: 'JazzCash', bank: 'Bank transfer', cash: 'Cash, in person', none: '' };

async function devOutbox(env, entry) {
  const raw = await env.CODES.get('dev:outbox');
  const list = raw ? JSON.parse(raw) : [];
  list.push({ at: new Date().toISOString(), ...entry });
  await env.CODES.put('dev:outbox', JSON.stringify(list.slice(-50)), { expirationTtl: 3600 });
}

const escapeHtml = (s) =>
  String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

// The HTML version of an email: a branded card with the message text and optional
// buttons. Everything that came from a person (their name is in `message`) is
// escaped, and button labels and links are fixed by this code, never by the user.
// EmailJS shows it through `{{{html}}}` (triple braces = unescaped).
export function emailHtml(env, message, buttons = []) {
  const brand = escapeHtml(siteName(env));
  const body = escapeHtml(message).replace(/\n/g, '<br>');
  const btns = buttons
    .map(
      (b) =>
        `<a href="${escapeHtml(b.url)}" style="display:inline-block;margin:0 10px 10px 0;padding:12px 22px;border-radius:999px;` +
        `background:#e0b455;color:#0e0f12;font-weight:600;font-size:15px;text-decoration:none;">${escapeHtml(b.label)}</a>`
    )
    .join('');
  return (
    '<div style="background:#f4f2ee;padding:24px 12px;font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;">' +
    '<div style="max-width:560px;margin:0 auto;background:#ffffff;border-radius:14px;overflow:hidden;border:1px solid #e6e1d6;">' +
    `<div style="background:#0e0f12;padding:18px 24px;color:#e0b455;font-size:20px;font-weight:700;letter-spacing:.02em;">${brand}</div>` +
    `<div style="padding:24px;color:#1b1c20;font-size:15px;line-height:1.6;">${body}` +
    (btns ? `<div style="margin-top:22px;">${btns}</div>` : '') +
    '</div>' +
    '<div style="padding:14px 24px;background:#faf8f4;color:#7a7a85;font-size:12px;">18–19 October · Beaconhouse Cantt Campus, Multan</div>' +
    '</div></div>'
  );
}

async function sendUserEmail(ctx, to, name, subject, message, code, buttons) {
  const { env, sendEmail } = ctx;
  const html = emailHtml(env, message, buttons || []);
  if (env.DEV_MODE === '1') {
    await devOutbox(env, { kind: 'user', to, subject, message, html });
    return;
  }
  await sendEmail(env, env.EMAILJS_CODE_TEMPLATE_ID, {
    name,
    email: to,
    subject,
    message, // plain text, for a template that still uses {{message}}
    html, // rich version, for {{{html}}}
    form_type: subject,
    code: code || '',
  });
}

function pendingEmail(env, user, t) {
  const name = siteName(env);
  const lines = [`Hi ${user.name},`, ''];
  if (t.persona === 'sponsor') {
    lines.push(`Thanks for your interest in sponsoring ${name}. We have your details and a member of our team will be in touch about next steps.`);
    return [
      `${name}: we've received your sponsorship interest`,
      lines.join('\n'),
      [{ label: `Visit ${name}`, url: `${siteUrl(env)}/index.html` }],
    ];
  }
  lines.push(`Thanks for registering for ${name}. Here is what we have:`, '');
  lines.push(`Pass: ${PASS_LABEL[t.pass]}`);
  if (t.persona === 'group') lines.push(`Group size: ${t.attendeeCount}`);
  lines.push(`Amount: ${rs(t.amountPkr)}`);
  lines.push(`Payment method: ${METHOD_LABEL[t.payMethod]}`, '');
  if (t.payMethod === 'cash') {
    lines.push('Your registration is pending until we receive your cash payment in person. We will email you again as soon as it is confirmed.');
  } else {
    lines.push('Your payment is pending verification. One of our organisers will check your name, email and receipt, and we will email you again as soon as it is confirmed.');
  }
  lines.push('', `You can check the status any time by signing in at ${siteUrl(env)}/account.html`, '', `${name} organising team`);
  return [
    `${name}: your payment is pending verification`,
    lines.join('\n'),
    [
      { label: 'View my registration', url: `${siteUrl(env)}/account.html` },
      { label: 'Event info', url: `${siteUrl(env)}/info.html` },
    ],
  ];
}

function confirmedEmail(env, user, t) {
  const name = siteName(env);
  const lines = [
    `Hi ${user.name},`,
    '',
    `Good news: your payment of ${rs(t.amountPkr)} has been confirmed and your place at ${name} is booked.`,
    '',
    `Pass: ${PASS_LABEL[t.pass]}`,
  ];
  if (t.persona === 'group') lines.push(`Group size: ${t.attendeeCount}`);
  lines.push(
    '',
    'See you at Beaconhouse Cantt Campus, Multan, on 18 and 19 October.',
    '',
    `You can see your registration any time at ${siteUrl(env)}/account.html`,
    '',
    `${name} organising team`
  );
  return [
    `${name}: your payment is confirmed`,
    lines.join('\n'),
    [
      { label: 'View my registration', url: `${siteUrl(env)}/account.html` },
      { label: 'Event info', url: `${siteUrl(env)}/info.html` },
    ],
  ];
}

async function notifyOrganisers(ctx, user, t) {
  const { env, sendEmail } = ctx;
  const details = [
    `Persona: ${t.persona}`,
    `Pass: ${PASS_LABEL[t.pass]}`,
    `Amount: ${rs(t.amountPkr)}`,
    `Payment: ${METHOD_LABEL[t.payMethod] || 'n/a'}`,
    t.persona === 'group' ? `Group size: ${t.attendeeCount}` : '',
    t.receipt ? 'Receipt attached: open the admin panel to review it' : '',
  ].filter(Boolean).join(' | ');
  const params = {
    name: user.name,
    email: user.email,
    form_type: t.status === 'interest' ? 'Sponsor interest' : 'Ticket submitted (payment pending)',
    details,
    message: '',
  };
  if (env.DEV_MODE === '1') {
    await devOutbox(env, { kind: 'organiser', ...params });
    return;
  }
  await sendEmail(env, env.EMAILJS_NOTIFY_TEMPLATE_ID, params);
}

// ---------- admin: review tickets and confirm payments ----------
// Auth is the existing admin bearer token (see index.js); `isAdmin` checks it.

export async function handleAdminTickets(ctx) {
  const { request, env, url, body, cors, json, isAdmin } = ctx;
  const fail = (msg, status) => json({ ok: false, error: msg }, status, cors);
  if (!env.DB) return fail('Accounts are not configured on this server', 503);
  if (!(await isAdmin(request))) return fail('Not signed in', 401);

  if (url.pathname === '/admin/tickets') {
    const { results } = await env.DB.prepare(
      `SELECT t.id, u.name, u.email, t.persona, t.pass, t.amount_pkr AS amountPkr, t.pay_method AS payMethod,
              t.status, t.attendee_count AS attendeeCount, t.group_names AS groupNames,
              t.hear_about AS hearAbout, t.sponsor_tier AS sponsorTier,
              t.submitted_at AS submittedAt, t.confirmed_at AS confirmedAt,
              (t.receipt IS NOT NULL) AS hasReceipt
         FROM tickets t JOIN users u ON u.id = t.user_id
        ORDER BY (t.status = 'pending') DESC, t.submitted_at DESC`
    ).all();
    return json({ ok: true, tickets: results.map((r) => ({ ...r, hasReceipt: !!r.hasReceipt })) }, 200, cors);
  }

  const id = Number.parseInt(body.id, 10);
  if (!Number.isInteger(id)) return fail('Missing ticket id', 400);

  if (url.pathname === '/admin/ticket-receipt') {
    const row = await env.DB.prepare('SELECT receipt FROM tickets WHERE id = ?').bind(id).first();
    if (!row) return fail('Ticket not found', 404);
    if (!row.receipt) return fail('No receipt on this ticket', 404);
    return json({ ok: true, receipt: row.receipt }, 200, cors);
  }

  if (url.pathname === '/admin/ticket-confirm') {
    const row = await env.DB.prepare(
      `SELECT t.id, t.persona, t.pass, t.amount_pkr AS amountPkr, t.attendee_count AS attendeeCount,
              t.status, u.name, u.email
         FROM tickets t JOIN users u ON u.id = t.user_id WHERE t.id = ?`
    ).bind(id).first();
    if (!row) return fail('Ticket not found', 404);
    if (row.status === 'interest') return fail('Sponsor interest has no payment to confirm', 400);
    if (row.status === 'confirmed') return json({ ok: true, alreadyConfirmed: true }, 200, cors);

    // Only move pending -> confirmed, atomically, so a double click cannot email twice.
    const res = await env.DB.prepare(
      "UPDATE tickets SET status = 'confirmed', confirmed_at = ? WHERE id = ? AND status = 'pending'"
    ).bind(new Date().toISOString(), id).run();
    if (!res.meta.changes) return json({ ok: true, alreadyConfirmed: true }, 200, cors);

    let emailSent = true;
    try {
      const [subject, message, buttons] = confirmedEmail(env, { name: row.name }, row);
      await sendUserEmail(ctx, row.email, row.name, subject, message, '', buttons);
    } catch (err) {
      console.log('sendEmail (confirmed) failed:', err.message);
      emailSent = false;
    }
    return json({ ok: true, emailSent }, 200, cors);
  }

  return fail('Not found', 404);
}

// ---------- the routes ----------

export async function handleAccount(ctx) {
  const { request, env, url, body, cors, json, checkRateLimit, sendEmail } = ctx;
  const path = url.pathname;
  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  const fail = (msg, status) => json({ ok: false, error: msg }, status, cors);
  const ok = (extra) => json({ ok: true, ...(extra || {}) }, 200, cors);

  if (!env.DB) return fail('Accounts are not configured on this server', 503);
  if (!env.PEPPER) return fail('Accounts are not configured on this server', 503);

  // Local testing only: with DEV_MODE=1 the code is returned in the response
  // instead of being emailed. Never set DEV_MODE in the production config.
  const isDev = env.DEV_MODE === '1';

  async function deliverCode(email, name, purpose, code) {
    if (isDev) return { devCode: code };
    const subject = `${siteName(env)}: your verification code`;
    const message =
      `Hi ${name},\n\nYour ${siteName(env)} code for "${purpose}" is ${code}. ` +
      'It expires in 10 minutes. If you did not ask for this, you can ignore this email.';
    await sendUserEmail(ctx, email, name, subject, message, code);
    return {};
  }

  // ----- sign-up, step 1: validate, stash the pending account, email a code -----
  if (path === '/account/signup/request') {
    const email = cleanEmail(body.email);
    const name = cleanName(body.name);
    if (!email) return fail('Enter a valid email address', 400);
    if (!name) return fail('Enter your name', 400);
    const problem = passwordProblem(body.password, email);
    if (problem) return fail(problem, 400);

    if (!(await checkRateLimit(env, `rl:acct-signup-ip:${ip}`, 10, 3600))) {
      return fail('Too many attempts. Please try again later', 429);
    }
    if (!(await checkRateLimit(env, `rl:acct-signup-email:${email}`, 3, 600))) {
      return fail('Too many code requests for this email. Please wait a few minutes', 429);
    }

    const existing = await env.DB.prepare('SELECT id FROM users WHERE email = ?').bind(email).first();
    if (existing) {
      // Same answer as a fresh sign-up, so this cannot be used to find out who has an account.
      return ok();
    }

    const code = secureCode();
    await env.CODES.put(
      `acct-signup:${email}`,
      JSON.stringify({ code, attempts: 0, name, pwHash: await hashPassword(env, body.password) }),
      { expirationTtl: CODE_TTL_S }
    );
    try {
      return ok(await deliverCode(email, name, 'Account sign-up', code));
    } catch (err) {
      console.log('sendEmail (signup code) failed:', err.message);
      return fail('Could not send the verification email', 502);
    }
  }

  // ----- sign-up, step 2: check the code, create the account, sign in -----
  if (path === '/account/signup/verify') {
    const email = cleanEmail(body.email);
    if (!email || !body.code) return fail('Missing email or code', 400);

    const key = `acct-signup:${email}`;
    const raw = await env.CODES.get(key);
    if (!raw) return fail('Code expired or not found. Please start again', 404);
    const pending = JSON.parse(raw);
    if (pending.attempts >= MAX_CODE_ATTEMPTS) {
      await env.CODES.delete(key);
      return fail('Too many attempts. Please start again', 429);
    }
    if (!safeEqualStr(pending.code, String(body.code).trim())) {
      pending.attempts += 1;
      await env.CODES.put(key, JSON.stringify(pending), { expirationTtl: CODE_TTL_S });
      return fail('Incorrect code', 401);
    }
    await env.CODES.delete(key);

    const now = new Date().toISOString();
    let userId;
    try {
      const res = await env.DB.prepare(
        'INSERT INTO users (email, name, pw_hash, created_at, email_verified_at) VALUES (?, ?, ?, ?, ?)'
      )
        .bind(email, pending.name, pending.pwHash, now, now)
        .run();
      userId = res.meta.last_row_id;
    } catch (err) {
      // The UNIQUE constraint on email: someone finished a sign-up for it first.
      if (/UNIQUE/i.test(String(err.message))) return fail('An account with this email already exists', 409);
      throw err;
    }

    const token = await createSession(env, userId);
    return ok({ token, user: { email, name: pending.name, createdAt: now } });
  }

  // ----- login -----
  if (path === '/account/login') {
    const email = cleanEmail(body.email);
    const password = typeof body.password === 'string' ? body.password : '';
    if (!email || !password || password.length > 128) return fail('Incorrect email or password', 401);

    if (!(await checkRateLimit(env, `rl:acct-login-ip:${ip}`, 20, 600))) {
      return fail('Too many attempts. Please wait a few minutes and try again', 429);
    }
    if (!(await checkRateLimit(env, `rl:acct-login-email:${email}`, 8, 600))) {
      return fail('Too many attempts for this account. Please wait a few minutes and try again', 429);
    }

    const user = await env.DB.prepare(
      'SELECT id, email, name, pw_hash AS pwHash, created_at AS createdAt FROM users WHERE email = ?'
    )
      .bind(email)
      .first();

    const good = await verifyPassword(env, password, user ? user.pwHash : DUMMY_HASH);
    if (!user || !good) return fail('Incorrect email or password', 401);

    const token = await createSession(env, user.id);
    return ok({ token, user: publicUser(user) });
  }

  // ----- password reset -----
  if (path === '/account/password/forgot') {
    const email = cleanEmail(body.email);
    if (!email) return fail('Enter a valid email address', 400);
    if (!(await checkRateLimit(env, `rl:acct-reset-ip:${ip}`, 10, 3600))) {
      return fail('Too many attempts. Please try again later', 429);
    }
    if (!(await checkRateLimit(env, `rl:acct-reset-email:${email}`, 3, 600))) {
      return fail('Too many requests for this email. Please wait a few minutes', 429);
    }

    const user = await env.DB.prepare('SELECT id, name FROM users WHERE email = ?').bind(email).first();
    if (!user) return ok(); // identical response whether or not the account exists

    const code = secureCode();
    await env.CODES.put(`acct-reset:${email}`, JSON.stringify({ code, attempts: 0 }), {
      expirationTtl: CODE_TTL_S,
    });
    try {
      return ok(await deliverCode(email, user.name, 'Password reset', code));
    } catch (err) {
      console.log('sendEmail (reset code) failed:', err.message);
      return fail('Could not send the verification email', 502);
    }
  }

  if (path === '/account/password/reset') {
    const email = cleanEmail(body.email);
    if (!email || !body.code) return fail('Missing email or code', 400);
    const problem = passwordProblem(body.newPassword, email);
    if (problem) return fail(problem, 400);

    const key = `acct-reset:${email}`;
    const raw = await env.CODES.get(key);
    if (!raw) return fail('Code expired or not found. Please request a new one', 404);
    const rec = JSON.parse(raw);
    if (rec.attempts >= MAX_CODE_ATTEMPTS) {
      await env.CODES.delete(key);
      return fail('Too many attempts. Please request a new code', 429);
    }
    if (!safeEqualStr(rec.code, String(body.code).trim())) {
      rec.attempts += 1;
      await env.CODES.put(key, JSON.stringify(rec), { expirationTtl: CODE_TTL_S });
      return fail('Incorrect code', 401);
    }
    await env.CODES.delete(key);

    const user = await env.DB.prepare('SELECT id FROM users WHERE email = ?').bind(email).first();
    if (!user) return fail('Code expired or not found. Please request a new one', 404);

    const pwHash = await hashPassword(env, body.newPassword);
    await env.DB.batch([
      env.DB.prepare('UPDATE users SET pw_hash = ?, pw_changed_at = ? WHERE id = ?').bind(
        pwHash,
        new Date().toISOString(),
        user.id
      ),
      // A reset signs out every device, in case the old password was compromised.
      env.DB.prepare('DELETE FROM sessions WHERE user_id = ?').bind(user.id),
    ]);
    return ok();
  }

  // ----- everything below needs a valid session -----
  const me = await authenticate(env, request);
  if (!me) return fail('Not signed in', 401);

  if (path === '/account/logout') {
    await env.DB.prepare('DELETE FROM sessions WHERE token_hash = ?').bind(me.tokenHash).run();
    return ok();
  }

  if (path === '/account/me') {
    const row = await env.DB.prepare(
      `SELECT persona, pass, amount_pkr AS amountPkr, pay_method AS payMethod, status,
              attendee_count AS attendeeCount, submitted_at AS submittedAt, confirmed_at AS confirmedAt,
              (receipt IS NOT NULL) AS hasReceipt
         FROM tickets WHERE user_id = ?`
    )
      .bind(me.id)
      .first();
    return ok({ user: publicUser(me), ticket: row ? { ...row, hasReceipt: !!row.hasReceipt } : null });
  }

  if (path === '/account/update') {
    const name = cleanName(body.name);
    if (!name) return fail('Enter your name', 400);
    await env.DB.prepare('UPDATE users SET name = ? WHERE id = ?').bind(name, me.id).run();
    return ok({ user: publicUser({ ...me, name }) });
  }

  // ----- register for the event: one ticket per account -----
  if (path === '/account/ticket/submit') {
    if (!(await checkRateLimit(env, `rl:acct-ticket:${me.id}`, 15, 3600))) {
      return fail('Too many submissions. Please try again later', 429);
    }
    const t = validateTicket(body);
    if (t.error) return fail(t.error, 400);

    const existing = await env.DB.prepare('SELECT status FROM tickets WHERE user_id = ?').bind(me.id).first();
    if (existing && existing.status === 'confirmed') {
      return fail('Your payment is already confirmed. Contact the organisers if you need to change anything', 409);
    }

    const now = new Date().toISOString();
    await env.DB.prepare(
      `INSERT INTO tickets (user_id, persona, hear_about, attendee_count, group_names, sponsor_tier,
                            pass, amount_pkr, pay_method, receipt, status, submitted_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT(user_id) DO UPDATE SET persona = excluded.persona, hear_about = excluded.hear_about,
         attendee_count = excluded.attendee_count, group_names = excluded.group_names,
         sponsor_tier = excluded.sponsor_tier, pass = excluded.pass, amount_pkr = excluded.amount_pkr,
         pay_method = excluded.pay_method, receipt = excluded.receipt, status = excluded.status,
         submitted_at = excluded.submitted_at`
    )
      .bind(me.id, t.persona, t.hearAbout, t.attendeeCount, t.groupNames, t.sponsorTier,
            t.pass, t.amountPkr, t.payMethod, t.receipt, t.status, now)
      .run();

    // The two emails are best-effort: the ticket is saved either way, and the
    // admin panel shows it whether or not these send.
    const warnings = [];
    try {
      const [subject, message, buttons] = pendingEmail(env, me, t);
      await sendUserEmail(ctx, me.email, me.name, subject, message, '', buttons);
    } catch (err) {
      console.log('sendEmail (pending) failed:', err.message);
      warnings.push('confirmation-email');
    }
    try {
      await notifyOrganisers(ctx, me, t);
    } catch (err) {
      console.log('notify organisers failed:', err.message);
    }

    return ok({
      ticket: { persona: t.persona, pass: t.pass, amountPkr: t.amountPkr, payMethod: t.payMethod,
                status: t.status, attendeeCount: t.attendeeCount, submittedAt: now, hasReceipt: !!t.receipt },
      warnings,
    });
  }

  if (path === '/account/delete') {
    const password = typeof body.password === 'string' ? body.password : '';
    if (!password || password.length > 128) return fail('Enter your password to delete your account', 400);
    if (!(await checkRateLimit(env, `rl:acct-delete:${me.id}`, 5, 600))) {
      return fail('Too many attempts. Please wait a few minutes', 429);
    }
    const row = await env.DB.prepare('SELECT pw_hash AS pwHash FROM users WHERE id = ?').bind(me.id).first();
    if (!row || !(await verifyPassword(env, password, row.pwHash))) return fail('Incorrect password', 401);
    // A confirmed ticket is the organisers' record of a payment, so it is kept.
    const paid = await env.DB.prepare("SELECT 1 AS x FROM tickets WHERE user_id = ? AND status = 'confirmed'")
      .bind(me.id)
      .first();
    if (paid) return fail('Your payment is confirmed, so this account cannot be deleted online. Please contact the organisers', 409);
    await env.DB.batch([
      env.DB.prepare('DELETE FROM sessions WHERE user_id = ?').bind(me.id),
      env.DB.prepare('DELETE FROM tickets WHERE user_id = ?').bind(me.id),
      env.DB.prepare('DELETE FROM users WHERE id = ?').bind(me.id),
    ]);
    return ok();
  }

  return fail('Not found', 404);
}
