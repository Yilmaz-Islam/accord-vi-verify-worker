// Accord VI email verification worker.
//
// Two endpoints, both POST, both JSON:
//   /request-code  { name, email, form_type, details, message }
//     -> generates a 6-digit code, stores the submission in KV for 10
//        minutes, emails the code to the submitter. Nothing reaches the
//        organizer inbox at this point.
//   /verify-code    { email, code }
//     -> if the code matches what's stored, sends the real notification
//        to the organizer inbox and deletes the KV entry. Wrong/expired
//        codes never trigger that notification.
//
// The EmailJS "code" template doubles as the submitter-facing email
// (EmailJS's free plan caps templates at 2, and the organizer-notification
// template already uses one of them).

function corsHeaders(origin, env) {
  const allowed = env.ALLOWED_ORIGINS.split(',').map((s) => s.trim());
  const allow = allowed.includes(origin) ? origin : allowed[0];
  return {
    'Access-Control-Allow-Origin': allow,
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    // Authorization carries the admin bearer token (see below).
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
  };
}

function json(data, status, headers) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...headers },
  });
}

function generateCode() {
  return String(Math.floor(100000 + Math.random() * 900000));
}

// Simple fixed-window counter in the same KV namespace as the codes
// themselves — good enough to stop casual abuse (someone hammering the
// endpoint to spam an inbox or run up the EmailJS quota), not meant to
// withstand a distributed attack. Two limits stack: per-IP catches one
// attacker cycling through many email addresses, per-email catches
// someone spamming a single victim's inbox with code emails.
async function checkRateLimit(env, key, limit, windowSeconds) {
  const raw = await env.CODES.get(key);
  const count = raw ? parseInt(raw, 10) : 0;
  if (count >= limit) return false;
  await env.CODES.put(key, String(count + 1), { expirationTtl: windowSeconds });
  return true;
}

async function sendEmail(env, templateId, params) {
  const res = await fetch('https://api.emailjs.com/api/v1.0/email/send', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      service_id: env.EMAILJS_SERVICE_ID,
      template_id: templateId,
      user_id: env.EMAILJS_PUBLIC_KEY,
      accessToken: env.EMAILJS_PRIVATE_KEY,
      template_params: params,
    }),
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`EmailJS send failed (${res.status}): ${text}`);
  }
}

// ---------- Admin session: a signed, expiring bearer token ----------
// No session store — the token itself carries an expiry plus an HMAC
// over that expiry, keyed on the admin password. Valid until it expires
// or the password is rotated (which invalidates every outstanding
// session at once, by design). Web Crypto (crypto.subtle) is available
// natively in the Workers runtime, no extra dependency.
//
// This is a bearer token in localStorage, not a cookie: the admin page
// (github.io) and this worker (workers.dev) are different sites, and
// browsers that block third-party cookies (Safari by default, and a
// growing number of others) silently refuse to persist a cookie set
// from a cross-site fetch response — which broke sign-in for exactly
// those visitors under the old cookie-based version. A bearer token
// sent via the Authorization header isn't subject to that policy at all.
async function hmacSign(secret, message) {
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(message));
  return btoa(String.fromCharCode(...new Uint8Array(sig)))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

const SESSION_TTL_MS = 12 * 60 * 60 * 1000; // 12 hours

async function makeSessionToken(env) {
  const expires = Date.now() + SESSION_TTL_MS;
  const sig = await hmacSign(env.ADMIN_PASSWORD, String(expires));
  return `${expires}.${sig}`;
}

async function verifySessionToken(env, token) {
  if (!token) return false;
  const parts = token.split('.');
  if (parts.length !== 2) return false;
  const [expiresStr, sig] = parts;
  const expires = parseInt(expiresStr, 10);
  if (!expires || Date.now() > expires) return false;
  const expected = await hmacSign(env.ADMIN_PASSWORD, expiresStr);
  return expected === sig;
}

function bearerToken(request) {
  const header = request.headers.get('Authorization') || '';
  return header.startsWith('Bearer ') ? header.slice(7) : '';
}

export default {
  async fetch(request, env) {
    const origin = request.headers.get('Origin') || '';
    const cors = corsHeaders(origin, env);

    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: cors });
    }
    if (request.method !== 'POST') {
      return json({ ok: false, error: 'Method not allowed' }, 405, cors);
    }

    const url = new URL(request.url);
    let body;
    try {
      body = await request.json();
    } catch {
      return json({ ok: false, error: 'Invalid JSON body' }, 400, cors);
    }

    if (url.pathname === '/request-code') {
      const { name, email, form_type, details, message } = body;
      if (!name || !email || !form_type) {
        return json({ ok: false, error: 'Missing required fields' }, 400, cors);
      }
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
        return json({ ok: false, error: 'Invalid email address' }, 400, cors);
      }

      const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
      const ipOk = await checkRateLimit(env, `rl:ip:${ip}`, 10, 3600);
      if (!ipOk) {
        return json({ ok: false, error: 'Too many requests — please try again later' }, 429, cors);
      }
      const emailOk = await checkRateLimit(env, `rl:email:${email.toLowerCase()}`, 3, 600);
      if (!emailOk) {
        return json({ ok: false, error: 'Too many code requests for this email — please wait a few minutes and try again' }, 429, cors);
      }

      const code = generateCode();
      const key = `code:${email.toLowerCase()}`;
      await env.CODES.put(
        key,
        JSON.stringify({ code, attempts: 0, name, email, form_type, details, message }),
        { expirationTtl: 600 }
      );

      try {
        await sendEmail(env, env.EMAILJS_CODE_TEMPLATE_ID, {
          name,
          email,
          form_type,
          code,
        });
      } catch (err) {
        console.log('sendEmail (code) failed:', err.message);
        return json({ ok: false, error: 'Could not send verification email' }, 502, cors);
      }

      return json({ ok: true }, 200, cors);
    }

    if (url.pathname === '/verify-code') {
      const { email, code } = body;
      if (!email || !code) {
        return json({ ok: false, error: 'Missing email or code' }, 400, cors);
      }

      const key = `code:${email.toLowerCase()}`;
      const raw = await env.CODES.get(key);
      if (!raw) {
        return json({ ok: false, error: 'Code expired or not found — please request a new one' }, 404, cors);
      }

      const record = JSON.parse(raw);

      if (record.attempts >= 5) {
        await env.CODES.delete(key);
        return json({ ok: false, error: 'Too many attempts — please request a new code' }, 429, cors);
      }

      if (record.code !== String(code).trim()) {
        record.attempts += 1;
        await env.CODES.put(key, JSON.stringify(record), { expirationTtl: 600 });
        return json({ ok: false, error: 'Incorrect code' }, 401, cors);
      }

      await env.CODES.delete(key);

      // Permanent log entry for the admin portal — separate from the
      // `code:` entry above (which is transient, TTL'd, and just deleted).
      // No expirationTtl here: this is meant to last. Timestamp-first key
      // means CODES.list({ prefix: 'reg:' }) comes back in chronological
      // order for free (ISO-8601 strings sort the same as the instants
      // they name). Written before the notify email, and regardless of
      // whether that email succeeds below — the verification itself is
      // what happened; a flaky notify send shouldn't cost the log entry.
      const submittedAt = new Date().toISOString();
      await env.CODES.put(
        `reg:${submittedAt}:${record.email.toLowerCase()}`,
        JSON.stringify({
          name: record.name,
          email: record.email,
          form_type: record.form_type,
          details: record.details || '',
          message: record.message || '',
          submittedAt,
        })
      );

      try {
        await sendEmail(env, env.EMAILJS_NOTIFY_TEMPLATE_ID, {
          name: record.name,
          email: record.email,
          form_type: record.form_type,
          details: record.details || '',
          message: record.message || '',
        });
      } catch (err) {
        console.log('sendEmail (notify) failed:', err.message);
        return json({ ok: false, error: 'Verified, but notifying the organizers failed — please email us directly' }, 502, cors);
      }

      return json({ ok: true }, 200, cors);
    }

    // ---------- Admin portal: password login + registration log ----------
    if (url.pathname === '/admin/login') {
      const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
      // 20/10min: generous enough that a human mistyping a password (or
      // several execs sharing one campus IP) won't get locked out, while
      // still capping a brute-force guesser at ~2 attempts/minute.
      const ipOk = await checkRateLimit(env, `rl:admin-login:${ip}`, 20, 600);
      if (!ipOk) {
        return json({ ok: false, error: 'Too many attempts — please wait a few minutes and try again' }, 429, cors);
      }

      const { password } = body;
      if (typeof password !== 'string' || password !== env.ADMIN_PASSWORD) {
        return json({ ok: false, error: 'Incorrect password' }, 401, cors);
      }

      const token = await makeSessionToken(env);
      return json({ ok: true, token }, 200, cors);
    }

    if (url.pathname === '/admin/logout') {
      // Stateless token: there's nothing to revoke server-side, this
      // just gives the client a symmetrical endpoint to call.
      return json({ ok: true }, 200, cors);
    }

    if (url.pathname === '/admin/registrations') {
      const valid = await verifySessionToken(env, bearerToken(request));
      if (!valid) {
        return json({ ok: false, error: 'Not signed in' }, 401, cors);
      }

      const list = await env.CODES.list({ prefix: 'reg:' });
      const registrations = await Promise.all(
        list.keys.map(async (k) => {
          const raw = await env.CODES.get(k.name);
          return raw ? JSON.parse(raw) : null;
        })
      );
      registrations.reverse(); // most recent first
      return json({ ok: true, registrations: registrations.filter(Boolean) }, 200, cors);
    }

    return json({ ok: false, error: 'Not found' }, 404, cors);
  },
};
