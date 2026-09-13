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
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
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

    return json({ ok: false, error: 'Not found' }, 404, cors);
  },
};
