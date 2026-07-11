/**
 * Cloudflare Pages Function — serves POST /api/contact
 *
 * Validates a contact-form submission server-side and forwards it to the email
 * provider using a secret that never reaches the client.
 *
 * Environment variables (Pages project → Settings → Environment variables):
 *   WEB3FORMS_ACCESS_KEY   required  — your web3forms.com key (mark encrypted)
 *   TURNSTILE_SECRET_KEY   optional  — turns on Cloudflare Turnstile spam checks
 *
 * Bindings (Pages project → Settings → Functions → KV namespace bindings):
 *   CONTACT_RL             optional  — a KV namespace; turns on per-IP rate limiting
 *
 * Everything optional degrades gracefully: with only WEB3FORMS_ACCESS_KEY set you
 * still get the honeypot + validation; add the others to harden.
 *
 * Local dev:  npx wrangler pages dev . --binding WEB3FORMS_ACCESS_KEY=<key>
 */

const MAX = { name: 200, email: 320, message: 5000 };
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const RATE = { max: 5, windowSec: 600 }; // max submissions per IP per window

const json = (body, status = 200) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });

// Per-IP fixed-window limiter. Fails open (no KV binding, or a KV error → allow),
// so a storage hiccup never blocks a legitimate visitor.
async function isRateLimited(env, ip) {
  const kv = env.CONTACT_RL;
  if (!kv || !ip) return false;
  try {
    const key = `rl:${ip}`;
    const count = parseInt(await kv.get(key), 10) || 0;
    if (count >= RATE.max) return true;
    await kv.put(key, String(count + 1), { expirationTtl: RATE.windowSec });
    return false;
  } catch {
    return false;
  }
}

// Verifies a Turnstile token with Cloudflare. Skips when unconfigured; fails
// closed (rejects) on a missing token or a verification error.
async function turnstilePassed(env, token, ip) {
  const secret = env.TURNSTILE_SECRET_KEY;
  if (!secret) return true;
  if (!token) return false;
  try {
    const form = new FormData();
    form.append('secret', secret);
    form.append('response', token);
    if (ip) form.append('remoteip', ip);
    const res = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
      method: 'POST',
      body: form,
    });
    const data = await res.json();
    return data.success === true;
  } catch {
    return false;
  }
}

export async function onRequestPost({ request, env }) {
  const ip = request.headers.get('CF-Connecting-IP') || '';

  let data;
  try {
    data = await request.json();
  } catch {
    return json({ success: false, message: 'Invalid request.' }, 400);
  }

  // Throttle before doing any real work, so a flood is cheap to reject.
  if (await isRateLimited(env, ip)) {
    return json({ success: false, message: 'Too many messages — please try again in a few minutes.' }, 429);
  }

  // Honeypot: bots tick the hidden checkbox. Pretend success, send nothing.
  if (data.botcheck) return json({ success: true });

  const name = String(data.name ?? '').trim();
  const email = String(data.email ?? '').trim();
  const message = String(data.message ?? '').trim();

  if (!name || !message || !EMAIL_RE.test(email)) {
    return json({ success: false, message: 'Please fill in every field with a valid email.' }, 422);
  }
  if (name.length > MAX.name || email.length > MAX.email || message.length > MAX.message) {
    return json({ success: false, message: 'One of the fields is too long.' }, 422);
  }

  if (!(await turnstilePassed(env, data['cf-turnstile-response'], ip))) {
    return json({ success: false, message: 'Spam check failed. Please try again.' }, 403);
  }

  const key = env.WEB3FORMS_ACCESS_KEY;
  if (!key) return json({ success: false, message: 'The form is not configured yet.' }, 500);

  let upstream;
  try {
    upstream = await fetch('https://api.web3forms.com/submit', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
      body: JSON.stringify({
        access_key: key,
        subject: `Portfolio enquiry from ${name}`,
        from_name: name,
        name,
        email,
        message,
      }),
    });
  } catch {
    return json({ success: false, message: 'Could not reach the mail service.' }, 502);
  }

  const result = await upstream.json().catch(() => ({}));
  if (!upstream.ok || result.success === false) {
    return json({ success: false, message: 'Could not send your message right now.' }, 502);
  }

  return json({ success: true });
}
