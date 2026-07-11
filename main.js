/**
 * Contact form + theme toggle.
 *
 * The form POSTs { name, email, message } as JSON to CONTACT_ENDPOINT — the
 * bundled Cloudflare Function at functions/api/contact.js — which validates it
 * and forwards it to the email provider using a secret kept off the client.
 *
 * TURNSTILE_SITE_KEY: optional Cloudflare Turnstile spam check. Paste your public
 * site key and set TURNSTILE_SECRET_KEY on the backend to switch it on; leave it
 * empty and the form still relies on the honeypot + server-side validation.
 */
const CONTACT_ENDPOINT = '/api/contact';
const TURNSTILE_SITE_KEY = '';
const CONTACT_ADDRESS = 'contact@viktorhalushka.dev';

/* ---------- Theme ---------- */

const root = document.documentElement;
const toggle = document.getElementById('theme-toggle');

const applyTheme = (theme) => {
  root.dataset.theme = theme;
  toggle.setAttribute('aria-pressed', String(theme === 'dark'));
};

applyTheme(root.dataset.theme);

toggle.addEventListener('click', () => {
  const next = root.dataset.theme === 'dark' ? 'light' : 'dark';
  applyTheme(next);
  try {
    localStorage.setItem('theme', next);
  } catch (e) {}
});

// Follow the OS until the visitor makes an explicit choice.
matchMedia('(prefers-color-scheme: dark)').addEventListener('change', (e) => {
  let stored = null;
  try {
    stored = localStorage.getItem('theme');
  } catch (err) {}
  if (!stored) applyTheme(e.matches ? 'dark' : 'light');
});

/* ---------- Contact form ---------- */

const form = document.getElementById('contact-form');
const success = document.getElementById('contact-success');
const error = document.getElementById('contact-error');
const submit = form.querySelector('button[type="submit"]');

const showError = (html) => {
  error.innerHTML = html
    || `<span class="error-lead">Something went wrong sending that.</span> Please email me directly at <a href="mailto:${CONTACT_ADDRESS}">${CONTACT_ADDRESS}</a>.`;
  error.hidden = false;
};

// Cloudflare Turnstile — loaded only when a site key is configured.
let turnstileWidget = null;
if (TURNSTILE_SITE_KEY) {
  window.onTurnstileLoad = () => {
    turnstileWidget = window.turnstile.render('#turnstile', { sitekey: TURNSTILE_SITE_KEY });
  };
  const s = document.createElement('script');
  s.src = 'https://challenges.cloudflare.com/turnstile/v0/api.js?onload=onTurnstileLoad&render=explicit';
  s.async = true;
  s.defer = true;
  document.head.appendChild(s);
}

form.addEventListener('submit', async (event) => {
  event.preventDefault();
  if (!form.reportValidity()) return;

  const payload = Object.fromEntries(new FormData(form));
  error.hidden = true;

  // Attach the Turnstile token; block submission until the challenge is solved.
  if (TURNSTILE_SITE_KEY) {
    const token = turnstileWidget !== null ? window.turnstile.getResponse(turnstileWidget) : '';
    if (!token) {
      showError('Please complete the spam check, then try again.');
      return;
    }
    payload['cf-turnstile-response'] = token;
  }

  submit.disabled = true;
  submit.textContent = 'Sending…';

  try {
    const response = await fetch(CONTACT_ENDPOINT, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
      body: JSON.stringify(payload),
    });
    let data = {};
    try { data = await response.json(); } catch (e) {}
    if (!response.ok || data.success === false) {
      throw new Error(data.message || `Request failed: ${response.status}`);
    }
    form.hidden = true;
    success.hidden = false;
  } catch (err) {
    showError();
    submit.disabled = false;
    submit.textContent = 'Send message';
    // A token is single-use — reset so the visitor can retry.
    if (TURNSTILE_SITE_KEY && turnstileWidget !== null) window.turnstile.reset(turnstileWidget);
  }
});
