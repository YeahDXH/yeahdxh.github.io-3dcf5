const crypto = require('crypto');
const querystring = require('querystring');

exports.handler = async (event) => {
  try {
    if (event.httpMethod !== 'POST') {
      return { statusCode: 405, headers: { 'Content-Type': 'text/plain' }, body: 'Method Not Allowed' };
    }

    const contentType = (event.headers['content-type'] || event.headers['Content-Type'] || '').toLowerCase();
    let pass;
    if (contentType.includes('application/json')) {
      const parsed = JSON.parse(event.body || '{}');
      pass = parsed.pass;
    } else {
      const parsed = querystring.parse(event.body || '');
      pass = parsed.pass;
    }

    if (!pass) {
      return { statusCode: 401, headers: { 'Content-Type': 'text/html' }, body: '<h1>Incorrect passcode</h1>' };
    }

    const hash = crypto.createHash('sha256').update(pass, 'utf8').digest('hex');
    const stored = (process.env.PASS_HASH || '').trim();
    if (!stored || stored.length !== hash.length) {
      return { statusCode: 401, headers: { 'Content-Type': 'text/html' }, body: '<h1>Incorrect passcode</h1>' };
    }

    const ok = crypto.timingSafeEqual(Buffer.from(hash, 'hex'), Buffer.from(stored, 'hex'));
    if (!ok) {
      return { statusCode: 401, headers: { 'Content-Type': 'text/html' }, body: '<h1>Incorrect passcode</h1>' };
    }

    // If SECRET_PAGE env var is set, redirect there. Otherwise default to the internal secret page.
    const secretPage = (process.env.SECRET_PAGE || '/secret.html').trim();
    // If SECRET_PAGE looks like a full URL (http(s)://) redirect there; otherwise treat as relative internal path
    if (/^https?:\/\//i.test(secretPage)) {
      return { statusCode: 302, headers: { Location: secretPage }, body: '' };
    }

    // Internal redirect to the secret page on the same site
    return { statusCode: 302, headers: { Location: secretPage }, body: '' };

  } catch (err) {
    return { statusCode: 500, headers: { 'Content-Type': 'text/plain' }, body: 'Server error' };
  }
};
