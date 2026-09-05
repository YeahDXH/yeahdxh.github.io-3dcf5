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

    // SPECIAL-CASE: literal passphrase redirect to short secret page
    if (pass === 'DXHISCOOL') {
      const shortSecret = '/sdfg9804kdhsioug4pfeud89sfpg.html';
      return { statusCode: 302, headers: { Location: shortSecret }, body: '' };
    }

    // Compute SHA-256 of submitted pass and compare with stored env var(s)
    const hash = crypto.createHash('sha256').update(pass, 'utf8').digest('hex');

    // Support PASS_HASH or PASS_HASH_2 as a fallback
    const stored = ((process.env.PASS_HASH || process.env.PASS_HASH_2) || '').trim();
    if (!stored || stored.length !== hash.length) {
      return { statusCode: 401, headers: { 'Content-Type': 'text/html' }, body: '<h1>Incorrect passcode</h1>' };
    }

    const ok = crypto.timingSafeEqual(Buffer.from(hash, 'hex'), Buffer.from(stored, 'hex'));
    if (!ok) {
      return { statusCode: 401, headers: { 'Content-Type': 'text/html' }, body: '<h1>Incorrect passcode</h1>' };
    }

    // Read SECRET_PAGE from env and normalize it. Default to the new short secret page.
    let secretPage = (process.env.SECRET_PAGE || '/sdfg9804kdhsioug4pfeud89sfpg.html').trim();

    // If it's an absolute URL, redirect as-is
    if (/^https?:\/\//i.test(secretPage)) {
      return { statusCode: 302, headers: { Location: secretPage }, body: '' };
    }

    // Otherwise treat as an internal path. Ensure it starts with '/'
    if (!secretPage.startsWith('/')) {
      if (!secretPage.includes('.')) {
        secretPage = '/' + secretPage + '.html';
      } else {
        secretPage = '/' + secretPage;
      }
    }

    return { statusCode: 302, headers: { Location: secretPage }, body: '' };

  } catch (err) {
    console.error('check-pass error', err);
    return { statusCode: 500, headers: { 'Content-Type': 'text/plain' }, body: 'Server error' };
  }
};
