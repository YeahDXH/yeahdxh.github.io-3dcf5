const crypto = require('crypto');
const querystring = require('querystring');

exports.handler = async (event) => {
  try {
    const headers = event.headers || {};
    const contentType = (headers['content-type'] || headers['Content-Type'] || '').toLowerCase();
    const body = event.body || '';
    let pass, code;

    if (contentType.includes('application/json')) {
      const parsed = JSON.parse(body || '{}');
      pass = parsed.pass;
      code = parsed.code;
    } else {
      const parsed = querystring.parse(body || '');
      pass = parsed.pass;
      code = parsed.code;
    }

    // If a token/code was submitted, verify it and show a success page (no redirect to external URL)
    if (code !== undefined && code !== null) {
      const codeTrim = ('' + code).trim();

      // Determine expected token: prefer SECRET_TOKEN, fallback to extract from SECRET_URL if it's a MediaFire link
      let expectedToken = (process.env.SECRET_TOKEN || '').trim();
      if (!expectedToken) {
        const su = (process.env.SECRET_URL || '').trim();
        const m = su.match(/\/file\/([^\/]+)\//);
        if (m) expectedToken = m[1];
      }

      if (expectedToken && codeTrim === expectedToken) {
        const html = `<!doctype html><html><head><meta charset="utf-8"><title>Access granted</title></head><body style="font-family: Arial, sans-serif; padding:2rem;"><h1>Access granted</h1><p>Your token is correct. Well done.</p></body></html>`;
        return { statusCode: 200, headers: { 'Content-Type': 'text/html' }, body: html };
      }

      // incorrect code
      const html = `<!doctype html><html><head><meta charset="utf-8"><title>Incorrect token</title></head><body style="font-family: Arial, sans-serif; padding:2rem;"><h1>Incorrect token</h1><p>The token you entered is incorrect. Please try again.</p><p><a href="javascript:history.back()">Go back</a></p></body></html>`;
      return { statusCode: 200, headers: { 'Content-Type': 'text/html' }, body: html };
    }

    // Otherwise this is a passcode check — verify pass
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

    // Passcode OK — render a page that displays only the clue and a form to submit the solved token.
    const clue = (process.env.CLUE || 'h64hj5bf0yeenz3 13🔥').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    const html = `<!doctype html><html><head><meta charset="utf-8"><title>Clue</title></head><body style="font-family: Arial, sans-serif; padding:2rem;"><h1>Clue</h1><p style="font-size:18px;">${clue}</p><form method="post" action="/.netlify/functions/check-pass" style="margin-top:1rem;"><label>Enter the token you found:<br><input name="code" style="padding:0.4rem; font-size:16px;"></label><div style="margin-top:1rem;"><button type="submit" style="padding:0.5rem 1rem;">Submit token</button></div></form></body></html>`;

    return { statusCode: 200, headers: { 'Content-Type': 'text/html' }, body: html };

  } catch (err) {
    return { statusCode: 500, headers: { 'Content-Type': 'text/plain' }, body: 'Server error' };
  }
};
