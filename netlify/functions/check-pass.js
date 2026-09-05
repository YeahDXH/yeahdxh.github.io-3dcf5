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

    // Read SECRET_PAGE from env and normalize it.
    let secretPage = (process.env.SECRET_PAGE || '').trim();

    // If env not set, default to the original internal secret page
    if (!secretPage) secretPage = '/043a718774c572bd8a25adbeb1bfcd5c0256ae11cecf9f9c3f925d0e52beaf893f79bb7b435b05321651daefd374cdc681dc06faa65e374e38337b88ca046dea2e7d2c03a9507ae265ecf5b5356885a53393a2029d241394997265a1a25aefc6454349e422f05297191ead13e21d3db520e5abef52055e4964b82fb213f593a13f79bb7b435b05321651daefd374cdc681dc06faa65e374e38337b88ca046deae3b98a4da31a127d4bde6e43033f66ba274cab0eb7eb1c70ec41402bf6273dd8.html.html';

    // If it's an absolute URL, redirect as-is
    if (/^https?:\/\//i.test(secretPage)) {
      return { statusCode: 302, headers: { Location: secretPage }, body: '' };
    }

    // Otherwise treat as an internal path. Ensure it starts with '/'
    if (!secretPage.startsWith('/')) {
      // If the value looks like a bare filename without an extension, append .html
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
