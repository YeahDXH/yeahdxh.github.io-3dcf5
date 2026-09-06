const crypto = require('crypto');
const querystring = require('querystring');

// Helper: normalize and build internal path for redirect
function normalizeSecretPage(value, fallback) {
  let secretPage = (value || fallback || '').trim();
  if (!secretPage) secretPage = fallback;
  if (!secretPage) secretPage = '/';
  // absolute URL -> return as-is
  if (/^https?:\/\//i.test(secretPage)) return secretPage;
  if (!secretPage.startsWith('/')) {
    if (!secretPage.includes('.')) secretPage = '/' + secretPage + '.html';
    else secretPage = '/' + secretPage;
  }
  return secretPage;
}

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

    // Normalize pass string for literal comparisons
    const passRaw = String(pass);
    const passNorm = passRaw.toLowerCase().trim();

    // 1) Case-insensitive special-case for the main puzzle phrase
    // Any capitalization of "start the puzzle" will redirect to SECRET_PAGE (or default /puzzle/intro.html)
    if (passNorm === 'start the puzzle') {
      const secret = normalizeSecretPage(process.env.SECRET_PAGE, '/puzzle/intro.html');
      return { statusCode: 302, headers: { Location: secret }, body: '' };
    }

    // 1b) Backwards compatibility: literal mixed-case DxhiSCOoL (keeps prior behaviour)
    if (pass === 'DxhiSCOoL') {
      return { statusCode: 302, headers: { Location: '/sdfg9804kdhsioug4pfeud89sfpg.html' }, body: '' };
    }

    // 2) Support plaintext env values as direct passcodes (case-insensitive), otherwise fall back to hash comparison.
    const storedEnv = ((process.env.PASS_HASH || process.env.PASS_HASH_2) || '').trim();

    // If storedEnv exists and does NOT look like a 64-char hex, treat it as a plaintext passcode
    if (storedEnv && !/^[0-9a-f]{64}$/i.test(storedEnv)) {
      if (passNorm === storedEnv.toLowerCase().trim()) {
        const secret = normalizeSecretPage(process.env.SECRET_PAGE, '/sdfg9804kdhsioug4pfeud89sfpg.html');
        return { statusCode: 302, headers: { Location: secret }, body: '' };
      }
      return { statusCode: 401, headers: { 'Content-Type': 'text/html' }, body: '<h1>Incorrect passcode</h1>' };
    }

    // 3) Hashed flow (storedEnv is expected to be a SHA-256 hex)
    if (!storedEnv || storedEnv.length !== 64) {
      // nothing useful configured for hashing
      return { statusCode: 401, headers: { 'Content-Type': 'text/html' }, body: '<h1>Incorrect passcode</h1>' };
    }

    const hash = crypto.createHash('sha256').update(passRaw, 'utf8').digest('hex');

    // timing-safe compare
    const ok = crypto.timingSafeEqual(Buffer.from(hash, 'hex'), Buffer.from(storedEnv, 'hex'));
    if (!ok) {
      return { statusCode: 401, headers: { 'Content-Type': 'text/html' }, body: '<h1>Incorrect passcode</h1>' };
    }

    // Success — redirect to SECRET_PAGE (or default short secret page)
    const secret = normalizeSecretPage(process.env.SECRET_PAGE, '/sdfg9804kdhsioug4pfeud89sfpg.html');
    return { statusCode: 302, headers: { Location: secret }, body: '' };

  } catch (err) {
    console.error('check-pass error', err);
    return { statusCode: 500, headers: { 'Content-Type': 'text/plain' }, body: 'Server error' };
  }
};
