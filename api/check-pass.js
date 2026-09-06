import crypto from 'crypto';
import querystring from 'querystring';

function normalizeSecretPage(value, fallback) {
  // Normalize a SECRET_PAGE-like value into a safe absolute path or absolute URL.
  // Behavior:
  // - If value is an absolute URL (http(s)://) -> return as-is.
  // - If value starts with a slash -> treat as absolute path and return it (ensure trimmed).
  // - If value contains a dot (e.g. "file.html") but no leading slash -> add leading slash.
  // - If value is a short name without dot or slash (e.g. "thegreatdxhpuzzlesanctuary") ->
  //   assume it's inside the /puzzle/ folder and return "/puzzle/<value>.html".
  let secretPage = (value || fallback || '').trim();
  if (!secretPage) secretPage = fallback || '/';
  if (/^https?:\/\//i.test(secretPage)) return secretPage; // absolute URL unchanged
  if (secretPage.startsWith('/')) return secretPage; // already absolute path

  // If it contains a dot assume it's a filename like "somepage.html" -> add leading slash
  if (secretPage.includes('.')) {
    return '/' + secretPage;
  }

  // Otherwise treat as short name and place under /puzzle/ with .html
  return '/puzzle/' + secretPage + '.html';
}

export default async function handler(req, res) {
  try {
    if (req.method !== 'POST') {
      res.status(405).send('Method Not Allowed');
      return;
    }

    let pass;
    const ct = (req.headers['content-type'] || req.headers['Content-Type'] || '').toLowerCase();
    if (ct.includes('application/json')) {
      pass = req.body && req.body.pass;
    } else if (ct.includes('application/x-www-form-urlencoded')) {
      if (typeof req.body === 'object' && req.body !== null) pass = req.body.pass;
      else {
        const raw = typeof req.body === 'string' ? req.body : '';
        const parsed = querystring.parse(raw || '');
        pass = parsed.pass;
      }
    } else {
      if (typeof req.body === 'object' && req.body !== null) pass = req.body.pass;
      else {
        const raw = typeof req.body === 'string' ? req.body : '';
        const parsed = querystring.parse(raw || '');
        pass = parsed.pass;
      }
    }

    if (!pass) {
      res.status(401).send('<h1>Incorrect passcode</h1>');
      return;
    }

    const passRaw = String(pass);
    const passNorm = passRaw.toLowerCase().trim();

    // Case-insensitive literal for the main puzzle phrase
    if (passNorm === 'start the puzzle') {
      const secretPath = normalizeSecretPage(process.env.SECRET_PAGE, '/puzzle/thegreatdxhpuzzlesanctuary.html');
      let location = secretPath;
      if (!/^https?:\/\//i.test(secretPath)) {
        const host = req.headers['x-forwarded-host'] || req.headers.host || '';
        const proto = req.headers['x-forwarded-proto'] || 'https';
        location = proto + '://' + host + encodeURI(secretPath);
      }
      res.writeHead(302, { Location: location });
      res.end();
      return;
    }

    // Backwards compatibility literal
    if (pass === 'DxhiSCOoL') {
      const secretPath = '/sdfg9804kdhsioug4pfeud89sfpg.html';
      const host = req.headers['x-forwarded-host'] || req.headers.host || '';
      const proto = req.headers['x-forwarded-proto'] || 'https';
      const location = proto + '://' + host + encodeURI(secretPath);
      res.writeHead(302, { Location: location });
      res.end();
      return;
    }

    // Decide which stored value to use (PASS_HASH has priority)
    const storedEnv = ((process.env.PASS_HASH || process.env.PASS_HASH_2) || '').trim();

    // Plaintext env fallback
    if (storedEnv && !/^[0-9a-f]{64}$/i.test(storedEnv)) {
      if (passNorm === storedEnv.toLowerCase().trim()) {
        const secretPath = normalizeSecretPage(process.env.SECRET_PAGE, '/puzzle/thegreatdxhpuzzlesanctuary.html');
        let location = secretPath;
        if (!/^https?:\/\//i.test(secretPath)) {
          const host = req.headers['x-forwarded-host'] || req.headers.host || '';
          const proto = req.headers['x-forwarded-proto'] || 'https';
          location = proto + '://' + host + encodeURI(secretPath);
        }
        res.writeHead(302, { Location: location });
        res.end();
        return;
      }
      res.status(401).send('<h1>Incorrect passcode</h1>');
      return;
    }

    if (!storedEnv || storedEnv.length !== 64) {
      res.status(401).send('<h1>Incorrect passcode</h1>');
      return;
    }

    const hash = crypto.createHash('sha256').update(passRaw, 'utf8').digest('hex');
    let ok = false;
    try {
      ok = crypto.timingSafeEqual(Buffer.from(hash, 'hex'), Buffer.from(storedEnv, 'hex'));
    } catch (e) {
      ok = false;
    }

    if (!ok) {
      res.status(401).send('<h1>Incorrect passcode</h1>');
      return;
    }

    const secretPath = normalizeSecretPage(process.env.SECRET_PAGE, '/puzzle/thegreatdxhpuzzlesanctuary.html');
    let location = secretPath;
    if (!/^https?:\/\//i.test(secretPath)) {
      const host = req.headers['x-forwarded-host'] || req.headers.host || '';
      const proto = req.headers['x-forwarded-proto'] || 'https';
      location = proto + '://' + host + encodeURI(secretPath);
    }
    res.writeHead(302, { Location: location });
    res.end();

  } catch (err) {
    console.error('check-pass error', err);
    res.status(500).send('Server error');
  }
}
