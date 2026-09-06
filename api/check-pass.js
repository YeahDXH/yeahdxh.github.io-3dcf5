import crypto from 'crypto';
import querystring from 'querystring';

function normalizeSecretPage(value, fallback) {
  let secretPage = (value || fallback || '').trim();
  if (!secretPage) secretPage = fallback || '/';
  if (/^https?:\/\//i.test(secretPage)) return secretPage;
  if (!secretPage.startsWith('/')) {
    if (!secretPage.includes('.')) secretPage = '/' + secretPage + '.html';
    else secretPage = '/' + secretPage;
  }
  return secretPage;
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
      // If Vercel/Next already parsed the body, req.body may be an object; otherwise try parsing raw
      if (typeof req.body === 'object' && req.body !== null) pass = req.body.pass;
      else {
        const raw = typeof req.body === 'string' ? req.body : '';
        const parsed = querystring.parse(raw || '');
        pass = parsed.pass;
      }
    } else {
      // Try best-effort: check req.body or parse as urlencoded fallback
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
      const secret = normalizeSecretPage(process.env.SECRET_PAGE, '/puzzle/intro.html');
      res.writeHead(302, { Location: secret });
      res.end();
      return;
    }

    // Backwards compatibility literal
    if (pass === 'DxhiSCOoL') {
      res.writeHead(302, { Location: '/sdfg9804kdhsioug4pfeud89sfpg.html' });
      res.end();
      return;
    }

    // Decide which stored value to use (PASS_HASH has priority)
    const storedEnv = ((process.env.PASS_HASH || process.env.PASS_HASH_2) || '').trim();

    // Plaintext env fallback
    if (storedEnv && !/^[0-9a-f]{64}$/i.test(storedEnv)) {
      if (passNorm === storedEnv.toLowerCase().trim()) {
        const secret = normalizeSecretPage(process.env.SECRET_PAGE, '/sdfg9804kdhsioug4pfeud89sfpg.html');
        res.writeHead(302, { Location: secret });
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

    const secret = normalizeSecretPage(process.env.SECRET_PAGE, '/sdfg9804kdhsioug4pfeud89sfpg.html');
    res.writeHead(302, { Location: secret });
    res.end();

  } catch (err) {
    console.error('check-pass error', err);
    res.status(500).send('Server error');
  }
}
