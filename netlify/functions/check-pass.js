const crypto = require('crypto');
const querystring = require('querystring');

exports.handler = async (event) => {
  try {
    // Parse pass from either JSON body or urlencoded form body
    const headers = event.headers || {};
    const contentType = (headers['content-type'] || headers['Content-Type'] || '').toLowerCase();
    let pass;

    if (contentType.includes('application/json')) {
      const body = JSON.parse(event.body || '{}');
      pass = body.pass;
    } else if (contentType.includes('application/x-www-form-urlencoded')) {
      const parsed = querystring.parse(event.body || '');
      pass = parsed.pass;
    } else {
      // Fallback: try JSON then urlencoded
      try {
        const body = JSON.parse(event.body || '{}');
        pass = body.pass;
      } catch (e) {
        const parsed = querystring.parse(event.body || '');
        pass = parsed.pass;
      }
    }

    if (!pass) {
      return {
        statusCode: 401,
        headers: { 'Content-Type': 'text/html' },
        body: '<h1>Incorrect passcode</h1>'
      };
    }

    // Compute SHA-256 of submitted passcode and compare
    const hash = crypto.createHash('sha256').update(pass, 'utf8').digest('hex');
    const stored = (process.env.PASS_HASH || '').trim();

    if (!stored || stored.length !== hash.length) {
      return {
        statusCode: 401,
        headers: { 'Content-Type': 'text/html' },
        body: '<h1>Incorrect passcode</h1>'
      };
    }

    const ok = crypto.timingSafeEqual(Buffer.from(hash, 'hex'), Buffer.from(stored, 'hex'));

    if (!ok) {
      return {
        statusCode: 401,
        headers: { 'Content-Type': 'text/html' },
        body: '<h1>Incorrect passcode</h1>'
      };
    }

    // Success: redirect to the secret URL stored in the environment variable
    const mediaUrl = process.env.SECRET_URL;
    if (!mediaUrl) {
      return {
        statusCode: 500,
        headers: { 'Content-Type': 'text/plain' },
        body: 'Media URL not configured'
      };
    }

    return {
      statusCode: 302,
      headers: {
        Location: mediaUrl
      },
      body: ''
    };
  } catch (err) {
    return {
      statusCode: 500,
      headers: { 'Content-Type': 'text/plain' },
      body: 'Server error'
    };
  }
};
