const crypto = require('crypto');

const ALLOWED_FIELDS = [
    'TITLE', 'FIRSTNAME', 'LASTNAME', 'EMAIL', 'EMAIL_CONFIRM',
    'DAY_BIRTHDAY', 'MONTH_BIRTHDAY', 'YEAR_BIRTHDAY',
    'HOUR', 'MINUTES', 'CITY1', 'COUNTRY', 'CITY',
    'majeur', 'SOURCE', 'form_validate'
];

function verifyToken(secret, token, ts) {
    try {
        const expected = crypto.createHmac('sha256', secret).update(ts).digest('hex');
        return crypto.timingSafeEqual(Buffer.from(token, 'hex'), Buffer.from(expected, 'hex'));
    } catch {
        return false;
    }
}

function redirect(path) {
    return { statusCode: 303, headers: { Location: path } };
}

async function verifyRecaptcha(token) {
    const secret = process.env.RECAPTCHA_SECRET_KEY;
    if (!secret || !token) return false;
    try {
        const res = await fetch('https://www.google.com/recaptcha/api/siteverify', {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: `secret=${encodeURIComponent(secret)}&response=${encodeURIComponent(token)}`
        });
        const data = await res.json();
        return data.success === true && (data.score ?? 0) >= 0.5;
    } catch {
        return false;
    }
}

exports.handler = async (event) => {
    if (event.httpMethod !== 'POST') return redirect('/form.html');

    const fields = Object.fromEntries(new URLSearchParams(event.body));

    /* ── Honeypot ── */
    if (fields._hp) return redirect('/thanks.html');

    /* ── reCAPTCHA v3 ── */
    const recaptchaOk = await verifyRecaptcha(fields['g-recaptcha-response']);
    console.log('[proxy] recaptcha ok:', recaptchaOk, '| token present:', !!fields['g-recaptcha-response']);
    if (!recaptchaOk) return redirect('/error.html');

    /* ── HMAC token validation ── */
    const secret = process.env.DEVA_HMAC_SECRET;
    const { token, ts } = fields;
    const hmacOk = !!(secret && token && ts && verifyToken(secret, token, ts));
    console.log('[proxy] hmac ok:', hmacOk, '| secret set:', !!secret, '| token present:', !!token, '| ts present:', !!ts);
    if (!hmacOk) return redirect('/error.html');

    /* ── Timing: between 4 s and 30 min ── */
    const age = Date.now() - parseInt(ts, 10);
    console.log('[proxy] age ms:', age);
    if (age < 4000 || age > 1_800_000) return redirect('/error.html');

    /* ── Build whitelisted payload ── */
    const apiToken = process.env.DEVA_API_TOKEN;
    console.log('[proxy] apiToken set:', !!apiToken);
    if (!apiToken) return redirect('/error.html');

    const body = new URLSearchParams();
    for (const key of ALLOWED_FIELDS) {
        if (fields[key]) body.append(key, String(fields[key]).slice(0, 255));
    }
    body.append('apiToken', apiToken);

    /* ── Forward to API ── */
    const endpoint = process.env.API_ENDPOINT_FORM;
    console.log('[proxy] endpoint set:', !!endpoint);
    if (!endpoint) return redirect('/error.html');

    try {
        const response = await fetch(endpoint, {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: body.toString()
        });
        console.log('[proxy] upstream status:', response.status);
        if (!response.ok) return redirect('/error.html');
    } catch (err) {
        console.error('[proxy] fetch error:', err.message);
        return redirect('/error.html');
    }

    return redirect('/thanks.html');
};
