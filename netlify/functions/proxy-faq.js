const crypto = require('crypto');

const ALLOWED_FIELDS = ['EMAIL', 'objet', 'message', 'porteur', 'queueid'];

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
    if (event.httpMethod !== 'POST') return redirect('/faq.html');

    const fields = Object.fromEntries(new URLSearchParams(event.body));

    /* ── Honeypot ── */
    if (fields._hp_faq) return redirect('/thanks.html'); /* silent discard */

    /* ── reCAPTCHA v3 ── */
    if (!await verifyRecaptcha(fields['g-recaptcha-response'])) {
        return redirect('/error.html');
    }

    /* ── HMAC token validation ── */
    const secret = process.env.DEVA_HMAC_SECRET;
    const { token, ts } = fields;

    if (!secret || !token || !ts || !verifyToken(secret, token, ts)) {
        return redirect('/error.html');
    }

    /* ── Timing: between 4 s and 30 min ── */
    const age = Date.now() - parseInt(ts, 10);
    if (age < 4000 || age > 1_800_000) return redirect('/error.html');

    /* ── Build whitelisted payload ── */
    const apiToken = process.env.DEVA_API_TOKEN;
    if (!apiToken) return redirect('/error.html');

    const body = new URLSearchParams();
    for (const key of ALLOWED_FIELDS) {
        if (fields[key]) body.append(key, String(fields[key]).slice(0, 2000));
    }
    body.append('apiToken', apiToken);

    /* ── Forward to API ── */
    const endpoint = process.env.API_ENDPOINT_FAQ;
    if (!endpoint) return redirect('/error.html');

    try {
        const response = await fetch(endpoint, {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: body.toString()
        });
        if (!response.ok) return redirect('/error.html');
    } catch (err) {
        console.error('proxy-faq error:', err.message);
        return redirect('/error.html');
    }

    return redirect('/thanks.html');
};
