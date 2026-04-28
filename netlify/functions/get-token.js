const crypto = require('crypto');

exports.handler = async () => {
    const secret = process.env.DEVA_HMAC_SECRET;
    if (!secret) {
        return { statusCode: 500, body: 'Server misconfiguration' };
    }

    const ts    = Date.now().toString();
    const token = crypto.createHmac('sha256', secret).update(ts).digest('hex');

    return {
        statusCode: 200,
        headers: {
            'Content-Type': 'application/json',
            'Cache-Control': 'no-store, no-cache'
        },
        body: JSON.stringify({ token, ts })
    };
};
