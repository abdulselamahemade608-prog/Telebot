const express = require("express");
const crypto = require("crypto");
const { Pool } = require("pg");

const app = express();

// =====================================================
// MIDDLEWARE
// =====================================================

app.use(express.json({ limit: "1mb" }));

// =====================================================
// CORS
// =====================================================

const ALLOWED_ORIGIN =
    "https://abdulselamahemade608-prog.github.io";

app.use((req, res, next) => {

    res.header(
        "Access-Control-Allow-Origin",
        ALLOWED_ORIGIN
    );

    res.header(
        "Access-Control-Allow-Methods",
        "GET,POST,OPTIONS"
    );

    res.header(
        "Access-Control-Allow-Headers",
        "Content-Type,x-init-data,x-device"
    );

    if (req.method === "OPTIONS") {
        return res.status(204).end();
    }

    next();
});

// =====================================================
// ENVIRONMENT VARIABLES
// =====================================================

const PORT = process.env.PORT || 3000;

const BOT_TOKEN = process.env.BOT_TOKEN;
const DATABASE_URL = process.env.DATABASE_URL;
const BOT_USERNAME = process.env.BOT_USERNAME;

const MINI_APP_URL =
    process.env.MINI_APP_URL ||
    "https://abdulselamahemade608-prog.github.io/Telebot/";

// =====================================================
// BASIC CHECK
// =====================================================

if (!BOT_TOKEN) {
    console.warn("WARNING: BOT_TOKEN is missing.");
}

if (!DATABASE_URL) {
    console.warn("WARNING: DATABASE_URL is missing.");
}

if (!BOT_USERNAME) {
    console.warn("WARNING: BOT_USERNAME is missing.");
}

// =====================================================
// DATABASE
// =====================================================

let pool = null;

if (DATABASE_URL) {

    pool = new Pool({
        connectionString: DATABASE_URL,
        ssl: {
            rejectUnauthorized: false
        }
    });

}

// =====================================================
// DATABASE INITIALIZATION
// =====================================================

async function initDatabase() {

    if (!pool) {
        throw new Error(
            "DATABASE_URL is missing. Please add DATABASE_URL in Vercel."
        );
    }

    await pool.query(`
        CREATE TABLE IF NOT EXISTS fraud_users (

            telegram_id BIGINT PRIMARY KEY,

            username TEXT,
            first_name TEXT,

            ip_hash TEXT,
            device_hash TEXT,

            vpn_detected BOOLEAN DEFAULT FALSE,
            proxy_detected BOOLEAN DEFAULT FALSE,

            risk_score INTEGER DEFAULT 0,

            status TEXT DEFAULT 'verified',

            ban_reason TEXT,

            verification_message_sent BOOLEAN DEFAULT FALSE,
            ban_message_sent BOOLEAN DEFAULT FALSE,

            first_seen TIMESTAMP DEFAULT NOW(),
            last_seen TIMESTAMP DEFAULT NOW(),

            request_count INTEGER DEFAULT 0
        );
    `);

}

// =====================================================
// TELEGRAM API
// =====================================================

async function telegram(method, data = {}) {

    if (!BOT_TOKEN) {
        throw new Error("BOT_TOKEN is missing.");
    }

    const response = await fetch(
        `https://api.telegram.org/bot${BOT_TOKEN}/${method}`,
        {
            method: "POST",

            headers: {
                "Content-Type": "application/json"
            },

            body: JSON.stringify(data)
        }
    );

    const result = await response.json();

    if (!result.ok) {

        throw new Error(
            result.description ||
            "Telegram API error."
        );

    }

    return result.result;
}

// =====================================================
// SEND TELEGRAM MESSAGE
// =====================================================

async function sendTelegramMessage(
    chatId,
    text,
    replyMarkup = null
) {

    const data = {
        chat_id: chatId,
        text: text,
        parse_mode: "HTML"
    };

    if (replyMarkup) {
        data.reply_markup = replyMarkup;
    }

    return telegram(
        "sendMessage",
        data
    );
}

// =====================================================
// SHA256
// =====================================================

function sha256(value) {

    return crypto
        .createHash("sha256")
        .update(String(value))
        .digest("hex");

}

// =====================================================
// TELEGRAM MINI APP INIT DATA
// =====================================================

function verifyTelegramInitData(initData) {

    if (!initData) {
        throw new Error(
            "Telegram initData is missing."
        );
    }

    if (!BOT_TOKEN) {
        throw new Error(
            "BOT_TOKEN is missing."
        );
    }

    const params =
        new URLSearchParams(initData);

    const hash =
        params.get("hash");

    if (!hash) {
        throw new Error(
            "Telegram hash is missing."
        );
    }

    params.delete("hash");

    const dataCheckString =
        Array.from(params.entries())
            .sort(([a], [b]) =>
                a.localeCompare(b)
            )
            .map(
                ([key, value]) =>
                    `${key}=${value}`
            )
            .join("\n");

    const secretKey =
        crypto
            .createHmac(
                "sha256",
                "WebAppData"
            )
            .update(BOT_TOKEN)
            .digest();

    const calculatedHash =
        crypto
            .createHmac(
                "sha256",
                secretKey
            )
            .update(dataCheckString)
            .digest("hex");

    if (calculatedHash !== hash) {

        throw new Error(
            "Invalid Telegram initData."
        );

    }

    const authDate =
        Number(
            params.get("auth_date")
        );

    if (!authDate) {

        throw new Error(
            "auth_date is missing."
        );

    }

    const now =
        Math.floor(
            Date.now() / 1000
        );

    if (
        now - authDate > 86400
    ) {

        throw new Error(
            "Telegram session expired."
        );

    }

    const userString =
        params.get("user");

    if (!userString) {

        throw new Error(
            "Telegram user data is missing."
        );

    }

    try {

        return JSON.parse(
            userString
        );

    } catch {

        throw new Error(
            "Invalid Telegram user data."
        );

    }

}

// =====================================================
// CLIENT IP
// =====================================================

function getClientIP(req) {

    const forwarded =
        req.headers["x-forwarded-for"];

    if (forwarded) {

        return forwarded
            .split(",")[0]
            .trim();

    }

    return (
        req.socket.remoteAddress ||
        "unknown"
    );

}

// =====================================================
// VPN / PROXY DETECTION
// =====================================================

async function detectVPNProxy(ip) {

    try {

        const response =
            await fetch(
                `https://ipwho.is/${encodeURIComponent(ip)}`
            );

        const data =
            await response.json();

        if (
            !data ||
            data.success === false
        ) {

            return {
                vpn: false,
                proxy: false,
                tor: false,
                hosting: false
            };

        }

        const security =
            data.security || {};

        return {

            vpn:
                Boolean(security.vpn),

            proxy:
                Boolean(security.proxy),

            tor:
                Boolean(security.tor),

            hosting:
                Boolean(security.hosting)

        };

    } catch (error) {

        console.error(
            "IP detection error:",
            error.message
        );

        return {

            vpn: false,
            proxy: false,
            tor: false,
            hosting: false

        };

    }

}

// =====================================================
// MULTIPLE ACCOUNT DETECTION
// =====================================================

async function detectMultiAccount(
    telegramId,
    ipHash,
    deviceHash
) {

    if (!pool) {
        return false;
    }

    const result =
        await pool.query(
            `
            SELECT telegram_id
            FROM fraud_users
            WHERE status = 'verified'
            AND telegram_id <> $1
            AND (
                device_hash = $2
                OR (
                    ip_hash = $3
                    AND device_hash <> $4
                )
            )
            LIMIT 1
            `,
            [
                telegramId,
                deviceHash,
                ipHash,
                deviceHash
            ]
        );

    return (
        result.rows.length > 0
    );

}

// =====================================================
// ROOT
// =====================================================

app.get("/", async (req, res) => {

    res.json({

        ok: true,

        app:
            "Adewa Telegram Mini App",

        status:
            "online",

        database:
            Boolean(pool),

        mini_app:
            MINI_APP_URL

    });

});

// =====================================================
// HEALTH CHECK
// =====================================================

app.get(
    "/api/health",
    async (req, res) => {

        let database = false;

        let databaseError = null;

        try {

            if (!pool) {

                databaseError =
                    "DATABASE_URL is missing.";

            } else {

                await pool.query(
                    "SELECT 1"
                );

                database = true;

            }

        } catch (error) {

            databaseError =
                error.message;

        }

        res.json({

            ok:
                database,

            online:
                true,

            database,

            databaseError

        });

    }
);

// =====================================================
// MINI APP AUTH
// =====================================================

app.post(
    "/api/auth",
    async (req, res) => {

        try {

            // ==========================================
            // DATABASE CHECK
            // ==========================================

            if (!pool) {

                return res.status(500).json({

                    ok: false,

                    status: "database_error",

                    message:
                        "DATABASE_URL is not configured on Vercel."

                });

            }

            await initDatabase();

            // ==========================================
            // HEADERS
            // ==========================================

            const initData =
                req.headers["x-init-data"];

            const deviceId =
                req.headers["x-device"];

            if (!initData) {

                return res.status(400).json({

                    ok: false,

                    status: "error",

                    message:
                        "Missing Telegram initData."

                });

            }

            if (!deviceId) {

                return res.status(400).json({

                    ok: false,

                    status: "error",

                    message:
                        "Missing device ID."

                });

            }

            // ==========================================
            // TELEGRAM VALIDATION
            // ==========================================

            const telegramUser =
                verifyTelegramInitData(
                    initData
                );

            const telegramId =
                telegramUser.id;

            const username =
                telegramUser.username || "";

            const firstName =
                telegramUser.first_name ||
                "User";

            // ==========================================
            // IP / DEVICE
            // ==========================================

            const ip =
                getClientIP(req);

            const ipHash =
                sha256(ip);

            const deviceHash =
                sha256(deviceId);

            // ==========================================
            // EXISTING USER
            // ==========================================

            const existing =
                await pool.query(
                    `
                    SELECT *
                    FROM fraud_users
                    WHERE telegram_id = $1
                    `,
                    [telegramId]
                );

            if (
                existing.rows.length > 0 &&
                existing.rows[0].status === "banned"
            ) {

                return res.json({

                    ok: false,

                    status: "banned",

                    message:
                        existing.rows[0]
                            .ban_reason ||
                        "Account banned."

                });

            }

            // ==========================================
            // VPN / PROXY
            // ==========================================

            const security =
                await detectVPNProxy(ip);

            const vpnDetected =
                security.vpn ||
                security.tor;

            const proxyDetected =
                security.proxy ||
                security.hosting;

            // ==========================================
            // MULTI ACCOUNT
            // ==========================================

            const multiAccount =
                await detectMultiAccount(
                    telegramId,
                    ipHash,
                    deviceHash
                );

            // ==========================================
            // SECURITY FAILURE
            // ==========================================

            if (
                vpnDetected ||
                proxyDetected ||
                multiAccount
            ) {

                let reason =
                    "Security violation detected.";

                if (multiAccount) {

                    reason =
                        "Multiple accounts detected.";

                } else if (vpnDetected) {

                    reason =
                        "VPN/Tor usage detected.";

                } else if (proxyDetected) {

                    reason =
                        "Proxy/hosting connection detected.";

                }

                await pool.query(
                    `
                    INSERT INTO fraud_users (

                        telegram_id,
                        username,
                        first_name,
                        ip_hash,
                        device_hash,
                        vpn_detected,
                        proxy_detected,
                        risk_score,
                        status,
                        ban_reason,
                        ban_message_sent

                    )

                    VALUES (
                        $1,$2,$3,$4,$5,
                        $6,$7,$8,'banned',
                        $9,true
                    )

                    ON CONFLICT (telegram_id)

                    DO UPDATE SET

                        username =
                            EXCLUDED.username,

                        first_name =
                            EXCLUDED.first_name,

                        ip_hash =
                            EXCLUDED.ip_hash,

                        device_hash =
                            EXCLUDED.device_hash,

                        vpn_detected =
                            EXCLUDED.vpn_detected,

                        proxy_detected =
                            EXCLUDED.proxy_detected,

                        risk_score =
                            EXCLUDED.risk_score,

                        status =
                            'banned',

                        ban_reason =
                            EXCLUDED.ban_reason,

                        ban_message_sent =
                            true,

                        last_seen =
                            NOW()
                    `,
                    [
                        telegramId,
                        username,
                        firstName,
                        ipHash,
                        deviceHash,
                        vpnDetected,
                        proxyDetected,
                        100,
                        reason
                    ]
                );

                // ======================================
                // TELEGRAM BAN MESSAGE
                // ======================================

                try {

                    await sendTelegramMessage(

                        telegramId,

                        `🚫 <b>Verification Failed</b>\n\n` +
                        `${reason}\n\n` +
                        `Your verification could not be completed.`

                    );

                } catch (error) {

                    console.error(
                        "Ban message error:",
                        error.message
                    );

                }

                return res.json({

                    ok: false,

                    status: "banned",

                    message: reason

                });

            }

            // ==========================================
            // SAVE VERIFIED USER
            // ==========================================

            await pool.query(
                `
                INSERT INTO fraud_users (

                    telegram_id,
                    username,
                    first_name,
                    ip_hash,
                    device_hash,
                    vpn_detected,
                    proxy_detected,
                    risk_score,
                    status,
                    verification_message_sent,
                    last_seen,
                    request_count

                )

                VALUES (
                    $1,$2,$3,$4,$5,
                    false,false,0,
                    'verified',
                    false,
                    NOW(),
                    1
                )

                ON CONFLICT (telegram_id)

                DO UPDATE SET

                    username =
                        EXCLUDED.username,

                    first_name =
                        EXCLUDED.first_name,

                    ip_hash =
                        EXCLUDED.ip_hash,

                    device_hash =
                        EXCLUDED.device_hash,

                    vpn_detected =
                        false,

                    proxy_detected =
                        false,

                    risk_score =
                        0,

                    status =
                        'verified',

                    last_seen =
                        NOW(),

                    request_count =
                        fraud_users.request_count + 1
                `,
                [
                    telegramId,
                    username,
                    firstName,
                    ipHash,
                    deviceHash
                ]
            );

            // ==========================================
            // CONTINUE BUTTON
            // ==========================================

            let continueButton = null;

            if (BOT_USERNAME) {

                continueButton = {

                    inline_keyboard: [

                        [
                            {
                                text:
                                    "✅ Continue",

                                url:
                                    `https://t.me/${BOT_USERNAME}?start=verify`
                            }
                        ]

                    ]

                };

            }

            // ==========================================
            // TELEGRAM SUCCESS MESSAGE
            // ==========================================

            try {

                await sendTelegramMessage(

                    telegramId,

                    `✅ <b>Verification Successful!</b>\n\n` +
                    `Your account has been successfully verified.\n\n` +
                    `Click <b>Continue</b> below to return to the bot.`,

                    continueButton

                );

            } catch (error) {

                console.error(
                    "Telegram success message error:",
                    error.message
                );

            }

            // ==========================================
            // MINI APP RESPONSE
            // ==========================================

            return res.json({

                ok: true,

                status: "verified",

                message:
                    "Your verification is successfully.",

                telegram_id:
                    telegramId

            });

        } catch (error) {

            console.error(
                "AUTH ERROR:",
                error
            );

            return res.status(500).json({

                ok: false,

                status: "error",

                message:
                    error.message ||
                    "Verification server error."

            });

        }

    }
);

// =====================================================
// 404
// =====================================================

app.use((req, res) => {

    res.status(404).json({

        ok: false,

        error:
            "Route not found."

    });

});

// =====================================================
// VERCEL
// =====================================================

module.exports = app;

// =====================================================
// LOCAL SERVER
// =====================================================

if (require.main === module) {

    const port =
        process.env.PORT || 3000;

    app.listen(
        port,
        () => {

            console.log(
                `Adewa backend running on port ${port}`
            );

        }
    );

                    }
