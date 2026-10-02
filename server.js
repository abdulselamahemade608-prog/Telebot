const express = require("express");
const crypto = require("crypto");
const { Pool } = require("pg");

const app = express();

app.use(express.json({ limit: "1mb" }));

// =====================================================
// ENVIRONMENT VARIABLES
// =====================================================

const PORT = process.env.PORT || 3000;

const BOT_TOKEN = process.env.BOT_TOKEN;
const DATABASE_URL = process.env.DATABASE_URL;
const WEBHOOK_SECRET = process.env.WEBHOOK_SECRET || "adewa_webhook_secret";

const BOT_USERNAME = process.env.BOT_USERNAME;

// Telegram Mini App
const MINI_APP_URL =
    process.env.MINI_APP_URL ||
    "https://abdulselamahemade608-prog.github.io/Adewa-frontend/";

// Vercel webhook
const WEBHOOK_URL =
    process.env.WEBHOOK_URL ||
    "https://adewa.vercel.app/telegram/webhook";

const TELEGRAM_API =
    BOT_TOKEN
        ? `https://api.telegram.org/bot${BOT_TOKEN}`
        : null;


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
        throw new Error("DATABASE_URL is missing.");
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

    console.log("Database initialized.");
}


// =====================================================
// TELEGRAM API
// =====================================================

async function telegram(method, data = {}) {

    if (!TELEGRAM_API) {
        throw new Error("BOT_TOKEN is missing.");
    }

    const response = await fetch(
        `${TELEGRAM_API}/${method}`,
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
            result.description || "Telegram API error"
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

    return telegram("sendMessage", data);
}


// =====================================================
// HASH FUNCTION
// =====================================================

function sha256(value) {

    return crypto
        .createHash("sha256")
        .update(String(value))
        .digest("hex");
}


// =====================================================
// TELEGRAM INIT DATA VERIFICATION
// =====================================================

function verifyTelegramInitData(initData) {

    if (!initData) {
        throw new Error("Telegram initData is missing.");
    }

    const params = new URLSearchParams(initData);

    const hash = params.get("hash");

    if (!hash) {
        throw new Error("Telegram hash is missing.");
    }

    params.delete("hash");

    const dataCheckString = Array.from(params.entries())
        .sort(([a], [b]) => a.localeCompare(b))
        .map(([key, value]) => `${key}=${value}`)
        .join("\n");

    const secretKey = crypto
        .createHmac("sha256", "WebAppData")
        .update(BOT_TOKEN)
        .digest();

    const calculatedHash = crypto
        .createHmac("sha256", secretKey)
        .update(dataCheckString)
        .digest("hex");

    if (calculatedHash !== hash) {
        throw new Error("Invalid Telegram initData.");
    }

    const authDate = Number(
        params.get("auth_date")
    );

    if (!authDate) {
        throw new Error("auth_date is missing.");
    }

    const now = Math.floor(Date.now() / 1000);

    if (now - authDate > 86400) {
        throw new Error("Telegram session expired.");
    }

    const userString = params.get("user");

    if (!userString) {
        throw new Error("Telegram user data is missing.");
    }

    return JSON.parse(userString);
}


// =====================================================
// GET CLIENT IP
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

        const response = await fetch(
            `https://ipwho.is/${encodeURIComponent(ip)}`
        );

        const data = await response.json();

        if (!data || data.success === false) {
            return {
                vpn: false,
                proxy: false,
                tor: false,
                hosting: false
            };
        }

        const security = data.security || {};

        return {
            vpn: Boolean(security.vpn),
            proxy: Boolean(security.proxy),
            tor: Boolean(security.tor),
            hosting: Boolean(security.hosting)
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

    const result = await pool.query(
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

    return result.rows.length > 0;
}


// =====================================================
// ROOT
// =====================================================

app.get("/", async (req, res) => {

    try {

        await setupWebhook();

        res.json({
            ok: true,
            app: "Adewa Telegram Mini App",
            status: "online"
        });

    } catch (error) {

        res.status(500).json({
            ok: false,
            error: error.message
        });
    }
});


// =====================================================
// HEALTH CHECK
// =====================================================

app.get("/api/health", async (req, res) => {

    let database = false;

    try {

        if (pool) {
            await pool.query("SELECT 1");
            database = true;
        }

    } catch (_) {
        database = false;
    }

    res.json({
        ok: true,
        online: true,
        database
    });
});


// =====================================================
// WEBHOOK STATUS
// =====================================================

app.get("/api/webhook-status", async (req, res) => {

    try {

        const result = await telegram(
            "getWebhookInfo"
        );

        res.json({
            ok: true,
            webhook: result
        });

    } catch (error) {

        res.status(500).json({
            ok: false,
            error: error.message
        });
    }
});


// =====================================================
// TELEGRAM WEBHOOK
// =====================================================

app.post(
    "/telegram/webhook",
    async (req, res) => {

        try {

            const secret =
                req.headers[
                    "x-telegram-bot-api-secret-token"
                ];

            if (
                secret !== WEBHOOK_SECRET
            ) {

                return res
                    .status(401)
                    .json({
                        ok: false,
                        error: "Unauthorized"
                    });
            }

            const update = req.body;

            if (!update.message) {
                return res.json({
                    ok: true
                });
            }

            const message =
                update.message;

            const chatId =
                message.chat.id;

            const text =
                message.text || "";

            const firstName =
                message.from?.first_name ||
                "User";


            // =========================================
            // /start
            // =========================================

            if (text === "/start" ||
                text.startsWith("/start ")) {

                await initDatabase();

                const existing =
                    await pool.query(
                        `
                        SELECT *
                        FROM fraud_users
                        WHERE telegram_id = $1
                        `,
                        [chatId]
                    );

                if (
                    existing.rows.length > 0 &&
                    existing.rows[0].status === "banned"
                ) {

                    const reason =
                        existing.rows[0].ban_reason ||
                        "Security violation.";

                    await sendTelegramMessage(
                        chatId,

                        `🚫 <b>Account Banned</b>\n\n` +
                        `${reason}`
                    );

                    return res.json({
                        ok: true
                    });
                }


                // =====================================
                // NORMAL /start
                // =====================================

                if (text === "/start") {

                    await sendTelegramMessage(
                        chatId,

                        `👋 <b>Welcome ${firstName}!</b>\n\n` +
                        `Welcome to <b>Adewa Mini App</b>.\n\n` +
                        `Complete verification to continue.`,

                        {
                            inline_keyboard: [
                                [
                                    {
                                        text: "🚀 OPEN ADEWA",
                                        web_app: {
                                            url: MINI_APP_URL
                                        }
                                    }
                                ]
                            ]
                        }
                    );

                    return res.json({
                        ok: true
                    });
                }


                // =====================================
                // /start verify
                // =====================================

                if (
                    text.startsWith(
                        "/start verify"
                    )
                ) {

                    await sendTelegramMessage(
                        chatId,

                        `✅ <b>Verification Successful!</b>\n\n` +
                        `Your account has been verified successfully.\n\n` +
                        `You can now continue using Adewa.`
                    );

                    return res.json({
                        ok: true
                    });
                }

            }

            return res.json({
                ok: true
            });

        } catch (error) {

            console.error(
                "Webhook error:",
                error
            );

            return res.json({
                ok: true
            });
        }
    }
);


// =====================================================
// MINI APP AUTHENTICATION
// =====================================================

app.post(
    "/api/auth",
    async (req, res) => {

        try {

            await initDatabase();

            const initData =
                req.headers["x-init-data"];

            const deviceId =
                req.headers["x-device"];

            if (!initData) {

                return res.status(400).json({
                    ok: false,
                    status: "error",
                    message: "Missing Telegram initData."
                });
            }

            if (!deviceId) {

                return res.status(400).json({
                    ok: false,
                    status: "error",
                    message: "Missing device ID."
                });
            }


            // =========================================
            // VERIFY TELEGRAM
            // =========================================

            const telegramUser =
                verifyTelegramInitData(
                    initData
                );

            const telegramId =
                telegramUser.id;

            const username =
                telegramUser.username ||
                "";

            const firstName =
                telegramUser.first_name ||
                "User";


            // =========================================
            // IP + DEVICE HASH
            // =========================================

            const ip =
                getClientIP(req);

            const ipHash =
                sha256(ip);

            const deviceHash =
                sha256(deviceId);


            // =========================================
            // EXISTING USER
            // =========================================

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
                        existing.rows[0].ban_reason ||
                        "Account banned."
                });
            }


            // =========================================
            // VPN / PROXY CHECK
            // =========================================

            const security =
                await detectVPNProxy(ip);

            const vpnDetected =
                security.vpn ||
                security.tor;

            const proxyDetected =
                security.proxy ||
                security.hosting;


            // =========================================
            // MULTI ACCOUNT CHECK
            // =========================================

            const multiAccount =
                await detectMultiAccount(
                    telegramId,
                    ipHash,
                    deviceHash
                );


            // =========================================
            // SECURITY VIOLATION
            // =========================================

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
                }

                else if (vpnDetected) {

                    reason =
                        "VPN/Tor usage detected.";
                }

                else if (proxyDetected) {

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
                        $1,$2,$3,$4,$5,$6,$7,$8,'banned',$9,true
                    )
                    ON CONFLICT (telegram_id)
                    DO UPDATE SET
                        username = EXCLUDED.username,
                        first_name = EXCLUDED.first_name,
                        ip_hash = EXCLUDED.ip_hash,
                        device_hash = EXCLUDED.device_hash,
                        vpn_detected = EXCLUDED.vpn_detected,
                        proxy_detected = EXCLUDED.proxy_detected,
                        risk_score = EXCLUDED.risk_score,
                        status = 'banned',
                        ban_reason = EXCLUDED.ban_reason,
                        ban_message_sent = true,
                        last_seen = NOW()
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


                try {

                    await sendTelegramMessage(
                        telegramId,

                        `🚫 <b>Verification Failed</b>\n\n` +
                        `${reason}\n\n` +
                        `Your account has been permanently blocked.`
                    );

                } catch (_) {}


                return res.json({
                    ok: false,
                    status: "banned",
                    message: reason
                });
            }


            // =========================================
            // VERIFIED USER
            // =========================================

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
                    $1,$2,$3,$4,$5,$6,$7,0,
                    'verified',
                    false,
                    NOW(),
                    1
                )
                ON CONFLICT (telegram_id)
                DO UPDATE SET
                    username = EXCLUDED.username,
                    first_name = EXCLUDED.first_name,
                    ip_hash = EXCLUDED.ip_hash,
                    device_hash = EXCLUDED.device_hash,
                    vpn_detected = false,
                    proxy_detected = false,
                    risk_score = 0,
                    status = 'verified',
                    last_seen = NOW(),
                    request_count =
                        fraud_users.request_count + 1
                `,
                [
                    telegramId,
                    username,
                    firstName,
                    ipHash,
                    deviceHash,
                    false,
                    false
                ]
            );


            // =========================================
            // CONTINUE BUTTON
            // =========================================

            let continueButton = null;

            if (BOT_USERNAME) {

                continueButton = {
                    inline_keyboard: [
                        [
                            {
                                text: "✅ Continue",
                                url:
                                    `https://t.me/${BOT_USERNAME}?start=verify`
                            }
                        ]
                    ]
                };
            }


            // =========================================
            // SUCCESS MESSAGE
            // =========================================

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
                    "Success Telegram message error:",
                    error.message
                );
            }


            // =========================================
            // RESPONSE TO MINI APP
            // =========================================

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
                "Auth error:",
                error
            );

            return res.status(400).json({

                ok: false,

                status: "error",

                message:
                    error.message ||
                    "Verification failed."
            });
        }
    }
);


// =====================================================
// WEBHOOK SETUP
// =====================================================

async function setupWebhook() {

    if (!BOT_TOKEN) {
        throw new Error(
            "BOT_TOKEN is missing."
        );
    }

    await telegram(
        "setWebhook",
        {
            url: WEBHOOK_URL,

            secret_token:
                WEBHOOK_SECRET,

            allowed_updates: [
                "message"
            ]
        }
    );

    console.log(
        "Telegram webhook configured:",
        WEBHOOK_URL
    );
}


// =====================================================
// START SERVER
// =====================================================

async function startServer() {

    try {

        if (DATABASE_URL) {
            await initDatabase();
        }

        app.listen(
            PORT,
            () => {

                console.log(
                    `Adewa backend running on port ${PORT}`
                );
            }
        );

    } catch (error) {

        console.error(
            "Startup error:",
            error
        );

        process.exit(1);
    }
}


// =====================================================
// VERCEL EXPORT
// =====================================================

module.exports = app;


// =====================================================
// LOCAL START
// =====================================================

if (require.main === module) {
    startServer();
}
