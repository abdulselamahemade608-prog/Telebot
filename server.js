const express = require("express");
const crypto = require("crypto");
const zlib = require("zlib");
const { Pool } = require("pg");

const app = express();

app.use(express.json({ limit: "1mb" }));

const VERSION = "emoji-v3";

// ==========================================
// CORS
// ==========================================

const ALLOWED_ORIGIN =
    "https://abdulselamahemade608-prog.github.io";

app.use((req, res, next) => {
    res.header("Access-Control-Allow-Origin", ALLOWED_ORIGIN);
    res.header("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
    res.header(
        "Access-Control-Allow-Headers",
        "Content-Type,x-init-data,x-device,x-status-key"
    );

    if (req.method === "OPTIONS") {
        return res.status(204).end();
    }

    next();
});

// ==========================================
// ENVIRONMENT
// ==========================================

const BOT_TOKEN = process.env.BOT_TOKEN;
const DATABASE_URL = process.env.DATABASE_URL;
const WEBHOOK_SECRET = process.env.WEBHOOK_SECRET;

const MINI_APP_URL =
    process.env.MINI_APP_URL ||
    "https://abdulselamahemade608-prog.github.io/Telebot/";

// ==========================================
// DATABASE
// ==========================================

const pool = DATABASE_URL
    ? new Pool({
          connectionString: DATABASE_URL,
          ssl: { rejectUnauthorized: false }
      })
    : null;

let dbReady = null;

async function initDatabase() {
    if (!pool) {
        throw new Error("DATABASE_URL is missing.");
    }

    if (!dbReady) {
        dbReady = pool.query(`
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
                request_count INTEGER DEFAULT 0,
                whitelisted BOOLEAN DEFAULT FALSE
            )
        `).catch(error => {
            dbReady = null;
            throw error;
        });
    }

    return dbReady;
}

// ==========================================
// PREMIUM EMOJIS
// DO NOT CHANGE THESE IDs
// ==========================================

const EMOJI_IDS = {
    warning: "6285138648568437249",
    success: "6001066354810034923",
    star: "5791863789221581366",
    info: "6071194666718469290"
};

function premium(id, fallback) {
    return `<tg-emoji emoji-id='${id}'>${fallback}</tg-emoji>`;
}

const E = {
    ok: premium(EMOJI_IDS.success, "✅"),
    star: premium(EMOJI_IDS.star, "⭐"),
    info: premium(EMOJI_IDS.info, "ℹ️")
};

const EMOJI_ALLOWED = new Set([
    "6285138648568437249",
    "6001066354810034923",
    "5791863789221581366",
    "6071194666718469290",
    "5397782960512444700",
    "5458603043203327669",
    "5859691201250201986",
    "5456140674028019486"
]);

const emojiCache = new Map();

// ==========================================
// HELPERS
// ==========================================

function safeEqualHex(a, b) {
    if (!/^[a-f0-9]+$/i.test(String(a))) return false;
    if (!/^[a-f0-9]+$/i.test(String(b))) return false;

    const first = Buffer.from(String(a), "hex");
    const second = Buffer.from(String(b), "hex");

    return (
        first.length === second.length &&
        first.length > 0 &&
        crypto.timingSafeEqual(first, second)
    );
}

function safeEqualText(a, b) {
    const first = crypto
        .createHash("sha256")
        .update(String(a))
        .digest();

    const second = crypto
        .createHash("sha256")
        .update(String(b))
        .digest();

    return crypto.timingSafeEqual(first, second);
}

function escapeHtml(value) {
    return String(value)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;");
}

function hasValidStatusKey(req) {
    const key = req.headers["x-status-key"];

    return (
        Boolean(WEBHOOK_SECRET) &&
        Boolean(key) &&
        safeEqualText(key, WEBHOOK_SECRET)
    );
}

// ==========================================
// TELEGRAM API
// ==========================================

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
            result.description || "Telegram API error."
        );
    }

    return result.result;
}

async function sendTelegramMessage(chatId, text, extra = {}) {
    return telegram("sendMessage", {
        chat_id: chatId,
        text,
        parse_mode: "HTML",
        ...extra
    });
}

// ==========================================
// SUCCESSFUL VERIFICATION MESSAGE
// ==========================================

async function sendVerifiedMessage(telegramId, firstName) {
    const claim = await pool.query(
        `
        UPDATE fraud_users
        SET verification_message_sent = true
        WHERE telegram_id = $1
          AND verification_message_sent = false
        RETURNING telegram_id
        `,
        [telegramId]
    );

    if (claim.rowCount === 0) {
        return false;
    }

    try {
        await sendTelegramMessage(
            telegramId,
            `${E.star} ` +
            "<b>Successfully verified!</b>\n\n" +
            `Welcome, <b>${escapeHtml(firstName)}</b>. ` +
            "Your account has been verified.\n\n" +
            "Press the button below to continue.",
            {
                reply_markup: {
                    inline_keyboard: [
                        [
                            {
                                text: "Continue",
                                style: "success",
                                icon_custom_emoji_id: EMOJI_IDS.star,
                                callback_data: "verified_ok"
                            }
                        ]
                    ]
                }
            }
        );

        return true;

    } catch (error) {
        console.error(
            "VERIFIED MESSAGE ERROR:",
            error.message
        );

        await pool.query(
            `
            UPDATE fraud_users
            SET verification_message_sent = false
            WHERE telegram_id = $1
            `,
            [telegramId]
        ).catch(() => {});

        return false;
    }
}

// ==========================================
// VERIFY TELEGRAM MINI APP DATA
// ==========================================

function verifyTelegramInitData(initData) {
    if (!initData || !BOT_TOKEN) {
        throw new Error(
            "Telegram authentication data is missing."
        );
    }

    const params = new URLSearchParams(initData);
    const receivedHash = params.get("hash");

    if (!receivedHash) {
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

    if (!safeEqualHex(calculatedHash, receivedHash)) {
        throw new Error(
            "Invalid Telegram authentication data."
        );
    }

    const authDate = Number(params.get("auth_date"));
    const now = Math.floor(Date.now() / 1000);

    if (
        !authDate ||
        authDate > now + 60 ||
        now - authDate > 3600
    ) {
        throw new Error(
            "Telegram session expired. Open the bot again."
        );
    }

    const userString = params.get("user");

    if (!userString) {
        throw new Error("Telegram user data is missing.");
    }

    let user;

    try {
        user = JSON.parse(userString);
    } catch {
        throw new Error("Invalid Telegram user data.");
    }

    if (!user.id || !Number.isSafeInteger(user.id)) {
        throw new Error("Invalid Telegram user ID.");
    }

    return user;
}

// ==========================================
// ROOT / HEALTH
// ==========================================

app.get("/", (req, res) => {
    res.json({
        ok: true,
        app: "Telegram Verification Mini App",
        status: "online",
        version: VERSION,
        database: Boolean(pool),
        mini_app: MINI_APP_URL
    });
});

app.get("/api/health", async (req, res) => {
    try {
        if (!pool) {
            return res.status(500).json({
                ok: false,
                online: true,
                version: VERSION,
                database: false
            });
        }

        await pool.query("SELECT 1");

        return res.json({
            ok: true,
            online: true,
            version: VERSION,
            database: true
        });

    } catch (error) {
        return res.status(500).json({
            ok: false,
            online: true,
            version: VERSION,
            database: false
        });
    }
});

// ==========================================
// PREMIUM EMOJI API
// GET /api/emoji/:id
// ==========================================

app.get("/api/emoji/:id", async (req, res) => {
    try {
        const id = String(req.params.id || "");

        if (!EMOJI_ALLOWED.has(id)) {
            return res.status(404).json({
                ok: false,
                error: "Emoji not allowed."
            });
        }

        let item = emojiCache.get(id);

        if (!item) {
            const stickers = await telegram(
                "getCustomEmojiStickers",
                { custom_emoji_ids: [id] }
            );

            const sticker = Array.isArray(stickers)
                ? stickers[0]
                : null;

            if (!sticker) {
                throw new Error("Emoji not found.");
            }

            const file = await telegram(
                "getFile",
                { file_id: sticker.file_id }
            );

            const download = await fetch(
                `https://api.telegram.org/file/bot${BOT_TOKEN}/${file.file_path}`
            );

            if (!download.ok) {
                throw new Error("Emoji download failed.");
            }

            const buffer = Buffer.from(
                await download.arrayBuffer()
            );

            const path = String(file.file_path).toLowerCase();

            if (path.endsWith(".tgs")) {
                item = {
                    type: "application/json",
                    body: zlib.gunzipSync(buffer)
                };
            } else if (path.endsWith(".webm")) {
                item = {
                    type: "video/webm",
                    body: buffer
                };
            } else {
                item = {
                    type: "image/webp",
                    body: buffer
                };
            }

            emojiCache.set(id, item);
        }

        res.set("Content-Type", item.type);
        res.set("Cache-Control", "public, max-age=86400");

        return res.send(item.body);

    } catch (error) {
        console.error("EMOJI ERROR:", error.message);

        return res.status(502).json({
            ok: false,
            error: "Emoji could not be loaded."
        });
    }
});

// ==========================================
// MINI APP AUTH
// NO BAN SYSTEM
// NO VPN / PROXY CHECK
// NO MULTIPLE ACCOUNT BAN
// ==========================================

app.post("/api/auth", async (req, res) => {
    try {
        if (!pool) {
            return res.status(500).json({
                ok: false,
                status: "error",
                message: "Database is not configured."
            });
        }

        await initDatabase();

        const initData = req.headers["x-init-data"];

        if (!initData) {
            return res.status(400).json({
                ok: false,
                status: "error",
                message: "Missing Telegram data."
            });
        }

        const telegramUser = verifyTelegramInitData(initData);

        const telegramId = String(telegramUser.id);
        const username = telegramUser.username || "";
        const firstName = telegramUser.first_name || "User";

        // ======================================
        // SAVE USER AS VERIFIED
        // Old banned records are also reset.
        // ======================================

        await pool.query(
            `
            INSERT INTO fraud_users (
                telegram_id,
                username,
                first_name,
                status,
                ban_reason,
                vpn_detected,
                proxy_detected,
                risk_score,
                ban_message_sent,
                verification_message_sent,
                last_seen,
                request_count,
                whitelisted
            )
            VALUES (
                $1,$2,$3,'verified',NULL,
                false,false,0,false,false,NOW(),1,false
            )
            ON CONFLICT (telegram_id)
            DO UPDATE SET
                username = EXCLUDED.username,
                first_name = EXCLUDED.first_name,
                status = 'verified',
                ban_reason = NULL,
                vpn_detected = false,
                proxy_detected = false,
                risk_score = 0,
                ban_message_sent = false,
                last_seen = NOW(),
                request_count = fraud_users.request_count + 1
            `,
            [
                telegramId,
                username,
                firstName
            ]
        );

        // ======================================
        // SEND SUCCESS MESSAGE
        // ======================================

        await pool.query(
            `
            UPDATE fraud_users
            SET verification_message_sent = false
            WHERE telegram_id = $1
            `,
            [telegramId]
        );

        const messageSent = await sendVerifiedMessage(
            telegramId,
            firstName
        );

        return res.json({
            ok: true,
            status: "verified",
            message: "Verification finished!",
            telegram_id: telegramId,
            message_sent: messageSent
        });

    } catch (error) {
        console.error("AUTH ERROR:", error.message);

        return res.status(500).json({
            ok: false,
            status: "error",
            message:
                "Verification could not be completed. Please try again."
        });
    }
});

// ==========================================
// STATUS API FOR TELEBOT CREATOR
// GET /api/status?id=USER_ID
// Header: x-status-key
//
// No user can have banned status through
// this backend anymore.
// ==========================================

app.get("/api/status", async (req, res) => {
    try {
        if (!hasValidStatusKey(req)) {
            return res.status(403).json({
                ok: false,
                status: "forbidden"
            });
        }

        const id = String(req.query.id || "");

        if (!/^\d+$/.test(id)) {
            return res.status(400).json({
                ok: false,
                status: "error"
            });
        }

        if (!pool) {
            return res.status(500).json({
                ok: false,
                status: "error"
            });
        }

        await initDatabase();

        const result = await pool.query(
            `
            SELECT telegram_id
            FROM fraud_users
            WHERE telegram_id = $1
            `,
            [id]
        );

        if (result.rows.length === 0) {
            return res.json({
                ok: true,
                status: "unknown"
            });
        }

        return res.json({
            ok: true,
            status: "verified"
        });

    } catch (error) {
        console.error("STATUS ERROR:", error.message);

        return res.status(500).json({
            ok: false,
            status: "error"
        });
    }
});

// ==========================================
// 404
// ==========================================

app.use((req, res) => {
    res.status(404).json({
        ok: false,
        error: "Route not found."
    });
});

// ==========================================
// VERCEL / LOCAL
// ==========================================

module.exports = app;

if (require.main === module) {
    const port = process.env.PORT || 3000;

    app.listen(port, () => {
        console.log(
            `Backend running on port ${port}`
        );
    });
        }
