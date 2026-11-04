const express = require("express");
const crypto = require("crypto");
const { Pool } = require("pg");

const app = express();
app.use(express.json({ limit: "1mb" }));

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
const ADMIN_ID = process.env.ADMIN_ID;
const WEBHOOK_SECRET = process.env.WEBHOOK_SECRET;

const MINI_APP_URL =
    process.env.MINI_APP_URL ||
    "https://abdulselamahemade608-prog.github.io/Telebot/";

// Reward (USD) paid to the inviter when the friend verifies
// (or when the admin unbans the friend)
const REFERRAL_REWARD = 0.10;

const pool = DATABASE_URL
    ? new Pool({
          connectionString: DATABASE_URL,
          ssl: { rejectUnauthorized: false }
      })
    : null;

let dbReady = null;

// ==========================================
// DATABASE
// ==========================================

async function initDatabase() {
    if (!pool) {
        throw new Error("DATABASE_URL is missing.");
    }

    if (!dbReady) {
        dbReady = pool
            .query(`
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
            `)
            .then(() =>
                pool.query(`
                    ALTER TABLE fraud_users
                    ADD COLUMN IF NOT EXISTS whitelisted
                    BOOLEAN DEFAULT FALSE
                `)
            )
            .then(() =>
                pool.query(`
                    CREATE INDEX IF NOT EXISTS fraud_users_device_idx
                    ON fraud_users(device_hash)
                `)
            )
            .then(() =>
                pool.query(`
                    CREATE TABLE IF NOT EXISTS referrals (
                        user_id BIGINT PRIMARY KEY,
                        referrer_id BIGINT NOT NULL,
                        rewarded BOOLEAN DEFAULT FALSE,
                        claimed BOOLEAN DEFAULT FALSE,
                        created_at TIMESTAMP DEFAULT NOW(),
                        rewarded_at TIMESTAMP
                    )
                `)
            )
            .then(() =>
                pool.query(`
                    CREATE INDEX IF NOT EXISTS referrals_referrer_idx
                    ON referrals(referrer_id)
                `)
            )
            .catch(error => {
                dbReady = null;
                throw error;
            });
    }

    return dbReady;
}

// ==========================================
// HELPERS
// ==========================================

function sha256(value) {
    return crypto
        .createHash("sha256")
        .update(String(value))
        .digest("hex");
}

function safeEqualHex(a, b) {
    if (!/^[a-f0-9]+$/i.test(String(a))) return false;
    if (!/^[a-f0-9]+$/i.test(String(b))) return false;

    const first = Buffer.from(String(a), "hex");
    const second = Buffer.from(String(b), "hex");

    return first.length === second.length &&
        first.length > 0 &&
        crypto.timingSafeEqual(first, second);
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

function getClientIP(req) {
    return (
        req.headers["x-vercel-forwarded-for"] ||
        req.headers["x-real-ip"] ||
        req.socket.remoteAddress ||
        "unknown"
    ).toString().split(",")[0].trim();
}

function isAdmin(id) {
    return Boolean(ADMIN_ID) && String(id) === String(ADMIN_ID);
}

function hasValidStatusKey(req) {
    const key = req.headers["x-status-key"];

    return Boolean(WEBHOOK_SECRET) &&
        Boolean(key) &&
        safeEqualText(key, WEBHOOK_SECRET);
}

function money(count) {
    return Number((count * REFERRAL_REWARD).toFixed(2));
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
// BOT MESSAGES TO USERS
// ==========================================

async function sendBanMessage(telegramId, reason) {
    try {
        await sendTelegramMessage(
            telegramId,
            "🚫 <b>Account Permanently Banned</b>\n\n" +
            "Your account has been blocked because multiple " +
            "accounts or a policy violation was detected.\n\n" +
            `Reason: ${escapeHtml(reason)}`
        );
    } catch (error) {
        console.error("BAN MESSAGE ERROR:", error.message);
    }
}

async function sendUnbanMessage(telegramId) {
    try {
        await sendTelegramMessage(
            telegramId,
            "✅ <b>Your account has been unbanned.</b>\n\n" +
            "You can use the bot again. Press the button below.",
            {
                reply_markup: {
                    inline_keyboard: [
                        [
                            {
                                text: "Main Menu",
                                callback_data: "main_menu"
                            }
                        ]
                    ]
                }
            }
        );
    } catch (error) {
        console.error("UNBAN MESSAGE ERROR:", error.message);
    }
}

async function sendReferralRewardMessage(referrerId, friendName) {
    try {
        await sendTelegramMessage(
            referrerId,
            "🎉 <b>New referral!</b>\n\n" +
            `<b>${escapeHtml(friendName)}</b> joined with your link ` +
            "and verified their account.\n" +
            `You earned <b>$${REFERRAL_REWARD.toFixed(2)}</b>.\n\n` +
            "Open the main menu to add it to your balance.",
            {
                reply_markup: {
                    inline_keyboard: [
                        [
                            {
                                text: "Main Menu",
                                callback_data: "main_menu"
                            }
                        ]
                    ]
                }
            }
        );
    } catch (error) {
        console.error("REFERRAL MESSAGE ERROR:", error.message);
    }
}

// ==========================================
// SEND "SUCCESSFULLY VERIFIED" MESSAGE (ONCE)
// ==========================================

async function sendVerifiedMessage(telegramId, firstName) {
    // Atomic claim: only one request can flip false -> true,
    // so the message is never sent twice.
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
            "✅ <b>Successfully verified!</b>\n\n" +
            `Welcome, <b>${escapeHtml(firstName)}</b>. ` +
            "Your account has been verified.\n\n" +
            "Press the button below to open the main menu.",
            {
                reply_markup: {
                    inline_keyboard: [
                        [
                            {
                                text: "Main Menu",
                                callback_data: "main_menu"
                            }
                        ]
                    ]
                }
            }
        );

        return true;

    } catch (error) {
        console.error("VERIFIED MESSAGE ERROR:", error.message);

        // Allow a retry on the next verification
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
// REFERRAL REWARD (VERIFY OR ADMIN UNBAN)
// ==========================================

async function rewardReferrer(telegramId, firstName) {
    // Atomic: a referral can be rewarded only once, and only if
    // the inviter is a verified (not banned) user.
    const result = await pool.query(
        `
        UPDATE referrals r
        SET rewarded = true,
            rewarded_at = NOW()
        WHERE r.user_id = $1
          AND r.rewarded = false
          AND EXISTS (
              SELECT 1
              FROM fraud_users f
              WHERE f.telegram_id = r.referrer_id
                AND f.status = 'verified'
          )
        RETURNING r.referrer_id
        `,
        [telegramId]
    );

    if (result.rowCount === 0) {
        return false;
    }

    await sendReferralRewardMessage(
        result.rows[0].referrer_id,
        firstName
    );

    return true;
}

// ==========================================
// ADMIN ACTIONS: BAN / UNBAN
// ==========================================

async function banUser(targetId, reason) {
    await pool.query(
        `
        INSERT INTO fraud_users (
            telegram_id,
            status,
            ban_reason,
            risk_score,
            ban_message_sent,
            whitelisted
        )
        VALUES ($1,'banned',$2,100,true,false)
        ON CONFLICT (telegram_id)
        DO UPDATE SET
            status = 'banned',
            ban_reason = EXCLUDED.ban_reason,
            risk_score = 100,
            ban_message_sent = true,
            whitelisted = false,
            last_seen = NOW()
        `,
        [targetId, reason]
    );

    await sendBanMessage(targetId, reason);

    return (
        `User ${targetId} has been banned.\n` +
        `Reason: ${reason}`
    );
}

async function unbanUser(targetId) {
    const result = await pool.query(
        `
        UPDATE fraud_users
        SET status = 'verified',
            ban_reason = NULL,
            vpn_detected = false,
            proxy_detected = false,
            risk_score = 0,
            ban_message_sent = false,
            whitelisted = true,
            last_seen = NOW()
        WHERE telegram_id = $1
        RETURNING first_name
        `,
        [targetId]
    );

    if (result.rowCount === 0) {
        return {
            found: false,
            message: `User ${targetId} was not found.`
        };
    }

    await sendUnbanMessage(targetId);

    // If this user came through a referral link and the inviter
    // was not rewarded yet, reward the inviter now (only once).
    let rewarded = false;

    try {
        const friendName = result.rows[0].first_name || "Your friend";
        rewarded = await rewardReferrer(targetId, friendName);
    } catch (error) {
        console.error("UNBAN REWARD ERROR:", error.message);
    }

    return {
        found: true,
        message:
            `User ${targetId} has been unbanned.` +
            (rewarded
                ? `\nInviter rewarded $${REFERRAL_REWARD.toFixed(2)}.`
                : "")
    };
}

// ==========================================
// VERIFY TELEGRAM MINI APP DATA
// ==========================================

function verifyTelegramInitData(initData) {
    if (!initData || !BOT_TOKEN) {
        throw new Error("Telegram authentication data is missing.");
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
        throw new Error("Invalid Telegram authentication data.");
    }

    const authDate = Number(params.get("auth_date"));

    if (
        !authDate ||
        authDate > Math.floor(Date.now() / 1000) + 60 ||
        Math.floor(Date.now() / 1000) - authDate > 3600
    ) {
        throw new Error("Telegram session expired. Open the bot again.");
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
// VPN / PROXY DETECTION
// ==========================================

async function detectVPNProxy(ip) {
    const clean = {
        vpn: false,
        proxy: false,
        tor: false,
        hosting: false
    };

    try {
        const response = await fetch(
            `https://ipwho.is/${encodeURIComponent(ip)}`,
            { signal: AbortSignal.timeout(4000) }
        );

        if (!response.ok) return clean;

        const data = await response.json();

        if (!data || data.success === false) {
            return clean;
        }

        const security = data.security || {};

        return {
            vpn: Boolean(security.vpn),
            proxy: Boolean(security.proxy),
            tor: Boolean(security.tor),
            hosting: Boolean(security.hosting)
        };
    } catch (error) {
        console.error("IP detection error:", error.message);
        return clean;
    }
}

// ==========================================
// MULTIPLE ACCOUNT DETECTION
// ==========================================

async function detectMultiAccount(telegramId, deviceHash) {
    const result = await pool.query(
        `
        SELECT telegram_id
        FROM fraud_users
        WHERE status = 'verified'
          AND telegram_id <> $1
          AND device_hash = $2
        LIMIT 1
        `,
        [telegramId, deviceHash]
    );

    return result.rows.length > 0;
}

// ==========================================
// ROOT / HEALTH
// ==========================================

app.get("/", (req, res) => {
    res.json({
        ok: true,
        app: "Telegram Mini App",
        status: "online",
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
                database: false
            });
        }

        await pool.query("SELECT 1");

        return res.json({
            ok: true,
            online: true,
            database: true
        });
    } catch (error) {
        return res.status(500).json({
            ok: false,
            online: true,
            database: false
        });
    }
});

// ==========================================
// MINI APP AUTH
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
        const deviceId = req.headers["x-device"];

        if (!initData || !deviceId) {
            return res.status(400).json({
                ok: false,
                status: "error",
                message: "Missing Telegram or device data."
            });
        }

        if (String(deviceId).length > 200) {
            return res.status(400).json({
                ok: false,
                status: "error",
                message: "Invalid device data."
            });
        }

        const telegramUser = verifyTelegramInitData(initData);

        const telegramId = String(telegramUser.id);
        const username = telegramUser.username || "";
        const firstName = telegramUser.first_name || "User";

        const ipHash = sha256(getClientIP(req));
        const deviceHash = sha256(deviceId);

        // IMPORTANT: Existing bans are checked first.
        const existing = await pool.query(
            `
            SELECT status, ban_reason, whitelisted
            FROM fraud_users
            WHERE telegram_id = $1
            `,
            [telegramId]
        );

        if (
            existing.rows.length > 0 &&
            existing.rows[0].status === "banned"
        ) {
            return res.status(403).json({
                ok: false,
                status: "banned",
                message:
                    "Your account is permanently banned. Contact the administrator if you believe this is a mistake."
            });
        }

        const isWhitelisted =
            existing.rows.length > 0 &&
            existing.rows[0].whitelisted === true;

        let security = {
            vpn: false,
            proxy: false,
            tor: false,
            hosting: false
        };

        let multiAccount = false;

        if (!isWhitelisted) {
            [security, multiAccount] = await Promise.all([
                detectVPNProxy(getClientIP(req)),
                detectMultiAccount(telegramId, deviceHash)
            ]);
        }

        const vpnDetected = security.vpn || security.tor;
        const proxyDetected = security.proxy || security.hosting;

        // ==========================================
        // BAN: MULTIPLE ACCOUNTS / SECURITY RULES
        // ==========================================

        if (multiAccount || vpnDetected || proxyDetected) {
            let reason = "Security violation detected.";

            if (multiAccount) {
                reason = "Multiple accounts detected.";
            } else if (vpnDetected) {
                reason = "VPN/Tor usage detected.";
            } else if (proxyDetected) {
                reason = "Proxy/hosting connection detected.";
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
                    ban_message_sent,
                    whitelisted,
                    last_seen
                )
                VALUES (
                    $1,$2,$3,$4,$5,$6,$7,100,
                    'banned',$8,true,false,NOW()
                )
                ON CONFLICT (telegram_id)
                DO UPDATE SET
                    username = EXCLUDED.username,
                    first_name = EXCLUDED.first_name,
                    ip_hash = EXCLUDED.ip_hash,
                    device_hash = EXCLUDED.device_hash,
                    vpn_detected = EXCLUDED.vpn_detected,
                    proxy_detected = EXCLUDED.proxy_detected,
                    risk_score = 100,
                    status = 'banned',
                    ban_reason = EXCLUDED.ban_reason,
                    ban_message_sent = true,
                    whitelisted = false,
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
                    reason
                ]
            );

            // Tell the user inside the bot as well
            await sendBanMessage(telegramId, reason);

            return res.status(403).json({
                ok: false,
                status: "banned",
                message: multiAccount
                    ? "Multiple accounts detected. Your account is permanently banned."
                    : reason
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
                $1,$2,$3,$4,$5,false,false,0,
                'verified',false,NOW(),1
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
                request_count = fraud_users.request_count + 1
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
        // SEND SUCCESS MESSAGE DIRECTLY IN THE BOT
        // ==========================================

        const messageSent = await sendVerifiedMessage(
            telegramId,
            firstName
        );

        // ==========================================
        // REWARD THE INVITER (ONCE)
        // ==========================================

        try {
            await rewardReferrer(telegramId, firstName);
        } catch (error) {
            console.error("REFERRAL REWARD ERROR:", error.message);
        }

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
            message: "Verification could not be completed. Please try again."
        });
    }
});

// ==========================================
// STATUS API FOR TELEBOT CREATOR
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
            SELECT status, ban_reason
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

        const row = result.rows[0];

        if (row.status === "banned") {
            return res.json({
                ok: true,
                status: "banned",
                reason: row.ban_reason || "Account banned."
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
// REFERRAL API FOR TELEBOT CREATOR
// ==========================================
// GET /api/referral?action=register&id=USER&ref=INVITER
// GET /api/referral?action=stats&id=USER
// GET /api/referral?action=claim&id=USER
// Header: x-status-key

app.get("/api/referral", async (req, res) => {
    try {
        if (!hasValidStatusKey(req)) {
            return res.status(403).json({
                ok: false,
                status: "forbidden"
            });
        }

        const action = String(req.query.action || "");
        const id = String(req.query.id || "");

        if (!/^\d+$/.test(id)) {
            return res.status(400).json({
                ok: false,
                status: "error",
                message: "Invalid user ID."
            });
        }

        if (!pool) {
            return res.status(500).json({
                ok: false,
                status: "error",
                message: "Database is not configured."
            });
        }

        await initDatabase();

        // ------------------------------------------
        // REGISTER: remember who invited this user
        // ------------------------------------------

        if (action === "register") {
            const ref = String(req.query.ref || "");

            if (!/^\d+$/.test(ref) || ref === id) {
                return res.json({
                    ok: false,
                    status: "invalid_ref"
                });
            }

            // Users already known to the system cannot be referred
            const known = await pool.query(
                `
                SELECT 1
                FROM fraud_users
                WHERE telegram_id = $1
                `,
                [id]
            );

            if (known.rowCount > 0) {
                return res.json({
                    ok: true,
                    status: "already_known"
                });
            }

            await pool.query(
                `
                INSERT INTO referrals (user_id, referrer_id)
                VALUES ($1, $2)
                ON CONFLICT (user_id) DO NOTHING
                `,
                [id, ref]
            );

            return res.json({
                ok: true,
                status: "registered"
            });
        }

        // ------------------------------------------
        // STATS: invited friends and total earned
        // ------------------------------------------

        if (action === "stats") {
            const result = await pool.query(
                `
                SELECT
                    COUNT(*) FILTER (WHERE rewarded) AS invited,
                    COUNT(*) FILTER (
                        WHERE rewarded AND NOT claimed
                    ) AS unclaimed
                FROM referrals
                WHERE referrer_id = $1
                `,
                [id]
            );

            const invited = Number(result.rows[0].invited) || 0;
            const unclaimed = Number(result.rows[0].unclaimed) || 0;

            return res.json({
                ok: true,
                status: "ok",
                invited,
                earned: money(invited),
                unclaimed: money(unclaimed)
            });
        }

        // ------------------------------------------
        // CLAIM: atomically hand over unclaimed rewards
        // ------------------------------------------

        if (action === "claim") {
            const result = await pool.query(
                `
                UPDATE referrals
                SET claimed = true
                WHERE referrer_id = $1
                  AND rewarded = true
                  AND claimed = false
                RETURNING user_id
                `,
                [id]
            );

            return res.json({
                ok: true,
                status: "ok",
                count: result.rowCount,
                amount: money(result.rowCount)
            });
        }

        return res.status(400).json({
            ok: false,
            status: "error",
            message: "Invalid action."
        });

    } catch (error) {
        console.error("REFERRAL ERROR:", error.message);

        return res.status(500).json({
            ok: false,
            status: "error",
            message: "Server error. Please try again."
        });
    }
});

// ==========================================
// ADMIN API FOR TELEBOT CREATOR (/ban, /unban)
// ==========================================
// GET /api/admin?action=ban|unban&admin=CALLER_ID&target=USER_ID&reason=...
// Header: x-status-key

app.get("/api/admin", async (req, res) => {
    try {
        if (!hasValidStatusKey(req)) {
            return res.status(403).json({
                ok: false,
                status: "forbidden",
                message: "Forbidden."
            });
        }

        const caller = String(req.query.admin || "");

        // Silent for everyone who is not the admin
        if (!isAdmin(caller)) {
            return res.json({
                ok: false,
                status: "not_admin",
                message: "Not authorized."
            });
        }

        const action = String(req.query.action || "");
        const target = String(req.query.target || "");

        if (action !== "ban" && action !== "unban") {
            return res.status(400).json({
                ok: false,
                status: "error",
                message: "Invalid action."
            });
        }

        if (!/^\d+$/.test(target)) {
            return res.status(400).json({
                ok: false,
                status: "error",
                message: "Invalid user ID."
            });
        }

        if (!pool) {
            return res.status(500).json({
                ok: false,
                status: "error",
                message: "Database is not configured."
            });
        }

        await initDatabase();

        if (action === "ban") {
            const reason =
                String(req.query.reason || "").trim().slice(0, 200) ||
                "Banned by admin.";

            const message = await banUser(target, reason);

            return res.json({
                ok: true,
                status: "banned",
                message
            });
        }

        const result = await unbanUser(target);

        return res.json({
            ok: result.found,
            status: result.found ? "unbanned" : "not_found",
            message: result.message
        });

    } catch (error) {
        console.error("ADMIN ERROR:", error.message);

        return res.status(500).json({
            ok: false,
            status: "error",
            message: "Server error. Please try again."
        });
    }
});

// ==========================================
// OPTIONAL TELEGRAM WEBHOOK: /ban AND /unban
// (Only works if this URL is the bot's real webhook.
//  With Telebot Creator use /api/admin instead.)
// ==========================================

app.post("/api/webhook", async (req, res) => {
    try {
        const receivedSecret =
            req.headers["x-telegram-bot-api-secret-token"];

        if (
            !WEBHOOK_SECRET ||
            !receivedSecret ||
            !safeEqualText(receivedSecret, WEBHOOK_SECRET)
        ) {
            return res.status(403).json({ ok: false });
        }

        const message = req.body && req.body.message;

        if (!message || !message.text || !message.from) {
            return res.json({ ok: true });
        }

        if (!isAdmin(message.from.id)) {
            return res.json({ ok: true });
        }

        const parts = message.text.trim().split(/\s+/);
        const command = parts[0].split("@")[0].toLowerCase();

        if (command !== "/ban" && command !== "/unban") {
            return res.json({ ok: true });
        }

        const chatId = message.chat.id;
        const targetId = parts[1];

        if (!targetId || !/^\d+$/.test(targetId)) {
            await sendTelegramMessage(
                chatId,
                "Usage:\n<code>/ban USER_ID [reason]</code>\n" +
                "<code>/unban USER_ID</code>"
            );

            return res.json({ ok: true });
        }

        if (!pool) {
            await sendTelegramMessage(
                chatId,
                "Database is not configured."
            );

            return res.json({ ok: true });
        }

        await initDatabase();

        if (command === "/ban") {
            const reason =
                parts.slice(2).join(" ") || "Banned by admin.";

            const text = await banUser(targetId, reason);

            await sendTelegramMessage(chatId, escapeHtml(text));

        } else {
            const result = await unbanUser(targetId);

            await sendTelegramMessage(
                chatId,
                escapeHtml(result.message)
            );
        }

        return res.json({ ok: true });

    } catch (error) {
        console.error("WEBHOOK ERROR:", error.message);
        return res.json({ ok: true });
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
        console.log(`Backend running on port ${port}`);
    });
                        }
