
const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const { Pool } = require("pg");

const app = express();
const PORT = process.env.PORT || 3000;

const BOT_TOKEN = process.env.BOT_TOKEN;
const DATABASE_URL = process.env.DATABASE_URL;
const WEBHOOK_SECRET = process.env.WEBHOOK_SECRET || "";

if (!BOT_TOKEN) {
  throw new Error("BOT_TOKEN environment variable is required.");
}

if (!DATABASE_URL) {
  throw new Error("DATABASE_URL environment variable is required.");
}

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: process.env.NODE_ENV === "production"
    ? { rejectUnauthorized: false }
    : false
});

app.use(express.json({ limit: "1mb" }));

const allowedOrigins = [
  "https://abdulselamahemade608-prog.github.io",
  "https://mrabdubot.vercel.app",
  "http://localhost:3000",
  "http://127.0.0.1:3000"
];

app.use(cors({
  origin(origin, callback) {
    if (!origin || allowedOrigins.includes(origin)) {
      return callback(null, true);
    }

    return callback(new Error("Origin not allowed by CORS."));
  },
  methods: ["GET", "POST", "OPTIONS"],
  allowedHeaders: [
    "Content-Type",
    "x-init-data",
    "x-device"
  ]
}));

// ==========================================
// DATABASE
// ==========================================

async function initializeDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS mini_users (
      id BIGINT PRIMARY KEY,
      first_name TEXT NOT NULL DEFAULT '',
      last_name TEXT NOT NULL DEFAULT '',
      username TEXT,
      language_code TEXT,
      is_premium BOOLEAN NOT NULL DEFAULT FALSE,
      device_id TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  console.log("Database initialized.");
}

// ==========================================
// TELEGRAM INIT DATA VERIFICATION
// ==========================================

function verifyTelegramInitData(initData) {
  if (!initData || typeof initData !== "string") {
    return null;
  }

  try {
    const params = new URLSearchParams(initData);
    const receivedHash = params.get("hash");

    if (!receivedHash) {
      return null;
    }

    params.delete("hash");

    const dataCheckString = [...params.entries()]
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

    const received = Buffer.from(receivedHash, "hex");
    const calculated = Buffer.from(calculatedHash, "hex");

    if (
      received.length !== calculated.length ||
      !crypto.timingSafeEqual(received, calculated)
    ) {
      return null;
    }

    const authDate = Number(params.get("auth_date"));
    const now = Math.floor(Date.now() / 1000);

    // Reject invalid or old Telegram login data.
    if (
      !Number.isFinite(authDate) ||
      authDate > now + 60 ||
      now - authDate > 86400
    ) {
      return null;
    }

    const userString = params.get("user");

    if (!userString) {
      return null;
    }

    const user = JSON.parse(userString);

    if (!user || !user.id) {
      return null;
    }

    return user;
  } catch (error) {
    console.error("Telegram verification error:", error.message);
    return null;
  }
}

// ==========================================
// HEALTH CHECK
// ==========================================

app.get("/", (req, res) => {
  res.json({
    ok: true,
    service: "Telegram Mini App",
    status: "online",
    ban_system: false
  });
});

app.get("/health", async (req, res) => {
  try {
    await pool.query("SELECT 1");

    res.json({
      ok: true,
      service: "Telegram Mini App",
      database: "connected",
      ban_system: false
    });
  } catch (error) {
    res.status(500).json({
      ok: false,
      database: "disconnected"
    });
  }
});

// ==========================================
// TELEGRAM AUTHENTICATION
// ==========================================

app.post("/api/auth", async (req, res) => {
  try {
    const initData = req.headers["x-init-data"];
    const deviceId = String(req.headers["x-device"] || "").slice(0, 200);

    const user = verifyTelegramInitData(initData);

    if (!user) {
      return res.status(401).json({
        ok: false,
        message: "Telegram authentication failed. Please reopen the Mini App."
      });
    }

    const result = await pool.query(
      `
      INSERT INTO mini_users (
        id,
        first_name,
        last_name,
        username,
        language_code,
        is_premium,
        device_id,
        last_seen
      )
      VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())
      ON CONFLICT (id)
      DO UPDATE SET
        first_name = EXCLUDED.first_name,
        last_name = EXCLUDED.last_name,
        username = EXCLUDED.username,
        language_code = EXCLUDED.language_code,
        is_premium = EXCLUDED.is_premium,
        device_id = EXCLUDED.device_id,
        last_seen = NOW()
      RETURNING
        id,
        first_name,
        last_name,
        username,
        language_code,
        is_premium,
        created_at,
        last_seen
      `,
      [
        String(user.id),
        user.first_name || "",
        user.last_name || "",
        user.username || null,
        user.language_code || null,
        Boolean(user.is_premium),
        deviceId || null
      ]
    );

    return res.json({
      ok: true,
      authenticated: true,
      banned: false,
      status: "active",
      message: "Authentication successful.",
      user: result.rows[0]
    });

  } catch (error) {
    console.error("Auth error:", error);

    return res.status(500).json({
      ok: false,
      message: "Server error. Please try again."
    });
  }
});

// ==========================================
// OPTIONAL: TELEGRAM WEBHOOK
// ==========================================

app.post("/telegram/webhook", async (req, res) => {
  if (WEBHOOK_SECRET) {
    const suppliedSecret = req.headers["x-telegram-bot-api-secret-token"];

    if (suppliedSecret !== WEBHOOK_SECRET) {
      return res.sendStatus(403);
    }
  }

  // This endpoint intentionally does not ban or restrict users.
  return res.sendStatus(200);
});

// ==========================================
// ERROR HANDLER
// ==========================================

app.use((error, req, res, next) => {
  console.error("Server error:", error.message);

  if (res.headersSent) {
    return next(error);
  }

  res.status(500).json({
    ok: false,
    message: "Internal server error."
  });
});

// ==========================================
// START SERVER
// ==========================================

async function startServer() {
  try {
    await initializeDatabase();

    app.listen(PORT, () => {
      console.log(`Server running on port ${PORT}`);
      console.log("Ban system: DISABLED");
    });
  } catch (error) {
    console.error("Failed to start server:", error);
    process.exit(1);
  }
}

startServer();
