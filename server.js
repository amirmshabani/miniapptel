require("dotenv").config();

const crypto = require("crypto");
const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");
const rateLimit = require("express-rate-limit");

const requiredEnv = ["DATABASE_URL", "BOT_TOKEN", "JWT_SECRET"];
for (const key of requiredEnv) {
  if (!process.env[key]) throw new Error(`Missing environment variable: ${key}`);
}

const app = express();
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === "production"
    ? { rejectUnauthorized: false }
    : undefined
});

app.use(helmet());
app.use(express.json({ limit: "30kb" }));

app.use(cors({
  origin: process.env.FRONTEND_ORIGIN
    ? [process.env.FRONTEND_ORIGIN]
    : true,
  methods: ["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"]
}));

app.use("/api", rateLimit({
  windowMs: 60 * 1000,
  limit: 100,
  standardHeaders: "draft-7",
  legacyHeaders: false
}));

function publicUser(row) {
  return {
    id: String(row.id),
    username: row.username,
    name: row.display_name,
    bio: row.bio,
    interests: row.interests || [],
    movies: row.movies || [],
    books: row.books || [],
    createdAt: row.created_at
  };
}

function cleanList(value, maxItems = 30) {
  if (!Array.isArray(value)) return [];
  return [...new Set(value
    .filter(item => typeof item === "string")
    .map(item => item.trim().slice(0, 80))
    .filter(Boolean))]
    .slice(0, maxItems);
}

function verifyTelegramInitData(initData) {
  if (!initData || typeof initData !== "string") {
    throw new Error("Missing Telegram initData");
  }

const params = new URLSearchParams(initData);
  const hash = params.get("hash");
  const authDate = Number(params.get("auth_date"));
  const userText = params.get("user");

if (!hash || !authDate || !userText) {
    throw new Error("Invalid Telegram initData");
  }

// Reject data older than 24 hours.
  const ageSeconds = Math.floor(Date.now() / 1000) - authDate;
  if (ageSeconds < -60 || ageSeconds > 86400) {
    throw new Error("Telegram login data has expired");
  }

const checkString = [...params.entries()]
    .filter(([key]) => key !== "hash")
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([key, value]) => `${key}=${value}`)
    .join("\n");

const secretKey = crypto
    .createHmac("sha256", "WebAppData")
    .update(process.env.BOT_TOKEN)
    .digest();

const calculatedHash = crypto
    .createHmac("sha256", secretKey)
    .update(checkString)
    .digest();

let receivedHash;
  try {
    receivedHash = Buffer.from(hash, "hex");
  } catch {
    throw new Error("Invalid Telegram hash");
  }

if (
    receivedHash.length !== calculatedHash.length ||
    !crypto.timingSafeEqual(receivedHash, calculatedHash)
  ) {
    throw new Error("Telegram signature verification failed");
  }

const user = JSON.parse(userText);
  if (!user.id) throw new Error("Telegram user ID is missing");

return user;
}

function requireAuth(req, res, next) {
  const header = req.get("authorization") || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : "";

if (!token) {
    return res.status(401).json({ error: "Authentication required" });
  }

try {
    req.auth = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: "Session expired; please reopen the app" });
  }
}

async function telegramNotify(telegramId, text) {
  try {
    const response = await fetch(
      `https://api.telegram.org/bot${process.env.BOT_TOKEN}/sendMessage`,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          chat_id: String(telegramId),
          text
        })
      }
    );

if (!response.ok) {
      console.warn("Telegram notification was not delivered.");
    }
  } catch {
    console.warn("Could not reach Telegram notification API.");
  }
}

// Telegram Mini App login.
// The frontend sends Telegram.WebApp.initData, never the user ID by itself.
app.post("/api/auth/telegram", async (req, res) => {
  try {
    const tgUser = verifyTelegramInitData(req.body?.initData);
    const telegramId = String(tgUser.id);
    const fallbackName = String(tgUser.first_name || "New user").slice(0, 80);

const result = await pool.query(
      `INSERT INTO users (telegram_id, display_name)
       VALUES ($1, $2)
       ON CONFLICT (telegram_id)
       DO UPDATE SET updated_at = NOW()
       RETURNING *`,
      [telegramId, fallbackName]
    );

const user = result.rows[0];
    const token = jwt.sign(
      { userId: String(user.id), telegramId },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );

res.json({ token, user: publicUser(user) });
  } catch (error) {
    res.status(401).json({ error: error.message || "Telegram login failed" });
  }
});

app.get("/api/me", requireAuth, async (req, res) => {
  const result = await pool.query(
    "SELECT * FROM users WHERE id = $1",
    [req.auth.userId]
  );

if (!result.rowCount) return res.status(404).json({ error: "User not found" });
  res.json({ user: publicUser(result.rows[0]) });
});

app.patch("/api/me", requireAuth, async (req, res) => {
  const name = typeof req.body.name === "string" ? req.body.name.trim() : "";
  const username = typeof req.body.username === "string"
    ? req.body.username.trim().replace(/^@/, "")
    : "";
  const bio = typeof req.body.bio === "string" ? req.body.bio.trim().slice(0, 180) : "";

if (name.length < 1 || name.length > 80) {
    return res.status(400).json({ error: "Name must be 1–80 characters" });
  }

if (!/^[A-Za-z0-9_]{3,24}$/.test(username)) {
    return res.status(400).json({ error: "Username must be 3–24 letters, numbers, or underscores" });
  }

try {
    const result = await pool.query(
      `UPDATE users
       SET username = $1,
           display_name = $2,
           bio = $3,
           interests = $4,
           movies = $5,
           books = $6,
           updated_at = NOW()
       WHERE id = $7
       RETURNING *`,
      [
        username,
        name,
        bio,
        cleanList(req.body.interests),
        cleanList(req.body.movies),
        cleanList(req.body.books),
        req.auth.userId
      ]
    );

res.json({ user: publicUser(result.rows[0]) });
  } catch (error) {
    if (error.code === "23505") {
      return res.status(409).json({ error: "That username is already taken" });
    }
    console.error(error);
    res.status(500).json({ error: "Could not update profile" });
  }
});

app.get("/api/profiles", requireAuth, async (req, res) => {
  const search = String(req.query.search || "").trim().slice(0, 80);
  const interest = String(req.query.interest || "").trim().slice(0, 80);

const result = await pool.query(
    `SELECT u.*
     FROM users u
     WHERE u.id <> $1
       AND u.username IS NOT NULL
       AND u.username <> ''
       AND NOT EXISTS (
         SELECT 1 FROM friendships f
         WHERE (f.user1_id = LEAST(u.id, $1::bigint)
           AND f.user2_id = GREATEST(u.id, $1::bigint))
       )
       AND (
         NOT EXISTS (
           SELECT 1 FROM friend_requests r
           WHERE r.status = 'pending'
             AND ((r.sender_id = $1 AND r.receiver_id = u.id)
               OR (r.sender_id = u.id AND r.receiver_id = $1))
         )
       )
       AND ($2 = '' OR
         u.display_name ILIKE '%' || $2 || '%' OR
         u.username ILIKE '%' || $2 || '%' OR
         u.bio ILIKE '%' || $2 || '%' OR
         EXISTS (SELECT 1 FROM unnest(u.interests) i WHERE i ILIKE '%' || $2 || '%') OR
         EXISTS (SELECT 1 FROM unnest(u.movies) i WHERE i ILIKE '%' || $2 || '%') OR
         EXISTS (SELECT 1 FROM unnest(u.books) i WHERE i ILIKE '%' || $2 || '%')
       )
       AND ($3 = '' OR EXISTS (
         SELECT 1 FROM unnest(u.interests) i WHERE lower(i) = lower($3)
       ))
     ORDER BY u.created_at DESC
     LIMIT 100`,
    [req.auth.userId, search, interest]
  );

res.json({ profiles: result.rows.map(publicUser) });
});

app.post("/api/requests/:userId", requireAuth, async (req, res) => {
  const targetId = req.params.userId;
  const me = req.auth.userId;

if (targetId === me) return res.status(400).json({ error: "You cannot connect with yourself" });

const client = await pool.connect();
  try {
    await client.query("BEGIN");

const target = await client.query(
      "SELECT id, telegram_id, display_name FROM users WHERE id = $1",
      [targetId]
    );
    if (!target.rowCount) {
      await client.query("ROLLBACK");
      return res.status(404).json({ error: "User not found" });
    }

const low = BigInt(me) < BigInt(targetId) ? me : targetId;
    const high = BigInt(me) < BigInt(targetId) ? targetId : me;

const friendship = await client.query(
      "SELECT 1 FROM friendships WHERE user1_id = $1 AND user2_id = $2",
      [low, high]
    );
    if (friendship.rowCount) {
      await client.query("ROLLBACK");
      return res.status(409).json({ error: "You are already friends" });
    }

const reverse = await client.query(
      `SELECT id FROM friend_requests
       WHERE sender_id = $1 AND receiver_id = $2 AND status = 'pending'`,
      [targetId, me]
    );
    if (reverse.rowCount) {
      await client.query("ROLLBACK");
      return res.status(409).json({ error: "This person has already sent you a request. Check Requests." });
    }

await client.query(
      `INSERT INTO friend_requests (sender_id, receiver_id, status)
       VALUES ($1, $2, 'pending')
       ON CONFLICT (sender_id, receiver_id)
       DO UPDATE SET status = 'pending', updated_at = NOW()`,
      [me, targetId]
    );

await client.query("COMMIT");

// Real Telegram notification, if the recipient has opened/started the bot.
    telegramNotify(
      target.rows[0].telegram_id,
      "You have a new friend request on Common Ground. Open the Mini App to review it."
    );

res.status(201).json({ ok: true, status: "pending" });
  } catch (error) {
    await client.query("ROLLBACK");
    console.error(error);
    res.status(500).json({ error: "Could not send request" });
  } finally {
    client.release();
  }
});

app.get("/api/requests", requireAuth, async (req, res) => {
  const result = await pool.query(
    `SELECT r.id, r.status, r.created_at, r.sender_id, r.receiver_id,
            u.id AS person_id, u.username, u.display_name, u.bio,
            u.interests, u.movies, u.books, u.created_at AS person_created_at
     FROM friend_requests r
     JOIN users u ON u.id = CASE
       WHEN r.sender_id = $1 THEN r.receiver_id
       ELSE r.sender_id
     END
     WHERE (r.sender_id = $1 OR r.receiver_id = $1)
       AND r.status = 'pending'
     ORDER BY r.created_at DESC`,
    [req.auth.userId]
  );

res.json({
    requests: result.rows.map(r => ({
      id: String(r.id),
      direction: String(r.receiver_id) === req.auth.userId ? "incoming" : "outgoing",
      status: r.status,
      createdAt: r.created_at,
      person: publicUser({
        id: r.person_id,
        username: r.username,
        display_name: r.display_name,
        bio: r.bio,
        interests: r.interests,
        movies: r.movies,
        books: r.books,
        created_at: r.person_created_at
      })
    }))
  });
});

app.post("/api/requests/:userId/accept", requireAuth, async (req, res) => {
  const otherId = req.params.userId;
  const me = req.auth.userId;
  const client = await pool.connect();

try {
    await client.query("BEGIN");

const request = await client.query(
      `SELECT id FROM friend_requests
       WHERE sender_id = $1 AND receiver_id = $2 AND status = 'pending'
       FOR UPDATE`,
      [otherId, me]
    );

if (!request.rowCount) {
      await client.query("ROLLBACK");
      return res.status(404).json({ error: "Incoming request not found" });
    }

const low = BigInt(me) < BigInt(otherId) ? me : otherId;
    const high = BigInt(me) < BigInt(otherId) ? otherId : me;

await client.query(
      `INSERT INTO friendships (user1_id, user2_id)
       VALUES ($1, $2) ON CONFLICT DO NOTHING`,
      [low, high]
    );

await client.query(
      `UPDATE friend_requests SET status = 'accepted', updated_at = NOW()
       WHERE id = $1`,
      [request.rows[0].id]
    );

await client.query("COMMIT");
    res.json({ ok: true, status: "friends" });
  } catch (error) {
    await client.query("ROLLBACK");
    console.error(error);
    res.status(500).json({ error: "Could not accept request" });
  } finally {
    client.release();
  }
});

app.post("/api/requests/:userId/decline", requireAuth, async (req, res) => {
  const result = await pool.query(
    `UPDATE friend_requests SET status = 'declined', updated_at = NOW()
     WHERE sender_id = $1 AND receiver_id = $2 AND status = 'pending'
     RETURNING id`,
    [req.params.userId, req.auth.userId]
  );
  if (!result.rowCount) return res.status(404).json({ error: "Request not found" });
  res.json({ ok: true });
});

app.post("/api/requests/:userId/cancel", requireAuth, async (req, res) => {
  const result = await pool.query(
    `UPDATE friend_requests SET status = 'cancelled', updated_at = NOW()
     WHERE sender_id = $1 AND receiver_id = $2 AND status = 'pending'
     RETURNING id`,
    [req.auth.userId, req.params.userId]
  );
  if (!result.rowCount) return res.status(404).json({ error: "Request not found" });
  res.json({ ok: true });
});

app.get("/api/friends", requireAuth, async (req, res) => {
  const result = await pool.query(
    `SELECT u.*
     FROM friendships f
     JOIN users u ON u.id = CASE
       WHEN f.user1_id = $1 THEN f.user2_id
       ELSE f.user1_id
     END
     WHERE f.user1_id = $1 OR f.user2_id = $1
     ORDER BY u.display_name`,
    [req.auth.userId]
  );
  res.json({ friends: result.rows.map(publicUser) });
});

app.delete("/api/friends/:userId", requireAuth, async (req, res) => {
  const me = req.auth.userId;
  const other = req.params.userId;
  const low = BigInt(me) < BigInt(other) ? me : other;
  const high = BigInt(me) < BigInt(other) ? other : me;

const result = await pool.query(
    "DELETE FROM friendships WHERE user1_id = $1 AND user2_id = $2",
    [low, high]
  );

if (!result.rowCount) return res.status(404).json({ error: "Friend not found" });
  res.json({ ok: true });
});

async function requireFriend(me, other) {
  const low = BigInt(me) < BigInt(other) ? me : other;
  const high = BigInt(me) < BigInt(other) ? other : me;
  const result = await pool.query(
    "SELECT 1 FROM friendships WHERE user1_id = $1 AND user2_id = $2",
    [low, high]
  );
  return result.rowCount > 0;
}

app.get("/api/messages/:userId", requireAuth, async (req, res) => {
  if (!(await requireFriend(req.auth.userId, req.params.userId))) {
    return res.status(403).json({ error: "Messaging is available to friends only" });
  }

const result = await pool.query(
    `SELECT id, sender_id, receiver_id, body, created_at
     FROM messages
     WHERE (sender_id = $1 AND receiver_id = $2)
        OR (sender_id = $2 AND receiver_id = $1)
     ORDER BY created_at DESC
     LIMIT 100`,
    [req.auth.userId, req.params.userId]
  );

res.json({
    messages: result.rows.reverse().map(m => ({
      id: String(m.id),
      senderId: String(m.sender_id),
      receiverId: String(m.receiver_id),
      text: m.body,
      createdAt: m.created_at
    }))
  });
});

app.post("/api/messages/:userId", requireAuth, async (req, res) => {
  const text = typeof req.body.text === "string" ? req.body.text.trim() : "";
  if (!text || text.length > 2000) {
    return res.status(400).json({ error: "Message must be 1–2000 characters" });
  }

if (!(await requireFriend(req.auth.userId, req.params.userId))) {
    return res.status(403).json({ error: "Messaging is available to friends only" });
  }

const result = await pool.query(
    `INSERT INTO messages (sender_id, receiver_id, body)
     VALUES ($1, $2, $3)
     RETURNING id, sender_id, receiver_id, body, created_at`,
    [req.auth.userId, req.params.userId, text]
  );

const m = result.rows[0];
  res.status(201).json({
    message: {
      id: String(m.id),
      senderId: String(m.sender_id),
      receiverId: String(m.receiver_id),
      text: m.body,
      createdAt: m.created_at
    }
  });
});

app.get("/health", (_req, res) => res.json({ ok: true }));

app.use((error, _req, res, _next) => {
  console.error(error);
  res.status(500).json({ error: "Internal server error" });
});

const port = Number(process.env.PORT || 3000);
app.listen(port, () => console.log(`Common Ground API running on port ${port}`));
