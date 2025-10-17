// index.js
import express from "express";
import cookieSession from "cookie-session";
import cors from 'cors';
import crypto from "crypto";
import dotenv from "dotenv";
import * as jose from "jose";
import axios from "axios";
import path from "path";
import { fileURLToPath } from "url";

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;

const {
    LINE_CHANNEL_ID,
    LINE_CHANNEL_SECRET,
    SESSION_SECRET,
    BASE_URL,
    NOTION_API_KEY,
    NOTION_DATABASE_ID,
    NOTION_VERSION = "2022-06-28",
} = process.env;

// Session middleware
app.set("trust proxy", 1);
app.use(
    cookieSession({
        name: "sess",
        secret: SESSION_SECRET || "dev-secret",
        httpOnly: true,
        sameSite: "none",
        secure: true,
        maxAge: 24 * 60 * 60 * 1000,
    })
);
app.use(express.json());
app.use(express.static("public"));

// Simple request logger (timestamp + method + path)
app.use((req, _res, next) => {
    const ts = new Date().toISOString();
    console.log(`[${ts}] ${req.method} ${req.path}`);
    next();
});

/* -------------------------------
   ✅ 1) LIFF → Create Express session
-------------------------------- */
app.post("/liff/session", async (req, res) => {
    try {
        const { idToken, profile } = req.body;
        if (!idToken) return res.status(400).send("Missing idToken");

        const { alg } = jose.decodeProtectedHeader(idToken);
        let payload;

        if (alg === "HS256") {
            const secret = new TextEncoder().encode(LINE_CHANNEL_SECRET);
            const verified = await jose.jwtVerify(idToken, secret, {
                algorithms: ["HS256"],
                issuer: "https://access.line.me",
                audience: LINE_CHANNEL_ID,
            });
            payload = verified.payload;
        } else {
            const JWKS = jose.createRemoteJWKSet(
                new URL("https://api.line.me/oauth2/v2.1/certs")
            );
            const verified = await jose.jwtVerify(idToken, JWKS, {
                issuer: "https://access.line.me",
                audience: LINE_CHANNEL_ID,
            });
            payload = verified.payload;
        }

        req.session.user = {
            lineUserId: payload.sub,
            name: profile?.displayName || payload.name || null,
            picture: profile?.pictureUrl || payload.picture || null,
            email: payload.email || null,
            profileApi: profile || null,
        };

        console.log(
            `[LOGIN] LINE user logged in: ${req.session.user.lineUserId}` +
            (req.session.user.name ? ` (${req.session.user.name})` : "")
        );

        res.json({ ok: true });
    } catch (e) {
        console.error("LIFF session error:", e);
        res.status(401).send("Invalid LIFF token");
    }
});

/* -------------------------------
   ✅ 2) Get /me
-------------------------------- */
app.get("/me", (req, res) => {
    if (!req.session.user) return res.status(401).json({ ok: false });
    res.json({ ok: true, user: req.session.user });
});

/* -------------------------------
   ✅ 3) Logout
-------------------------------- */
app.get("/logout", (req, res) => {
    req.session = null;
    res.redirect("/");
});

/* -------------------------------
   ✅ 4) Notion API helper
-------------------------------- */
async function fetchStaffRoleFromNotion(staffId) {
    const notionUrl = `https://api.notion.com/v1/databases/${NOTION_DATABASE_ID}/query`;

    const payload = {
        filter: {
            property: "Staff ID", // must match Notion property
            number: { equals: Number(staffId) },
        },
    };

    const response = await axios.post(notionUrl, payload, {
        headers: {
            Authorization: `Bearer ${NOTION_API_KEY}`,
            "Notion-Version": NOTION_VERSION,
            "Content-Type": "application/json",
        },
    });

    const results = response.data.results || [];
    if (results.length === 0) throw new Error("Staff ID not found");
    const page = results[0];

    const roleProp = page.properties?.["Role"];
    const role = roleProp?.select?.name || "Unknown";
    const name =
        page.properties?.["Name"]?.title?.[0]?.plain_text ||
        page.properties?.["Channel"]?.title?.[0]?.plain_text ||
        "Unknown";

    return { role, pageId: page.id, name };
}

// ------------------ LINE Rich Menu Helpers (NEW) ------------------
async function linkRichMenuToUser(userId, richMenuId) {
    const url = `https://api.line.me/v2/bot/user/${encodeURIComponent(userId)}/richmenu/${encodeURIComponent(richMenuId)}`;
    await axios.post(url, null, {
        headers: {
            Authorization: `Bearer ${process.env.LINE_MESSAGING_CHANNEL_ACCESS_TOKEN}`
        }
    });
    console.log(`[RICHMENU] Linked user ${userId} → ${richMenuId}`);
}

async function unlinkRichMenuFromUser(userId) {
    const url = `https://api.line.me/v2/bot/user/${encodeURIComponent(userId)}/richmenu`;
    await axios.delete(url, {
        headers: {
            Authorization: `Bearer ${process.env.LINE_MESSAGING_CHANNEL_ACCESS_TOKEN}`
        }
    });
    console.log(`[RICHMENU] Unlinked user ${userId}`);
}

// ===== Minimal Notion fetch + poller =====
const POLL_INTERVAL_MS = Number(process.env.RICHMENU_POLL_INTERVAL_MS || 10000); // 10s
const DESIRED_ACTIVE_ROLE = 'PC'; // who should see the Notion menu

async function fetchAllBoundLineUsers() {
  // Pull only pages that have a Bound Line User ID (one query page)
  const url = `https://api.notion.com/v1/databases/${NOTION_DATABASE_ID}/query`;
  const payload = {
    page_size: 50,
    filter: {
      and: [
        { property: "Bound Line User ID", rich_text: { is_not_empty: true } }
      ]
    }
  };

  const r = await axios.post(url, payload, {
    headers: {
      Authorization: `Bearer ${NOTION_API_KEY}`,
      "Notion-Version": NOTION_VERSION,
      "Content-Type": "application/json",
    },
  });

  const rows = [];
  for (const page of r.data.results || []) {
    const props = page.properties || {};
    rows.push({
      userId: props["Bound Line User ID"]?.rich_text?.[0]?.plain_text || "",
      status: props["Status"]?.select?.name || "",
      role:   props["Role"]?.select?.name || "",
      pageId: page.id,
    });
  }
  return rows;
}

async function pollRichMenusOnce() {
  try {
    const rows = await fetchAllBoundLineUsers();
    for (const row of rows) {
      if (!row.userId) continue;

      // Decide desired menu: Active + PC → Notion; else → Login
      const desired = (row.status === 'Active' && row.role === DESIRED_ACTIVE_ROLE)
        ? process.env.RICHMENU_ID_NOTION
        : process.env.RICHMENU_ID_LOGIN;

      // Fire-and-forget: link the desired menu (LINE ignores if already same)
      try {
        await linkRichMenuToUser(row.userId, desired);
        console.log(`[AUTO] ${row.userId} → ${desired} (status=${row.status}, role=${row.role})`);
      } catch (e) {
        console.warn(`[AUTO] link failed for ${row.userId}:`, e.response?.data || e.message);
      }

      // Tiny delay to be kind to LINE API
      await new Promise(res => setTimeout(res, 200));
    }
  } catch (e) {
    console.error('[AUTO] poll error:', e.response?.data || e.message);
  }
}

// Start the interval (optional: set env to 0 to disable)
if (POLL_INTERVAL_MS > 0) {
  console.log(`[AUTO] Polling every ${POLL_INTERVAL_MS}ms`);
  pollRichMenusOnce().catch(()=>{});
  setInterval(() => pollRichMenusOnce().catch(()=>{}), POLL_INTERVAL_MS);
}

/* -------------------------------
   ✅ 5) Staff page
-------------------------------- */
app.get("/staff", (_req, res) => {
    res.sendFile(path.join(__dirname, "public", "staff.html"));
});

/* -------------------------------
   ✅ 6) Staff role API
-------------------------------- */
app.post("/staff/role", async (req, res) => {
    const ts = new Date().toISOString();
    try {
        if (!req.session.user) {
            console.warn(`[${ts}] [ROLE] No session for role lookup`);
            return res.status(401).json({ ok: false, error: "No session" });
        }

        const staffId = String(req.body?.staffId ?? "").trim();
        const viewer = `${req.session.user.lineUserId}` +
            (req.session.user.name ? ` (${req.session.user.name})` : "");

        if (!staffId) {
            console.warn(`[${ts}] [ROLE] Missing staffId from ${viewer}`);
            return res.status(400).json({ ok: false, error: "Missing staffId" });
        }

        console.log(`[${ts}] [ROLE] Lookup by ${viewer} → Staff ID: ${staffId}`);

        const { role, pageId, name } = await fetchStaffRoleFromNotion(staffId);

        // --- Switch per-user rich menu based on role (NEW) ---
        try {
            const userId = req.session.user.lineUserId;
            if (role === "PC") {
                await linkRichMenuToUser(userId, process.env.RICHMENU_ID_NOTION);
                console.log(`[RICHMENU] Role PC → Notion menu linked for ${userId}`);
            } else {
                // fallback/default: keep or switch back to Login menu
                await linkRichMenuToUser(userId, process.env.RICHMENU_ID_LOGIN);
                console.log(`[RICHMENU] Non-PC role → Login menu linked for ${userId}`);
            }
        } catch (err) {
            const msg = err.response?.data ? JSON.stringify(err.response.data) : err.message;
            console.error("[RICHMENU] switch error:", msg);
        }

        // --- Write-back to Notion: bind this LINE user + activate status ---
        try {
            const bindPayload = {
                properties: {
                    // set “Active”
                    "Status": { select: { name: "Active" } },

                    // bind who logged in
                    "Bound Line User ID": {
                        rich_text: [{ type: "text", text: { content: req.session.user.lineUserId } }]
                    },
                    "Bound Line Name": {
                        rich_text: [{ type: "text", text: { content: req.session.user.name || req.session.user.profileApi?.displayName || "" } }]
                    },
                    "Bound Picture URL": {
                        url: req.session.user.picture || req.session.user.profileApi?.pictureUrl || null
                    },

                    // timestamp for auditing
                    "Bound At": { date: { start: new Date().toISOString() } },
                }
            };

            await axios.patch(
                `https://api.notion.com/v1/pages/${pageId}`,
                bindPayload,
                {
                    headers: {
                        Authorization: `Bearer ${NOTION_API_KEY}`,
                        "Notion-Version": NOTION_VERSION,
                        "Content-Type": "application/json",
                    },
                }
            );
            console.log(`[ROLE] Notion updated for Staff ID ${staffId} → Active + bound to ${req.session.user.lineUserId}`);
        } catch (err) {
            const msg = err.response?.data ? JSON.stringify(err.response.data) : err.message;
            console.error("[ROLE] Notion write-back failed:", msg);
            // do not fail the request — user already logged in and menu switched
        }

        console.log(`[${ts}] [ROLE] Match for Staff ID ${staffId}: role="${role}", pageId=${pageId}`);

        res.json({
            ok: true,
            role,
            pageId,
            name,
            lineUserId: req.session.user.lineUserId,
            lineName: req.session.user.name || req.session.user.profileApi?.displayName || "",
            picture: req.session.user.picture || req.session.user.profileApi?.pictureUrl || null,
        });
    } catch (e) {
        const msg = e.response?.data ? JSON.stringify(e.response.data) : (e.message || e);
        console.error(`[${ts}] [ROLE] Error for staffId="${req.body?.staffId}":`, msg);

        if (String(e.message).includes("not found")) {
            return res.status(404).json({ ok: false, error: "Staff ID not found" });
        }
        res.status(500).json({ ok: false, error: "Server error" });
    }
});

app.get('/userbase/bootstrap', (req, res) => {
    const secret = process.env.USERBASE_BOOT_SECRET;
    if (!secret) return res.status(500).json({ ok: false, error: 'Missing USERBASE_BOOT_SECRET' });

    const u = req.session.user;
    if (!u?.lineUserId) return res.status(401).json({ ok: false, error: 'No LINE session' });

    const username = `line:${u.lineUserId}`;
    const raw = crypto.createHmac('sha256', secret).update('ub:' + u.lineUserId).digest('base64url');
    const password = raw.slice(0, 64);  // long, stable

    // (Optional) small audit line:
    console.log('[UB/BOOT]', { username, pwLen: password.length });

    res.json({ ok: true, username, password });
});

/* -------------------------------
   ✅ 7) Start
-------------------------------- */

/* -------------------------------
   🌐 Redirect root → LIFF login
-------------------------------- */
app.get("/", (req, res) => {
  res.redirect("/liff.html?next=/staff");
});

app.listen(PORT, () => {
    console.log(`✅ Server on http://localhost:${PORT}`);
    console.log(`➡ Open LIFF via: ${BASE_URL}/liff.html?next=/staff`);
});