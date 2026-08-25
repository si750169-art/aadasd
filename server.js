const express = require("express");
const session = require("express-session");
const Database = require("better-sqlite3");
const path = require("path");
const fs = require("fs");

const app = express();

const PORT = Number(process.env.PORT || 3000);
const HOST = "0.0.0.0";

app.set("trust proxy", true);

app.use(express.json({ limit: "2mb" }));
app.use(express.urlencoded({ extended: true }));

app.use(
    session({
        secret:
            process.env.SESSION_SECRET ||
            "CHANGE_THIS_SECRET_2026_CIA_RP",
        resave: false,
        saveUninitialized: false,
        cookie: {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
            sameSite: "lax",
            maxAge: 1000 * 60 * 60 * 24 * 30
        }
    })
);

/* =====================================================
   DATABASE
===================================================== */

const dbPath = path.join(__dirname, "cia.db");

const db = new Database(dbPath);

db.pragma("journal_mode = WAL");

db.exec(`
CREATE TABLE IF NOT EXISTS audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    actor TEXT,
    actor_label TEXT,
    action TEXT NOT NULL,
    ip TEXT,
    details TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
`);

/* =====================================================
   IP
===================================================== */

function getClientIP(req) {
    const cloudflareIP =
        req.headers["cf-connecting-ip"];

    if (cloudflareIP) {
        return String(cloudflareIP)
            .split(",")[0]
            .trim()
            .replace("::ffff:", "");
    }

    const forwarded =
        req.headers["x-forwarded-for"];

    if (forwarded) {
        return String(forwarded)
            .split(",")[0]
            .trim()
            .replace("::ffff:", "");
    }

    return String(
        req.socket.remoteAddress ||
            "unknown"
    )
        .trim()
        .replace("::ffff:", "");
}

/* =====================================================
   AUDIT LOGGER
===================================================== */

function addAudit(req, action, details = "") {
    try {
        const user =
            req.session &&
            req.session.user
                ? req.session.user
                : null;

        db.prepare(`
            INSERT INTO audit
            (
                actor,
                actor_label,
                action,
                ip,
                details
            )
            VALUES (?, ?, ?, ?, ?)
        `).run(
            user?.id || null,
            user?.username || "PUBLIC",
            action,
            getClientIP(req),
            details
        );

        console.log(
            `[AUDIT] ${action} | IP: ${getClientIP(req)}`
        );
    } catch (error) {
        console.error(
            "[AUDIT ERROR]",
            error
        );
    }
}

/* =====================================================
   PUBLIC WEBSITE
===================================================== */

/*
   أول ما يدخل شخص الموقع:
   يتم تسجيل IP في audit.
*/

app.get("/", (req, res) => {
    addAudit(
        req,
        "SITE_VISIT",
        "Visitor opened website"
    );

    const indexPath = path.join(
        __dirname,
        "public",
        "index.html"
    );

    if (!fs.existsSync(indexPath)) {
        return res
            .status(404)
            .send("public/index.html not found.");
    }

    res.sendFile(indexPath);
});

/* =====================================================
   CURRENT USER
===================================================== */

app.get("/api/me", (req, res) => {
    if (!req.session.user) {
        return res.json({
            authenticated: false,
            user: null
        });
    }

    res.json({
        authenticated: true,
        user: req.session.user
    });
});

/* =====================================================
   LOGIN
===================================================== */

/*
   هذا endpoint تجريبي بسيط للجلسة.
   إذا كان index.html عندك يحتوي نظام تسجيل
   دخول خاص به، يمكنك ربطه بهذا endpoint.
*/

app.post("/api/login", (req, res) => {
    const username = String(
        req.body.username || ""
    ).trim();

    if (!username) {
        return res.status(400).json({
            error: "USERNAME_REQUIRED"
        });
    }

    req.session.user = {
        username: username
    };

    addAudit(
        req,
        "LOGIN",
        `username=${username}`
    );

    res.json({
        ok: true,
        user: req.session.user
    });
});

/* =====================================================
   LOGOUT
===================================================== */

app.get("/logout", (req, res) => {
    if (req.session.user) {
        addAudit(req, "LOGOUT");
    }

    req.session.destroy(() => {
        res.redirect("/");
    });
});

/* =====================================================
   COMMAND AUDIT
===================================================== */

/*
   مهم جدًا:

   فقط:
       code_alpha

   يستطيع مشاهدة الـlogs.

   أي شخص آخر يحصل على 403.
*/

app.get(
    "/api/admin/logs",
    (req, res) => {
        if (!req.session.user) {
            return res.status(401).json({
                error: "AUTH_REQUIRED"
            });
        }

        if (
            req.session.user.username !==
            "code_alpha"
        ) {
            return res.status(403).json({
                error: "FORBIDDEN"
            });
        }

        try {
            const logs = db
                .prepare(`
                    SELECT
                        id,
                        actor,
                        actor_label,
                        action,
                        ip,
                        details,
                        created_at
                    FROM audit
                    ORDER BY id DESC
                    LIMIT 500
                `)
                .all();

            res.json({
                ok: true,
                logs: logs
            });
        } catch (error) {
            console.error(
                "Logs error:",
                error
            );

            res.status(500).json({
                error: "LOGS_ERROR"
            });
        }
    }
);

/* =====================================================
   COMMAND AUDIT ALIAS
===================================================== */

app.get(
    "/api/command/audit",
    (req, res) => {
        if (!req.session.user) {
            return res.status(401).json({
                error: "AUTH_REQUIRED"
            });
        }

        if (
            req.session.user.username !==
            "code_alpha"
        ) {
            return res.status(403).json({
                error: "FORBIDDEN"
            });
        }

        try {
            const logs = db
                .prepare(`
                    SELECT
                        id,
                        actor,
                        actor_label,
                        action,
                        ip,
                        details,
                        created_at
                    FROM audit
                    ORDER BY id DESC
                    LIMIT 500
                `)
                .all();

            res.json({
                ok: true,
                logs: logs
            });
        } catch (error) {
            console.error(
                "Command audit error:",
                error
            );

            res.status(500).json({
                error: "LOGS_ERROR"
            });
        }
    }
);

/* =====================================================
   STATIC PUBLIC FILES
===================================================== */

app.use(
    express.static(
        path.join(
            __dirname,
            "public"
        )
    )
);

/* =====================================================
   404
===================================================== */

app.use((req, res) => {
    res.status(404).send(
        "Page not found."
    );
});

/* =====================================================
   ERROR HANDLER
===================================================== */

app.use(
    (err, req, res, next) => {
        console.error(
            "[SERVER ERROR]",
            err
        );

        if (res.headersSent) {
            return next(err);
        }

        res.status(500).json({
            error: "SERVER_ERROR"
        });
    }
);

/* =====================================================
   START SERVER
===================================================== */

app.listen(
    PORT,
    HOST,
    () => {
        console.log(
            "===================================="
        );

        console.log(
            "CIA RP SERVER ONLINE"
        );

        console.log(
            `PORT: ${PORT}`
        );

        console.log(
            `DATABASE: ${dbPath}`
        );

        console.log(
            "INDEX: /public/index.html"
        );

        console.log(
            "AUDIT: /api/admin/logs"
        );

        console.log(
            "COMMAND USER: code_alpha"
        );

        console.log(
            "===================================="
        );
    }
);
