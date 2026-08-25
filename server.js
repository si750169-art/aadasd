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
            "CIA-RP-CHANGE-THIS-SECRET-2026",
        resave: false,
        saveUninitialized: false,
        cookie: {
            httpOnly: true,
            sameSite: "lax",
            secure: process.env.NODE_ENV === "production",
            maxAge: 1000 * 60 * 60 * 24 * 30
        }
    })
);

/* =========================
   DATABASE
========================= */

const db = new Database(
    path.join(__dirname, "cia.db")
);

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

/* =========================
   GET VISITOR IP
========================= */

function getIP(req) {
    const cf =
        req.headers["cf-connecting-ip"];

    if (cf) {
        return String(cf)
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
        .replace("::ffff:", "")
        .trim();
}

/* =========================
   AUDIT
========================= */

function addAudit(
    req,
    action,
    details = ""
) {
    try {
        const user =
            req.session?.user || null;

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
            getIP(req),
            details
        );
    } catch (err) {
        console.error(
            "Audit error:",
            err
        );
    }
}

/* =========================
   HOME
========================= */

/*
   يسجل الزائر مرة واحدة عند
   دخول الصفحة الرئيسية.
*/

app.get("/", (req, res) => {
    addAudit(
        req,
        "SITE_VISIT",
        "Visitor opened website"
    );

    const indexPath =
        path.join(
            __dirname,
            "index.html"
        );

    if (!fs.existsSync(indexPath)) {
        return res
            .status(404)
            .send(
                "index.html not found."
            );
    }

    res.sendFile(indexPath);
});

/* =========================
   LOGIN SESSION
========================= */

app.post(
    "/api/login",
    (req, res) => {
        const {
            username
        } = req.body;

        /*
           هذا مجرد نظام جلسة بسيط.
           اربطه بنظام تسجيل الدخول
           الموجود عندك إذا كان عندك
           نظام مستخدمين منفصل.
        */

        if (!username) {
            return res.status(400).json({
                error: "USERNAME_REQUIRED"
            });
        }

        req.session.user = {
            username: String(
                username
            )
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
    }
);

/* =========================
   CURRENT USER
========================= */

app.get(
    "/api/me",
    (req, res) => {
        res.json({
            authenticated:
                !!req.session.user,
            user:
                req.session.user ||
                null
        });
    }
);

/* =========================
   LOGOUT
========================= */

app.get(
    "/logout",
    (req, res) => {
        if (req.session.user) {
            addAudit(
                req,
                "LOGOUT"
            );
        }

        req.session.destroy(() => {
            res.redirect("/");
        });
    }
);

/* =========================
   COMMAND LOGS
========================= */

/*
   مهم:
   فقط code_alpha يستطيع
   رؤية الـ IP والـ logs.
*/

app.get(
    "/api/admin/logs",
    (req, res) => {

        if (!req.session.user) {
            return res.status(401).json({
                error:
                    "AUTH_REQUIRED"
            });
        }

        if (
            req.session.user.username !==
            "code_alpha"
        ) {
            return res.status(403).json({
                error:
                    "FORBIDDEN"
            });
        }

        const logs =
            db.prepare(`
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
            `).all();

        res.json({
            ok: true,
            logs
        });
    }
);

/* =========================
   SECOND LOG ENDPOINT
========================= */

app.get(
    "/api/command/audit",
    (req, res) => {

        if (!req.session.user) {
            return res.status(401).json({
                error:
                    "AUTH_REQUIRED"
            });
        }

        if (
            req.session.user.username !==
            "code_alpha"
        ) {
            return res.status(403).json({
                error:
                    "FORBIDDEN"
            });
        }

        const logs =
            db.prepare(`
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
            `).all();

        res.json({
            ok: true,
            logs
        });
    }
);

/* =========================
   STATIC FILES
========================= */

/*
   بما أنك قلت إن عندك index.html
   فقط، نخليه من جذر المشروع.
*/

app.use(
    express.static(
        __dirname
    )
);

/* =========================
   START
========================= */

app.listen(
    PORT,
    HOST,
    () => {
        console.log(
            "================================"
        );

        console.log(
            "CIA RP SERVER ONLINE"
        );

        console.log(
            `PORT: ${PORT}`
        );

        console.log(
            "Audit endpoint: /api/admin/logs"
        );

        console.log(
            "================================"
        );
    }
);
