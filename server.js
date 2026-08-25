const express = require("express");
const session = require("express-session");
const path = require("path");
const fs = require("fs");

const app = express();

const PORT = process.env.PORT || 3000;

const DISCORD_CLIENT_ID = process.env.DISCORD_CLIENT_ID;
const DISCORD_CLIENT_SECRET = process.env.DISCORD_CLIENT_SECRET;
const DISCORD_REDIRECT_URI = process.env.DISCORD_REDIRECT_URI;

if (!DISCORD_CLIENT_ID || !DISCORD_CLIENT_SECRET || !DISCORD_REDIRECT_URI) {
    console.error("Missing Discord OAuth environment variables.");
    process.exit(1);
}

app.use(express.json());

app.use(
    session({
        secret: process.env.SESSION_SECRET || "CHANGE_THIS_SECRET",
        resave: false,
        saveUninitialized: false,
        cookie: {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
            sameSite: "lax",
            maxAge: 1000 * 60 * 60 * 24
        }
    })
);

// ===============================
// Logs
// ===============================

const logsDir = path.join(__dirname, "logs");
const logsFile = path.join(logsDir, "login-logs.json");

if (!fs.existsSync(logsDir)) {
    fs.mkdirSync(logsDir, { recursive: true });
}

if (!fs.existsSync(logsFile)) {
    fs.writeFileSync(logsFile, "[]");
}

function addLog(user) {
    let logs = [];

    try {
        logs = JSON.parse(fs.readFileSync(logsFile, "utf8"));
    } catch {
        logs = [];
    }

    logs.push({
        discordId: user.id,
        username: user.username,
        globalName: user.global_name || null,
        email: user.email || null,
        avatar: user.avatar || null,
        timestamp: new Date().toISOString()
    });

    fs.writeFileSync(logsFile, JSON.stringify(logs, null, 2));
}

// ===============================
// Authentication middleware
// ===============================

function requireAuth(req, res, next) {
    if (!req.session.user) {
        return res.redirect("/auth/discord");
    }

    next();
}

// ===============================
// Discord Login
// ===============================

app.get("/auth/discord", (req, res) => {
    const params = new URLSearchParams({
        client_id: DISCORD_CLIENT_ID,
        response_type: "code",
        redirect_uri: DISCORD_REDIRECT_URI,
        scope: "identify email"
    });

    res.redirect(
        `https://discord.com/oauth2/authorize?${params.toString()}`
    );
});

// ===============================
// Discord Callback
// ===============================

app.get("/auth/discord/callback", async (req, res) => {
    const { code } = req.query;

    if (!code) {
        return res.status(400).send("Missing OAuth code.");
    }

    try {
        const tokenResponse = await fetch(
            "https://discord.com/api/oauth2/token",
            {
                method: "POST",
                headers: {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                body: new URLSearchParams({
                    client_id: DISCORD_CLIENT_ID,
                    client_secret: DISCORD_CLIENT_SECRET,
                    grant_type: "authorization_code",
                    code,
                    redirect_uri: DISCORD_REDIRECT_URI
                })
            }
        );

        if (!tokenResponse.ok) {
            const error = await tokenResponse.text();

            console.error("Discord token error:", error);

            return res
                .status(500)
                .send("Discord authentication failed.");
        }

        const tokenData = await tokenResponse.json();

        const userResponse = await fetch(
            "https://discord.com/api/users/@me",
            {
                headers: {
                    Authorization: `${tokenData.token_type} ${tokenData.access_token}`
                }
            }
        );

        if (!userResponse.ok) {
            return res
                .status(500)
                .send("Unable to retrieve Discord account.");
        }

        const user = await userResponse.json();

        // Save only the information requested from Discord OAuth.
        const sessionUser = {
            id: user.id,
            username: user.username,
            global_name: user.global_name,
            email: user.email || null,
            avatar: user.avatar || null
        };

        req.session.user = sessionUser;

        // Login log
        addLog(sessionUser);

        console.log(
            `[DISCORD LOGIN] ${sessionUser.username} (${sessionUser.id}) - ${sessionUser.email || "No email"}`
        );

        res.redirect("/");
    } catch (error) {
        console.error("OAuth error:", error);

        res
            .status(500)
            .send("Authentication error.");
    }
});

// ===============================
// API - Current user
// ===============================

app.get("/api/me", requireAuth, (req, res) => {
    res.json({
        authenticated: true,
        user: req.session.user
    });
});

// ===============================
// Logout
// ===============================

app.get("/logout", (req, res) => {
    req.session.destroy(() => {
        res.redirect("/auth/discord");
    });
});

// ===============================
// Protect website
// ===============================

// Login must happen before accessing the website.
app.use(requireAuth);

app.use(
    express.static(path.join(__dirname, "public"))
);

// ===============================
// Start
// ===============================

app.listen(PORT, "0.0.0.0", () => {
    console.log(`CIA RP website running on port ${PORT}`);
});
