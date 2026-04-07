import express = require("express");
import cookieParser = require("cookie-parser");
import * as path from "path";
import * as admin from "firebase-admin";

if (!admin.apps.length) {
  admin.initializeApp();
}

const app = express();

app.use(cookieParser());
app.use(express.json());

// View engine setup
app.set("views", path.join(__dirname, "../views"));
app.set("view engine", "ejs");

// Middleware to verify session and inject uid
app.use(async (req, res, next) => {
  const sessionCookie = req.cookies.__session || "";
  let uid: string | null = null;

  if (sessionCookie) {
    try {
      const decodedClaims = await admin.auth().verifySessionCookie(sessionCookie, true);
      uid = decodedClaims.uid;
    } catch (error) {
      console.error("Error verifying session cookie:", error);
    }
  }

  // Inject uid into locals so it's available in all EJS templates
  res.locals.uid = uid;
  next();
});

// Routes
app.get("/", (req, res) => {
  res.render("index", { title: "Home" });
});

app.get("/index.html", (req, res) => {
  res.redirect("/");
});

app.get("/forum", (req, res) => {
  res.render("forum", { title: "Forum" });
});

app.get("/forum.html", (req, res) => {
  res.redirect("/forum");
});

// Endpoint to establish session cookie
app.post("/api/sessionLogin", async (req, res) => {
  const idToken = req.body.idToken;
  if (!idToken) {
    res.status(400).send("No ID Token provided");
    return;
  }

  const expiresIn = 60 * 60 * 24 * 5 * 1000; // 5 days
  try {
    const sessionCookie = await admin.auth().createSessionCookie(idToken, { expiresIn });
    const isEmulator = process.env.FUNCTIONS_EMULATOR === "true";
    const options = { maxAge: expiresIn, httpOnly: true, secure: !isEmulator, path: "/" };
    res.cookie("__session", sessionCookie, options);
    res.json({ status: "success" });
  } catch (error) {
    console.error("Session login error:", error);
    res.status(401).send("UNAUTHORIZED REQUEST!");
  }
});

app.post("/api/sessionLogout", (req, res) => {
  res.clearCookie("__session", { path: "/" });
  res.json({ status: "success" });
});

export default app;
