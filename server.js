const express = require("express");
const cors = require("cors");

const app = express();
app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 3000;

/* ================= CONFIG ================= */

const PAK_IP_PREFIXES = [
  "39.", "101.", "110.", "111.",
  "116.", "117.", "119.",
  "182.", "203.", "210.",
  "223."
];

const PAK_LANGS = ["ur", "ur-pk", "pk", "pak"];
const PAK_ISP_HINTS = [
  "jazz", "telenor", "zong", "ufone",
  "ptcl", "nayatel", "stormfiber"
];

const PAK_APPS = [
  "easypaisa", "jazzcash", "sadapay",
  "nayapay", "daraz", "careem", "bykea"
];

/* ================= HELPERS ================= */

function getClientIP(req) {
  return (
    req.headers["cf-connecting-ip"] ||
    req.headers["x-forwarded-for"]?.split(",")[0]?.trim() ||
    req.socket.remoteAddress ||
    "unknown"
  );
}

function ipScore(ip) {
  if (!ip || ip === "unknown") return 20; // safe default
  if (ip === "127.0.0.1" || ip === "::1") return 40;

  return PAK_IP_PREFIXES.some(p => ip.startsWith(p)) ? 40 : 0;
}

function languageScore(lang = "") {
  lang = lang.toLowerCase();
  return PAK_LANGS.some(l => lang.includes(l)) ? 20 : 0;
}

function timezoneScore(req) {
  const tz = req.headers["x-timezone-offset"];
  if (!tz) return 0;
  return parseInt(tz) === -300 ? 15 : 0; // PKT UTC+5
}

function userAgentScore(ua = "") {
  ua = ua.toLowerCase();
  let score = 0;

  if (PAK_ISP_HINTS.some(i => ua.includes(i))) score += 10;
  if (PAK_APPS.some(a => ua.includes(a))) score += 10;

  return score;
}

/* ================= MAIN LOGIC ================= */

app.get("/detect", (req, res) => {
  const ip = getClientIP(req);

  const score =
    ipScore(ip) +
    languageScore(req.headers["accept-language"]) +
    timezoneScore(req) +
    userAgentScore(req.headers["user-agent"]);

  const isPakistan = score >= 30; // 🔥 FINAL THRESHOLD
  const showPage = !isPakistan;

  res.json({
    showPage, // true = special, false = normal
    decision: isPakistan ? "NORMAL_PAGE" : "SPECIAL_PAGE",
    score,
    signals: {
      ip,
      language: req.headers["accept-language"] || null,
      timezone: req.headers["x-timezone-offset"] || null,
      userAgent: req.headers["user-agent"]?.slice(0, 80)
    },
    message: isPakistan
      ? "Pakistan user detected (VPN ignored)"
      : "Non-Pakistan user detected",
    timestamp: new Date().toISOString()
  });
});

/* ================= SERVER ================= */

app.listen(PORT, () => {
  console.log(`🇵🇰 Advanced Pakistan Detection running on ${PORT}`);
});
