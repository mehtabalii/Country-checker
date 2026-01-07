// server.js
const express = require("express");
const fetch = require("node-fetch"); // Node 18+ me built-in fetch hai
const cors = require("cors");

const app = express();
app.use(cors());

// ⚡ Replace with your actual IPHub API key
const IPHUB_API_KEY = "MzA3NDk6bnBvTFJxZ0FUQlRmME5DZXF1T0RLc2E5YXdWWk9QV1A=";

app.get("/dc", async (req, res) => {
  try {
    // Client IP detection
    const clientIp =
      req.headers["x-forwarded-for"] ||
      req.headers["cf-connecting-ip"] ||
      req.connection.remoteAddress ||
      "unknown";

    // Call IPHub API
    const iphubResponse = await fetch(
      `https://v2.api.iphub.info/ip/${clientIp}`,
      {
        headers: { "X-Key": IPHUB_API_KEY },
      }
    );

    const iphubData = await iphubResponse.json();

    const isPakistan = iphubData.countryCode === "PK";
    const isVPN = iphubData.block === 1 || iphubData.block === 2; // 1=VPN, 2=Proxy

    // 🔥 Business Logic
    // Pakistan → normal page
    // Non-Pakistan → special page
    const showPage = !isPakistan;

    const responseData = {
      clientIp: clientIp,
      [clientIp]: {
        isocode: iphubData.countryCode || "UNKNOWN",
        country_name: iphubData.countryName || "Unknown",
        proxy: isVPN,
      },
      showPage: showPage,
      country: iphubData.countryCode || "UNKNOWN",
      vpn: isVPN,
      message: showPage
        ? "Special page for non-Pakistan"
        : "Normal page for Pakistan",
      timestamp: new Date().toISOString(),
    };

    res.json(responseData);
  } catch (err) {
    console.error(err);
    res.status(500).json({
      error: "Server error",
      showPage: false,
      message: "Defaulting to normal page",
    });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
