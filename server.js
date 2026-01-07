import express from "express";
import fetch from "node-fetch"; // Node 18+ me built-in fetch bhi chal sakta hai
import cors from "cors";

const app = express();
app.use(cors());

const IPHUB_API_KEY = "MzA3NDk6bnBvTFJxZ0FUQlRmME5DZXF1T0RLc2E5YXdWWk9QV1A="; // Yahan apni IPHub key lagao

app.get("/dc", async (req, res) => {
  try {
    const clientIp =
      req.headers["x-forwarded-for"] ||
      req.connection.remoteAddress ||
      "unknown";

    // IPHub API call
    const response = await fetch(`https://v2.api.iphub.info/ip/${clientIp}`, {
      headers: {
        "X-Key": IPHUB_API_KEY
      }
    });

    const data = await response.json();

    // data.block: 0 = Residential, 1 = Non-Residential (VPN/Proxy), 2 = Data Center
    const isPakistan = data.countryCode === "PK";
    const showPage = !isPakistan; // Pakistan users -> normal page, others -> special page

    res.json({
      clientIp: clientIp,
      [clientIp]: {
        isocode: data.countryCode || "UNKNOWN",
        country_name: data.country || "Unknown",
        proxy: data.block === 1 || data.block === 2
      },
      showPage: showPage,
      country: data.countryCode || "UNKNOWN",
      vpn: data.block === 1 || data.block === 2,
      message: showPage
        ? "Special page for non-Pakistan"
        : "Normal page for Pakistan",
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    console.error("Error:", error);
    res.status(500).json({
      error: "Server error",
      showPage: false,
      message: "Defaulting to normal page due to error"
    });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
