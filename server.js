const express = require("express");
const cors = require("cors");
const fetch = require("node-fetch");

const app = express();
app.use(cors());

const IPDATA_API_KEY = "d383fa127e8095876a4be47e1b4117bcf65ba49a6a0f777861879ed9"; // 👈 Yahan apni key dal do

app.get("/dc", async (req, res) => {
  try {
    const clientIp = req.headers["x-forwarded-for"] || req.ip || "unknown";

    // IPData API call
    const response = await fetch(`https://api.ipdata.co/${clientIp}?api-key=${IPDATA_API_KEY}`);
    const data = await response.json();

    // Country code
    const countryCode = data.country_code || "UNKNOWN";

    // VPN/Proxy detection
    const vpnDetected = data.threat?.is_proxy || false;

    // Logic
    const isPakistan = countryCode === "PK";

    // Show page logic
    // Pakistan → normal page
    // Non-Pakistan + VPN → special page
    const showPage = !isPakistan && !vpnDetected ? true : false;

    res.json({
      clientIp,
      [clientIp]: {
        isocode: countryCode,
        country_name: data.country_name || "Other",
        proxy: vpnDetected
      },
      showPage,
      country: countryCode,
      vpn: vpnDetected,
      message: isPakistan
        ? "Normal page for Pakistan user"
        : vpnDetected
        ? "VPN detected: normal page"
        : "Special page for non-Pakistan",
      timestamp: new Date().toISOString()
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error", showPage: false });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
