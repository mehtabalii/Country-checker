const express = require("express");
const cors = require("cors");

const app = express();
app.use(cors());

app.get("/dc", (req, res) => {
  const ip =
    req.headers["x-forwarded-for"]?.split(",")[0] ||
    req.socket.remoteAddress;

  const country =
    req.headers["cf-ipcountry"] ||
    "UNKNOWN";

  const isPakistan = country === "PK";

  res.json({
    clientIp: ip,
    [ip]: {
      isocode: country,
      proxy: false
    },
    showPage: !isPakistan
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log("Running on port", PORT);
});
