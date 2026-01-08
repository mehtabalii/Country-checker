const express = require('express');
const cors = require('cors');
const geoip = require('geoip-lite');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

// ---------------------
// Session Storage
// ---------------------
const userSessions = new Map();
const suspiciousIPs = new Map();

// ---------------------
// Advanced Detector
// ---------------------
class AdvancedDetector {
    constructor() {
        this.pakLanguages = ['ur', 'ur-PK', 'ps', 'sd', 'pa', 'bal', 'brh'];
        this.pakNetworks = ['jazz', 'telenor', 'zong', 'ufone', 'mobilink', 'warid', 'ptcl', 'nayatel'];
        this.pakDevices = ['PK-', 'Infinix', 'QMobile', 'Samsung-PK'];
        this.cloudIPs = ['104.200.', '185.159.', '45.134.', '91.200.']; // VPN/cloud IPs
    }

    // ---------------------
    // Pakistan detection
    // ---------------------
    isPakistan(req, clientIP) {
        let score = 0;

        // 1. GeoIP
        const geo = geoip.lookup(clientIP);
        if (geo && geo.country === 'PK') score += 3;

        // 2. Language
        const lang = req.headers['accept-language'] || '';
        if (this.pakLanguages.some(l => lang.toLowerCase().includes(l))) score += 2;

        // 3. User-Agent
        const ua = req.headers['user-agent'] || '';
        if (this.pakDevices.some(d => ua.toLowerCase().includes(d.toLowerCase()))) score += 2;
        if (this.pakNetworks.some(n => ua.toLowerCase().includes(n))) score += 1;

        // 4. Session behavior (simulate)
        const sessionId = req.headers['session-id'] || clientIP;
        const session = userSessions.get(sessionId) || { requests: 0 };
        session.requests += 1;
        userSessions.set(sessionId, session);
        if (session.requests > 5) score += 1;

        return score >= 5;
    }

    // ---------------------
    // VPN detection
    // ---------------------
    isVPN(req, clientIP) {
        let vpnScore = 0;
        const headers = req.headers;

        // Proxy headers
        const proxyHeaders = ['x-forwarded-for', 'via', 'x-real-ip', 'cf-connecting-ip'];
        if (proxyHeaders.some(h => headers[h] && headers[h] !== clientIP)) vpnScore += 2;

        // Cloud IPs
        if (this.cloudIPs.some(range => clientIP.startsWith(range))) vpnScore += 2;

        // Suspicious session
        const suspiciousCount = suspiciousIPs.get(clientIP) || 0;
        if (suspiciousCount > 2) vpnScore += 1;
        if (vpnScore > 0) suspiciousIPs.set(clientIP, suspiciousCount + 1);

        return vpnScore >= 3;
    }

    // ---------------------
    // Device fingerprint
    // ---------------------
    createFingerprint(req) {
        const headers = req.headers;
        const components = [
            headers['user-agent'] || '',
            headers['accept-language'] || '',
            headers['accept-encoding'] || '',
            headers['connection'] || '',
            headers['sec-ch-ua'] || '',
            headers['sec-ch-ua-mobile'] || '',
            headers['sec-ch-ua-platform'] || '',
            new Date().getTimezoneOffset(),
            headers['dnt'] || '0'
        ];
        return crypto.createHash('sha256').update(components.join('|')).digest('hex');
    }

    // ---------------------
    // Final decision
    // ---------------------
    getDecision(req, clientIP) {
        const pak = this.isPakistan(req, clientIP);
        const vpn = this.isVPN(req, clientIP);

        const fingerprint = this.createFingerprint(req);

        // Pakistan or VPN = Normal Page
        const showPage = !(pak || vpn);

        const message = pak
            ? 'Pakistan user detected → Normal Page'
            : vpn
                ? 'VPN user detected → Normal Page'
                : 'Non-Pakistan user → Special Page';

        return {
            showPage,
            isPakistan: pak,
            isVPN: vpn,
            fingerprint,
            message
        };
    }
}

const detector = new AdvancedDetector();

// ---------------------
// Main Endpoint
// ---------------------
app.get('/dc', (req, res) => {
    let clientIP = req.headers['x-forwarded-for'] || req.ip;
    if (clientIP.includes(',')) clientIP = clientIP.split(',')[0].trim();
    if (clientIP.startsWith('::ffff:')) clientIP = clientIP.replace('::ffff:', '');

    const decision = detector.getDecision(req, clientIP);

    res.json({
        ip: clientIP,
        ...decision,
        timestamp: new Date().toISOString()
    });
});

// ---------------------
// Admin Dashboard
// ---------------------
app.get('/admin/stats', (req, res) => {
    res.json({
        totalSessions: userSessions.size,
        totalSuspiciousIPs: suspiciousIPs.size,
        recentSessions: Array.from(userSessions.entries()).slice(-10),
        recentSuspicious: Array.from(suspiciousIPs.entries()).slice(-10)
    });
});

// ---------------------
// Health Check
// ---------------------
app.get('/health', (req, res) => {
    res.json({
        status: 'OK',
        version: 'Advanced v4.0',
        features: [
            'Pakistan Detection',
            'VPN/Proxy Detection',
            'Device Fingerprinting',
            'Session Tracking',
            'Admin Stats Dashboard'
        ],
        timestamp: new Date().toISOString()
    });
});

// ---------------------
// Start Server
// ---------------------
app.listen(PORT, () => {
    console.log(`🚀 Advanced Detection System running on port ${PORT}`);
    console.log(`📌 Main endpoint: http://localhost:${PORT}/dc`);
    console.log(`📌 Admin stats: http://localhost:${PORT}/admin/stats`);
    console.log(`📌 Health check: http://localhost:${PORT}/health`);
});
