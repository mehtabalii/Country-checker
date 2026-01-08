// server.js - ADVANCED PAKISTAN DETECTION v3.0
const express = require('express');
const cors = require('cors');
const geoip = require('geoip-lite');
const uaparser = require('ua-parser-js');
const crypto = require('crypto');
const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());

// Cache for IP lookups (in-memory)
const ipCache = new Map();
const CACHE_DURATION = 5 * 60 * 1000; // 5 minutes

// SIMULATION MODE (for testing without real databases)
const SIMULATION_MODE = true;

class AdvancedPakistanDetector {
    constructor() {
        this.userPatternsDB = new Map(); // Store user fingerprint patterns
        this.suspiciousPatterns = new Set();
        this.loadPakistaniPatterns();
    }
    
    loadPakistaniPatterns() {
        // Extensive Pakistani digital footprint database
        this.pakPatterns = {
            // ISP Patterns
            isps: [
                'jazz', 'telenor', 'zong', 'ufone', 'mobilink', 'warid', 
                'ptcl', 'nayatel', 'witribe', 'stormfiber', 'transworld',
                'optix', 'cybernet', 'comsats', 'supernet', 'worldcall',
                'linkdotnet', 'connect', 'optimus', 'brainnet', 'nexlinx'
            ],
            
            // Device Brands (popular in Pakistan)
            devices: [
                'qmobile', 'infinix', 'tecno', 'samsung', 'nokia', 'oppo',
                'vivo', 'realme', 'xiaomi', 'itel', 'lenovo', 'haier',
                'dany', 'voice', 'gfive', 'htc', 'blackberry', 'motorola'
            ],
            
            // Pakistani Apps/Services
            apps: [
                'easypaisa', 'jazzcash', 'upaisa', 'sadapay', 'nayapay',
                'daraz', 'foodpanda', 'cheetay', 'tajir', 'bykea', 'careem',
                'indrive', 'airlift', 'swvl', 'bookme', 'pakwheels', 'zameen',
                'rozee', 'ilmkidunya', 'taleemabad', 'telenor', 'bankalfalah',
                'mcb', 'hbl', 'ubl', 'askari', 'alfalah', 'meezan'
            ],
            
            // Pakistani Websites
            websites: [
                'propakistani', 'dawn', 'tribune', 'geo', 'ary', 'express',
                'pakistantoday', 'thenews', 'brecorder', 'jang', 'nawaiwaqt',
                'bol', 'hum', 'geo.tv', 'arynews.tv', 'samaa', 'abbasitv',
                '92news', 'dunya', 'city42', 'apnahd'
            ],
            
            // Cities/Regions
            locations: [
                'karachi', 'lahore', 'islamabad', 'rawalpindi', 'faisalabad',
                'multan', 'peshawar', 'quetta', 'hyderabad', 'sialkot',
                'gujranwala', 'bahawalpur', 'sargodha', 'sukkur', 'larkana',
                'sheikhupura', 'mirpur', 'jhelum', 'mardan', 'kasur', 'rwp',
                'khi', 'lhr', 'isb', 'fsd', 'mul', 'pew', 'qta'
            ],
            
            // Languages/Locales
            languages: [
                'ur', 'ur-pk', 'ps', 'sd', 'pa', 'bal', 'brh', 'hnd',
                'ks', 'lah', 'skr', 'urdu', 'pashto', 'punjabi', 'sindhi',
                'balochi', 'saraiki', 'hindko'
            ],
            
            // Timezones
            timezones: ['PKT', 'UTC+5', 'Asia/Karachi'],
            
            // Currency
            currency: ['PKR', 'Rs', 'Rupees', 'پاکستانی روپیہ']
        };
        
        // Behavioral patterns
        this.behavioralPatterns = {
            typicalBrowsingHours: [9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23], // 9 AM - 11 PM PKT
            weekendActivity: [5, 6], // Friday, Saturday
            commonResolutions: ['360x640', '360x780', '375x667', '414x896', '412x915']
        };
    }
    
    detectPakistanUser(req) {
        const startTime = Date.now();
        const detectionScore = {
            isPakistan: false,
            confidence: 0,
            reasons: [],
            score: 0,
            maxScore: 100,
            metadata: {}
        };
        
        // 1. IP Address Analysis (Weight: 30)
        const ipScore = this.analyzeIP(req);
        detectionScore.score += ipScore.score;
        detectionScore.confidence += ipScore.confidence;
        if (ipScore.reason) detectionScore.reasons.push(ipScore.reason);
        
        // 2. User Agent Analysis (Weight: 25)
        const uaScore = this.analyzeUserAgent(req);
        detectionScore.score += uaScore.score;
        detectionScore.confidence += uaScore.confidence;
        if (uaScore.reason) detectionScore.reasons.push(uaScore.reason);
        
        // 3. Header Analysis (Weight: 20)
        const headerScore = this.analyzeHeaders(req);
        detectionScore.score += headerScore.score;
        detectionScore.confidence += headerScore.confidence;
        if (headerScore.reason) detectionScore.reasons.push(headerScore.reason);
        
        // 4. Behavioral Analysis (Weight: 15)
        const behaviorScore = this.analyzeBehavior(req);
        detectionScore.score += behaviorScore.score;
        detectionScore.confidence += behaviorScore.confidence;
        if (behaviorScore.reason) detectionScore.reasons.push(behaviorScore.reason);
        
        // 5. VPN/Proxy Detection (Weight: 10)
        const vpnScore = this.analyzeVPN(req);
        detectionScore.score += vpnScore.score;
        detectionScore.confidence += vpnScore.confidence;
        if (vpnScore.reason) detectionScore.reasons.push(vpnScore.reason);
        
        // Calculate final confidence
        detectionScore.confidence = Math.min(100, Math.round(detectionScore.confidence));
        detectionScore.score = Math.min(100, detectionScore.score);
        
        // Decision Logic with multiple thresholds
        if (detectionScore.score >= 70) {
            detectionScore.isPakistan = true;
            detectionScore.decision = "HIGH_CONFIDENCE_PAKISTAN";
        } else if (detectionScore.score >= 50) {
            detectionScore.isPakistan = true;
            detectionScore.decision = "MODERATE_CONFIDENCE_PAKISTAN";
        } else if (detectionScore.score >= 30) {
            detectionScore.isPakistan = true;
            detectionScore.decision = "LOW_CONFIDENCE_PAKISTAN";
        } else {
            detectionScore.isPakistan = false;
            detectionScore.decision = "NON_PAKISTAN";
        }
        
        // Add fingerprint
        detectionScore.fingerprint = this.generateFingerprint(req);
        detectionScore.processingTime = Date.now() - startTime;
        detectionScore.timestamp = new Date().toISOString();
        
        // Cache the result
        this.cacheDetection(req, detectionScore);
        
        return detectionScore;
    }
    
    analyzeIP(req) {
        const ip = this.getClientIP(req);
        const result = { score: 0, confidence: 0, reason: null };
        
        if (!ip || ip === 'unknown') {
            return result;
        }
        
        // Check cache first
        const cached = ipCache.get(ip);
        if (cached && (Date.now() - cached.timestamp) < CACHE_DURATION) {
            return cached.result;
        }
        
        // Known Pakistani IP ranges (extended list)
        const pakIPRanges = [
            // Mobilink/Jazz
            '39.34.', '39.35.', '39.36.', '39.37.', '39.38.', '39.39.',
            '39.40.', '39.41.', '39.42.', '39.43.', '39.44.', '39.45.',
            
            // PTCL
            '101.50.', '101.51.', '101.52.', '101.53.', '101.54.', '101.55.',
            '110.36.', '110.37.', '110.38.', '110.39.', '110.40.', '110.41.',
            '111.68.', '111.69.', '111.70.', '111.71.', '111.72.', '111.73.',
            
            // Telenor
            '116.0.', '116.1.', '116.2.', '116.3.', '116.4.', '116.5.',
            
            // Zong
            '117.102.', '117.103.', '117.104.', '117.105.', '117.106.',
            
            // Ufone
            '119.152.', '119.153.', '119.154.', '119.155.', '119.156.',
            
            // WiFi/Others
            '182.176.', '182.177.', '182.178.', '182.179.', '182.180.',
            '202.69.', '202.70.', '203.82.', '203.83.', '203.84.',
            '210.56.', '223.29.', '223.30.'
        ];
        
        // Check IP ranges
        for (const range of pakIPRanges) {
            if (ip.startsWith(range)) {
                result.score = 30;
                result.confidence = 85;
                result.reason = `PAK_IP_RANGE_${range.replace('.', '_')}`;
                break;
            }
        }
        
        // GeoIP lookup (if available and not in simulation mode)
        if (!SIMULATION_MODE && geoip.lookup) {
            const geo = geoip.lookup(ip);
            if (geo && geo.country === 'PK') {
                result.score = 30;
                result.confidence = 95;
                result.reason = `GEOIP_PAKISTAN_${geo.city || 'Unknown'}`;
            }
        } else if (SIMULATION_MODE) {
            // Simulate GeoIP for testing
            const ipHash = crypto.createHash('md5').update(ip).digest('hex');
            const isSimulatedPak = parseInt(ipHash.charAt(0), 16) % 3 === 0; // 33% chance
            
            if (isSimulatedPak) {
                result.score = 25;
                result.confidence = 80;
                result.reason = `SIMULATED_PAK_IP`;
            }
        }
        
        // Cache the result
        ipCache.set(ip, {
            result: result,
            timestamp: Date.now()
        });
        
        return result;
    }
    
    analyzeUserAgent(req) {
        const uaString = req.headers['user-agent'] || '';
        const result = { score: 0, confidence: 0, reason: null };
        
        if (!uaString) return result;
        
        const ua = uaparser(uaString);
        const uaLower = uaString.toLowerCase();
        
        // Check for Pakistani ISP in UA
        for (const isp of this.pakPatterns.isps) {
            if (uaLower.includes(isp.toLowerCase())) {
                result.score += 15;
                result.confidence += 80;
                result.reason = `UA_ISP_${isp.toUpperCase()}`;
                break;
            }
        }
        
        // Check for Pakistani apps
        for (const app of this.pakPatterns.apps) {
            if (uaLower.includes(app.toLowerCase())) {
                result.score += 10;
                result.confidence += 75;
                result.reason = `UA_APP_${app.toUpperCase()}`;
                break;
            }
        }
        
        // Check device brands popular in Pakistan
        const deviceBrand = ua.device.vendor || '';
        for (const brand of this.pakPatterns.devices) {
            if (deviceBrand.toLowerCase().includes(brand.toLowerCase()) || 
                uaLower.includes(brand.toLowerCase())) {
                result.score += 8;
                result.confidence += 70;
                result.reason = `UA_DEVICE_${brand.toUpperCase()}`;
                break;
            }
        }
        
        // Check browser language/locale settings
        const langHeader = req.headers['accept-language'] || '';
        for (const lang of this.pakPatterns.languages) {
            if (langHeader.toLowerCase().includes(lang.toLowerCase())) {
                result.score += 7;
                result.confidence += 75;
                result.reason = `UA_LANG_${lang.toUpperCase()}`;
                break;
            }
        }
        
        // Cap the score
        result.score = Math.min(25, result.score);
        result.confidence = Math.min(100, result.confidence);
        
        return result;
    }
    
    analyzeHeaders(req) {
        const headers = req.headers;
        const result = { score: 0, confidence: 0, reason: null };
        
        // Timezone analysis
        const timezone = headers['x-timezone-offset'] || headers['timezone-offset'];
        if (timezone) {
            const offset = parseInt(timezone);
            if (offset === -300) { // PKT (UTC+5)
                result.score += 10;
                result.confidence += 85;
                result.reason = `TIMEZONE_PKT`;
            }
        }
        
        // Check for Pakistani locale in various headers
        const localeHeaders = [
            headers['accept-language'],
            headers['content-language'],
            headers['x-locale'],
            headers['locale']
        ].filter(Boolean).join(' ').toLowerCase();
        
        for (const lang of this.pakPatterns.languages) {
            if (localeHeaders.includes(lang.toLowerCase())) {
                result.score += 8;
                result.confidence += 80;
                result.reason = `HEADER_LANG_${lang.toUpperCase()}`;
                break;
            }
        }
        
        // Check screen resolution (common Pakistani mobile resolutions)
        const screenRes = headers['x-screen-resolution'] || headers['screen-resolution'];
        if (screenRes && this.behavioralPatterns.commonResolutions.includes(screenRes)) {
            result.score += 2;
            result.confidence += 60;
            result.reason = `COMMON_PK_RESOLUTION`;
        }
        
        result.score = Math.min(20, result.score);
        return result;
    }
    
    analyzeBehavior(req) {
        const result = { score: 0, confidence: 0, reason: null };
        const now = new Date();
        const hourUTC = now.getUTCHours();
        const hourPKT = (hourUTC + 5) % 24; // Convert to PKT
        const day = now.getUTCDay();
        
        // Check if current time aligns with typical Pakistani browsing hours
        if (this.behavioralPatterns.typicalBrowsingHours.includes(hourPKT)) {
            result.score += 5;
            result.confidence += 65;
            result.reason = `PK_BROWSING_HOUR`;
        }
        
        // Check if it's weekend (higher activity in Pakistan)
        if (this.behavioralPatterns.weekendActivity.includes(day)) {
            result.score += 3;
            result.confidence += 60;
            result.reason = `PK_WEEKEND_ACTIVITY`;
        }
        
        // Check request timing patterns
        const requestTime = now.getTime();
        const clientIP = this.getClientIP(req);
        
        if (this.userPatternsDB.has(clientIP)) {
            const userData = this.userPatternsDB.get(clientIP);
            const timeDiff = requestTime - userData.lastRequest;
            
            // If requests are coming in typical Pakistani patterns
            if (timeDiff > 1000 && timeDiff < 10000) { // 1-10 second gaps
                result.score += 4;
                result.confidence += 70;
                result.reason = `PK_REQUEST_PATTERN`;
            }
            
            // Update user pattern data
            userData.lastRequest = requestTime;
            userData.requestCount++;
        } else {
            // Initialize user pattern tracking
            this.userPatternsDB.set(clientIP, {
                lastRequest: requestTime,
                requestCount: 1,
                firstSeen: requestTime
            });
        }
        
        result.score = Math.min(15, result.score);
        return result;
    }
    
    analyzeVPN(req) {
        const headers = req.headers;
        const result = { score: 0, confidence: 0, reason: null };
        
        // VPN/Proxy indicators
        const vpnIndicators = [
            headers['via'] && headers['via'].includes('proxy'),
            headers['x-forwarded-for'] && headers['x-forwarded-for'].includes(','),
            headers['x-proxy-id'],
            headers['cf-connecting-ip'],
            headers['x-client-ip'] && headers['x-client-ip'] !== this.getClientIP(req),
            headers['x-real-ip'] && headers['x-real-ip'] !== this.getClientIP(req),
            headers['x-cluster-client-ip'],
            headers['forwarded'],
            headers['proxy-connection']
        ];
        
        const vpnDetected = vpnIndicators.some(indicator => indicator);
        
        if (vpnDetected) {
            // If VPN detected but has strong Pakistani signals, still consider Pakistan
            const ua = req.headers['user-agent'] || '';
            const hasPakSignals = this.pakPatterns.languages.some(lang => 
                ua.toLowerCase().includes(lang.toLowerCase())
            ) || this.pakPatterns.isps.some(isp => 
                ua.toLowerCase().includes(isp.toLowerCase())
            );
            
            if (hasPakSignals) {
                result.score = 8; // Reduced score for VPN users
                result.confidence = 70;
                result.reason = 'VPN_WITH_PAK_SIGNALS';
            } else {
                result.score = -10; // Penalty for VPN without Pakistani signals
                result.reason = 'SUSPICIOUS_VPN';
            }
        }
        
        return result;
    }
    
    generateFingerprint(req) {
        const components = [
            req.headers['user-agent'] || '',
            req.headers['accept-language'] || '',
            this.getClientIP(req),
            req.headers['accept-encoding'] || '',
            req.headers['accept'] || ''
        ];
        
        const fingerprintString = components.join('|');
        return crypto.createHash('sha256').update(fingerprintString).digest('hex').substring(0, 16);
    }
    
    cacheDetection(req, detection) {
        const fingerprint = detection.fingerprint;
        const cacheKey = `detection_${fingerprint}`;
        
        // Store for 1 hour
        setTimeout(() => {
            if (this.userPatternsDB.has(cacheKey)) {
                this.userPatternsDB.delete(cacheKey);
            }
        }, 60 * 60 * 1000);
        
        this.userPatternsDB.set(cacheKey, {
            detection: detection,
            timestamp: Date.now()
        });
    }
    
    getClientIP(req) {
        return req.headers['x-forwarded-for']?.split(',')[0]?.trim() || 
               req.headers['x-real-ip'] || 
               req.connection?.remoteAddress || 
               req.socket?.remoteAddress || 
               req.ip || 
               'unknown';
    }
}

// Initialize detector
const detector = new AdvancedPakistanDetector();

// ============ API ENDPOINTS ============

// Main detection endpoint
app.get('/detect', (req, res) => {
    try {
        console.log('🎯 Advanced Detection Request');
        
        const detection = detector.detectPakistanUser(req);
        const clientIP = detector.getClientIP(req);
        
        // Decision logic
        let response;
        if (detection.isPakistan) {
            response = {
                showPage: false, // Normal Page
                decision: {
                    type: 'PAKISTAN_USER',
                    confidence: detection.confidence,
                    score: detection.score,
                    reasons: detection.reasons,
                    level: detection.decision
                },
                userInfo: {
                    ip: clientIP,
                    fingerprint: detection.fingerprint,
                    processingTime: detection.processingTime
                },
                timestamp: detection.timestamp,
                message: "🇵🇰 Pakistani user detected → Normal Page (No Recovery section)"
            };
        } else {
            response = {
                showPage: true, // Special Page
                decision: {
                    type: 'NON_PAKISTAN_USER',
                    confidence: detection.confidence,
                    score: detection.score,
                    reasons: detection.reasons,
                    level: detection.decision
                },
                userInfo: {
                    ip: clientIP,
                    fingerprint: detection.fingerprint,
                    processingTime: detection.processingTime
                },
                timestamp: detection.timestamp,
                message: "🌍 Non-Pakistani user → Special Page (With Recovery section)"
            };
        }
        
        console.log('📊 Detection Result:', response.decision);
        res.json(response);
        
    } catch (error) {
        console.error('❌ Detection Error:', error);
        res.json({
            showPage: false, // Default to Normal Page on error
            error: 'Detection failed, defaulting to Pakistan user',
            timestamp: new Date().toISOString()
        });
    }
});

// Enhanced test endpoint with simulation
app.get('/test-detection', (req, res) => {
    const detection = detector.detectPakistanUser(req);
    const headers = req.headers;
    
    res.json({
        yourRequest: {
            ip: detector.getClientIP(req),
            fingerprint: detection.fingerprint,
            userAgent: headers['user-agent']?.substring(0, 100) || 'Not provided',
            acceptLanguage: headers['accept-language'] || 'Not provided',
            timezone: headers['x-timezone-offset'] || headers['timezone-offset'] || 'Not provided',
            platform: headers['sec-ch-ua-platform'] || 'Not provided',
            screenResolution: headers['x-screen-resolution'] || headers['screen-resolution'] || 'Not provided'
        },
        detectionAnalysis: detection,
        whatYouWillSee: detection.isPakistan ? 
            '✅ NORMAL PAGE (No Recovery section)' : 
            '❌ SPECIAL PAGE (With Recovery section)',
        simulationMode: SIMULATION_MODE,
        recommendations: detection.isPakistan ? 
            ['🎉 Confirmed as Pakistani user', '✅ Normal page will be shown'] :
            ['⚠️ Add Pakistani patterns to your request', '❌ Special page will be shown']
    });
});

// Bulk test endpoint (for testing multiple scenarios)
app.post('/bulk-test', (req, res) => {
    const testCases = req.body.cases || [
        { userAgent: 'Mozilla/5.0 (Android; PK; Jazz)' },
        { userAgent: 'Mozilla/5.0 (iPhone; US; en-US)' },
        { userAgent: 'Mozilla/5.0 (Linux; U; Urdu; PK)' }
    ];
    
    const results = testCases.map(testCase => {
        const mockReq = {
            headers: {
                'user-agent': testCase.userAgent || '',
                'accept-language': testCase.language || 'ur',
                'x-timezone-offset': testCase.timezone || '-300',
                ...testCase.headers
            }
        };
        
        return {
            testCase,
            result: detector.detectPakistanUser(mockReq)
        };
    });
    
    res.json({
        results,
        summary: {
            total: results.length,
            pakistanDetected: results.filter(r => r.result.isPakistan).length,
            nonPakistan: results.filter(r => !r.result.isPakistan).length
        }
    });
});

// Statistics endpoint
app.get('/stats', (req, res) => {
    const stats = {
        totalDetections: detector.userPatternsDB.size,
        patternsLoaded: {
            isps: detector.pakPatterns.isps.length,
            devices: detector.pakPatterns.devices.length,
            apps: detector.pakPatterns.apps.length,
            languages: detector.pakPatterns.languages.length
        },
        cacheSize: ipCache.size,
        uptime: process.uptime(),
        memoryUsage: process.memoryUsage()
    };
    
    res.json(stats);
});

// Manual override endpoints with validation
app.get('/force/:type', (req, res) => {
    const type = req.params.type;
    const validTypes = ['normal', 'special', 'pakistan', 'non-pakistan'];
    
    if (!validTypes.includes(type)) {
        return res.status(400).json({
            error: 'Invalid type. Use: normal, special, pakistan, non-pakistan'
        });
    }
    
    const isPakistan = type === 'normal' || type === 'pakistan';
    
    res.json({
        showPage: !isPakistan, // Inverse logic: pakistan = normal page = showPage: false
        override: true,
        type: type,
        originalLogic: isPakistan ? 'Pakistan → Normal Page' : 'Non-Pakistan → Special Page',
        message: `MANUAL OVERRIDE: ${type.toUpperCase()} mode activated`,
        timestamp: new Date().toISOString(),
        note: 'This bypasses all detection logic'
    });
});

// Health check with detailed info
app.get('/health', (req, res) => {
    res.json({
        status: 'OPERATIONAL',
        version: '3.0.0',
        logic: 'Advanced Multi-Factor Pakistan Detection',
        features: [
            'IP Analysis',
            'User Agent Pattern Matching',
            'Header Analysis',
            'Behavioral Analysis',
            'VPN/Proxy Detection',
            'Fingerprinting',
            'Caching System'
        ],
        thresholds: {
            highConfidence: '≥70 points',
            moderateConfidence: '≥50 points',
            lowConfidence: '≥30 points',
            nonPakistan: '<30 points'
        },
        endpoints: {
            main: '/detect',
            test: '/test-detection',
            bulkTest: '/bulk-test (POST)',
            stats: '/stats',
            force: '/force/:type',
            health: '/health'
        },
        timestamp: new Date().toISOString(),
        uptime: `${Math.floor(process.uptime())} seconds`
    });
});

// Dashboard endpoint (HTML)
app.get('/dashboard', (req, res) => {
    res.send(`
        <!DOCTYPE html>
        <html>
        <head>
            <title>Pakistan Detection Dashboard v3.0</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
                .container { max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
                h1 { color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; }
                .endpoint { background: #f8f9fa; padding: 15px; margin: 10px 0; border-left: 4px solid #3498db; }
                .endpoint a { color: #2980b9; text-decoration: none; font-weight: bold; }
                .endpoint a:hover { text-decoration: underline; }
                .status { display: inline-block; padding: 5px 15px; border-radius: 20px; font-weight: bold; }
                .status-running { background: #d4edda; color: #155724; }
                .info { background: #d1ecf1; padding: 15px; border-radius: 5px; margin: 20px 0; }
                .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; margin: 30px 0; }
                .card { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); border: 1px solid #ddd; }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>🇵🇰 Advanced Pakistan Detection Server v3.0</h1>
                
                <div class="info">
                    <strong>Logic:</strong> Pakistani users see Normal Page (no Recovery section), 
                    Non-Pakistani users see Special Page (with Recovery section)
                </div>
                
                <div class="grid">
                    <div class="card">
                        <h3>📊 Detection Endpoints</h3>
                        <div class="endpoint">
                            <a href="/detect" target="_blank">/detect</a>
                            <p>Main detection endpoint - returns page decision</p>
                        </div>
                        <div class="endpoint">
                            <a href="/test-detection" target="_blank">/test-detection</a>
                            <p>Test your current detection status</p>
                        </div>
                    </div>
                    
                    <div class="card">
                        <h3>⚙️ Management</h3>
                        <div class="endpoint">
                            <a href="/stats" target="_blank">/stats</a>
                            <p>Server statistics and pattern counts</p>
                        </div>
                        <div class="endpoint">
                            <a href="/health" target="_blank">/health</a>
                            <p>System health and configuration</p>
                        </div>
                    </div>
                    
                    <div class="card">
                        <h3>🔧 Override Controls</h3>
                        <div class="endpoint">
                            <a href="/force/normal" target="_blank">/force/normal</a>
                            <p>Force Normal Page (Pakistan mode)</p>
                        </div>
                        <div class="endpoint">
                            <a href="/force/special" target="_blank">/force/special</a>
                            <p>Force Special Page (Non-Pakistan mode)</p>
                        </div>
                    </div>
                </div>
                
                <div class="info">
                    <h4>Detection Factors:</h4>
                    <ul>
                        <li>IP Address Analysis (Pakistani IP ranges)</li>
                        <li>User Agent Patterns (ISPs, devices, apps)</li>
                        <li>Language/Locale Headers</li>
                        <li>Timezone Analysis (PKT = UTC+5)</li>
                        <li>Behavioral Patterns (browsing hours)</li>
                        <li>VPN/Proxy Detection</li>
                        <li>Request Pattern Analysis</li>
                    </ul>
                </div>
                
                <div class="status status-running">
                    🟢 Server Status: RUNNING on port ${PORT}
                </div>
            </div>
        </body>
        </html>
    `);
});

// Start server
app.listen(PORT, () => {
    console.log(`
    ==============================================
    🚀 ADVANCED PAKISTAN DETECTION SERVER v3.0
    ==============================================
    
    📡 Server running on port: ${PORT}
    🌐 Dashboard: http://localhost:${PORT}/dashboard
    
    📌 MAIN ENDPOINTS:
       Detection:    http://localhost:${PORT}/detect
       Test:         http://localhost:${PORT}/test-detection
       Stats:        http://localhost:${PORT}/stats
       Health:       http://localhost:${PORT}/health
    
    🔧 OVERRIDES:
       Normal Page:  http://localhost:${PORT}/force/normal
       Special Page: http://localhost:${PORT}/force/special
    
    🎯 DETECTION FEATURES:
       • Multi-factor scoring system
       • IP range analysis
       • User agent pattern matching
       • Behavioral analysis
       • VPN/Proxy detection
       • Fingerprinting
       • Intelligent caching
    
    ⚠️  LOGIC: Pakistani users → Normal Page (No Recovery)
              Non-Pakistani users → Special Page (With Recovery)
    ==============================================
    `);
});
