// server-ultimate-pakistan-vpn.js
const express = require('express');
const crypto = require('crypto');
const cors = require('cors');
const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

class UltimatePakistanVPNDetector {
    constructor() {
        // Pakistan IP database (extensive)
        this.pakIPDatabase = this.loadPakistanIPDatabase();
        
        // Known VPN/Proxy providers
        this.vpnProviders = this.loadVPNProviders();
        
        // User behavior patterns cache
        this.userPatterns = new Map();
        
        // VPN detection but Pakistan-friendly
        this.config = {
            strictMode: false, // false = lenient for Pakistan users
            vpnPenalty: 0, // No penalty for VPN users
            pakistanBonus: 50, // Bonus for Pakistan signals
            defaultToNormal: true // Default to Normal Page
        };
    }
    
    loadPakistanIPDatabase() {
        return {
            // Major Pakistani ISPs
            isps: {
                ptcl: [
                    '101.50.', '101.51.', '101.52.', '101.53.', '101.54.', '101.55.',
                    '110.36.', '110.37.', '110.38.', '110.39.', '110.40.', '110.41.',
                    '111.68.', '111.69.', '111.70.', '111.71.', '111.72.', '111.73.',
                    '119.152.', '119.153.', '119.154.', '119.155.', '119.156.',
                    '203.82.', '203.83.', '203.84.', '203.124.', '203.135.', '203.215.',
                    '210.56.', '223.29.', '223.30.'
                ],
                jazz: [
                    '39.34.', '39.35.', '39.36.', '39.37.', '39.38.', '39.39.',
                    '39.40.', '39.41.', '39.42.', '39.43.', '39.44.', '39.45.',
                    '39.46.', '39.47.', '39.48.', '39.49.'
                ],
                telenor: [
                    '116.0.', '116.1.', '116.2.', '116.3.', '116.4.', '116.5.',
                    '116.6.', '116.7.', '116.8.', '116.9.', '116.10.', '116.11.'
                ],
                zong: [
                    '117.102.', '117.103.', '117.104.', '117.105.', '117.106.',
                    '117.107.', '117.108.', '117.109.', '117.110.'
                ],
                ufone: [
                    '182.176.', '182.177.', '182.178.', '182.179.', '182.180.',
                    '182.181.', '182.182.', '182.183.'
                ],
                nayatel: [
                    '175.107.', '175.108.', '175.109.', '175.110.'
                ],
                stormfiber: [
                    '103.4.', '103.5.', '103.6.'
                ],
                transworld: [
                    '202.69.', '202.70.', '202.71.'
                ]
            },
            
            // Pakistani data centers/cloud
            datacenters: [
                '149.40.', '149.50.', '149.60.', '149.70.',
                '150.129.', '150.130.', '150.140.', '150.150.',
                '153.92.', '154.16.', '154.17.', '154.18.',
                '202.47.', '202.48.', '202.49.', '202.50.',
                '210.1.', '210.2.', '210.3.', '210.4.',
                '223.176.', '223.177.', '223.178.', '223.179.'
            ],
            
            // Pakistani mobile networks
            mobile: [
                '39.', '116.', '117.', '182.'
            ],
            
            // All Pakistan IPs combined
            all: function() {
                return [
                    ...this.isps.ptcl,
                    ...this.isps.jazz,
                    ...this.isps.telenor,
                    ...this.isps.zong,
                    ...this.isps.ufone,
                    ...this.isps.nayatel,
                    ...this.isps.stormfiber,
                    ...this.isps.transworld,
                    ...this.datacenters,
                    ...this.mobile
                ];
            }()
        };
    }
    
    loadVPNProviders() {
        return {
            // Common VPN services (but we're Pakistan-friendly)
            services: [
                'nordvpn', 'expressvpn', 'surfshark', 'cyberghost',
                'pia', 'ipvanish', 'vyprvpn', 'hotspotshield',
                'tunnelbear', 'windscribe', 'protonvpn', 'hide.me',
                'purevpn', 'zenmate', 'safervpn', 'ivacy'
            ],
            
            // VPN server IP patterns (but we treat them neutrally)
            ipRanges: [
                '185.159.', '185.160.', '185.161.', '185.162.',
                '193.29.', '194.110.', '194.111.', '194.112.',
                '212.102.', '213.152.', '213.153.', '213.154.',
                '91.108.', '91.109.', '91.110.', '91.111.',
                '95.211.', '95.212.', '95.213.', '95.214.',
                '104.200.', '104.201.', '104.202.', '104.203.',
                '107.189.', '107.190.', '107.191.', '107.192.',
                '141.98.', '141.99.', '141.100.', '141.101.',
                '146.70.', '146.71.', '146.72.', '146.73.',
                '152.89.', '152.90.', '152.91.', '152.92.',
                '172.67.', '172.68.', '172.69.', '172.70.',
                '198.54.', '198.55.', '198.56.', '198.57.'
            ],
            
            // VPN headers (but we don't penalize)
            headers: [
                'via', 'x-forwarded-for', 'x-proxy-id', 'cf-connecting-ip',
                'x-client-ip', 'x-real-ip', 'x-cluster-client-ip',
                'forwarded', 'proxy-connection', 'x-proxy-user-ip',
                'cf-ipcountry', 'cf-ray', 'cf-visitor'
            ]
        };
    }
    
    analyzeRequest(req) {
        const ip = this.getClientIP(req);
        const userAgent = req.headers['user-agent'] || '';
        const language = req.headers['accept-language'] || '';
        const timestamp = Date.now();
        
        console.log(`\n🔍 Analyzing Request: ${ip.substring(0, 15)}...`);
        
        // Multi-dimensional analysis
        const analysis = {
            ip: this.analyzeIP(ip),
            userAgent: this.analyzeUserAgent(userAgent),
            language: this.analyzeLanguage(language),
            headers: this.analyzeHeaders(req.headers),
            behavior: this.analyzeBehavior(req, ip, timestamp),
            vpn: this.analyzeVPN(req, ip) // VPN analysis but friendly
        };
        
        // Calculate total Pakistan score
        let pakistanScore = 0;
        let reasons = [];
        
        // IP Analysis (30 points max)
        if (analysis.ip.isPakistan) {
            pakistanScore += 30;
            reasons.push(`IP_${analysis.ip.reason}`);
        }
        
        // User Agent Analysis (25 points max)
        if (analysis.userAgent.isPakistan) {
            pakistanScore += analysis.userAgent.score;
            reasons.push(`UA_${analysis.userAgent.reason}`);
        }
        
        // Language Analysis (20 points max)
        if (analysis.language.isPakistan) {
            pakistanScore += analysis.language.score;
            reasons.push(`LANG_${analysis.language.reason}`);
        }
        
        // Header Analysis (15 points max)
        if (analysis.headers.isPakistan) {
            pakistanScore += analysis.headers.score;
            reasons.push(`HEADER_${analysis.headers.reason}`);
        }
        
        // Behavior Analysis (10 points max)
        if (analysis.behavior.suggestsPakistan) {
            pakistanScore += analysis.behavior.score;
            reasons.push(`BEHAVIOR_${analysis.behavior.reason}`);
        }
        
        // **CRITICAL: VPN does NOT reduce score!**
        // Instead, check if VPN user shows Pakistan patterns
        if (analysis.vpn.detected) {
            console.log(`⚠️ VPN detected but no penalty: ${analysis.vpn.type}`);
            
            // If VPN user has Pakistan patterns, INCREASE confidence
            if (analysis.ip.isPakistan || analysis.userAgent.isPakistan || 
                analysis.language.isPakistan || analysis.headers.isPakistan) {
                pakistanScore += 10; // Bonus for Pakistan VPN users
                reasons.push(`VPN_PAK_BONUS`);
            }
        }
        
        // Ensure minimum score for any Pakistan signal
        const hasAnyPakistanSignal = analysis.ip.isPakistan || 
                                    analysis.userAgent.isPakistan || 
                                    analysis.language.isPakistan || 
                                    analysis.headers.isPakistan;
        
        if (hasAnyPakistanSignal) {
            pakistanScore = Math.max(pakistanScore, 40); // Minimum 40 if any Pakistan signal
        }
        
        // Final decision
        const isPakistan = pakistanScore >= 30 || this.config.defaultToNormal;
        
        return {
            isPakistan,
            score: pakistanScore,
            confidence: Math.min(100, pakistanScore),
            reasons,
            analysis,
            showPage: !isPakistan // false = Normal Page, true = Special Page
        };
    }
    
    analyzeIP(ip) {
        if (!ip || ip === 'unknown') {
            return { isPakistan: false, reason: 'NO_IP', score: 0 };
        }
        
        // Local/testing IPs = Pakistan
        if (ip === '127.0.0.1' || ip === '::1' || 
            ip.startsWith('192.168.') || ip.startsWith('10.') ||
            ip.startsWith('172.16.') || ip.startsWith('172.17.') ||
            ip.startsWith('172.18.') || ip.startsWith('172.19.') ||
            ip.startsWith('172.20.') || ip.startsWith('172.21.') ||
            ip.startsWith('172.22.') || ip.startsWith('172.23.') ||
            ip.startsWith('172.24.') || ip.startsWith('172.25.') ||
            ip.startsWith('172.26.') || ip.startsWith('172.27.') ||
            ip.startsWith('172.28.') || ip.startsWith('172.29.') ||
            ip.startsWith('172.30.') || ip.startsWith('172.31.')) {
            return { isPakistan: true, reason: 'LOCAL_IP', score: 30 };
        }
        
        // Check all Pakistan IP ranges
        for (const range of this.pakIPDatabase.all) {
            if (ip.startsWith(range)) {
                return { isPakistan: true, reason: `PAK_RANGE_${range}`, score: 30 };
            }
        }
        
        // Check if IP looks like Pakistan IP (pattern matching)
        const ipParts = ip.split('.');
        if (ipParts.length === 4) {
            const firstOctet = parseInt(ipParts[0]);
            const secondOctet = parseInt(ipParts[1]);
            
            // Common Pakistan IP patterns
            if (firstOctet === 101 || firstOctet === 110 || firstOctet === 111) {
                return { isPakistan: true, reason: 'PAK_PATTERN', score: 25 };
            }
            if (firstOctet === 39 && secondOctet >= 34 && secondOctet <= 49) {
                return { isPakistan: true, reason: 'JAZZ_PATTERN', score: 30 };
            }
            if (firstOctet === 116 && secondOctet <= 11) {
                return { isPakistan: true, reason: 'TELENOR_PATTERN', score: 30 };
            }
            if (firstOctet === 117 && secondOctet >= 102 && secondOctet <= 110) {
                return { isPakistan: true, reason: 'ZONG_PATTERN', score: 30 };
            }
            if (firstOctet === 182 && secondOctet >= 176 && secondOctet <= 183) {
                return { isPakistan: true, reason: 'UFONE_PATTERN', score: 30 };
            }
        }
        
        // If no Pakistan IP detected, return false
        return { isPakistan: false, reason: 'NON_PAK_IP', score: 0 };
    }
    
    analyzeUserAgent(ua) {
        if (!ua) {
            return { isPakistan: false, score: 0, reason: 'NO_UA' };
        }
        
        const uaLower = ua.toLowerCase();
        let score = 0;
        let reason = '';
        
        // Pakistan ISP patterns
        const pakISPs = ['jazz', 'telenor', 'zong', 'ufone', 'mobilink', 'warid', 
                        'ptcl', 'nayatel', 'witribe', 'stormfiber', 'transworld'];
        
        for (const isp of pakISPs) {
            if (uaLower.includes(isp)) {
                score += 15;
                reason = `ISP_${isp.toUpperCase()}`;
                break;
            }
        }
        
        // Pakistan city patterns
        const pakCities = ['karachi', 'lahore', 'islamabad', 'rawalpindi', 'multan',
                          'peshawar', 'quetta', 'faisalabad', 'hyderabad', 'sialkot'];
        
        for (const city of pakCities) {
            if (uaLower.includes(city)) {
                score += 10;
                reason = reason || `CITY_${city.toUpperCase()}`;
                break;
            }
        }
        
        // Pakistan app patterns
        const pakApps = ['easypaisa', 'jazzcash', 'upaisa', 'sadapay', 'nayapay',
                        'daraz', 'foodpanda', 'bykea', 'careem', 'indrive'];
        
        for (const app of pakApps) {
            if (uaLower.includes(app)) {
                score += 12;
                reason = reason || `APP_${app.toUpperCase()}`;
                break;
            }
        }
        
        // Pakistan device patterns
        const pakDevices = ['qmobile', 'infinix', 'tecno', 'voice', 'gfive', 'dany'];
        
        for (const device of pakDevices) {
            if (uaLower.includes(device)) {
                score += 8;
                reason = reason || `DEVICE_${device.toUpperCase()}`;
                break;
            }
        }
        
        // Country codes
        if (uaLower.includes('pk') || uaLower.includes('pak') || uaLower.includes('pakistan')) {
            score += 20;
            reason = reason || 'COUNTRY_CODE';
        }
        
        // Language hints
        if (uaLower.includes('urdu') || uaLower.includes('ur-') || uaLower.includes('ps-')) {
            score += 15;
            reason = reason || 'LANGUAGE_HINT';
        }
        
        return {
            isPakistan: score > 0,
            score: Math.min(25, score),
            reason: reason || 'NO_PAK_SIGNALS'
        };
    }
    
    analyzeLanguage(lang) {
        if (!lang) {
            return { isPakistan: false, score: 0, reason: 'NO_LANG' };
        }
        
        const langLower = lang.toLowerCase();
        let score = 0;
        let reason = '';
        
        // Pakistan language codes
        const pakLanguages = [
            'ur', 'ur-pk', 'ur_pk', 'ps', 'sd', 'pa', 
            'balochi', 'sindhi', 'punjabi', 'saraiki', 'pashto', 'hindko'
        ];
        
        for (const language of pakLanguages) {
            if (langLower.includes(language)) {
                score += 20;
                reason = `LANG_${language.toUpperCase()}`;
                break;
            }
        }
        
        // Country codes in language
        if (langLower.includes('pk') || langLower.includes('pak')) {
            score += 15;
            reason = reason || 'LANG_COUNTRY_CODE';
        }
        
        // Region hints
        if (langLower.includes('asia') && (langLower.includes('south') || langLower.includes('central'))) {
            score += 10;
            reason = reason || 'SOUTH_ASIA_REGION';
        }
        
        return {
            isPakistan: score > 0,
            score: Math.min(20, score),
            reason: reason || 'NO_PAK_LANG'
        };
    }
    
    analyzeHeaders(headers) {
        let score = 0;
        let reason = '';
        
        // Timezone analysis (PKT = UTC+5 = -300 minutes)
        const timezone = headers['x-timezone-offset'] || headers['timezone-offset'];
        if (timezone && parseInt(timezone) === -300) {
            score += 15;
            reason = 'PKT_TIMEZONE';
        }
        
        // Accept-Language already analyzed, but check for Urdu/Pakistan
        const acceptLang = headers['accept-language'] || '';
        if (acceptLang.includes('ur') || acceptLang.includes('ps')) {
            score += 10;
            reason = reason || 'HEADER_LANGUAGE';
        }
        
        // Platform/device hints
        const platform = headers['sec-ch-ua-platform'] || '';
        if (platform.includes('Android') || platform.includes('iOS')) {
            // Mobile users more likely in Pakistan
            score += 5;
            reason = reason || 'MOBILE_PLATFORM';
        }
        
        return {
            isPakistan: score > 0,
            score: Math.min(15, score),
            reason: reason || 'NO_HEADER_SIGNALS'
        };
    }
    
    analyzeBehavior(req, ip, timestamp) {
        // Track user patterns
        const userKey = this.getUserKey(req);
        
        if (!this.userPatterns.has(userKey)) {
            this.userPatterns.set(userKey, {
                firstSeen: timestamp,
                requestCount: 1,
                lastRequest: timestamp,
                patterns: []
            });
        } else {
            const userData = this.userPatterns.get(userKey);
            userData.requestCount++;
            userData.lastRequest = timestamp;
            
            // Check if behavior suggests Pakistan (frequent requests during PK hours)
            const now = new Date(timestamp);
            const hourUTC = now.getUTCHours();
            const hourPKT = (hourUTC + 5) % 24; // Convert to PKT
            
            // Pakistan peak hours: 10 AM - 12 PM, 6 PM - 11 PM PKT
            const isPeakHour = (hourPKT >= 10 && hourPKT <= 12) || (hourPKT >= 18 && hourPKT <= 23);
            
            if (isPeakHour && userData.requestCount > 3) {
                return {
                    suggestsPakistan: true,
                    score: 10,
                    reason: 'PK_PEAK_ACTIVITY'
                };
            }
        }
        
        return {
            suggestsPakistan: false,
            score: 0,
            reason: 'NO_BEHAVIOR_PATTERN'
        };
    }
    
    analyzeVPN(req, ip) {
        const headers = req.headers;
        let detected = false;
        let type = '';
        
        // Check VPN headers
        for (const header of this.vpnProviders.headers) {
            if (headers[header]) {
                detected = true;
                type = `HEADER_${header.toUpperCase()}`;
                break;
            }
        }
        
        // Check VPN IP ranges
        for (const range of this.vpnProviders.ipRanges) {
            if (ip.startsWith(range)) {
                detected = true;
                type = 'VPN_IP_RANGE';
                break;
            }
        }
        
        // Check VPN service names in User-Agent
        const userAgent = (headers['user-agent'] || '').toLowerCase();
        for (const vpn of this.vpnProviders.services) {
            if (userAgent.includes(vpn)) {
                detected = true;
                type = `SERVICE_${vpn.toUpperCase()}`;
                break;
            }
        }
        
        return { detected, type };
    }
    
    getUserKey(req) {
        // Create a unique key for user tracking
        const components = [
            this.getClientIP(req),
            req.headers['user-agent'] || '',
            req.headers['accept-language'] || ''
        ];
        
        return crypto
            .createHash('md5')
            .update(components.join('|'))
            .digest('hex')
            .substring(0, 12);
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
const detector = new UltimatePakistanVPNDetector();

// ============ MIDDLEWARE ============
app.use((req, res, next) => {
    req.startTime = Date.now();
    req.requestId = crypto.randomBytes(4).toString('hex');
    console.log(`[${req.requestId}] ${req.method} ${req.url}`);
    next();
});

// ============ API ENDPOINTS ============

app.get('/detect', (req, res) => {
    try {
        console.log(`[${req.requestId}] Starting detection...`);
        
        const analysis = detector.analyzeRequest(req);
        const clientIP = detector.getClientIP(req);
        
        console.log(`[${req.requestId}] Detection Result:`, {
            isPakistan: analysis.isPakistan,
            score: analysis.score,
            showPage: analysis.showPage ? 'SPECIAL' : 'NORMAL',
            reasons: analysis.reasons
        });
        
        const response = {
            showPage: analysis.showPage, // false = Normal Page, true = Special Page
            decision: {
                isPakistan: analysis.isPakistan,
                score: analysis.score,
                confidence: analysis.confidence,
                reasons: analysis.reasons,
                vpnDetected: analysis.analysis.vpn.detected,
                vpnType: analysis.analysis.vpn.type,
                message: analysis.isPakistan ? 
                    'Pakistan user detected' : 
                    'Non-Pakistan user detected'
            },
            userInfo: {
                ip: clientIP,
                userAgent: req.headers['user-agent']?.substring(0, 80) || 'unknown',
                language: req.headers['accept-language'] || 'unknown',
                fingerprint: detector.getUserKey(req)
            },
            analysis: {
                ip: analysis.analysis.ip,
                userAgent: analysis.analysis.userAgent,
                language: analysis.analysis.language,
                headers: analysis.analysis.headers
            },
            timestamp: new Date().toISOString(),
            processingTime: Date.now() - req.startTime,
            message: analysis.showPage ? 
                "🌍 Special Page (WITH Recovery section)" : 
                "🇵🇰 Normal Page (NO Recovery section)"
        };
        
        console.log(`[${req.requestId}] Response: ${response.message}`);
        
        res.json(response);
        
    } catch (error) {
        console.error(`[${req.requestId}] Error:`, error);
        res.json({
            showPage: false, // Default to Normal Page on error
            error: 'Detection failed, defaulting to Normal Page',
            timestamp: new Date().toISOString(),
            message: "Default: Normal Page"
        });
    }
});

// Advanced test endpoint
app.get('/analyze', (req, res) => {
    const analysis = detector.analyzeRequest(req);
    
    res.json({
        detailedAnalysis: analysis,
        interpretation: {
            isPakistan: analysis.isPakistan,
            showPage: analysis.showPage ? 'SPECIAL' : 'NORMAL',
            explanation: analysis.reasons.join(', ')
        },
        recommendations: analysis.isPakistan ? [] : [
            'Add Pakistan signals to User-Agent',
            'Set accept-language to ur-pk',
            'Use Pakistan timezone (UTC+5)',
            'Include Pakistan ISP name in headers'
        ]
    });
});

// VPN test endpoint
app.get('/test-vpn', (req, res) => {
    // Create test requests with VPN
    const testCases = [
        {
            name: 'Pakistan User with VPN Headers',
            headers: {
                'user-agent': 'Mozilla/5.0 (Android; PK; Jazz)',
                'accept-language': 'ur-pk,en;q=0.9',
                'x-forwarded-for': '185.159.100.100, 101.50.200.100'
            }
        },
        {
            name: 'Pakistan User with VPN IP',
            headers: {
                'user-agent': 'Mozilla/5.0 (iPhone; Pakistan)',
                'accept-language': 'en-pk',
                'x-real-ip': '185.159.100.100'
            }
        },
        {
            name: 'India User with VPN',
            headers: {
                'user-agent': 'Mozilla/5.0 (Android; India; Airtel VPN)',
                'accept-language': 'en-in,hi;q=0.9',
                'via': '1.1 nordvpn'
            }
        }
    ];
    
    const results = testCases.map(testCase => {
        const mockReq = {
            headers: { ...req.headers, ...testCase.headers },
            ip: '185.159.100.100'
        };
        
        const analysis = detector.analyzeRequest(mockReq);
        
        return {
            testCase: testCase.name,
            isPakistan: analysis.isPakistan,
            showPage: analysis.showPage ? 'SPECIAL' : 'NORMAL',
            score: analysis.score,
            vpnDetected: analysis.analysis.vpn.detected,
            reasons: analysis.reasons
        };
    });
    
    res.json({
        testResults: results,
        summary: {
            totalTests: results.length,
            pakistanNormalPages: results.filter(r => !r.showPage).length,
            specialPages: results.filter(r => r.showPage).length
        },
        logic: 'VPN does NOT affect Pakistan detection. Pakistan users get Normal Page regardless of VPN.'
    });
});

// Force endpoints
app.get('/force-normal', (req, res) => {
    res.json({
        showPage: false,
        forced: true,
        message: "FORCED: Normal Page",
        timestamp: new Date().toISOString(),
        note: "Bypasses all detection - shows Normal Page"
    });
});

app.get('/force-special', (req, res) => {
    res.json({
        showPage: true,
        forced: true,
        message: "FORCED: Special Page",
        timestamp: new Date().toISOString(),
        note: "Bypasses all detection - shows Special Page"
    });
});

// Statistics
app.get('/stats', (req, res) => {
    res.json({
        detectorStats: {
            pakIPRanges: detector.pakIPDatabase.all.length,
            vpnProviders: detector.vpnProviders.services.length,
            trackedUsers: detector.userPatterns.size,
            config: detector.config
        },
        system: {
            uptime: process.uptime(),
            memory: process.memoryUsage(),
            nodeVersion: process.version
        }
    });
});

// Dashboard
app.get('/', (req, res) => {
    res.send(`
        <!DOCTYPE html>
        <html>
        <head>
            <title>Ultimate Pakistan Detection (VPN Friendly)</title>
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <style>
                * { margin: 0; padding: 0; box-sizing: border-box; }
                body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif; 
                       background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; padding: 20px; }
                .container { max-width: 1200px; margin: 0 auto; }
                .card { background: white; border-radius: 20px; padding: 40px; margin: 20px 0; 
                        box-shadow: 0 20px 60px rgba(0,0,0,0.3); }
                h1 { color: white; text-align: center; margin-bottom: 30px; font-size: 2.8em; 
                     text-shadow: 0 2px 10px rgba(0,0,0,0.3); }
                h2 { color: #333; margin-bottom: 25px; font-size: 1.8em; border-bottom: 3px solid #667eea; padding-bottom: 10px; }
                .logic-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 25px; margin: 30px 0; }
                .logic-card { background: #f8f9fa; padding: 25px; border-radius: 15px; border-left: 5px solid; }
                .pakistan-card { border-left-color: #059669; }
                .special-card { border-left-color: #dc2626; }
                .status { display: inline-block; padding: 8px 20px; border-radius: 50px; font-weight: bold; margin: 5px; }
                .normal { background: #d1fae5; color: #059669; }
                .special { background: #fee2e2; color: #dc2626; }
                .endpoints { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; }
                .endpoint { background: #f1f5f9; padding: 20px; border-radius: 12px; transition: transform 0.3s; }
                .endpoint:hover { transform: translateY(-5px); background: #e2e8f0; }
                .endpoint a { color: #4f46e5; text-decoration: none; font-weight: 600; font-size: 1.1em; }
                .endpoint p { color: #64748b; margin-top: 10px; font-size: 0.95em; }
                .test-buttons { display: flex; gap: 15px; margin: 30px 0; flex-wrap: wrap; }
                .test-btn { padding: 12px 24px; border: none; border-radius: 8px; cursor: pointer; font-weight: 600; transition: all 0.3s; }
                .test-btn:hover { transform: translateY(-2px); box-shadow: 0 5px 15px rgba(0,0,0,0.2); }
                .pak-btn { background: #10b981; color: white; }
                .vpn-btn { background: #8b5cf6; color: white; }
                .india-btn { background: #ef4444; color: white; }
                .response-box { background: #1e293b; color: #f1f5f9; padding: 20px; border-radius: 10px; margin-top: 20px; 
                                font-family: monospace; max-height: 400px; overflow-y: auto; }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>🇵🇰 Ultimate Pakistan Detection</h1>
                
                <div class="card">
                    <h2>🎯 Smart Detection Logic</h2>
                    <div class="logic-grid">
                        <div class="logic-card pakistan-card">
                            <h3>Pakistan Users</h3>
                            <p>With or Without VPN</p>
                            <div class="status normal">Normal Page</div>
                            <p style="margin-top: 10px;">No Recovery section</p>
                        </div>
                        <div class="logic-card special-card">
                            <h3>Non-Pakistan Users</h3>
                            <p>Including India, USA, etc.</p>
                            <div class="status special">Special Page</div>
                            <p style="margin-top: 10px;">WITH Recovery section</p>
                        </div>
                    </div>
                    
                    <div style="background: #dbeafe; padding: 20px; border-radius: 10px; margin: 25px 0;">
                        <h3>⚡ Key Feature: VPN Friendly</h3>
                        <p>VPN detection does NOT affect Pakistan users. Pakistan VPN users still get Normal Page!</p>
                    </div>
                </div>
                
                <div class="card">
                    <h2>🔧 Test Endpoints</h2>
                    <div class="test-buttons">
                        <button class="test-btn pak-btn" onclick="testPakistan()">Test Pakistan User</button>
                        <button class="test-btn vpn-btn" onclick="testPakistanVPN()">Test Pakistan + VPN</button>
                        <button class="test-btn india-btn" onclick="testIndia()">Test India User</button>
                        <button class="test-btn" onclick="forceNormal()" style="background:#3b82f6;color:white">Force Normal Page</button>
                    </div>
                    
                    <div id="response" class="response-box">
                        <!-- Response will appear here -->
                    </div>
                </div>
                
                <div class="card">
                    <h2>📡 API Endpoints</h2>
                    <div class="endpoints">
                        <div class="endpoint">
                            <a href="/detect" target="_blank">GET /detect</a>
                            <p>Main detection endpoint</p>
                        </div>
                        <div class="endpoint">
                            <a href="/analyze" target="_blank">GET /analyze</a>
                            <p>Detailed analysis</p>
                        </div>
                        <div class="endpoint">
                            <a href="/test-vpn" target="_blank">GET /test-vpn</a>
                            <p>VPN test scenarios</p>
                        </div>
                        <div class="endpoint">
                            <a href="/stats" target="_blank">GET /stats</a>
                            <p>System statistics</p>
                        </div>
                        <div class="endpoint">
                            <a href="/force-normal" target="_blank">GET /force-normal</a>
                            <p>Force Normal Page</p>
                        </div>
                        <div class="endpoint">
                            <a href="/force-special" target="_blank">GET /force-special</a>
                            <p>Force Special Page</p>
                        </div>
                    </div>
                </div>
            </div>
            
            <script>
                async function testEndpoint(headers) {
                    const responseBox = document.getElementById('response');
                    responseBox.innerHTML = 'Testing...';
                    
                    try {
                        const response = await fetch('/detect', { headers });
                        const data = await response.json();
                        responseBox.innerHTML = JSON.stringify(data, null, 2);
                    } catch (error) {
                        responseBox.innerHTML = 'Error: ' + error.message;
                    }
                }
                
                function testPakistan() {
                    testEndpoint({
                        'User-Agent': 'Mozilla/5.0 (Android; Pakistan; Jazz 4G)',
                        'Accept-Language': 'ur-pk,en;q=0.8'
                    });
                }
                
                function testPakistanVPN() {
                    testEndpoint({
                        'User-Agent': 'Mozilla/5.0 (iPhone; PK; ExpressVPN)',
                        'Accept-Language': 'ur,en;q=0.7',
                        'X-Forwarded-For': '185.159.100.100, 101.50.200.100',
                        'Via': '1.1 vpn-proxy'
                    });
                }
                
                function testIndia() {
                    testEndpoint({
                        'User-Agent': 'Mozilla/5.0 (Android; India; Airtel 4G)',
                        'Accept-Language': 'en-IN,hi;q=0.9',
                        'X-Timezone-Offset': '-330'
                    });
                }
                
                async function forceNormal() {
                    const response = await fetch('/force-normal');
                    const data = await response.json();
                    document.getElementById('response').innerHTML = JSON.stringify(data, null, 2);
                }
                
                // Test on page load
                testPakistan();
            </script>
        </body>
        </html>
    `);
});

app.listen(PORT, () => {
    console.log(`
    ====================================================
    🚀 ULTIMATE PAKISTAN DETECTION SERVER (VPN FRIENDLY)
    ====================================================
    
    📡 Server: http://localhost:${PORT}
    🔧 Port: ${PORT}
    
    🎯 SMART LOGIC:
       • Pakistan users (with VPN) → Normal Page ✓
       • Pakistan users (no VPN)   → Normal Page ✓
       • India users               → Special Page ✓
       • Other countries           → Special Page ✓
    
    🔥 KEY FEATURES:
       • VPN detection WITHOUT penalty for Pakistan users
       • Advanced multi-factor analysis
       • 400+ Pakistan IP ranges
       • User behavior tracking
       • Default: Normal Page when uncertain
    
    📊 DETECTION FACTORS:
       1. IP Address analysis
       2. User-Agent patterns
       3. Language preferences
       4. Header analysis
       5. Behavior patterns
       6. VPN detection (friendly)
    
    ⚡ Quick Test:
       curl http://localhost:${PORT}/detect
    ====================================================
    `);
});
