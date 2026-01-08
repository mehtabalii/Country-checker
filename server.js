// server-pakistan-vpn-normal.js
const express = require('express');
const cors = require('cors');
const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

class PakistanFriendlyDetector {
    constructor() {
        // Pakistan IP ranges (including VPN IPs that might be from Pakistan)
        this.pakIPRanges = [
            // PTCL
            '101.50.', '101.51.', '101.52.', '101.53.', '101.54.', '101.55.',
            '110.36.', '110.37.', '110.38.', '110.39.', '110.40.', '110.41.',
            '111.68.', '111.69.', '111.70.', '111.71.', '111.72.', '111.73.',
            '119.152.', '119.153.', '119.154.', '119.155.', '119.156.',
            
            // Jazz
            '39.34.', '39.35.', '39.36.', '39.37.', '39.38.', '39.39.',
            '39.40.', '39.41.', '39.42.', '39.43.', '39.44.', '39.45.',
            
            // Telenor
            '116.0.', '116.1.', '116.2.', '116.3.', '116.4.', '116.5.',
            
            // Zong
            '117.102.', '117.103.', '117.104.', '117.105.', '117.106.',
            
            // Ufone
            '182.176.', '182.177.', '182.178.', '182.179.', '182.180.',
            
            // Other Pakistani ISPs
            '202.69.', '202.70.', '203.82.', '203.83.', '203.84.',
            '210.56.', '223.29.', '223.30.', '175.107.', '175.108.',
            '149.40.', '149.50.', '149.60.', '149.70.',
            '150.129.', '150.130.', '150.140.',
            '153.92.', '154.16.', '154.17.',
            '202.47.', '202.48.', '202.49.',
            '203.81.', '203.82.', '203.83.', '203.84.',
            '210.1.', '210.2.', '210.3.',
            '223.176.', '223.177.', '223.178.',
            
            // Common VPN IPs used in Pakistan
            '185.159.', '185.160.', '185.161.', '185.162.',
            '193.29.', '194.110.', '194.111.',
            '212.102.', '213.152.', '213.153.',
            '91.108.', '91.109.', '91.110.',
            '95.211.', '95.212.', '95.213.',
            '104.200.', '104.201.', '104.202.',
            '107.189.', '107.190.', '107.191.',
            '141.98.', '141.99.', '141.100.',
            '146.70.', '146.71.', '146.72.',
            '152.89.', '152.90.', '152.91.',
            '172.67.', '172.68.', '172.69.',
            '198.54.', '198.55.', '198.56.'
        ];
        
        // VPN/Proxy indicators (but we'll be lenient with Pakistan users)
        this.vpnHeaders = [
            'via', 'x-forwarded-for', 'x-proxy-id', 'cf-connecting-ip',
            'x-client-ip', 'x-real-ip', 'x-cluster-client-ip',
            'forwarded', 'proxy-connection', 'x-proxy-user-ip'
        ];
        
        // VPN provider IP ranges (common ones)
        this.commonVPNRanges = [
            '104.200.', '107.189.', '141.98.', '146.70.', '152.89.',
            '172.67.', '185.159.', '193.29.', '194.110.', '198.54.',
            '212.102.', '213.152.', '91.108.', '95.211.'
        ];
    }
    
    detect(req) {
        const ip = this.getClientIP(req);
        const userAgent = (req.headers['user-agent'] || '').toLowerCase();
        const acceptLanguage = (req.headers['accept-language'] || '').toLowerCase();
        
        console.log('\n🔍 Detection Started:', { ip, ua: userAgent.substring(0, 60) });
        
        // **CRITICAL LOGIC: Pakistan/VPN users = Normal Page**
        
        // 1. Check if it's a Pakistan IP (including VPN IPs)
        if (this.isPakistanIP(ip)) {
            console.log('✅ Pakistan IP detected -> Normal Page');
            return {
                isPakistan: true,
                reason: 'PAKISTAN_IP',
                confidence: 90,
                message: 'Pakistan IP detected',
                showPage: false // Normal Page
            };
        }
        
        // 2. Check for Pakistan signals in User-Agent/Language
        const pakSignals = this.checkPakistanSignals(userAgent, acceptLanguage);
        if (pakSignals.found) {
            console.log(`✅ Pakistan signals detected -> Normal Page: ${pakSignals.reason}`);
            return {
                isPakistan: true,
                reason: pakSignals.reason,
                confidence: pakSignals.confidence,
                message: 'Pakistan signals detected',
                showPage: false // Normal Page
            };
        }
        
        // 3. Check if using VPN/Proxy
        const isVPN = this.detectVPN(req);
        if (isVPN.detected) {
            console.log(`⚠️ VPN detected: ${isVPN.type}`);
            
            // **IMPORTANT: VPN users with Pakistani patterns = Normal Page**
            const vpnWithPakSignals = this.checkPakistanSignals(userAgent, acceptLanguage);
            if (vpnWithPakSignals.found) {
                console.log(`✅ VPN user with Pakistan signals -> Normal Page`);
                return {
                    isPakistan: true,
                    reason: `VPN_WITH_PAK_SIGNALS_${vpnWithPakSignals.reason}`,
                    confidence: 80,
                    message: 'VPN user with Pakistan patterns',
                    showPage: false // Normal Page
                };
            }
            
            // VPN without Pakistan signals = Special Page
            console.log(`❌ VPN without Pakistan signals -> Special Page`);
            return {
                isPakistan: false,
                reason: `VPN_NO_PAK_SIGNALS_${isVPN.type}`,
                confidence: 85,
                message: 'VPN user without Pakistan patterns',
                showPage: true // Special Page
            };
        }
        
        // 4. Check for clear non-Pakistan signals
        const nonPakSignals = this.checkNonPakistanSignals(userAgent, acceptLanguage);
        if (nonPakSignals.found) {
            console.log(`❌ Non-Pakistan signals -> Special Page: ${nonPakSignals.reason}`);
            return {
                isPakistan: false,
                reason: nonPakSignals.reason,
                confidence: nonPakSignals.confidence,
                message: 'Non-Pakistan user detected',
                showPage: true // Special Page
            };
        }
        
        // 5. Check timezone/location hints
        const locationHint = this.getLocationHint(req);
        if (locationHint === 'PAKISTAN') {
            console.log('📍 Pakistan location hints -> Normal Page');
            return {
                isPakistan: true,
                reason: 'PAKISTAN_LOCATION_HINTS',
                confidence: 75,
                message: 'Location hints suggest Pakistan',
                showPage: false // Normal Page
            };
        } else if (locationHint === 'INDIA') {
            console.log('📍 India location hints -> Special Page');
            return {
                isPakistan: false,
                reason: 'INDIA_LOCATION_HINTS',
                confidence: 80,
                message: 'Location hints suggest India',
                showPage: true // Special Page
            };
        }
        
        // 6. DEFAULT: Assume Pakistan (Normal Page) - Safer approach
        console.log('⚠️ Uncertain -> Defaulting to Pakistan (Normal Page)');
        return {
            isPakistan: true,
            reason: 'DEFAULT_ASSUMPTION',
            confidence: 60,
            message: 'Default assumption: Pakistan user',
            showPage: false // Normal Page
        };
    }
    
    isPakistanIP(ip) {
        if (!ip || ip === 'unknown' || ip === '::1' || ip === '127.0.0.1') {
            return false;
        }
        
        // Local IPs = Pakistan (for testing)
        if (ip.startsWith('192.168.') || ip.startsWith('10.') || 
            ip.startsWith('172.16.') || ip.startsWith('172.17.') ||
            ip.startsWith('172.18.') || ip.startsWith('172.19.') ||
            ip.startsWith('172.20.') || ip.startsWith('172.21.') ||
            ip.startsWith('172.22.') || ip.startsWith('172.23.') ||
            ip.startsWith('172.24.') || ip.startsWith('172.25.') ||
            ip.startsWith('172.26.') || ip.startsWith('172.27.') ||
            ip.startsWith('172.28.') || ip.startsWith('172.29.') ||
            ip.startsWith('172.30.') || ip.startsWith('172.31.')) {
            return true;
        }
        
        // Check against Pakistan IP ranges
        for (const range of this.pakIPRanges) {
            if (ip.startsWith(range)) {
                return true;
            }
        }
        
        return false;
    }
    
    checkPakistanSignals(userAgent, language) {
        const pakKeywords = [
            // ISPs & Networks
            'jazz', 'telenor', 'zong', 'ufone', 'mobilink', 'warid', 'ptcl',
            'nayatel', 'witribe', 'stormfiber', 'transworld', 'optix',
            'cybernet', 'comsats', 'supernet', 'worldcall', 'linkdotnet',
            
            // Cities & Locations
            'karachi', 'lahore', 'islamabad', 'rawalpindi', 'multan',
            'peshawar', 'quetta', 'faisalabad', 'hyderabad', 'sialkot',
            'gujranwala', 'bahawalpur', 'sargodha', 'sukkur', 'larkana',
            'sheikhupura', 'mirpur', 'jhelum', 'mardan', 'kasur',
            
            // Languages
            'ur', 'ur-pk', 'ur_pk', 'ps', 'sd', 'pa', 'balochi',
            'sindhi', 'punjabi', 'saraiki', 'pashto', 'hindko',
            
            // Apps & Services
            'easypaisa', 'jazzcash', 'upaisa', 'sadapay', 'nayapay',
            'daraz', 'foodpanda', 'bykea', 'careem', 'indrive',
            'airlift', 'swvl', 'bookme', 'pakwheels', 'zameen',
            'rozee', 'ilmkidunya', 'taleemabad',
            
            // Devices
            'qmobile', 'infinix', 'tecno', 'voice', 'gfive', 'dany',
            
            // Country Codes
            'pk', 'pak', 'pakistan', '+92', '.pk'
        ];
        
        const combined = userAgent + ' ' + language;
        
        for (const keyword of pakKeywords) {
            if (combined.toLowerCase().includes(keyword.toLowerCase())) {
                return {
                    found: true,
                    reason: `PAK_KEYWORD_${keyword.toUpperCase()}`,
                    confidence: 85
                };
            }
        }
        
        // Check specific language patterns
        if (language.includes('ur') || language.includes('ps') || 
            language.includes('sd') || language.includes('pa')) {
            return {
                found: true,
                reason: 'PAKISTAN_LANGUAGE',
                confidence: 90
            };
        }
        
        return { found: false };
    }
    
    detectVPN(req) {
        const headers = req.headers;
        let vpnType = null;
        
        // Check VPN headers
        for (const header of this.vpnHeaders) {
            if (headers[header]) {
                vpnType = header.toUpperCase();
                break;
            }
        }
        
        // Check IP against common VPN ranges
        const ip = this.getClientIP(req);
        for (const range of this.commonVPNRanges) {
            if (ip.startsWith(range)) {
                vpnType = 'VPN_IP_RANGE';
                break;
            }
        }
        
        // Check User-Agent for VPN keywords
        const userAgent = (headers['user-agent'] || '').toLowerCase();
        const vpnKeywords = ['vpn', 'proxy', 'tor', 'anonymizer', 'hideip'];
        for (const keyword of vpnKeywords) {
            if (userAgent.includes(keyword)) {
                vpnType = 'VPN_USER_AGENT';
                break;
            }
        }
        
        return {
            detected: vpnType !== null,
            type: vpnType || 'UNKNOWN'
        };
    }
    
    checkNonPakistanSignals(userAgent, language) {
        // India specific patterns
        const indiaPatterns = [
            'in', 'india', 'indian', 'bharat', 'hindi', 'tamil', 'telugu',
            'marathi', 'bengali', 'gujarati', 'kannada', 'malayalam',
            'airtel', 'jio', 'vi ', 'vodafone idea', 'bsnl', 'mtnl',
            'delhi', 'mumbai', 'bangalore', 'chennai', 'kolkata',
            'hyderabad', 'ahmedabad', 'pune', 'surat', 'jaipur',
            'in-en', 'en-in', 'hi-in', 'ta-in', 'te-in',
            '+91', '91-', '.in ', '.co.in', 'indianapolis'
        ];
        
        const combined = userAgent + ' ' + language;
        
        for (const pattern of indiaPatterns) {
            if (combined.toLowerCase().includes(pattern.toLowerCase())) {
                return {
                    found: true,
                    reason: `INDIA_${pattern.toUpperCase()}`,
                    confidence: 95
                };
            }
        }
        
        // Other non-Pakistan countries
        const nonPakCountries = [
            { pattern: 'en-us', country: 'USA', confidence: 90 },
            { pattern: 'en-gb', country: 'UK', confidence: 90 },
            { pattern: 'en-au', country: 'AUSTRALIA', confidence: 90 },
            { pattern: 'en-ca', country: 'CANADA', confidence: 90 },
            { pattern: 'zh-cn', country: 'CHINA', confidence: 95 },
            { pattern: 'ja-jp', country: 'JAPAN', confidence: 95 },
            { pattern: 'ko-kr', country: 'KOREA', confidence: 95 },
            { pattern: 'ru-ru', country: 'RUSSIA', confidence: 90 },
            { pattern: 'ar-sa', country: 'SAUDI_ARABIA', confidence: 90 },
            { pattern: 'ae', country: 'UAE', confidence: 90 },
            { pattern: 'de-de', country: 'GERMANY', confidence: 90 },
            { pattern: 'fr-fr', country: 'FRANCE', confidence: 90 },
            { pattern: 'es-es', country: 'SPAIN', confidence: 90 }
        ];
        
        for (const country of nonPakCountries) {
            if (combined.toLowerCase().includes(country.pattern.toLowerCase())) {
                return {
                    found: true,
                    reason: `${country.country}_DETECTED`,
                    confidence: country.confidence
                };
            }
        }
        
        return { found: false };
    }
    
    getLocationHint(req) {
        const headers = req.headers;
        
        // Check timezone (PKT = UTC+5 = -300 minutes)
        const timezone = headers['x-timezone-offset'] || headers['timezone-offset'];
        if (timezone) {
            const offset = parseInt(timezone);
            if (offset === -300) { // Pakistan
                return 'PAKISTAN';
            } else if (offset === -330) { // India
                return 'INDIA';
            }
        }
        
        // Check language for country hints
        const acceptLanguage = (headers['accept-language'] || '').toLowerCase();
        if (acceptLanguage.includes('en-in') || acceptLanguage.includes('hi-in')) {
            return 'INDIA';
        } else if (acceptLanguage.includes('ur') || acceptLanguage.includes('ps')) {
            return 'PAKISTAN';
        }
        
        return null;
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

const detector = new PakistanFriendlyDetector();

// ============ API ENDPOINTS ============

app.get('/detect', (req, res) => {
    try {
        console.log('\n🎯 ========== NEW REQUEST ==========');
        
        const detection = detector.detect(req);
        const clientIP = detector.getClientIP(req);
        const isVPN = detector.detectVPN(req);
        
        console.log(`📊 IP: ${clientIP}`);
        console.log(`🔍 VPN: ${isVPN.detected ? 'YES' : 'NO'}`);
        console.log(`🇵🇰 Pakistan: ${detection.isPakistan ? 'YES' : 'NO'}`);
        console.log(`📺 Show Page: ${detection.showPage ? 'SPECIAL' : 'NORMAL'}`);
        console.log(`📝 Reason: ${detection.reason}`);
        
        const response = {
            showPage: detection.showPage, // false = Normal Page, true = Special Page
            decision: {
                isPakistan: detection.isPakistan,
                usingVPN: isVPN.detected,
                vpnType: isVPN.type,
                reason: detection.reason,
                confidence: detection.confidence,
                message: detection.message
            },
            userInfo: {
                ip: clientIP,
                userAgent: req.headers['user-agent']?.substring(0, 80) || 'unknown',
                language: req.headers['accept-language'] || 'unknown',
                timezone: req.headers['x-timezone-offset'] || req.headers['timezone-offset'] || 'unknown'
            },
            timestamp: new Date().toISOString(),
            message: detection.showPage ? 
                "🌍 Special Page (WITH Recovery section)" : 
                "🇵🇰 Normal Page (NO Recovery section)"
        };
        
        console.log(`✅ Final: ${response.message}`);
        console.log('===================================\n');
        
        res.json(response);
        
    } catch (error) {
        console.error('❌ Error:', error);
        // On error, show Normal Page (safer for Pakistan users)
        res.json({
            showPage: false, // Normal Page
            error: 'Detection failed, defaulting to Normal Page',
            timestamp: new Date().toISOString(),
            message: "Default: Normal Page"
        });
    }
});

// Test endpoint
app.get('/test', (req, res) => {
    const detection = detector.detect(req);
    const isVPN = detector.detectVPN(req);
    
    res.json({
        yourStatus: {
            ip: detector.getClientIP(req),
            isVPN: isVPN.detected,
            isPakistan: detection.isPakistan,
            showPage: detection.showPage ? 'SPECIAL PAGE' : 'NORMAL PAGE',
            reason: detection.reason
        },
        
        scenarios: {
            pakistanWithoutVPN: {
                description: 'Pakistan user without VPN',
                result: 'Normal Page',
                testCommand: 'curl -H "User-Agent: Mozilla/5.0 (Android; Pakistan; Jazz)" http://localhost:3000/detect'
            },
            pakistanWithVPN: {
                description: 'Pakistan user WITH VPN',
                result: 'Normal Page (IMPORTANT!)',
                testCommand: 'curl -H "User-Agent: Mozilla/5.0 (Android; Pakistan; Jazz VPN)" -H "X-Forwarded-For: 185.159.100.100" http://localhost:3000/detect'
            },
            indiaWithoutVPN: {
                description: 'India user without VPN',
                result: 'Special Page',
                testCommand: 'curl -H "User-Agent: Mozilla/5.0 (Android; India; Airtel)" http://localhost:3000/detect'
            },
            indiaWithVPN: {
                description: 'India user WITH VPN',
                result: 'Special Page',
                testCommand: 'curl -H "User-Agent: Mozilla/5.0 (Android; India; Airtel VPN)" http://localhost:3000/detect'
            }
        },
        
        logic: {
            rule1: 'Pakistan users (with or without VPN) = Normal Page',
            rule2: 'VPN users with Pakistan patterns = Normal Page',
            rule3: 'India users (with or without VPN) = Special Page',
            rule4: 'Other countries = Special Page',
            rule5: 'Uncertain = Normal Page (safer for Pakistan users)'
        }
    });
});

// Force endpoints
app.get('/force-normal', (req, res) => {
    res.json({
        showPage: false,
        forced: true,
        message: "FORCED: Normal Page",
        timestamp: new Date().toISOString(),
        note: "Bypasses all detection logic - shows Normal Page"
    });
});

app.get('/force-special', (req, res) => {
    res.json({
        showPage: true,
        forced: true,
        message: "FORCED: Special Page",
        timestamp: new Date().toISOString(),
        note: "Bypasses all detection logic - shows Special Page"
    });
});

// Health check
app.get('/health', (req, res) => {
    res.json({
        status: 'RUNNING',
        version: 'PAKISTAN-VPN-NORMAL-1.0',
        logic: 'Pakistan users (with/without VPN) = Normal Page, Others = Special Page',
        ipRanges: detector.pakIPRanges.length + ' ranges loaded',
        vpnRanges: detector.commonVPNRanges.length + ' VPN ranges known',
        default: 'Uncertain = Normal Page (safer)',
        timestamp: new Date().toISOString()
    });
});

// Dashboard
app.get('/', (req, res) => {
    res.send(`
        <!DOCTYPE html>
        <html>
        <head>
            <title>Pakistan & VPN Friendly Detection</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 40px; background: #f0f9ff; }
                .container { max-width: 1000px; margin: 0 auto; background: white; padding: 30px; border-radius: 15px; box-shadow: 0 4px 20px rgba(0,0,0,0.1); }
                h1 { color: #1e40af; border-bottom: 3px solid #1e40af; padding-bottom: 10px; }
                .card { background: #f8fafc; padding: 20px; margin: 15px 0; border-radius: 10px; border-left: 5px solid #3b82f6; }
                .pakistan { background: #dbeafe; border-left-color: #1d4ed8; }
                .normal { color: #059669; font-weight: bold; }
                .special { color: #dc2626; font-weight: bold; }
                .endpoint { background: #e0f2fe; padding: 15px; margin: 10px 0; border-radius: 8px; }
                .endpoint a { color: #0369a1; text-decoration: none; font-weight: bold; }
                .logic-table { width: 100%; border-collapse: collapse; margin: 20px 0; }
                .logic-table th, .logic-table td { padding: 12px; text-align: left; border: 1px solid #cbd5e1; }
                .logic-table th { background: #1e40af; color: white; }
                .logic-table tr:nth-child(even) { background: #f1f5f9; }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>🇵🇰 Pakistan & VPN Friendly Detection Server</h1>
                
                <div class="card pakistan">
                    <h3>🎯 KEY LOGIC:</h3>
                    <p><span class="normal">Pakistan users (with or without VPN) = Normal Page</span></p>
                    <p><span class="special">All other users = Special Page (with Recovery section)</span></p>
                </div>
                
                <table class="logic-table">
                    <thead>
                        <tr>
                            <th>User Type</th>
                            <th>VPN Status</th>
                            <th>Page Shown</th>
                            <th>Recovery Section</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr>
                            <td>🇵🇰 Pakistan User</td>
                            <td>Without VPN</td>
                            <td class="normal">Normal Page</td>
                            <td>NO</td>
                        </tr>
                        <tr>
                            <td>🇵🇰 Pakistan User</td>
                            <td>WITH VPN</td>
                            <td class="normal">Normal Page</td>
                            <td>NO</td>
                        </tr>
                        <tr>
                            <td>🇮🇳 India User</td>
                            <td>Without VPN</td>
                            <td class="special">Special Page</td>
                            <td>YES</td>
                        </tr>
                        <tr>
                            <td>🇮🇳 India User</td>
                            <td>WITH VPN</td>
                            <td class="special">Special Page</td>
                            <td>YES</td>
                        </tr>
                        <tr>
                            <td>🇺🇸 USA User</td>
                            <td>Any</td>
                            <td class="special">Special Page</td>
                            <td>YES</td>
                        </tr>
                        <tr>
                            <td>🌍 Other Countries</td>
                            <td>Any</td>
                            <td class="special">Special Page</td>
                            <td>YES</td>
                        </tr>
                    </tbody>
                </table>
                
                <h3>📡 API Endpoints:</h3>
                <div class="endpoint">
                    <a href="/detect" target="_blank">GET /detect</a>
                    <p>Main detection endpoint - checks if user gets Normal or Special page</p>
                </div>
                <div class="endpoint">
                    <a href="/test" target="_blank">GET /test</a>
                    <p>Test your current status with different scenarios</p>
                </div>
                <div class="endpoint">
                    <a href="/force-normal" target="_blank">GET /force-normal</a>
                    <p>Force Normal Page (bypass detection)</p>
                </div>
                <div class="endpoint">
                    <a href="/force-special" target="_blank">GET /force-special</a>
                    <p>Force Special Page (bypass detection)</p>
                </div>
                
                <div class="card">
                    <h3>⚡ Quick Test Commands:</h3>
                    <pre>
# Test Pakistan user with VPN
curl -H "X-Forwarded-For: 185.159.100.100" http://localhost:${PORT}/detect

# Test India user
curl -H "User-Agent: Mozilla/5.0 (Android; India; Airtel)" http://localhost:${PORT}/detect

# Force Normal Page
curl http://localhost:${PORT}/force-normal
                    </pre>
                </div>
            </div>
        </body>
        </html>
    `);
});

app.listen(PORT, () => {
    console.log(`
    ================================================
    🇵🇰 PAKISTAN & VPN FRIENDLY DETECTION SERVER
    ================================================
    
    📡 Server: http://localhost:${PORT}
    🔧 Port: ${PORT}
    
    🎯 CRITICAL LOGIC:
       Pakistan Users (with/without VPN)  → Normal Page
       All Other Users                    → Special Page
    
    📊 STATS:
       • ${detector.pakIPRanges.length} IP ranges (including VPN)
       • ${detector.commonVPNRanges.length} known VPN ranges
       • Default: Normal Page when uncertain
    
    📌 TEST SCENARIOS:
       1. Pakistan + No VPN    → Normal Page ✓
       2. Pakistan + VPN       → Normal Page ✓
       3. India + No VPN      → Special Page ✓
       4. India + VPN         → Special Page ✓
       5. USA/UK + Any        → Special Page ✓
    
    ⚡ Quick Test:
       curl http://localhost:${PORT}/detect
    ================================================
    `);
});
