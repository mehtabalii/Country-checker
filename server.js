// server.js - IMPROVED VPN DETECTION
const express = require('express');
const cors = require('cors');
const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());

// Pakistan IP ranges
const PAKISTAN_IPS = [
    '39.34.', '39.35.', '39.36.', '39.37.', '39.38.', '39.39.', '39.40.', '39.41.', '39.42.', '39.43.',
    '39.44.', '39.45.', '39.46.', '39.47.', '39.48.', '39.49.', '39.50.', '39.51.', '39.52.', '39.53.',
    '39.54.', '39.55.', '39.56.', '39.57.', '39.58.', '39.59.', '39.60.', '39.61.', '39.62.', '39.63.',
    
    '101.50.', '101.51.', '101.52.', '101.53.', '101.54.', '101.55.', '101.56.', '101.57.', '101.58.',
    '101.59.', '101.60.', '101.61.', '101.62.', '101.63.', '101.64.', '101.65.', '101.66.', '101.67.',
    '101.68.', '101.69.', '101.70.', '101.71.', '101.72.', '101.73.', '101.74.', '101.75.', '101.76.',
    '101.77.', '101.78.', '101.79.', '101.80.', '101.81.', '101.82.', '101.83.', '101.84.', '101.85.',
    '101.86.', '101.87.', '101.88.', '101.89.', '101.90.', '101.91.', '101.92.', '101.93.', '101.94.',
    '101.95.', '101.96.', '101.97.', '101.98.', '101.99.', '101.100.', '101.101.', '101.102.', '101.103.',
    
    '110.36.', '110.37.', '110.38.', '110.39.', '110.40.', '110.41.', '110.42.', '110.43.',
    '110.44.', '110.45.', '110.46.', '110.47.', '110.48.', '110.49.', '110.50.', '110.51.',
    '110.52.', '110.53.', '110.54.', '110.55.', '110.56.', '110.57.', '110.58.', '110.59.',
    
    '111.68.', '111.69.', '111.70.', '111.71.', '111.72.', '111.73.', '111.74.', '111.75.',
    '111.76.', '111.77.', '111.78.', '111.79.', '111.80.', '111.81.', '111.82.', '111.83.',
    
    '113.203.', '113.204.', '113.205.', '113.206.', '113.207.', '113.208.', '113.209.',
    
    '115.186.', '115.187.', '115.188.', '115.189.', '115.190.', '115.191.', '115.192.',
    
    '116.0.', '116.1.', '116.2.', '116.3.', '116.4.', '116.5.', '116.6.', '116.7.',
    '116.8.', '116.9.', '116.10.', '116.11.', '116.12.', '116.13.', '116.14.', '116.15.',
    
    '117.102.', '117.103.', '117.104.', '117.105.', '117.106.', '117.107.', '117.108.',
    '117.109.', '117.110.', '117.111.', '117.112.', '117.113.', '117.114.', '117.115.',
    
    '119.152.', '119.153.', '119.154.', '119.155.', '119.156.', '119.157.', '119.158.',
    '119.159.', '119.160.', '119.161.', '119.162.', '119.163.', '119.164.', '119.165.',
    
    '182.176.', '182.177.', '182.178.', '182.179.', '182.180.', '182.181.', '182.182.',
    '182.183.', '182.184.', '182.185.', '182.186.', '182.187.', '182.188.', '182.189.',
    
    '202.141.', '202.142.', '202.143.', '202.144.', '202.145.', '202.146.', '202.147.',
    '202.148.', '202.149.', '202.150.', '202.151.', '202.152.', '202.153.', '202.154.',
    
    '203.81.', '203.82.', '203.83.', '203.84.', '203.99.', '203.100.', '203.101.',
    '203.102.', '203.103.', '203.104.', '203.105.', '203.106.', '203.107.', '203.108.',
    
    '210.1.', '210.2.', '210.3.', '210.4.', '210.5.', '210.6.', '210.7.', '210.8.',
    '210.9.', '210.10.', '210.11.', '210.12.', '210.13.', '210.14.', '210.15.'
];

// VPN IP ranges - Your VPN IP added
const VPN_IPS = [
    '104.200.', '104.201.', '104.202.', '104.203.', '104.204.', '104.205.', '104.206.', '104.207.',
    '104.208.', '104.209.', '104.210.', '104.211.', '104.212.', '104.213.', '104.214.', '104.215.',
    
    '185.159.', '185.160.', '185.161.', '185.162.', '185.163.', '185.164.', '185.165.',
    '185.166.', '185.167.', '185.168.', '185.169.', '185.170.', '185.171.', '185.172.',
    
    '45.134.', '45.135.', '45.136.', '45.137.', '45.138.', '45.139.', '45.140.', '45.141.',
    
    '91.200.', '91.201.', '91.202.', '91.203.', '91.204.', '91.205.', '91.206.', '91.207.',
    
    '103.146.', '103.147.', '103.148.', '103.149.', '103.150.', '103.151.', '103.152.',
    
    '5.188.', '5.189.', '5.190.', '5.191.', '5.192.', '5.193.', '5.194.', '5.195.',
    
    // ✅ Aapke VPN ke IP ko add karein
    '207.244.', '207.245.', '207.246.', '207.247.', '207.248.', '207.249.', '207.250.', '207.251.',
    
    // Common VPN services
    '104.139.', '104.140.', '104.141.', '104.142.', '104.143.', '104.144.', '104.145.',
    '104.146.', '104.147.', '104.148.', '104.149.', '104.150.', '104.151.', '104.152.',
    
    '185.93.', '185.94.', '185.95.', '185.96.', '185.97.', '185.98.', '185.99.',
    '185.100.', '185.101.', '185.102.', '185.103.', '185.104.', '185.105.', '185.106.',
    
    '45.87.', '45.88.', '45.89.', '45.90.', '45.91.', '45.92.', '45.93.', '45.94.',
    '45.95.', '45.96.', '45.97.', '45.98.', '45.99.', '45.100.', '45.101.', '45.102.',
    
    '104.128.', '104.129.', '104.130.', '104.131.', '104.132.', '104.133.', '104.134.',
    '104.135.', '104.136.', '104.137.', '104.138.'
];

// Check if IP is from Pakistan
function isPakistanIP(ip) {
    if (!ip) return false;
    ip = ip.trim();
    
    for (const pakIP of PAKISTAN_IPS) {
        if (ip.startsWith(pakIP)) {
            return true;
        }
    }
    return false;
}

// Check if IP is VPN (improved)
function isVPN(ip) {
    if (!ip) return false;
    ip = ip.trim();
    
    // Common VPN patterns check
    const vpnPatterns = [
        /^104\.2\d{2}\./,  // 104.200-104.299
        /^185\.1\d{2}\./,  // 185.100-185.199
        /^45\.1\d{2}\./,   // 45.100-45.199
        /^91\.2\d{2}\./,   // 91.200-91.299
        /^103\.1\d{2}\./,  // 103.100-103.199
        /^5\.18[8-9]\./,   // 5.188-5.199
        /^207\.244\./,     // Your VPN
        /^207\.245\./,
        /^207\.246\./,
        /^207\.247\./,
        /^207\.248\./,
        /^207\.249\./,
        /^207\.250\./,
        /^207\.251\./,
        /^185\.9[0-9]\./,  // 185.90-185.99
        /^45\.8[7-9]\./,   // 45.87-45.99
        /^104\.139\./,
        /^104\.14[0-9]\./, // 104.140-104.149
        /^104\.15[0-9]\./  // 104.150-104.159
    ];
    
    for (const pattern of vpnPatterns) {
        if (pattern.test(ip)) {
            return true;
        }
    }
    
    // Also check exact VPN list
    for (const vpnIP of VPN_IPS) {
        if (ip.startsWith(vpnIP)) {
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
        
        console.log('🔍 Original IP:', clientIP);
        
        // Clean IP address
        if (clientIP.includes(',')) {
            clientIP = clientIP.split(',')[0].trim();
        }
        if (clientIP.startsWith('::ffff:')) {
            clientIP = clientIP.replace('::ffff:', '');
        }
        
        // Remove port if present
        if (clientIP.includes(':')) {
            const parts = clientIP.split(':');
            if (parts.length > 1) {
                clientIP = parts[0]; // Take first part only
            }
        }
        
        console.log('📡 Cleaned IP:', clientIP);
        
        // Check if IP is from Pakistan
        const isPak = isPakistanIP(clientIP);
        const isVPNIP = isVPN(clientIP);
        
        console.log('🏳️ Is Pakistan IP:', isPak);
        console.log('🔒 Is VPN:', isVPNIP);
        
        // 🔥 DECISION LOGIC:
        // showPage: true = Special Page (WITH Recovery section) → NON-PAKISTAN
        // showPage: false = Normal Page (NO Recovery section) → PAKISTAN
        
        let showPage = true; // Default: Special Page (NON-PAKISTAN)
        let message = '';
        
        if (isPak || isVPNIP) {
            // ✅ Pakistan user OR VPN user = Normal Page
            showPage = false; // Normal Page (NO Recovery)
            message = isPak ? 
                (isVPNIP ? "Pakistan user with VPN → Normal Page" : "Pakistan user → Normal Page") :
                "VPN user → Normal Page";
        } else {
            // ❌ Non-Pakistan, non-VPN = Special Page
            showPage = true; // Special Page (WITH Recovery)
            message = "Non-Pakistan user → Special Page";
        }
        
        const response = {
            showPage: showPage,  // true=Special, false=Normal
            ip: clientIP,
            isPakistanIP: isPak,
            isVPN: isVPNIP,
            timestamp: new Date().toISOString(),
            message: message
        };
        
        console.log('📊 Final Response:', response);
        res.json(response);
        
    } catch (error) {
        console.error('❌ Error:', error);
        res.status(500).json({
            showPage: false, // Default to Normal Page on error
            error: 'Server error',
            timestamp: new Date().toISOString()
        });
    }
});

// Test endpoint for your VPN IP
app.get('/test-vpn', (req, res) => {
    const testIP = '207.244.71.82';
    const isPak = isPakistanIP(testIP);
    const isVPNIP = isVPN(testIP);
    
    res.json({
        testIP: testIP,
        isPakistanIP: isPak,
        isVPN: isVPNIP,
        result: isPak || isVPNIP ? 'Normal Page' : 'Special Page',
        message: isPak ? 'Pakistan IP' : (isVPNIP ? 'VPN IP' : 'Non-Pakistan IP')
    });
});

// Health check
app.get('/health', (req, res) => {
    res.json({
        status: 'OK',
        message: 'Backend is running',
        timestamp: new Date().toISOString()
    });
});

// Start server
app.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
    console.log(`📌 Main endpoint: http://localhost:${PORT}/dc`);
    console.log(`📌 Test VPN: http://localhost:${PORT}/test-vpn`);
    console.log(`📌 Health check: http://localhost:${PORT}/health`);
    console.log(`\n🔍 Aapka VPN IP (207.244.71.82) ab detect ho jayega!`);
});
