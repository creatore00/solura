const express = require('express');
const { query } = require('./dbPromise');
const mysql = require('mysql2');
const bodyParser = require('body-parser');
const cron = require('node-cron');
const axios = require('axios');
const moment = require('moment');
const { scheduleTestUpdates } = require('./holidayAccrualService.js');
const newRota = require('./Rota.js');
const newRota2 = require('./rota2.js');
const confirmpassword = require('./ConfirmPassword.js'); 
const token = require('./Token.js');
const Backend = require('./Backend.js');
const TimeTracking = require('./TimeTracking.js');
const generate = require('./Generate.js');
const pastemployees = require('./PastEmployees.js');
const updateinfo = require('./UpdateInfo.js');
const ForgotPassword = require('./ForgotPassword.js');
const userholidays = require('./Holidays.js');
const hours = require('./Hours.js');
const pastpayslips = require('./PastPayslips.js');
const request = require('./Request.js');
const tip = require('./Tip.js');
const labor = require('./labor.js');
const TotalHolidays = require('./TotalHolidays.js');
const UserCrota = require('./UserCRota.js');
const UserHolidays = require('./UserHolidays.js');
const confirmrota = require('./ConfirmRota.js');
const confirmrota2 = require('./confirmrota2.js');
const profile = require('./Profile.js');
const UserTotalHours = require('./UserTotalHours.js');
const insertpayslip = require('./InsertPayslip.js');
const modify = require('./Modify.js');
const endday = require('./EndDay.js');
const financialsummary = require('./FinancialSummary.js');
const http = require('http');
const fs = require('fs');
const path = require('path');
const { getPool, mainPool } = require('./db.js');
const bcrypt = require('bcrypt');
const saltRounds = 10;
const jwt = require('jsonwebtoken');
const session = require('express-session');
const cors = require('cors');
const MySQLStore = require('express-mysql-session')(session);
const cookieParser = require('cookie-parser');

const app = express();
const port = process.env.PORT || 8080;

// Environment configuration
const isProduction = process.env.NODE_ENV === 'production';
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-in-production';
const SESSION_SECRET = process.env.SESSION_SECRET || 'fallback-secret-key-change-in-production';

// Trust proxy for Heroku
app.set('trust proxy', 1);

// Add cookie parser middleware - CRITICAL FIX
app.use(cookieParser());

// Manual cookie parser function (no dependencies needed)
function parseCookies(cookieHeader) {
    const cookies = {};
    if (cookieHeader && typeof cookieHeader === 'string') {
        cookieHeader.split(';').forEach(cookie => {
            const parts = cookie.trim().split('=');
            if (parts.length >= 2) {
                const name = parts[0].trim();
                const value = parts.slice(1).join('=').trim(); // Handle values with '='
                if (name && value) {
                    try {
                        cookies[name] = decodeURIComponent(value);
                    } catch (e) {
                        cookies[name] = value; // Use raw value if decode fails
                    }
                }
            }
        });
    }
    return cookies;
}
// Add this to your server - BEFORE your routes
app.use((req, res, next) => {
    // Special handling for Capacitor iOS
    if (req.headers['x-capacitor'] === 'true' || req.headers.origin?.includes('capacitor://')) {
        res.header('Access-Control-Allow-Origin', '*');
        res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
        res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With, X-Capacitor, X-Session-ID');
        res.header('Access-Control-Expose-Headers', 'Set-Cookie');
        
        // Bypass some security for Capacitor
        if (req.method === 'OPTIONS') {
            return res.sendStatus(200);
        }
    }
    next();
});
// Track active sessions for duplicate login prevention
const activeSessions = new Map(); // email -> sessionIds

// Enhanced device detection helper - SERVER SAFE
function isMobileDevice(req) {
    const userAgent = req.headers['user-agent'] || '';
    const isIOS = /iPhone|iPad|iPod/i.test(userAgent);
    const isAndroid = /Android/i.test(userAgent);
    const isMobileApp = req.headers['x-capacitor'] === 'true' || 
                       req.query.capacitor === 'true' ||
                       req.headers.origin?.startsWith('capacitor://') ||
                       req.headers.origin?.startsWith('ionic://');

    // Server-safe iPad detection
    const isIPad = /iPad/.test(userAgent) || 
                  (/Macintosh/.test(userAgent) && /AppleWebKit/.test(userAgent) && !/Safari/.test(userAgent));

    return isIOS || isIPad || isAndroid || isMobileApp;
}

// Enhanced iPad detection
function isIPadDevice(req) {
    const userAgent = req.headers['user-agent'] || '';
    return /iPad/.test(userAgent) || 
           (/Macintosh/.test(userAgent) && /AppleWebKit/.test(userAgent) && !/Safari/.test(userAgent));
}

// Safe session touch utility
function safeSessionTouch(req) {
    if (req.session && req.session.touch && typeof req.session.touch === 'function') {
        req.session.touch();
    } else if (req.session && req.session.cookie) {
        req.session.cookie.maxAge = req.session.cookie.originalMaxAge || 24 * 60 * 60 * 1000;
    }
}

// Token generation function
function generateToken(user) {
    return jwt.sign(
        { 
            email: user.email, 
            role: user.role, 
            name: user.name, 
            lastName: user.lastName, 
            dbName: user.dbName
        },
        JWT_SECRET,
        { expiresIn: '7d' }
    );
}

// MySQL session store
const sessionStore = new MySQLStore({
    host: 'sv41.byethost41.org',
    port: 3306,
    user: 'yassir_yassir',
    password: 'Qazokm123890',
    database: 'yassir_access',
    createDatabaseTable: true,
    schema: {
        tableName: 'user_sessions',
        columnNames: {
            session_id: 'session_id',
            expires: 'expires',
            data: 'data'
        }
    },
    checkExpirationInterval: 60000,
    expiration: 600000,
    clearExpired: true
}, mainPool);

// ENHANCED CORS for all devices
const corsOptions = {
    origin: function (origin, callback) {
        // Allow all origins for iOS/Capacitor and mobile devices
        if (!origin || origin.startsWith('capacitor://') || origin.startsWith('ionic://') || origin.startsWith('file://')) {
            return callback(null, true);
        }
        
        const allowedOrigins = [
            'https://www.solura.uk', 
            'https://solura.uk', 
            'http://localhost:8080',
            'http://localhost:3000',
            'capacitor://localhost',
            'ionic://localhost',
            'http://localhost',
            'https://localhost:'
        ];
        
        if (allowedOrigins.indexOf(origin) !== -1 || origin?.includes('solura.uk')) {
            callback(null, true);
        } else {
            console.log('Blocked by CORS:', origin);
            callback(new Error('Not allowed by CORS'));
        }
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'Cookie', 'Accept', 'X-Session-ID', 'X-Capacitor', 'Origin', 'X-Requested-With'],
    exposedHeaders: ['Set-Cookie', 'X-Session-ID', 'Authorization']
};
app.use(cors({
  origin: [
    'capacitor://localhost',
    'http://localhost',
    'https://solura.uk',
    /\.solura\.uk$/,
  ],
  credentials: true,
}));

// Handle preflight requests
app.options('*', cors(corsOptions));

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Enhanced static file serving for all devices
app.use(express.static(__dirname, {
    setHeaders: (res, path) => {
        // Set proper MIME types
        if (path.endsWith('.js')) {
            res.set('Content-Type', 'application/javascript');
        } else if (path.endsWith('.css')) {
            res.set('Content-Type', 'text/css');
        } else if (path.endsWith('.html')) {
            res.set('Content-Type', 'text/html');
        }
        
        // Allow all origins for static files
        res.set('Access-Control-Allow-Origin', '*');
        res.set('Access-Control-Allow-Methods', 'GET, OPTIONS');
        res.set('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    }
}));

// Manual CORS headers for all responses
app.use((req, res, next) => {
    const origin = req.headers.origin;
    
    // Always set CORS headers
    if (!origin || origin.startsWith('capacitor://') || origin.startsWith('ionic://') || origin.startsWith('file://')) {
        res.header('Access-Control-Allow-Origin', '*');
    } else {
        res.header('Access-Control-Allow-Origin', origin);
    }
    
    res.header('Access-Control-Allow-Credentials', 'true');
    res.header('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS');
    res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization, Content-Length, X-Requested-With, Cookie, X-Session-ID, X-Capacitor, Origin');
    res.header('Access-Control-Expose-Headers', 'Set-Cookie', 'X-Session-ID', 'Authorization');
    
    if (req.method === 'OPTIONS') {
        return res.sendStatus(200);
    }
    next();
});

// Cookie cleanup middleware
app.use((req, res, next) => {
    if (req.headers.cookie) {
        const cookies = req.headers.cookie.split(';');
        const uniqueCookies = new Map();
        
        for (let i = cookies.length - 1; i >= 0; i--) {
            const cookie = cookies[i].trim();
            const [name, value] = cookie.split('=');
            if (name && value) {
                if (!uniqueCookies.has(name)) {
                    uniqueCookies.set(name, value);
                }
            }
        }
        
        const newCookieHeader = Array.from(uniqueCookies.entries())
            .map(([name, value]) => `${name}=${value}`)
            .join('; ');
        
        req.headers.cookie = newCookieHeader;
    }
    next();
});

// Device detection middleware
app.use((req, res, next) => {
    const userAgent = req.headers['user-agent'] || '';
    req.isMobileDevice = isMobileDevice(req);
    req.isIOS = /iPhone|iPad|iPod/i.test(userAgent);
    req.isIPad = isIPadDevice(req);
    
    if (req.isIPad) {
        console.log('📱 iPad Device Detected');
    } else if (req.isIOS) {
        console.log('📱 iOS Device Detected');
    } else if (req.isMobileDevice) {
        console.log('📱 Mobile Device Detected');
    } else {
        console.log('💻 Desktop Device Detected');
    }
    next();
});

app.use(session({
  key: 'solura.session',
  secret: process.env.SESSION_SECRET || 'your-fallback-session-secret',
  store: sessionStore,
  resave: false,
  saveUninitialized: true, // Recommended to establish session before login
  rolling: true, // Keeps the session active as the user browses

  cookie: {
    httpOnly: true, // Helps prevent XSS attacks

    // **THE FIX: Conditional settings for Production vs. Localhost**
    secure: isProduction, // Use secure cookies ONLY in production (HTTPS)
    sameSite: isProduction ? 'none' : 'lax', // 'none' for cross-origin on HTTPS, 'lax' for localhost
    
    // **THE FIX: Conditionally set the domain**
    domain: isProduction ? '.solura.uk' : undefined, // ONLY set domain for production

    maxAge: 24 * 60 * 60 * 1000, // 24 hours
    path: '/',
  }
}));

// CRITICAL FIX: Enhanced session persistence middleware
app.use((req, res, next) => {
  // Store original session save method
  const originalSave = req.session.save;
  
  // Enhanced session save with proper error handling
  req.session.save = function(callback) {
    console.log('💾 Attempting to save session:', req.sessionID);
    console.log('💾 Session data to save:', {
      user: req.session.user,
      initialized: req.session.initialized
    });
    
    return originalSave.call(this, (err) => {
      if (err) {
        console.error('❌ Session save error:', err);
        if (callback) return callback(err);
        return;
      }
      
      console.log('✅ Session saved successfully:', req.sessionID);
      if (callback) callback(null);
    });
  };
  
  next();
});

// CRITICAL FIX: iPad-specific session handling - COMPLETELY REWRITTEN
app.use((req, res, next) => {
    if (req.isIPad) {
        console.log('🔧 iPad-specific session handling initiated');
        
        // Enhanced iPad session recovery
        const cookieHeader = req.headers.cookie;
        const cookies = parseCookies(cookieHeader);
        const sessionCookie = cookies['solura.session'];
        
        console.log('📱 iPad Session Analysis:', {
            hasCookieHeader: !!cookieHeader,
            sessionCookie: sessionCookie,
            currentSessionId: req.sessionID,
            hasUser: !!req.session?.user,
            sessionInitialized: req.session?.initialized
        });
        
        // iPad-specific session initialization
        if (!req.session.initialized) {
            req.session.initialized = true;
            req.session.ipadDevice = true;
            console.log('📱 iPad session marked as initialized');
        }
        
        // iPad session persistence enhancement
        if (req.sessionID) {
            // Force session cookie for iPad with specific settings
            res.cookie('solura.session', req.sessionID, {
                maxAge: 24 * 60 * 60 * 1000,
                httpOnly: false, // iPad needs JS access
                secure: false,   // iPad Safari has issues with secure cookies
                sameSite: 'Lax', // Lax works better for iPad
                path: '/',
                domain: isProduction ? '.solura.uk' : undefined
            });
            
            console.log('📱 iPad session cookie set:', req.sessionID);
        }
        
        // iPad session validation
        if (req.session.user && !activeSessions.has(req.session.user.email)) {
            console.log('📱 iPad session not in active sessions, adding it');
            if (!activeSessions.has(req.session.user.email)) {
                activeSessions.set(req.session.user.email, new Set());
            }
            activeSessions.get(req.session.user.email).add(req.sessionID);
        }
    }
    next();
});

// Session store health check
app.get('/api/session-store-health', (req, res) => {
  if (!sessionStore || typeof sessionStore.get !== 'function') {
    return res.json({ healthy: false, error: 'Session store not properly initialized' });
  }
  
  // Test the store
  const testSessionId = 'health-check-' + Date.now();
  const testData = { test: true, timestamp: Date.now() };
  
  sessionStore.set(testSessionId, testData, (setErr) => {
    if (setErr) {
      return res.json({ healthy: false, error: 'Store set failed: ' + setErr.message });
    }
    
    sessionStore.get(testSessionId, (getErr, retrievedData) => {
      if (getErr) {
        return res.json({ healthy: false, error: 'Store get failed: ' + getErr.message });
      }
      
      sessionStore.destroy(testSessionId, (destroyErr) => {
        const healthy = retrievedData && retrievedData.test === true;
        res.json({
          healthy: healthy,
          canSet: !setErr,
          canGet: !getErr && retrievedData,
          canDestroy: !destroyErr,
          retrievedData: retrievedData
        });
      });
    });
  });
});

// Session debugging middleware
app.use((req, res, next) => {
  console.log('=== ENHANCED SESSION DEBUG ===');
  console.log('URL:', req.url);
  console.log('Method:', req.method);
  console.log('Session ID:', req.sessionID);
  console.log('Session exists:', !!req.session);
  console.log('Session User:', req.session?.user);
  console.log('Session Keys:', req.session ? Object.keys(req.session) : 'No session');
  console.log('=== END ENHANCED DEBUG ===');
  next();
});

// Mobile device session enhancement
app.use((req, res, next) => {
    if (req.isMobileDevice && req.sessionID) {
        // Always set session cookie for mobile devices
        res.cookie('solura.session', req.sessionID, {
            maxAge: 24 * 60 * 60 * 1000,
            httpOnly: false,
            secure: false,
            sameSite: 'Lax',
            path: '/',
            domain: isProduction ? '.solura.uk' : undefined
        });
        
        // Add session ID to all responses for mobile devices
        res.setHeader('X-Session-ID', req.sessionID);
        
        if (req.session.user) {
            console.log('📱 Mobile session enhancement for:', req.session.user.email);
        }
    }
    next();
});

// CRITICAL FIX: Cookie and session persistence middleware
app.use((req, res, next) => {
    // Store original cookie method
    const originalCookie = res.cookie;
    
    // Enhanced cookie method that ensures session cookie is properly set
    res.cookie = function(name, value, options = {}) {
        if (name === 'solura.session') {
            // Ensure consistent cookie settings
            options = {
                maxAge: 24 * 60 * 60 * 1000,
                httpOnly: false,
                secure: false,
                sameSite: 'Lax',
                path: '/',
                domain: isProduction ? '.solura.uk' : undefined,
                ...options
            };
            console.log('🍪 Setting session cookie:', { name, value, options });
        }
        return originalCookie.call(this, name, value, options);
    };
    
    // Ensure session ID consistency across requests
    if (req.sessionID && req.session && req.session.user) {
        console.log('🔗 Maintaining session consistency:', req.sessionID);
        
        // Always set the session cookie for authenticated users
        res.cookie('solura.session', req.sessionID, {
            maxAge: 24 * 60 * 60 * 1000,
            httpOnly: false,
            secure: false,
            sameSite: 'Lax',
            path: '/',
            domain: isProduction ? '.solura.uk' : undefined
        });
    }
    
    next();
});

// FIXED: Session recovery with proper session recreation
app.use((req, res, next) => {
    // Manual cookie parsing
    const cookieHeader = req.headers.cookie;
    const cookies = parseCookies(cookieHeader);
    const sessionCookie = cookies['solura.session'];
    const headerSessionId = req.headers['x-session-id'];
    const querySessionId = req.query.sessionId;
    
    console.log('🔄 Session Recovery Check:', {
        hasCookies: !!cookieHeader,
        cookie: sessionCookie,
        header: headerSessionId,
        query: querySessionId,
        currentSessionId: req.sessionID,
        hasSessionObject: !!req.session,
        hasUser: !!req.session?.user
    });
    
    // If we have an existing session ID from cookie/header/query, use it
    const externalSessionId = sessionCookie || headerSessionId || querySessionId;
    
    if (externalSessionId && externalSessionId !== req.sessionID) {
        console.log('🔄 Attempting to restore session:', externalSessionId);
        
        // Load the session data from store
        req.sessionStore.get(externalSessionId, (err, sessionData) => {
            if (err) {
                console.error('❌ Error loading external session:', err);
                return next();
            }
            
            if (sessionData && sessionData.user) {
                console.log('✅ External session restored:', {
                    sessionId: externalSessionId,
                    user: sessionData.user.email
                });
                
                // Set the session ID and data
                req.sessionID = externalSessionId;
                
                // CRITICAL: Ensure session object exists
                if (!req.session) {
                    console.log('🆕 Creating new session object for restoration');
                    req.session = {};
                }
                
                Object.assign(req.session, sessionData);
                
                // Ensure cookie is set for future requests
                res.cookie('solura.session', externalSessionId, {
                    maxAge: 24 * 60 * 60 * 1000,
                    httpOnly: false,
                    secure: false,
                    sameSite: 'Lax',
                    path: '/',
                    domain: isProduction ? '.solura.uk' : undefined
                });
                
                console.log('✅ Session restoration complete');
            } else {
                console.log('❌ No valid session data found for:', externalSessionId);
                // If no valid session found, continue with current session
            }
            next();
        });
    } else {
        next();
    }
});

// Enhanced root route with proper device detection
app.get('/', (req, res) => {
    const userAgent = req.headers['user-agent'] || '';
    const referer = req.headers.referer || '';
    const origin = req.headers.origin || '';

    console.log('=== ROOT REQUEST DETECTION ===');
    console.log('User-Agent:', userAgent);
    console.log('Referer:', referer);
    console.log('Origin:', origin);

    // Use the enhanced device detection
    const useMobileApp = isMobileDevice(req);

    console.log('Mobile app detected:', useMobileApp);

    // Set session cookie for all devices
    if (req.sessionID) {
        res.cookie('solura.session', req.sessionID, {
            maxAge: 24 * 60 * 60 * 1000,
            httpOnly: false,
            secure: false,
            sameSite: 'Lax',
            path: '/',
            domain: isProduction ? '.solura.uk' : undefined
        });
    }

    if (useMobileApp) {
        console.log('📱 Serving LoginApp.html for mobile device');
        return res.sendFile(path.join(__dirname, 'LoginApp.html'));
    }

    console.log('💻 Serving Login.html for desktop');
    res.sendFile(path.join(__dirname, 'Login.html'));
});

// Enhanced file serving routes
app.get('/LoginApp.html', (req, res) => {
    console.log('📱 Direct access to LoginApp.html');
    
    // Set session cookie
    if (req.sessionID) {
        res.cookie('solura.session', req.sessionID, {
            maxAge: 24 * 60 * 60 * 1000,
            httpOnly: false,
            secure: false,
            sameSite: 'Lax',
            path: '/',
            domain: isProduction ? '.solura.uk' : undefined
        });
    }
    
    res.sendFile(path.join(__dirname, 'LoginApp.html'));
});

app.get('/Login.html', (req, res) => {
    console.log('💻 Direct access to Login.html');
    res.sendFile(path.join(__dirname, 'Login.html'));
});

// NEW: iPad-specific session initialization endpoint
app.get('/api/ipad-init', (req, res) => {
    console.log('📱 iPad Session Initialization Request');
    
    // Ensure session is created and properly initialized for iPad
    if (!req.session.initialized) {
        req.session.initialized = true;
        req.session.ipadDevice = true;
        req.session.userAgent = req.headers['user-agent'];
    }
    
    // iPad-specific cookie settings
    res.cookie('solura.session', req.sessionID, {
        maxAge: 24 * 60 * 60 * 1000,
        httpOnly: false, // iPad needs JS access to cookies
        secure: false,   // iPad Safari has issues with secure cookies
        sameSite: 'Lax', // Lax works better for iPad cross-site requests
        path: '/',
        domain: isProduction ? '.solura.uk' : undefined
    });
    
    // Additional iPad session headers
    res.setHeader('X-Session-ID', req.sessionID);
    res.setHeader('X-Device-Type', 'ipad');
    
    res.json({
        success: true,
        sessionId: req.sessionID,
        message: 'iPad session initialized',
        cookiesSupported: true,
        isIPad: true,
        sessionInitialized: req.session.initialized
    });
});

// NEW: iPad session validation endpoint
app.get('/api/ipad-validate', (req, res) => {
    console.log('📱 iPad Session Validation Request');
    
    if (req.session?.user && req.session.ipadDevice) {
        // iPad session is valid - extend it
        safeSessionTouch(req);
        
        // Always reset the cookie for iPad
        res.cookie('solura.session', req.sessionID, {
            maxAge: 24 * 60 * 60 * 1000,
            httpOnly: false,
            secure: false,
            sameSite: 'Lax',
            path: '/',
            domain: isProduction ? '.solura.uk' : undefined
        });
        
        res.json({
            valid: true,
            user: req.session.user,
            sessionId: req.sessionID,
            device: 'ipad',
            message: 'iPad session is valid'
        });
    } else {
        console.log('❌ iPad session validation failed');
        res.status(401).json({
            valid: false,
            device: 'ipad',
            message: 'iPad session not found or invalid'
        });
    }
});

// Device debug endpoint
app.get('/api/device-debug', (req, res) => {
    console.log('=== DEVICE DEBUG INFO ===');
    
    res.json({
        success: true,
        platform: req.isIPad ? 'ipad' : req.isIOS ? 'ios' : req.isMobileDevice ? 'mobile' : 'desktop',
        session: {
            id: req.sessionID,
            exists: !!req.session,
            user: req.session?.user,
            initialized: req.session?.initialized,
            ipadDevice: req.session?.ipadDevice
        },
        headers: req.headers,
        timestamp: new Date().toISOString()
    });
});

app.get('/health', (req, res) => {
    res.json({ 
        status: 'OK', 
        timestamp: new Date().toISOString(),
        session: req.sessionID ? 'active' : 'none'
    });
});
// ALL YOUR ORIGINAL ROUTES - KEPT INTACT
app.use('/rota', newRota);
app.use('/rota2', newRota2);
app.use('/confirmpassword', confirmpassword);
app.use('/token', token);
app.use('/Backend', Backend);
app.use('/generate', generate);
app.use('/updateinfo', updateinfo);
app.use('/ForgotPassword', ForgotPassword);
app.use('/userholidays', userholidays);
app.use('/hours', hours);
app.use('/labor', labor);
app.use('/pastpayslips', pastpayslips);
app.use('/request', request);
app.use('/tip', tip);
app.use('/pastemployees', pastemployees);
app.use('/TotalHolidays', TotalHolidays);
app.use('/UserCrota', UserCrota);
app.use('/TimeTracking', TimeTracking);
app.use('/UserHoliday', UserHolidays);
app.use('/confirmrota', confirmrota);
app.use('/confirmrota2', confirmrota2);
app.use('/profile', profile);
app.use('/UserTotalHours', UserTotalHours);
app.use('/insertpayslip', insertpayslip);
app.use('/modify', modify);
app.use('/endday', endday);
app.use('/financialsummary', financialsummary);

// NEW: Check if user already has active session
app.post('/api/check-active-session', async (req, res) => {
    const { email } = req.body;
    
    if (!email) {
        return res.status(400).json({ 
            success: false, 
            error: 'Email is required' 
        });
    }

    try {
        const activeSessionIds = activeSessions.get(email);
        
        if (activeSessionIds && activeSessionIds.size > 0) {
            // Check which sessions are still valid
            const validSessions = [];
            
            for (const sessionId of activeSessionIds) {
                await new Promise((resolve) => {
                    sessionStore.get(sessionId, (err, sessionData) => {
                        if (err) {
                            console.error('Error checking session:', err);
                            resolve();
                            return;
                        }
                        
                        if (sessionData && sessionData.user && sessionData.user.email === email) {
                            validSessions.push({
                                sessionId: sessionId,
                                lastAccess: sessionData.cookie?.originalMaxAge ? 
                                    new Date(Date.now() - (24 * 60 * 60 * 1000 - sessionData.cookie.originalMaxAge)) : 
                                    new Date()
                            });
                        }
                        resolve();
                    });
                });
            }
            
            // Remove invalid sessions from tracking
            if (validSessions.length === 0) {
                activeSessions.delete(email);
            } else {
                activeSessions.set(email, new Set(validSessions.map(s => s.sessionId)));
            }
            
            if (validSessions.length > 0) {
                return res.json({
                    success: true,
                    hasActiveSession: true,
                    activeSessions: validSessions.length,
                    message: `You are already logged in on ${validSessions.length} device(s).`
                });
            }
        }
        
        res.json({
            success: true,
            hasActiveSession: false
        });
        
    } catch (error) {
        console.error('Error checking active sessions:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Internal server error' 
        });
    }
});

// Enhanced force logout with immediate effect
app.post('/api/force-logout-others', async (req, res) => {
    const { email, keepCurrentSession } = req.body;
    
    if (!email) {
        return res.status(400).json({ 
            success: false, 
            error: 'Email is required' 
        });
    }

    try {
        const activeSessionIds = activeSessions.get(email);
        let loggedOutCount = 0;

        if (activeSessionIds) {
            const sessionsToDestroy = [];
            
            for (const sessionId of activeSessionIds) {
                if (keepCurrentSession && req.sessionID === sessionId) {
                    continue;
                }
                sessionsToDestroy.push(sessionId);
            }
            
            console.log(`🔄 Force logging out ${sessionsToDestroy.length} sessions for ${email}`);
            
            for (const sessionId of sessionsToDestroy) {
                await new Promise((resolve) => {
                    sessionStore.destroy(sessionId, (err) => {
                        if (!err) {
                            loggedOutCount++;
                            console.log(`✅ Immediately destroyed session: ${sessionId}`);
                        }
                        resolve();
                    });
                });
            }
            
            if (keepCurrentSession && req.sessionID) {
                activeSessions.set(email, new Set([req.sessionID]));
            } else {
                activeSessions.delete(email);
            }
        }

        res.json({
            success: true,
            loggedOutCount: loggedOutCount,
            message: `Immediately logged out from ${loggedOutCount} other session(s)`
        });

    } catch (error) {
        console.error('Error force logging out:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Internal server error' 
        });
    }
});
// Add to your server - Biometric debug endpoint
app.get('/api/biometric-debug', (req, res) => {
    const deviceFingerprint = req.headers['x-device-fingerprint'];
    
    console.log('🔐 BIOMETRIC DEBUG REQUEST:');
    console.log('  - Device Fingerprint:', deviceFingerprint);
    console.log('  - Session ID:', req.sessionID);
    console.log('  - Has Session:', !!req.session);
    console.log('  - Session User:', req.session?.user);
    console.log('  - Headers:', req.headers);
    
    res.json({
        success: true,
        deviceFingerprint: deviceFingerprint,
        session: {
            id: req.sessionID,
            exists: !!req.session,
            user: req.session?.user
        },
        timestamp: new Date().toISOString()
    });
});

// Enhanced biometric login with better debugging
app.post('/api/biometric-login', async (req, res) => {
    safeSessionTouch(req);
    
    console.log('🔐 BIOMETRIC LOGIN ATTEMPT:');
    console.log('  - Body:', req.body);
    console.log('  - Session ID:', req.sessionID);
    console.log('  - Headers:', req.headers);
    
    try {
        const { deviceFingerprint } = req.body;
        
        if (!deviceFingerprint) {
            console.log('❌ No device fingerprint provided');
            return res.status(400).json({ 
                success: false, 
                error: 'Device fingerprint is required' 
            });
        }

        console.log('🔐 Looking up device:', deviceFingerprint);

        // Find user by device fingerprint
        const sql = `
            SELECT bd.user_email, u.Access, u.db_name 
            FROM biometric_devices bd
            JOIN users u ON bd.user_email = u.Email
            WHERE bd.device_fingerprint = ? AND bd.is_active = TRUE
        `;

        mainPool.query(sql, [deviceFingerprint], (err, results) => {
            if (err) {
                console.error('❌ Database error:', err);
                return res.status(500).json({ 
                    success: false, 
                    error: 'Authentication failed' 
                });
            }

            console.log('🔐 Database results:', results);

            if (results.length === 0) {
                console.log('❌ Device not registered:', deviceFingerprint);
                return res.status(401).json({ 
                    success: false, 
                    error: 'Device not registered for biometric access. Please log in with password first.' 
                });
            }

            const deviceRecord = results[0];
            const userEmail = deviceRecord.user_email;

            console.log('✅ Device verified for user:', userEmail);

            // Get user info from company database
            const companyPool = getPool(deviceRecord.db_name);
            const companySql = `SELECT name, lastName FROM Employees WHERE email = ?`;
            
            companyPool.query(companySql, [userEmail], (err, companyResults) => {
                if (err) {
                    console.error('❌ Company database error:', err);
                    return res.status(500).json({ 
                        success: false, 
                        error: 'Internal Server Error' 
                    });
                }

                console.log('🔐 Company database results:', companyResults);

                if (companyResults.length === 0) {
                    console.log('❌ User not found in company database:', userEmail);
                    return res.status(404).json({ 
                        success: false, 
                        error: 'User not found in company database' 
                    });
                }

                const userInfo = {
                    email: userEmail,
                    role: deviceRecord.Access,
                    name: companyResults[0].name,
                    lastName: companyResults[0].lastName,
                    dbName: deviceRecord.db_name,
                };

                console.log('✅ User info retrieved:', userInfo);

                // Create session
                req.session.user = userInfo;
                req.session.initialized = true;
                req.session.biometricLogin = true;
                
                // Track this session
                if (!activeSessions.has(userEmail)) {
                    activeSessions.set(userEmail, new Set());
                }
                activeSessions.get(userEmail).add(req.sessionID);
                
                console.log('✅ Session created:', req.sessionID);

                // Generate tokens
                const authToken = generateToken(userInfo);
                const refreshToken = jwt.sign(
                    {
                        email: userInfo.email,
                        role: userInfo.role,
                        name: userInfo.name,
                        lastName: userInfo.lastName,
                        dbName: userInfo.dbName
                    },
                    process.env.JWT_REFRESH_SECRET || 'your-refresh-secret',
                    { expiresIn: '30d' }
                );

                // Determine redirect URL
                const useMobileApp = isMobileDevice(req);
                let redirectUrl = '';

                if (deviceRecord.Access === 'admin' || deviceRecord.Access === 'AM') {
                    redirectUrl = useMobileApp ? '/AdminApp.html' : '/Admin.html';
                } else if (deviceRecord.Access === 'user') {
                    redirectUrl = useMobileApp ? '/UserApp.html' : '/User.html';
                } else if (deviceRecord.Access === 'supervisor') {
                    redirectUrl = useMobileApp ? '/SupervisorApp.html' : '/Supervisor.html';
                }

                console.log('🔄 Redirect URL determined:', redirectUrl);

                req.session.save((err) => {
                    if (err) {
                        console.error('❌ Session save error:', err);
                        return res.status(500).json({ 
                            success: false,
                            error: 'Failed to create session'
                        });
                    }

                    console.log('✅ Session saved successfully');

                    res.json({
                        success: true,
                        message: 'Biometric authentication successful',
                        redirectUrl: redirectUrl,
                        user: userInfo,
                        accessToken: authToken,
                        refreshToken: refreshToken,
                        sessionId: req.sessionID,
                        debug: {
                            sessionSaved: true,
                            redirectTo: redirectUrl
                        }
                    });
                });
            });
        });

    } catch (error) {
        console.error('❌ Biometric login error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Internal server error' 
        });
    }
});
async function testBiometricConnection() {
    console.log('🔐 Testing biometric connection...');
    
    try {
        // Test basic connection
        const healthResponse = await makeApiRequest('/health');
        console.log('🌐 Health check:', await healthResponse.json());
        
        // Test biometric debug endpoint
        const debugResponse = await makeApiRequest('/api/biometric-debug', {
            headers: {
                'X-Device-Fingerprint': currentDeviceFingerprint
            }
        });
        console.log('🔐 Biometric debug:', await debugResponse.json());
        
        // Test device registration check
        const regResponse = await makeApiRequest('/api/check-device-registration', {
            method: 'POST',
            body: JSON.stringify({ deviceFingerprint: currentDeviceFingerprint })
        });
        console.log('🔐 Device registration check:', await regResponse.json());
        
        return true;
    } catch (error) {
        console.error('❌ Connection test failed:', error);
        return false;
    }
}
// Biometric authentication verification endpoint
app.post('/api/verify-biometric', async (req, res) => {
    safeSessionTouch(req);
    try {
        const { email, accessToken } = req.body;

        if (!email || !accessToken) {
            return res.status(400).json({ 
                success: false,
                error: 'Email and access token are required' 
            });
        }

        // Verify the access token
        try {
            const decoded = jwt.verify(accessToken, process.env.JWT_SECRET || 'your-secret-key');
            if (decoded.email !== email) {
                return res.status(401).json({ 
                    success: false,
                    error: 'Invalid token' 
                });
            }
        } catch (tokenError) {
            return res.status(401).json({ 
                success: false,
                error: 'Invalid or expired token' 
            });
        }

        // Get user info from database - include ALL databases for this user
        const sql = `SELECT u.Access, u.Email, u.db_name FROM users u WHERE u.Email = ?`;

        mainPool.query(sql, [email], (err, results) => {
            if (err) {
                console.error('Error querying database:', err);
                return res.status(500).json({ 
                    success: false,
                    error: 'Internal Server Error'
                });
            }

            if (results.length === 0) {
                return res.status(401).json({ 
                    success: false,
                    message: 'User not found' 
                });
            }

            // Find the database that matches the token's dbName
            const userDetails = results.find(row => row.db_name === decoded.dbName);
            if (!userDetails) {
                return res.status(401).json({ 
                    success: false,
                    message: 'User not authorized for this database' 
                });
            }
            
            // Get user info from company database
            const companyPool = getPool(userDetails.db_name);
            const companySql = `SELECT name, lastName FROM Employees WHERE email = ?`;

            companyPool.query(companySql, [email], (err, companyResults) => {
                if (err) {
                    console.error('Error querying company database:', err);
                    return res.status(500).json({ 
                        success: false,
                        error: 'Internal Server Error'
                    });
                }

                if (companyResults.length === 0) {
                    return res.status(401).json({ 
                        success: false,
                        message: 'User not found in company database' 
                    });
                }

                const name = companyResults[0].name;
                const lastName = companyResults[0].lastName;

                const userInfo = {
                    email: email,
                    role: userDetails.Access,
                    name: name,
                    lastName: lastName,
                    dbName: userDetails.db_name,
                };

                console.log('✅ Biometric authentication successful for user:', userInfo);

                // Create session
                req.session.user = userInfo;
                req.session.initialized = true;
                
                // iPad-specific session handling
                if (req.isIPad) {
                    req.session.ipadDevice = true;
                    console.log('📱 iPad biometric authentication - marking device');
                }
                
                // Track this session
                if (!activeSessions.has(email)) {
                    activeSessions.set(email, new Set());
                }
                // Only add if not already present
                if (!activeSessions.get(email).has(req.sessionID)) {
                    activeSessions.get(email).add(req.sessionID);
                    console.log(`✅ Login session tracked for ${email}: ${req.sessionID}`);
                }
                
                // Generate new tokens
                const authToken = generateToken(userInfo);
                const refreshToken = jwt.sign(
                    {
                        email: userInfo.email,
                        role: userInfo.role,
                        name: userInfo.name,
                        lastName: userInfo.lastName,
                        dbName: userInfo.dbName
                    },
                    process.env.JWT_REFRESH_SECRET || 'your-refresh-secret',
                    { expiresIn: '30d' }
                );

                // PROPER DEVICE DETECTION FOR REDIRECT
                const useMobileApp = isMobileDevice(req);
                let redirectUrl = '';

                if (userDetails.Access === 'admin' || userDetails.Access === 'AM') {
                    redirectUrl = useMobileApp ? '/AdminApp.html' : '/Admin.html';
                } else if (userDetails.Access === 'user') {
                    redirectUrl = useMobileApp ? '/UserApp.html' : '/User.html';
                } else if (userDetails.Access === 'supervisor') {
                    redirectUrl = useMobileApp ? '/SupervisorApp.html' : '/Supervisor.html';
                }

                req.session.save((err) => {
                    if (err) {
                        console.error('Error saving session:', err);
                        return res.status(500).json({ 
                            success: false,
                            error: 'Failed to create session'
                        });
                    }

                    res.json({
                        success: true,
                        message: 'Biometric authentication successful',
                        redirectUrl: redirectUrl,
                        user: userInfo,
                        accessToken: authToken,
                        refreshToken: refreshToken,
                        sessionId: req.sessionID
                    });
                });
            });
        });
    } catch (error) {
        console.error('Biometric authentication error:', error);
        res.status(500).json({ 
            success: false,
            error: 'Internal server error'
        });
    }
});

// Token refresh endpoint for biometric authentication
app.post('/api/refresh-token', async (req, res) => {
    safeSessionTouch(req);
    try {
        const { refreshToken } = req.body;

        if (!refreshToken) {
            return res.status(400).json({ 
                success: false,
                error: 'Refresh token is required' 
            });
        }

        // Verify the refresh token
        try {
            const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET || 'your-refresh-secret');
            
            // Generate new access token
            const newAccessToken = generateToken({
                email: decoded.email,
                role: decoded.role,
                name: decoded.name,
                lastName: decoded.lastName,
                dbName: decoded.dbName
            });

            res.json({
                success: true,
                accessToken: newAccessToken,
                expiresIn: '7d'
            });

        } catch (tokenError) {
            return res.status(401).json({ 
                success: false,
                error: 'Invalid or expired refresh token' 
            });
        }
    } catch (error) {
        console.error('Token refresh error:', error);
        res.status(500).json({ 
            success: false,
            error: 'Internal server error'
        });
    }
});

// NEW: Get current user info endpoint for frontend
app.get('/api/current-user', isAuthenticated, (req, res) => {
    safeSessionTouch(req);
    res.json({
        success: true,
        user: req.session.user
    });
});

// Session debug endpoint
app.get('/api/session-debug', (req, res) => {
    const sessionCookie = req.cookies['solura.session'];
    const headerSessionId = req.headers['x-session-id'];
    
    res.json({
        session: {
            id: req.sessionID,
            exists: !!req.session,
            user: req.session?.user,
            cookie: sessionCookie,
            header: headerSessionId
        },
        headers: {
            cookie: req.headers.cookie,
            'x-session-id': req.headers['x-session-id'],
            origin: req.headers.origin,
            'user-agent': req.headers['user-agent']
        },
        timestamp: new Date().toISOString()
    });
});

// Session validation endpoint with safe touch
app.get('/api/validate-session', (req, res) => {
    console.log('=== VALIDATE SESSION ===');
    console.log('Session ID:', req.sessionID);
    console.log('Session exists:', !!req.session);
    console.log('Session User:', req.session?.user);
    
    if (req.session?.user) {
        // Safe session extension
        safeSessionTouch(req);
        res.json({ 
            valid: true, 
            user: req.session.user,
            sessionId: req.sessionID 
        });
    } else {
        console.log('Session validation failed - no user in session');
        res.status(401).json({ 
            valid: false,
            message: 'No active session'
        });
    }
});

// FIXED: Simplified heartbeat endpoint
app.get('/api/session-heartbeat', (req, res) => {
    console.log('💓 Heartbeat connection established - Session ID:', req.sessionID);
    
    // Set proper SSE headers
    res.writeHead(200, {
        'Content-Type': 'text/event-stream',
        'Cache-Control': 'no-cache',
        'Connection': 'keep-alive',
        'Access-Control-Allow-Origin': req.headers.origin || '*',
        'Access-Control-Allow-Credentials': 'true'
    });

    // Send immediate connection confirmation
    res.write('data: ' + JSON.stringify({
        type: 'connected',
        message: 'Heartbeat connection established',
        sessionId: req.sessionID,
        timestamp: Date.now()
    }) + '\n\n');

    let isConnected = true;

    // Check session validity immediately
    const checkSession = () => {
        if (!isConnected) return;

        try {
            // Simple session check - don't rely on activeSessions tracking
            if (!req.session?.user) {
                console.log('💔 Heartbeat: No user in session');
                res.write('data: ' + JSON.stringify({
                    valid: false,
                    reason: 'no_session_user',
                    message: 'Please log in again',
                    timestamp: Date.now()
                }) + '\n\n');
                return;
            }

            // Session is valid
            res.write('data: ' + JSON.stringify({
                valid: true,
                type: 'heartbeat',
                user: req.session.user.email,
                timestamp: Date.now()
            }) + '\n\n');

        } catch (error) {
            console.error('💔 Heartbeat error:', error);
        }
    };

    // Check immediately and then every 10 seconds
    checkSession();
    const intervalId = setInterval(checkSession, 10000);

    // Handle client disconnect
    req.on('close', () => {
        console.log('💓 Heartbeat connection closed');
        isConnected = false;
        clearInterval(intervalId);
    });

    req.on('error', (error) => {
        console.error('💓 Heartbeat connection error:', error);
        isConnected = false;
        clearInterval(intervalId);
    });
});

// NEW: Get available databases for current user
app.get('/api/user-databases', isAuthenticated, (req, res) => {
    safeSessionTouch(req);
    const email = req.session.user.email;
    
    const sql = `SELECT u.db_name, u.Access FROM users u WHERE u.Email = ?`;
    
    mainPool.query(sql, [email], (err, results) => {
        if (err) {
            console.error('Error querying user databases:', err);
            return res.status(500).json({ 
                success: false, 
                error: 'Internal Server Error' 
            });
        }

        const databases = results.map(row => ({
            db_name: row.db_name,
            access: row.Access
        }));

        res.json({
            success: true,
            databases: databases,
            currentDb: req.session.user.dbName
        });
    });
});

// FIXED: Switch database endpoint - ensure session ID consistency
app.post('/api/switch-database', isAuthenticated, async (req, res) => {
    const { dbName } = req.body;
    const email = req.session.user.email;

    if (!dbName) {
        return res.status(400).json({ 
            success: false, 
            error: 'Database name is required' 
        });
    }

    try {
        // Verify user has access to the requested database
        const verifySql = `SELECT u.Access, u.Email, u.db_name FROM users u WHERE u.Email = ? AND u.db_name = ?`;
        
        mainPool.query(verifySql, [email, dbName], (err, results) => {
            if (err) {
                console.error('Error verifying database access:', err);
                return res.status(500).json({ 
                    success: false, 
                    error: 'Internal Server Error' 
                });
            }

            if (results.length === 0) {
                return res.status(403).json({ 
                    success: false, 
                    error: 'User not authorized for this database' 
                });
            }

            const userDetails = results[0];
            
            // Get user info from the new company database
            const companyPool = getPool(dbName);
            const companySql = `SELECT name, lastName FROM Employees WHERE email = ?`;
            
            companyPool.query(companySql, [email], (err, companyResults) => {
                if (err) {
                    console.error('Error querying company database:', err);
                    return res.status(500).json({ 
                        success: false, 
                        error: 'Internal Server Error' 
                    });
                }

                if (companyResults.length === 0) {
                    return res.status(404).json({ 
                        success: false, 
                        error: 'User not found in company database' 
                    });
                }

                const name = companyResults[0].name;
                const lastName = companyResults[0].lastName;

                // Update session with new database info
                req.session.user = {
                    email: email,
                    role: userDetails.Access,
                    name: name,
                    lastName: lastName,
                    dbName: dbName,
                };

                // iPad-specific session preservation
                if (req.isIPad) {
                    req.session.ipadDevice = true;
                    console.log('📱 iPad database switch - preserving device type');
                }

                console.log('🔄 Database switching - Same session ID:', req.sessionID);
                console.log('🔄 Updated session user:', req.session.user);

                // Save the updated session
                req.session.save((err) => {
                    if (err) {
                        console.error('Error saving session after database switch:', err);
                        return res.status(500).json({ 
                            success: false, 
                            error: 'Failed to update session' 
                        });
                    }

                    console.log('✅ Database switched successfully to:', dbName);

                    res.json({
                        success: true,
                        message: 'Database switched successfully',
                        user: req.session.user,
                        sessionId: req.sessionID
                    });
                });
            });
        });
    } catch (error) {
        console.error('Database switch error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Internal server error' 
        });
    }
});

// FIXED: Session initialization endpoint for iOS
app.get('/api/init-session', (req, res) => {
    console.log('🔄 Initializing session');
    
    // Ensure session is created and marked as initialized
    if (!req.session.initialized) {
        req.session.initialized = true;
    }
    
    // iPad-specific initialization
    if (req.isIPad) {
        req.session.ipadDevice = true;
        console.log('📱 iPad session initialization');
    }
    
    // Touch the session to ensure it's saved
    safeSessionTouch(req);
    
    req.session.save((err) => {
        if (err) {
            console.error('Error saving session:', err);
            return res.status(500).json({ success: false, error: 'Session initialization failed' });
        }
        
        console.log('✅ Session initialized with ID:', req.sessionID);
        
        res.json({
            success: true,
            sessionId: req.sessionID,
            message: 'Session initialized successfully'
        });
    });
});

// CRITICAL FIX: Enhanced authentication middleware for iOS and iPad
function isAuthenticated(req, res, next) {
    console.log('=== AUTH CHECK ===');
    console.log('Session ID:', req.sessionID);
    console.log('Session exists:', !!req.session);
    console.log('Session User:', req.session?.user);
    console.log('iPad Device:', req.session?.ipadDevice);
    
    // For iOS/iPad, also check for session ID in headers or query
    const sessionIdFromHeader = req.headers['x-session-id'];
    const sessionIdFromQuery = req.query.sessionId;
    
    if ((!req.session?.user) && (sessionIdFromHeader || sessionIdFromQuery)) {
        const externalSessionId = sessionIdFromHeader || sessionIdFromQuery;
        console.log('📱 iOS/iPad - Attempting session recovery from external ID:', externalSessionId);
        
        // Check if sessionStore exists before using it
        if (!req.sessionStore || typeof req.sessionStore.get !== 'function') {
            console.log('❌ Session store not available for recovery');
            return sendAuthError(res, req);
        }
        
        req.sessionStore.get(externalSessionId, (err, sessionData) => {
            if (err) {
                console.error('Error loading external session:', err);
                return sendAuthError(res, req);
            }
            
            if (sessionData && sessionData.user) {
                console.log('✅ External session recovery successful');
                Object.assign(req.session, sessionData);
                
                // IMPORTANT: Force save recovered session to ensure persistence
                req.session.save((saveErr) => {
                   if (saveErr) console.error('Error saving recovered session', saveErr);
                   return next();
                });
            } else {
                console.log('❌ No valid session data found for recovery');
                sendAuthError(res, req);
            }
        });
    } else if (req.session?.user && req.session.user.dbName && req.session.user.email) {
        console.log('✅ Authentication SUCCESS for user:', req.session.user.email);
        
        // iPad-specific session validation
        if (req.isIPad && !req.session.ipadDevice) {
            console.log('📱 iPad session - marking as iPad device');
            req.session.ipadDevice = true;
            req.session.save(() => {}); // Save without waiting for callback
        }
        
        return next();
    } else {
        console.log('❌ Authentication FAILED');
        sendAuthError(res, req);
    }
}

function sendAuthError(res, req, customMessage = null) {
    const message = customMessage || 'Please log in again';
    
    if (req.path.startsWith('/api/') || req.xhr) {
        return res.status(401).json({ 
            success: false, 
            error: 'Unauthorized',
            message: message,
            requiresLogin: true
        });
    }
    
    res.redirect('/?error=' + encodeURIComponent(message));
}

// Role-based middleware (keep existing)
function isAdmin(req, res, next) {
    if (req.session?.user && (req.session.user.role === 'admin' || req.session.user.role === 'AM')) {
        return next();
    }
    sendAuthError(res, req, 'Admin access required');
}

function isSupervisor(req, res, next) {
    if (req.session?.user && req.session.user.role === 'supervisor') {
        return next();
    }
    sendAuthError(res, req, 'Supervisor access required');
}

function isUser(req, res, next) {
    if (req.session?.user && req.session.user.role === 'user') {
        return next();
    }
    sendAuthError(res, req, 'User access required');
}

// Enhanced database selection with force logout support
app.post('/submit-database', async (req, res) => {
    console.log('=== DATABASE SELECTION ===');
    console.log('Session ID:', req.sessionID);
    
    const { email, password, dbName, forceLogout } = req.body;

    if (!email || !password || !dbName) {
        return res.status(400).json({ 
            success: false,
            message: 'Email, password, and database name are required' 
        });
    }

    try {
        // First verify the user credentials
        const sql = `SELECT u.Access, u.Password, u.Email, u.db_name FROM users u WHERE u.Email = ? AND u.db_name = ?`;
        
        mainPool.query(sql, [email, dbName], async (err, results) => {
            if (err) {
                console.error('Error querying database:', err);
                return res.status(500).json({ 
                    success: false,
                    error: 'Internal Server Error'
                });
            }

            if (results.length === 0) {
                return res.status(401).json({ 
                    success: false,
                    message: 'Invalid database selection' 
                });
            }

            // Verify password
            const row = results[0];
            const storedPassword = row.Password;
            try {
                const isMatch = await bcrypt.compare(password, storedPassword);
                if (!isMatch) {
                    return res.status(401).json({ 
                        success: false,
                        message: 'Invalid credentials' 
                    });
                }
            } catch (err) {
                console.error('Error comparing passwords:', err);
                return res.status(500).json({ 
                    success: false,
                    error: 'Internal Server Error'
                });
            }

            // Check for active sessions
            const activeSessionIds = activeSessions.get(email);
            let hasActiveSessions = false;
            
            if (activeSessionIds && activeSessionIds.size > 0) {
                for (const sessionId of activeSessionIds) {
                    await new Promise((resolve) => {
                        sessionStore.get(sessionId, (err, sessionData) => {
                            if (!err && sessionData && sessionData.user) {
                                hasActiveSessions = true;
                            }
                            resolve();
                        });
                    });
                    if (hasActiveSessions) break;
                }
            }

            // If user has active sessions and hasn't chosen to force logout, return warning
            if (hasActiveSessions && forceLogout !== true) {
                return res.status(409).json({
                    success: false,
                    message: 'already_logged_in',
                    activeSessions: activeSessionIds ? activeSessionIds.size : 0
                });
            }

            // If force logout is requested, destroy other sessions
            if (hasActiveSessions && forceLogout === true) {
                console.log('🔄 Force logout requested for database selection:', email);
                for (const sessionId of activeSessionIds) {
                    if (sessionId !== req.sessionID) {
                        await new Promise((resolve) => {
                            sessionStore.destroy(sessionId, (err) => {
                                if (err) {
                                    console.error('Error destroying session:', err);
                                } else {
                                    console.log(`✅ Destroyed previous session: ${sessionId}`);
                                }
                                resolve();
                            });
                        });
                    }
                }
                // Clear tracking and only keep current session
                activeSessions.set(email, new Set([req.sessionID]));
            }

            // Continue with login
            const companyPool = getPool(dbName);
            const companySql = `SELECT name, lastName FROM Employees WHERE email = ?`;

            companyPool.query(companySql, [email], (err, companyResults) => {
                if (err) {
                    console.error('Error querying company database:', err);
                    return res.status(500).json({ 
                        success: false,
                        error: 'Internal Server Error'
                    });
                }

                if (companyResults.length === 0) {
                    return res.status(401).json({ 
                        success: false,
                        message: 'User not found in company database' 
                    });
                }

                const name = companyResults[0].name;
                const lastName = companyResults[0].lastName;

                const userInfo = {
                    email: email,
                    role: row.Access,
                    name: name,
                    lastName: lastName,
                    dbName: dbName,
                };

                console.log('✅ Database selection successful, creating session for user:', userInfo);

                // Set session data
                req.session.user = userInfo;
                req.session.initialized = true;
                
                // iPad-specific session handling
                if (req.isIPad) {
                    req.session.ipadDevice = true;
                    console.log('📱 iPad database selection - marking device');
                }
                
                // Track this session
                if (!activeSessions.has(email)) {
                    activeSessions.set(email, new Set());
                }
                // Only add if not already present
                if (!activeSessions.get(email).has(req.sessionID)) {
                    activeSessions.get(email).add(req.sessionID);
                    console.log(`✅ Login session tracked for ${email}: ${req.sessionID}`);
                }
                
                // Generate tokens
                const authToken = generateToken(userInfo);
                const refreshToken = jwt.sign(
                    {
                        email: userInfo.email,
                        role: userInfo.role,
                        name: userInfo.name,
                        lastName: userInfo.lastName,
                        dbName: userInfo.dbName
                    },
                    process.env.JWT_REFRESH_SECRET || 'your-refresh-secret',
                    { expiresIn: '30d' }
                );

                // PROPER DEVICE DETECTION
                const useMobileApp = isMobileDevice(req);
                let redirectUrl = '';

                if (row.Access === 'admin' || row.Access === 'AM') {
                    redirectUrl = useMobileApp ? '/AdminApp.html' : '/Admin.html';
                } else if (row.Access === 'user') {
                    redirectUrl = useMobileApp ? '/UserApp.html' : '/User.html';
                } else if (row.Access === 'supervisor') {
                    redirectUrl = useMobileApp ? '/SupervisorApp.html' : '/Supervisor.html';
                }

                console.log(`🔄 Redirecting to: ${redirectUrl} (Mobile: ${useMobileApp})`);

                // Save session and then respond
                req.session.save((err) => {
                    if (err) {
                        console.error('Error saving session:', err);
                        return res.status(500).json({ 
                            success: false,
                            error: 'Failed to create session'
                        });
                    }

                    console.log('✅ Session saved successfully. Session ID:', req.sessionID);

                    // Set session cookie with device-specific settings
                    const cookieOptions = {
                        maxAge: 24 * 60 * 60 * 1000,
                        path: '/',
                        domain: isProduction ? '.solura.uk' : undefined
                    };

                    // iPad-specific cookie settings
                    if (req.isIPad) {
                        cookieOptions.httpOnly = false; // iPad needs JS access
                        cookieOptions.secure = false;   // iPad Safari issues with secure
                        cookieOptions.sameSite = 'Lax'; // Lax works better for iPad
                    } else {
                        cookieOptions.httpOnly = true;
                        cookieOptions.secure = isProduction;
                        cookieOptions.sameSite = 'none';
                    }

                    res.cookie('solura.session', req.sessionID, cookieOptions);

                    res.json({
                        success: true,
                        message: 'Login successful',
                        redirectUrl: redirectUrl,
                        user: userInfo,
                        accessToken: authToken,
                        refreshToken: refreshToken,
                        sessionId: req.sessionID,
                        isMobile: useMobileApp,
                        isIPad: req.isIPad
                    });
                });
            });
        });
    } catch (error) {
        console.error('Database selection error:', error);
        res.status(500).json({ 
            success: false,
            error: 'Internal server error'
        });
    }
});
