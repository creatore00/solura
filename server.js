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

// Define a list of origins that are allowed to connect.
const allowedOrigins = [
    'https://www.solura.uk', // Your main web domain
    'http://localhost:8080',   // Your local development environment
    'http://localhost',        // Common for local testing
    'capacitor://localhost',   // **Crucial for Capacitor on iOS/Android**
    'ionic://localhost'        // **Crucial for Ionic Framework**
];

const corsOptions = {
    origin: function (origin, callback) {
        // Allow requests with no origin (like mobile apps or curl requests)
        // or requests from an origin in our whitelist.
        if (!origin || allowedOrigins.indexOf(origin) !== -1) {
            callback(null, true);
        } else {
            console.error('CORS Error: This origin is not allowed:', origin);
            callback(new Error('Not allowed by CORS'));
        }
    },
    credentials: true, // This allows cookies to be sent and received
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'Cookie', 'X-Session-ID', 'X-Capacitor'],
    exposedHeaders: ['Set-Cookie', 'X-Session-ID', 'Authorization']
};

// **Use this single, robust CORS configuration for your entire app.**
app.use(cors(corsOptions));

// **Handle pre-flight requests for all routes.**
// This is essential for requests with custom headers or non-simple methods (like POST with JSON).
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

// Enhanced session configuration for iOS/Capacitor
app.use(session({
  key: 'solura.session',
  secret: process.env.SESSION_SECRET || 'supersecret',
  store: sessionStore,
  resave: false,
  saveUninitialized: true,
  proxy: true,
  cookie: {
    // CRITICAL FOR iOS: These settings work best for iOS Safari/Capacitor
    httpOnly: false, // Allow JavaScript access for Capacitor
    secure: isProduction, // Use secure cookies in production
    sameSite: isProduction ? 'none' : 'lax', // 'none' for cross-site in production
    maxAge: 24 * 60 * 60 * 1000, // 24 hours
    domain: isProduction ? '.solura.uk' : undefined,
    // iOS-specific optimizations
    path: '/',
    // Add these for better iOS compatibility
    ...(req.isIOS && {
      secure: false, // iOS Safari has issues with secure cookies
      sameSite: 'Lax' // Lax works better for iOS
    })
  },
  // Add genid function for better session ID management
  genid: (req) => {
    return require('crypto').randomBytes(16).toString('hex');
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

// CRITICAL FIX: iOS Cookie Persistence Middleware
app.use((req, res, next) => {
  // Store original cookie method
  const originalCookie = res.cookie;
  
  // Enhanced cookie method for iOS
  res.cookie = function(name, value, options = {}) {
    // iOS-specific cookie settings
    if (req.isIOS || req.isIPad) {
      options = {
        httpOnly: false,
        secure: false, // iOS Safari works better with non-secure cookies
        sameSite: 'Lax',
        maxAge: 24 * 60 * 60 * 1000,
        path: '/',
        domain: isProduction ? '.solura.uk' : undefined,
        ...options
      };
    }
    
    console.log(`🍪 Setting cookie: ${name}=${value}`, {
      ios: req.isIOS,
      ipad: req.isIPad,
      options
    });
    
    return originalCookie.call(this, name, value, options);
  };
  
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

// Health check with session info
app.get('/health', (req, res) => {
    res.json({
        status: 'OK',
        session: {
            id: req.sessionID,
            exists: !!req.session,
            user: req.session?.user,
            initialized: req.session?.initialized,
            ipadDevice: req.session?.ipadDevice
        },
        timestamp: new Date().toISOString()
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

// FIXED: Real-time session validation endpoint
app.get('/api/validate-session-real-time', async (req, res) => {
    console.log('=== REAL-TIME SESSION VALIDATION ===');
    console.log('Session ID from cookie:', req.sessionID);
    console.log('Session exists:', !!req.session);
    console.log('Session User:', req.session?.user);
    
    // Ensure session is loaded
    if (!req.session) {
        return res.json({
            valid: false,
            reason: 'session_not_loaded',
            message: 'Session not loaded'
        });
    }

    if (!req.session.user) {
        return res.json({
            valid: false,
            reason: 'no_session_user',
            message: 'No user in session'
        });
    }

    const email = req.session.user.email;
    const activeSessionIds = activeSessions.get(email);
    
    console.log('Active sessions for user:', activeSessionIds ? Array.from(activeSessionIds) : 'None');
    console.log('Current session in active sessions:', activeSessionIds?.has(req.sessionID));
    
    // Check if this session is still active
    if (!activeSessionIds || !activeSessionIds.has(req.sessionID)) {
        console.log('🚫 Session terminated - no longer in active sessions');
        
        // Destroy the invalid session
        req.session.destroy((err) => {
            if (err) {
                console.error('Error destroying invalid session:', err);
            }
        });
        
        return res.json({
            valid: false,
            reason: 'session_terminated',
            message: 'Your session was terminated from another device',
            terminated: true
        });
    }

    // Session is valid - update last access
    safeSessionTouch(req);
    
    res.json({
        valid: true,
        user: req.session.user,
        sessionId: req.sessionID,
        activeSessions: activeSessionIds ? Array.from(activeSessionIds) : [],
        message: 'Session is valid'
    });
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

// ENHANCED: iOS session restoration with proper session handling
app.post('/api/ios-restore-session', async (req, res) => {
    safeSessionTouch(req);
    try {
        const { email, dbName, accessToken, sessionId } = req.body;
        
        if (!email || !dbName || !accessToken) {
            return res.status(400).json({ 
                success: false, 
                error: 'Missing required parameters' 
            });
        }

        // Verify the access token first
        try {
            const decoded = jwt.verify(accessToken, process.env.JWT_SECRET || 'your-secret-key');
            if (decoded.email !== email || decoded.dbName !== dbName) {
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

        // Then proceed with user verification - get ALL databases first
        const verifySql = `SELECT u.Access, u.Email, u.db_name FROM users u WHERE u.Email = ?`;

        mainPool.query(verifySql, [email], (err, results) => {
            if (err) {
                console.error('Error verifying user access:', err);
                return res.status(500).json({ 
                    success: false, 
                    error: 'Internal Server Error' 
                });
            }

            if (results.length === 0) {
                return res.status(403).json({ 
                    success: false, 
                    error: 'User not found' 
                });
            }

            // Find the specific database the user is trying to access
            const userDetails = results.find(row => row.db_name === dbName);
            if (!userDetails) {
                return res.status(403).json({ 
                    success: false, 
                    error: 'User not authorized for this database' 
                });
            }
            
            // Get user info from company database
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

                const userInfo = {
                    email: email,
                    role: userDetails.Access,
                    name: companyResults[0].name,
                    lastName: companyResults[0].lastName,
                    dbName: dbName,
                };

                console.log('✅ iOS session restoration successful for user:', userInfo);

                // Use existing session or create new one
                if (sessionId) {
                    req.sessionID = sessionId;
                }
                
                // Set user data - this is critical
                req.session.user = userInfo;
                req.session.initialized = true;
                
                // iPad-specific session handling
                if (req.isIPad) {
                    req.session.ipadDevice = true;
                    console.log('📱 iPad session restoration - marking device');
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
                
                // Force save with callback to ensure it's persisted
                req.session.save((err) => {
                    if (err) {
                        console.error('❌ Error saving iOS session:', err);
                        return res.status(500).json({ 
                            success: false, 
                            error: 'Failed to save session' 
                        });
                    }

                    console.log('✅ iOS session saved/updated with ID:', req.sessionID);
                    
                    res.json({ 
                        success: true, 
                        user: userInfo,
                        sessionId: req.sessionID,
                        accessToken: accessToken
                    });
                });
            });
        });
        
    } catch (error) {
        console.error('iOS session restoration error:', error);
        res.status(500).json({ 
            success: false, 
            error: error.message 
        });
    }
});

// NEW: Device registration endpoint
app.post('/api/register-device', isAuthenticated, async (req, res) => { // ADDED: isAuthenticated
    safeSessionTouch(req);
    try {
        // **FIX: Get the email from the authenticated session, not the request body.**
        const email = req.session.user.email;
        const { deviceFingerprint, deviceInfo } = req.body;

        if (!deviceFingerprint || !deviceInfo) { // Email check is no longer needed here
            return res.status(400).json({ 
                success: false, 
                error: 'Device fingerprint and device info are required' 
            });
        }

        console.log('📱 Registering device for authenticated user:', {
            email: email, // Log the email from the session
            deviceFingerprint: deviceFingerprint
        });

        // The rest of your database insertion logic remains the same...
        const sql = `
            INSERT INTO biometric_devices 
            (user_email, device_fingerprint, device_name, platform, user_agent, screen_resolution, 
             hardware_concurrency, timezone, language, registration_date, last_used, is_active) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NOW(), NOW(), TRUE)
            ON DUPLICATE KEY UPDATE 
            last_used = NOW(), is_active = TRUE
        `;

        mainPool.query(sql, [
            email,
            deviceFingerprint,
            `Device-${deviceFingerprint.substring(0, 8)}`,
            deviceInfo.platform,
            deviceInfo.userAgent,
            deviceInfo.screenResolution,
            deviceInfo.hardwareConcurrency || 0,
            deviceInfo.timezone,
            deviceInfo.language
        ], (err, results) => {
            if (err) {
                console.error('Error registering device:', err);
                return res.status(500).json({ 
                    success: false, 
                    error: 'Failed to register device' 
                });
            }

            console.log('✅ Device registered successfully for user:', email);
            
            res.json({
                success: true,
                message: 'Device registered for biometric authentication',
                deviceFingerprint: deviceFingerprint
            });
        });

    } catch (error) {
        console.error('Device registration error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Internal server error' 
        });
    }
});

// NEW: Check device registration endpoint
app.post('/api/check-device-registration', async (req, res) => {
    safeSessionTouch(req);
    try {
        const deviceFingerprint = req.headers['x-device-fingerprint'] || req.body.deviceFingerprint;

        if (!deviceFingerprint) {
            return res.status(400).json({ 
                success: false, 
                error: 'Device fingerprint is required' 
            });
        }

        console.log('🔍 Checking device registration:', deviceFingerprint);

        // Check if device is registered
        const sql = `
            SELECT bd.*, u.db_name 
            FROM biometric_devices bd
            JOIN users u ON bd.user_email = u.Email
            WHERE bd.device_fingerprint = ? AND bd.is_active = TRUE
        `;

        mainPool.query(sql, [deviceFingerprint], (err, results) => {
            if (err) {
                console.error('Error checking device registration:', err);
                return res.status(500).json({ 
                    success: false, 
                    error: 'Failed to check device registration' 
                });
            }

            if (results.length > 0) {
                const deviceInfo = results[0];
                console.log('✅ Device is registered for user:', deviceInfo.user_email);
                
                res.json({
                    success: true,
                    registered: true,
                    deviceInfo: {
                        userEmail: deviceInfo.user_email,
                        deviceName: deviceInfo.device_name,
                        platform: deviceInfo.platform,
                        registrationDate: deviceInfo.registration_date,
                        lastUsed: deviceInfo.last_used
                    }
                });
            } else {
                console.log('❌ Device not registered:', deviceFingerprint);
                res.json({
                    success: true,
                    registered: false
                });
            }
        });

    } catch (error) {
        console.error('Device registration check error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Internal server error' 
        });
    }
});

// Enhanced biometric login with policy support
app.post('/api/biometric-login', async (req, res) => {
    safeSessionTouch(req);
    try {
        const deviceFingerprint = req.headers['x-device-fingerprint'] || req.body.deviceFingerprint;
        const biometricPolicy = req.headers['x-biometric-policy'] || 'device_owner_authentication';

        if (!deviceFingerprint) {
            return res.status(400).json({ 
                success: false, 
                error: 'Device fingerprint is required' 
            });
        }

        console.log('🔐 Biometric login attempt:', {
            deviceFingerprint,
            policy: biometricPolicy,
            ip: req.ip,
            userAgent: req.headers['user-agent']
        });

        // Enhanced device verification with policy consideration
        const sql = `
            SELECT bd.user_email, u.Access, u.db_name 
            FROM biometric_devices bd
            JOIN users u ON bd.user_email = u.Email
            WHERE bd.device_fingerprint = ? AND bd.is_active = TRUE
        `;

        mainPool.query(sql, [deviceFingerprint], (err, results) => {
            if (err) {
                console.error('Error during biometric login:', err);
                return res.status(500).json({ 
                    success: false, 
                    error: 'Authentication failed' 
                });
            }

            if (results.length === 0) {
                console.log('❌ Biometric login failed: Device not registered');
                return res.status(401).json({ 
                    success: false, 
                    error: 'Device not registered for biometric access' 
                });
            }

            const deviceRecord = results[0];
            const userEmail = deviceRecord.user_email;

            console.log('✅ Device verified for user:', userEmail);

            // Log the authentication policy used
            console.log('📋 Authentication policy used:', biometricPolicy);

            // Continue with your existing login logic...
            // [Keep your existing database selection and session creation code]

            // Add policy information to response for debugging
            const responseData = {
                success: true,
                message: 'Biometric login successful',
                redirectUrl: redirectUrl,
                user: userInfo,
                accessToken: authToken,
                refreshToken: refreshToken,
                sessionId: req.sessionID,
                authenticationMethod: 'biometric',
                policyUsed: biometricPolicy
            };

            res.json(responseData);
        });

    } catch (error) {
        console.error('Biometric login error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Internal server error' 
        });
    }
});

// NEW: Get registered devices for a user (admin function)
app.get('/api/registered-devices', isAuthenticated, (req, res) => {
    safeSessionTouch(req);
    const userEmail = req.session.user.email;

    const sql = `
        SELECT device_fingerprint, device_name, platform, user_agent, screen_resolution,
               hardware_concurrency, timezone, language, registration_date, last_used, is_active
        FROM biometric_devices 
        WHERE user_email = ?
        ORDER BY last_used DESC
    `;

    mainPool.query(sql, [userEmail], (err, results) => {
        if (err) {
            console.error('Error fetching registered devices:', err);
            return res.status(500).json({ 
                success: false, 
                error: 'Failed to fetch devices' 
            });
        }

        res.json({
            success: true,
            devices: results,
            count: results.length
        });
    });
});

// NEW: Revoke device access
app.post('/api/revoke-device', isAuthenticated, (req, res) => {
    safeSessionTouch(req);
    const { deviceFingerprint } = req.body;
    const userEmail = req.session.user.email;

    if (!deviceFingerprint) {
        return res.status(400).json({ 
            success: false, 
            error: 'Device fingerprint is required' 
        });
    }

    const sql = `UPDATE biometric_devices SET is_active = FALSE WHERE user_email = ? AND device_fingerprint = ?`;

    mainPool.query(sql, [userEmail, deviceFingerprint], (err, results) => {
        if (err) {
            console.error('Error revoking device:', err);
            return res.status(500).json({ 
                success: false, 
                error: 'Failed to revoke device' 
            });
        }

        res.json({
            success: true,
            message: 'Device access revoked successfully'
        });
    });
});

// Enhanced session recovery endpoint
app.post('/api/recover-session', async (req, res) => {
    safeSessionTouch(req);
    try {
        const { email, dbName, accessToken } = req.body;
        
        console.log('🔄 Attempting session recovery for:', { email, dbName });
        
        if (!email || !dbName || !accessToken) {
            return res.status(400).json({ 
                success: false, 
                error: 'Missing email, dbName, or accessToken' 
            });
        }

        // Verify access token first
        try {
            const decoded = jwt.verify(accessToken, process.env.JWT_SECRET || 'your-secret-key');
            if (decoded.email !== email || decoded.dbName !== dbName) {
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

        // Verify user has access to this database
        const verifySql = `SELECT u.Access, u.Email, u.db_name FROM users u WHERE u.Email = ? AND u.db_name = ?`;
        
        mainPool.query(verifySql, [email, dbName], (err, results) => {
            if (err) {
                console.error('Error verifying user access:', err);
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
            
            // Get user info from company database
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

                const userInfo = {
                    email: email,
                    role: userDetails.Access,
                    name: companyResults[0].name,
                    lastName: companyResults[0].lastName,
                    dbName: dbName,
                };

                console.log('✅ Session recovery successful for user:', userInfo);

                // Assign user data to existing session
                req.session.user = userInfo;
                req.session.initialized = true;
                
                // iPad-specific session handling
                if (req.isIPad) {
                    req.session.ipadDevice = true;
                    console.log('📱 iPad session recovery - marking device');
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
                
                req.session.save((err) => {
                    if (err) {
                        console.error('Error saving recovered session:', err);
                        return res.status(500).json({ 
                            success: false, 
                            error: 'Failed to restore session' 
                        });
                    }

                    console.log('✅ Recovered session saved with ID:', req.sessionID);

                    res.json({ 
                        success: true, 
                        user: userInfo,
                        sessionId: req.sessionID 
                    });
                });
            });
        });
        
    } catch (error) {
        console.error('Session recovery error:', error);
        res.status(500).json({ 
            success: false, 
            error: error.message 
        });
    }
});

// ENHANCED: iOS session initialization with cookie guarantee
app.get('/api/init-session', (req, res) => {
  console.log('🔄 iOS Session Initialization Request');
  
  const isIOS = req.isIOS || req.isIPad;
  const sessionId = req.sessionID;
  
  console.log('📱 Device Info:', {
    isIOS: isIOS,
    isIPad: req.isIPad,
    sessionId: sessionId,
    hasCookies: !!req.headers.cookie,
    userAgent: req.headers['user-agent']
  });

  // Always initialize session for iOS
  if (!req.session.initialized) {
    req.session.initialized = true;
    req.session.deviceType = isIOS ? 'ios' : 'web';
    req.session.createdAt = new Date();
    console.log('✅ Session marked as initialized');
  }

  // CRITICAL: Set multiple cookie formats for iOS compatibility
  const cookieOptions = {
    maxAge: 24 * 60 * 60 * 1000,
    path: '/',
    domain: isProduction ? '.solura.uk' : undefined
  };

  // iOS-specific cookie settings
  if (isIOS) {
    cookieOptions.httpOnly = false;
    cookieOptions.secure = false;
    cookieOptions.sameSite = 'Lax';
  } else {
    cookieOptions.httpOnly = true;
    cookieOptions.secure = isProduction;
    cookieOptions.sameSite = isProduction ? 'none' : 'lax';
  }

  // Set the session cookie
  res.cookie('solura.session', sessionId, cookieOptions);
  
  // Also set a custom header for iOS to store manually
  res.setHeader('X-Session-ID', sessionId);
  res.setHeader('X-Session-Initialized', 'true');
  res.setHeader('X-Device-Type', isIOS ? 'ios' : 'web');

  console.log('✅ iOS Session Response Headers:', {
    sessionId: sessionId,
    hasSetCookie: true,
    deviceType: isIOS ? 'ios' : 'web'
  });

  res.json({
    success: true,
    sessionId: sessionId,
    message: 'Session initialized successfully',
    deviceType: isIOS ? 'ios' : 'web',
    requiresManualStorage: isIOS, // Tell iOS to store session manually
    timestamp: new Date().toISOString()
  });
});

// NEW: iOS Session Restoration via Headers
app.post('/api/ios-session-restore', (req, res) => {
  console.log('📱 iOS Session Restoration via Headers');
  
  const sessionId = req.headers['x-session-id'];
  const deviceFingerprint = req.headers['x-device-fingerprint'];
  
  if (!sessionId) {
    return res.status(400).json({
      success: false,
      error: 'Session ID required'
    });
  }

  console.log('🔄 Attempting to restore iOS session:', sessionId);

  // Load the session from store
  sessionStore.get(sessionId, (err, sessionData) => {
    if (err) {
      console.error('❌ Error loading session:', err);
      return res.status(500).json({
        success: false,
        error: 'Failed to load session'
      });
    }

    if (sessionData && sessionData.user) {
      console.log('✅ iOS session restored successfully:', {
        sessionId: sessionId,
        user: sessionData.user.email
      });

      // Assign session data to current request
      req.sessionID = sessionId;
      Object.assign(req.session, sessionData);
      
      // Mark as iOS device
      req.session.deviceType = 'ios';
      req.session.lastAccess = new Date();

      // Set cookie again for good measure
      res.cookie('solura.session', sessionId, {
        maxAge: 24 * 60 * 60 * 1000,
        httpOnly: false,
        secure: false,
        sameSite: 'Lax',
        path: '/',
        domain: isProduction ? '.solura.uk' : undefined
      });

      res.json({
        success: true,
        sessionId: sessionId,
        user: sessionData.user,
        message: 'Session restored successfully'
      });
    } else {
      console.log('❌ No valid session found for:', sessionId);
      res.status(404).json({
        success: false,
        error: 'Session not found or expired'
      });
    }
  });
});
// Add session headers to all API requests from iOS
app.use((req, res, next) => {
  // For iOS devices, also check for session ID in headers
  const sessionIdFromHeader = req.headers['x-session-id'];
  const sessionIdFromLocalStorage = req.headers['x-client-session-id'];
  
  if ((req.isIOS || req.isIPad) && (sessionIdFromHeader || sessionIdFromLocalStorage)) {
    const externalSessionId = sessionIdFromHeader || sessionIdFromLocalStorage;
    
    if (externalSessionId !== req.sessionID) {
      console.log('📱 iOS session header detected:', externalSessionId);
      
      // Try to load this session
      sessionStore.get(externalSessionId, (err, sessionData) => {
        if (!err && sessionData && sessionData.user) {
          console.log('✅ Restoring iOS session from header');
          req.sessionID = externalSessionId;
          Object.assign(req.session, sessionData);
        }
        next();
      });
    } else {
      next();
    }
  } else {
    next();
  }
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
                return next();
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

// --- (FULLY CORRECTED) LOGIN ENDPOINT ---
app.post('/submit', async (req, res) => {
    console.log('=== LOGIN ATTEMPT ===');
    console.log('Session ID at login start:', req.sessionID);
    console.log('Device Fingerprint:', req.headers['x-device-fingerprint']);
    console.log('Request Body:', req.body);

    const { email, password, dbName, forceLogout } = req.body;

    if (!email || !password) {
        return res.status(400).json({ success: false, message: 'Email and password are required' });
    }

    try {
        // --- (FIX) Smarter Active Session Check ---
        const [activeSessions] = await mainPool.promise().query("SELECT session_id, data FROM user_sessions");
        const userActiveSessions = activeSessions.filter(s => {
            try {
                const sessionData = JSON.parse(s.data);
                return sessionData && sessionData.user && sessionData.user.email === email;
            } catch (e) {
                return false;
            }
        });

        if (userActiveSessions.length > 0 && !forceLogout) {
            return res.status(409).json({
                success: false,
                message: 'already_logged_in',
                activeSessions: userActiveSessions.length
            });
        }
        
        if (forceLogout) {
            console.log(`Force logout for ${email}. Destroying ${userActiveSessions.length} sessions.`);
            for (const activeSession of userActiveSessions) {
                await new Promise(resolve => sessionStore.destroy(activeSession.session_id, () => resolve()));
            }
        }
        // --- END OF FIX ---

        // (The rest of your login logic continues from here...)
        const sql = `SELECT u.Access, u.Password, u.Email, u.db_name FROM users u WHERE u.Email = ?`;
        mainPool.query(sql, [email], async (err, results) => {
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
                    message: 'Incorrect email or password' 
                });
            }

            let matchingDatabases = [];
            for (const row of results) {
                const storedPassword = row.Password;
                try {
                    const isMatch = await bcrypt.compare(password, storedPassword);
                    if (isMatch) {
                        matchingDatabases.push({
                            db_name: row.db_name,
                            access: row.Access,
                        });
                    }
                } catch (err) {
                    console.error('Error comparing passwords:', err);
                    return res.status(500).json({ 
                        success: false,
                        error: 'Internal Server Error'
                    });
                }
            }

            if (matchingDatabases.length === 0) {
                return res.status(401).json({ 
                    success: false,
                    message: 'Incorrect email or password' 
                });
            }

            // Continue with database selection or login
            if (matchingDatabases.length > 1 && !dbName) {
                return res.status(200).json({
                    success: true,
                    message: 'Multiple databases found',
                    databases: matchingDatabases,
                });
            }

            const userDetails = dbName
                ? matchingDatabases.find((db) => db.db_name === dbName)
                : matchingDatabases[0];

            if (!userDetails) {
                return res.status(400).json({ 
                    success: false,
                    error: 'Invalid database selection' 
                });
            }

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
                    role: userDetails.access,
                    name: name,
                    lastName: lastName,
                    dbName: userDetails.db_name,
                };

                console.log('✅ Login successful, creating session for user:', userInfo);

                // CRITICAL: Ensure session object exists
                if (!req.session) {
                    console.error('❌ No session object available');
                    return res.status(500).json({ 
                        success: false,
                        error: 'Session object not available' 
                    });
                }

                const loginSessionId = req.sessionID;
                console.log('🔐 Using session ID for login:', loginSessionId);

                // Set session data
                req.session.user = userInfo;
                req.session.initialized = true;
                
                // iPad-specific session handling
                if (req.isIPad) {
                    req.session.ipadDevice = true;
                    console.log('📱 iPad login - marking device');
                }

                console.log('💾 Session data set for session:', loginSessionId);

                if (enableBiometric && deviceFingerprint) {
                    // (Device registration logic remains the same)
                }

                // Save session and then respond
                req.session.save((err) => {
                    if (err) {
                        console.error('Error saving session:', err);
                        return res.status(500).json({ 
                            success: false,
                            error: 'Failed to create session'
                        });
                    }

                    console.log('✅ Session saved successfully. Session ID:', loginSessionId);
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

// Enhanced login endpoint with device fingerprint support
app.post('/submit', async (req, res) => {
    console.log('=== LOGIN ATTEMPT ===');
    console.log('Session ID at login start:', req.sessionID);
    console.log('Session object exists:', !!req.session);
    console.log('Device Fingerprint:', req.headers['x-device-fingerprint']);
    console.log('Request Body:', {
        email: req.body.email,
        hasPassword: !!req.body.password,
        dbName: req.body.dbName,
        forceLogout: req.body.forceLogout,
        enableBiometric: req.body.enableBiometric,
        deviceFingerprint: req.body.deviceFingerprint
    });

    const { email, password, dbName, forceLogout, enableBiometric, deviceFingerprint } = req.body;

    if (!email || !password) {
        return res.status(400).json({ 
            success: false,
            message: 'Email and password are required' 
        });
    }

    try {
        // --- (FIX) Smarter Active Session Check ---
        // This query now correctly checks for sessions that are actually authenticated with the user's email.
        const [activeSessions] = await mainPool.promise().query("SELECT session_id, data FROM user_sessions");
        const userActiveSessions = activeSessions.filter(s => {
            try {
                const sessionData = JSON.parse(s.data);
                // Check if the session has a user object and if the email matches.
                return sessionData && sessionData.user && sessionData.user.email === email;
            } catch (e) {
                return false;
            }
        });

        if (userActiveSessions.length > 0 && !forceLogout) {
            return res.status(409).json({
                success: false,
                message: 'already_logged_in',
                activeSessions: userActiveSessions.length
            });
        }
        
        // If forceLogout is true, destroy all of that user's other sessions.
        if (forceLogout) {
            console.log(`Force logout requested for ${email}. Destroying ${userActiveSessions.length} sessions.`);
            for (const activeSession of userActiveSessions) {
                await new Promise((resolve, reject) => {
                    sessionStore.destroy(activeSession.session_id, (err) => {
                        if (err) {
                            console.error(`Error destroying session ${activeSession.session_id}:`, err);
                            // Don't block login if one fails to destroy, just log it.
                        }
                        resolve();
                    });
                });
            }
        }
        // --- END OF FIX ---


        // First verify the user credentials
        const sql = `SELECT u.Access, u.Password, u.Email, u.db_name FROM users u WHERE u.Email = ?`;
        
        mainPool.query(sql, [email], async (err, results) => {
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
                    message: 'Incorrect email or password' 
                });
            }

            let matchingDatabases = [];
            for (const row of results) {
                const storedPassword = row.Password;
                try {
                    const isMatch = await bcrypt.compare(password, storedPassword);
                    if (isMatch) {
                        matchingDatabases.push({
                            db_name: row.db_name,
                            access: row.Access,
                        });
                    }
                } catch (err) {
                    console.error('Error comparing passwords:', err);
                    return res.status(500).json({ 
                        success: false,
                        error: 'Internal Server Error'
                    });
                }
            }

            if (matchingDatabases.length === 0) {
                return res.status(401).json({ 
                    success: false,
                    message: 'Incorrect email or password' 
                });
            }

            // Continue with database selection or login
            if (matchingDatabases.length > 1 && !dbName) {
                return res.status(200).json({
                    success: true,
                    message: 'Multiple databases found',
                    databases: matchingDatabases,
                });
            }

            const userDetails = dbName
                ? matchingDatabases.find((db) => db.db_name === dbName)
                : matchingDatabases[0];

            if (!userDetails) {
                return res.status(400).json({ 
                    success: false,
                    error: 'Invalid database selection' 
                });
            }

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
                    role: userDetails.access,
                    name: name,
                    lastName: lastName,
                    dbName: userDetails.db_name,
                };

                console.log('✅ Login successful, creating session for user:', userInfo);

                // CRITICAL: Ensure session object exists
                if (!req.session) {
                    console.error('❌ No session object available');
                    return res.status(500).json({ 
                        success: false,
                        error: 'Session object not available' 
                    });
                }

                const loginSessionId = req.sessionID;
                console.log('🔐 Using session ID for login:', loginSessionId);

                // Set session data
                req.session.user = userInfo;
                req.session.initialized = true;
                
                // iPad-specific session handling
                if (req.isIPad) {
                    req.session.ipadDevice = true;
                    console.log('📱 iPad login - marking device');
                }

                console.log('💾 Session data set for session:', loginSessionId);

                if (enableBiometric && deviceFingerprint) {
                    // (Device registration logic remains the same)
                }

                // Save session and then respond
                req.session.save((err) => {
                    if (err) {
                        console.error('Error saving session:', err);
                        return res.status(500).json({ 
                            success: false,
                            error: 'Failed to create session'
                        });
                    }

                    console.log('✅ Session saved successfully. Session ID:', loginSessionId);

                    // Track this session
                    if (!activeSessions.has(email)) {
                        activeSessions.set(email, new Set());
                    }
                    activeSessions.get(email).add(loginSessionId);
                    console.log(`✅ Login session tracked for ${email}: ${loginSessionId}`);

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

                    // PROPER DEVICE DETECTION FOR REDIRECT
                    const useMobileApp = isMobileDevice(req);
                    let redirectUrl = '';

                    if (userDetails.access === 'admin' || userDetails.access === 'AM') {
                        redirectUrl = useMobileApp ? '/AdminApp.html' : '/Admin.html';
                    } else if (userDetails.access === 'user') {
                        redirectUrl = useMobileApp ? '/UserApp.html' : '/User.html';
                    } else if (userDetails.access === 'supervisor') {
                        redirectUrl = useMobileApp ? '/SupervisorApp.html' : '/Supervisor.html';
                    }

                    console.log(`🔄 Redirecting to: ${redirectUrl} (Mobile: ${useMobileApp})`);

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

                    res.cookie('solura.session', loginSessionId, cookieOptions);

                    // For mobile devices, include session ID in headers
                    if (useMobileApp) {
                        res.setHeader('X-Session-ID', loginSessionId);
                    }

                    res.json({
                        success: true,
                        message: 'Login successful',
                        redirectUrl: redirectUrl,
                        user: userInfo,
                        accessToken: authToken,
                        refreshToken: refreshToken,
                        sessionId: loginSessionId,
                        isMobile: useMobileApp,
                        isIPad: req.isIPad
                    });
                });
            });
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ 
            success: false,
            error: 'Internal server error'
        });
    }
});

// Comprehensive device logging function
function logDeviceDetails(deviceFingerprint, deviceInfo, action) {
    const logEntry = {
        timestamp: new Date().toISOString(),
        action: action,
        deviceFingerprint: deviceFingerprint,
        deviceInfo: deviceInfo,
        url: window.location.href,
        userAgent: navigator.userAgent
    };
    
    console.log('📱 DEVICE LOG:', logEntry);
    
    // Send to server for storage (optional)
    fetch('/api/log-device-activity', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify(logEntry)
    }).catch(err => console.log('Failed to send device log:', err));
}

// Protected routes - PROPER DEVICE DETECTION
app.get('/Admin.html', isAuthenticated, isAdmin, (req, res) => {
    // iPad-specific session maintenance
    if (req.isIPad && req.session) {
        safeSessionTouch(req);
    }
    res.sendFile(path.join(__dirname, 'Admin.html'));
});

app.get('/AdminApp.html', isAuthenticated, isAdmin, (req, res) => {
    // iPad-specific session maintenance
    if (req.isIPad && req.session) {
        safeSessionTouch(req);
    }
    res.sendFile(path.join(__dirname, 'AdminApp.html'));
});

app.get('/User.html', isAuthenticated, isUser, (req, res) => {
    // iPad-specific session maintenance
    if (req.isIPad && req.session) {
        safeSessionTouch(req);
    }
    res.sendFile(path.join(__dirname, 'User.html'));
});

app.get('/UserApp.html', isAuthenticated, isUser, (req, res) => {
    // iPad-specific session maintenance
    if (req.isIPad && req.session) {
        safeSessionTouch(req);
    }
    res.sendFile(path.join(__dirname, 'UserApp.html'));
});

app.get('/Supervisor.html', isAuthenticated, isSupervisor, (req, res) => {
    // iPad-specific session maintenance
    if (req.isIPad && req.session) {
        safeSessionTouch(req);
    }
    res.sendFile(path.join(__dirname, 'Supervisor.html'));
});

app.get('/SupervisorApp.html', isAuthenticated, isSupervisor, (req, res) => {
    // iPad-specific session maintenance
    if (req.isIPad && req.session) {
        safeSessionTouch(req);
    }
    res.sendFile(path.join(__dirname, 'SupervisorApp.html'));
});

// Endpoint to get employees on shift today
app.get('/api/employees-on-shift', isAuthenticated, (req, res) => {
    safeSessionTouch(req);
    const dbName = req.session.user.dbName;
    if (!dbName) return res.status(401).json({ success: false, message: 'User not authenticated' });

    const pool = getPool(dbName);
    const today = new Date();
    const dayName = today.toLocaleDateString('en-US', { weekday: 'long' });
    const formattedDate = `${String(today.getDate()).padStart(2, '0')}/${String(today.getMonth() + 1).padStart(2, '0')}/${today.getFullYear()} (${dayName})`;
    
    pool.query(
        `SELECT name, lastName, startTime, endTime, designation 
         FROM rota 
         WHERE day = ?
         ORDER BY designation DESC, lastName, name, startTime`,
        [formattedDate],
        (error, results) => {
            if (error) {
                console.error('Database error:', error);
                return res.status(500).json({ success: false, error: 'Database error' });
            }

            const employeeMap = new Map();
            const now = new Date();
            const currentTime = now.getHours() * 60 + now.getMinutes();
            
            results.forEach(row => {
                const key = `${row.name} ${row.lastName}`;
                if (!employeeMap.has(key)) {
                    employeeMap.set(key, {
                        name: row.name,
                        lastName: row.lastName,
                        designation: row.designation,
                        timeFrames: []
                    });
                }
                
                const [startH, startM] = row.startTime.split(':').map(Number);
                const [endH, endM] = row.endTime.split(':').map(Number);
                const startMinutes = startH * 60 + startM;
                const endMinutes = endH * 60 + endM;
                
                employeeMap.get(key).timeFrames.push({
                    start: row.startTime,
                    end: row.endTime,
                    startMinutes,
                    endMinutes
                });
            });

            const employees = Array.from(employeeMap.values()).map(emp => {
                emp.timeFrames.sort((a, b) => a.startMinutes - b.startMinutes);
                
                let currentStatus = 'Not started';
                let nextEvent = '';
                let activeFrame = null;
                
                for (const frame of emp.timeFrames) {
                    if (currentTime < frame.startMinutes) {
                        const minsLeft = frame.startMinutes - currentTime;
                        const hoursLeft = Math.floor(minsLeft / 60);
                        const remainingMins = minsLeft % 60;
                        nextEvent = `Starts in ${hoursLeft}h ${remainingMins}m`;
                        break;
                    } else if (currentTime <= frame.endMinutes) {
                        currentStatus = 'Working now';
                        const minsLeft = frame.endMinutes - currentTime;
                        const hoursLeft = Math.floor(minsLeft / 60);
                        const remainingMins = minsLeft % 60;
                        nextEvent = `Ends in ${hoursLeft}h ${remainingMins}m`;
                        activeFrame = frame;
                        break;
                    }
                }
                
                if (!nextEvent && emp.timeFrames.length > 0) {
                    const lastFrame = emp.timeFrames[emp.timeFrames.length - 1];
                    const minsAgo = currentTime - lastFrame.endMinutes;
                    if (minsAgo > 0) {
                        const hoursAgo = Math.floor(minsAgo / 60);
                        const remainingMins = minsAgo % 60;
                        nextEvent = `Ended ${hoursAgo}h ${remainingMins}m ago`;
                        currentStatus = 'Shift ended';
                    }
                }

                return {
                    employeeName: `${emp.name} ${emp.lastName}`,
                    designation: emp.designation,
                    timeFrames: emp.timeFrames.map(f => ({ start: f.start, end: f.end })),
                    status: currentStatus,
                    nextEvent,
                    currentFrame: activeFrame ? {
                        endMinutes: activeFrame.endMinutes,
                        currentTime: currentTime
                    } : null
                };
            });

            res.json({
                success: true,
                count: employeeMap.size,
                employees,
                serverTime: currentTime 
            });
        }
    );
});

// Helper function to get current Monday's date
function getCurrentMonday() {
    const today = new Date();
    const day = today.getDay();
    const diff = today.getDate() - day + (day === 0 ? -6 : 1);
    const monday = new Date(today.setDate(diff));
    return monday.toISOString().split('T')[0];
}

// Function to get labor cost
app.get('/api/labor-cost', isAuthenticated, (req, res) => {
    safeSessionTouch(req);
    const dbName = req.session.user.dbName;
    if (!dbName) {
        return res.status(401).json({ success: false, message: 'User not authenticated' });
    }

    const pool = getPool(dbName);
    const mondayDate = getCurrentMonday();
    
    pool.query(
        `SELECT Weekly_Cost_Before FROM Data WHERE WeekStart = ?`,
        [mondayDate],
        (error, results) => {
            if (error) {
                console.error('Database error:', error);
                return res.status(500).json({ success: false, error: 'Database error' });
            }
            
            if (results.length === 0) {
                return res.status(404).json({
                    success: false,
                    message: 'No data found for current week',
                    week_start_date: mondayDate
                });
            }
            
            res.json({
                success: true,
                cost: results[0].Weekly_Cost_Before,
                week_start_date: mondayDate
            });
        }
    );
});

// API routes
app.get('/api/pending-approvals', isAuthenticated, async (req, res) => {
    safeSessionTouch(req);
    const dbName = req.session.user.dbName;
    if (!dbName) {
        return res.status(401).json({ success: false, message: 'User not authenticated' });
    }

    const pool = getPool(dbName);
    const today = new Date();
    const currentMonth = today.getMonth() + 1;
    const currentYear = today.getFullYear();

    try {
        const yesterday = new Date(today);
        yesterday.setDate(today.getDate() - 1);
        const daysToCheck = yesterday.getDate();

        let missingDaysCount = 0;

        for (let day = 1; day <= daysToCheck; day++) {
            const date = new Date(currentYear, currentMonth - 1, day);
            const dayName = date.toLocaleDateString('en-US', { weekday: 'long' });
            const formattedDay = `${String(day).padStart(2, '0')}/${String(currentMonth).padStart(2, '0')}/${currentYear} (${dayName})`;

            const dayExists = await new Promise((resolve, reject) => {
                pool.query(
                    `SELECT 1 FROM ConfirmedRota WHERE day = ? LIMIT 1`,
                    [formattedDay],
                    (error, results) => {
                        if (error) return reject(error);
                        resolve(results.length > 0);
                    }
                );
            });

            if (!dayExists) {
                missingDaysCount++;
            }
        }

        res.json({
            success: true,
            count: missingDaysCount,
            checkedDays: daysToCheck
        });

    } catch (error) {
        console.error('Error:', error);
        res.status(500).json({ success: false, error: 'Server error' });
    }
});

app.get('/api/tip-approvals', isAuthenticated, async (req, res) => {
    safeSessionTouch(req);
    const dbName = req.session.user.dbName;
    if (!dbName) {
        return res.status(401).json({ success: false, message: 'User not authenticated' });
    }

    const pool = getPool(dbName);
    const today = new Date();
    const currentMonth = today.getMonth() + 1;
    const currentYear = today.getFullYear();

    try {
        const yesterday = new Date(today);
        yesterday.setDate(today.getDate() - 1);
        const daysToCheck = yesterday.getDate();

        let missingDaysCount = 0;

        for (let day = 1; day <= daysToCheck; day++) {
            const date = new Date(currentYear, currentMonth - 1, day);
            const formattedDay = `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, '0')}-${String(date.getDate()).padStart(2, '0')}`;

            const dayExists = await new Promise((resolve, reject) => {
                pool.query(
                    `SELECT 1 FROM tip WHERE day = ? LIMIT 1`,
                    [formattedDay],
                    (error, results) => {
                        if (error) return reject(error);
                        resolve(results.length > 0);
                    }
                );
            });

            if (!dayExists) {
                missingDaysCount++;
            }
        }

        res.json({
            success: true,
            count: missingDaysCount,
            checkedDays: daysToCheck
        });

    } catch (error) {
        console.error('Error:', error);
        res.status(500).json({ success: false, error: 'Server error' });
    }
});

// NEW: Mobile session initialization endpoint
app.get('/api/mobile-init', (req, res) => {
    const isIOS = req.isIOS || req.isIPad;
    const sessionId = req.sessionID;
    
    console.log('📱 Mobile Init Request:', {
        sessionId: sessionId,
        isIOS: isIOS,
        hasCookies: !!req.headers.cookie,
        userAgent: req.headers['user-agent']
    });

    // Initialize session for mobile devices
    if (!req.session.initialized) {
        req.session.initialized = true;
        req.session.deviceType = isIOS ? 'ios' : 'mobile';
        req.session.createdAt = new Date();
        console.log('✅ Mobile session initialized');
    }

    // iOS-specific cookie settings
    const cookieOptions = {
        maxAge: 24 * 60 * 60 * 1000,
        path: '/',
        domain: isProduction ? '.solura.uk' : undefined,
        httpOnly: false,
        secure: false,
        sameSite: 'Lax'
    };

    // Set session cookie
    res.cookie('solura.session', sessionId, cookieOptions);
    
    // Additional headers for mobile
    res.setHeader('X-Session-ID', sessionId);
    res.setHeader('X-Session-Initialized', 'true');
    res.setHeader('X-Device-Type', isIOS ? 'ios' : 'mobile');

    res.json({
        success: true,
        sessionId: sessionId,
        message: 'Mobile session initialized',
        deviceType: isIOS ? 'ios' : 'mobile',
        requiresManualStorage: isIOS
    });
});

// Enhanced logout route
app.get('/logout', (req, res) => {
    if (req.session) {
        const sessionId = req.sessionID;
        const userEmail = req.session.user?.email;
        
        req.session.destroy(err => {
            if (err) {
                console.error('Failed to destroy session:', err);
            }
            
            if (userEmail && activeSessions.has(userEmail)) {
                activeSessions.get(userEmail).delete(sessionId);
                if (activeSessions.get(userEmail).size === 0) {
                    activeSessions.delete(userEmail);
                }
            }
            
            // Clear the cookie
            res.clearCookie('solura.session', {
                path: '/',
                httpOnly: true,
                secure: isProduction,
                sameSite: 'none',
                domain: isProduction ? '.solura.uk' : undefined
            });

            
            console.log('✅ Logout successful for session:', sessionId);
            res.redirect('/');
        });
    } else {
        res.redirect('/');
    }
});

// Catch-all handler
app.get('*', (req, res) => {
    const requestedPath = path.join(__dirname, req.path);
    
    if (fs.existsSync(requestedPath) && fs.statSync(requestedPath).isFile()) {
        // Set session cookie for all devices on static files
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
        res.sendFile(requestedPath);
    } else if (req.path.startsWith('/api/')) {
        res.status(404).json({ error: 'API endpoint not found' });
    } else {
        res.redirect('/');
    }
});

// Session store event handlers
sessionStore.on('connected', () => {
    console.log('✅ Session store connected to database');
});

sessionStore.on('error', (error) => {
    console.error('❌ Session store error:', error);
});

app.listen(port, () => {
    console.log(`Server listening at http://localhost:${port}`);
    console.log(`Environment: ${isProduction ? 'production' : 'development'}`);
    const databaseNames = ['bbuonaoxford', '100%pastaoxford'];
    scheduleTestUpdates(databaseNames);
});