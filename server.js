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

// Enhanced device detection helper - UNIVERSAL
function isMobileDevice(req) {
    const userAgent = req.headers['user-agent'] || '';
    
    // iOS detection
    const isIOS = /iPhone|iPad|iPod/i.test(userAgent);
    
    // Android detection
    const isAndroid = /Android/i.test(userAgent);
    
    // Mobile app detection
    const isMobileApp = req.headers['x-capacitor'] === 'true' || 
                       req.query.capacitor === 'true' ||
                       req.headers.origin?.startsWith('capacitor://') ||
                       req.headers.origin?.startsWith('ionic://');

    // Enhanced iPad detection - FIXED for all iPad variants
    const isIPad = /iPad/.test(userAgent) || 
                  (/Macintosh/.test(userAgent) && /AppleWebKit/.test(userAgent) && !/Safari/.test(userAgent)) ||
                  (/\b(iPad)\b/.test(userAgent) && /AppleWebKit/.test(userAgent));

    // Mobile browser detection
    const isMobileBrowser = /Mobile|Android|webOS|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i.test(userAgent);

    return isIOS || isIPad || isAndroid || isMobileApp || isMobileBrowser;
}

// Enhanced iPad detection - FIXED
function isIPadDevice(req) {
    const userAgent = req.headers['user-agent'] || '';
    
    // Comprehensive iPad detection
    return /iPad/.test(userAgent) || 
           (/Macintosh/.test(userAgent) && /AppleWebKit/.test(userAgent) && !/Safari/.test(userAgent)) ||
           (/\b(iPad)\b/.test(userAgent) && /AppleWebKit/.test(userAgent)) ||
           (userAgent.includes('Macintosh') && userAgent.includes('AppleWebKit') && !userAgent.includes('Safari') && 'ontouchend' in document);
}

// Enhanced Android detection
function isAndroidDevice(req) {
    const userAgent = req.headers['user-agent'] || '';
    return /Android/i.test(userAgent) && !/Windows Phone/i.test(userAgent);
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

// MySQL session store with FIXED configuration
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
    checkExpirationInterval: 900000, // 15 minutes
    expiration: 86400000, // 24 hours
    clearExpired: true,
    endConnectionOnClose: false,
    charset: 'utf8mb4_bin'
}, mainPool);

// UNIVERSAL CORS for all devices - FIXED
const corsOptions = {
    origin: function (origin, callback) {
        // Allow all origins for mobile apps and local development
        if (!origin || 
            origin.startsWith('capacitor://') || 
            origin.startsWith('ionic://') || 
            origin.startsWith('file://') ||
            origin.includes('localhost') ||
            origin.includes('solura.uk')) {
            return callback(null, true);
        }
        
        const allowedOrigins = [
            'https://www.solura.uk', 
            'https://solura.uk', 
            'http://localhost:8080',
            'http://localhost:3000',
            'http://localhost:4200',
            'capacitor://localhost',
            'ionic://localhost',
            'http://localhost',
            'https://localhost'
        ];
        
        if (allowedOrigins.indexOf(origin) !== -1) {
            callback(null, true);
        } else {
            console.log('Blocked by CORS:', origin);
            callback(new Error('Not allowed by CORS'));
        }
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'],
    allowedHeaders: [
        'Content-Type', 
        'Authorization', 
        'X-Requested-With', 
        'Cookie', 
        'Accept', 
        'X-Session-ID', 
        'X-Capacitor', 
        'Origin', 
        'X-Requested-With',
        'X-Device-Type',
        'User-Agent'
    ],
    exposedHeaders: ['Set-Cookie', 'X-Session-ID', 'Authorization', 'X-Device-Info']
};

app.use(cors(corsOptions));

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

// Manual CORS headers for all responses - FIXED for Android/iPad
app.use((req, res, next) => {
    const origin = req.headers.origin;
    const userAgent = req.headers['user-agent'] || '';
    
    // Always set CORS headers for mobile devices
    if (isMobileDevice(req) || !origin || 
        origin.startsWith('capacitor://') || 
        origin.startsWith('ionic://') || 
        origin.startsWith('file://')) {
        res.header('Access-Control-Allow-Origin', origin || '*');
    } else {
        res.header('Access-Control-Allow-Origin', origin);
    }
    
    res.header('Access-Control-Allow-Credentials', 'true');
    res.header('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS,PATCH');
    res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization, Content-Length, X-Requested-With, Cookie, X-Session-ID, X-Capacitor, Origin, X-Device-Type, User-Agent');
    res.header('Access-Control-Expose-Headers', 'Set-Cookie, X-Session-ID, Authorization, X-Device-Info');
    
    // Add device info headers
    res.header('X-Device-Info', JSON.stringify({
        isMobile: isMobileDevice(req),
        isIPad: isIPadDevice(req),
        isAndroid: isAndroidDevice(req),
        isIOS: /iPhone|iPad|iPod/i.test(userAgent),
        userAgent: userAgent
    }));
    
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

// Enhanced device detection middleware - FIXED
app.use((req, res, next) => {
    const userAgent = req.headers['user-agent'] || '';
    
    req.isMobileDevice = isMobileDevice(req);
    req.isIOS = /iPhone|iPad|iPod/i.test(userAgent);
    req.isIPad = isIPadDevice(req);
    req.isAndroid = isAndroidDevice(req);
    
    // Enhanced logging for device detection
    if (req.isIPad) {
        console.log('📱 iPad Device Detected - User Agent:', userAgent);
    } else if (req.isIOS) {
        console.log('📱 iOS Device Detected');
    } else if (req.isAndroid) {
        console.log('📱 Android Device Detected');
    } else if (req.isMobileDevice) {
        console.log('📱 Mobile Device Detected');
    } else {
        console.log('💻 Desktop Device Detected');
    }
    
    next();
});

// CRITICAL FIX: Enhanced session configuration with proper store handling
app.use(session({
    secret: SESSION_SECRET,
    resave: false, // Changed to false to prevent race conditions
    saveUninitialized: false, // Changed to false - only save when we have data
    store: sessionStore,
    name: 'solura.session',
    cookie: {
        secure: false, // Set to true in production with HTTPS
        httpOnly: false, // Allow JavaScript access for mobile apps
        sameSite: 'lax', // Changed from 'none' to 'lax' for better compatibility
        maxAge: 24 * 60 * 60 * 1000, // 24 hours
        path: '/',
        domain: isProduction ? '.solura.uk' : undefined // Leading dot for subdomain compatibility
    },
    rolling: true,
    proxy: false,
    genid: function(req) {
        return require('crypto').randomBytes(16).toString('hex');
    }
}));

// CRITICAL FIX: Enhanced session persistence middleware with proper error handling
app.use((req, res, next) => {
    // Store original session save method
    const originalSave = req.session.save;
    
    // Enhanced session save with proper error handling and validation
    req.session.save = function(callback) {
        console.log('💾 Attempting to save session:', req.sessionID);
        console.log('💾 Session data to save:', {
            user: req.session.user,
            initialized: req.session.initialized,
            deviceType: req.session.deviceType
        });
        
        // Validate session data before saving
        if (!req.sessionID) {
            console.error('❌ Cannot save session: No session ID');
            if (callback) return callback(new Error('No session ID'));
            return;
        }
        
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

// CRITICAL FIX: Enhanced session initialization for ALL devices
app.use((req, res, next) => {
    // Initialize session with basic data if not already initialized
    if (req.session && !req.session.initialized) {
        req.session.initialized = true;
        req.session.deviceType = req.isIPad ? 'ipad' : req.isAndroid ? 'android' : req.isIOS ? 'ios' : 'desktop';
        req.session.createdAt = new Date();
    }
    
    next();
});

// UNIVERSAL session handling for all mobile devices - FIXED
app.use((req, res, next) => {
    if (req.isMobileDevice || req.isIPad || req.isAndroid) {
        console.log('🔧 UNIVERSAL Mobile Session Handling');
        
        // Parse cookies manually
        const cookies = parseCookies(req.headers.cookie);
        const sessionCookie = cookies['solura.session'];
        
        console.log('📱 MOBILE Session Check:', {
            device: req.isIPad ? 'iPad' : req.isAndroid ? 'Android' : req.isIOS ? 'iOS' : 'Mobile',
            hasCookieHeader: !!req.headers.cookie,
            sessionCookie: sessionCookie,
            currentSessionId: req.sessionID,
            sessionMatch: sessionCookie === req.sessionID,
            hasUser: !!req.session?.user
        });
        
        // CRITICAL: Always set session cookie for mobile devices on every request
        if (req.sessionID) {
            res.cookie('solura.session', req.sessionID, {
                maxAge: 24 * 60 * 60 * 1000,
                httpOnly: false,
                secure: false,
                sameSite: 'lax',
                path: '/',
                domain: isProduction ? '.solura.uk' : undefined
            });
            
            // Additional headers for mobile devices
            res.setHeader('X-Session-ID', req.sessionID);
            res.setHeader('X-Session-Confirmed', 'true');
        }
        
        // Session recovery for mobile devices - FIXED with proper async handling
        if (sessionCookie && sessionCookie !== req.sessionID) {
            console.log('🔄 Mobile Session Restoration Needed');
            
            const originalSessionId = req.sessionID;
            
            // Load the session data from store with timeout
            const loadSession = () => {
                return new Promise((resolve) => {
                    req.sessionStore.get(sessionCookie, (err, sessionData) => {
                        if (err) {
                            console.error('❌ Mobile session recovery error:', err);
                            resolve(null);
                            return;
                        }
                        
                        if (sessionData && sessionData.user) {
                            console.log('✅ Mobile session data found, restoring...');
                            resolve(sessionData);
                        } else {
                            console.log('❌ No valid session data found for cookie:', sessionCookie);
                            resolve(null);
                        }
                    });
                });
            };
            
            // Execute session recovery
            loadSession().then((sessionData) => {
                if (sessionData) {
                    // Destroy the temporary session and use the cookie session
                    req.sessionStore.destroy(originalSessionId, (destroyErr) => {
                        if (destroyErr) {
                            console.error('Error destroying temporary session:', destroyErr);
                        }
                        
                        // Set the session ID to match the cookie
                        req.sessionID = sessionCookie;
                        Object.assign(req.session, sessionData);
                        
                        console.log('✅ Mobile session fully restored:', {
                            from: originalSessionId,
                            to: sessionCookie,
                            user: sessionData.user.email
                        });
                        
                        // Force immediate save
                        req.session.save((saveErr) => {
                            if (saveErr) {
                                console.error('❌ Mobile session save error after restoration:', saveErr);
                            } else {
                                console.log('✅ Mobile session persisted after restoration');
                            }
                            next();
                        });
                    });
                } else {
                    next();
                }
            });
        } else {
            next();
        }
    } else {
        next();
    }
});

// CRITICAL FIX: Always set session cookie for mobile devices on every response
app.use((req, res, next) => {
    if (req.sessionID && (req.isMobileDevice || req.isIPad || req.isAndroid)) {
        res.cookie('solura.session', req.sessionID, {
            maxAge: 24 * 60 * 60 * 1000,
            httpOnly: false,
            secure: false,
            sameSite: 'lax',
            path: '/',
            domain: isProduction ? '.solura.uk' : undefined
        });
        
        // Also set in headers for extra insurance
        res.setHeader('X-Session-ID', req.sessionID);
        res.setHeader('X-Device-Type', req.isIPad ? 'ipad' : req.isAndroid ? 'android' : req.isIOS ? 'ios' : 'mobile');
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
    console.log('Cookies:', parseCookies(req.headers.cookie));
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
            sameSite: 'lax',
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
            // Ensure consistent cookie settings for all devices
            options = {
                maxAge: 24 * 60 * 60 * 1000,
                httpOnly: false,
                secure: false,
                sameSite: 'lax',
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
            sameSite: 'lax',
            path: '/',
            domain: isProduction ? '.solura.uk' : undefined
        });
    }
    
    next();
});

// FIXED: Session recovery with proper session recreation for ALL devices
app.use((req, res, next) => {
    // Manual cookie parsing
    const cookieHeader = req.headers.cookie;
    const cookies = parseCookies(cookieHeader);
    const sessionCookie = cookies['solura.session'];
    const headerSessionId = req.headers['x-session-id'];
    const querySessionId = req.query.sessionId;
    
    console.log('🔄 UNIVERSAL Session Recovery Check:', {
        device: req.isIPad ? 'iPad' : req.isAndroid ? 'Android' : req.isIOS ? 'iOS' : 'Desktop',
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
                    sameSite: 'lax',
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
    console.log('Device Detection:', {
        isMobile: req.isMobileDevice,
        isIPad: req.isIPad,
        isAndroid: req.isAndroid,
        isIOS: req.isIOS
    });

    // Use the enhanced device detection
    const useMobileApp = isMobileDevice(req);

    console.log('Mobile app detected:', useMobileApp);

    // Set session cookie for all devices
    if (req.sessionID) {
        res.cookie('solura.session', req.sessionID, {
            maxAge: 24 * 60 * 60 * 1000,
            httpOnly: false,
            secure: false,
            sameSite: 'lax',
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
            sameSite: 'lax',
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

// CRITICAL FIX: Enhanced mobile device session initialization endpoint
app.get('/api/mobile-init', (req, res) => {
    const deviceType = req.isIPad ? 'iPad' : req.isAndroid ? 'Android' : req.isIOS ? 'iOS' : 'Mobile';
    console.log(`📱 ${deviceType} Session Initialization Request`);
    
    // Ensure session is created and properly initialized
    if (!req.session.initialized) {
        req.session.initialized = true;
        req.session.deviceType = deviceType.toLowerCase();
        req.session.userAgent = req.headers['user-agent'];
        req.session.createdAt = new Date();
    }
    
    // CRITICAL: Manually set the session cookie with mobile-specific settings
    res.cookie('solura.session', req.sessionID, {
        maxAge: 24 * 60 * 60 * 1000,
        httpOnly: false,
        secure: false,
        sameSite: 'lax',
        path: '/',
        domain: isProduction ? '.solura.uk' : undefined
    });
    
    // Additional headers for mobile devices
    res.setHeader('X-Session-ID', req.sessionID);
    res.setHeader('X-Session-Confirmed', 'true');
    res.setHeader('X-Device-Type', req.session.deviceType);
    
    req.session.save((err) => {
        if (err) {
            console.error('❌ Error saving mobile init session:', err);
            return res.status(500).json({ 
                success: false, 
                error: 'Session initialization failed' 
            });
        }
        
        console.log(`✅ ${deviceType} session initialized with ID:`, req.sessionID);
        
        res.json({
            success: true,
            sessionId: req.sessionID,
            message: `${deviceType} session initialized`,
            cookiesSupported: true,
            deviceType: req.session.deviceType,
            userAgent: req.session.userAgent
        });
    });
});

// Device debug endpoint
app.get('/api/device-debug', (req, res) => {
    const cookies = parseCookies(req.headers.cookie);
    
    res.json({
        success: true,
        platform: req.isIPad ? 'ipad' : req.isAndroid ? 'android' : req.isIOS ? 'ios' : req.isMobileDevice ? 'mobile' : 'desktop',
        session: {
            id: req.sessionID,
            exists: !!req.session,
            user: req.session?.user,
            initialized: req.session?.initialized,
            cookieMatch: cookies['solura.session'] === req.sessionID
        },
        cookies: cookies,
        headers: {
            'user-agent': req.headers['user-agent'],
            cookie: req.headers.cookie,
            origin: req.headers.origin
        },
        timestamp: new Date().toISOString()
    });
});

// Health check with session info
app.get('/health', (req, res) => {
    const cookies = parseCookies(req.headers.cookie);
    
    res.json({
        status: 'OK',
        session: {
            id: req.sessionID,
            exists: !!req.session,
            user: req.session?.user,
            initialized: req.session?.initialized,
            cookieMatch: cookies['solura.session'] === req.sessionID
        },
        device: {
            isMobile: req.isMobileDevice,
            isIPad: req.isIPad,
            isAndroid: req.isAndroid,
            isIOS: req.isIOS
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

                    // CRITICAL: Set enhanced cookies for mobile devices
                    res.cookie('solura.session', req.sessionID, {
                        maxAge: 24 * 60 * 60 * 1000,
                        httpOnly: false,
                        secure: false,
                        sameSite: 'lax',
                        path: '/',
                        domain: isProduction ? '.solura.uk' : undefined
                    });

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
    const cookies = parseCookies(req.headers.cookie);
    const sessionCookie = cookies['solura.session'];
    const headerSessionId = req.headers['x-session-id'];
    
    res.json({
        session: {
            id: req.sessionID,
            exists: !!req.session,
            user: req.session?.user,
            cookie: sessionCookie,
            header: headerSessionId,
            cookieMatch: sessionCookie === req.sessionID
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
        
        // CRITICAL: Always set cookie on validation for mobile devices
        res.cookie('solura.session', req.sessionID, {
            maxAge: 24 * 60 * 60 * 1000,
            httpOnly: false,
            secure: false,
            sameSite: 'lax',
            path: '/',
            domain: isProduction ? '.solura.uk' : undefined
        });
        
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

// ENHANCED: Mobile session restoration with proper session handling
app.post('/api/mobile-restore-session', async (req, res) => {
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

                console.log('✅ Mobile session restoration successful for user:', userInfo);

                // Use existing session or create new one
                if (sessionId) {
                    req.sessionID = sessionId;
                }
                
                // Set user data - this is critical
                req.session.user = userInfo;
                req.session.initialized = true;
                
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
                        console.error('❌ Error saving mobile session:', err);
                        return res.status(500).json({ 
                            success: false, 
                            error: 'Failed to save session' 
                        });
                    }

                    console.log('✅ Mobile session saved/updated with ID:', req.sessionID);
                    
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
        console.error('Mobile session restoration error:', error);
        res.status(500).json({ 
            success: false, 
            error: error.message 
        });
    }
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

// FIXED: Session initialization endpoint for mobile devices
app.get('/api/init-session', (req, res) => {
    console.log('🔄 Initializing session for device:', req.isIPad ? 'iPad' : req.isAndroid ? 'Android' : req.isIOS ? 'iOS' : 'Desktop');
    
    // Ensure session is created and marked as initialized
    if (!req.session.initialized) {
        req.session.initialized = true;
        req.session.deviceType = req.isIPad ? 'ipad' : req.isAndroid ? 'android' : req.isIOS ? 'ios' : 'desktop';
        req.session.createdAt = new Date();
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
            message: 'Session initialized successfully',
            deviceType: req.session.deviceType
        });
    });
});

// CRITICAL FIX: Enhanced authentication middleware for ALL devices
function isAuthenticated(req, res, next) {
    console.log('=== AUTH CHECK ===');
    console.log('Session ID:', req.sessionID);
    console.log('Session exists:', !!req.session);
    console.log('Session User:', req.session?.user);
    
    const cookies = parseCookies(req.headers.cookie);
    const sessionCookie = cookies['solura.session'];
    const sessionIdFromHeader = req.headers['x-session-id'];
    const sessionIdFromQuery = req.query.sessionId;
    
    console.log('Auth Check - Cookie vs Session:', {
        cookieSession: sessionCookie,
        currentSession: req.sessionID,
        match: sessionCookie === req.sessionID
    });
    
    // For mobile devices, check for session ID in headers or query
    if ((!req.session?.user) && (sessionIdFromHeader || sessionIdFromQuery)) {
        const externalSessionId = sessionIdFromHeader || sessionIdFromQuery;
        console.log('📱 Mobile Device - Attempting session recovery from external ID:', externalSessionId);
        
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
        
        // CRITICAL: Always touch session and set cookie for authenticated requests
        safeSessionTouch(req);
        res.cookie('solura.session', req.sessionID, {
            maxAge: 24 * 60 * 60 * 1000,
            httpOnly: false,
            secure: false,
            sameSite: 'lax',
            path: '/',
            domain: isProduction ? '.solura.uk' : undefined
        });
        
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

                    // Set session cookie
                    res.cookie('solura.session', req.sessionID, {
                        maxAge: 24 * 60 * 60 * 1000,
                        httpOnly: false,
                        secure: false,
                        sameSite: 'lax',
                        path: '/',
                        domain: isProduction ? '.solura.uk' : undefined
                    });

                    res.json({
                        success: true,
                        message: 'Login successful',
                        redirectUrl: redirectUrl,
                        user: userInfo,
                        accessToken: authToken,
                        refreshToken: refreshToken,
                        sessionId: req.sessionID,
                        isMobile: useMobileApp
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

// CRITICAL FIX: Enhanced login route with proper mobile session handling
app.post('/submit', async (req, res) => {
    console.log('=== LOGIN ATTEMPT ===');
    console.log('Session ID at login start:', req.sessionID);
    console.log('Session object exists:', !!req.session);
    
    const { email, password, dbName, forceLogout } = req.body;

    if (!email || !password) {
        return res.status(400).json({ 
            success: false,
            message: 'Email and password are required' 
        });
    }

    try {
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

            // NOW check for active sessions (after we know credentials are valid)
            const activeSessionIds = activeSessions.get(email);
            let hasActiveSessions = false;
            
            if (activeSessionIds && activeSessionIds.size > 0) {
                // Verify sessions are still valid
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
                console.log('🔄 Force logout requested for:', email);
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

                // CRITICAL: Ensure we have a valid session before proceeding
                if (!req.sessionID) {
                    console.error('❌ No session ID available');
                    return res.status(500).json({ 
                        success: false,
                        error: 'Session initialization failed' 
                    });
                }

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
                req.session.loginTime = new Date();
                req.session.lastAccess = new Date();

                console.log('💾 Session data set for session:', loginSessionId);

                // Save session
                req.session.save((err) => {
                    if (err) {
                        console.error('Error saving session:', err);
                        return res.status(500).json({ 
                            success: false,
                            error: 'Failed to create session'
                        });
                    }

                    console.log('✅ Session saved successfully:', loginSessionId);

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

                    console.log(`🔄 Redirecting to: ${redirectUrl} (Mobile: ${useMobileApp}, iPad: ${req.isIPad}, Android: ${req.isAndroid})`);

                    // CRITICAL: Enhanced cookie setting for mobile devices
                    res.cookie('solura.session', loginSessionId, {
                        maxAge: 24 * 60 * 60 * 1000,
                        httpOnly: false,
                        secure: false,
                        sameSite: 'lax',
                        path: '/',
                        domain: isProduction ? '.solura.uk' : undefined
                    });

                    // Additional headers for mobile devices
                    if (useMobileApp || req.isIPad || req.isAndroid) {
                        res.setHeader('X-Session-ID', loginSessionId);
                        res.setHeader('X-Session-Confirmed', 'true');
                        res.setHeader('X-Device-Type', req.isIPad ? 'ipad' : req.isAndroid ? 'android' : 'mobile');
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
                        isIPad: req.isIPad,
                        isAndroid: req.isAndroid
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

// Protected routes - PROPER DEVICE DETECTION
app.get('/Admin.html', isAuthenticated, isAdmin, (req, res) => {
    res.sendFile(path.join(__dirname, 'Admin.html'));
});

app.get('/AdminApp.html', isAuthenticated, isAdmin, (req, res) => {
    res.sendFile(path.join(__dirname, 'AdminApp.html'));
});

app.get('/User.html', isAuthenticated, isUser, (req, res) => {
    res.sendFile(path.join(__dirname, 'User.html'));
});

app.get('/UserApp.html', isAuthenticated, isUser, (req, res) => {
    res.sendFile(path.join(__dirname, 'UserApp.html'));
});

app.get('/Supervisor.html', isAuthenticated, isSupervisor, (req, res) => {
    res.sendFile(path.join(__dirname, 'Supervisor.html'));
});

app.get('/SupervisorApp.html', isAuthenticated, isSupervisor, (req, res) => {
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
                httpOnly: false,
                secure: false,
                sameSite: 'lax',
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
                sameSite: 'lax',
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
    console.log('🔧 UNIVERSAL Mobile Session Fixes Applied:');
    console.log('   - Enhanced iPad detection with leading dot domain');
    console.log('   - Android device detection and support');
    console.log('   - Universal mobile session handling');
    console.log('   - Improved cookie settings for all devices');
    console.log('   - Fixed session store configuration');
    console.log('   - Enhanced session initialization');
    
    const databaseNames = ['bbuonaoxford', '100%pastaoxford'];
    scheduleTestUpdates(databaseNames);
});