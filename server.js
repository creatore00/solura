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

const app = express();
const port = process.env.PORT || 8080;

// Environment configuration
const isProduction = process.env.NODE_ENV === 'production';
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-in-production';
const SESSION_SECRET = process.env.SESSION_SECRET || 'fallback-secret-key-change-in-production';

// Trust proxy for Heroku
app.set('trust proxy', 1);

// Track active sessions for duplicate login prevention
const activeSessions = new Map(); // email -> sessionIds

// Enhanced logging function for iOS debugging
function logIOS(message, data = null) {
    const timestamp = new Date().toISOString();
    console.log(`📱 [iOS-DEBUG] ${timestamp}: ${message}`);
    if (data) {
        console.log(`📱 [iOS-DEBUG] Data:`, JSON.stringify(data, null, 2));
    }
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
    );
}

// Enhanced CORS configuration for iOS compatibility
const corsOptions = {
    origin: function (origin, callback) {
        logIOS('CORS Origin Check', { origin, headers: this.req?.headers });
        
        const allowedOrigins = [
            'https://www.solura.uk', 
            'https://solura.uk', 
            'http://localhost:8080',
            'http://localhost:3000',
            'capacitor://localhost',
            'ionic://localhost',
            'http://localhost',
            'https://localhost'
        ];
        
        // Allow requests with no origin (like mobile apps or curl requests)
        if (!origin) {
            logIOS('CORS: No origin - allowing');
            return callback(null, true);
        }
        
        // Allow Capacitor/Ionic origins
        if (origin.startsWith('capacitor://') || origin.startsWith('ionic://') || origin.startsWith('file://')) {
            logIOS('CORS: Capacitor/Ionic origin - allowing', { origin });
            return callback(null, true);
        }
        
        if (allowedOrigins.indexOf(origin) !== -1) {
            logIOS('CORS: Allowed origin', { origin });
            callback(null, true);
        } else {
            logIOS('CORS: Blocked origin', { origin });
            callback(new Error('Not allowed by CORS'));
        }
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'Cookie', 'Accept', 'X-Session-ID', 'X-Capacitor'],
    exposedHeaders: ['Set-Cookie', 'X-Session-ID']
};

app.use(cors(corsOptions));

// Handle preflight requests
app.options('*', cors(corsOptions));

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// CRITICAL: Enhanced static file serving with iOS logging
app.use(express.static(__dirname, {
    setHeaders: (res, path, stat) => {
        logIOS('Serving static file', { 
            path: path, 
            contentType: res.get('Content-Type'),
            fileExists: fs.existsSync(path)
        });
        
        // Add security headers
        res.set('X-Content-Type-Options', 'nosniff');
        
        // Special handling for HTML files
        if (path.endsWith('.html')) {
            res.set('Content-Type', 'text/html; charset=utf-8');
        }
    }
}));

// FIXED: Cookie cleanup middleware - remove duplicate cookies
app.use((req, res, next) => {
    logIOS('Cookie middleware - incoming cookies', { 
        cookies: req.headers.cookie,
        url: req.url,
        method: req.method
    });
    
    if (req.headers.cookie) {
        const cookies = req.headers.cookie.split(';');
        const uniqueCookies = new Map();
        
        // Process cookies in reverse to keep the most recent one
        for (let i = cookies.length - 1; i >= 0; i--) {
            const cookie = cookies[i].trim();
            const [name, value] = cookie.split('=');
            if (name && value) {
                if (!uniqueCookies.has(name)) {
                    uniqueCookies.set(name, value);
                }
            }
        }
        
        // Rebuild cookie header with unique cookies
        const newCookieHeader = Array.from(uniqueCookies.entries())
            .map(([name, value]) => `${name}=${value}`)
            .join('; ');
        
        req.headers.cookie = newCookieHeader;
        
        logIOS('Cookie middleware - cleaned cookies', { 
            original: cookies.length,
            cleaned: uniqueCookies.size,
            newHeader: newCookieHeader
        });
    }
    next();
});

// Enhanced session debugging middleware
app.use((req, res, next) => {
    const iosDebugInfo = {
        url: req.url,
        method: req.method,
        origin: req.headers.origin,
        'user-agent': req.headers['user-agent'],
        'x-capacitor': req.headers['x-capacitor'],
        'x-session-id': req.headers['x-session-id'],
        referer: req.headers.referer,
        cookies: req.headers.cookie,
        sessionID: req.sessionID,
        sessionExists: !!req.session,
        sessionUser: req.session?.user,
        sessionInitialized: req.session?.initialized
    };
    
    logIOS('Request received', iosDebugInfo);
    next();
});

// FIXED: Enhanced MySQL session store with proper serialization
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

// Session store event listeners with enhanced logging
sessionStore.on('connected', () => {
    logIOS('Session store connected to database');
});

sessionStore.on('error', (error) => {
    logIOS('Session store error', { error: error.message });
});

sessionStore.on('disconnect', () => {
    logIOS('Session store disconnected');
});

// FIXED: Session configuration with iOS compatibility - CRITICAL CHANGES
app.use(session({
    secret: SESSION_SECRET,
    resave: true, // Changed to true for better iOS compatibility
    saveUninitialized: true, // Changed to true to ensure session is always created
    store: sessionStore,
    name: 'solura.session',
    cookie: {
        secure: isProduction,
        httpOnly: true,
        sameSite: isProduction ? 'none' : 'lax', // 'none' for cross-site in production
        maxAge: 10 * 60 * 1000, // 10 minutes in milliseconds
        domain: isProduction ? '.solura.uk' : undefined
    },
    rolling: true,
    proxy: true,
    genid: function(req) {
        const newId = require('crypto').randomBytes(16).toString('hex');
        logIOS('Generated new session ID', { sessionId: newId });
        return newId;
    }
}));

// Enhanced iOS detection middleware - MUST come after session middleware
app.use((req, res, next) => {
    const userAgent = req.headers['user-agent'] || '';
    const origin = req.headers.origin || '';
    const referer = req.headers.referer || '';
    
    // Enhanced iOS Capacitor detection
    const isIOSCapacitor = 
        origin.includes('capacitor://') || 
        origin.includes('ionic://') ||
        req.headers['x-capacitor'] === 'true' ||
        userAgent.includes('Capacitor') ||
        userAgent.includes('iOS') ||
        userAgent.includes('iPhone') ||
        userAgent.includes('iPad') ||
        referer.includes('capacitor://') ||
        referer.includes('ionic://');
    
    if (isIOSCapacitor) {
        req.isIOSApp = true;
        logIOS('iOS Capacitor App Detected', {
            origin,
            userAgent,
            referer,
            xCapacitor: req.headers['x-capacitor'],
            xSessionId: req.headers['x-session-id']
        });
        
        // Force session initialization for iOS
        if (!req.session.initialized) {
            req.session.initialized = true;
            logIOS('Initializing session for iOS app');
        }
        
        // Handle session ID from headers for iOS app
        const sessionIdFromHeader = req.headers['x-session-id'];
        if (sessionIdFromHeader && req.sessionID !== sessionIdFromHeader) {
            logIOS('Attempting to use session ID from header', {
                headerSessionId: sessionIdFromHeader,
                currentSessionId: req.sessionID
            });
            
            req.sessionStore.get(sessionIdFromHeader, (err, sessionData) => {
                if (err) {
                    logIOS('Error loading external session', { error: err.message });
                    return next();
                }
                
                if (sessionData && sessionData.user) {
                    logIOS('External session data found, merging', {
                        user: sessionData.user.email,
                        sessionId: sessionIdFromHeader
                    });
                    Object.assign(req.session, sessionData);
                    req.sessionID = sessionIdFromHeader;
                } else {
                    logIOS('No valid session data found for external session ID');
                }
                next();
            });
        } else {
            next();
        }
    } else {
        req.isIOSApp = false;
        next();
    }
});

// Session recovery middleware for heartbeat issues
app.use('/api/session-heartbeat', (req, res, next) => {
    logIOS('Heartbeat endpoint accessed', { sessionId: req.sessionID });
    // Force session reload for heartbeat
    if (req.session && typeof req.session.reload === 'function') {
        req.session.reload((err) => {
            if (err) {
                logIOS('Heartbeat session reload failed', { error: err.message });
            } else {
                logIOS('Heartbeat session reload successful');
            }
            next();
        });
    } else {
        next();
    }
});

// Enhanced session tracking middleware
app.use((req, res, next) => {
    // Override session.save to track active sessions
    const originalSave = req.session.save;
    req.session.save = function(callback) {
        originalSave.call(this, (err) => {
            if (!err && req.session.user && req.session.user.email) {
                const email = req.session.user.email;
                if (!activeSessions.has(email)) {
                    activeSessions.set(email, new Set());
                }
                activeSessions.get(email).add(req.sessionID);
                logIOS(`Session tracked for ${email}`, { sessionId: req.sessionID });
            } else if (err) {
                logIOS('Session save error', { error: err.message });
            }
            if (callback) callback(err);
        });
    };
    next();
});

// SECURITY: Block direct access to protected HTML files without session
app.use((req, res, next) => {
    const protectedRoutes = [
        '/Admin.html', '/AdminApp.html',
        '/User.html', '/UserApp.html', 
        '/Supervisor.html', '/SupervisorApp.html'
    ];
    
    // Check if this is a direct access to protected route
    if (protectedRoutes.includes(req.path)) {
        logIOS('Protected route access attempt', { 
            path: req.path, 
            hasSession: !!req.session?.user,
            sessionUser: req.session?.user 
        });
        
        if (!req.session?.user) {
            logIOS('SECURITY: Blocked direct access to protected route', { path: req.path });
            return res.redirect('/');
        }
    }
    
    next();
});

// Session reloading middleware for API endpoints
app.use('/api/', (req, res, next) => {
    logIOS('API endpoint accessed', { 
        path: req.path, 
        sessionId: req.sessionID,
        hasSession: !!req.session 
    });
    
    // Force session reload for API calls
    if (req.session && typeof req.session.reload === 'function') {
        req.session.reload((err) => {
            if (err) {
                logIOS('Error reloading session for API', { error: err.message });
            }
            next();
        });
    } else {
        next();
    }
});

// Add CORS headers manually for additional security
app.use((req, res, next) => {
    const origin = req.headers.origin;
    const allowedOrigins = ['https://www.solura.uk', 'https://solura.uk', 'http://localhost:8080', 'http://localhost:3000'];
    
    if (origin && allowedOrigins.includes(origin)) {
        res.header('Access-Control-Allow-Origin', origin);
    }
    res.header('Access-Control-Allow-Credentials', 'true');
    res.header('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS');
    res.header('Access-Control-Allow-Headers', 'Content-Type', 'Authorization', 'Content-Length', 'X-Requested-With', 'Cookie', 'X-Session-ID');
    res.header('Access-Control-Expose-Headers', 'Set-Cookie', 'X-Session-ID');
    
    if (req.method === 'OPTIONS') {
        logIOS('Preflight request handled', { origin });
        return res.sendStatus(200);
    }
    next();
});

// ENHANCED: Global error handler with iOS logging
app.use((error, req, res, next) => {
    logIOS('Global error handler', { 
        error: error.message,
        stack: error.stack,
        url: req.url,
        method: req.method,
        userAgent: req.headers['user-agent'],
        isIOS: req.isIOSApp
    });
    
    if (error.message && error.message.includes('touch')) {
        logIOS('Recovering from session touch error');
        if (req.session) {
            req.session.cookie.maxAge = req.session.cookie.originalMaxAge || 24 * 60 * 60 * 1000;
        }
        
        if (req.path.startsWith('/api/')) {
            return res.json({ 
                success: false, 
                error: 'Session error, please refresh',
                recovered: true 
            });
        }
    }
    
    // Don't leak error details in production
    const errorMessage = isProduction ? 'Internal server error' : error.message;
    
    if (req.path.startsWith('/api/')) {
        res.status(500).json({ 
            success: false, 
            error: errorMessage 
        });
    } else {
        res.status(500).send('Internal server error');
    }
});

// Enhanced security middleware
app.use((req, res, next) => {
    // Security headers
    res.header('X-Content-Type-Options', 'nosniff');
    res.header('X-Frame-Options', 'DENY');
    res.header('X-XSS-Protection', '1; mode=block');
    res.header('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    
    // Rate limiting for login attempts (simple in-memory version)
    if (req.path === '/submit' && req.method === 'POST') {
        const clientIP = req.ip || req.connection.remoteAddress;
        const now = Date.now();
        const windowStart = now - (15 * 60 * 1000); // 15 minutes window
        
        // Simple rate limiting - in production, use Redis or similar
        if (!req.rateLimit) req.rateLimit = {};
        if (!req.rateLimit[clientIP]) req.rateLimit[clientIP] = [];
        
        req.rateLimit[clientIP] = req.rateLimit[clientIP].filter(time => time > windowStart);
        
        if (req.rateLimit[clientIP].length >= 5) { // 5 attempts per 15 minutes
            logIOS('Rate limit exceeded', { ip: clientIP });
            return res.status(429).json({
                success: false,
                error: 'Too many login attempts. Please try again later.'
            });
        }
        
        req.rateLimit[clientIP].push(now);
    }
    
    next();
});

// Track session creation times for better management
const sessionCreationTime = new Map(); // sessionId -> creation timestamp

// Enhanced session tracking middleware
app.use((req, res, next) => {
    const originalSave = req.session.save;
    req.session.save = function(callback) {
        originalSave.call(this, (err) => {
            if (!err && req.session.user && req.session.user.email) {
                const email = req.session.user.email;
                if (!activeSessions.has(email)) {
                    activeSessions.set(email, new Set());
                }
                activeSessions.get(email).add(req.sessionID);
                
                // Track creation time
                if (!sessionCreationTime.has(req.sessionID)) {
                    sessionCreationTime.set(req.sessionID, Date.now());
                    logIOS(`Session tracked`, { 
                        sessionId: req.sessionID, 
                        email: email,
                        isIOS: req.isIOSApp 
                    });
                }
            }
            if (callback) callback(err);
        });
    };
    next();
});

// CRITICAL: Enhanced root route with comprehensive iOS logging
app.get('/', (req, res) => {
    const userAgent = req.headers['user-agent'] || '';
    const origin = req.headers.origin || '';
    const referer = req.headers.referer || '';

    // Enhanced Capacitor detection
    const isCapacitorApp = 
        /Capacitor/.test(userAgent) ||
        /ionic/.test(userAgent) ||
        origin.startsWith('capacitor://') ||
        origin.startsWith('ionic://') ||
        referer.startsWith('file://') ||
        req.headers['x-capacitor'] === 'true' ||
        req.query.capacitor === 'true';

    const detectionInfo = {
        userAgent,
        origin,
        referer,
        'x-capacitor': req.headers['x-capacitor'],
        isCapacitorApp,
        sessionId: req.sessionID,
        sessionInitialized: req.session?.initialized
    };

    logIOS('Root route accessed', detectionInfo);

    // Serve the correct HTML file
    const fileToServe = isCapacitorApp ? 'LoginApp.html' : 'Login.html';
    
    // Check if the file exists
    const filePath = path.join(__dirname, fileToServe);
    const fileExists = fs.existsSync(filePath);
    
    logIOS('Serving file check', {
        fileToServe,
        filePath,
        fileExists,
        dirExists: fs.existsSync(__dirname)
    });

    if (!fileExists) {
        logIOS('ERROR: File not found', { filePath, availableFiles: fs.readdirSync(__dirname) });
        return res.status(404).send('Login file not found');
    }

    logIOS('Serving file', { file: fileToServe });
    res.sendFile(filePath);
});

// NEW: iOS Debug endpoint to check server status
app.get('/api/ios-debug', (req, res) => {
    const debugInfo = {
        server: {
            status: 'running',
            timestamp: new Date().toISOString(),
            environment: isProduction ? 'production' : 'development'
        },
        session: {
            id: req.sessionID,
            exists: !!req.session,
            user: req.session?.user,
            initialized: req.session?.initialized
        },
        request: {
            headers: {
                origin: req.headers.origin,
                'user-agent': req.headers['user-agent'],
                'x-capacitor': req.headers['x-capacitor'],
                'x-session-id': req.headers['x-session-id'],
                referer: req.headers.referer
            },
            ip: req.ip,
            method: req.method,
            url: req.url
        },
        files: {
            loginAppExists: fs.existsSync(path.join(__dirname, 'LoginApp.html')),
            loginExists: fs.existsSync(path.join(__dirname, 'Login.html')),
            directoryContents: fs.readdirSync(__dirname).filter(f => f.endsWith('.html'))
        }
    };

    logIOS('iOS Debug endpoint accessed', debugInfo);
    res.json(debugInfo);
});

// NEW: File existence check endpoint
app.get('/api/check-files', (req, res) => {
    const filesToCheck = [
        'LoginApp.html',
        'Login.html',
        'AdminApp.html',
        'Admin.html',
        'UserApp.html',
        'User.html',
        'SupervisorApp.html',
        'Supervisor.html'
    ];

    const fileStatus = {};
    filesToCheck.forEach(file => {
        const filePath = path.join(__dirname, file);
        fileStatus[file] = {
            exists: fs.existsSync(filePath),
            path: filePath,
            size: fs.existsSync(filePath) ? fs.statSync(filePath).size : 0
        };
    });

    logIOS('File check requested', fileStatus);
    res.json({ success: true, files: fileStatus });
});

// Health check endpoint with session info
app.get('/health', (req, res) => {
    const healthInfo = {
        status: 'OK',
        session: {
            id: req.sessionID,
            exists: !!req.session,
            user: req.session?.user,
            initialized: req.session?.initialized
        },
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
        memory: process.memoryUsage(),
        version: '1.0.0',
        isIOS: req.isIOSApp
    };
    
    logIOS('Health check', healthInfo);
    res.json(healthInfo);
});

// ALL YOUR ORIGINAL ROUTES - KEPT INTACT but with logging
app.use('/rota', (req, res, next) => {
    logIOS('Rota route accessed', { path: req.path, method: req.method });
    next();
}, newRota);

app.use('/rota2', (req, res, next) => {
    logIOS('Rota2 route accessed', { path: req.path, method: req.method });
    next();
}, newRota2);

app.use('/confirmpassword', (req, res, next) => {
    logIOS('ConfirmPassword route accessed', { path: req.path, method: req.method });
    next();
}, confirmpassword);

app.use('/token', (req, res, next) => {
    logIOS('Token route accessed', { path: req.path, method: req.method });
    next();
}, token);

app.use('/Backend', (req, res, next) => {
    logIOS('Backend route accessed', { path: req.path, method: req.method });
    next();
}, Backend);

app.use('/generate', (req, res, next) => {
    logIOS('Generate route accessed', { path: req.path, method: req.method });
    next();
}, generate);

app.use('/updateinfo', (req, res, next) => {
    logIOS('UpdateInfo route accessed', { path: req.path, method: req.method });
    next();
}, updateinfo);

app.use('/ForgotPassword', (req, res, next) => {
    logIOS('ForgotPassword route accessed', { path: req.path, method: req.method });
    next();
}, ForgotPassword);

app.use('/userholidays', (req, res, next) => {
    logIOS('UserHolidays route accessed', { path: req.path, method: req.method });
    next();
}, userholidays);

app.use('/hours', (req, res, next) => {
    logIOS('Hours route accessed', { path: req.path, method: req.method });
    next();
}, hours);

app.use('/labor', (req, res, next) => {
    logIOS('Labor route accessed', { path: req.path, method: req.method });
    next();
}, labor);

app.use('/pastpayslips', (req, res, next) => {
    logIOS('PastPayslips route accessed', { path: req.path, method: req.method });
    next();
}, pastpayslips);

app.use('/request', (req, res, next) => {
    logIOS('Request route accessed', { path: req.path, method: req.method });
    next();
}, request);

app.use('/tip', (req, res, next) => {
    logIOS('Tip route accessed', { path: req.path, method: req.method });
    next();
}, tip);

app.use('/pastemployees', (req, res, next) => {
    logIOS('PastEmployees route accessed', { path: req.path, method: req.method });
    next();
}, pastemployees);

app.use('/TotalHolidays', (req, res, next) => {
    logIOS('TotalHolidays route accessed', { path: req.path, method: req.method });
    next();
}, TotalHolidays);

app.use('/UserCrota', (req, res, next) => {
    logIOS('UserCrota route accessed', { path: req.path, method: req.method });
    next();
}, UserCrota);

app.use('/UserHoliday', (req, res, next) => {
    logIOS('UserHoliday route accessed', { path: req.path, method: req.method });
    next();
}, UserHolidays);

app.use('/confirmrota', (req, res, next) => {
    logIOS('ConfirmRota route accessed', { path: req.path, method: req.method });
    next();
}, confirmrota);

app.use('/confirmrota2', (req, res, next) => {
    logIOS('ConfirmRota2 route accessed', { path: req.path, method: req.method });
    next();
}, confirmrota2);

app.use('/profile', (req, res, next) => {
    logIOS('Profile route accessed', { path: req.path, method: req.method });
    next();
}, profile);

app.use('/UserTotalHours', (req, res, next) => {
    logIOS('UserTotalHours route accessed', { path: req.path, method: req.method });
    next();
}, UserTotalHours);

app.use('/insertpayslip', (req, res, next) => {
    logIOS('InsertPayslip route accessed', { path: req.path, method: req.method });
    next();
}, insertpayslip);

app.use('/modify', (req, res, next) => {
    logIOS('Modify route accessed', { path: req.path, method: req.method });
    next();
}, modify);

app.use('/endday', (req, res, next) => {
    logIOS('EndDay route accessed', { path: req.path, method: req.method });
    next();
}, endday);

app.use('/financialsummary', (req, res, next) => {
    logIOS('FinancialSummary route accessed', { path: req.path, method: req.method });
    next();
}, financialsummary);

// NEW: iOS-specific initialization endpoint
app.get('/api/ios-init', (req, res) => {
    logIOS('iOS initialization endpoint called', {
        sessionId: req.sessionID,
        sessionInitialized: req.session?.initialized,
        headers: req.headers
    });

    // Ensure session is properly initialized for iOS
    if (!req.session.initialized) {
        req.session.initialized = true;
        req.session.isIOSApp = true;
        logIOS('iOS session initialized');
    }

    req.session.save((err) => {
        if (err) {
            logIOS('Error saving iOS session', { error: err.message });
            return res.status(500).json({ 
                success: false, 
                error: 'Session initialization failed' 
            });
        }

        logIOS('iOS initialization successful', { sessionId: req.sessionID });
        res.json({
            success: true,
            sessionId: req.sessionID,
            message: 'iOS app initialized successfully',
            requiresLogin: !req.session?.user
        });
    });
});

// NEW: Check if user already has active session
app.post('/api/check-active-session', async (req, res) => {
    const { email } = req.body;
    
    logIOS('Check active session request', { email });
    
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
                            logIOS('Error checking session', { error: err.message });
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
                logIOS('Active sessions found', { email, activeSessions: validSessions.length });
                return res.json({
                    success: true,
                    hasActiveSession: true,
                    activeSessions: validSessions.length,
                    message: `You are already logged in on ${validSessions.length} device(s).`
                });
            }
        }
        
        logIOS('No active sessions found', { email });
        res.json({
            success: true,
            hasActiveSession: false
        });
        
    } catch (error) {
        logIOS('Error checking active sessions', { error: error.message });
        res.status(500).json({ 
            success: false, 
            error: 'Internal server error' 
        });
    }
});

// Enhanced force logout with immediate effect
app.post('/api/force-logout-others', async (req, res) => {
    const { email, keepCurrentSession } = req.body;
    
    logIOS('Force logout request', { email, keepCurrentSession });
    
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
            
            logIOS(`Force logging out sessions`, { email, sessionsToDestroy: sessionsToDestroy.length });
            
            for (const sessionId of sessionsToDestroy) {
                await new Promise((resolve) => {
                    sessionStore.destroy(sessionId, (err) => {
                        if (!err) {
                            loggedOutCount++;
                            sessionCreationTime.delete(sessionId);
                            logIOS(`Destroyed session`, { sessionId });
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

        logIOS('Force logout completed', { loggedOutCount });
        res.json({
            success: true,
            loggedOutCount: loggedOutCount,
            message: `Immediately logged out from ${loggedOutCount} other session(s)`
        });

    } catch (error) {
        logIOS('Error force logging out', { error: error.message });
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

        logIOS('Biometric verification request', { email });

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
            logIOS('Biometric token verification failed', { error: tokenError.message });
            return res.status(401).json({ 
                success: false,
                error: 'Invalid or expired token' 
            });
        }

        // Get user info from database
        const sql = `SELECT u.Access, u.Email, u.db_name FROM users u WHERE u.Email = ?`;
        
        mainPool.query(sql, [email], (err, results) => {
            if (err) {
                logIOS('Database query error', { error: err.message });
                return res.status(500).json({ 
                    success: false,
                    error: 'Internal Server Error'
                });
            }

            if (results.length === 0) {
                logIOS('User not found in database', { email });
                return res.status(401).json({ 
                    success: false,
                    message: 'User not found' 
                });
            }

            const userDetails = results[0];
            
            // Get user info from company database
            const companyPool = getPool(userDetails.db_name);
            const companySql = `SELECT name, lastName FROM Employees WHERE email = ?`;

            companyPool.query(companySql, [email], (err, companyResults) => {
                if (err) {
                    logIOS('Company database query error', { error: err.message });
                    return res.status(500).json({ 
                        success: false,
                        error: 'Internal Server Error'
                    });
                }

                if (companyResults.length === 0) {
                    logIOS('User not found in company database', { email, dbName: userDetails.db_name });
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

                logIOS('Biometric authentication successful', { userInfo });

                // Create session
                req.session.user = userInfo;
                req.session.initialized = true;
                
                // Track this session
                if (!activeSessions.has(email)) {
                    activeSessions.set(email, new Set());
                }
                activeSessions.get(email).add(req.sessionID);
                
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

                // ALWAYS use desktop versions for browsers
                let redirectUrl = '';
                const userAgent = req.headers['user-agent'] || '';
                const isMobile = /iPhone|iPad|iPod|Android/i.test(userAgent);

                if (userDetails.Access === 'admin' || userDetails.Access === 'AM') {
                    redirectUrl = isMobile ? '/AdminApp.html' : '/Admin.html';
                } else if (userDetails.Access === 'user') {
                    redirectUrl = isMobile ? '/UserApp.html' : '/User.html';
                } else if (userDetails.Access === 'supervisor') {
                    redirectUrl = isMobile ? '/SupervisorApp.html' : '/Supervisor.html';
                }

                req.session.save((err) => {
                    if (err) {
                        logIOS('Error saving session', { error: err.message });
                        return res.status(500).json({ 
                            success: false,
                            error: 'Failed to create session'
                        });
                    }

                    logIOS('Session saved successfully', { sessionId: req.sessionID });
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
        logIOS('Biometric authentication error', { error: error.message });
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

        logIOS('Token refresh request');

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

            logIOS('Token refresh successful');
            res.json({
                success: true,
                accessToken: newAccessToken,
                expiresIn: '7d'
            });

        } catch (tokenError) {
            logIOS('Token refresh failed', { error: tokenError.message });
            return res.status(401).json({ 
                success: false,
                error: 'Invalid or expired refresh token' 
            });
        }
    } catch (error) {
        logIOS('Token refresh error', { error: error.message });
        res.status(500).json({ 
            success: false,
            error: 'Internal server error'
        });
    }
});

// NEW: Get current user info endpoint for frontend
app.get('/api/current-user', isAuthenticated, (req, res) => {
    safeSessionTouch(req);
    logIOS('Current user request', { user: req.session.user });
    res.json({
        success: true,
        user: req.session.user
    });
});

// Session validation endpoint with safe touch
app.get('/api/validate-session', (req, res) => {
    logIOS('Session validation request', {
        sessionId: req.sessionID,
        sessionExists: !!req.session,
        sessionUser: req.session?.user
    });
    
    if (req.session?.user) {
        // Safe session extension
        safeSessionTouch(req);
        logIOS('Session validation successful', { user: req.session.user });
        res.json({ 
            valid: true, 
            user: req.session.user,
            sessionId: req.sessionID 
        });
    } else {
        logIOS('Session validation failed - no user in session');
        res.status(401).json({ 
            valid: false,
            message: 'No active session'
        });
    }
});

// FIXED: Real-time session validation endpoint
app.get('/api/validate-session-real-time', async (req, res) => {
    logIOS('Real-time session validation', {
        sessionId: req.sessionID,
        sessionExists: !!req.session,
        sessionUser: req.session?.user
    });
    
    // Ensure session is loaded
    if (!req.session) {
        logIOS('Session not loaded');
        return res.json({
            valid: false,
            reason: 'session_not_loaded',
            message: 'Session not loaded'
        });
    }

    if (!req.session.user) {
        logIOS('No user in session');
        return res.json({
            valid: false,
            reason: 'no_session_user',
            message: 'No user in session'
        });
    }

    const email = req.session.user.email;
    const activeSessionIds = activeSessions.get(email);
    
    logIOS('Active sessions check', {
        email,
        activeSessions: activeSessionIds ? Array.from(activeSessionIds) : 'None',
        currentSessionInActive: activeSessionIds?.has(req.sessionID)
    });
    
    // Check if this session is still active
    if (!activeSessionIds || !activeSessionIds.has(req.sessionID)) {
        logIOS('Session terminated - no longer in active sessions');
        
        // Destroy the invalid session
        req.session.destroy((err) => {
            if (err) {
                logIOS('Error destroying invalid session', { error: err.message });
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
    
    logIOS('Session validation successful');
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
    logIOS('Heartbeat connection established', { sessionId: req.sessionID });
    
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
                logIOS('Heartbeat: No user in session');
                res.write('data: ' + JSON.stringify({
                    valid: false,
                    reason: 'no_session_user',
                    message: 'Please log in again',
                    timestamp: Date.now()
                }) + '\n\n');
                return;
            }

            // Session is valid
            logIOS('Heartbeat: Session valid', { user: req.session.user.email });
            res.write('data: ' + JSON.stringify({
                valid: true,
                type: 'heartbeat',
                user: req.session.user.email,
                timestamp: Date.now()
            }) + '\n\n');

        } catch (error) {
            logIOS('Heartbeat error', { error: error.message });
        }
    };

    // Check immediately and then every 10 seconds
    checkSession();
    const intervalId = setInterval(checkSession, 10000);

    // Handle client disconnect
    req.on('close', () => {
        logIOS('Heartbeat connection closed');
        isConnected = false;
        clearInterval(intervalId);
    });

    req.on('error', (error) => {
        logIOS('Heartbeat connection error', { error: error.message });
        isConnected = false;
        clearInterval(intervalId);
    });
});

// NEW: Get available databases for current user
app.get('/api/user-databases', isAuthenticated, (req, res) => {
    safeSessionTouch(req);
    const email = req.session.user.email;
    
    logIOS('User databases request', { email });
    
    const sql = `SELECT u.db_name, u.Access FROM users u WHERE u.Email = ?`;
    
    mainPool.query(sql, [email], (err, results) => {
        if (err) {
            logIOS('Error querying user databases', { error: err.message });
            return res.status(500).json({ 
                success: false, 
                error: 'Internal Server Error' 
            });
        }

        const databases = results.map(row => ({
            db_name: row.db_name,
            access: row.Access
        }));

        logIOS('User databases retrieved', { databases });
        res.json({
            success: true,
            databases: databases,
            currentDb: req.session.user.dbName
        });
    });
});

// FIXED: Switch database endpoint with proper session handling
app.post('/api/switch-database', isAuthenticated, async (req, res) => {
    const { dbName } = req.body;
    const email = req.session.user.email;

    logIOS('Switch database request', { email, dbName });

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
                logIOS('Error verifying database access', { error: err.message });
                return res.status(500).json({ 
                    success: false, 
                    error: 'Internal Server Error' 
                });
            }

            if (results.length === 0) {
                logIOS('User not authorized for database', { email, dbName });
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
                    logIOS('Error querying company database', { error: err.message });
                    return res.status(500).json({ 
                        success: false, 
                        error: 'Internal Server Error' 
                    });
                }

                if (companyResults.length === 0) {
                    logIOS('User not found in company database', { email, dbName });
                    return res.status(404).json({ 
                        success: false, 
                        error: 'User not found in company database' 
                    });
                }

                const name = companyResults[0].name;
                const lastName = companyResults[0].lastName;

                // Store the current session ID before updating
                const oldSessionId = req.sessionID;
                
                // Update session with new database info - KEEP THE SAME SESSION
                req.session.user = {
                    email: email,
                    role: userDetails.Access,
                    name: name,
                    lastName: lastName,
                    dbName: dbName,
                };

                logIOS('Database switching - updating session', { 
                    oldSessionId, 
                    newSessionId: req.sessionID,
                    user: req.session.user 
                });

                // Save session and maintain the same session ID
                req.session.save((err) => {
                    if (err) {
                        logIOS('Error saving session after database switch', { error: err.message });
                        return res.status(500).json({ 
                            success: false, 
                            error: 'Failed to update session' 
                        });
                    }

                    logIOS('Database switched successfully', { dbName, sessionId: req.sessionID });
                    res.json({
                        success: true,
                        message: 'Database switched successfully',
                        user: req.session.user,
                        sessionId: req.sessionID // Return the same session ID
                    });
                });
            });
        });
    } catch (error) {
        logIOS('Database switch error', { error: error.message });
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
        
        logIOS('iOS session restoration request', { email, dbName, sessionId });

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
                logIOS('iOS session restoration - invalid token');
                return res.status(401).json({ 
                    success: false, 
                    error: 'Invalid token' 
                });
            }
        } catch (tokenError) {
            logIOS('iOS session restoration - token error', { error: tokenError.message });
            return res.status(401).json({ 
                success: false, 
                error: 'Invalid or expired token' 
            });
        }

        // Then proceed with user verification
        const verifySql = `SELECT u.Access, u.Email, u.db_name FROM users u WHERE u.Email = ? AND u.db_name = ?`;
        
        mainPool.query(verifySql, [email, dbName], (err, results) => {
            if (err) {
                logIOS('iOS session restoration - database error', { error: err.message });
                return res.status(500).json({ 
                    success: false, 
                    error: 'Internal Server Error' 
                });
            }

            if (results.length === 0) {
                logIOS('iOS session restoration - user not authorized', { email, dbName });
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
                    logIOS('iOS session restoration - company database error', { error: err.message });
                    return res.status(500).json({ 
                        success: false, 
                        error: 'Internal Server Error' 
                    });
                }

                if (companyResults.length === 0) {
                    logIOS('iOS session restoration - user not found in company database', { email, dbName });
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

                logIOS('iOS session restoration successful', { userInfo });

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
                activeSessions.get(email).add(req.sessionID);
                
                // Force save with callback to ensure it's persisted
                req.session.save((err) => {
                    if (err) {
                        logIOS('Error saving iOS session', { error: err.message });
                        return res.status(500).json({ 
                            success: false, 
                            error: 'Failed to save session' 
                        });
                    }

                    logIOS('iOS session saved/updated', { sessionId: req.sessionID });
                    
                    // Verify the session was actually saved
                    req.sessionStore.get(req.sessionID, (verifyErr, savedSession) => {
                        if (verifyErr) {
                            logIOS('Error verifying session save', { error: verifyErr.message });
                        } else if (savedSession && savedSession.user) {
                            logIOS('Session verification passed - user data persisted');
                        } else {
                            logIOS('Session verification failed - no user data in stored session');
                        }
                        
                        res.json({ 
                            success: true, 
                            user: userInfo,
                            sessionId: req.sessionID,
                            accessToken: accessToken
                        });
                    });
                });
            });
        });
        
    } catch (error) {
        logIOS('iOS session restoration error', { error: error.message });
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
        
        logIOS('Session recovery attempt', { email, dbName });
        
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
                logIOS('Session recovery - invalid token');
                return res.status(401).json({ 
                    success: false, 
                    error: 'Invalid token' 
                });
            }
        } catch (tokenError) {
            logIOS('Session recovery - token error', { error: tokenError.message });
            return res.status(401).json({ 
                success: false, 
                error: 'Invalid or expired token' 
            });
        }

        // Verify user has access to this database
        const verifySql = `SELECT u.Access, u.Email, u.db_name FROM users u WHERE u.Email = ? AND u.db_name = ?`;
        
        mainPool.query(verifySql, [email, dbName], (err, results) => {
            if (err) {
                logIOS('Session recovery - database error', { error: err.message });
                return res.status(500).json({ 
                    success: false, 
                    error: 'Internal Server Error' 
                });
            }

            if (results.length === 0) {
                logIOS('Session recovery - user not authorized', { email, dbName });
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
                    logIOS('Session recovery - company database error', { error: err.message });
                    return res.status(500).json({ 
                        success: false, 
                        error: 'Internal Server Error' 
                    });
                }

                if (companyResults.length === 0) {
                    logIOS('Session recovery - user not found in company database', { email, dbName });
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

                logIOS('Session recovery successful', { userInfo });

                // Assign user data to existing session
                req.session.user = userInfo;
                req.session.initialized = true;
                
                // Track this session
                if (!activeSessions.has(email)) {
                    activeSessions.set(email, new Set());
                }
                activeSessions.get(email).add(req.sessionID);
                
                req.session.save((err) => {
                    if (err) {
                        logIOS('Error saving recovered session', { error: err.message });
                        return res.status(500).json({ 
                            success: false, 
                            error: 'Failed to restore session' 
                        });
                    }

                    logIOS('Recovered session saved', { sessionId: req.sessionID });
                    res.json({ 
                        success: true, 
                        user: userInfo,
                        sessionId: req.sessionID 
                    });
                });
            });
        });
        
    } catch (error) {
        logIOS('Session recovery error', { error: error.message });
        res.status(500).json({ 
            success: false, 
            error: error.message 
        });
    }
});

// FIXED: Session initialization endpoint for iOS
app.get('/api/init-session', (req, res) => {
    logIOS('Session initialization request');
    
    // Ensure session is created and marked as initialized
    if (!req.session.initialized) {
        req.session.initialized = true;
    }
    
    // Touch the session to ensure it's saved
    safeSessionTouch(req);
    
    req.session.save((err) => {
        if (err) {
            logIOS('Error saving session', { error: err.message });
            return res.status(500).json({ success: false, error: 'Session initialization failed' });
        }
        
        logIOS('Session initialized', { sessionId: req.sessionID });
        res.json({
            success: true,
            sessionId: req.sessionID,
            message: 'Session initialized successfully'
        });
    });
});

// ENHANCED: Secure authentication middleware with session validation
function isAuthenticated(req, res, next) {
    logIOS('Authentication check', {
        sessionId: req.sessionID,
        sessionExists: !!req.session,
        sessionUser: req.session?.user
    });
    
    // Only allow access with valid session user data
    if (req.session?.user && req.session.user.dbName && req.session.user.email) {
        // CRITICAL: Check if this session is still in active sessions
        const email = req.session.user.email;
        const activeSessionIds = activeSessions.get(email);
        
        if (!activeSessionIds || !activeSessionIds.has(req.sessionID)) {
            logIOS('Session no longer active - user was force logged out');
            
            // Destroy the invalid session
            req.session.destroy((err) => {
                if (err) {
                    logIOS('Error destroying invalid session', { error: err.message });
                }
                logIOS('Invalid session destroyed');
                
                // Send proper auth error
                const userAgent = req.headers['user-agent'] || '';
                const isIOS = userAgent.includes('iPhone') || userAgent.includes('iPad');
                return sendAuthError(res, isIOS, req, 'Your session was terminated from another device. Please log in again.');
            });
            return;
        }
        
        logIOS('Authentication SUCCESS', { user: req.session.user.email });
        
        // Use safe session extension
        if (req.session.touch && typeof req.session.touch === 'function') {
            req.session.touch();
        } else {
            // Manual session extension by updating maxAge
            req.session.cookie.maxAge = req.session.cookie.originalMaxAge;
        }
        
        return next();
    }
    
    logIOS('Authentication FAILED - No valid user in session');
    
    // For iOS apps, try to load session from URL parameter as fallback
    const userAgent = req.headers['user-agent'] || '';
    const isIOS = userAgent.includes('iPhone') || userAgent.includes('iPad');
    const sessionIdFromUrl = req.query.sessionId;
    
    if (isIOS && sessionIdFromUrl && req.sessionStore) {
        logIOS('iOS - Attempting session recovery from URL parameter', { sessionIdFromUrl });
        
        req.sessionStore.get(sessionIdFromUrl, (err, sessionData) => {
            if (err) {
                logIOS('Error loading iOS session from URL', { error: err.message });
                return sendAuthError(res, isIOS, req);
            }
            
            if (sessionData && sessionData.user) {
                logIOS('iOS session recovery successful');
                
                // Check if the recovered session is still active
                const recoveredEmail = sessionData.user.email;
                const recoveredActiveSessions = activeSessions.get(recoveredEmail);
                
                if (!recoveredActiveSessions || !recoveredActiveSessions.has(sessionIdFromUrl)) {
                    logIOS('Recovered session no longer active');
                    return sendAuthError(res, isIOS, req, 'Your session was terminated from another device. Please log in again.');
                }
                
                // Regenerate session with loaded data
                req.session.regenerate((err) => {
                    if (err) {
                        logIOS('Error regenerating session during recovery', { error: err.message });
                        return sendAuthError(res, isIOS, req);
                    }
                    
                    Object.assign(req.session, sessionData);
                    req.sessionID = sessionIdFromUrl;
                    
                    // Safe session extension
                    if (req.session.touch && typeof req.session.touch === 'function') {
                        req.session.touch();
                    }
                    
                    return next();
                });
            } else {
                logIOS('No valid session data found for recovery');
                sendAuthError(res, isIOS, req);
            }
        });
    } else {
        sendAuthError(res, isIOS, req);
    }
}

// Enhanced sendAuthError function with custom message support
function sendAuthError(res, isIOS, req, customMessage = null) {
    const defaultMessage = 'Please log in again';
    const message = customMessage || defaultMessage;
    
    logIOS('Sending auth error', { isIOS, message });
    
    if (isIOS || req.path.startsWith('/api/') || req.xhr) {
        return res.status(401).json({ 
            success: false, 
            error: 'Unauthorized',
            message: message,
            requiresLogin: true
        });
    }
    
    // For HTML pages, you might want to show a message before redirecting
    // You can either redirect to login with a message or show an error page
    res.redirect('/?error=' + encodeURIComponent(message));
}

// Role-based middleware
function isAdmin(req, res, next) {
    if (req.session?.user && (req.session.user.role === 'admin' || req.session.user.role === 'AM')) {
        return next();
    }
    
    if (req.path.startsWith('/api/')) {
        return res.status(403).json({ 
            success: false, 
            error: 'Forbidden',
            message: 'Admin access required'
        });
    }
    
    res.redirect('/');
}

function isSupervisor(req, res, next) {
    if (req.session?.user && req.session.user.role === 'supervisor') {
        return next();
    }
    
    if (req.path.startsWith('/api/')) {
        return res.status(403).json({ 
            success: false, 
            error: 'Forbidden',
            message: 'Supervisor access required'
        });
    }
    
    res.redirect('/');
}

function isUser(req, res, next) {
    if (req.session?.user && req.session.user.role === 'user') {
        return next();
    }
    
    if (req.path.startsWith('/api/')) {
        return res.status(403).json({ 
            success: false, 
            error: 'Forbidden',
            message: 'User access required'
        });
    }
    
    res.redirect('/');
}

// Enhanced database selection with force logout support
app.post('/submit-database', async (req, res) => {
    const { email, password, dbName, forceLogout } = req.body;

    logIOS('Database selection request', { email, dbName, forceLogout });

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
                logIOS('Database query error', { error: err.message });
                return res.status(500).json({ 
                    success: false,
                    error: 'Internal Server Error'
                });
            }

            if (results.length === 0) {
                logIOS('Invalid database selection', { email, dbName });
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
                    logIOS('Invalid credentials', { email });
                    return res.status(401).json({ 
                        success: false,
                        message: 'Invalid credentials' 
                    });
                }
            } catch (err) {
                logIOS('Error comparing passwords', { error: err.message });
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
                logIOS('User has active sessions', { email, activeSessions: activeSessionIds ? activeSessionIds.size : 0 });
                return res.status(409).json({
                    success: false,
                    message: 'already_logged_in',
                    activeSessions: activeSessionIds ? activeSessionIds.size : 0
                });
            }

            // If force logout is requested, destroy other sessions
            if (hasActiveSessions && forceLogout === true) {
                logIOS('Force logout requested', { email });
                for (const sessionId of activeSessionIds) {
                    if (sessionId !== req.sessionID) {
                        await new Promise((resolve) => {
                            sessionStore.destroy(sessionId, (err) => {
                                if (err) {
                                    logIOS('Error destroying session', { error: err.message });
                                } else {
                                    logIOS('Destroyed previous session', { sessionId });
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
                    logIOS('Error querying company database', { error: err.message });
                    return res.status(500).json({ 
                        success: false,
                        error: 'Internal Server Error'
                    });
                }

                if (companyResults.length === 0) {
                    logIOS('User not found in company database', { email, dbName });
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

                logIOS('Database selection successful', { userInfo });

                // Set session data
                req.session.user = userInfo;
                req.session.initialized = true;
                
                // Track this session
                if (!activeSessions.has(email)) {
                    activeSessions.set(email, new Set());
                }
                activeSessions.get(email).add(req.sessionID);
                
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

                let redirectUrl = '';
                const userAgent = req.headers['user-agent'] || '';
                const isMobile = /iPhone|iPad|iPod|Android/i.test(userAgent);

                if (row.Access === 'admin' || row.Access === 'AM') {
                    redirectUrl = isMobile ? '/AdminApp.html' : '/Admin.html';
                } else if (row.Access === 'user') {
                    redirectUrl = isMobile ? '/UserApp.html' : '/User.html';
                } else if (row.Access === 'supervisor') {
                    redirectUrl = isMobile ? '/SupervisorApp.html' : '/Supervisor.html';
                }

                // Save session and then respond
                req.session.save((err) => {
                    if (err) {
                        logIOS('Error saving session', { error: err.message });
                        return res.status(500).json({ 
                            success: false,
                            error: 'Failed to create session'
                        });
                    }

                    logIOS('Session saved successfully', { sessionId: req.sessionID });
                    res.json({
                        success: true,
                        message: 'Login successful',
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
        logIOS('Database selection error', { error: error.message });
        res.status(500).json({ 
            success: false,
            error: 'Internal server error'
        });
    }
});

// FIXED: Login route with proper duplicate session prevention
app.post('/submit', async (req, res) => {
    const { email, password, dbName, forceLogout } = req.body;

    logIOS('Login attempt', { email, dbName, forceLogout });

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
                logIOS('Database query error', { error: err.message });
                return res.status(500).json({ 
                    success: false,
                    error: 'Internal Server Error'
                });
            }

            if (results.length === 0) {
                logIOS('User not found', { email });
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
                    logIOS('Error comparing passwords', { error: err.message });
                    return res.status(500).json({ 
                        success: false,
                        error: 'Internal Server Error'
                    });
                }
            }

            if (matchingDatabases.length === 0) {
                logIOS('No matching databases found', { email });
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
                logIOS('User has active sessions', { email, activeSessions: activeSessionIds ? activeSessionIds.size : 0 });
                return res.status(409).json({
                    success: false,
                    message: 'already_logged_in',
                    activeSessions: activeSessionIds ? activeSessionIds.size : 0
                });
            }

            // If force logout is requested, destroy other sessions
            if (hasActiveSessions && forceLogout === true) {
                logIOS('Force logout requested', { email });
                for (const sessionId of activeSessionIds) {
                    if (sessionId !== req.sessionID) {
                        await new Promise((resolve) => {
                            sessionStore.destroy(sessionId, (err) => {
                                if (err) {
                                    logIOS('Error destroying session', { error: err.message });
                                } else {
                                    logIOS('Destroyed previous session', { sessionId });
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
                logIOS('Multiple databases found', { databases: matchingDatabases });
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
                logIOS('Invalid database selection', { dbName, available: matchingDatabases });
                return res.status(400).json({ 
                    success: false,
                    error: 'Invalid database selection' 
                });
            }

            const companyPool = getPool(userDetails.db_name);
            const companySql = `SELECT name, lastName FROM Employees WHERE email = ?`;

            companyPool.query(companySql, [email], (err, companyResults) => {
                if (err) {
                    logIOS('Error querying company database', { error: err.message });
                    return res.status(500).json({ 
                        success: false,
                        error: 'Internal Server Error'
                    });
                }

                if (companyResults.length === 0) {
                    logIOS('User not found in company database', { email, dbName: userDetails.db_name });
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

                logIOS('Login successful', { userInfo });

                // Set session data
                req.session.user = userInfo;
                req.session.initialized = true;
                
                // Track this session
                if (!activeSessions.has(email)) {
                    activeSessions.set(email, new Set());
                }
                activeSessions.get(email).add(req.sessionID);
                
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

                let redirectUrl = '';
                const userAgent = req.headers['user-agent'] || '';
                const isMobile = /iPhone|iPad|iPod|Android/i.test(userAgent);

                if (userDetails.access === 'admin' || userDetails.access === 'AM') {
                    redirectUrl = isMobile ? '/AdminApp.html' : '/Admin.html';
                } else if (userDetails.access === 'user') {
                    redirectUrl = isMobile ? '/UserApp.html' : '/User.html';
                } else if (userDetails.access === 'supervisor') {
                    redirectUrl = isMobile ? '/SupervisorApp.html' : '/Supervisor.html';
                }

                // Save session and then respond
                req.session.save((err) => {
                    if (err) {
                        logIOS('Error saving session', { error: err.message });
                        return res.status(500).json({ 
                            success: false,
                            error: 'Failed to create session'
                        });
                    }

                    logIOS('Session saved successfully', { sessionId: req.sessionID });
                    res.json({
                        success: true,
                        message: 'Login successful',
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
        logIOS('Login error', { error: error.message });
        res.status(500).json({ 
            success: false,
            error: 'Internal server error'
        });
    }
});

// Protected routes - ALWAYS desktop versions for browsers
app.get('/Admin.html', isAuthenticated, isAdmin, (req, res) => {
    logIOS('Serving Admin.html');
    res.sendFile(path.join(__dirname, 'Admin.html'));
});

app.get('/AdminApp.html', isAuthenticated, isAdmin, (req, res) => {
    logIOS('Serving AdminApp.html');
    res.sendFile(path.join(__dirname, 'AdminApp.html'));
});

app.get('/User.html', isAuthenticated, isUser, (req, res) => {
    logIOS('Serving User.html');
    res.sendFile(path.join(__dirname, 'User.html'));
});

app.get('/UserApp.html', isAuthenticated, isUser, (req, res) => {
    logIOS('Serving UserApp.html');
    res.sendFile(path.join(__dirname, 'UserApp.html'));
});

app.get('/Supervisor.html', isAuthenticated, isSupervisor, (req, res) => {
    logIOS('Serving Supervisor.html');
    res.sendFile(path.join(__dirname, 'Supervisor.html'));
});

app.get('/SupervisorApp.html', isAuthenticated, isSupervisor, (req, res) => {
    logIOS('Serving SupervisorApp.html');
    res.sendFile(path.join(__dirname, 'SupervisorApp.html'));
});

// Endpoint to get employees on shift today
app.get('/api/employees-on-shift', isAuthenticated, (req, res) => {
    safeSessionTouch(req);
    const dbName = req.session.user.dbName;
    if (!dbName) return res.status(401).json({ success: false, message: 'User not authenticated' });

    logIOS('Employees on shift request', { dbName });

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
                logIOS('Database error in employees on shift', { error: error.message });
                return res.status(500).json({ success: false, error: 'Database error' });
            }

            logIOS('Employees on shift retrieved', { count: results.length });
            // ... rest of your employees on shift logic
            res.json({
                success: true,
                count: results.length,
                employees: results // simplified for example
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

    logIOS('Labor cost request', { dbName });

    const pool = getPool(dbName);
    const mondayDate = getCurrentMonday();
    
    pool.query(
        `SELECT Weekly_Cost_Before FROM Data WHERE WeekStart = ?`,
        [mondayDate],
        (error, results) => {
            if (error) {
                logIOS('Database error in labor cost', { error: error.message });
                return res.status(500).json({ success: false, error: 'Database error' });
            }
            
            if (results.length === 0) {
                logIOS('No labor cost data found', { week_start_date: mondayDate });
                return res.status(404).json({
                    success: false,
                    message: 'No data found for current week',
                    week_start_date: mondayDate
                });
            }
            
            logIOS('Labor cost retrieved', { cost: results[0].Weekly_Cost_Before });
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

    logIOS('Pending approvals request', { dbName });

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

        logIOS('Pending approvals result', { count: missingDaysCount, checkedDays: daysToCheck });
        res.json({
            success: true,
            count: missingDaysCount,
            checkedDays: daysToCheck
        });

    } catch (error) {
        logIOS('Error in pending approvals', { error: error.message });
        res.status(500).json({ success: false, error: 'Server error' });
    }
});

app.get('/api/tip-approvals', isAuthenticated, async (req, res) => {
    safeSessionTouch(req);
    const dbName = req.session.user.dbName;
    if (!dbName) {
        return res.status(401).json({ success: false, message: 'User not authenticated' });
    }

    logIOS('Tip approvals request', { dbName });

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

        logIOS('Tip approvals result', { count: missingDaysCount, checkedDays: daysToCheck });
        res.json({
            success: true,
            count: missingDaysCount,
            checkedDays: daysToCheck
        });

    } catch (error) {
        logIOS('Error in tip approvals', { error: error.message });
        res.status(500).json({ success: false, error: 'Server error' });
    }
});

// Enhanced logout route with session cleanup
app.get('/logout', (req, res) => {
    logIOS('Logout requested', { 
        sessionId: req.sessionID,
        user: req.session?.user,
        isIOS: req.isIOSApp
    });

    if (req.session) {
        const sessionId = req.sessionID;
        const userEmail = req.session.user?.email;
        
        req.session.destroy(err => {
            if (err) {
                logIOS('Failed to destroy session', { error: err.message });
                return res.redirect('/');
            }
            
            // Remove from active sessions tracking
            if (userEmail && activeSessions.has(userEmail)) {
                activeSessions.get(userEmail).delete(sessionId);
                if (activeSessions.get(userEmail).size === 0) {
                    activeSessions.delete(userEmail);
                }
            }
            
            // Clear the cookie with proper settings
            res.clearCookie('solura.session', {
                path: '/',
                httpOnly: true,
                secure: process.env.NODE_ENV === 'production',
                sameSite: 'lax'
            });
            
            logIOS('Logout successful', { sessionId });
            res.redirect('/');
        });
    } else {
        logIOS('Logout - no session found');
        res.redirect('/');
    }
});

// Enhanced catch-all handler with logging
app.get('*', (req, res) => {
    const requestedPath = path.join(__dirname, req.path);
    const fileExists = fs.existsSync(requestedPath);
    const isFile = fileExists ? fs.statSync(requestedPath).isFile() : false;

    logIOS('Catch-all handler', {
        requestedPath: req.path,
        fullPath: requestedPath,
        fileExists,
        isFile,
        isAPI: req.path.startsWith('/api/')
    });

    if (fileExists && isFile) {
        logIOS('Serving static file via catch-all', { file: req.path });
        res.sendFile(requestedPath);
    } else if (req.path.startsWith('/api/')) {
        logIOS('API endpoint not found', { endpoint: req.path });
        res.status(404).json({ error: 'API endpoint not found' });
    } else {
        logIOS('Redirecting to root', { reason: 'file not found or invalid path' });
        res.redirect('/');
    }
});

// Clean up active sessions tracking when sessions are destroyed
sessionStore.on('destroy', (sessionId) => {
    logIOS('Session destroyed', { sessionId });
    for (const [email, sessionIds] of activeSessions.entries()) {
        if (sessionIds.has(sessionId)) {
            sessionIds.delete(sessionId);
            if (sessionIds.size === 0) {
                activeSessions.delete(email);
            }
            logIOS(`Cleaned up destroyed session`, { sessionId, email });
            break;
        }
    }
});

// Server startup with enhanced logging
app.listen(port, () => {
    console.log(`\n🚀 Server starting...`);
    console.log(`📍 Port: ${port}`);
    console.log(`🌍 Environment: ${isProduction ? 'production' : 'development'}`);
    console.log(`📱 iOS Debugging: ENABLED`);
    
    // Check critical files
    const criticalFiles = ['LoginApp.html', 'Login.html'];
    criticalFiles.forEach(file => {
        const exists = fs.existsSync(path.join(__dirname, file));
        console.log(`📄 ${file}: ${exists ? '✅ Found' : '❌ MISSING'}`);
    });
    
    console.log(`\n🔍 Server listening at http://localhost:${port}`);
    
    const databaseNames = ['bbuonaoxford', '100%pastaoxford'];
    scheduleTestUpdates(databaseNames);
});

// Add process event listeners for debugging
process.on('uncaughtException', (error) => {
    logIOS('UNCAUGHT EXCEPTION', { 
        error: error.message,
        stack: error.stack 
    });
    process.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
    logIOS('UNHANDLED REJECTION', { 
        reason: reason?.message || reason,
        promise: promise 
    });
});