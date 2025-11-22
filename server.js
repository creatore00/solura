// Environment Check: Ensure this file is running in Node.js
// We use an IIFE to create a safe scope and prevent browser execution issues
(function() {
    // Check for Node.js environment variables
    const isNode = typeof process !== 'undefined' && 
                   process.versions && 
                   process.versions.node;

    if (!isNode) {
        console.warn('⚠️ Server-side code (index.js) detected in browser environment. Aborting execution.');
        // Create a dummy exports object if in a module system to prevent import errors
        if (typeof module !== 'undefined') module.exports = {};
        return;
    }

    // Only execute server code if we are in Node
    startServer();
})();

function startServer() {
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

    // Manual cookie parser function
    function parseCookies(cookieHeader) {
        const cookies = {};
        if (cookieHeader && typeof cookieHeader === 'string') {
            cookieHeader.split(';').forEach(cookie => {
                const parts = cookie.trim().split('=');
                if (parts.length >= 2) {
                    const name = parts[0].trim();
                    const value = parts.slice(1).join('=').trim();
                    if (name && value) {
                        try {
                            cookies[name] = decodeURIComponent(value);
                        } catch (e) {
                            cookies[name] = value;
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

    // Enhanced static file serving
    app.use(express.static(__dirname, {
        setHeaders: (res, path) => {
            if (path.endsWith('.js')) {
                res.set('Content-Type', 'application/javascript');
            } else if (path.endsWith('.css')) {
                res.set('Content-Type', 'text/css');
            } else if (path.endsWith('.html')) {
                res.set('Content-Type', 'text/html');
            }
            
            res.set('Access-Control-Allow-Origin', '*');
            res.set('Access-Control-Allow-Methods', 'GET, OPTIONS');
            res.set('Access-Control-Allow-Headers', 'Content-Type, Authorization');
        }
    }));

    // Manual CORS headers
    app.use((req, res, next) => {
        const origin = req.headers.origin;
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
    saveUninitialized: true,
    rolling: true,

    cookie: {
        httpOnly: true,
        secure: isProduction,
        sameSite: isProduction ? 'none' : 'lax',
        domain: isProduction ? '.solura.uk' : undefined,
        maxAge: 24 * 60 * 60 * 1000,
        path: '/',
    }
    }));

    // CRITICAL FIX: Enhanced session persistence middleware
    app.use((req, res, next) => {
    const originalSave = req.session.save;
    req.session.save = function(callback) {
        console.log('💾 Attempting to save session:', req.sessionID);
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

    // iPad-specific session handling
    app.use((req, res, next) => {
        if (req.isIPad) {
            console.log('🔧 iPad-specific session handling initiated');
            
            // Enhanced iPad session recovery
            const cookieHeader = req.headers.cookie;
            const cookies = parseCookies(cookieHeader);
            
            console.log('📱 iPad Session Analysis:', {
                hasCookieHeader: !!cookieHeader,
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
                res.cookie('solura.session', req.sessionID, {
                    maxAge: 24 * 60 * 60 * 1000,
                    httpOnly: false,
                    secure: false,
                    sameSite: 'Lax',
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
        const testSessionId = 'health-check-' + Date.now();
        const testData = { test: true, timestamp: Date.now() };
        
        sessionStore.set(testSessionId, testData, (setErr) => {
            if (setErr) return res.json({ healthy: false, error: 'Store set failed: ' + setErr.message });
            sessionStore.get(testSessionId, (getErr, retrievedData) => {
                if (getErr) return res.json({ healthy: false, error: 'Store get failed: ' + getErr.message });
                sessionStore.destroy(testSessionId, (destroyErr) => {
                    const healthy = retrievedData && retrievedData.test === true;
                    res.json({ healthy, canSet: !setErr, canGet: !getErr && retrievedData, canDestroy: !destroyErr });
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
            res.cookie('solura.session', req.sessionID, {
                maxAge: 24 * 60 * 60 * 1000,
                httpOnly: false,
                secure: false,
                sameSite: 'Lax',
                path: '/',
                domain: isProduction ? '.solura.uk' : undefined
            });
            res.setHeader('X-Session-ID', req.sessionID);
        }
        next();
    });

    // Cookie and session persistence middleware
    app.use((req, res, next) => {
        const originalCookie = res.cookie;
        res.cookie = function(name, value, options = {}) {
            if (name === 'solura.session') {
                options = {
                    maxAge: 24 * 60 * 60 * 1000,
                    httpOnly: false,
                    secure: false,
                    sameSite: 'Lax',
                    path: '/',
                    domain: isProduction ? '.solura.uk' : undefined,
                    ...options
                };
            }
            return originalCookie.call(this, name, value, options);
        };
        
        if (req.sessionID && req.session && req.session.user) {
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
        
        const externalSessionId = sessionCookie || headerSessionId || querySessionId;
        
        if (externalSessionId && externalSessionId !== req.sessionID) {
            console.log('🔄 Attempting to restore session:', externalSessionId);
            
            req.sessionStore.get(externalSessionId, (err, sessionData) => {
                if (err) {
                    console.error('❌ Error loading external session:', err);
                    return next();
                }
                
                if (sessionData && sessionData.user) {
                    console.log('✅ External session restored:', externalSessionId);
                    req.sessionID = externalSessionId;
                    if (!req.session) req.session = {};
                    Object.assign(req.session, sessionData);
                    
                    res.cookie('solura.session', externalSessionId, {
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
        } else {
            next();
        }
    });

    // Routes
    app.get('/', (req, res) => {
        const useMobileApp = isMobileDevice(req);
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
            return res.sendFile(path.join(__dirname, 'LoginApp.html'));
        }
        res.sendFile(path.join(__dirname, 'Login.html'));
    });

    app.get('/LoginApp.html', (req, res) => {
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
        res.sendFile(path.join(__dirname, 'Login.html'));
    });

    // API Endpoints
    app.get('/api/ipad-init', (req, res) => {
        if (!req.session.initialized) {
            req.session.initialized = true;
            req.session.ipadDevice = true;
            req.session.userAgent = req.headers['user-agent'];
        }
        res.cookie('solura.session', req.sessionID, {
            maxAge: 24 * 60 * 60 * 1000,
            httpOnly: false,
            secure: false,
            sameSite: 'Lax',
            path: '/',
            domain: isProduction ? '.solura.uk' : undefined
        });
        res.setHeader('X-Session-ID', req.sessionID);
        res.json({ success: true, sessionId: req.sessionID, message: 'iPad session initialized' });
    });

    app.get('/api/ipad-validate', (req, res) => {
        if (req.session?.user && req.session.ipadDevice) {
            safeSessionTouch(req);
            res.cookie('solura.session', req.sessionID, {
                maxAge: 24 * 60 * 60 * 1000,
                httpOnly: false,
                secure: false,
                sameSite: 'Lax',
                path: '/',
                domain: isProduction ? '.solura.uk' : undefined
            });
            res.json({ valid: true, user: req.session.user, sessionId: req.sessionID });
        } else {
            res.status(401).json({ valid: false, message: 'Invalid session' });
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

    // Other Route Imports
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

    app.post('/api/check-active-session', async (req, res) => {
        const { email } = req.body;
        if (!email) return res.status(400).json({ success: false, error: 'Email is required' });

        try {
            const activeSessionIds = activeSessions.get(email);
            if (activeSessionIds && activeSessionIds.size > 0) {
                const validSessions = [];
                for (const sessionId of activeSessionIds) {
                    await new Promise((resolve) => {
                        sessionStore.get(sessionId, (err, sessionData) => {
                            if (!err && sessionData && sessionData.user && sessionData.user.email === email) {
                                validSessions.push(sessionId);
                            }
                            resolve();
                        });
                    });
                }
                if (validSessions.length === 0) {
                    activeSessions.delete(email);
                } else {
                    activeSessions.set(email, new Set(validSessions));
                }
                if (validSessions.length > 0) {
                    return res.json({ success: true, hasActiveSession: true, activeSessions: validSessions.length });
                }
            }
            res.json({ success: true, hasActiveSession: false });
        } catch (error) {
            res.status(500).json({ success: false, error: 'Internal server error' });
        }
    });

    app.post('/api/force-logout-others', async (req, res) => {
        const { email, keepCurrentSession } = req.body;
        if (!email) return res.status(400).json({ success: false, error: 'Email required' });

        try {
            const activeSessionIds = activeSessions.get(email);
            if (activeSessionIds) {
                const sessionsToDestroy = [];
                for (const sessionId of activeSessionIds) {
                    if (keepCurrentSession && req.sessionID === sessionId) continue;
                    sessionsToDestroy.push(sessionId);
                }
                for (const sessionId of sessionsToDestroy) {
                    await new Promise((resolve) => sessionStore.destroy(sessionId, () => resolve()));
                }
                if (keepCurrentSession && req.sessionID) {
                    activeSessions.set(email, new Set([req.sessionID]));
                } else {
                    activeSessions.delete(email);
                }
            }
            res.json({ success: true });
        } catch (error) {
            res.status(500).json({ success: false, error: 'Internal server error' });
        }
    });

    // Biometric authentication endpoints
    app.post('/api/biometric-login', async (req, res) => {
        safeSessionTouch(req);
        try {
            const { deviceFingerprint } = req.body;
            if (!deviceFingerprint) return res.status(400).json({ success: false, error: 'Fingerprint required' });

            const sql = `SELECT bd.user_email, u.Access, u.db_name FROM biometric_devices bd JOIN users u ON bd.user_email = u.Email WHERE bd.device_fingerprint = ? AND bd.is_active = TRUE`;
            mainPool.query(sql, [deviceFingerprint], (err, results) => {
                if (err) return res.status(500).json({ success: false, error: 'Auth failed' });
                if (results.length === 0) return res.status(401).json({ success: false, error: 'Device not registered' });

                const deviceRecord = results[0];
                const userEmail = deviceRecord.user_email;
                const companyPool = getPool(deviceRecord.db_name);
                
                companyPool.query(`SELECT name, lastName FROM Employees WHERE email = ?`, [userEmail], (err, companyResults) => {
                    if (err || companyResults.length === 0) return res.status(404).json({ success: false, error: 'User not found' });

                    const userInfo = {
                        email: userEmail,
                        role: deviceRecord.Access,
                        name: companyResults[0].name,
                        lastName: companyResults[0].lastName,
                        dbName: deviceRecord.db_name,
                    };

                    req.session.user = userInfo;
                    req.session.initialized = true;
                    req.session.biometricLogin = true;
                    if (req.isIPad) req.session.ipadDevice = true;

                    if (!activeSessions.has(userEmail)) activeSessions.set(userEmail, new Set());
                    activeSessions.get(userEmail).add(req.sessionID);

                    const authToken = generateToken(userInfo);
                    const refreshToken = jwt.sign({ email: userInfo.email }, JWT_SECRET, { expiresIn: '30d' });
                    const useMobileApp = isMobileDevice(req);
                    
                    let redirectUrl = '';
                    if (userInfo.role === 'admin' || userInfo.role === 'AM') redirectUrl = useMobileApp ? '/AdminApp.html' : '/Admin.html';
                    else if (userInfo.role === 'user') redirectUrl = useMobileApp ? '/UserApp.html' : '/User.html';
                    else redirectUrl = useMobileApp ? '/SupervisorApp.html' : '/Supervisor.html';

                    req.session.save((err) => {
                        if (err) return res.status(500).json({ success: false, error: 'Session create failed' });
                        res.json({
                            success: true,
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
            res.status(500).json({ success: false, error: 'Server error' });
        }
    });

    app.post('/api/register-device', async (req, res) => {
        safeSessionTouch(req);
        try {
            const { email, deviceFingerprint, deviceInfo } = req.body;
            if (!email || !deviceFingerprint || !deviceInfo) return res.status(400).json({ success: false, error: 'Missing fields' });

            const sql = `INSERT INTO biometric_devices (user_email, device_fingerprint, device_name, platform, user_agent, screen_resolution, hardware_concurrency, timezone, language, registration_date, last_used, is_active) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NOW(), NOW(), TRUE) ON DUPLICATE KEY UPDATE last_used = NOW(), is_active = TRUE`;
            
            mainPool.query(sql, [
                email, deviceFingerprint, `Device-${deviceFingerprint.substring(0, 8)}`,
                deviceInfo.platform, deviceInfo.userAgent, deviceInfo.screenResolution || 'unknown',
                0, deviceInfo.timezone || 'UTC', deviceInfo.language || 'en'
            ], (err) => {
                if (err) {
                    console.error(err);
                    return res.status(500).json({ success: false, error: 'Register failed' });
                }
                res.json({ success: true, message: 'Device registered' });
            });
        } catch (error) {
            res.status(500).json({ success: false, error: 'Server error' });
        }
    });

    app.post('/api/check-device-registration', async (req, res) => {
        safeSessionTouch(req);
        try {
            const deviceFingerprint = req.headers['x-device-fingerprint'] || req.body.deviceFingerprint;
            if (!deviceFingerprint) return res.status(400).json({ success: false, error: 'Fingerprint required' });

            const sql = `SELECT bd.* FROM biometric_devices bd WHERE bd.device_fingerprint = ? AND bd.is_active = TRUE`;
            mainPool.query(sql, [deviceFingerprint], (err, results) => {
                if (err) return res.status(500).json({ success: false, error: 'Check failed' });
                if (results.length > 0) {
                    res.json({ success: true, registered: true, deviceInfo: results[0] });
                } else {
                    res.json({ success: true, registered: false });
                }
            });
        } catch (error) {
            res.status(500).json({ success: false, error: 'Server error' });
        }
    });

    app.post('/api/ios-session-setup', (req, res) => {
        if (!req.session.initialized) {
            req.session.initialized = true;
            req.session.iosDevice = true;
            req.session.userAgent = req.headers['user-agent'];
        }
        res.cookie('solura.session', req.sessionID, {
            maxAge: 24 * 60 * 60 * 1000,
            httpOnly: false,
            secure: false,
            sameSite: 'Lax',
            path: '/'
        });
        res.json({ success: true, sessionId: req.sessionID, message: 'iOS session configured' });
    });

    app.get('/api/validate-session', (req, res) => {
        if (req.session?.user) {
            safeSessionTouch(req);
            res.json({ valid: true, user: req.session.user, sessionId: req.sessionID });
        } else {
            res.status(401).json({ valid: false, message: 'No active session' });
        }
    });

    // Enhanced login with biometric support
    app.post('/submit', async (req, res) => {
        const { email, password, dbName, forceLogout, enableBiometric, deviceFingerprint } = req.body;
        if (!email || !password) return res.status(400).json({ success: false, message: 'Credentials required' });

        try {
            const sql = `SELECT u.Access, u.Password, u.Email, u.db_name FROM users u WHERE u.Email = ?`;
            mainPool.query(sql, [email], async (err, results) => {
                if (err || results.length === 0) return res.status(401).json({ success: false, message: 'Invalid credentials' });

                let matchingDatabases = [];
                for (const row of results) {
                    const isMatch = await bcrypt.compare(password, row.Password);
                    if (isMatch) matchingDatabases.push({ db_name: row.db_name, access: row.Access });
                }

                if (matchingDatabases.length === 0) return res.status(401).json({ success: false, message: 'Invalid credentials' });

                // Active session check
                const activeSessionIds = activeSessions.get(email);
                if (activeSessionIds && activeSessionIds.size > 0 && forceLogout !== true) {
                    return res.status(409).json({ success: false, message: 'already_logged_in', activeSessions: activeSessionIds.size });
                }

                if (forceLogout === true && activeSessionIds) {
                    for (const sessionId of activeSessionIds) {
                        if (sessionId !== req.sessionID) {
                            await new Promise(resolve => sessionStore.destroy(sessionId, resolve));
                        }
                    }
                    activeSessions.set(email, new Set([req.sessionID]));
                }

                if (matchingDatabases.length > 1 && !dbName) {
                    return res.status(200).json({ success: true, requiresDbSelection: true, databases: matchingDatabases });
                }

                const userDetails = dbName ? matchingDatabases.find(db => db.db_name === dbName) : matchingDatabases[0];
                const companyPool = getPool(userDetails.db_name);
                
                companyPool.query(`SELECT name, lastName FROM Employees WHERE email = ?`, [email], (err, companyResults) => {
                    if (err || companyResults.length === 0) return res.status(401).json({ success: false, message: 'User not found in company DB' });

                    const userInfo = {
                        email: email,
                        role: userDetails.access,
                        name: companyResults[0].name,
                        lastName: companyResults[0].lastName,
                        dbName: userDetails.db_name,
                    };

                    req.session.user = userInfo;
                    req.session.initialized = true;
                    if (req.isIPad) req.session.ipadDevice = true;

                    if (!activeSessions.has(email)) activeSessions.set(email, new Set());
                    activeSessions.get(email).add(req.sessionID);

                    // Biometric auto-registration
                    if (enableBiometric && deviceFingerprint) {
                        const regSql = `INSERT INTO biometric_devices (user_email, device_fingerprint, is_active, last_used) VALUES (?, ?, TRUE, NOW()) ON DUPLICATE KEY UPDATE is_active=TRUE, last_used=NOW()`;
                        mainPool.query(regSql, [email, deviceFingerprint]);
                    }

                    const authToken = generateToken(userInfo);
                    const refreshToken = jwt.sign({ email: userInfo.email }, JWT_SECRET, { expiresIn: '30d' });
                    const useMobileApp = isMobileDevice(req);
                    
                    let redirectUrl = '';
                    if (userDetails.access === 'admin' || userDetails.access === 'AM') redirectUrl = useMobileApp ? '/AdminApp.html' : '/Admin.html';
                    else if (userDetails.access === 'user') redirectUrl = useMobileApp ? '/UserApp.html' : '/User.html';
                    else redirectUrl = useMobileApp ? '/SupervisorApp.html' : '/Supervisor.html';

                    res.cookie('solura.session', req.sessionID, {
                        maxAge: 24 * 60 * 60 * 1000,
                        httpOnly: !req.isIPad,
                        secure: isProduction && !req.isIPad,
                        sameSite: req.isIPad ? 'Lax' : (isProduction ? 'none' : 'lax'),
                        path: '/',
                        domain: isProduction ? '.solura.uk' : undefined
                    });

                    if (useMobileApp) res.setHeader('X-Session-ID', req.sessionID);

                    req.session.save((err) => {
                        if (err) return res.status(500).json({ success: false, error: 'Session save failed' });
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
            res.status(500).json({ success: false, error: 'Internal server error' });
        }
    });

    // Additional endpoints from second version
    app.get('/api/current-user', isAuthenticated, (req, res) => {
        safeSessionTouch(req);
        res.json({
            success: true,
            user: req.session.user
        });
    });

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

    app.get('/api/validate-session-real-time', async (req, res) => {
        console.log('=== REAL-TIME SESSION VALIDATION ===');
        console.log('Session ID from cookie:', req.sessionID);
        console.log('Session exists:', !!req.session);
        console.log('Session User:', req.session?.user);
        
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
        
        if (!activeSessionIds || !activeSessionIds.has(req.sessionID)) {
            console.log('🚫 Session terminated - no longer in active sessions');
            
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

        safeSessionTouch(req);
        
        res.json({
            valid: true,
            user: req.session.user,
            sessionId: req.sessionID,
            activeSessions: activeSessionIds ? Array.from(activeSessionIds) : [],
            message: 'Session is valid'
        });
    });

    app.get('/api/session-heartbeat', (req, res) => {
        console.log('💓 Heartbeat connection established - Session ID:', req.sessionID);
        
        res.writeHead(200, {
            'Content-Type': 'text/event-stream',
            'Cache-Control': 'no-cache',
            'Connection': 'keep-alive',
            'Access-Control-Allow-Origin': req.headers.origin || '*',
            'Access-Control-Allow-Credentials': 'true'
        });

        res.write('data: ' + JSON.stringify({
            type: 'connected',
            message: 'Heartbeat connection established',
            sessionId: req.sessionID,
            timestamp: Date.now()
        }) + '\n\n');

        let isConnected = true;

        const checkSession = () => {
            if (!isConnected) return;

            try {
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

        checkSession();
        const intervalId = setInterval(checkSession, 10000);

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

                    req.session.user = {
                        email: email,
                        role: userDetails.Access,
                        name: name,
                        lastName: lastName,
                        dbName: dbName,
                    };

                    if (req.isIPad) {
                        req.session.ipadDevice = true;
                        console.log('📱 iPad database switch - preserving device type');
                    }

                    console.log('🔄 Database switching - Same session ID:', req.sessionID);
                    console.log('🔄 Updated session user:', req.session.user);

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

    app.get('/api/init-session', (req, res) => {
        console.log('🔄 Initializing session');
        
        if (!req.session.initialized) {
            req.session.initialized = true;
        }
        
        if (req.isIPad) {
            req.session.ipadDevice = true;
            console.log('📱 iPad session initialization');
        }
        
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

    // Authentication Middleware
    function isAuthenticated(req, res, next) {
        console.log('=== AUTH CHECK ===');
        console.log('Session ID:', req.sessionID);
        console.log('Session exists:', !!req.session);
        console.log('Session User:', req.session?.user);
        console.log('iPad Device:', req.session?.ipadDevice);
        
        const sessionIdFromHeader = req.headers['x-session-id'];
        const sessionIdFromQuery = req.query.sessionId;
        
        if ((!req.session?.user) && (sessionIdFromHeader || sessionIdFromQuery)) {
            const externalSessionId = sessionIdFromHeader || sessionIdFromQuery;
            console.log('📱 iOS/iPad - Attempting session recovery from external ID:', externalSessionId);
            
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
            
            if (req.isIPad && !req.session.ipadDevice) {
                console.log('📱 iPad session - marking as iPad device');
                req.session.ipadDevice = true;
                req.session.save(() => {});
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

    // Protected HTML Routes
    app.get('/Admin.html', isAuthenticated, isAdmin, (req, res) => {
        if (req.isIPad && req.session) {
            safeSessionTouch(req);
        }
        res.sendFile(path.join(__dirname, 'Admin.html'));
    });

    app.get('/AdminApp.html', isAuthenticated, isAdmin, (req, res) => {
        if (req.isIPad && req.session) {
            safeSessionTouch(req);
        }
        res.sendFile(path.join(__dirname, 'AdminApp.html'));
    });

    app.get('/User.html', isAuthenticated, isUser, (req, res) => {
        if (req.isIPad && req.session) {
            safeSessionTouch(req);
        }
        res.sendFile(path.join(__dirname, 'User.html'));
    });

    app.get('/UserApp.html', isAuthenticated, isUser, (req, res) => {
        if (req.isIPad && req.session) {
            safeSessionTouch(req);
        }
        res.sendFile(path.join(__dirname, 'UserApp.html'));
    });

    app.get('/Supervisor.html', isAuthenticated, isSupervisor, (req, res) => {
        if (req.isIPad && req.session) {
            safeSessionTouch(req);
        }
        res.sendFile(path.join(__dirname, 'Supervisor.html'));
    });

    app.get('/SupervisorApp.html', isAuthenticated, isSupervisor, (req, res) => {
        if (req.isIPad && req.session) {
            safeSessionTouch(req);
        }
        res.sendFile(path.join(__dirname, 'SupervisorApp.html'));
    });

    // Additional business endpoints from second version
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
}