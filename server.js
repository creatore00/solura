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

// CRITICAL FIX: Session operation queue to prevent race conditions
const sessionOperationQueue = new Map(); // sessionId -> operation promises

// OPTIMIZED: Safe session touch utility with queueing
async function safeSessionTouch(req) {
    const sessionId = req.sessionID;
    if (!sessionId || !req.session) return;

    // If there's already an operation for this session, wait for it
    if (sessionOperationQueue.has(sessionId)) {
        await sessionOperationQueue.get(sessionId);
    }

    const touchPromise = new Promise((resolve) => {
        try {
            if (req.session.touch && typeof req.session.touch === 'function') {
                req.session.touch((err) => {
                    if (err) {
                        // Fallback: manually extend session
                        if (req.session.cookie) {
                            req.session.cookie.maxAge = req.session.cookie.originalMaxAge || 24 * 60 * 60 * 1000;
                        }
                    }
                    resolve();
                });
            } else if (req.session.cookie) {
                req.session.cookie.maxAge = req.session.cookie.originalMaxAge || 24 * 60 * 60 * 1000;
                resolve();
            } else {
                resolve();
            }
        } catch (error) {
            console.log('Session touch error, using fallback');
            resolve();
        }
    });

    sessionOperationQueue.set(sessionId, touchPromise);
    await touchPromise;
    sessionOperationQueue.delete(sessionId);
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

// OPTIMIZED: CORS configuration for iOS
const corsOptions = {
    origin: function (origin, callback) {
        const allowedOrigins = [
            'https://www.solura.uk', 
            'https://solura.uk', 
            'http://localhost:8080',
            'http://localhost:3000',
            'capacitor://localhost',
            'ionic://localhost'
        ];
        
        // Allow requests with no origin (like mobile apps)
        if (!origin) return callback(null, true);
        
        if (allowedOrigins.indexOf(origin) !== -1 || origin.includes('localhost')) {
            callback(null, true);
        } else {
            console.log('Blocked by CORS:', origin);
            callback(new Error('Not allowed by CORS'));
        }
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'Cookie', 'Accept', 'X-Session-ID'],
    exposedHeaders: ['Set-Cookie', 'X-Session-ID']
};

app.use(cors(corsOptions));

// Handle preflight requests
app.options('*', cors(corsOptions));

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(express.static(__dirname));

// FIXED: Cookie cleanup middleware
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

// OPTIMIZED: Reduced session debugging (only log errors)
app.use((req, res, next) => {
    // Only log session issues, not every request
    const shouldLog = req.path.includes('/api/') && (Math.random() < 0.01 || !req.session?.user);
    
    if (shouldLog) {
        console.log('=== SESSION DEBUG ===');
        console.log('URL:', req.url);
        console.log('Session ID:', req.sessionID);
        console.log('Session User:', req.session?.user?.email);
        console.log('=== END DEBUG ===');
    }
    next();
});

// FIXED: MySQL session store with better configuration
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
    clearExpired: true
}, mainPool);

// CRITICAL FIX: Session configuration optimized for iOS
app.use(session({
    secret: SESSION_SECRET,
    resave: false, // Changed to false to prevent race conditions
    saveUninitialized: false, // Changed to false to reduce unnecessary sessions
    store: sessionStore,
    name: 'solura.session',
    cookie: {
        secure: isProduction,
        httpOnly: true,
        sameSite: isProduction ? 'none' : 'lax',
        maxAge: 24 * 60 * 60 * 1000, // 24 hours
        domain: isProduction ? '.solura.uk' : undefined
    },
    rolling: true,
    proxy: true,
    genid: function(req) {
        return require('crypto').randomBytes(16).toString('hex');
    }
}));

// OPTIMIZED: iOS-specific middleware with caching
const iosSessionCache = new Map();

app.use((req, res, next) => {
    const userAgent = req.headers['user-agent'] || '';
    const isIOS = /iPhone|iPad|iPod/i.test(userAgent);
    
    if (isIOS) {
        req.isIOS = true;
        
        const sessionIdFromUrl = req.query.sessionId;
        const sessionIdFromHeader = req.headers['x-session-id'];
        const externalSessionId = sessionIdFromUrl || sessionIdFromHeader;
        
        if (externalSessionId && (!req.sessionID || req.sessionID !== externalSessionId)) {
            // Check cache first
            if (iosSessionCache.has(externalSessionId)) {
                const cached = iosSessionCache.get(externalSessionId);
                if (Date.now() - cached.timestamp < 30000) { // 30 second cache
                    Object.assign(req.session, cached.data);
                    req.sessionID = externalSessionId;
                    return next();
                }
            }
            
            // Load from store
            req.sessionStore.get(externalSessionId, (err, sessionData) => {
                if (err) {
                    console.error('Error loading external session:', err);
                    return next();
                }
                
                if (sessionData && sessionData.user) {
                    Object.assign(req.session, sessionData);
                    req.sessionID = externalSessionId;
                    
                    // Cache for future requests
                    iosSessionCache.set(externalSessionId, {
                        data: sessionData,
                        timestamp: Date.now()
                    });
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

// SECURITY: Block direct access to protected HTML files
app.use((req, res, next) => {
    const protectedRoutes = [
        '/Admin.html', '/AdminApp.html',
        '/User.html', '/UserApp.html', 
        '/Supervisor.html', '/SupervisorApp.html'
    ];
    
    if (protectedRoutes.includes(req.path) && !req.session?.user) {
        console.log('🚫 SECURITY: Blocked direct access to protected route:', req.path);
        return res.redirect('/');
    }
    
    next();
});

// OPTIMIZED: Session middleware for API endpoints
app.use('/api/', async (req, res, next) => {
    if (req.session && typeof req.session.reload === 'function') {
        try {
            await new Promise((resolve, reject) => {
                req.session.reload((err) => {
                    if (err) {
                        console.error('Error reloading session:', err);
                    }
                    resolve();
                });
            });
        } catch (error) {
            console.error('Session reload error:', error);
        }
    }
    next();
});

// Add CORS headers manually
app.use((req, res, next) => {
    const origin = req.headers.origin;
    const allowedOrigins = ['https://www.solura.uk', 'https://solura.uk', 'http://localhost:8080', 'http://localhost:3000'];
    
    if (origin && allowedOrigins.includes(origin)) {
        res.header('Access-Control-Allow-Origin', origin);
    }
    res.header('Access-Control-Allow-Credentials', 'true');
    res.header('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS');
    res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization, Content-Length, X-Requested-With, Cookie, X-Session-ID');
    res.header('Access-Control-Expose-Headers', 'Set-Cookie, X-Session-ID');
    
    if (req.method === 'OPTIONS') {
        return res.sendStatus(200);
    }
    next();
});

// ENHANCED: Global error handler
app.use((error, req, res, next) => {
    console.error('🚨 Global error handler:', error.message);
    
    if (error.message && error.message.includes('touch')) {
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

// OPTIMIZED: Rate limiting with proper storage
const rateLimitMap = new Map();
app.use((req, res, next) => {
    // Security headers
    res.header('X-Content-Type-Options', 'nosniff');
    res.header('X-Frame-Options', 'DENY');
    res.header('X-XSS-Protection', '1; mode=block');
    res.header('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    
    // Rate limiting for login attempts
    if ((req.path === '/submit' || req.path === '/submit-database') && req.method === 'POST') {
        const clientIP = req.ip || req.connection.remoteAddress;
        const now = Date.now();
        const windowStart = now - (15 * 60 * 1000);
        
        if (!rateLimitMap.has(clientIP)) {
            rateLimitMap.set(clientIP, []);
        }
        
        const attempts = rateLimitMap.get(clientIP).filter(time => time > windowStart);
        rateLimitMap.set(clientIP, attempts);
        
        if (attempts.length >= 5) {
            return res.status(429).json({
                success: false,
                error: 'Too many login attempts. Please try again in 15 minutes.'
            });
        }
        
        attempts.push(now);
    }
    
    next();
});

// Enhanced session tracking
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
            }
            if (callback) callback(err);
        });
    };
    next();
});

// ENHANCED: Root route with mobile/desktop detection
app.get('/', (req, res) => {
    const userAgent = req.headers['user-agent'] || '';
    const referer = req.headers.referer || '';

    const isCapacitorApp = 
        /Capacitor/.test(userAgent) ||
        /ionic/.test(userAgent) ||
        referer.startsWith('file://') ||
        req.headers['x-capacitor'] === 'true' ||
        req.query.capacitor === 'true';

    const fileToServe = isCapacitorApp ? 'LoginApp.html' : 'Login.html';
    res.sendFile(path.join(__dirname, fileToServe));
});

// Health check endpoint
app.get('/health', (req, res) => {
    res.json({
        status: 'OK',
        session: {
            id: req.sessionID,
            exists: !!req.session,
            user: req.session?.user,
        },
        timestamp: new Date().toISOString(),
        uptime: process.uptime()
    });
});

// ALL YOUR ORIGINAL ROUTES
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

// NEW: iOS session initialization endpoint
app.get('/api/ios-init', async (req, res) => {
    try {
        if (!req.session.initialized) {
            req.session.initialized = true;
            await new Promise((resolve, reject) => {
                req.session.save((err) => {
                    if (err) reject(err);
                    else resolve();
                });
            });
        }
        
        res.json({
            success: true,
            sessionId: req.sessionID,
            message: 'iOS session initialized'
        });
    } catch (error) {
        console.error('iOS init error:', error);
        res.json({
            success: true,
            sessionId: req.sessionID,
            message: 'Session available'
        });
    }
});

// OPTIMIZED: Check active sessions
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
            return res.json({
                success: true,
                hasActiveSession: true,
                activeSessions: activeSessionIds.size,
                message: `You are already logged in on ${activeSessionIds.size} device(s).`
            });
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

// OPTIMIZED: Force logout
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
            
            // Destroy sessions in parallel with limit
            const destroyPromises = sessionsToDestroy.map(sessionId => 
                new Promise((resolve) => {
                    sessionStore.destroy(sessionId, (err) => {
                        if (!err) {
                            loggedOutCount++;
                        }
                        resolve();
                    });
                })
            );
            
            await Promise.all(destroyPromises);
            
            if (keepCurrentSession && req.sessionID) {
                activeSessions.set(email, new Set([req.sessionID]));
            } else {
                activeSessions.delete(email);
            }
        }

        res.json({
            success: true,
            loggedOutCount: loggedOutCount,
            message: `Logged out from ${loggedOutCount} other session(s)`
        });

    } catch (error) {
        console.error('Error force logging out:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Internal server error' 
        });
    }
});

// OPTIMIZED: Biometric authentication
app.post('/api/verify-biometric', async (req, res) => {
    try {
        await safeSessionTouch(req);
        const { email, accessToken } = req.body;

        if (!email || !accessToken) {
            return res.status(400).json({ 
                success: false,
                error: 'Email and access token are required' 
            });
        }

        // Verify the access token
        try {
            const decoded = jwt.verify(accessToken, JWT_SECRET);
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

        // Get user info from database
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

            const userDetails = results[0];
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

                const userInfo = {
                    email: email,
                    role: userDetails.Access,
                    name: companyResults[0].name,
                    lastName: companyResults[0].lastName,
                    dbName: userDetails.db_name,
                };

                // Create session
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
                    userInfo,
                    process.env.JWT_REFRESH_SECRET || 'your-refresh-secret',
                    { expiresIn: '30d' }
                );

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

// Token refresh endpoint
app.post('/api/refresh-token', async (req, res) => {
    try {
        await safeSessionTouch(req);
        const { refreshToken } = req.body;

        if (!refreshToken) {
            return res.status(400).json({ 
                success: false,
                error: 'Refresh token is required' 
            });
        }

        try {
            const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET || 'your-refresh-secret');
            const newAccessToken = generateToken(decoded);

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

// OPTIMIZED: Session validation with caching
const sessionValidationCache = new Map();
app.get('/api/validate-session', async (req, res) => {
    try {
        await safeSessionTouch(req);
        
        const cacheKey = req.sessionID;
        const cacheTime = 5000; // 5 seconds cache
        
        // Check cache first
        if (sessionValidationCache.has(cacheKey)) {
            const cached = sessionValidationCache.get(cacheKey);
            if (Date.now() - cached.timestamp < cacheTime) {
                return res.json(cached.response);
            }
        }
        
        let response;
        
        if (req.session?.user) {
            response = { 
                valid: true, 
                user: req.session.user,
                sessionId: req.sessionID 
            };
        } else {
            response = { 
                valid: false,
                message: 'No active session'
            };
        }
        
        // Cache the response
        sessionValidationCache.set(cacheKey, {
            response: response,
            timestamp: Date.now()
        });
        
        res.json(response);
        
    } catch (error) {
        console.error('Session validation error:', error);
        res.json({ 
            valid: false,
            message: 'Session validation error'
        });
    }
});

// OPTIMIZED: Real-time session validation
app.get('/api/validate-session-real-time', async (req, res) => {
    try {
        if (req.session?.user) {
            await safeSessionTouch(req);
            
            res.json({
                valid: true,
                user: req.session.user,
                sessionId: req.sessionID,
                message: 'Session is valid'
            });
        } else {
            res.json({
                valid: false,
                reason: 'no_session_user',
                message: 'Please log in again'
            });
        }
    } catch (error) {
        console.error('Real-time session validation error:', error);
        res.json({
            valid: false,
            reason: 'validation_error',
            message: 'Session validation failed'
        });
    }
});

// OPTIMIZED: Simplified heartbeat endpoint
app.get('/api/session-heartbeat', (req, res) => {
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
    let heartbeatCount = 0;

    // Send heartbeat every 30 seconds instead of 10
    const intervalId = setInterval(() => {
        if (!isConnected) return;

        try {
            heartbeatCount++;
            
            const isValid = !!(req.session?.user);
            
            res.write('data: ' + JSON.stringify({
                valid: isValid,
                type: 'heartbeat',
                count: heartbeatCount,
                timestamp: Date.now()
            }) + '\n\n');

            // Close connection after 10 minutes to prevent resource leaks
            if (heartbeatCount > 20) {
                clearInterval(intervalId);
                res.end();
            }
        } catch (error) {
            console.error('Heartbeat error:', error);
        }
    }, 30000); // 30 seconds

    req.on('close', () => {
        isConnected = false;
        clearInterval(intervalId);
    });

    req.on('error', (error) => {
        console.error('Heartbeat connection error:', error);
        isConnected = false;
        clearInterval(intervalId);
    });
});

// Get current user info
app.get('/api/current-user', isAuthenticated, async (req, res) => {
    try {
        await safeSessionTouch(req);
        res.json({
            success: true,
            user: req.session.user
        });
    } catch (error) {
        console.error('Current user error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Failed to get user info' 
        });
    }
});

// Get available databases
app.get('/api/user-databases', isAuthenticated, async (req, res) => {
    try {
        await safeSessionTouch(req);
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
    } catch (error) {
        console.error('User databases error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Internal server error' 
        });
    }
});

// OPTIMIZED: Switch database
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
        await safeSessionTouch(req);
        
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

                // Update session
                req.session.user = {
                    email: email,
                    role: userDetails.Access,
                    name: companyResults[0].name,
                    lastName: companyResults[0].lastName,
                    dbName: dbName,
                };

                req.session.save((err) => {
                    if (err) {
                        console.error('Error saving session after database switch:', err);
                        return res.status(500).json({ 
                            success: false, 
                            error: 'Failed to update session' 
                        });
                    }

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

// OPTIMIZED: iOS session restoration
app.post('/api/ios-restore-session', async (req, res) => {
    try {
        await safeSessionTouch(req);
        const { email, dbName, accessToken, sessionId } = req.body;
        
        if (!email || !dbName || !accessToken) {
            return res.status(400).json({ 
                success: false, 
                error: 'Missing required parameters' 
            });
        }

        // Verify the access token
        try {
            const decoded = jwt.verify(accessToken, JWT_SECRET);
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

                // Use existing session or create new one
                if (sessionId) {
                    req.sessionID = sessionId;
                }
                
                req.session.user = userInfo;
                req.session.initialized = true;
                
                // Track this session
                if (!activeSessions.has(email)) {
                    activeSessions.set(email, new Set());
                }
                activeSessions.get(email).add(req.sessionID);
                
                req.session.save((err) => {
                    if (err) {
                        console.error('Error saving iOS session:', err);
                        return res.status(500).json({ 
                            success: false, 
                            error: 'Failed to save session' 
                        });
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
        
    } catch (error) {
        console.error('iOS session restoration error:', error);
        res.status(500).json({ 
            success: false, 
            error: error.message 
        });
    }
});

// OPTIMIZED: Session recovery
app.post('/api/recover-session', async (req, res) => {
    try {
        await safeSessionTouch(req);
        const { email, dbName, accessToken } = req.body;
        
        if (!email || !dbName || !accessToken) {
            return res.status(400).json({ 
                success: false, 
                error: 'Missing email, dbName, or accessToken' 
            });
        }

        // Verify access token
        try {
            const decoded = jwt.verify(accessToken, JWT_SECRET);
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

                req.session.user = userInfo;
                req.session.initialized = true;
                
                if (!activeSessions.has(email)) {
                    activeSessions.set(email, new Set());
                }
                activeSessions.get(email).add(req.sessionID);
                
                req.session.save((err) => {
                    if (err) {
                        console.error('Error saving recovered session:', err);
                        return res.status(500).json({ 
                            success: false, 
                            error: 'Failed to restore session' 
                        });
                    }

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

// OPTIMIZED: Authentication middleware
async function isAuthenticated(req, res, next) {
    try {
        // Simple check - only validate session user data
        if (req.session?.user && req.session.user.dbName && req.session.user.email) {
            await safeSessionTouch(req);
            return next();
        }
        
        // For API calls, return JSON error
        if (req.path.startsWith('/api/') || req.xhr) {
            return res.status(401).json({ 
                success: false, 
                error: 'Unauthorized',
                message: 'Please log in again',
                requiresLogin: true
            });
        }
        
        // For HTML pages, redirect to login
        res.redirect('/');
    } catch (error) {
        console.error('Auth middleware error:', error);
        
        if (req.path.startsWith('/api/') || req.xhr) {
            res.status(500).json({ 
                success: false, 
                error: 'Authentication error'
            });
        } else {
            res.redirect('/');
        }
    }
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

// OPTIMIZED: Database selection
app.post('/submit-database', async (req, res) => {
    const { email, password, dbName, forceLogout } = req.body;

    if (!email || !password || !dbName) {
        return res.status(400).json({ 
            success: false,
            message: 'Email, password, and database name are required' 
        });
    }

    try {
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

            const row = results[0];
            try {
                const isMatch = await bcrypt.compare(password, row.Password);
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
            const hasActiveSessions = activeSessionIds && activeSessionIds.size > 0;

            if (hasActiveSessions && forceLogout !== true) {
                return res.status(409).json({
                    success: false,
                    message: 'already_logged_in',
                    activeSessions: activeSessionIds.size
                });
            }

            if (hasActiveSessions && forceLogout === true) {
                for (const sessionId of activeSessionIds) {
                    if (sessionId !== req.sessionID) {
                        await new Promise((resolve) => {
                            sessionStore.destroy(sessionId, (err) => {
                                resolve();
                            });
                        });
                    }
                }
                activeSessions.set(email, new Set([req.sessionID]));
            }

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

                const userInfo = {
                    email: email,
                    role: row.Access,
                    name: companyResults[0].name,
                    lastName: companyResults[0].lastName,
                    dbName: dbName,
                };

                req.session.user = userInfo;
                req.session.initialized = true;
                
                if (!activeSessions.has(email)) {
                    activeSessions.set(email, new Set());
                }
                activeSessions.get(email).add(req.sessionID);
                
                const authToken = generateToken(userInfo);
                const refreshToken = jwt.sign(
                    userInfo,
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
        console.error('Database selection error:', error);
        res.status(500).json({ 
            success: false,
            error: 'Internal server error'
        });
    }
});

// OPTIMIZED: Login route
app.post('/submit', async (req, res) => {
    const { email, password, dbName, forceLogout } = req.body;

    if (!email || !password) {
        return res.status(400).json({ 
            success: false,
            message: 'Email and password are required' 
        });
    }

    try {
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
                try {
                    const isMatch = await bcrypt.compare(password, row.Password);
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

            const activeSessionIds = activeSessions.get(email);
            const hasActiveSessions = activeSessionIds && activeSessionIds.size > 0;

            if (hasActiveSessions && forceLogout !== true) {
                return res.status(409).json({
                    success: false,
                    message: 'already_logged_in',
                    activeSessions: activeSessionIds.size
                });
            }

            if (hasActiveSessions && forceLogout === true) {
                for (const sessionId of activeSessionIds) {
                    if (sessionId !== req.sessionID) {
                        await new Promise((resolve) => {
                            sessionStore.destroy(sessionId, (err) => {
                                resolve();
                            });
                        });
                    }
                }
                activeSessions.set(email, new Set([req.sessionID]));
            }

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

                const userInfo = {
                    email: email,
                    role: userDetails.access,
                    name: companyResults[0].name,
                    lastName: companyResults[0].lastName,
                    dbName: userDetails.db_name,
                };

                req.session.user = userInfo;
                req.session.initialized = true;
                
                if (!activeSessions.has(email)) {
                    activeSessions.set(email, new Set());
                }
                activeSessions.get(email).add(req.sessionID);
                
                const authToken = generateToken(userInfo);
                const refreshToken = jwt.sign(
                    userInfo,
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
        console.error('Login error:', error);
        res.status(500).json({ 
            success: false,
            error: 'Internal server error'
        });
    }
});

// Protected routes
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
app.get('/api/employees-on-shift', isAuthenticated, async (req, res) => {
    try {
        await safeSessionTouch(req);
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
    } catch (error) {
        console.error('Employees on shift error:', error);
        res.status(500).json({ success: false, error: 'Server error' });
    }
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
app.get('/api/labor-cost', isAuthenticated, async (req, res) => {
    try {
        await safeSessionTouch(req);
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
    } catch (error) {
        console.error('Labor cost error:', error);
        res.status(500).json({ success: false, error: 'Server error' });
    }
});

// API routes
app.get('/api/pending-approvals', isAuthenticated, async (req, res) => {
    try {
        await safeSessionTouch(req);
        const dbName = req.session.user.dbName;
        if (!dbName) {
            return res.status(401).json({ success: false, message: 'User not authenticated' });
        }

        const pool = getPool(dbName);
        const today = new Date();
        const currentMonth = today.getMonth() + 1;
        const currentYear = today.getFullYear();

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
    try {
        await safeSessionTouch(req);
        const dbName = req.session.user.dbName;
        if (!dbName) {
            return res.status(401).json({ success: false, message: 'User not authenticated' });
        }

        const pool = getPool(dbName);
        const today = new Date();
        const currentMonth = today.getMonth() + 1;
        const currentYear = today.getFullYear();

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
                secure: process.env.NODE_ENV === 'production',
                sameSite: 'lax'
            });
            
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
        res.sendFile(requestedPath);
    } else if (req.path.startsWith('/api/')) {
        res.status(404).json({ error: 'API endpoint not found' });
    } else {
        res.redirect('/');
    }
});

// Clean up active sessions tracking
sessionStore.on('destroy', (sessionId) => {
    for (const [email, sessionIds] of activeSessions.entries()) {
        if (sessionIds.has(sessionId)) {
            sessionIds.delete(sessionId);
            if (sessionIds.size === 0) {
                activeSessions.delete(email);
            }
            break;
        }
    }
    sessionValidationCache.delete(sessionId);
    iosSessionCache.delete(sessionId);
});

// Clean up caches periodically
setInterval(() => {
    const now = Date.now();
    
    // Clean session validation cache (5 minute TTL)
    for (const [key, value] of sessionValidationCache.entries()) {
        if (now - value.timestamp > 300000) {
            sessionValidationCache.delete(key);
        }
    }
    
    // Clean iOS session cache (30 second TTL)
    for (const [key, value] of iosSessionCache.entries()) {
        if (now - value.timestamp > 30000) {
            iosSessionCache.delete(key);
        }
    }
    
    // Clean rate limit map (15 minute TTL)
    for (const [ip, attempts] of rateLimitMap.entries()) {
        const windowStart = now - (15 * 60 * 1000);
        const filtered = attempts.filter(time => time > windowStart);
        if (filtered.length === 0) {
            rateLimitMap.delete(ip);
        } else {
            rateLimitMap.set(ip, filtered);
        }
    }
}, 60000); // Run every minute

// Test session store connection
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