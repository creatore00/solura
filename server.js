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

// Enhanced CORS configuration for iOS compatibility
const corsOptions = {
    origin: function (origin, callback) {
        const allowedOrigins = [
            'https://www.solura.uk', 
            'https://solura.uk', 
            'http://localhost:8080',
            'http://localhost:3000'
        ];
        
        // Allow requests with no origin (like mobile apps or curl requests)
        if (!origin) return callback(null, true);
        
        if (allowedOrigins.indexOf(origin) !== -1) {
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

// FIXED: Cookie cleanup middleware - remove duplicate cookies
app.use((req, res, next) => {
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
    }
    next();
});

// Session debugging middleware
app.use((req, res, next) => {
    console.log('=== SESSION DEBUG ===');
    console.log('URL:', req.url);
    console.log('Method:', req.method);
    console.log('Session ID:', req.sessionID);
    console.log('Session exists:', !!req.session);
    console.log('Session User:', req.session?.user);
    console.log('Cookies:', req.headers.cookie);
    console.log('=== END DEBUG ===');
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
        return require('crypto').randomBytes(16).toString('hex');
    }
}));

// Session recovery middleware for heartbeat issues
app.use('/api/session-heartbeat', (req, res, next) => {
    // Force session reload for heartbeat
    if (req.session && typeof req.session.reload === 'function') {
        req.session.reload((err) => {
            if (err) {
                console.log('🔄 Heartbeat session reload failed, continuing anyway');
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
                console.log(`✅ Session tracked for ${email}: ${req.sessionID}`);
            }
            if (callback) callback(err);
        });
    };
    next();
});

// FIXED: iOS-specific middleware - MUST come after session middleware
app.use((req, res, next) => {
    const userAgent = req.headers['user-agent'] || '';
    const isIOS = /iPhone|iPad|iPod/i.test(userAgent);
    
    if (isIOS) {
        console.log('📱 iOS Device Detected');
        
        // Handle session ID from various sources for iOS
        const sessionIdFromUrl = req.query.sessionId;
        const sessionIdFromHeader = req.headers['x-session-id'];
        
        console.log('📱 Session ID from URL:', sessionIdFromUrl);
        console.log('📱 Session ID from Header:', sessionIdFromHeader);
        console.log('📱 Current Session ID:', req.sessionID);
        
        // Ensure session is initialized for iOS
        if (!req.session.initialized) {
            req.session.initialized = true;
            console.log('📱 Initializing session for iOS');
        }
        
        // If we have a session ID from URL/header, try to use it
        const externalSessionId = sessionIdFromUrl || sessionIdFromHeader;
        if (externalSessionId && req.sessionID !== externalSessionId) {
            console.log('🔄 Attempting to use external session ID for iOS:', externalSessionId);
            
            req.sessionStore.get(externalSessionId, (err, sessionData) => {
                if (err) {
                    console.error('❌ Error loading external session:', err);
                    return next();
                }
                
                if (sessionData && sessionData.user) {
                    console.log('✅ External session data found, merging...');
                    // Merge the external session data with current session
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

// SECURITY: Block direct access to protected HTML files without session
app.use((req, res, next) => {
    const protectedRoutes = [
        '/Admin.html', '/AdminApp.html',
        '/User.html', '/UserApp.html', 
        '/Supervisor.html', '/SupervisorApp.html'
    ];
    
    // Check if this is a direct access to protected route
    if (protectedRoutes.includes(req.path)) {
        if (!req.session?.user) {
            console.log('🚫 SECURITY: Blocked direct access to protected route:', req.path);
            return res.redirect('/');
        }
    }
    
    next();
});

// Session reloading middleware for API endpoints
app.use('/api/', (req, res, next) => {
    // Force session reload for API calls
    if (req.session && typeof req.session.reload === 'function') {
        req.session.reload((err) => {
            if (err) {
                console.error('Error reloading session:', err);
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
    res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization, Content-Length, X-Requested-With, Cookie, X-Session-ID');
    res.header('Access-Control-Expose-Headers', 'Set-Cookie, X-Session-ID');
    
    if (req.method === 'OPTIONS') {
        return res.sendStatus(200);
    }
    next();
});

// ENHANCED: Global error handler
app.use((error, req, res, next) => {
    console.error('🚨 Global error handler:', error);
    
    // Log additional context
    console.error('Error context:', {
        url: req.url,
        method: req.method,
        userAgent: req.headers['user-agent'],
        ip: req.ip
    });
    
    if (error.message && error.message.includes('touch')) {
        console.log('🔄 Recovering from session touch error');
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
    const isProduction = process.env.NODE_ENV === 'production';
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
                    console.log(`✅ Session tracked: ${req.sessionID} for ${email}`);
                }
            }
            if (callback) callback(err);
        });
    };
    next();
});

// ENHANCED: Root route with mobile/desktop detection
app.get('/', (req, res) => {
    const userAgent = req.headers['user-agent'] || '';
    const isMobileApp = req.query.mobile === 'true';
    
    console.log('User-Agent:', userAgent);
    console.log('Mobile app parameter:', isMobileApp);
    
    if (isMobileApp) {
        console.log('📱 Mobile APP detected via parameter - serving LoginApp.html');
        res.sendFile(path.join(__dirname, 'LoginApp.html'));
    } else {
        console.log('🌐 Browser detected - serving Login.html');
        res.sendFile(path.join(__dirname, 'Login.html'));
    }
});

// Health check endpoint with session info
app.get('/health', (req, res) => {
    res.json({
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
        version: '1.0.0'
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
                            sessionCreationTime.delete(sessionId);
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

// FIXED: Switch database endpoint with proper session handling
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

                console.log('🔄 Database switching - Updated session user:', req.session.user);

                // Save session and maintain the same session ID
                req.session.save((err) => {
                    if (err) {
                        console.error('Error saving session after database switch:', err);
                        return res.status(500).json({ 
                            success: false, 
                            error: 'Failed to update session' 
                        });
                    }

                    console.log('✅ Database switched successfully to:', dbName);
                    console.log('🔄 Session maintained with ID:', req.sessionID);

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

        // Then proceed with user verification
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

                console.log('✅ iOS session restoration successful for user:', userInfo);

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
                        console.error('❌ Error saving iOS session:', err);
                        return res.status(500).json({ 
                            success: false, 
                            error: 'Failed to save session' 
                        });
                    }

                    console.log('✅ iOS session saved/updated with ID:', req.sessionID);
                    
                    // Verify the session was actually saved
                    req.sessionStore.get(req.sessionID, (verifyErr, savedSession) => {
                        if (verifyErr) {
                            console.error('❌ Error verifying session save:', verifyErr);
                        } else if (savedSession && savedSession.user) {
                            console.log('✅ Session verification passed - user data persisted');
                        } else {
                            console.error('❌ Session verification failed - no user data in stored session');
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
        console.error('iOS session restoration error:', error);
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
                activeSessions.get(email).add(req.sessionID);
                
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

// FIXED: Session initialization endpoint for iOS
app.get('/api/init-session', (req, res) => {
    console.log('🔄 Initializing session');
    
    // Ensure session is created and marked as initialized
    if (!req.session.initialized) {
        req.session.initialized = true;
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

// ENHANCED: Secure authentication middleware with session validation
function isAuthenticated(req, res, next) {
    console.log('=== AUTH CHECK ===');
    console.log('Session ID:', req.sessionID);
    console.log('Session exists:', !!req.session);
    console.log('Session User:', req.session?.user);
    
    // Only allow access with valid session user data
    if (req.session?.user && req.session.user.dbName && req.session.user.email) {
        // CRITICAL: Check if this session is still in active sessions
        const email = req.session.user.email;
        const activeSessionIds = activeSessions.get(email);
        
        if (!activeSessionIds || !activeSessionIds.has(req.sessionID)) {
            console.log('🚫 Session no longer active - user was force logged out');
            
            // Destroy the invalid session
            req.session.destroy((err) => {
                if (err) {
                    console.error('Error destroying invalid session:', err);
                }
                console.log('✅ Invalid session destroyed');
                
                // Send proper auth error
                const userAgent = req.headers['user-agent'] || '';
                const isIOS = userAgent.includes('iPhone') || userAgent.includes('iPad');
                return sendAuthError(res, isIOS, req, 'Your session was terminated from another device. Please log in again.');
            });
            return;
        }
        
        console.log('✅ Authentication SUCCESS for user:', req.session.user.email);
        
        // Use safe session extension
        if (req.session.touch && typeof req.session.touch === 'function') {
            req.session.touch();
        } else {
            // Manual session extension by updating maxAge
            req.session.cookie.maxAge = req.session.cookie.originalMaxAge;
        }
        
        return next();
    }
    
    console.log('❌ Authentication FAILED - No valid user in session');
    
    // For iOS apps, try to load session from URL parameter as fallback
    const userAgent = req.headers['user-agent'] || '';
    const isIOS = userAgent.includes('iPhone') || userAgent.includes('iPad');
    const sessionIdFromUrl = req.query.sessionId;
    
    if (isIOS && sessionIdFromUrl && req.sessionStore) {
        console.log('📱 iOS - Attempting session recovery from URL parameter');
        
        req.sessionStore.get(sessionIdFromUrl, (err, sessionData) => {
            if (err) {
                console.error('❌ Error loading iOS session from URL:', err);
                return sendAuthError(res, isIOS, req);
            }
            
            if (sessionData && sessionData.user) {
                console.log('✅ iOS session recovery successful');
                
                // Check if the recovered session is still active
                const recoveredEmail = sessionData.user.email;
                const recoveredActiveSessions = activeSessions.get(recoveredEmail);
                
                if (!recoveredActiveSessions || !recoveredActiveSessions.has(sessionIdFromUrl)) {
                    console.log('🚫 Recovered session no longer active');
                    return sendAuthError(res, isIOS, req, 'Your session was terminated from another device. Please log in again.');
                }
                
                // Regenerate session with loaded data
                req.session.regenerate((err) => {
                    if (err) {
                        console.error('❌ Error regenerating session during recovery:', err);
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
                console.log('❌ No valid session data found for recovery');
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
                        console.error('Error saving session:', err);
                        return res.status(500).json({ 
                            success: false,
                            error: 'Failed to create session'
                        });
                    }

                    console.log('✅ Session saved successfully. Session ID:', req.sessionID);

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

// FIXED: Login route with proper duplicate session prevention
app.post('/submit', async (req, res) => {
    console.log('=== LOGIN ATTEMPT ===');
    console.log('Session ID at login start:', req.sessionID);
    
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
                        console.error('Error saving session:', err);
                        return res.status(500).json({ 
                            success: false,
                            error: 'Failed to create session'
                        });
                    }

                    console.log('✅ Session saved successfully. Session ID:', req.sessionID);

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

// Protected routes - ALWAYS desktop versions for browsers
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

// Enhanced logout route with session cleanup
app.get('/logout', (req, res) => {
    if (req.session) {
        const sessionId = req.sessionID;
        const userEmail = req.session.user?.email;
        
        req.session.destroy(err => {
            if (err) {
                console.error('Failed to destroy session:', err);
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
        res.sendFile(requestedPath);
    } else if (req.path.startsWith('/api/')) {
        res.status(404).json({ error: 'API endpoint not found' });
    } else {
        res.redirect('/');
    }
});

// Clean up active sessions tracking when sessions are destroyed
sessionStore.on('destroy', (sessionId) => {
    for (const [email, sessionIds] of activeSessions.entries()) {
        if (sessionIds.has(sessionId)) {
            sessionIds.delete(sessionId);
            if (sessionIds.size === 0) {
                activeSessions.delete(email);
            }
            console.log(`🧹 Cleaned up destroyed session: ${sessionId}`);
            break;
        }
    }
});

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