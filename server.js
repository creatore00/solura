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

// CRITICAL FIX: Simple CORS configuration
app.use(cors({
    origin: ['https://www.solura.uk', 'https://solura.uk', 'http://localhost:8080'],
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'Cookie'],
    exposedHeaders: ['Set-Cookie']
}));

// Handle preflight requests
app.options('*', cors());

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Static file serving
app.use(express.static(__dirname));

// CRITICAL FIX: Manual CORS headers for all responses
app.use((req, res, next) => {
    const origin = req.headers.origin;
    
    // Allow specific origins with credentials
    const allowedOrigins = ['https://www.solura.uk', 'https://solura.uk', 'http://localhost:8080'];
    if (origin && allowedOrigins.includes(origin)) {
        res.header('Access-Control-Allow-Origin', origin);
    }
    
    res.header('Access-Control-Allow-Credentials', 'true');
    res.header('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS');
    res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization, Content-Length, X-Requested-With, Cookie');
    res.header('Access-Control-Expose-Headers', 'Set-Cookie');
    
    if (req.method === 'OPTIONS') {
        return res.sendStatus(200);
    }
    next();
});

// CRITICAL FIX: Enhanced cookie parsing middleware
app.use((req, res, next) => {
    console.log('=== COOKIE ANALYSIS ===');
    console.log('URL:', req.url);
    console.log('RAW Cookie Header:', req.headers.cookie || 'UNDEFINED');
    
    // Parse cookies manually
    if (req.headers.cookie) {
        const cookies = {};
        req.headers.cookie.split(';').forEach(cookie => {
            const [name, value] = cookie.trim().split('=');
            if (name && value) {
                cookies[name] = value;
            }
        });
        req.parsedCookies = cookies;
        console.log('PARSED Cookies:', Object.keys(cookies));
    } else {
        console.log('❌ NO COOKIES RECEIVED FROM BROWSER');
        req.parsedCookies = {};
    }
    
    next();
});

// Device detection middleware
app.use((req, res, next) => {
    const userAgent = req.headers['user-agent'] || '';
    req.isMobile = /iPhone|iPad|iPod|Android/i.test(userAgent);
    req.isIPad = /iPad/.test(userAgent);
    req.isIOS = /iPhone|iPad|iPod/.test(userAgent);
    
    console.log('📱 Device - Mobile:', req.isMobile, 'iPad:', req.isIPad, 'iOS:', req.isIOS);
    
    next();
});

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
    expiration: 24 * 60 * 60 * 1000, // 24 hours
    clearExpired: true
}, mainPool);

// CRITICAL FIX: Session configuration - SIMPLIFIED AND CORRECTED
app.use(session({
    secret: SESSION_SECRET,
    resave: false, // Changed to false - let store handle resaving
    saveUninitialized: false, // Don't save empty sessions
    store: sessionStore,
    name: 'solura.session',
    cookie: {
        secure: false, // MUST be false for HTTP and mixed content
        httpOnly: true, // More secure - JavaScript can't access
        sameSite: 'lax', // Good balance of security and functionality
        maxAge: 24 * 60 * 60 * 1000, // 24 hours
        path: '/'
        // NO domain setting - let browser handle it
    },
    rolling: true, // Refresh session on activity
    proxy: false,
    unset: 'destroy'
}));

// CRITICAL FIX: Session debugging and enforcement middleware
app.use((req, res, next) => {
    console.log('=== SESSION DEBUG ===');
    console.log('URL:', req.url);
    console.log('Method:', req.method);
    console.log('Session ID:', req.sessionID);
    console.log('Session exists:', !!req.session);
    console.log('Session User:', req.session?.user);
    console.log('Cookies present:', req.headers.cookie ? 'YES' : 'NO');
    console.log('=== END DEBUG ===');
    
    // CRITICAL: If we have a session with user data, ensure it's tracked
    if (req.session?.user?.email) {
        const email = req.session.user.email;
        if (!activeSessions.has(email)) {
            activeSessions.set(email, new Set());
        }
        if (!activeSessions.get(email).has(req.sessionID)) {
            activeSessions.get(email).add(req.sessionID);
            console.log(`✅ Session tracked for ${email}: ${req.sessionID}`);
        }
    }
    
    next();
});

// CRITICAL FIX: Session cookie enforcement - ONLY when we have user data
app.use((req, res, next) => {
    // Only set cookies when we actually have a valid session with user data
    if (req.sessionID && req.session?.user) {
        console.log('🔧 Setting session cookie for authenticated user:', req.session.user.email);
        
        res.cookie('solura.session', req.sessionID, {
            maxAge: 24 * 60 * 60 * 1000,
            httpOnly: true,
            secure: false,
            sameSite: 'lax',
            path: '/'
        });
        
        // Also send in header for debugging
        res.setHeader('X-Session-ID', req.sessionID);
    }
    
    next();
});

// Add session ID to JSON responses
app.use((req, res, next) => {
    const originalJson = res.json;
    
    res.json = function(data) {
        // Include session ID in response for debugging
        if (req.sessionID && req.session?.user) {
            res.setHeader('X-Session-ID', req.sessionID);
            
            if (data && typeof data === 'object') {
                data.sessionId = req.sessionID;
            }
        }
        return originalJson.call(this, data);
    };
    next();
});

// ALL YOUR EXISTING ROUTES
// Enhanced root route
app.get('/', (req, res) => {
    console.log('=== ROOT REQUEST ===');
    console.log('Session ID:', req.sessionID);
    console.log('Session User exists:', !!req.session?.user);

    // Serve mobile version for mobile devices
    if (req.isMobile) {
        console.log('📱 Serving LoginApp.html for mobile');
        return res.sendFile(path.join(__dirname, 'LoginApp.html'));
    }

    console.log('💻 Serving Login.html for desktop');
    res.sendFile(path.join(__dirname, 'Login.html'));
});

// Health check endpoint
app.get('/health', (req, res) => {
    res.json({
        status: 'OK',
        device: {
            mobile: req.isMobile,
            iPad: req.isIPad,
            iOS: req.isIOS
        },
        session: {
            id: req.sessionID,
            exists: !!req.session,
            user: req.session?.user
        },
        cookiesReceived: !!req.headers.cookie,
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

                // CRITICAL FIX: Create session with proper error handling
                req.session.user = userInfo;
                
                // Track this session
                if (!activeSessions.has(email)) {
                    activeSessions.set(email, new Set());
                }
                activeSessions.get(email).add(req.sessionID);
                console.log(`✅ Login session tracked for ${email}: ${req.sessionID}`);
                
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

                // Determine redirect URL based on device
                let redirectUrl = '';

                if (userDetails.Access === 'admin' || userDetails.Access === 'AM') {
                    redirectUrl = req.isMobile ? '/AdminApp.html' : '/Admin.html';
                } else if (userDetails.Access === 'user') {
                    redirectUrl = req.isMobile ? '/UserApp.html' : '/User.html';
                } else if (userDetails.Access === 'supervisor') {
                    redirectUrl = req.isMobile ? '/SupervisorApp.html' : '/Supervisor.html';
                }

                // CRITICAL FIX: Save session with callback
                req.session.save((err) => {
                    if (err) {
                        console.error('❌ Error saving session:', err);
                        return res.status(500).json({ 
                            success: false,
                            error: 'Failed to create session'
                        });
                    }

                    console.log('✅ Session saved successfully. Session ID:', req.sessionID);

                    // Set session cookie explicitly
                    res.cookie('solura.session', req.sessionID, {
                        maxAge: 24 * 60 * 60 * 1000,
                        httpOnly: true,
                        secure: false,
                        sameSite: 'lax',
                        path: '/'
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

// Session validation endpoint
app.get('/api/validate-session', (req, res) => {
    console.log('=== VALIDATE SESSION ===');
    console.log('Session ID:', req.sessionID);
    console.log('Session exists:', !!req.session);
    console.log('Session User:', req.session?.user);
    
    if (req.session?.user) {
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
    console.log('Session ID:', req.sessionID);
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
            // Simple session check
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

// FIXED: Switch database endpoint
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

                // Save the session
                req.session.save((err) => {
                    if (err) {
                        console.error('Error saving session after database switch:', err);
                        return res.status(500).json({ 
                            success: false, 
                            error: 'Failed to update session' 
                        });
                    }

                    console.log('✅ Database switched successfully to:', dbName);
                    console.log('🆔 Same session ID maintained:', req.sessionID);

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

                // Set user data
                req.session.user = userInfo;
                
                // Track this session
                if (!activeSessions.has(email)) {
                    activeSessions.set(email, new Set());
                }
                activeSessions.get(email).add(req.sessionID);
                console.log(`✅ Login session tracked for ${email}: ${req.sessionID}`);
                
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
                
                // Track this session
                if (!activeSessions.has(email)) {
                    activeSessions.set(email, new Set());
                }
                activeSessions.get(email).add(req.sessionID);
                console.log(`✅ Login session tracked for ${email}: ${req.sessionID}`);
                
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

// FIXED: Session initialization endpoint
app.get('/api/init-session', (req, res) => {
    console.log('🔄 Initializing session');
    
    // Ensure session is created
    req.session.initialized = true;
    
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

// CRITICAL FIX: Enhanced authentication middleware
function isAuthenticated(req, res, next) {
    console.log('=== AUTH CHECK ===');
    console.log('Session ID:', req.sessionID);
    console.log('Session exists:', !!req.session);
    console.log('Session User:', req.session?.user);
    
    if (req.session?.user && req.session.user.dbName && req.session.user.email) {
        console.log('✅ Authentication SUCCESS for user:', req.session.user.email);
        return next();
    } else {
        console.log('❌ Authentication FAILED');
        sendAuthError(res, true, req);
    }
}

function sendAuthError(res, isIOS, req, customMessage = null) {
    const message = customMessage || 'Please log in again';
    
    if (isIOS || req.path.startsWith('/api/') || req.xhr) {
        return res.status(401).json({ 
            success: false, 
            error: 'Unauthorized',
            message: message,
            requiresLogin: true
        });
    }
    
    res.redirect('/?error=' + encodeURIComponent(message));
}

// Role-based middleware
function isAdmin(req, res, next) {
    if (req.session?.user && (req.session.user.role === 'admin' || req.session.user.role === 'AM')) {
        return next();
    }
    sendAuthError(res, true, req, 'Admin access required');
}

function isSupervisor(req, res, next) {
    if (req.session?.user && req.session.user.role === 'supervisor') {
        return next();
    }
    sendAuthError(res, true, req, 'Supervisor access required');
}

function isUser(req, res, next) {
    if (req.session?.user && req.session.user.role === 'user') {
        return next();
    }
    sendAuthError(res, true, req, 'User access required');
}

// CRITICAL FIX: Enhanced database selection endpoint
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
                
                // Track this session
                if (!activeSessions.has(email)) {
                    activeSessions.set(email, new Set());
                }
                activeSessions.get(email).add(req.sessionID);
                console.log(`✅ Login session tracked for ${email}: ${req.sessionID}`);
                
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

                // Determine redirect URL based on device
                let redirectUrl = '';

                if (row.Access === 'admin' || row.Access === 'AM') {
                    redirectUrl = req.isMobile ? '/AdminApp.html' : '/Admin.html';
                } else if (row.Access === 'user') {
                    redirectUrl = req.isMobile ? '/UserApp.html' : '/User.html';
                } else if (row.Access === 'supervisor') {
                    redirectUrl = req.isMobile ? '/SupervisorApp.html' : '/Supervisor.html';
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

                    // Set session cookie explicitly
                    res.cookie('solura.session', req.sessionID, {
                        maxAge: 24 * 60 * 60 * 1000,
                        httpOnly: true,
                        secure: false,
                        sameSite: 'lax',
                        path: '/'
                    });

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

// CRITICAL FIX: Enhanced login endpoint with database selection
app.post('/submit', async (req, res) => {
    console.log('=== LOGIN ATTEMPT ===');
    console.log('Device - Mobile:', req.isMobile, 'iPad:', req.isIPad);
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
                console.log('🔄 Multiple databases found, returning selection');
                return res.status(200).json({
                    success: true,
                    message: 'Multiple databases found',
                    databases: matchingDatabases,
                    requiresDatabaseSelection: true
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
                
                // Track this session
                if (!activeSessions.has(email)) {
                    activeSessions.set(email, new Set());
                }
                activeSessions.get(email).add(req.sessionID);
                console.log(`✅ Login session tracked for ${email}: ${req.sessionID}`);

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

                // Determine redirect URL based on device
                let redirectUrl = '';

                if (userDetails.access === 'admin' || userDetails.access === 'AM') {
                    redirectUrl = req.isMobile ? '/AdminApp.html' : '/Admin.html';
                } else if (userDetails.access === 'user') {
                    redirectUrl = req.isMobile ? '/UserApp.html' : '/User.html';
                } else if (userDetails.access === 'supervisor') {
                    redirectUrl = req.isMobile ? '/SupervisorApp.html' : '/Supervisor.html';
                }

                // Save session and respond
                req.session.save((err) => {
                    if (err) {
                        console.error('Error saving session:', err);
                        return res.status(500).json({ 
                            success: false,
                            error: 'Failed to create session'
                        });
                    }

                    console.log('✅ Session saved successfully. Session ID:', req.sessionID);

                    // Set session cookie explicitly
                    res.cookie('solura.session', req.sessionID, {
                        maxAge: 24 * 60 * 60 * 1000,
                        httpOnly: true,
                        secure: false,
                        sameSite: 'lax',
                        path: '/'
                    });

                    res.json({
                        success: true,
                        message: 'Login successful',
                        redirectUrl: redirectUrl,
                        user: userInfo,
                        accessToken: authToken,
                        refreshToken: refreshToken,
                        sessionId: req.sessionID,
                        requiresDatabaseSelection: false
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

// Protected routes with device-specific support
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

// Add the rest of your existing endpoints (employees-on-shift, labor-cost, etc.)
// [KEEP ALL YOUR EXISTING ENDPOINT CODE HERE - employees-on-shift, labor-cost, pending-approvals, tip-approvals]

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
                secure: false,
                sameSite: 'Lax'
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

// Session store event handlers
sessionStore.on('connected', () => {
    console.log('✅ Session store connected to database');
});

sessionStore.on('error', (error) => {
    console.error('❌ Session store error:', error);
});

app.get('/support', (req, res) => {
    res.sendFile(path.join(__dirname, '/support.html'));
});

app.listen(port, () => {
    console.log(`Server listening at http://localhost:${port}`);
    console.log(`Environment: ${isProduction ? 'production' : 'development'}`);
    const databaseNames = ['bbuonaoxford', '100%pastaoxford'];
    scheduleTestUpdates(databaseNames);
});