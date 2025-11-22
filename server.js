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

// Trust proxy for Heroku
app.set('trust proxy', 1);

// --- Standard Middleware Stack ---
app.use(cookieParser());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// --- CORS Configuration ---
const allowedOrigins = [
    'https://www.solura.uk', 
    'https://solura.uk', 
    'http://localhost:8080',
    'http://localhost:3000',
    'capacitor://localhost',
    'ionic://localhost'
];

app.use(cors({
    origin: function (origin, callback) {
        // Allow requests with no origin (like mobile apps or curl requests)
        if (!origin) return callback(null, true);
        
        if (allowedOrigins.includes(origin) || origin.endsWith('.solura.uk') || origin.startsWith('capacitor://')) {
            return callback(null, true);
        }
        
        // For development/testing, allow permissive CORS
        return callback(null, true);
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'X-Device-Fingerprint', 'X-Session-ID'],
    exposedHeaders: ['Set-Cookie', 'X-Session-ID', 'Authorization']
}));

// --- Session Store Setup ---
const sessionStore = new MySQLStore({
    host: 'sv41.byethost41.org',
    port: 3306,
    user: 'yassir_yassir',
    password: 'Qazokm123890',
    database: 'yassir_access',
    createDatabaseTable: true,
    clearExpired: true,
    checkExpirationInterval: 900000,
    expiration: 86400000
}, mainPool);

// --- Session Middleware ---
app.use(session({
    key: 'solura.session',
    secret: process.env.SESSION_SECRET || 'solura-fallback-secret',
    store: sessionStore,
    resave: false,
    saveUninitialized: false, // Prevents empty sessions from cluttering store
    rolling: true, // Refreshes cookie expiration on every request
    cookie: {
        secure: isProduction,
        httpOnly: true, // Prevents JS access, safer against XSS
        sameSite: isProduction ? 'none' : 'lax',
        maxAge: 24 * 60 * 60 * 1000, // 24 hours
        path: '/'
    }
}));

// --- Helper: Promisify DB Query for Main Pool ---
const dbQuery = (sql, params) => {
    return new Promise((resolve, reject) => {
        mainPool.query(sql, params, (err, results) => {
            if (err) return reject(err);
            resolve(results);
        });
    });
};

// --- Helper: Promisify DB Query for Company Pools ---
const companyQuery = (pool, sql, params) => {
    return new Promise((resolve, reject) => {
        pool.query(sql, params, (err, results) => {
            if (err) return reject(err);
            resolve(results);
        });
    });
};

// --- Helper: Generate Tokens ---
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

// --- Helper: Device Detection ---
function isMobileDevice(req) {
    const userAgent = req.headers['user-agent'] || '';
    return /iPhone|iPad|iPod|Android/i.test(userAgent) || 
           req.headers['x-capacitor'] === 'true' || 
           req.headers.origin?.startsWith('capacitor://');
}

// --- Routes Import ---
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

// --- STATIC FILES ---
app.use(express.static(__dirname));

// --- MAIN AUTHENTICATION ROUTES ---

// 1. Main Login Route (Async/Await Fixed)
app.post('/submit', async (req, res) => {
    console.log('Login Request:', req.body.email);
    const { email, password, dbName, enableBiometric, deviceFingerprint } = req.body;

    if (!email || !password) {
        return res.status(400).json({ success: false, message: 'Email and password are required' });
    }

    try {
        // 1. Fetch user from central DB
        const users = await dbQuery(
            `SELECT u.Access, u.Password, u.Email, u.db_name FROM users u WHERE u.Email = ?`, 
            [email]
        );

        if (users.length === 0) {
            return res.status(401).json({ success: false, message: 'Incorrect email or password' });
        }

        // 2. Verify Password
        let validUser = null;
        let matchingDbs = [];

        for (const user of users) {
            const isMatch = await bcrypt.compare(password, user.Password);
            if (isMatch) {
                matchingDbs.push(user);
                // If a specific DB was requested, check if it matches
                if (dbName && user.db_name === dbName) {
                    validUser = user;
                }
            }
        }

        // If no specific DB requested, default to the first one found
        if (!validUser && matchingDbs.length > 0) {
            validUser = matchingDbs[0];
        }

        if (!validUser && matchingDbs.length === 0) {
            return res.status(401).json({ success: false, message: 'Incorrect email or password' });
        }

        // 3. Handle Multiple Databases (Selection required)
        if (matchingDbs.length > 1 && !dbName) {
            return res.status(200).json({
                success: true,
                message: 'Multiple databases found',
                databases: matchingDbs.map(db => ({ db_name: db.db_name, access: db.Access }))
            });
        }

        // 4. Fetch Employee Details from Company DB
        const companyPool = getPool(validUser.db_name);
        const employees = await companyQuery(companyPool, 
            `SELECT name, lastName FROM Employees WHERE email = ?`, 
            [email]
        );

        if (employees.length === 0) {
            return res.status(401).json({ success: false, message: 'User not found in company database' });
        }

        const userInfo = {
            email: email,
            role: validUser.Access,
            name: employees[0].name,
            lastName: employees[0].lastName,
            dbName: validUser.db_name
        };

        // 5. Initialize Session
        req.session.regenerate(async (err) => {
            if (err) {
                console.error('Session regeneration error:', err);
                return res.status(500).json({ success: false, error: 'Session Error' });
            }

            req.session.user = userInfo;
            req.session.initialized = true;
            req.session.loginTime = new Date();

            // 6. Handle Biometric Registration (Async)
            if (enableBiometric && deviceFingerprint) {
                const ua = req.headers['user-agent'] || '';
                await dbQuery(`
                    INSERT INTO biometric_devices 
                    (user_email, device_fingerprint, device_name, platform, user_agent, registration_date, last_used, is_active) 
                    VALUES (?, ?, 'User Device', 'Web', ?, NOW(), NOW(), TRUE)
                    ON DUPLICATE KEY UPDATE last_used = NOW(), is_active = TRUE
                `, [email, deviceFingerprint, ua]);
            }

            // 7. Save Session & Respond
            req.session.save((saveErr) => {
                if (saveErr) {
                    return res.status(500).json({ success: false, error: 'Session Save Error' });
                }

                const token = generateToken(userInfo);
                
                // Determine Redirect
                const useMobileApp = isMobileDevice(req);
                let redirectUrl = '/User.html';
                if (userInfo.role === 'admin' || userInfo.role === 'AM') redirectUrl = useMobileApp ? '/AdminApp.html' : '/Admin.html';
                else if (userInfo.role === 'supervisor') redirectUrl = useMobileApp ? '/SupervisorApp.html' : '/Supervisor.html';
                else redirectUrl = useMobileApp ? '/UserApp.html' : '/User.html';

                res.status(200).json({
                    success: true,
                    message: 'Login successful',
                    redirectUrl: redirectUrl,
                    user: userInfo,
                    accessToken: token,
                    sessionId: req.sessionID
                });
            });
        });

    } catch (error) {
        console.error('Login Logic Error:', error);
        res.status(500).json({ success: false, error: 'Internal Server Error' });
    }
});

// 2. Biometric Login Route
app.post('/api/biometric-login', async (req, res) => {
    const { deviceFingerprint } = req.body;
    
    if (!deviceFingerprint) {
        return res.status(400).json({ success: false, error: 'Device fingerprint required' });
    }

    try {
        // 1. Find user by fingerprint
        const devices = await dbQuery(
            `SELECT bd.user_email, u.Access, u.db_name 
             FROM biometric_devices bd
             JOIN users u ON bd.user_email = u.Email
             WHERE bd.device_fingerprint = ? AND bd.is_active = TRUE`,
            [deviceFingerprint]
        );

        if (devices.length === 0) {
            return res.status(401).json({ success: false, error: 'Device not recognized' });
        }

        const deviceUser = devices[0];

        // 2. Fetch Company Details
        const companyPool = getPool(deviceUser.db_name);
        const employees = await companyQuery(companyPool,
            `SELECT name, lastName FROM Employees WHERE email = ?`,
            [deviceUser.user_email]
        );

        if (employees.length === 0) {
            return res.status(404).json({ success: false, error: 'User details not found' });
        }

        const userInfo = {
            email: deviceUser.user_email,
            role: deviceUser.Access,
            name: employees[0].name,
            lastName: employees[0].lastName,
            dbName: deviceUser.db_name
        };

        // 3. Create Session
        req.session.regenerate((err) => {
            if (err) return res.status(500).json({ success: false, error: 'Session Error' });

            req.session.user = userInfo;
            req.session.initialized = true;
            req.session.biometric = true;

            req.session.save((saveErr) => {
                if (saveErr) return res.status(500).json({ success: false, error: 'Session Save Error' });

                const token = generateToken(userInfo);
                const useMobileApp = isMobileDevice(req);
                
                let redirectUrl = '/User.html';
                if (userInfo.role === 'admin' || userInfo.role === 'AM') redirectUrl = useMobileApp ? '/AdminApp.html' : '/Admin.html';
                else if (userInfo.role === 'supervisor') redirectUrl = useMobileApp ? '/SupervisorApp.html' : '/Supervisor.html';
                else redirectUrl = useMobileApp ? '/UserApp.html' : '/User.html';

                res.json({
                    success: true,
                    message: 'Biometric login successful',
                    redirectUrl,
                    user: userInfo,
                    accessToken: token,
                    sessionId: req.sessionID
                });
            });
        });

    } catch (error) {
        console.error('Biometric Login Error:', error);
        res.status(500).json({ success: false, error: 'Internal server error' });
    }
});

// 3. Device Registration Check
app.post('/api/check-device-registration', async (req, res) => {
    const { deviceFingerprint } = req.body;
    try {
        const results = await dbQuery(
            `SELECT 1 FROM biometric_devices WHERE device_fingerprint = ? AND is_active = TRUE`,
            [deviceFingerprint]
        );
        res.json({ registered: results.length > 0 });
    } catch (error) {
        res.status(500).json({ registered: false });
    }
});

// 4. Logout
app.get('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) console.error('Logout error:', err);
        res.clearCookie('solura.session');
        res.redirect('/');
    });
});

// 5. Session Validation
app.get('/api/validate-session-real-time', (req, res) => {
    if (req.session && req.session.user) {
        // Refresh cookie
        req.session.touch();
        res.json({ 
            valid: true, 
            user: req.session.user,
            sessionId: req.sessionID 
        });
    } else {
        res.json({ valid: false });
    }
});

// --- Authentication Middleware for Protected Routes ---
function isAuthenticated(req, res, next) {
    if (req.session && req.session.user) {
        return next();
    }
    
    // If API call, return JSON
    if (req.xhr || req.path.startsWith('/api/')) {
        return res.status(401).json({ success: false, message: 'Unauthorized' });
    }
    
    // If Page Load, redirect
    res.redirect('/');
}

// --- Page Routes ---
app.get('/', (req, res) => {
    if (req.session && req.session.user) {
        // Redirect logic based on role
        const useMobileApp = isMobileDevice(req);
        let redirectUrl = useMobileApp ? '/UserApp.html' : '/User.html';
        if (req.session.user.role === 'admin') redirectUrl = useMobileApp ? '/AdminApp.html' : '/Admin.html';
        else if (req.session.user.role === 'supervisor') redirectUrl = useMobileApp ? '/SupervisorApp.html' : '/Supervisor.html';
        
        return res.redirect(redirectUrl);
    }
    
    const useMobileApp = isMobileDevice(req);
    res.sendFile(path.join(__dirname, useMobileApp ? 'LoginApp.html' : 'Login.html'));
});

app.get('/LoginApp.html', (req, res) => res.sendFile(path.join(__dirname, 'LoginApp.html')));
app.get('/Login.html', (req, res) => res.sendFile(path.join(__dirname, 'Login.html')));

app.get('/Admin.html', isAuthenticated, (req, res) => res.sendFile(path.join(__dirname, 'Admin.html')));
app.get('/User.html', isAuthenticated, (req, res) => res.sendFile(path.join(__dirname, 'User.html')));
app.get('/Supervisor.html', isAuthenticated, (req, res) => res.sendFile(path.join(__dirname, 'Supervisor.html')));
app.get('/AdminApp.html', isAuthenticated, (req, res) => res.sendFile(path.join(__dirname, 'AdminApp.html')));
app.get('/UserApp.html', isAuthenticated, (req, res) => res.sendFile(path.join(__dirname, 'UserApp.html')));
app.get('/SupervisorApp.html', isAuthenticated, (req, res) => res.sendFile(path.join(__dirname, 'SupervisorApp.html')));

// --- Catch-All ---
app.get('*', (req, res) => {
    const filePath = path.join(__dirname, req.path);
    if (fs.existsSync(filePath)) {
        res.sendFile(filePath);
    } else {
        res.redirect('/');
    }
});

// Start Server
app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}`);
});
