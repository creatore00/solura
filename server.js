// =================================================================================
// --- (1) IMPORTS & SETUP ---
// =================================================================================
const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const session = require('express-session');
const cors = require('cors');
const MySQLStore = require('express-mysql-session')(session);
const cookieParser = require('cookie-parser');
const { getPool, mainPool } = require('./db.js');

// --- Your Route Handlers ---
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

// --- Your Authentication Middleware ---
const { sessionMiddleware, isAuthenticated, isAdmin, isSupervisor, isUser } = require('./sessionoconfig.js');

const app = express();
const port = process.env.PORT || 8080;

// --- Environment Configuration ---
const isProduction = process.env.NODE_ENV === 'production';
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-in-production';
const SESSION_SECRET = process.env.SESSION_SECRET || 'fallback-secret-key-change-in-production';

// --- Helper Functions ---
const activeSessions = new Map();
function isMobileDevice(req) {
    const userAgent = req.headers['user-agent'] || '';
    return /iPhone|iPad|iPod|Android/i.test(userAgent) || req.headers['x-capacitor'] === 'true';
}
function generateToken(user) {
    return jwt.sign({ 
        email: user.email, role: user.role, name: user.name, 
        lastName: user.lastName, dbName: user.dbName
    }, JWT_SECRET, { expiresIn: '7d' });
}


// =================================================================================
// --- (2) MIDDLEWARE & CONFIGURATION ---
// =================================================================================

// --- CORS Configuration (Single Source of Truth) ---
const corsOptions = {
  origin: [ 'capacitor://localhost', 'http://localhost', 'https://www.solura.uk', 'https://solura.uk' ],
  credentials: true, methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'Cookie', 'Accept', 'X-Session-ID', 'X-Capacitor', 'Origin', 'X-Device-Fingerprint'],
  exposedHeaders: ['Set-Cookie', 'X-Session-ID', 'Authorization']
};
app.use(cors(corsOptions));
app.options('*', cors(corsOptions));

// --- Standard Middleware ---
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(cookieParser());
app.set('trust proxy', 1);

// --- Session Middleware ---
// CRITICAL: This MUST be used for req.session to exist.
app.use(sessionMiddleware); 

// --- Logger Middleware ---
app.use((req, res, next) => {
    console.log(`-> ${req.method} ${req.url}`);
    next();
});


// =================================================================================
// --- (3) PUBLIC API ROUTES (No Login Required) ---
// =================================================================================

app.get('/health', (req, res) => res.json({ status: 'OK' }));
app.post('/ForgotPassword', ForgotPassword);
app.post('/confirmpassword', confirmpassword);

// --- FULL LOGIN LOGIC RESTORED ---

app.post('/submit', async (req, res) => {
    console.log('=== LOGIN ATTEMPT (/submit) ===');
    const { email, password, dbName, forceLogout, enableBiometric, deviceFingerprint } = req.body;

    if (!email || !password) {
        return res.status(400).json({ success: false, message: 'Email and password are required' });
    }

    try {
        const existingSessions = activeSessions.get(email);
        if (existingSessions && existingSessions.size > 0 && forceLogout !== true) {
            return res.status(409).json({ success: false, message: 'already_logged_in' });
        }

        const sql = `SELECT u.Access, u.Password, u.Email, u.db_name FROM users u WHERE u.Email = ?`;
        mainPool.query(sql, [email], async (err, results) => {
            if (err) return res.status(500).json({ success: false, error: 'Internal Server Error' });
            if (results.length === 0) return res.status(401).json({ success: false, message: 'Incorrect email or password' });

            let matchingDatabases = [];
            for (const row of results) {
                const isMatch = await bcrypt.compare(password, row.Password);
                if (isMatch) matchingDatabases.push({ db_name: row.db_name, access: row.Access });
            }

            if (matchingDatabases.length === 0) return res.status(401).json({ success: false, message: 'Incorrect email or password' });
            
            if (existingSessions && forceLogout === true) {
                for (const oldSessionId of existingSessions) sessionStore.destroy(oldSessionId);
                activeSessions.delete(email);
            }

            if (matchingDatabases.length > 1 && !dbName) {
                return res.json({ success: true, message: 'Multiple databases found', databases: matchingDatabases });
            }

            const userDetails = dbName ? matchingDatabases.find(db => db.db_name === dbName) : matchingDatabases[0];
            if (!userDetails) return res.status(400).json({ success: false, error: 'Invalid database selection' });

            const companyPool = getPool(userDetails.db_name);
            companyPool.query(`SELECT name, lastName FROM Employees WHERE email = ?`, [email], (err, companyResults) => {
                if (err || companyResults.length === 0) return res.status(401).json({ success: false, message: 'User not found in company database' });

                const { name, lastName } = companyResults[0];
                const userInfo = { email, role: userDetails.access, name, lastName, dbName: userDetails.db_name };
                
                req.session.user = userInfo;
                req.session.save(err => {
                    if (err) return res.status(500).json({ success: false, error: 'Failed to create session' });

                    if (!activeSessions.has(email)) activeSessions.set(email, new Set());
                    activeSessions.get(email).add(req.sessionID);
                    
                    const useMobileApp = isMobileDevice(req);
                    let redirectUrl = '';
                    if (userInfo.role === 'admin' || userInfo.role === 'AM') redirectUrl = useMobileApp ? '/AdminApp.html' : '/Admin.html';
                    else if (userInfo.role === 'user') redirectUrl = useMobileApp ? '/UserApp.html' : '/User.html';
                    else redirectUrl = useMobileApp ? '/SupervisorApp.html' : '/Supervisor.html';

                    res.json({
                        success: true, message: 'Login successful', redirectUrl, user: userInfo,
                        sessionId: req.sessionID, accessToken: generateToken(userInfo)
                    });
                });
            });
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ success: false, error: 'Internal server error' });
    }
});

app.post('/submit-database', async (req, res) => {
    console.log('=== DATABASE SELECTION (/submit-database) ===');
    const { email, password, dbName } = req.body;

    if (!email || !password || !dbName) {
        return res.status(400).json({ success: false, message: 'Email, password, and database selection are required.' });
    }

    try {
        const sql = `SELECT Access, Password FROM users WHERE Email = ? AND db_name = ?`;
        mainPool.query(sql, [email, dbName], async (err, results) => {
            if (err) return res.status(500).json({ success: false, error: 'Internal Server Error' });
            if (results.length === 0) return res.status(403).json({ success: false, message: 'You do not have access to this database.' });

            const userRecord = results[0];
            const isMatch = await bcrypt.compare(password, userRecord.Password);
            if (!isMatch) return res.status(401).json({ success: false, message: 'Invalid credentials.' });

            const companyPool = getPool(dbName);
            companyPool.query(`SELECT name, lastName FROM Employees WHERE email = ?`, [email], (err, companyResults) => {
                if (err || companyResults.length === 0) return res.status(401).json({ success: false, message: 'User not found in the selected company database.' });

                const { name, lastName } = companyResults[0];
                const userInfo = { email, role: userRecord.Access, name, lastName, dbName };
                
                req.session.user = userInfo;
                req.session.save(err => {
                    if (err) return res.status(500).json({ success: false, error: 'Failed to create session after DB selection.' });

                    if (!activeSessions.has(email)) activeSessions.set(email, new Set());
                    activeSessions.get(email).add(req.sessionID);
                    
                    const useMobileApp = isMobileDevice(req);
                    let redirectUrl = '';
                    if (userInfo.role === 'admin' || userInfo.role === 'AM') redirectUrl = useMobileApp ? '/AdminApp.html' : '/Admin.html';
                    else if (userInfo.role === 'user') redirectUrl = useMobileApp ? '/UserApp.html' : '/User.html';
                    else redirectUrl = useMobileApp ? '/SupervisorApp.html' : '/Supervisor.html';
                    
                    res.json({
                        success: true, message: 'Login successful', redirectUrl, user: userInfo,
                        sessionId: req.sessionID, accessToken: generateToken(userInfo)
                    });
                });
            });
        });
    } catch (error) {
        console.error('Database selection error:', error);
        res.status(500).json({ success: false, error: 'Internal server error' });
    }
});

app.post('/api/biometric-login', async (req, res) => {
    const deviceFingerprint = req.headers['x-device-fingerprint'];
    if (!deviceFingerprint) return res.status(400).json({ success: false, error: 'Device fingerprint is required.' });

    try {
        const deviceSql = `SELECT bd.user_email, u.Access, u.db_name FROM biometric_devices bd JOIN users u ON bd.user_email = u.Email WHERE bd.device_fingerprint = ? AND bd.is_active = TRUE LIMIT 1;`;
        mainPool.query(deviceSql, [deviceFingerprint], (err, results) => {
            if (err) return res.status(500).json({ success: false, error: 'Internal server error.' });
            if (results.length === 0) return res.status(401).json({ success: false, error: 'Device not registered.' });

            const { user_email: email, Access: role, db_name: dbName } = results[0];
            const companyPool = getPool(dbName);
            companyPool.query(`SELECT name, lastName FROM Employees WHERE email = ?`, [email], (err, companyResults) => {
                if (err || companyResults.length === 0) return res.status(404).json({ success: false, error: 'User not found in company records.' });

                const { name, lastName } = companyResults[0];
                const userInfo = { email, role, name, lastName, dbName };
                req.session.user = userInfo;

                req.session.save(err => {
                    if (err) return res.status(500).json({ success: false, error: 'Failed to create session.' });

                    const useMobileApp = isMobileDevice(req);
                    let redirectUrl = '';
                    if (userInfo.role === 'admin' || userInfo.role === 'AM') redirectUrl = useMobileApp ? '/AdminApp.html' : '/Admin.html';
                    else if (userInfo.role === 'user') redirectUrl = useMobileApp ? '/UserApp.html' : '/User.html';
                    else redirectUrl = useMobileApp ? '/SupervisorApp.html' : '/Supervisor.html';
                    
                    res.json({
                        success: true, message: 'Biometric login successful', redirectUrl, user: userInfo,
                        sessionId: req.sessionID, accessToken: generateToken(userInfo)
                    });
                });
            });
        });
    } catch (error) {
        res.status(500).json({ success: false, error: 'Internal server error.' });
    }
});

app.get('/logout', (req, res) => { /* ... same as before ... */ });


// =================================================================================
// --- (5) PROTECTED API ROUTES (Login & Role Required) ---
// =================================================================================

// --- ADMIN-ONLY ROUTES ---
app.use('/rota', isAuthenticated, isAdmin, newRota);
app.use('/rota2', isAuthenticated, isAdmin, newRota2);
app.use('/generate', isAuthenticated, isAdmin, generate);
app.use('/pastemployees', isAuthenticated, isAdmin, pastemployees);
app.use('/updateinfo', isAuthenticated, isAdmin, updateinfo);
app.use('/hours', isAuthenticated, isAdmin, hours);
app.use('/labor', isAuthenticated, isAdmin, labor);
app.use('/tip', isAuthenticated, isAdmin, tip);
app.use('/TotalHolidays', isAuthenticated, isAdmin, TotalHolidays);
app.use('/confirmrota', isAuthenticated, isAdmin, confirmrota);
app.use('/confirmrota2', isAuthenticated, isAdmin, confirmrota2);
app.use('/insertpayslip', isAuthenticated, isAdmin, insertpayslip);
app.use('/modify', isAuthenticated, isAdmin, modify);
app.use('/endday', isAuthenticated, isAdmin, endday);
app.use('/financialsummary', isAuthenticated, isAdmin, financialsummary);
app.use('/Backend', isAuthenticated, isAdmin, Backend);


// --- GENERAL AUTHENTICATED ROUTES (Any Logged-in User) ---
app.use('/userholidays', isAuthenticated, userholidays);
app.use('/pastpayslips', isAuthenticated, pastpayslips);
app.use('/request', isAuthenticated, request);
app.use('/UserCrota', isAuthenticated, UserCrota);
app.use('/UserHolidays', isAuthenticated, UserHolidays);
app.use('/profile', isAuthenticated, profile);
app.use('/UserTotalHours', isAuthenticated, UserTotalHours);
app.use('/token', isAuthenticated, token);


// =================================================================================
// --- (6) SERVER START ---
// =================================================================================
app.listen(port, () => {
    console.log(`✅ Solura API Server listening on port ${port}`);
});