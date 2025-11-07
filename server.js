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
const { getPool, mainPool } = require('./db.js'); // Assuming db.js exports your pools

// Import all your other route handlers
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

const app = express();
const port = process.env.PORT || 8080;

// Environment configuration
const isProduction = process.env.NODE_ENV === 'production';
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-in-production';
const SESSION_SECRET = process.env.SESSION_SECRET || 'fallback-secret-key-change-in-production';

// Helper Functions
const activeSessions = new Map(); // email -> sessionIds
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
// --- (2) CORS CONFIGURATION (THE ONLY ONE YOU NEED) ---
// =================================================================================
const corsOptions = {
  origin: [
    'capacitor://localhost',
    'http://localhost',
    'https://www.solura.uk',
    'https://solura.uk'
  ],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'Cookie', 'Accept', 'X-Session-ID', 'X-Capacitor', 'Origin', 'X-Device-Fingerprint'],
  exposedHeaders: ['Set-Cookie', 'X-Session-ID', 'Authorization']
};

app.use(cors(corsOptions));
app.options('*', cors(corsOptions)); // Handle preflight requests for all routes


// =================================================================================
// --- (3) MIDDLEWARE ---
// =================================================================================
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(cookieParser());
app.set('trust proxy', 1); // Required for hosting environments like Heroku

// Session Store Setup
const sessionStore = new MySQLStore({
    host: 'sv41.byethost41.org',
    port: 3306,
    user: 'yassir_yassir',
    password: 'Qazokm123890',
    database: 'yassir_access',
}, mainPool);

// Session Middleware
app.use(session({
  key: 'solura.session',
  secret: SESSION_SECRET,
  store: sessionStore,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: isProduction, // Will be true on Heroku
    sameSite: 'none',    // Required for cross-origin API calls
    maxAge: 24 * 60 * 60 * 1000, // 24 hours
    domain: isProduction ? '.solura.uk' : undefined,
  }
}));

// Simple logger for debugging incoming requests
app.use((req, res, next) => {
    console.log(`-> Received Request: ${req.method} ${req.url}`);
    next();
});


// =================================================================================
// --- (4) API ROUTES ---
// =================================================================================

// --- Health Check ---
app.get('/health', (req, res) => {
    res.json({ status: 'OK', timestamp: new Date() });
});

// --- Authentication Routes (Kept in server.js as requested) ---

// NEW /submit ROUTE (With Duplicate Session Check Added Back)
app.post('/submit', async (req, res) => {
    console.log('=== LOGIN ATTEMPT (/submit) ===');
    const { email, password, dbName, forceLogout } = req.body; // Added forceLogout

    if (!email || !password) {
        return res.status(400).json({ success: false, message: 'Email and password are required' });
    }

    try {
        // --- THIS BLOCK IS THE DUPLICATE SESSION CHECK ---
        const existingSessions = activeSessions.get(email);
        if (existingSessions && existingSessions.size > 0 && forceLogout !== true) {
            console.log(`-> User ${email} already has an active session. Prompting for force logout.`);
            return res.status(409).json({ // 409 Conflict is the correct status code
                success: false,
                message: 'already_logged_in',
            });
        }
        // --- END OF CHECK ---

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

            // --- THIS BLOCK HANDLES THE FORCE LOGOUT ---
            if (existingSessions && forceLogout === true) {
                console.log(`-> Force logout requested for ${email}. Destroying ${existingSessions.size} old sessions.`);
                for (const oldSessionId of existingSessions) {
                    sessionStore.destroy(oldSessionId, (err) => {
                        if (err) console.error(`Error destroying session ${oldSessionId}:`, err);
                        else console.log(`  - Destroyed old session: ${oldSessionId}`);
                    });
                }
                activeSessions.delete(email); // Clear the old session tracking
            }
            // --- END OF FORCE LOGOUT ---

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

                req.session.save((err) => {
                    if (err) return res.status(500).json({ success: false, error: 'Failed to create session' });

                    // Start tracking the new session
                    if (!activeSessions.has(email)) activeSessions.set(email, new Set());
                    activeSessions.get(email).add(req.sessionID);
                    
                    const useMobileApp = isMobileDevice(req);
                    let redirectUrl = ''; // Determine redirectUrl logic...

                    res.json({
                        success: true,
                        message: 'Login successful',
                        redirectUrl: redirectUrl,
                        user: userInfo,
                        sessionId: req.sessionID,
                    });
                });
            });
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ success: false, error: 'Internal server error' });
    }
});


app.post('/api/biometric-login', async (req, res) => {
    const deviceFingerprint = req.headers['x-device-fingerprint'];
    if (!deviceFingerprint) {
        return res.status(400).json({ success: false, error: 'Device fingerprint is required.' });
    }

    console.log('🔐 Biometric login attempt for device:', deviceFingerprint);

    try {
        const deviceSql = `SELECT bd.user_email, u.Access, u.db_name FROM biometric_devices bd JOIN users u ON bd.user_email = u.Email WHERE bd.device_fingerprint = ? AND bd.is_active = TRUE LIMIT 1;`;
        mainPool.query(deviceSql, [deviceFingerprint], (err, results) => {
            if (err) {
                console.error("DB error during biometric login:", err);
                return res.status(500).json({ success: false, error: 'Internal server error.' });
            }
            if (results.length === 0) {
                return res.status(401).json({ success: false, error: 'Device not registered for biometric access.' });
            }

            const { user_email: email, Access: role, db_name: dbName } = results[0];
            const companyPool = getPool(dbName);
            const companySql = `SELECT name, lastName FROM Employees WHERE email = ?`;
            
            companyPool.query(companySql, [email], (err, companyResults) => {
                if (err || companyResults.length === 0) {
                    return res.status(404).json({ success: false, error: 'User not found in company records.' });
                }

                const { name, lastName } = companyResults[0];
                const userInfo = { email, role, name, lastName, dbName };
                req.session.user = userInfo;

                req.session.save((err) => {
                    if (err) {
                        return res.status(500).json({ success: false, error: 'Failed to create session.' });
                    }

                    const useMobileApp = isMobileDevice(req);
                    let redirectUrl = '';
                    if (userInfo.role === 'admin' || userInfo.role === 'AM') {
                        redirectUrl = useMobileApp ? '/AdminApp.html' : '/Admin.html';
                    } else if (userInfo.role === 'user') {
                        redirectUrl = useMobileApp ? '/UserApp.html' : '/User.html';
                    } else {
                        redirectUrl = useMobileApp ? '/SupervisorApp.html' : '/Supervisor.html';
                    }
                    
                    console.log(`✅ Biometric login successful for ${email}`);
                    res.json({
                        success: true,
                        message: 'Biometric login successful',
                        redirectUrl: redirectUrl,
                        user: userInfo,
                        sessionId: req.sessionID,
                    });
                });
            });
        });
    } catch (error) {
        console.error('Biometric login process error:', error);
        res.status(500).json({ success: false, error: 'Internal server error.' });
    }
});


app.get('/logout', (req, res) => {
    if (req.session) {
        req.session.destroy(err => {
            if (err) {
                return res.status(500).json({ message: 'Could not log out.' });
            }
            res.clearCookie('solura.session', { domain: isProduction ? '.solura.uk' : undefined });
            console.log('✅ Logout successful');
            res.json({ success: true, message: 'Logged out successfully' });
        });
    } else {
        res.json({ success: true, message: 'No active session to log out from' });
    }
});


// --- All Other API Routes ---
// This is where you mount all your other modular API endpoints
app.use('/rota', newRota);
app.use('/rota2', newRota2);
app.use('/confirmpassword', confirmpassword);
app.use('/token', token);
app.use('/Backend', Backend);
app.use('/generate', generate);
app.use('/pastemployees', pastemployees);
app.use('/updateinfo', updateinfo);
app.use('/ForgotPassword', ForgotPassword);
app.use('/userholidays', userholidays);
app.use('/hours', hours);
app.use('/pastpayslips', pastpayslips);
app.use('/request', request);
app.use('/tip', tip);
app.use('/labor', labor);
app.use('/TotalHolidays', TotalHolidays);
app.use('/UserCrota', UserCrota);
app.use('/UserHolidays', UserHolidays);
app.use('/confirmrota', confirmrota);
app.use('/confirmrota2', confirmrota2);
app.use('/profile', profile);
app.use('/UserTotalHours', UserTotalHours);
app.use('/insertpayslip', insertpayslip);
app.use('/modify', modify);
app.use('/endday', endday);
app.use('/financialsummary', financialsummary);

// A catch-all for any other API routes not found
app.use('/api/*', (req, res) => {
    res.status(404).json({ error: 'API endpoint not found' });
});


// =================================================================================
// --- (5) SERVER START ---
// =================================================================================
app.listen(port, () => {
    console.log(`✅ Solura API Server listening on port ${port}`);
    console.log(`Environment: ${isProduction ? 'production' : 'development'}`);
});