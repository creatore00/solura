const express = require('express');
const mysql = require('mysql2');
const path = require('path');
const { getPool, mainPool } = require('./db.js');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const session = require('express-session');
const cors = require('cors');
const MySQLStore = require('express-mysql-session')(session);
const cookieParser = require('cookie-parser');

// --- (RESTORED) All your route modules ---
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

// --- Configuration ---
const isProduction = process.env.NODE_ENV === 'production';
const JWT_SECRET = process.env.JWT_SECRET || 'your-super-secret-key-for-jwt';
const JWT_REFRESH_SECRET = process.env.JWT_REFRESH_SECRET || 'your-super-secret-key-for-refresh';
const SESSION_SECRET = process.env.SESSION_SECRET || 'a-different-super-secret-key-for-sessions';

// --- Core Middleware ---
app.set('trust proxy', 1);
app.use(cookieParser());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// --- CORS Configuration ---
const allowedOrigins = [
    'https://www.solura.uk',
    'http://localhost:8080',
    'http://localhost',
    'capacitor://localhost',
    'ionic://localhost'
];
const corsOptions = {
    origin: (origin, callback) => {
        if (!origin || allowedOrigins.indexOf(origin) !== -1) {
            callback(null, true);
        } else {
            callback(new Error('Not allowed by CORS'));
        }
    },
    credentials: true,
};
app.use(cors(corsOptions));
app.options('*', cors(corsOptions));

// --- Session Store (for Web Browsers) ---
const sessionStore = new MySQLStore({
    host: 'sv41.byethost41.org',
    port: 3306,
    user: 'yassir_yassir',
    password: 'Qazokm123890',
    database: 'yassir_access',
    createDatabaseTable: true,
}, mainPool);

app.use(session({
    key: 'solura.session',
    secret: SESSION_SECRET,
    store: sessionStore,
    resave: false,
    saveUninitialized: true,
    proxy: true,
    cookie: {
        httpOnly: true,
        secure: isProduction,
        sameSite: isProduction ? 'none' : 'lax',
        maxAge: 24 * 60 * 60 * 1000,
    }
}));

// --- Helper Functions ---
const isMobileDevice = (req) => {
    const userAgent = req.headers['user-agent'] || '';
    return /iPhone|iPad|iPod|Android/i.test(userAgent) || req.headers.origin?.startsWith('capacitor://');
};

const generateTokens = (userPayload) => {
    const accessToken = jwt.sign(userPayload, JWT_SECRET, { expiresIn: '1h' });
    const refreshToken = jwt.sign(userPayload, JWT_REFRESH_SECRET, { expiresIn: '30d' });
    return { accessToken, refreshToken };
};

// --- Unified Authentication Middleware ---
const isAuthenticated = (req, res, next) => {
    const authHeader = req.headers.authorization;

    if (authHeader && authHeader.startsWith('Bearer ')) {
        const token = authHeader.split(' ')[1];
        jwt.verify(token, JWT_SECRET, (err, user) => {
            if (err) {
                return res.status(403).json({ success: false, error: 'Forbidden: Invalid Token' });
            }
            req.user = user; // Standardize user object from token
            next();
        });
    } else if (req.session && req.session.user) {
        req.user = req.session.user; // Standardize user object from session
        next();
    } else {
        return res.status(401).json({ success: false, error: 'Unauthorized: Please log in' });
    }
};

// =================================================================
// --- PUBLIC ROUTES (No Authentication Required) ---
// =================================================================

app.get('/', (req, res) => {
    const targetFile = isMobileDevice(req) ? 'LoginApp.html' : 'Login.html';
    res.sendFile(path.join(__dirname, targetFile));
});

app.post('/submit', async (req, res) => {
    const { email, password, dbName } = req.body;
    if (!email || !password) {
        return res.status(400).json({ success: false, message: 'Email and password are required' });
    }

    try {
        const sql = `SELECT Access, Password, Email, db_name FROM users WHERE Email = ?`;
        const [results] = await mainPool.promise().query(sql, [email]);

        if (results.length === 0) {
            return res.status(401).json({ success: false, message: 'Incorrect email or password' });
        }

        const matchingDatabases = [];
        for (const row of results) {
            const isMatch = await bcrypt.compare(password, row.Password);
            if (isMatch) {
                matchingDatabases.push({ db_name: row.db_name, access: row.Access });
            }
        }

        if (matchingDatabases.length === 0) {
            return res.status(401).json({ success: false, message: 'Incorrect email or password' });
        }

        if (matchingDatabases.length > 1 && !dbName) {
            return res.status(200).json({
                success: true,
                requiresDbSelection: true,
                databases: matchingDatabases,
            });
        }

        const userDetails = dbName ? matchingDatabases.find(db => db.db_name === dbName) : matchingDatabases[0];
        if (!userDetails) {
            return res.status(400).json({ success: false, error: 'Invalid database selection' });
        }

        const companyPool = getPool(userDetails.db_name);
        const [companyResults] = await companyPool.promise().query(`SELECT name, lastName FROM Employees WHERE email = ?`, [email]);

        if (companyResults.length === 0) {
            return res.status(401).json({ success: false, message: 'User not found in company records' });
        }

        const { name, lastName } = companyResults[0];
        const userPayload = { email, role: userDetails.access, name, lastName, dbName: userDetails.db_name };

        if (!isMobileDevice(req)) {
            req.session.user = userPayload;
        }

        const { accessToken, refreshToken } = generateTokens(userPayload);
        const useMobileApp = isMobileDevice(req);
        let redirectUrl = '';
        if (userPayload.role === 'admin' || userPayload.role === 'AM') redirectUrl = useMobileApp ? '/AdminApp.html' : '/Admin.html';
        else if (userPayload.role === 'user') redirectUrl = useMobileApp ? '/UserApp.html' : '/User.html';
        else if (userPayload.role === 'supervisor') redirectUrl = useMobileApp ? '/SupervisorApp.html' : '/Supervisor.html';

        res.json({ success: true, message: 'Login successful', redirectUrl, user: userPayload, accessToken, refreshToken });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ success: false, error: 'Internal server error' });
    }
});

app.post('/api/biometric-login', async (req, res) => {
    const { deviceFingerprint } = req.body;
    if (!deviceFingerprint) {
        return res.status(400).json({ success: false, error: 'Device fingerprint is required' });
    }
    try {
        const [results] = await mainPool.promise().query(`SELECT user_email FROM biometric_devices WHERE device_fingerprint = ? AND is_active = TRUE`, [deviceFingerprint]);
        if (results.length === 0) {
            return res.status(401).json({ success: false, error: 'Device not registered for biometric access' });
        }
        const { user_email } = results[0];
        const [userProfiles] = await mainPool.promise().query(`SELECT Access, Email, db_name FROM users WHERE Email = ?`, [user_email]);
        if (userProfiles.length === 0) {
            return res.status(404).json({ success: false, error: 'User account not found' });
        }
        const defaultProfile = userProfiles[0];
        const [companyResults] = await getPool(defaultProfile.db_name).promise().query(`SELECT name, lastName FROM Employees WHERE email = ?`, [user_email]);
        const { name, lastName } = companyResults[0];
        const userPayload = { email: user_email, role: defaultProfile.Access, name, lastName, dbName: defaultProfile.db_name };
        const { accessToken, refreshToken } = generateTokens(userPayload);
        const useMobileApp = isMobileDevice(req);
        let redirectUrl = '';
        if (userPayload.role === 'admin' || userPayload.role === 'AM') redirectUrl = useMobileApp ? '/AdminApp.html' : '/Admin.html';
        else if (userPayload.role === 'user') redirectUrl = useMobileApp ? '/UserApp.html' : '/User.html';
        else if (userPayload.role === 'supervisor') redirectUrl = useMobileApp ? '/SupervisorApp.html' : '/Supervisor.html';
        res.json({ success: true, message: 'Biometric login successful', redirectUrl, user: userPayload, accessToken, refreshToken });
    } catch (error) {
        console.error('Biometric login error:', error);
        res.status(500).json({ success: false, error: 'Internal server error' });
    }
});

// =================================================================
// --- PROTECTED ROUTES (Authentication Is Required) ---
// =================================================================

app.post('/api/register-device', isAuthenticated, async (req, res) => {
    const email = req.user.email;
    const { deviceFingerprint, deviceInfo } = req.body;
    if (!deviceFingerprint || !deviceInfo) {
        return res.status(400).json({ success: false, error: 'Device fingerprint and info are required' });
    }
    try {
        const sql = `
            INSERT INTO biometric_devices (user_email, device_fingerprint, device_name, platform, user_agent, registration_date, last_used, is_active)
            VALUES (?, ?, ?, ?, ?, NOW(), NOW(), TRUE)
            ON DUPLICATE KEY UPDATE last_used = NOW(), is_active = TRUE`;
        await mainPool.promise().query(sql, [email, deviceFingerprint, deviceInfo.platform, deviceInfo.userAgent]);
        res.json({ success: true, message: 'Device registered successfully' });
    } catch (error) {
        console.error('Device registration error:', error);
        res.status(500).json({ success: false, error: 'Failed to register device' });
    }
});

// --- (RESTORED) All your protected API routes ---
app.use('/rota', isAuthenticated, newRota);
app.use('/rota2', isAuthenticated, newRota2);
app.use('/confirmpassword', isAuthenticated, confirmpassword);
app.use('/token', isAuthenticated, token);
app.use('/Backend', isAuthenticated, Backend);
app.use('/generate', isAuthenticated, generate);
app.use('/updateinfo', isAuthenticated, updateinfo);
app.use('/ForgotPassword', isAuthenticated, ForgotPassword);
app.use('/userholidays', isAuthenticated, userholidays);
app.use('/hours', isAuthenticated, hours);
app.use('/labor', isAuthenticated, labor);
app.use('/pastpayslips', isAuthenticated, pastpayslips);
app.use('/request', isAuthenticated, request);
app.use('/tip', isAuthenticated, tip);
app.use('/pastemployees', isAuthenticated, pastemployees);
app.use('/TotalHolidays', isAuthenticated, TotalHolidays);
app.use('/UserCrota', isAuthenticated, UserCrota);
app.use('/UserHoliday', isAuthenticated, UserHolidays);
app.use('/confirmrota', isAuthenticated, confirmrota);
app.use('/confirmrota2', isAuthenticated, confirmrota2);
app.use('/profile', isAuthenticated, profile);
app.use('/UserTotalHours', isAuthenticated, UserTotalHours);
app.use('/insertpayslip', isAuthenticated, insertpayslip);
app.use('/modify', isAuthenticated, modify);
app.use('/endday', isAuthenticated, endday);
app.use('/financialsummary', isAuthenticated, financialsummary);

// --- (RESTORED) Standalone Protected API Endpoints ---
app.get('/api/employees-on-shift', isAuthenticated, (req, res) => {
    const dbName = req.user.dbName; // Use user from token/session
    const pool = getPool(dbName);
    const today = new Date();
    const dayName = today.toLocaleDateString('en-US', { weekday: 'long' });
    const formattedDate = `${String(today.getDate()).padStart(2, '0')}/${String(today.getMonth() + 1).padStart(2, '0')}/${today.getFullYear()} (${dayName})`;
    
    pool.query(`SELECT name, lastName, startTime, endTime, designation FROM rota WHERE day = ? ORDER BY designation DESC, lastName, name, startTime`, [formattedDate], (error, results) => {
        if (error) {
            console.error('Database error:', error);
            return res.status(500).json({ success: false, error: 'Database error' });
        }
        res.json({ success: true, employees: results });
    });
});

// =================================================================
// --- STATIC FILE SERVING & FINAL HANDLERS ---
// =================================================================

// Serve static files (like AdminApp.html, etc.) for logged-in users
app.use(express.static(__dirname));

// Final catch-all to redirect unhandled routes to the login page
app.get('*', (req, res) => {
    const targetFile = isMobileDevice(req) ? 'LoginApp.html' : 'Login.html';
    res.sendFile(path.join(__dirname, targetFile));
});

app.listen(port, () => {
    console.log(`Server listening at http://localhost:${port}`);
});