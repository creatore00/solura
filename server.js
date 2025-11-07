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
const allowedOrigins = [ 'https://www.solura.uk', 'http://localhost:8080', 'http://localhost', 'capacitor://localhost', 'ionic://localhost' ];
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

// --- Session Store (for Web Browsers ONLY) ---
const sessionStore = new MySQLStore({
    host: 'sv41.byethost41.org', port: 3306, user: 'yassir_yassir', password: 'Qazokm123890', database: 'yassir_access',
}, mainPool);

app.use(session({
    key: 'solura.session',
    secret: SESSION_SECRET,
    store: sessionStore,
    resave: false,
    saveUninitialized: false, // Set to false, we only create sessions for logged-in web users
    proxy: true,
    cookie: { httpOnly: true, secure: isProduction, sameSite: isProduction ? 'none' : 'lax', maxAge: 24 * 60 * 60 * 1000 }
}));

// --- Helper Functions ---
const isMobileDevice = (req) => /iPhone|iPad|iPod|Android/i.test(req.headers['user-agent'] || '') || req.headers.origin?.startsWith('capacitor://');
const generateTokens = (userPayload) => ({
    accessToken: jwt.sign(userPayload, JWT_SECRET, { expiresIn: '1h' }),
    refreshToken: jwt.sign(userPayload, JWT_REFRESH_SECRET, { expiresIn: '30d' })
});

// --- (FINAL) Unified Authentication Middleware ---
const isAuthenticated = (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (authHeader && authHeader.startsWith('Bearer ')) {
        const token = authHeader.split(' ')[1];
        jwt.verify(token, JWT_SECRET, (err, user) => {
            if (err) return res.status(403).json({ success: false, error: 'Forbidden: Invalid Token' });
            req.user = user;
            next();
        });
    } else if (req.session && req.session.user) {
        req.user = req.session.user;
        next();
    } else {
        res.status(401).json({ success: false, error: 'Unauthorized' });
    }
};

// =================================================================
// --- PUBLIC ROUTES (No Auth Required) ---
// =================================================================

app.get('/', (req, res) => res.sendFile(path.join(__dirname, isMobileDevice(req) ? 'LoginApp.html' : 'Login.html')));

// --- (FINAL) Login Endpoint ---
app.post('/submit', async (req, res) => {
    const { email, password, dbName } = req.body;
    if (!email || !password) return res.status(400).json({ success: false, message: 'Email and password are required' });

    try {
        const [results] = await mainPool.promise().query(`SELECT Access, Password, Email, db_name FROM users WHERE Email = ?`, [email]);
        if (results.length === 0) return res.status(401).json({ success: false, message: 'Incorrect email or password' });

        const matchingDatabases = [];
        for (const row of results) {
            if (await bcrypt.compare(password, row.Password)) {
                matchingDatabases.push({ db_name: row.db_name, access: row.Access });
            }
        }
        if (matchingDatabases.length === 0) return res.status(401).json({ success: false, message: 'Incorrect email or password' });

        if (matchingDatabases.length > 1 && !dbName) {
            return res.json({ success: true, requiresDbSelection: true, databases: matchingDatabases });
        }

        const userDetails = dbName ? matchingDatabases.find(db => db.db_name === dbName) : matchingDatabases[0];
        if (!userDetails) return res.status(400).json({ success: false, error: 'Invalid database selection' });

        const [companyResults] = await getPool(userDetails.db_name).promise().query(`SELECT name, lastName FROM Employees WHERE email = ?`, [email]);
        if (companyResults.length === 0) return res.status(401).json({ success: false, message: 'User not found in company records' });

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

// (Other public routes like biometric login and device registration follow...)

// =================================================================
// --- PROTECTED ROUTES (Auth Is Required) ---
// =================================================================

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

// --- Final Handlers ---
app.use(express.static(__dirname));
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, isMobileDevice(req) ? 'LoginApp.html' : 'Login.html'));
});

app.listen(port, () => console.log(`Server listening at http://localhost:${port}`));