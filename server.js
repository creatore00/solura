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

// Trust proxy for Heroku
app.set('trust proxy', 1);

// Create session store using your MAIN database
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
    checkExpirationInterval: 900000,
    expiration: 86400000,
    clearExpired: true
}, mainPool);

// Enhanced CORS configuration
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
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'Cookie', 'Accept'],
    exposedHeaders: ['Set-Cookie']
};

app.use(cors(corsOptions));

// Handle preflight requests
app.options('*', cors(corsOptions));

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(express.static(__dirname));

// Session middleware - SIMPLIFIED configuration
app.use(session({
    secret: process.env.SESSION_SECRET || 'fallback-secret-key-change-in-production-2024',
    resave: false,
    saveUninitialized: false,
    store: sessionStore,
    name: 'sessionId',
    cookie: {
        secure: process.env.NODE_ENV === 'production',
        httpOnly: true,
        sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
        maxAge: 24 * 60 * 60 * 1000 // 24 hours
    },
    rolling: true,
    proxy: true
}));

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

// Add CORS headers manually
app.use((req, res, next) => {
    const origin = req.headers.origin;
    if (origin && (origin.includes('solura.uk') || origin.includes('localhost'))) {
        res.header('Access-Control-Allow-Origin', origin);
        res.header('Access-Control-Allow-Credentials', 'true');
        res.header('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS');
        res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization, Content-Length, X-Requested-With, Cookie, X-Session-ID');
        res.header('Access-Control-Expose-Headers', 'Set-Cookie');
    }
    
    if (req.method === 'OPTIONS') {
        return res.sendStatus(200);
    }
    next();
});

// Test session store connection
sessionStore.on('connected', () => {
    console.log('✅ Session store connected to database');
});

sessionStore.on('error', (error) => {
    console.error('❌ Session store error:', error);
});

// Routes
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

// Session validation endpoint
app.get('/api/validate-session', (req, res) => {
    console.log('=== VALIDATE SESSION ===');
    console.log('Session ID:', req.sessionID);
    console.log('Session User:', req.session?.user);
    
    if (req.session?.user) {
        // Update session to extend expiration
        req.session.touch();
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

// Enhanced session recovery endpoint
app.post('/api/recover-session', async (req, res) => {
    try {
        const { email, dbName } = req.body;
        
        console.log('🔄 Attempting session recovery for:', { email, dbName });
        
        if (!email || !dbName) {
            return res.status(400).json({ 
                success: false, 
                error: 'Missing email or dbName' 
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

                const name = companyResults[0].name;
                const lastName = companyResults[0].lastName;

                const userInfo = {
                    email: email,
                    role: userDetails.Access,
                    name: name,
                    lastName: lastName,
                    dbName: dbName,
                };

                console.log('✅ Session recovery successful for user:', userInfo);

                // Restore session
                req.session.regenerate((err) => {
                    if (err) {
                        console.error('Error regenerating session:', err);
                        return res.status(500).json({ 
                            success: false, 
                            error: 'Failed to restore session' 
                        });
                    }

                    req.session.user = userInfo;
                    
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
        });
        
    } catch (error) {
        console.error('Session recovery error:', error);
        res.status(500).json({ 
            success: false, 
            error: error.message 
        });
    }
});

// Authentication middleware
function isAuthenticated(req, res, next) {
    console.log('=== AUTH CHECK ===');
    console.log('Session ID:', req.sessionID);
    console.log('Session User:', req.session?.user);
    
    if (req.session?.user && req.session.user.dbName) {
        console.log('✅ Authentication SUCCESS for user:', req.session.user.email);
        req.session.touch();
        return next();
    }
    
    console.log('❌ Authentication FAILED');
    
    if (req.path.startsWith('/api/') || req.xhr) {
        return res.status(401).json({ 
            success: false, 
            error: 'Unauthorized',
            message: 'Please log in again',
            requiresLogin: true
        });
    }
    
    res.redirect('/');
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

// Function to detect mobile devices
function isMobile(userAgent) {
    return /android|iphone|ipad|ipod/i.test(userAgent.toLowerCase());
}

// Main route
app.get('/', (req, res) => {
    const userAgent = req.headers['user-agent'] || '';
    console.log('Root route - User-Agent:', userAgent);

    if (isMobile(userAgent)) {
        res.sendFile(path.join(__dirname, 'LoginApp.html'));
    } else {
        res.sendFile(path.join(__dirname, 'Login.html'));
    }
});

// Login route - FIXED VERSION
app.post('/submit', async (req, res) => {
    console.log('=== LOGIN ATTEMPT ===');
    const { email, password, dbName } = req.body;

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

                // Regenerate session to prevent fixation
                req.session.regenerate((err) => {
                    if (err) {
                        console.error('Error regenerating session:', err);
                        return res.status(500).json({ 
                            success: false,
                            error: 'Failed to create session'
                        });
                    }

                    // Set session data
                    req.session.user = userInfo;
                    
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

                    const queryString = `?name=${encodeURIComponent(name)}&lastName=${encodeURIComponent(lastName)}&email=${encodeURIComponent(email)}&dbName=${encodeURIComponent(userDetails.db_name)}`;
                    const userAgent = req.headers['user-agent'] || '';
                    const isMobileDevice = /android|iphone|ipad|ipod/i.test(userAgent.toLowerCase());

                    let redirectUrl = '';

                    if (userDetails.access === 'admin' || userDetails.access === 'AM') {
                        redirectUrl = isMobileDevice ? `/AdminApp.html${queryString}` : `/Admin.html${queryString}`;
                    } else if (userDetails.access === 'user') {
                        redirectUrl = isMobileDevice ? `/UserApp.html${queryString}` : `/User.html${queryString}`;
                    } else if (userDetails.access === 'supervisor') {
                        redirectUrl = isMobileDevice ? `/SupervisorApp.html${queryString}` : `/Supervisor.html${queryString}`;
                    } else {
                        return res.status(401).json({ 
                            success: false,
                            message: 'Incorrect email or password' 
                        });
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
                            sessionId: req.sessionID,
                            localStorageUser: userInfo
                        });
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

// Function to generate a JWT token
function generateToken(user) {
    return jwt.sign(
        { 
            email: user.email, 
            role: user.role, 
            name: user.name, 
            lastName: user.lastName, 
            dbName: user.dbName 
        },
        process.env.JWT_SECRET || 'your-secret-key',
        { expiresIn: '7d' }
    );
}

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

// API routes (add your existing API routes here)
app.get('/api/pending-approvals', isAuthenticated, async (req, res) => {
    // Your existing implementation
});

app.get('/api/tip-approvals', isAuthenticated, async (req, res) => {
    // Your existing implementation
});

app.get('/api/employees-on-shift', isAuthenticated, (req, res) => {
    // Your existing implementation
});

app.get('/api/labor-cost', isAuthenticated, (req, res) => {
    // Your existing implementation
});

// Route to handle logout
app.get('/logout', (req, res) => {
    if (req.session) {
        req.session.destroy(err => {
            if (err) {
                console.error('Failed to destroy session:', err);
                return res.status(500).json({ error: 'Failed to logout' });
            }
            res.clearCookie('sessionId');
            res.json({ success: true, message: 'Logged out successfully' });
        });
    } else {
        res.json({ success: true, message: 'No active session' });
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

app.listen(port, () => {
    console.log(`Server listening at http://localhost:${port}`);
    const databaseNames = ['bbuonaoxford', '100%pastaoxford'];
    scheduleTestUpdates(databaseNames);
});