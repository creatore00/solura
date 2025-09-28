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
const { sessionMiddleware, isAuthenticated, isAdmin, isSupervisor, isUser } = require('./sessionConfig');
const session = require('express-session');
const cors = require('cors');

const app = express();
const port = process.env.PORT || 8080;

// Middleware
app.use(cors({
    origin: true,
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
}));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(__dirname)); // ✅ SERVE STATIC FILES
app.use(sessionMiddleware);

app.use(session({
    secret: process.env.SESSION_SECRET || 'your-session-secret',
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: false,
        httpOnly: true,
        sameSite: 'none'
    }
}));

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

// Function to detect mobile devices
function isMobile(userAgent) {
    return /android|iphone|ipad|ipod/i.test(userAgent.toLowerCase());
}

// Route principale
app.get('/', (req, res) => {
    const userAgent = req.headers['user-agent'] || '';
    console.log('User-Agent:', userAgent);

    if (isMobile(userAgent)) {
        res.sendFile(path.join(__dirname, 'LoginApp.html'));
    } else {
        res.sendFile(path.join(__dirname, 'Login.html'));
    }
});

// Cron job
cron.schedule('0 0 1 * *', async () => {
    try {
        const [dbNames] = await mainPool.promise().query('SELECT db_name FROM users WHERE db_name IS NOT NULL');
        for (const db of dbNames) {
            const pool = getPool(db.db_name);
            const updateQuery = `UPDATE Employees SET Accrued = Accrued + 2.333`;
            await pool.promise().query(updateQuery);
        }
    } catch (error) {
        console.error('Error updating Accrued column:', error);
    }
}, {
    scheduled: true,
    timezone: 'Europe/London'
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

// Route to handle login and database selection
app.post('/submit', (req, res) => {
    console.log('Received /submit request:', req.body);
    const { email, password, dbName } = req.body;

    if (!email || !password) {
        return res.status(400).json({ message: 'Email and password are required' });
    }

    const sql = `SELECT u.Access, u.Password, u.Email, u.db_name FROM users u WHERE u.Email = ?`;

    mainPool.query(sql, [email], async (err, results) => {
        if (err) {
            console.error('Error querying database:', err);
            return res.status(500).json({ error: 'Internal Server Error', details: err.message });
        }

        if (results.length === 0) {
            return res.status(401).json({ message: 'Incorrect email or password' });
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
                return res.status(500).json({ error: 'Internal Server Error', details: err.message });
            }
        }

        if (matchingDatabases.length === 0) {
            return res.status(401).json({ message: 'Incorrect email or password' });
        }

        if (matchingDatabases.length > 1 && !dbName) {
            return res.status(200).json({
                message: 'Multiple databases found',
                databases: matchingDatabases,
            });
        }

        const userDetails = dbName
            ? matchingDatabases.find((db) => db.db_name === dbName)
            : matchingDatabases[0];

        if (!userDetails) {
            return res.status(400).json({ error: 'Invalid database selection' });
        }

        const companyPool = getPool(userDetails.db_name);
        const companySql = `SELECT name, lastName FROM Employees WHERE email = ?`;

        companyPool.query(companySql, [email], (err, companyResults) => {
            if (err) {
                console.error('Error querying company database:', err);
                return res.status(500).json({ error: 'Internal Server Error', details: err.message });
            }

            if (companyResults.length === 0) {
                return res.status(401).json({ message: 'User not found in company database' });
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

            req.session.user = userInfo;

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

            req.session.save((err) => {
                if (err) {
                    console.error('Error saving session:', err);
                    return res.status(500).json({ error: 'Internal Server Error', details: err.message });
                }

                const queryString = `?name=${encodeURIComponent(name)}&lastName=${encodeURIComponent(lastName)}&email=${encodeURIComponent(email)}`;
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
                    return res.status(401).json({ message: 'Incorrect email or password' });
                }

                return res.json({
                    success: true,
                    redirectUrl,
                    accessToken: authToken,
                    refreshToken: refreshToken
                });
            });
        });
    });
});

// Route to save notification token
app.post('/savePushToken', isAuthenticated, async (req, res) => {
    const dbName = req.session.user.dbName;
    const pool = getPool(dbName);
    const { pushToken } = req.body;
    const userEmail = req.session.user.email;

    try {
        await pool.promise().query(
            "UPDATE Employees SET push_token = ? WHERE email = ?",
            [pushToken, userEmail]
        );
        res.status(200).send('Push token saved');
    } catch (err) {
        console.error(err);
        res.status(500).send('Error saving token');
    }
});

// Route to get user's accessible databases
app.post('/getUserDatabases', (req, res) => {
    const { email } = req.body;
    
    if (!req.session.user || req.session.user.email !== email) {
        return res.status(403).json({ error: 'Unauthorized' });
    }

    const sql = `SELECT db_name, Access FROM users WHERE Email = ?`;

    mainPool.query(sql, [email], (err, results) => {
        if (err) {
            console.error('Error querying database:', err);
            return res.status(500).json({ error: 'Internal Server Error' });
        }

        if (results.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }

        res.json({
            databases: results,
            currentDb: req.session.user.dbName
        });
    });
});

// Route to switch databases
app.post('/switchDatabase', (req, res) => {
    const { email, dbName } = req.body;
    
    if (!req.session.user || req.session.user.email !== email) {
        return res.status(403).json({ error: 'Unauthorized' });
    }

    const verifySql = `SELECT 1 FROM users WHERE Email = ? AND db_name = ?`;

    mainPool.query(verifySql, [email, dbName], (err, results) => {
        if (err) {
            console.error('Error verifying database access:', err);
            return res.status(500).json({ error: 'Internal Server Error' });
        }

        if (results.length === 0) {
            return res.status(403).json({ error: 'Access to this database is not authorized' });
        }

        req.session.user.dbName = dbName;
        
        req.session.save((err) => {
            if (err) {
                console.error('Error saving session:', err);
                return res.status(500).json({ error: 'Internal Server Error' });
            }
            
            res.json({ success: true });
        });
    });
});

// Protected routes - ✅ CORRETTE
app.get('/Admin.html', isAuthenticated, isAdmin, (req, res) => {
    res.sendFile(path.join(__dirname, 'Admin.html'));
});

app.get('/AdminApp.html', isAuthenticated, isAdmin, (req, res) => {
    res.sendFile(path.join(__dirname, 'AdminApp.html'));
});

app.get('/User.html', isAuthenticated, isUser, (req, res) => {
    res.sendFile(path.join(__dirname, 'User.html'));
});

app.get('/Supervisor.html', isAuthenticated, isSupervisor, (req, res) => {
    res.sendFile(path.join(__dirname, 'Supervisor.html'));
});

// API routes
app.get('/api/pending-approvals', isAuthenticated, async (req, res) => {
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

// Helper function to get current Monday's date
function getCurrentMonday() {
    const today = new Date();
    const day = today.getDay();
    const diff = today.getDate() - day + (day === 0 ? -6 : 1);
    const monday = new Date(today.setDate(diff));
    return monday.toISOString().split('T')[0];
}

// Auto Login Function - ✅ CORRETTO: USA URL RELATIVI
app.post('/auto-login', async (req, res) => {
    const authHeader = req.headers['authorization'];
    if (!authHeader) return res.status(401).json({ message: 'No token provided' });

    const accessToken = authHeader.split(' ')[1];
    if (!accessToken) return res.status(401).json({ message: 'No token provided' });

    try {
        const decoded = jwt.verify(accessToken, process.env.JWT_SECRET || 'your-secret-key');
        req.session.user = decoded;
        req.session.save(err => {
            if (err) return res.status(500).json({ error: 'Failed to save session' });

            const queryString = `?name=${encodeURIComponent(decoded.name)}&lastName=${encodeURIComponent(decoded.lastName)}&email=${encodeURIComponent(decoded.email)}`;
            let redirectUrl;
            
            // ✅ CORRETTO: URL RELATIVI
            if (decoded.role === 'admin' || decoded.role === 'AM') {
                redirectUrl = `/Admin.html${queryString}`;
            } else if (decoded.role === 'user') {
                redirectUrl = `/User.html${queryString}`;
            } else if (decoded.role === 'supervisor') {
                redirectUrl = `/Supervisor.html${queryString}`;
            } else {
                return res.status(401).json({ message: 'Invalid role' });
            }

            res.json({ 
                success: true, 
                redirectUrl, 
                user: decoded,
                accessToken: accessToken
            });
        });
    } catch (err) {
        res.status(401).json({ message: 'Token expired or invalid' });
    }
});

// Function to Refresh Token
app.post('/refresh-token', async (req, res) => {
    const { refreshToken } = req.body;
    if (!refreshToken) return res.status(401).json({ message: 'No refresh token provided' });

    try {
        const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET || 'your-refresh-secret');
        const newAccessToken = jwt.sign(
            {
                email: decoded.email,
                role: decoded.role,
                name: decoded.name,
                lastName: decoded.lastName,
                dbName: decoded.dbName
            },
            process.env.JWT_SECRET || 'your-secret-key',
            { expiresIn: '7d' }
        );
        res.json({ accessToken: newAccessToken });
    } catch (err) {
        console.error('Refresh token error:', err);
        res.status(401).json({ message: 'Refresh token invalid or expired' });
    }
});

// Endpoint to get employees on shift today
app.get('/api/employees-on-shift', isAuthenticated, (req, res) => {
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

// Function to get labor cost
app.get('/api/labor-cost', isAuthenticated, (req, res) => {
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

// Route to handle logout - ✅ CORRETTO
app.get('/logout', (req, res) => {
    if (req.session && req.session.user) {
        req.session.destroy(err => {
            if (err) {
                console.error('Failed to destroy session:', err);
                return res.status(500).json({ error: 'Failed to logout' });
            }
            res.clearCookie('connect.sid');
            res.json({ success: true, message: 'Logged out successfully' });
        });
    } else {
        res.json({ success: true, message: 'No active session' });
    }
});

// ✅ CATCH-ALL HANDLER PER iOS WebView - IMPORTANTE!
app.get('*', (req, res) => {
    const requestedPath = path.join(__dirname, req.path);
    
    // Se il file esiste, servilo
    if (fs.existsSync(requestedPath) && fs.statSync(requestedPath).isFile()) {
        res.sendFile(requestedPath);
    } else if (req.path.startsWith('/api/')) {
        // API routes - return 404
        res.status(404).json({ error: 'API endpoint not found' });
    } else {
        // Per tutte le altre routes, reindirizza alla login
        res.redirect('/');
    }
});

app.listen(port, () => {
    console.log(`Server listening at http://localhost:${port}`);
    const databaseNames = ['bbuonaoxford', '100%pastaoxford'];
    scheduleTestUpdates(databaseNames);
});