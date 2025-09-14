const express = require('express');
const { query } = require('./dbPromise');
const mysql = require('mysql2');
const bodyParser = require('body-parser');
const cron = require('node-cron');
const moment = require('moment'); // Using moment for date handling
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
const { getPool, mainPool } = require('./db.js'); // Import the main pool
const bcrypt = require('bcrypt');
const saltRounds = 10; // Number of salt rounds, higher is more secure but slower
const jwt = require('jsonwebtoken');
const { sessionMiddleware, isAuthenticated, isAdmin, isSupervisor, isUser } = require('./sessionConfig'); // Adjust the path as needed

const app = express();
const port = process.env.PORT || 8080;
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
// Middleware to parse JSON data
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(sessionMiddleware);

// Function to detect mobile devices
function isMobile(userAgent) {
  return /android|iphone|ipad|ipod/i.test(userAgent.toLowerCase());
}

// Route principale
app.get('/', (req, res) => {
  const userAgent = req.headers['user-agent'] || '';
  console.log('User-Agent:', userAgent);

  if (isMobile(userAgent)) {
    // Se è mobile (o l'app), mandiamo login-app.html
    res.sendFile(path.join(__dirname, 'LoginApp.html'));
  } else {
    // Se è web, mandiamo login-web.html
    res.sendFile(path.join(__dirname, 'Login.html'));
  }
});

// Cron job to run on the 1st day of every month at midnight (00:00)
cron.schedule('0 0 1 * *', async () => {
    try {
        // Get all database names from the main database
        const [dbNames] = await mainPool.promise().query('SELECT db_name FROM users WHERE db_name IS NOT NULL');
  
        // Update Accrued column for all employees in each company database
        for (const db of dbNames) {
            const pool = getPool(db.db_name); // Get the correct connection pool
            const updateQuery = `
                UPDATE Employees
                SET Accrued = Accrued + 2.333
            `;
  
            await pool.promise().query(updateQuery);
        }
    } catch (error) {
        console.error('Error updating Accrued column:', error);
    }
  }, {
    scheduled: true,
    timezone: 'Europe/London' // Specify your timezone
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
        process.env.JWT_SECRET || 'your-secret-key', // Use environment variable for production
        { expiresIn: '7d' } // Token expires in 7 days
    );
}

// Route to handle login and database selection
app.post('/submit', (req, res) => {
    const { email, password, dbName } = req.body;

    // Step 1: Fetch user details from the main database
    const sql = `
        SELECT u.Access, u.Password, u.Email, u.db_name
        FROM users u
        WHERE u.Email = ?
    `;

    mainPool.query(sql, [email], async (err, results) => {
        if (err) {
            console.error('Error querying database:', err);
            return res.status(500).json({ error: 'Internal Server Error' });
        }

        if (results.length === 0) {
            return res.status(401).json({ message: 'Incorrect email or password' });
        }

        // Step 2: Check all rows for the given email and password
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
                return res.status(500).json({ error: 'Internal Server Error' });
            }
        }

        if (matchingDatabases.length === 0) {
            return res.status(401).json({ message: 'Incorrect email or password' });
        }

        // Step 3: If multiple databases match and no database is selected, return the list to the frontend
        if (matchingDatabases.length > 1 && !dbName) {
            return res.status(200).json({
                message: 'Multiple databases found',
                databases: matchingDatabases,
            });
        }

        // Step 4: If only one database matches or a database is selected, proceed
        const userDetails = dbName
            ? matchingDatabases.find((db) => db.db_name === dbName) // Use the selected database
            : matchingDatabases[0]; // Use the only matching database

        if (!userDetails) {
            return res.status(400).json({ error: 'Invalid database selection' });
        }

        const companyPool = getPool(userDetails.db_name); // Get the correct connection pool
        const companySql = `
            SELECT name, lastName
            FROM Employees
            WHERE email = ?
        `;

        companyPool.query(companySql, [email], (err, companyResults) => {
            if (err) {
                console.error('Error querying company database:', err);
                return res.status(500).json({ error: 'Internal Server Error' });
            }

            if (companyResults.length === 0) {
                return res.status(401).json({ message: 'User not found in company database' });
            }

            const name = companyResults[0].name;
            const lastName = companyResults[0].lastName;

            // Step 5: Store user information in session
            const userInfo = {
                email: email,
                role: userDetails.access,
                name: name,
                lastName: lastName,
                dbName: userDetails.db_name,
            };
            
            req.session.user = userInfo;

            // Generate JWT token for biometric storage
            const authToken = generateToken(userInfo);

            // Explicitly save the session
            req.session.save((err) => {
                if (err) {
                    console.error('Error saving session:', err);
                    return res.status(500).json({ error: 'Internal Server Error' });
                }

                // Step 6: Redirect based on role
                const queryString = `?name=${encodeURIComponent(name)}&lastName=${encodeURIComponent(lastName)}&email=${encodeURIComponent(email)}`;

                if (userDetails.access === 'admin' || userDetails.access === 'AM') {
                    return res.json({ 
                        success: true, 
                        redirectUrl: `/Admin.html${queryString}`,
                        token: authToken // Send token to client for biometric storage
                    });
                } else if (userDetails.access === 'user') {
                    return res.json({ 
                        success: true, 
                        redirectUrl: `/User.html${queryString}`,
                        token: authToken // Send token to client for biometric storage
                    });
                } else if (userDetails.access === 'supervisor') {
                    return res.json({ 
                        success: true, 
                        redirectUrl: `/Supervisor.html${queryString}`,
                        token: authToken // Send token to client for biometric storage
                    });
                } else {
                    return res.status(401).json({ message: 'Incorrect email or password' });
                }
            });
        });
    });
});

// Route to verify biometric authentication
app.post('/verify-biometric', async (req, res) => {
    try {
        // Verify the biometric authentication
        const verified = await NativeBiometric.isAvailable();
        
        if (!verified.isAvailable) {
            return res.status(400).json({ 
                success: false, 
                message: 'Biometric authentication not available' 
            });
        }

        // Get the stored credentials
        const credentials = await NativeBiometric.getCredentials({
            server: 'solura.uk' // Use a unique identifier for your app
        });

        // Verify the token from the stored credentials
        const token = credentials.password;
        const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key');
        
        // Set up the session
        req.session.user = decoded;
        
        req.session.save((err) => {
            if (err) {
                console.error('Error saving session:', err);
                return res.status(500).json({ error: 'Internal Server Error' });
            }
            
            // Return user information and redirect URL
            const queryString = `?name=${encodeURIComponent(decoded.name)}&lastName=${encodeURIComponent(decoded.lastName)}&email=${encodeURIComponent(decoded.email)}`;
            
            let redirectUrl;
            if (decoded.role === 'admin' || decoded.role === 'AM') {
                redirectUrl = `/Admin.html${queryString}`;
            } else if (decoded.role === 'user') {
                redirectUrl = `/User.html${queryString}`;
            } else if (decoded.role === 'supervisor') {
                redirectUrl = `/Supervisor.html${queryString}`;
            } else {
                return res.status(401).json({ message: 'Invalid user role' });
            }
            
            res.json({
                success: true,
                redirectUrl: redirectUrl,
                user: decoded
            });
        });
        
    } catch (error) {
        console.error('Biometric verification failed:', error);
        res.status(401).json({ 
            success: false, 
            message: 'Biometric authentication failed' 
        });
    }
});

// Route to get user's accessible databases
app.post('/getUserDatabases', (req, res) => {
    const { email } = req.body;
    
    if (!req.session.user || req.session.user.email !== email) {
        return res.status(403).json({ error: 'Unauthorized' });
    }

    const sql = `
        SELECT db_name, Access
        FROM users
        WHERE Email = ?
    `;

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

    // Verify the user has access to the requested database
    const verifySql = `
        SELECT 1
        FROM users
        WHERE Email = ? AND db_name = ?
    `;

    mainPool.query(verifySql, [email, dbName], (err, results) => {
        if (err) {
            console.error('Error verifying database access:', err);
            return res.status(500).json({ error: 'Internal Server Error' });
        }

        if (results.length === 0) {
            return res.status(403).json({ error: 'Access to this database is not authorized' });
        }

        // Update session with new database
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

// Apply isAuthenticated middleware to all protected routes
app.get('/Admin.html', isAuthenticated, isAdmin, (req, res) => {
    res.sendFile(path.join(__dirname, 'Admin.html'));
});

app.get('/User.html', isAuthenticated, isUser, (req, res) => {
    res.sendFile(path.join(__dirname, 'User.html'));
});

app.get('/Supervisor.html', isAuthenticated, isSupervisor, (req, res) => {
    res.sendFile(path.join(__dirname, 'Supervisor.html'));
});

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
        // Get yesterday's date (exclude today)
        const yesterday = new Date(today);
        yesterday.setDate(today.getDate() - 1);
        const daysToCheck = yesterday.getDate(); // e.g., 15 if today is 16th

        let missingDaysCount = 0;

        // Check each day from 1st to yesterday
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
        // Get yesterday's date (exclude today)
        const yesterday = new Date(today);
        yesterday.setDate(today.getDate() - 1);
        const daysToCheck = yesterday.getDate(); // e.g., 15 if today is 16th

        let missingDaysCount = 0;

        // Check each day from 1st to yesterday
        for (let day = 1; day <= daysToCheck; day++) {
            const date = new Date(currentYear, currentMonth - 1, day);
            // Format as yyyy-mm-dd
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

// Helper function to get current Monday's date in YYYY-MM-DD format
function getCurrentMonday() {
    const today = new Date();
    const day = today.getDay(); // 0 is Sunday, 1 is Monday, etc.
    const diff = today.getDate() - day + (day === 0 ? -6 : 1); // adjust when day is Sunday
    const monday = new Date(today.setDate(diff));
    return monday.toISOString().split('T')[0];
}

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
            const currentTime = now.getHours() * 60 + now.getMinutes(); // Total minutes
            
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
                
                // Convert times to minutes since midnight for easier calculation
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
                // Sort time frames chronologically
                emp.timeFrames.sort((a, b) => a.startMinutes - b.startMinutes);
                
                let currentStatus = 'Not started';
                let nextEvent = '';
                let activeFrame = null;
                
                // Find current or next active time frame
                for (const frame of emp.timeFrames) {
                    if (currentTime < frame.startMinutes) {
                        // Shift hasn't started yet
                        const minsLeft = frame.startMinutes - currentTime;
                        const hoursLeft = Math.floor(minsLeft / 60);
                        const remainingMins = minsLeft % 60;
                        nextEvent = `Starts in ${hoursLeft}h ${remainingMins}m`;
                        break;
                    } else if (currentTime <= frame.endMinutes) {
                        // Currently working
                        currentStatus = 'Working now';
                        const minsLeft = frame.endMinutes - currentTime;
                        const hoursLeft = Math.floor(minsLeft / 60);
                        const remainingMins = minsLeft % 60;
                        nextEvent = `Ends in ${hoursLeft}h ${remainingMins}m`;
                        activeFrame = frame;
                        break;
                    }
                }
                
                // If no active or upcoming shift found, show last ended shift
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
                    // Add these for client-side countdown updates
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
                // Include server time for client-side sync
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
        `SELECT Weekly_Cost_Before FROM Data WHERE WeekStart = ?`, // Parameterized query
        [mondayDate],
        (error, results) => {
            if (error) {
                console.error('Database error:', error);
                return res.status(500).json({
                    success: false,
                    error: 'Database error'
                });
            }
            
            // For mysql2, results is an array directly (not results.rows)
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

// Route to handle logout
app.get('/logout', (req, res) => {
    if (req.session && req.session.user) {
        // Delete biometric credentials on logout
        NativeBiometric.deleteCredentials({
            server: 'solura.uk'
        }).catch(err => {
            console.error('Failed to delete biometric credentials:', err);
        });
        
        req.session.destroy(err => {
            if (err) {
                console.error('Failed to destroy session:', err);
                return res.status(500).json({ error: 'Failed to logout' });
            }
            res.clearCookie('connect.sid'); // Ensure the name matches the session cookie
            res.redirect('/');
        });
    } else {
        res.redirect('/');
    }
});

app.listen(port, () => {
    console.log(`Server listening at http://localhost:${port}`);
    // Start holiday accrual updates for these databases
    const databaseNames = ['bbuonaoxford', '100%pastaoxford']; // Your database names
    scheduleTestUpdates(databaseNames);
});