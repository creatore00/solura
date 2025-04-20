const express = require('express');
const { query } = require('./dbPromise');
const mysql = require('mysql2');
const bodyParser = require('body-parser');
const cron = require('node-cron');
const newRota = require('./Rota.js');
const newRota2 = require('./rota2.js');
const confirmpassword = require('./ConfirmPassword.js'); 
const token = require('./Token.js');
const generate = require('./Generate.js');
const updateinfo = require('./UpdateInfo.js');
const ForgotPassword = require('./ForgotPassword.js');
const userholidays = require('./Holidays.js');
const hours = require('./Hours.js');
const pastpayslips = require('./PastPayslips.js');
const request = require('./Request.js');
const tip = require('./Tip.js');
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
app.use('/generate', generate);
app.use('/updateinfo', updateinfo);
app.use('/ForgotPassword', ForgotPassword);
app.use('/userholidays', userholidays);
app.use('/hours', hours);
app.use('/pastpayslips', pastpayslips);
app.use('/request', request);
app.use('/tip', tip);
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
// Middleware to parse JSON data
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(sessionMiddleware);
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
            req.session.user = {
                email: email,
                role: userDetails.access,
                name: name,
                lastName: lastName,
                dbName: userDetails.db_name,
            };

            // Explicitly save the session
            req.session.save((err) => {
                if (err) {
                    console.error('Error saving session:', err);
                    return res.status(500).json({ error: 'Internal Server Error' });
                }

                // Step 6: Redirect based on role
                const queryString = `?name=${encodeURIComponent(name)}&lastName=${encodeURIComponent(lastName)}&email=${encodeURIComponent(email)}`;

                if (userDetails.access === 'admin') {
                    return res.json({ success: true, redirectUrl: `/Admin.html${queryString}` });
                } else if (userDetails.access === 'user') {
                    return res.json({ success: true, redirectUrl: `/User.html${queryString}` });
                } else if (userDetails.access === 'supervisor') {
                    return res.json({ success: true, redirectUrl: `/Supervisor.html${queryString}` });
                } else {
                    return res.status(401).json({ message: 'Incorrect email or password' });
                }
            });
        });
    });
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
// Route to handle logout
app.get('/logout', (req, res) => {
    if (req.session && req.session.user) {
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
// Serve your HTML or other routes here...
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'Login.html'));
});
app.listen(port, () => {
    console.log(`Server listening at http://localhost:${port}`);
});