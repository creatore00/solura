// Import required modules
const express = require('express');
const mysql = require('mysql2');
const nodemailer = require('nodemailer');
const server = require('./server.js');
const path = require('path');
const bodyParser = require('body-parser');
const { getPool, mainPool } = require('./db.js'); // Import the connection pool functions
const { sessionMiddleware, isAuthenticated, isAdmin } = require('./sessionConfig'); // Adjust the path as needed
const app = express();
// Middleware
app.use(sessionMiddleware);
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
// In-memory database for storing password reset tokens
const tokens = new Map();
// Function to generate a random token
function generateToken() {
    return Math.random().toString(36).substr(2);
}
app.get('/api/emails', isAuthenticated, isAdmin, async (req, res) => {
    const dbName = req.session.user.dbName; // Get the database name from the session
    const pool = getPool(dbName); // Get the connection pool for the current database
    const mainPool = getPool('main'); // Get the connection pool for the main database

    try {
        // Step 1: Fetch users from the main database (mainPool) where db_name matches the session dbName
        const usersQuery = 'SELECT Email, Access FROM users WHERE db_name = ?';
        const [usersResults] = await mainPool.promise().query(usersQuery, [dbName]);

        // Step 2: Fetch employees from the current database (pool)
        const employeesQuery = 'SELECT Email, name, lastName FROM Employees';
        const [employeesResults] = await pool.promise().query(employeesQuery);

        // Step 3: Create a Set of emails from the Employees table for quick lookup
        const employeeEmails = new Set(employeesResults.map(emp => emp.Email));

        // Step 4: Filter users to include only those whose emails exist in the Employees table
        const combinedResults = usersResults
            .filter(user => employeeEmails.has(user.Email)) // Keep only users with emails in Employees
            .map(user => {
                // Find the corresponding employee in the Employees table
                const employee = employeesResults.find(emp => emp.Email === user.Email);
                return {
                    Email: user.Email,
                    Access: user.Access,
                    Name: employee ? employee.name : null, // Use employee name if found, otherwise null
                    LastName: employee ? employee.lastName : null // Use employee last name if found, otherwise null
                };
            });

        // Step 5: Send the combined results as JSON
        res.json(combinedResults);
    } catch (err) {
        console.error('Error fetching emails:', err);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});
// Route to update access level for a specific email
app.post('/api/update-access-level', isAuthenticated, isAdmin, (req, res) => {
    const { email, access_level } = req.body;

    // Validate access level
    if (!['admin', 'supervisor', 'user'].includes(access_level)) {
        return res.status(400).json({ error: 'Invalid access level' });
    }

    const sql = 'UPDATE users SET Access = ? WHERE Email = ?';
    mainPool.query(sql, [access_level, email], (err, results) => {
        if (err) {
            console.error('Error updating access level:', err);
            return res.status(500).json({ error: 'Internal Server Error' });
        }
        if (results.affectedRows === 0) {
            return res.status(404).json({ error: 'Email not found' });
        }
        res.json({ success: true, message: 'Access level updated successfully' });
    });
});
// Route to fetch all emails from the Employees table
app.get('/api/employees', isAuthenticated, isAdmin, async (req, res) => {
    const dbName = req.session.user.dbName; // Get the database name from the session
    const pool = getPool(dbName); // Get the correct connection pool for the current database
    const mainPool = getPool('main'); // Get the connection pool for the main database

    try {
        // Step 1: Fetch all emails, names, and last names from the Employees table (current database)
        const employeesQuery = `SELECT Email, name, lastName FROM Employees`;
        const [employeesResults] = await pool.promise().query(employeesQuery);

        // Step 2: Fetch all emails from the users table (main database)
        const usersQuery = 'SELECT Email FROM users';
        const [usersResults] = await mainPool.promise().query(usersQuery);

        // Step 3: Filter out emails that are in the users table
        const usedEmails = new Set(usersResults.map(row => row.Email)); // Create a Set of used emails
        const unusedEmails = employeesResults.filter(row => !usedEmails.has(row.Email)); // Filter unused emails

        // Step 4: Send the list of unused emails with names and last names as JSON
        res.json(unusedEmails);
        console.log(unusedEmails);
    } catch (err) {
        console.error('Error fetching emails:', err);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});
// Function to check if an email exists in the database
function checkEmailExists(email, callback) {
    const sql = 'SELECT * FROM users WHERE Email = ?';
    mainPool.query(sql, [email], (err, results) => {
        if (err) {
            return callback(err, null); // Return error if query fails
        }
        // If results array has any rows, email exists
        callback(null, results.length > 0);
    });
}
// Function to insert token into the database
function insertToken(token, email, expirationTime, userType, db_name, callback) {
    console.log('Database Name in insertToken:', db_name); // Log db_name

    // SQL query to insert a new record into the main database
    const sql = 'INSERT INTO users (Token, Email, Expiry, Access, db_name) VALUES (?, ?, ?, ?, ?)';

    // Use the mainPool to execute the query
    mainPool.query(sql, [token, email, expirationTime, userType, db_name], (err, results) => {
        if (err) {
            console.error('Error inserting token into the main database:', err);
            return callback(err);
        }
        console.log('Token inserted into the main database');
        callback(null);
    });
}
// Function to delete token from the database
async function deleteExpiredTokens(mainPool) {
    const currentTime = new Date(); // Get the current time
    try {
        // Step 1: Retrieve all tokens and their expiration times from the main database
        const sql = 'SELECT Token, Expiry FROM users WHERE Expiry IS NOT NULL';
        const [rows] = await mainPool.promise().query(sql);

        if (rows.length === 0) {
            return; // Exit if no tokens are found
        }

        const updatePromises = [];

        // Step 2: Iterate over the retrieved tokens
        rows.forEach(row => {
            const token = row.Token;
            const expirationTime = new Date(row.Expiry); // Convert database timestamp to Date object

            // Step 3: Check if the token's expiration time is older than the current time
            if (expirationTime < currentTime) {

                // Step 4: Create a promise to clear the Token and Expiry fields
                const promise = mainPool.promise().query(
                    'UPDATE users SET Token = NULL, Expiry = NULL WHERE Token = ?',
                    [token]
                )
                .then(() => {
                })
                .catch(err => {
                    console.error('Error clearing expired token from the database:', err);
                    throw err; // Propagate the error
                });

                updatePromises.push(promise); // Add the promise to the array
            } else {
            }
        });

        // Step 5: Wait for all update promises to complete
        await Promise.all(updatePromises);
    } catch (error) {
    }
}
// Schedule the deletion of expired tokens every ten minutes
setInterval(() => {
    // Iterate over all databases and delete expired tokens
    mainPool.query('SELECT db_name FROM users WHERE db_name IS NOT NULL', (err, results) => {
        if (err) {
            console.error('Error fetching database names:', err);
            return;
        }

        results.forEach((row) => {
            const pool = getPool(row.db_name); // Get the correct connection pool
            deleteExpiredTokens(pool); // Delete expired tokens for this database
        });
    });
}, 60000); // Check every 1 minute = 60000 milliseconds
// Route to handle token generation and email sending
app.post('/submit', (req, res) => {
    const { email, userType } = req.body;
    const db_name = req.session.user.dbName; // Get the database name from the session

    // Check if the email exists in the main database
    checkEmailExists(email, (err, exists) => {
        if (err) {
            console.error('Error checking email existence:', err);
            return res.status(500).json({ error: 'Internal Server Error' });
        }

        if (exists) {
            // Email already exists in the database
            return res.status(400).json({ error: 'Email already in use' });
        }

        // Email does not exist, proceed with token generation and email sending
        const token = generateToken();
        const expirationTime = new Date();
        expirationTime.setUTCMinutes(expirationTime.getUTCMinutes() + 10); // Expires in 10 minutes in UTC

        // Send password reset link to the provided email address
        const resetLink = `https://solura-6b215edc5c30.herokuapp.com/token`;

        const transporter = nodemailer.createTransport({
            host: 'smtp0001.neo.space', // Your SMTP Host
            port: 465, // SSL Port
            secure: true, // `true` for SSL (port 465)
            auth: {
                user: 'no-reply@solura.uk',
                pass: 'Salvemini01@'
            }
        });

        const mailOptions = {
            from: 'Solura WorkForce <no-reply@solura.uk>',
            to: email,
            subject: 'Password Reset Link',
            text: `Click the link to reset your password: ${resetLink} This is your token for security measures ${token}`
        };

        transporter.sendMail(mailOptions, (error, info) => {
            if (error) {
                return res.status(500).json({ error: 'Error sending email' });
            } else {
                // Insert token into the main database
                insertToken(token, email, expirationTime, userType, db_name, (err) => {
                    if (err) {
                        return res.status(500).json({ error: 'Error inserting token into the database' });
                    }
                    return res.json({ success: true }); // Return success message
                });
            }
        });
    });
});
// Route to serve HTML files
app.get('/', isAuthenticated, isAdmin, (req, res) => {
    res.sendFile(path.join(__dirname, 'Generate.html'));
});
app.get('/Token.html', isAuthenticated, isAdmin, (req, res) => {
    res.sendFile(path.join(__dirname, 'Token.html'));
});
app.get('/Admin.html', isAuthenticated, isAdmin, (req, res) => {
    res.sendFile(path.join(__dirname, 'Admin.html'));
});
module.exports = app; // Export the entire Express application