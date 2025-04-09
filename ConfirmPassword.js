const express = require('express');
const mysql = require('mysql2');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const path = require('path');
const saltRounds = 10; // Number of salt rounds, higher is more secure but slower
const { getPool, mainPool } = require('./db.js'); // Import the connection pool functions
const { sessionMiddleware, isAuthenticated } = require('./sessionConfig'); // Adjust the path as needed

const app = express();

// Middleware
app.use(sessionMiddleware);
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Route to handle password update
app.post('/submit', isAuthenticated, async (req, res) => {
    const { password } = req.body; // Get password from request body
    const email = req.session.email; // Get email from session

    if (!email) {
        return res.status(401).json({ error: 'Unauthorized: No session found' });
    }

    if (!password) {
        return res.status(400).json({ error: 'Password is required' });
    }

    try {
        // Hash the password
        const hashedPassword = await bcrypt.hash(password, saltRounds);

        // Update the password in the main database
        const updatePasswordSql = 'UPDATE users SET Password = ? WHERE Email = ?';
        mainPool.query(updatePasswordSql, [hashedPassword, email], (err, results) => {
            if (err) {
                console.error('Error updating password in the main database:', err);
                return res.status(500).json({ error: 'Error updating password in the main database' });
            }
            console.log('Password updated successfully for email:', email);

            // Clear session after password update
            req.session.destroy((err) => {
                if (err) {
                    console.error('Error destroying session:', err);
                    return res.status(500).json({ error: 'Internal server error' });
                }
                res.clearCookie('connect.sid'); // Clear the session cookie
                return res.json({ success: true, message: 'Password updated successfully!' });
            });
        });
    } catch (err) {
        console.error('Error hashing password:', err);
        return res.status(500).json({ error: 'Internal server error' });
    }
});

// Route to serve the ConfirmPassword.html file
app.get('/', (req, res) => {
    const email = req.query.email || req.session.email; // Get email from query or session
    if (!email) {
        return res.redirect('/'); // Redirect to token verification if email is missing
    }
    res.sendFile(path.join(__dirname, 'ConfirmPassword.html'));
});

module.exports = app;