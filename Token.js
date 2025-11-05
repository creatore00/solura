const express = require('express');
const mysql = require('mysql2');
const bodyParser = require('body-parser');
const path = require('path');
const confirmpassword = require('./ConfirmPassword.js'); 
const { getPool, mainPool } = require('./db.js'); // Import the connection pool functions
const { sessionMiddleware, isAuthenticated, isAdmin } = require('./sessionConfig'); // Adjust the path as needed

const app = express();

// Middleware
app.use(sessionMiddleware);
app.use('/confirmpassword', confirmpassword);
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Route to handle token verification
app.post('/submit', (req, res) => {
    console.log('Request Body:', req.body);
    const { token } = req.body;

    // Use the main database to verify the token
    const sql = 'SELECT Email FROM users WHERE Token = ?';
    mainPool.query(sql, [token], (err, results) => {
        if (err) {
            console.error('Error querying database:', err);
            return res.status(500).json({ error: 'Internal Server Error' });
        }
        if (results.length === 0) {
            // Token does not exist, redirect to error page
            return res.status(400).json({ success: false, message: 'Invalid token' });
        } else {
            // Token exists, store email in session and redirect to password reset page
            const email = results[0].Email;
            req.session.email = email; // Store email in session
            return res.json({ success: true, redirectUrl: `/confirmpassword?email=${encodeURIComponent(email)}` });
        }
    });
});

// Route to serve Token.html
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'Token.html'));
});

// Route to serve ConfirmPassword.html
app.get('/', (req, res) => {
    const email = req.query.email || req.session.email; // Get email from query or session
    if (!email) {
        return res.redirect('/'); // Redirect to token verification if email is missing
    }
    res.sendFile(path.join(__dirname, 'ConfirmPassword.html'));
});

// Route to serve WrongToken.html
app.get('/WrongToken.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'WrongToken.html'));
});

module.exports = app;