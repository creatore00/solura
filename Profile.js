const express = require('express');
const bodyParser = require('body-parser');
const { v4: uuidv4 } = require('uuid');
const { getPool, mainPool } = require('./db.js');
const path = require('path');
const bcrypt = require('bcrypt');
const saltRounds = 10;
const { sessionMiddleware, isAuthenticated, isAdmin, isSupervisor, isUser } = require('./sessionConfig');
const app = express();
// Middleware
app.use(sessionMiddleware);
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
// Route to fetch user profile data
app.get('/api/profile', isAuthenticated, (req, res) => {
    const dbName = req.session.user.dbName; // Get the database name from the session

    if (!dbName) {
        return res.status(401).json({ message: 'User not authenticated' });
    }

    const pool = getPool(dbName); // Get the correct connection pool

    const email = req.session.user.email;
    pool.query('SELECT * FROM Employees WHERE email = ?', [email], (err, results) => {
        if (err) {
            return res.status(500).send('Server error');
        }
        if (results.length === 0) {
            return res.status(404).send('User not found');
        }
        res.json(results[0]);
    });
});
// Route to serve the Profile.html file
app.get('/', isAuthenticated, (req, res) => {
    if (req.session.user.role === 'admin') {
        res.sendFile(path.join(__dirname, 'Profile.html'));
    } else if (req.session.user.role === 'supervisor') {
        res.sendFile(path.join(__dirname, 'Profile.html'));
    } else if (req.session.user.role === 'user') {
        res.sendFile(path.join(__dirname, 'Profile.html'));
    } else {
        res.status(403).json({ error: 'Access denied' });
    }
});
module.exports = app;