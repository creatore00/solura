const express = require('express');
const mysql = require('mysql2');
const bodyParser = require('body-parser');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const { getPool, mainPool } = require('./db.js'); // Import the connection pool functions
const { sessionMiddleware, isAuthenticated, isAdmin, isSupervisor, isUser } = require('./sessionConfig'); // Adjust the path as needed

const app = express();

// Middleware
app.use(sessionMiddleware);
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Route to get all holiday requests for the logged-in user
app.get('/holidays', isAuthenticated, (req, res) => {
    const email = req.session.user.email; // Get the email from the session
    const dbName = req.session.user.dbName; // Get the database name from the session

    if (!email || !dbName) {
        return res.status(401).send('Unauthorized: No session found');
    }

    const pool = getPool(dbName); // Get the correct connection pool

    // Query the database to get holiday requests for the logged-in user
    const sql = 'SELECT * FROM Holiday WHERE accepted = "true" AND email = ?';
    pool.query(sql, [email], (err, results) => {
        if (err) {
            console.error('Error fetching holiday requests:', err);
            res.status(500).send('Error fetching holiday requests');
        } else {
            res.json(results); // Send holiday requests as JSON response
        }
    });
});

// Route to serve the correct HTML file based on user role
app.get('/', isAuthenticated, (req, res) => {
    if (req.session.user.role === 'admin' || req.session.user.role === 'AM') {
        res.sendFile(path.join(__dirname, '/UserHolidays.html'));
    } else if (req.session.user.role === 'supervisor') {
        res.sendFile(path.join(__dirname, '/UserHolidays.html'));
    } else if (req.session.user.role === 'user') {
        res.sendFile(path.join(__dirname, '/UserHolidays.html'));
    } else {
        res.status(403).json({ error: 'Access denied' });
    }
});

module.exports = app; // Export the entire Express application