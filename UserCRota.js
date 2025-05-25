const express = require('express');
const mysql = require('mysql2');
const bodyParser = require('body-parser');
const http = require('http');
const fs = require('fs');
const path = require('path');
const { getPool, mainPool } = require('./db.js'); // Import the connection pool functions
const { sessionMiddleware, isAuthenticated, isAdmin, isSupervisor, isUser } = require('./sessionConfig'); // Adjust the path as needed

const app = express();

// Middleware
app.use(sessionMiddleware);
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Route to fetch rota data
app.get('/rota', isAuthenticated, (req, res) => {
    const { start, end } = req.query;
    const dbName = req.session.user.dbName; // Get the database name from the session

    if (!start || !end) {
        return res.status(400).json({ success: false, message: 'Start and end dates are required' });
    }

    if (!dbName) {
        return res.status(401).json({ error: 'User not authenticated' });
    }

    const pool = getPool(dbName); // Get the correct connection pool

    const query = `
        SELECT name, lastName, day, startTime, endTime, designation 
        FROM rota 
        WHERE day BETWEEN ? AND ?`; // Updated SQL query with date range filter

    pool.query(query, [start, end], (err, results) => {
        if (err) {
            console.error('Error fetching data:', err);
            res.status(500).json({ success: false, message: 'Server error' });
            return;
        }
        res.json(results);
    });
});

// Route to serve the correct HTML file based on user role
app.get('/', isAuthenticated, (req, res) => {
    if (req.session.user.role === 'supervisor') {
        res.sendFile(path.join(__dirname, 'UserCRota.html'));
    } else if (req.session.user.role === 'user') {
        res.sendFile(path.join(__dirname, 'UserCRota.html'));
    } else if (req.session.user.role === 'admin' || req.session.user.role === 'AM') {
        res.sendFile(path.join(__dirname, 'UserCRota.html'));
    } else {
        res.status(403).json({ error: 'Access denied' });
    }
});

module.exports = app; // Export the entire Express application