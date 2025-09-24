const express = require('express');
const bodyParser = require('body-parser');
const path = require('path');
const { getPool } = require('./db.js'); // Make sure this exports a function that returns a MySQL pool
const { sessionMiddleware, isAuthenticated } = require('./sessionConfig'); 

const app = express();

// Middleware
app.use(sessionMiddleware);
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Route to fetch rota data
app.get('/rota', isAuthenticated, (req, res) => {
    const { start, end } = req.query;
    const dbName = req.session.user?.dbName;

    if (!start || !end) {
        return res.status(400).json({ success: false, message: 'Start and end dates are required' });
    }

    if (!dbName) {
        return res.status(401).json({ success: false, message: 'User not authenticated with a DB' });
    }

    const pool = getPool(dbName);

    // Use proper SQL for null check, NOT a string 'null'
    const query = `
        SELECT r.name, r.lastName, r.day, r.startTime, r.endTime, r.designation 
        FROM rota r
        INNER JOIN Employees e ON r.name = e.name AND r.lastName = e.lastName
        WHERE STR_TO_DATE(SUBSTRING_INDEX(r.day, ' ', 1), '%d/%m/%Y') 
            BETWEEN STR_TO_DATE(?, '%d/%m/%Y') 
                AND STR_TO_DATE(?, '%d/%m/%Y')
        AND e.situation IS NULL
    `;
    pool.query(query, [start, end], (err, results) => {
        if (err) {
            console.error('Error fetching data:', err);
            res.status(500).json({ success: false, message: 'Server error' });
            return;
        }
        console.log('Results including Sunday:', results);
        res.json(results);
    });
});

// Route to serve HTML based on user role
app.get('/', isAuthenticated, (req, res) => {
    const role = req.session.user?.role;

    if (!role) {
        return res.status(401).json({ error: 'User not authenticated' });
    }

    // For now, all roles point to the same HTML
    res.sendFile(path.join(__dirname, 'UserCRota.html'));
});

module.exports = app;
