const http = require('http');
const fs = require('fs');
const ejs = require('ejs');
const mysql = require('mysql2');
const path = require('path');
const express = require('express');
const bodyParser = require('body-parser');
const { v4: uuidv4 } = require('uuid');
const { getPool, mainPool } = require('./db.js'); // Import the connection pool functions
const { sessionMiddleware, isAuthenticated, isAdmin, isSupervisor } = require('./sessionConfig'); // Adjust the path as needed

const app = express();

// Middleware
app.use(sessionMiddleware);
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Endpoint to insert cash reports
app.post('/api/cash-reports', isAuthenticated, (req, res) => {
    const dbName = req.session.user.dbName; // Get the database name from the session

    if (!dbName) {
        return res.status(401).json({ message: 'User not authenticated' });
    }

    const pool = getPool(dbName); // Get the correct connection pool

    const weekData = req.body; // Get the object containing week data

    // SQL query for inserting or updating cash reports
    const sql = `
        INSERT INTO cash_reports (
            day, zreport, fifty_pounds, twenty_pounds, ten_pounds, five_pounds, 
            two_pounds, one_pound, fifty_pence, twenty_pence, ten_pence, 
            five_pence, totalcash, card, service, petty, onaccount, 
            floatday, total, eod
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON DUPLICATE KEY UPDATE 
            day = VALUES(day), zreport = VALUES(zreport), fifty_pounds = VALUES(fifty_pounds), 
            twenty_pounds = VALUES(twenty_pounds), ten_pounds = VALUES(ten_pounds), 
            five_pounds = VALUES(five_pounds), two_pounds = VALUES(two_pounds), 
            one_pound = VALUES(one_pound), fifty_pence = VALUES(fifty_pence), 
            twenty_pence = VALUES(twenty_pence), ten_pence = VALUES(ten_pence), 
            five_pence = VALUES(five_pence), totalcash = VALUES(totalcash), 
            card = VALUES(card), service = VALUES(service), 
            petty = VALUES(petty), onaccount = VALUES(onaccount), 
            floatday = VALUES(floatday), total = VALUES(total), 
            eod = VALUES(eod)
    `;

    // Create an array of promises for each day's data insertion or update
    const promises = Object.entries(weekData).map(([day, data]) => {
        const values = [
            data.day, // The dynamic day value (e.g., Monday)
            data.zReport || 0, // The dynamic date for the day
            data.fifty || 0, // Amount of £50 notes
            data.twenty || 0, // Amount of £20 notes
            data.ten || 0, // Amount of £10 notes
            data.five || 0, // Amount of £5 notes
            data.two || 0, // Amount of £2 coins
            data.one || 0, // Amount of £1 coins
            data.fiftyPence || 0, // Amount of 50p coins
            data.twentyPence || 0, // Amount of 20p coins
            data.tenPence || 0, // Amount of 10p coins
            data.fivePence || 0, // Amount of 5p coins
            data.cash || 0, // Total cash amount
            data.cc || 0, // Credit card total
            data.service || 0, // Service charges
            data.pettyCash || 0, // Petty cash
            data.onAccount || 0, // On account
            data.float || 0, // Float amount
            data.total || 0, // Total amount
            data.missing || 0 // Missing data (if applicable)
        ];

        // Return a promise for each SQL insert/update operation
        return new Promise((resolve, reject) => {
            pool.query(sql, values, (err, result) => {
                if (err) {
                    console.error('Error inserting/updating data: ', err);
                    return reject(err); // Reject if there's an error
                }
                resolve(result.insertId); // Resolve with the inserted or updated ID
            });
        });
    });

    // Wait for all promises (inserts/updates) to complete
    Promise.all(promises)
        .then(results => {
            res.status(201).json({
                message: 'Cash reports created/updated successfully!',
                reportIds: results // Array of inserted or updated IDs
            });
        })
        .catch(err => {
            console.error('Error during batch insert/update: ', err);
            res.status(500).json({ error: 'Database error.' });
        });
});

// Route to retrieve cash report data based on week
app.get('/cashreport', isAuthenticated, (req, res) => {
    const dbName = req.session.user.dbName; // Get the database name from the session

    if (!dbName) {
        return res.status(401).json({ message: 'User not authenticated' });
    }

    const pool = getPool(dbName); // Get the correct connection pool

    const { startDate, endDate } = req.query; // Use query parameters for startDate and endDate

    // Convert startDate and endDate into Date objects
    const start = new Date(startDate.split('/').reverse().join('-')); // Convert to yyyy-mm-dd
    const end = new Date(endDate.split('/').reverse().join('-')); // Convert to yyyy-mm-dd

    // Adjust start to the first Monday (or keep the start date if it's already Monday)
    const firstMonday = new Date(start);
    firstMonday.setDate(start.getDate() + (1 - start.getDay() + 7) % 7); // Get the next Monday

    // Adjust end to the last Sunday (or keep the end date if it's already Sunday)
    const lastSunday = new Date(end);
    lastSunday.setDate(end.getDate() + (7 - end.getDay()) % 7); // Get the next Sunday

    // Generate all dates from firstMonday to lastSunday
    const dateArray = [];
    for (let d = firstMonday; d <= lastSunday; d.setDate(d.getDate() + 1)) {
        // Format each date as 'Monday dd/mm/yyyy' regardless of the actual day
        const formattedDate = `${d.toLocaleString('en-US', { weekday: 'long' })} ${d.getDate().toString().padStart(2, '0')}/${(d.getMonth() + 1).toString().padStart(2, '0')}/${d.getFullYear()}`;
        dateArray.push(formattedDate);
    }

    // Create a placeholder string for the SQL query
    const placeholders = dateArray.map(() => '?').join(', ');

    // SQL query to get data for the specified days
    const sql = `
        SELECT day, zreport, fifty_pounds, twenty_pounds, ten_pounds, five_pounds, 
            two_pounds, one_pound, fifty_pence, twenty_pence, ten_pence, 
            five_pence, totalcash, card, service, petty, onaccount, 
            floatday, total, eod
        FROM cash_reports
        WHERE day IN (${placeholders})
    `;

    // Execute the query with the formatted dates
    pool.query(sql, dateArray, (err, results) => {
        if (err) {
            console.error('Error retrieving data:', err);
            return res.status(500).json({ error: 'Database error.' });
        }
        res.status(200).json(results); // Send the data as JSON
    });
});

// Endpoint to retrieve cash reports by date range
app.get('/cash', isAuthenticated, (req, res) => {
    const dbName = req.session.user.dbName; // Get the database name from the session

    if (!dbName) {
        return res.status(401).json({ message: 'User not authenticated' });
    }

    const pool = getPool(dbName); // Get the correct connection pool

    const { startdate, enddate } = req.query;

    // Validate query parameters
    if (!startdate || !enddate) {
        return res.status(400).json({ error: 'Start date and end date are required.' });
    }

    // SQL query to select data
    const sql = `
        SELECT * FROM cash_reports 
        WHERE startdate >= ? AND enddate <= ?`;

    pool.query(sql, [startdate, enddate], (err, results) => {
        if (err) {
            console.error('Error retrieving data: ', err);
            return res.status(500).json({ error: 'Database error.' });
        }
        res.status(200).json(results);
    });
});

// Route to serve the EndDay.html file
app.get('/', isAuthenticated, (req, res) => {
    if (req.session.user.role === 'admin' || req.session.user.role === 'AM') {
        res.sendFile(path.join(__dirname, 'EndDay.html'));
    } else if (req.session.user.role === 'supervisor') {
        res.sendFile(path.join(__dirname, 'EndDay.html'));
    } else {
        res.status(403).json({ error: 'Access denied' });
    }
});

module.exports = app; // Export the entire Express application