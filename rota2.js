const nodemailer = require('nodemailer');
const http = require('http');
const fs = require('fs');
const pdf = require('html-pdf');
const ejs = require('ejs');
const mysql = require('mysql2');
const path = require('path');
const express = require('express');
const puppeteer = require('puppeteer');
const bodyParser = require('body-parser');
const { v4: uuidv4 } = require('uuid');
const { getPool, mainPool } = require('./db.js'); // Import the connection pool functions
const { sessionMiddleware, isAuthenticated, isAdmin } = require('./sessionConfig'); // Adjust the path as needed

const app = express();

// Middleware
app.use(sessionMiddleware);
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Function to Delete time frame
app.delete('/deleteTimeFrame', isAuthenticated, (req, res) => {
    const dbName = req.session.user.dbName; // Get the database name from the session

    if (!dbName) {
        return res.status(401).json({ success: false, message: 'User not authenticated' });
    }

    const pool = getPool(dbName); // Get the correct connection pool

    const { day, name, lastName, startTime, endTime } = req.body;

    const deleteQuery = 'DELETE FROM rota WHERE day = ? AND name = ? AND lastName = ? AND startTime = ? AND endTime = ?';

    pool.query(deleteQuery, [day, name, lastName, startTime, endTime], (err, result) => {
        if (err) {
            console.error('Error deleting time frame from the database:', err);
            return res.status(500).send('Error deleting time frame');
        }

        console.log(`Time frame for ${name} ${lastName} on ${day} from ${startTime} to ${endTime} deleted.`);
        res.status(200).send('Time frame deleted successfully');
    });
});

// Function to save rota
app.post('/saveData', isAuthenticated, (req, res) => {
    const dbName = req.session.user.dbName; // Get the database name from the session

    if (!dbName) {
        return res.status(401).json({ success: false, message: 'User not authenticated' });
    }

    const pool = getPool(dbName); // Get the correct connection pool

    console.log('Request Body:', req.body);
    const tableData = req.body;
    const insertQuery = 'INSERT INTO rota (id, name, lastName, wage, day, startTime, endTime, designation) VALUES (?, ?, ?, ?, ?, ?, ?, ?)';
    const updateQuery = 'UPDATE rota SET name = ?, lastName = ?, wage = ?, day = ?, startTime = ?, endTime = ?, designation = ? WHERE id = ?';
    const updateByNameDayQuery = 'UPDATE rota SET wage = ?, designation = ? WHERE name = ? AND lastName = ? AND day = ? AND startTime = ? AND endTime = ?';

    // Initialize an array to collect messages
    const operationMessages = [];

    tableData.forEach(row => {
        const id = generateUniqueId();
        const { name, lastName, wage, day, startTime, endTime, designation } = row;

        // Check for existing record based on id
        pool.query('SELECT id FROM rota WHERE id = ?', [id], (checkIdErr, checkIdResult) => {
            if (checkIdErr) {
                console.error('Error checking data by ID in the main database:', checkIdErr);
                return res.status(500).send('Error saving data');
            }

            if (checkIdResult.length > 0) {
                // If the record with the same id exists, update it
                pool.query(updateQuery, [name, lastName, wage, day, startTime, endTime, designation, id], (updateIdErr, updateIdResult) => {
                    if (updateIdErr) {
                        console.error('Error updating data by ID in the main database:', updateIdErr);
                        return res.status(500).send('Error saving data');
                    } else {
                        console.log(`Record with ID ${id} updated.`);
                        operationMessages.push(`Record with ID ${id} updated.`);
                    }
                });
            } else {
                // Check for existing record based on name, lastName, day, startTime, and endTime
                pool.query('SELECT id FROM rota WHERE name = ? AND lastName = ? AND day = ? AND startTime = ? AND endTime = ?', [name, lastName, day, startTime, endTime], (checkNameDayErr, checkNameDayResult) => {
                    if (checkNameDayErr) {
                        console.error('Error checking data by name, day, startTime, and endTime in the main database:', checkNameDayErr);
                        return res.status(500).send('Error saving data');
                    }

                    if (checkNameDayResult.length > 0) {
                        // If the record with the same name, lastName, day, startTime, and endTime exists, update it
                        pool.query(updateByNameDayQuery, [wage, designation, name, lastName, day, startTime, endTime], (updateNameDayErr, updateNameDayResult) => {
                            if (updateNameDayErr) {
                                console.error('Error updating data by name, day, startTime, and endTime in the main database:', updateNameDayErr);
                                return res.status(500).send('Error saving data');
                            } else {
                                console.log(`Record for ${name} ${lastName} on ${day} from ${startTime} to ${endTime} updated.`);
                                operationMessages.push(`Record for ${name} ${lastName} on ${day} from ${startTime} to ${endTime} updated.`);
                            }
                        });
                    } else {
                        // If the record with the same name, lastName, day, startTime, and endTime does not exist, insert a new record
                        pool.query(insertQuery, [id, name, lastName, wage, day, startTime, endTime, designation], (insertErr, insertResult) => {
                            if (insertErr) {
                                console.error('Error inserting data into the main database:', insertErr);
                                return res.status(500).send('Error saving data');
                            } else {
                                console.log(`New record inserted with ID ${id}.`);
                                operationMessages.push(`New record inserted with ID ${id}.`);
                            }
                        });
                    }
                });
            }
        });
    });

    // Send a success response after all rows have been processed
    res.status(200).send(operationMessages.join('\n'));
});

// Helper function to group and merge time frames for the same person on the same day
function groupAndMergeRotaData(data) {
    const groupedData = {};

    data.forEach(row => {
        const key = `${row.day}-${row.name}-${row.lastName}`;
        if (!groupedData[key]) {
            groupedData[key] = {
                day: row.day,
                name: row.name,
                lastName: row.lastName,
                designation: row.designation,
                timeFrames: []
            };
        }
        groupedData[key].timeFrames.push({ startTime: row.startTime, endTime: row.endTime });
    });

    return Object.values(groupedData).map(entry => {
        const { day, name, lastName, designation, timeFrames } = entry;
        const mergedTimeFrames = timeFrames.map(tf => `${tf.startTime} - ${tf.endTime}`).join(', ');
        return { day, name, lastName, timeFrames: mergedTimeFrames, designation };
    });
}

// Route to handle fetching rota data
app.get('/rota', isAuthenticated, (req, res) => {
    const dbName = req.session.user.dbName; // Get the database name from the session

    if (!dbName) {
        return res.status(401).json({ success: false, message: 'User not authenticated' });
    }

    const pool = getPool(dbName); // Get the correct connection pool

    const { days } = req.query; // Get the days parameter from the query string
    if (!days) {
        return res.status(400).send('Missing "days" query parameter');
    }

    // Split the comma-separated string of days into an array
    const weekDates = days.split(',');

    console.log('Filtered weekDates:', weekDates);

    // SQL query to fetch data for the specified days
    const query = `
        SELECT name, lastName, wage, day, startTime, endTime, designation
        FROM rota
        WHERE day IN (?)`;

    pool.query(query, [weekDates], (err, results) => {
        if (err) {
            console.error('Error fetching employee data:', err);
            return res.status(500).send('Error fetching employee data');
        }

        console.log('Filtered Results:', results);

        // Group results by day
        const groupedData = {};
        results.forEach(row => {
            if (!groupedData[row.day]) groupedData[row.day] = [];
            groupedData[row.day].push(row);
        });

        res.json(groupedData);
    });
    console.log('Executing SQL Query:', query, 'with weekDates:', weekDates);
});

// Route to handle fetching employee data
app.get('/employees', isAuthenticated, (req, res) => {
    const dbName = req.session.user.dbName; // Get the database name from the session

    if (!dbName) {
        return res.status(401).json({ success: false, message: 'User not authenticated' });
    }

    const pool = getPool(dbName); // Get the correct connection pool

    pool.query('SELECT name, lastName, wage, designation, position FROM Employees', (err, results) => {
        if (err) {
            console.error('Error fetching employee data:', err);
            return res.status(500).send('Error fetching employee data');
        }
        const employees = results.map(row => ({
            name: row.name,
            lastName: row.lastName,
            wage: row.wage,
            designation: row.designation,
            position: row.position
        }));
        res.json(employees);
    });
});

// Endpoint to retrieve holiday data
app.get('/getHolidayData', isAuthenticated, (req, res) => {
    const dbName = req.session.user.dbName; // Get the database name from the session

    if (!dbName) {
        return res.status(401).json({ success: false, message: 'User not authenticated' });
    }

    const pool = getPool(dbName); // Get the correct connection pool

    // Query to select specific columns from Holiday table
    const sql = 'SELECT name, lastName, startDate, endDate, accepted FROM Holiday';

    // Execute the query
    pool.query(sql, (err, results) => {
        if (err) {
            console.error('Error executing query:', err);
            res.status(500).send('Internal Server Error');
            return;
        }
        // Send the results as JSON
        res.json(results);
    });
});

// Route to insert total spent value into the database
app.post('/api/insert-total-spent', isAuthenticated, (req, res) => {
    const dbName = req.session.user.dbName; // Get the database name from the session

    if (!dbName) {
        return res.status(401).json({ success: false, message: 'User not authenticated' });
    }

    const pool = getPool(dbName); // Get the correct connection pool

    const { totalSpent, day } = req.body;

    if (!totalSpent || isNaN(totalSpent)) {
        return res.status(400).json({ success: false, message: 'Invalid total spent value' });
    }

    const query = `
        INSERT INTO banda (beforee, day)
        VALUES (?, ?)
    `;

    pool.query(query, [totalSpent, day], (err, result) => {
        if (err) {
            console.error('Error inserting total spent value:', err);
            return res.status(500).json({ success: false, message: 'Error inserting data' });
        }

        res.status(200).json({ success: true, message: 'Total spent value inserted successfully' });
    });
});

// Route to serve the rota2.html file
app.get('/', isAuthenticated, (req, res) => {
    if (req.session.user.role === 'admin') {
        res.sendFile(path.join(__dirname, 'rota2.html'));
    } else if (req.session.user.role === 'supervisor') {
        res.sendFile(path.join(__dirname, 'rota2.html'));
    } else {
        res.status(403).json({ error: 'Access denied' });
    }
});

module.exports = app; // Export the entire Express application