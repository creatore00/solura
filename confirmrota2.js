const express = require('express');
const mysql = require('mysql2');
const bodyParser = require('body-parser');
const nodemailer = require('nodemailer');
const http = require('http');
const fs = require('fs');
const path = require('path');
const { getPool, mainPool } = require('./db.js'); // Import the connection pool functions
const { sessionMiddleware, isAuthenticated, isAdmin, isSupervisor } = require('./sessionConfig'); // Adjust the path as needed

const app = express();

// Middleware
app.use(sessionMiddleware);
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Function to generate a unique ID
function generateUniqueId(pool, callback) {
    const id = Math.floor(Math.random() * 1e16).toString().padStart(16, '0');

    // Check if the ID already exists
    pool.query('SELECT COUNT(*) AS count FROM rota WHERE id = ?', [id], (err, results) => {
        if (err) {
            callback(err);
        } else if (results[0].count > 0) {
            // ID exists, generate a new one
            generateUniqueId(pool, callback);
        } else {
            // ID is unique
            callback(null, id);
        }
    });
}

// API endpoint to get rota data for a specific day
app.get('/api/rota', isAuthenticated, (req, res) => {
    const dbName = req.session.user.dbName; // Get the database name from the session

    if (!dbName) {
        return res.status(401).json({ message: 'User not authenticated' });
    }

    const pool = getPool(dbName); // Get the correct connection pool

    const day = req.query.day;
    if (!day) {
        return res.status(400).json({ error: 'Day is required' });
    }

    // Query to get rota data for the specified day
    const rotaQuery = `
        SELECT name, lastName, wage, day, designation, startTime, endTime
        FROM rota
        WHERE day = ?
    `;

    // Query to get confirmed rota data
    const confirmedRotaQuery = `
        SELECT name, lastName, designation, day, startTime, endTime
        FROM ConfirmedRota2
    `;

    // Fetch both rota and confirmed rota data
    pool.query(rotaQuery, [day], (err, rotaResults) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }

        pool.query(confirmedRotaQuery, (err, confirmedRotaResults) => {
            if (err) {
                return res.status(500).json({ error: err.message });
            }

            // Convert confirmed rota data to a set for quick lookup
            const confirmedRotaSet = new Set(
                confirmedRotaResults.map(entry => `${entry.name} ${entry.lastName} ${entry.designation} ${entry.day} ${entry.startTime} ${entry.endTime}`)
            );

            // Filter out rota data that is already confirmed
            const filteredRotaResults = rotaResults.filter(entry => {
                const key = `${entry.name} ${entry.lastName} ${entry.designation} ${entry.day} ${entry.startTime} ${entry.endTime}`;
                return !confirmedRotaSet.has(key);
            });

            res.json(filteredRotaResults);
        });
    });
});

// API endpoint to get confirmed rota data
app.get('/api/confirmed-rota', isAuthenticated, (req, res) => {
    const dbName = req.session.user.dbName; // Get the database name from the session

    if (!dbName) {
        return res.status(401).json({ message: 'User not authenticated' });
    }

    const pool = getPool(dbName); // Get the correct connection pool

    const day = req.query.day; // Get the 'day' parameter from the query string

    if (!day) {
        return res.status(400).json({ error: 'Day parameter is required' });
    }

    const sql = 'SELECT * FROM ConfirmedRota WHERE day = ?';
    pool.query(sql, [day], (err, results) => {
        if (err) {
            console.error('Error fetching confirmed rota:', err);
            return res.status(500).json({ error: 'Internal Server Error' });
        }

        res.json(results);
    });
});

// Endpoint to delete an employee from the rota
app.delete('/delete-employee', isAuthenticated, (req, res) => {
    const dbName = req.session.user.dbName; // Get the database name from the session

    if (!dbName) {
        return res.status(401).json({ message: 'User not authenticated' });
    }

    const pool = getPool(dbName); // Get the correct connection pool

    const { name, lastName, designation, day } = req.body;

    // Validate the incoming data
    if (!name || !lastName || !designation || !day) {
        return res.status(400).send('Missing required parameters.');
    }

    // Prepare the query to delete the employee's rota entry from the database
    const deleteRotaQuery = `
        DELETE FROM rota
        WHERE name = ? AND lastName = ? AND designation = ? AND day = ?
    `;

    // Execute the query to delete the employee entry
    pool.query(deleteRotaQuery, [name, lastName, designation, day], (err, results) => {
        if (err) {
            console.error('Error deleting rota entry:', err);
            return res.status(500).send('Internal Server Error');
        }

        // If no rows were deleted, return a message indicating no match found
        if (results.affectedRows === 0) {
            console.log(`No matching entry found for ${name} ${lastName} (${designation}) on ${day}`);
            return res.status(404).send('No matching record found to delete.');
        }

        // If successful, send a success response
        console.log(`Successfully deleted rota entry for ${name} ${lastName} (${designation}) on ${day}`);
        res.status(200).send('Employee entry successfully removed from the database.');
    });
});

// Endpoint to confirm rota
app.post('/confirm-rota', isAuthenticated, (req, res) => {
    const dbName = req.session.user.dbName; // Get the database name from the session

    if (!dbName) {
        return res.status(401).json({ message: 'User not authenticated' });
    }

    const pool = getPool(dbName); // Get the correct connection pool

    const rotaData = req.body;
    const userEmail = req.session.user.email; // Get the logged-in user's email
    console.log('Received rota data:', rotaData);

    if (!rotaData || !Array.isArray(rotaData) || rotaData.length === 0) {
        return res.status(400).send('Invalid rota data.');
    }

    const day = rotaData[0].day;

    // Queries
    const deleteConfirmedRotaQuery = 'DELETE FROM ConfirmedRota2 WHERE day = ?';
    const insertConfirmedRotaQuery = `
        INSERT INTO ConfirmedRota2 (name, lastName, wage, day, startTime, endTime, designation, who) 
        VALUES ?
    `;
    const deleteRotaQuery = `
        DELETE FROM rota
        WHERE name = ? AND lastName = ? AND designation = ? AND day = ?
    `;
    const insertRotaQuery = `
        INSERT INTO rota (id, name, lastName, designation, day, startTime, endTime)
        VALUES ?
    `;

    // Prepare values to insert into ConfirmedRota
    const confirmedRotaValues = rotaData.flatMap(entry => {
        const { name, lastName, wage, day, designation, times } = entry;
        return times.map(time => {
            const { startTime, endTime } = time;
            return [name, lastName, wage, day, startTime, endTime, designation, userEmail];
        });
    });

    // Print values to be inserted into the database
    console.log('Values to be inserted into ConfirmedRota:', confirmedRotaValues);

    // Delete old entries for the given day from ConfirmedRota
    pool.query(deleteConfirmedRotaQuery, [day], (err) => {
        if (err) {
            console.error('Error deleting existing confirmed rota data:', err);
            return res.status(500).send('Internal Server Error');
        }

        // Insert new or updated values into ConfirmedRota
        pool.query(insertConfirmedRotaQuery, [confirmedRotaValues], (err) => {
            if (err) {
                console.error('Error inserting rota data:', err);
                return res.status(500).send('Internal Server Error');
            }

            // Generate unique IDs and handle each entry
            const updateTasks = rotaData.flatMap(entry => {
                const { name, lastName, day, designation, times } = entry;

                // For each time frame, generate a unique ID
                const timeFrameTasks = times.map(time => {
                    const { startTime, endTime } = time;

                    return new Promise((resolve, reject) => {
                        generateUniqueId(pool, (err, uniqueId) => {
                            if (err) {
                                reject(err);
                            } else {
                                // Delete old entries from `rota`
                                pool.query(deleteRotaQuery, [name, lastName, designation, day], (err) => {
                                    if (err) {
                                        reject(err);
                                    } else {
                                        // Prepare value for insertion with the unique ID
                                        const value = [uniqueId, name, lastName, designation, day, startTime, endTime];

                                        // Insert new entry into `rota` with the unique ID
                                        pool.query(insertRotaQuery, [[value]], (err) => {
                                            if (err) {
                                                reject(err);
                                            } else {
                                                resolve();
                                            }
                                        });
                                    }
                                });
                            }
                        });
                    });
                });

                return timeFrameTasks;
            }).flat();

            Promise.all(updateTasks)
                .then(() => {
                    res.status(200).send('Rota Confirmed and Updated Successfully.');
                })
                .catch(err => {
                    console.error('Error updating rota data:', err);
                    res.status(500).send('Internal Server Error');
                });
        });
    });
});

// Route to fetch employees' name, last name, and designation
app.get('/api/employees', isAuthenticated, (req, res) => {
    const dbName = req.session.user.dbName; // Get the database name from the session

    if (!dbName) {
        return res.status(401).json({ message: 'User not authenticated' });
    }

    const pool = getPool(dbName); // Get the correct connection pool

    const sql = 'SELECT name, lastName, designation FROM Employees';
    pool.query(sql, (err, results) => {
        if (err) {
            console.error('Error fetching employees:', err);
            return res.status(500).json({ error: 'Internal Server Error' });
        }
        res.json(results);
    });
});

// Route to handle logout
app.get('/logout', (req, res) => {
    // Check if there is an active session
    if (req.session && req.session.user) {
        req.session.destroy(err => {
            if (err) {
                console.error('Failed to logout:', err);
                return res.status(500).json({ error: 'Failed to logout' });
            }
            res.clearCookie('connect.sid'); // Clear the session cookie
            res.redirect('/');
        });
    } else {
        // If no active session, just redirect to the login page
        res.redirect('/');
    }
});

// Route to serve the confirmrota2.html file
app.get('/', isAuthenticated, (req, res) => {
    if (req.session.user.role === 'supervisor') {
        res.sendFile(path.join(__dirname, 'confirmrota2.html'));
    } else {
        res.status(403).json({ error: 'Access denied' });
    }
});

// Export the entire Express application
module.exports = app;