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
const generateUniqueId = async (pool) => {
    let id;
    let isUnique = false;

    while (!isUnique) {
        id = Math.floor(Math.random() * 1e16).toString().padStart(16, '0'); // Generate a 16-digit code
        const [rows] = await pool.promise().query(`SELECT id FROM rota WHERE id = ?`, [id]);
        if (rows.length === 0) {
            isUnique = true;
        }
    }

    return id;
};

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
        FROM ConfirmedRota
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

// Check if Rota has been confirmed by Supervisor
app.get('/api/check-confirmed-rota2', isAuthenticated, (req, res) => {
    const dbName = req.session.user.dbName; // Get the database name from the session

    if (!dbName) {
        return res.status(401).json({ message: 'User not authenticated' });
    }

    const pool = getPool(dbName); // Get the correct connection pool

    const day = req.query.day;
    if (!day) {
        return res.status(400).json({ error: 'Day is required' });
    }

    // Query to check if the date exists in either ConfirmedRota2 or ConfirmedRota
    const sql = `
        SELECT 
            (SELECT COUNT(*) FROM ConfirmedRota2 WHERE day = ?) AS countConfirmedRota2,
            (SELECT COUNT(*) FROM ConfirmedRota WHERE day = ?) AS countConfirmedRota
    `;

    pool.query(sql, [day, day], (err, results) => {
        if (err) {
            console.error('Error checking ConfirmedRota2 and ConfirmedRota:', err);
            return res.status(500).json({ error: 'Internal Server Error' });
        }

        const existsInConfirmedRota2 = results[0].countConfirmedRota2 > 0;
        const existsInConfirmedRota = results[0].countConfirmedRota > 0;

        // If the date exists in either table, return exists: true
        const exists = existsInConfirmedRota2 || existsInConfirmedRota;
        res.json({ exists });
    });
});

// API endpoint to get confirmed rota data by date
app.get('/api/confirmed-rota', isAuthenticated, (req, res) => {
    const dbName = req.session.user.dbName; // Get the database name from the session

    if (!dbName) {
        return res.status(401).json({ message: 'User not authenticated' });
    }

    const pool = getPool(dbName); // Get the correct connection pool

    const day = req.query.day; // Get the day from query parameter

    if (!day) {
        return res.status(400).json({ error: 'Day is required' });
    }

    // Query the ConfirmedRota table using the provided day
    const sql = 'SELECT * FROM ConfirmedRota WHERE day = ?';
    pool.query(sql, [day], (err, results) => {
        if (err) {
            console.error('Error fetching confirmed rota:', err);
            return res.status(500).json({ error: 'Internal Server Error' });
        }

        // Return the results as JSON
        res.json(results);
    });
});

// Function to remove Employee from Rota
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

    // Prepare the queries to delete the employee's rota entry from the databases
    const deleteRotaQuery = `
        DELETE FROM rota
        WHERE name = ? AND lastName = ? AND designation = ? AND day = ?
    `;
    const deleteConfirmedRotaQuery = `
        DELETE FROM ConfirmedRota
        WHERE name = ? AND lastName = ? AND designation = ? AND day = ?
    `;
    const deleteConfirmedRota2Query = `
        DELETE FROM ConfirmedRota2
        WHERE name = ? AND lastName = ? AND designation = ? AND day = ?
    `;

    // Execute the first delete query (from rota)
    pool.query(deleteRotaQuery, [name, lastName, designation, day], (err, results) => {
        if (err) {
            console.error('Error deleting from rota:', err);
            return res.status(500).send('Internal Server Error');
        }

        // Check if any rows were deleted from rota
        if (results.affectedRows === 0) {
            console.log(`No matching entry found in rota for ${name} ${lastName} (${designation}) on ${day}`);
        }

        // Execute the second delete query (from ConfirmedRota)
        pool.query(deleteConfirmedRotaQuery, [name, lastName, designation, day], (err, results) => {
            if (err) {
                console.error('Error deleting from ConfirmedRota:', err);
                return res.status(500).send('Internal Server Error');
            }

            // Check if any rows were deleted from ConfirmedRota
            if (results.affectedRows === 0) {
                console.log(`No matching entry found in ConfirmedRota for ${name} ${lastName} (${designation}) on ${day}`);
            }

            // Execute the third delete query (from ConfirmedRota2)
            pool.query(deleteConfirmedRota2Query, [name, lastName, designation, day], (err, results) => {
                if (err) {
                    console.error('Error deleting from ConfirmedRota2:', err);
                    return res.status(500).send('Internal Server Error');
                }

                // Check if any rows were deleted from ConfirmedRota2
                if (results.affectedRows === 0) {
                    console.log(`No matching entry found in ConfirmedRota2 for ${name} ${lastName} (${designation}) on ${day}`);
                }

                console.log(`Successfully deleted entries for ${name} ${lastName} (${designation}) on ${day}`);
                res.status(200).send('Employee entry successfully removed from all relevant tables.');
            });
        });
    });
});

// Function to Confirm Rota
app.post('/confirm-rota', isAuthenticated, async (req, res) => {
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
    const deleteConfirmedRotaQuery = 'DELETE FROM ConfirmedRota WHERE day = ?';
    const insertConfirmedRotaQuery = `
        INSERT INTO ConfirmedRota (name, lastName, wage, day, startTime, endTime, designation, who) 
        VALUES ?`;
    const deleteRotaQuery = `
        DELETE FROM rota
        WHERE name = ? AND lastName = ? AND designation = ? AND day = ?`;
    const insertRotaQuery = `
        INSERT INTO rota (id, name, lastName, designation, day, startTime, endTime)
        VALUES ?`;

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
    pool.query(deleteConfirmedRotaQuery, [day], async (err) => {
        if (err) {
            console.error('Error deleting existing confirmed rota data:', err);
            return res.status(500).send('Internal Server Error');
        }

        // Insert new or updated values into ConfirmedRota
        pool.query(insertConfirmedRotaQuery, [confirmedRotaValues], async (err) => {
            if (err) {
                console.error('Error inserting rota data:', err);
                return res.status(500).send('Internal Server Error');
            }

            // Generate unique IDs and handle each entry
            const updateTasks = rotaData.flatMap(entry => {
                const { name, lastName, day, designation, times } = entry;

                // For each time frame, generate a unique ID
                const timeFrameTasks = times.map(async (time) => {
                    const { startTime, endTime } = time;

                    try {
                        // Generate unique ID for each time frame
                        const uniqueId = await generateUniqueId(pool);

                        // Delete old entries from `rota`
                        await new Promise((resolve, reject) => {
                            pool.query(deleteRotaQuery, [name, lastName, designation, day], (err) => {
                                if (err) {
                                    reject(err);
                                } else {
                                    resolve();
                                }
                            });
                        });

                        // Prepare value for insertion with the unique ID
                        const value = [uniqueId, name, lastName, designation, day, startTime, endTime];

                        // Insert new entry into `rota` with the unique ID
                        await new Promise((resolve, reject) => {
                            pool.query(insertRotaQuery, [[value]], (err) => {
                                if (err) {
                                    reject(err);
                                } else {
                                    resolve();
                                }
                            });
                        });

                    } catch (err) {
                        console.error('Error processing time frame:', err);
                        throw err;
                    }
                });

                return timeFrameTasks;
            }).flat();

            try {
                // Wait for all tasks to complete
                await Promise.all(updateTasks);
                res.status(200).send('Rota Confirmed and Updated Successfully.');
            } catch (err) {
                console.error('Error updating rota data:', err);
                res.status(500).send('Internal Server Error');
            }
        });
    });
});

// Function to Update Values in Rota table and ConfirmedRota table
app.post('/updateRotaData', isAuthenticated, async (req, res) => {
    const dbName = req.session.user.dbName; // Get the database name from the session

    if (!dbName) {
        return res.status(401).json({ message: 'User not authenticated' });
    }

    const pool = getPool(dbName); // Get the correct connection pool

    const updatedData = req.body;

    try {
        if (!updatedData || !Array.isArray(updatedData)) {
            return res.status(400).send({ success: false, message: 'Invalid input data.' });
        }

        // Start a transaction
        const connection = await pool.promise().getConnection();
        await connection.beginTransaction();

        // Extract unique days from the data
        const uniqueDays = [...new Set(updatedData.map(entry => entry.day))];

        // For each day, remove all existing records and insert the new data
        for (const day of uniqueDays) {
            // Delete all records for the day from both tables
            await connection.query(`DELETE FROM rota WHERE day = ?`, [day]);
            await connection.query(`DELETE FROM ConfirmedRota WHERE day = ?`, [day]);

            // Get all entries for this day from the client data
            const clientDataForDay = updatedData.filter(entry => entry.day === day);

            // Insert the updated records for the day into both tables
            for (const entry of clientDataForDay) {
                const { name, lastName, designation, startTime, endTime } = entry;

                // Validate required fields
                if (!day || !name || !lastName || !designation || !startTime || !endTime) {
                    continue;
                }

                // Insert into `rota`
                const id = await generateUniqueId(pool);
                await connection.query(
                    `INSERT INTO rota (id, day, name, lastName, designation, startTime, endTime) VALUES (?, ?, ?, ?, ?, ?, ?)`,
                    [id, day, name, lastName, designation, startTime, endTime]
                );

                // Insert into `ConfirmedRota`
                await connection.query(
                    `INSERT INTO ConfirmedRota (day, name, lastName, designation, startTime, endTime, who) VALUES (?, ?, ?, ?, ?, ?, ?)`,
                    [day, name, lastName, designation, startTime, endTime, req.session.user.email]
                );
            }
        }

        // Commit the transaction
        await connection.commit();
        connection.release();

        res.send({ success: true });
    } catch (err) {
        console.error('Error updating rota data:', err);

        // Rollback the transaction in case of errors
        if (connection) {
            await connection.rollback();
            connection.release();
        }

        res.status(500).send({ success: false, message: 'An error occurred while updating rota data.' });
    }
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

// API endpoint to get confirmed rota data by month/year
app.get('/api/confirmed-rota-month', isAuthenticated, (req, res) => {
    const dbName = req.session.user.dbName;

    if (!dbName) {
        return res.status(401).json({ message: 'User not authenticated' });
    }

    const pool = getPool(dbName);
    const { year, month } = req.query;

    if (!year || !month) {
        return res.status(400).json({ error: 'Year and month parameters are required' });
    }

    const monthNum = parseInt(month);
    if (isNaN(monthNum) || monthNum < 1 || monthNum > 12) {
        return res.status(400).json({ error: 'Invalid month parameter' });
    }

    const formattedMonth = String(monthNum).padStart(2, '0');
    const pattern = `__/${formattedMonth}/${year}%`;

    pool.query(`
        SELECT * FROM ConfirmedRota 
        WHERE day LIKE ?
        ORDER BY day
    `, [pattern], (err, results) => {
        if (err) {
            console.error('Error in /api/confirmed-rota-month:', err);
            return res.status(500).json({ 
                error: 'Internal Server Error',
                message: err.message 
            });
        }

        const groupedResults = {};
        for (const row of results) {
            const datePart = row.day.split(' ')[0];
            if (!groupedResults[datePart]) {
                groupedResults[datePart] = [];
            }
            groupedResults[datePart].push(row);
        }

        res.json({
            month: `${year}-${formattedMonth}`,
            data: groupedResults
        });
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

// Route to serve the ConfirmRota.html file
app.get('/', isAuthenticated, (req, res) => {
    if (req.session.user.role === 'admin') {
        res.sendFile(path.join(__dirname, 'ConfirmRota.html'));
    } else if (req.session.user.role === 'supervisor') {
        res.sendFile(path.join(__dirname, 'ConfirmRota.html'));
    } else {
        res.status(403).json({ error: 'Access denied' });
    }
});

module.exports = app; // Export the entire Express application