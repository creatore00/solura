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

// Enhanced session debugging middleware for this specific router
app.use((req, res, next) => {
    console.log('=== CONFIRMROTA ROUTER SESSION DEBUG ===');
    console.log('Path:', req.path);
    console.log('Session ID:', req.sessionID);
    console.log('Session User:', req.session?.user);
    console.log('User Role:', req.session?.user?.role);
    console.log('Database:', req.session?.user?.dbName);
    console.log('=== END DEBUG ===');
    next();
});

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
        console.error('No dbName in session for /api/rota');
        return res.status(401).json({ message: 'User not authenticated' });
    }

    const pool = getPool(dbName); // Get the correct connection pool

    const day = req.query.day;
    if (!day) {
        return res.status(400).json({ error: 'Day is required' });
    }

    console.log(`Fetching rota data for day: ${day}, db: ${dbName}`);

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
            console.error('Error fetching rota data:', err);
            return res.status(500).json({ error: err.message });
        }

        pool.query(confirmedRotaQuery, (err, confirmedRotaResults) => {
            if (err) {
                console.error('Error fetching confirmed rota data:', err);
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

            console.log(`Found ${filteredRotaResults.length} unconfirmed rota entries for ${day}`);
            res.json(filteredRotaResults);
        });
    });
});

// Check if Rota has been confirmed by Supervisor
// Backend API endpoint with enhanced logging
app.get('/api/check-confirmed-rota2', isAuthenticated, (req, res) => {
    const dbName = req.session.user.dbName;
    console.log(`[check-confirmed-rota2] Request received for db: ${dbName}, day: ${req.query.day}`);

    if (!dbName) {
        console.error('[check-confirmed-rota2] No dbName in session - unauthorized');
        return res.status(401).json({ message: 'User not authenticated' });
    }

    const pool = getPool(dbName);
    const day = req.query.day;
    if (!day) {
        console.error('[check-confirmed-rota2] Day parameter missing');
        return res.status(400).json({ error: 'Day is required' });
    }

    const sql = `
        SELECT 
            cr.who AS confirmedBy,
            e.name,
            e.lastName
        FROM 
            ConfirmedRota cr
        JOIN 
            Employees e ON cr.who = e.email
        WHERE 
            cr.day = ?
        
        UNION
        
        SELECT 
            cr2.who AS confirmedBy,
            e.name,
            e.lastName
        FROM 
            ConfirmedRota2 cr2
        JOIN 
            Employees e ON cr2.who = e.email
        WHERE 
            cr2.day = ?
    `;

    console.log(`[check-confirmed-rota2] Executing query for day: ${day}`);
    pool.query(sql, [day, day], (err, results) => {
        if (err) {
            console.error('[check-confirmed-rota2] Database error:', err);
            return res.status(500).json({ error: 'Internal Server Error' });
        }

        console.log(`[check-confirmed-rota2] Raw results:`, results);
        
        const confirmers = results.map(row => `${row.name} ${row.lastName}`);
        const uniqueConfirmers = [...new Set(confirmers)];
        
        console.log(`[check-confirmed-rota2] Found ${uniqueConfirmers.length} confirmers:`, uniqueConfirmers);
        
        res.json({ 
            exists: results.length > 0,
            confirmers: uniqueConfirmers 
        });
    });
});

// API endpoint to get confirmed rota data by date
app.get('/api/confirmed-rota', isAuthenticated, (req, res) => {
    const dbName = req.session.user.dbName; // Get the database name from the session

    if (!dbName) {
        console.error('No dbName in session for /api/confirmed-rota');
        return res.status(401).json({ message: 'User not authenticated' });
    }

    const pool = getPool(dbName); // Get the correct connection pool

    const day = req.query.day; // Get the day from query parameter

    if (!day) {
        return res.status(400).json({ error: 'Day is required' });
    }

    console.log(`Fetching confirmed rota for day: ${day}, db: ${dbName}`);

    // Query the ConfirmedRota table using the provided day
    const sql = `SELECT * FROM ConfirmedRota WHERE day = ?`;
    pool.query(sql, [day], (err, results) => {
        if (err) {
            console.error('Error fetching confirmed rota:', err);
            return res.status(500).json({ error: 'Internal Server Error' });
        }

        console.log(`Found ${results.length} confirmed rota entries for ${day}`);
        // Return the results as JSON
        res.json(results);
    });
});

// Function to remove Employee from Rota
app.delete('/delete-employee', isAuthenticated, (req, res) => {
    const dbName = req.session.user.dbName; // Get the database name from the session

    if (!dbName) {
        console.error('No dbName in session for /delete-employee');
        return res.status(401).json({ message: 'User not authenticated' });
    }

    const pool = getPool(dbName); // Get the correct connection pool

    const { name, lastName, designation, day } = req.body;

    // Validate the incoming data
    if (!name || !lastName || !designation || !day) {
        return res.status(400).send('Missing required parameters.');
    }

    console.log(`Deleting employee: ${name} ${lastName} (${designation}) from ${day}, db: ${dbName}`);

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
    const dbName = req.session.user.dbName;
    if (!dbName) {
        console.error('No dbName in session for /confirm-rota');
        return res.status(401).json({ message: 'User not authenticated' });
    }

    const pool = getPool(dbName);
    const rotaData = req.body;
    const userEmail = req.session.user.email;

    console.log(`Confirming rota for day: ${rotaData[0]?.day}, db: ${dbName}, user: ${userEmail}`);

    if (!rotaData || !Array.isArray(rotaData) || rotaData.length === 0) {
        return res.status(400).send('Invalid rota data.');
    }

    const day = rotaData[0].day;

    // Queries
    const deleteConfirmedRotaQuery = 'DELETE FROM ConfirmedRota WHERE day = ?';
    const insertConfirmedRotaQuery = `
        INSERT INTO ConfirmedRota (name, lastName, wage, day, startTime, endTime, designation, who) 
        VALUES ?`;
    const deleteRotaQuery = `DELETE FROM rota WHERE day = ?`;
    const insertRotaQuery = `
        INSERT INTO rota (id, name, lastName, designation, day, startTime, endTime)
        VALUES ?`;

    // Prepare ConfirmedRota values
    const confirmedRotaValues = rotaData.flatMap(entry => {
        const { name, lastName, wage, day, designation, times } = entry;
        return times.map(time => [name, lastName, wage, day, time.startTime, time.endTime, designation, userEmail]);
    });

    console.log(`Preparing to insert ${confirmedRotaValues.length} confirmed rota entries`);

    // Delete old ConfirmedRota entries
    pool.query(deleteConfirmedRotaQuery, [day], async (err) => {
        if (err) {
            console.error('Error deleting old confirmed rota:', err);
            return res.status(500).send('Internal Server Error');
        }

        // Insert ConfirmedRota values
        pool.query(insertConfirmedRotaQuery, [confirmedRotaValues], async (err) => {
            if (err) {
                console.error('Error inserting confirmed rota:', err);
                return res.status(500).send('Internal Server Error');
            }

            try {
                // Prepare all Rota values with unique IDs
                const rotaValues = await Promise.all(
                    rotaData.flatMap(async entry => {
                        const { name, lastName, day, designation, times } = entry;
                        return await Promise.all(times.map(async time => {
                            const uniqueId = await generateUniqueId(pool);
                            return [uniqueId, name, lastName, designation, day, time.startTime, time.endTime];
                        }));
                    })
                );

                // Flatten the array (since we have nested arrays)
                const flattenedRotaValues = rotaValues.flat();

                console.log(`Preparing to insert ${flattenedRotaValues.length} rota entries`);

                // Delete old rota entries for the day
                pool.query(deleteRotaQuery, [day], (err) => {
                    if (err) {
                        console.error('Error deleting old rota:', err);
                        return res.status(500).send('Internal Server Error');
                    }

                    // Insert all rota entries at once
                    pool.query(insertRotaQuery, [flattenedRotaValues], (err) => {
                        if (err) {
                            console.error('Error inserting new rota:', err);
                            return res.status(500).send('Internal Server Error');
                        }

                        console.log(`Successfully confirmed rota for ${day} with ${flattenedRotaValues.length} entries`);
                        res.status(200).send('Rota Confirmed and Updated Successfully.');
                    });
                });

            } catch (err) {
                console.error('Error generating unique IDs or preparing rota:', err);
                res.status(500).send('Internal Server Error');
            }
        });
    });
});

// Function to Update Values in Rota table and ConfirmedRota table
app.post('/updateRotaData', isAuthenticated, async (req, res) => {
    const dbName = req.session.user.dbName; // Get the database name from the session

    if (!dbName) {
        console.error('No dbName in session for /updateRotaData');
        return res.status(401).json({ message: 'User not authenticated' });
    }

    const pool = getPool(dbName); // Get the correct connection pool

    const updatedData = req.body;

    console.log(`Updating rota data for ${updatedData.length} entries, db: ${dbName}`);

    try {
        if (!updatedData || !Array.isArray(updatedData)) {
            return res.status(400).send({ success: false, message: 'Invalid input data.' });
        }

        // Start a transaction
        const connection = await pool.promise().getConnection();
        await connection.beginTransaction();

        // Extract unique days from the data
        const uniqueDays = [...new Set(updatedData.map(entry => entry.day))];

        console.log(`Processing days: ${uniqueDays.join(', ')}`);

        // For each day, remove all existing records and insert the new data
        for (const day of uniqueDays) {
            // Delete all records for the day from both tables
            await connection.query(`DELETE FROM rota WHERE day = ?`, [day]);
            await connection.query(`DELETE FROM ConfirmedRota WHERE day = ?`, [day]);

            // Get all entries for this day from the client data
            const clientDataForDay = updatedData.filter(entry => entry.day === day);

            console.log(`Processing ${clientDataForDay.length} entries for ${day}`);

            // Insert the updated records for the day into both tables
            for (const entry of clientDataForDay) {
                const { name, lastName, designation, startTime, endTime } = entry;

                // Validate required fields
                if (!day || !name || !lastName || !designation || !startTime || !endTime) {
                    console.warn(`Skipping invalid entry for ${day}:`, entry);
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

        console.log('Successfully updated rota data');
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
        console.error('No dbName in session for /api/employees');
        return res.status(401).json({ message: 'User not authenticated' });
    }

    const pool = getPool(dbName); // Get the correct connection pool

    console.log(`Fetching employees for db: ${dbName}`);

    const sql = 'SELECT name, lastName, designation FROM Employees';
    pool.query(sql, (err, results) => {
        if (err) {
            console.error('Error fetching employees:', err);
            return res.status(500).json({ error: 'Internal Server Error' });
        }
        console.log(`Found ${results.length} employees`);
        res.json(results);
    });
});

// API endpoint to get confirmed rota data by month/year
app.get('/api/confirmed-rota-month', isAuthenticated, (req, res) => {
    const dbName = req.session.user.dbName;

    if (!dbName) {
        console.error('No dbName in session for /api/confirmed-rota-month');
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

    console.log(`Fetching confirmed rota for ${year}-${month}, db: ${dbName}`);

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

        console.log(`Found confirmed rota data for ${Object.keys(groupedResults).length} days in ${year}-${month}`);
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
    console.log(`Serving ConfirmRota.html for user: ${req.session.user.email}, role: ${req.session.user.role}`);
    
    if (req.session.user.role === 'admin' || req.session.user.role === 'AM') {
        res.sendFile(path.join(__dirname, 'ConfirmRota.html'));
    } else {
        console.warn(`Access denied for user ${req.session.user.email} with role ${req.session.user.role}`);
        res.status(403).json({ error: 'Access denied' });
    }
});

module.exports = app; // Export the entire Express application