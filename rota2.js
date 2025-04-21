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
    const dbName = req.session.user.dbName;

    if (!dbName) {
        return res.status(401).json({ success: false, message: 'User not authenticated' });
    }

    const pool = getPool(dbName);
    const tableData = req.body;

    if (!Array.isArray(tableData) || tableData.length === 0) {
        return res.status(400).json({ success: false, message: 'Invalid data' });
    }

    const day = tableData[0].day;

    pool.getConnection((connErr, connection) => {
        if (connErr) {
            console.error('Error getting DB connection:', connErr);
            return res.status(500).send('Database connection error');
        }

        connection.beginTransaction(err => {
            if (err) {
                connection.release();
                console.error('Error starting transaction:', err);
                return res.status(500).send('Transaction error');
            }

            console.log('Deleting existing data for day:', day);

            connection.query('DELETE FROM rota WHERE day = ?', [day], (deleteErr, deleteResult) => {
                if (deleteErr) {
                    return connection.rollback(() => {
                        connection.release();
                        console.error('Error deleting old data:', deleteErr);
                        res.status(500).send('Error deleting data');
                    });
                }

                console.log(`Deleted ${deleteResult.affectedRows} rows.`);

                const insertQuery = 'INSERT INTO rota (id, name, lastName, wage, day, startTime, endTime, designation) VALUES ?';

                const values = tableData.map(row => [
                    generateUniqueId(),
                    row.name,
                    row.lastName,
                    row.wage,
                    row.day,
                    row.startTime,
                    row.endTime,
                    row.designation
                ]);

                console.log('Inserting new rota entries:', values);

                connection.query(insertQuery, [values], (insertErr, insertResult) => {
                    if (insertErr) {
                        return connection.rollback(() => {
                            connection.release();
                            console.error('Error inserting new data:', insertErr);
                            res.status(500).send('Error inserting data');
                        });
                    }

                    connection.commit(commitErr => {
                        if (commitErr) {
                            return connection.rollback(() => {
                                connection.release();
                                console.error('Error committing transaction:', commitErr);
                                res.status(500).send('Error committing changes');
                            });
                        }

                        connection.release();
                        console.log(`Inserted ${insertResult.affectedRows} new rows.`);
                        res.status(200).send(`Successfully saved ${insertResult.affectedRows} rota entries for ${day}.`);
                    });
                });
            });
        });
    });
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

// Function to Erase Data for the selected week
app.post('/clearWeek', isAuthenticated, (req, res) => {
    const dbName = req.session.user.dbName;
    if (!dbName) {
        return res.status(401).json({ success: false, message: 'User not authenticated' });
    }

    const pool = getPool(dbName);
    const { daysToDelete } = req.body;

    if (!Array.isArray(daysToDelete) || daysToDelete.length === 0) {
        return res.status(400).json({ success: false, message: 'No days provided for deletion' });
    }

    const deleteQuery = `DELETE FROM rota WHERE day IN (?)`;

    pool.query(deleteQuery, [daysToDelete], (err, result) => {
        if (err) {
            console.error('Error deleting week data:', err);
            return res.status(500).send('Error deleting rota data.');
        }
        res.status(200).send(`Deleted rota entries for: ${daysToDelete.join(', ')}`);
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

// Function to retrieve previous week's rota data for entire week
app.get('/get-previous-week-rota', (req, res) => {
    const dbName = req.session.user.dbName;
    const { prevWeek } = req.query;
    const pool = getPool(dbName);

    // Extract the Monday date from the formatted string "dd/mm/yyyy (Monday)"
    const datePart = prevWeek.split(' (')[0];
    const [day, month, year] = datePart.split('/');
    
    // Create Date object for Monday of previous week
    const mondayDate = new Date(`${year}-${month}-${day}`);
    
    // Calculate Sunday of the same week (6 days after Monday)
    const sundayDate = new Date(mondayDate);
    sundayDate.setDate(mondayDate.getDate() + 6);

    // Format dates to match database format (dd/mm/yyyy)
    const formatToDB = (date) => {
        const dd = String(date.getDate()).padStart(2, '0');
        const mm = String(date.getMonth() + 1).padStart(2, '0');
        const yyyy = date.getFullYear();
        return `${dd}/${mm}/${yyyy}`;
    };

    // Get all days between Monday and Sunday in db format
    const days = [];
    for (let d = new Date(mondayDate); d <= sundayDate; d.setDate(d.getDate() + 1)) {
        days.push(formatToDB(d));
    }

    pool.query(
        `SELECT name, lastName, wage, day, startTime, endTime, designation, color
         FROM rota 
         WHERE SUBSTRING_INDEX(day, ' (', 1) IN (?)`,
        [days],
        (err, results) => {
            if (err) {
                console.error('Error fetching previous week rota:', err);
                return res.status(500).json({ 
                    success: false, 
                    message: 'Failed to fetch previous week rota' 
                });
            }

            res.json({ 
                success: true,
                data: results 
            });
        }
    );
});

// Function to insert previous week's rota data into new week
app.post('/insert-copied-rota', (req, res) => {
    const dbName = req.session.user.dbName;
    const { currentWeek, rotaData } = req.body;
    const pool = getPool(dbName);

    // Extract the Monday date from currentWeek (format: "dd/mm/yyyy (Monday)")
    const mondayDate = currentWeek.split(' (')[0];
    const [day, month, year] = mondayDate.split('/');

    // Calculate date range for the full current week (Monday to Sunday)
    const startDate = new Date(`${year}-${month}-${day}`);
    const endDate = new Date(startDate);
    endDate.setDate(startDate.getDate() + 6);

    // Format dates for SQL query (dd/mm/yyyy)
    const formatDateForQuery = (date) => {
        const dd = String(date.getDate()).padStart(2, '0');
        const mm = String(date.getMonth() + 1).padStart(2, '0');
        const yyyy = date.getFullYear();
        return `${dd}/${mm}/${yyyy}`;
    };

    // Format date with day name (dd/mm/yyyy (Dayname))
    const formatDate = (date) => {
        const dd = String(date.getDate()).padStart(2, '0');
        const mm = String(date.getMonth() + 1).padStart(2, '0');
        const yyyy = date.getFullYear();
        return `${dd}/${mm}/${yyyy}`;
    };

    // Get a connection from the pool
    pool.getConnection((connErr, connection) => {
        if (connErr) {
            console.error('Error getting database connection:', connErr);
            return res.status(500).json({ 
                success: false, 
                message: 'Database connection failed' 
            });
        }

        // Start transaction
        connection.beginTransaction((beginErr) => {
            if (beginErr) {
                connection.release();
                console.error('Error starting transaction:', beginErr);
                return res.status(500).json({ 
                    success: false, 
                    message: 'Transaction start failed' 
                });
            }

            // First delete existing entries for the entire current week
            connection.query(
                `DELETE FROM rota 
                 WHERE SUBSTRING_INDEX(day, ' (', 1) 
                 BETWEEN ? AND ?`,
                [formatDateForQuery(startDate), formatDateForQuery(endDate)],
                (deleteErr, deleteResult) => {
                    if (deleteErr) {
                        return rollbackAndRespond(connection, 'Error deleting existing entries:', deleteErr);
                    }

                    console.log(`Deleted ${deleteResult.affectedRows} existing entries`);

                    if (rotaData.length === 0) {
                        return commitAndRespond(connection, res);
                    }

                    // Process all entries
                    let completed = 0;
                    let hasError = false;

                    const processNextEntry = (index) => {
                        if (index >= rotaData.length || hasError) {
                            if (!hasError) {
                                return commitAndRespond(connection, res);
                            }
                            return;
                        }

                        const entry = rotaData[index];
                        
                        // Extract day name from original entry (e.g., "Monday")
                        const dayName = entry.day.match(/\(([^)]+)\)/)[1];
                        
                        // Calculate the corresponding date in the current week
                        const currentWeekDay = new Date(startDate);
                        const dayOffset = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']
                            .indexOf(dayName);
                        
                        currentWeekDay.setDate(startDate.getDate() + dayOffset);
                        
                        // Format the new date with day name (dd/mm/yyyy (Dayname))
                        const formattedDate = formatDate(currentWeekDay);
                        const newDay = `${formattedDate} (${dayName})`;

                        const newId = generateUniqueId();

                        // Check if ID exists
                        connection.query(
                            'SELECT id FROM rota WHERE id = ?',
                            [newId],
                            (checkErr, results) => {
                                if (checkErr) {
                                    hasError = true;
                                    return rollbackAndRespond(connection, 'Error checking ID:', checkErr);
                                }

                                if (results.length > 0) {
                                    // If ID exists, try again with a new ID
                                    return processNextEntry(index);
                                }

                                // Insert with the unique ID and properly mapped date
                                connection.query(
                                    `INSERT INTO rota
                                    (id, name, lastName, wage, designation, day, startTime, endTime, color) 
                                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
                                    [
                                        newId,
                                        entry.name,
                                        entry.lastName,
                                        entry.wage,
                                        entry.designation,
                                        newDay,
                                        entry.startTime,
                                        entry.endTime,
                                        entry.color
                                    ],
                                    (insertErr) => {
                                        if (insertErr) {
                                            hasError = true;
                                            return rollbackAndRespond(connection, 'Error inserting entry:', insertErr);
                                        }

                                        completed++;
                                        processNextEntry(index + 1);
                                    }
                                );
                            }
                        );
                    };

                    // Start processing entries
                    processNextEntry(0);
                }
            );
        });
    });
});

// Helper functions for transaction management
function rollbackAndRespond(connection, errorMessage, error) {
    console.error(errorMessage, error);
    connection.rollback(() => {
        connection.release();
        return res.status(500).json({ 
            success: false, 
            message: 'Operation failed' 
        });
    });
}

// Helper functions for transaction management
function commitAndRespond(connection, res) {
    connection.commit((commitErr) => {
        if (commitErr) {
            return rollbackAndRespond(connection, 'Error committing transaction:', commitErr);
        }
        connection.release();
        res.json({ success: true });
    });
}

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