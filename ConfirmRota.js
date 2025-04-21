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
    const dbName = req.session.user.dbName;

    if (!dbName) {
        return res.status(401).json({ message: 'User not authenticated' });
    }

    const pool = getPool(dbName);
    const day = req.query.day;

    if (!day) {
        return res.status(400).json({ error: 'Day is required' });
    }

    const rotaQuery = `
        SELECT name, lastName, wage, day, designation, startTime, endTime
        FROM rota
        WHERE day = ?
    `;

    const confirmedRotaQuery = `
        SELECT name, lastName, designation, day, startTime, endTime
        FROM ConfirmedRota
    `;

    pool.query(rotaQuery, [day], (err, rotaResults) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }

        pool.query(confirmedRotaQuery, (err, confirmedRotaResults) => {
            if (err) {
                return res.status(500).json({ error: err.message });
            }

            const confirmedRotaSet = new Set(
                confirmedRotaResults.map(entry => `${entry.name} ${entry.lastName} ${entry.designation} ${entry.day} ${entry.startTime} ${entry.endTime}`)
            );

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

// Function to Retrieve Tax - Pension - Holiday % 
app.get('/api/tax-info', (req, res) => {
    const dbName = req.session.user.dbName; // Get the database name from the session

    if (!dbName) {
        return res.status(401).json({ message: 'User not authenticated' });
    }

    const pool = getPool(dbName); // Get the correct connection pool

    pool.execute('SELECT holiday, pension, tax FROM rota_tax WHERE id = ?', [1], (error, results) => {
        if (error) {
            console.error('Error fetching tax info:', error);
            return res.status(500).json({ error: 'Internal Server Error' });
        }

        if (results.length > 0) {
            res.json(results[0]);
        } else {
            res.status(404).json({ error: 'Tax info not found.' });
        }
    });
});

// Function to Retrieve Wage 
app.get('/api/employee-wages', (req, res) => {
    const dbName = req.session.user.dbName;

    if (!dbName) {
        return res.status(401).json({ message: 'User not authenticated' });
    }

    const pool = getPool(dbName);

    pool.execute('SELECT name, lastName, wage FROM Employees', (error, results) => {
        if (error) {
            console.error('Error fetching employee wages:', error);
            return res.status(500).json({ error: 'Internal Server Error' });
        }

        res.json(results);
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
    const dbName = req.session.user.dbName;
    if (!dbName) return res.status(401).json({ message: 'User not authenticated' });

    const pool = getPool(dbName);
    const rotaData = req.body;
    const userEmail = req.session.user.email;

    if (!rotaData || !Array.isArray(rotaData) || rotaData.length === 0) {
        return res.status(400).send('Invalid rota data.');
    }

    const day = rotaData[0].day;
    console.log(`[CONFIRM-ROTA] Starting process for day: ${day}`);

    try {
        // Fetch employee wages
        console.log('[EMPLOYEE-WAGES] Fetching wage data...');
        const [employees] = await pool.promise().query('SELECT name, lastName, wage FROM Employees');
        console.log(`[EMPLOYEE-WAGES] Fetched ${employees.length} employees`);
        
        const wageMap = employees.reduce((map, emp) => {
            const key = `${emp.name.trim()} ${emp.lastName.trim()}`;
            console.log(`[WAGE-MAP] ${key}: £${emp.wage}`);
            map[key] = parseFloat(emp.wage);
            return map;
        }, {});

        // Prepare confirmed rota values
        console.log('[PREPARE-DATA] Formatting rota data...');
        const confirmedRotaValues = rotaData.flatMap(entry => {
            const key = `${entry.name.trim()} ${entry.lastName.trim()}`;
            const wage = wageMap[key] || 0;
            console.log(`[EMPLOYEE-ENTRY] ${key} with ${entry.times.length} time slots`);
            
            return entry.times.map(time => [
                entry.name, 
                entry.lastName, 
                wage, 
                day, 
                time.startTime, 
                time.endTime, 
                userEmail
            ]);
        });
        console.log('[PREPARED-DATA] Formatted entries:', confirmedRotaValues.length);

        // Start transaction
        console.log('[TRANSACTION] Starting database transaction...');
        const connection = await pool.promise().getConnection();
        await connection.beginTransaction();

        try {
            // 1. Delete ALL old entries for this day from both tables
            console.log('[DELETE] Starting deletion of old records...');
            
            // Log current state before deletion
            const [currentConfirmed] = await connection.query(
                'SELECT COUNT(*) as count FROM ConfirmedRota WHERE day = ?', 
                [day]
            );
            const [currentRota] = await connection.query(
                'SELECT COUNT(*) as count FROM rota WHERE day = ?', 
                [day]
            );
            console.log(`[CURRENT-STATE] ConfirmedRota: ${currentConfirmed[0].count}, rota: ${currentRota[0].count}`);

            // Perform deletions
            console.log(`[DELETE] Executing deletions for day: ${day}`);
// 1. First get the EXACT format from the database for this day
const [existingDays] = await connection.query(
    "SELECT day FROM ConfirmedRota WHERE day LIKE CONCAT(?, '%') LIMIT 1",
    [day.split('/')[0]] // Gets just the day number (e.g. "01" from "01/11/2024 (Friday)")
  );
  
  let exactDayFormat;
  if (existingDays.length > 0) {
    exactDayFormat = existingDays[0].day; // Use the exact format from DB
    console.log(`[DAY-FORMAT] Using exact DB format: ${exactDayFormat}`);
  } else {
    exactDayFormat = day; // Fallback to original
    console.log(`[DAY-FORMAT] No match found, using original: ${exactDayFormat}`);
  }
  
  // 2. Now delete using the exact format
  const [confirmedDeleteResult] = await connection.query(
    'DELETE FROM ConfirmedRota WHERE day = ?',
    [exactDayFormat]
  );
  console.log(`[DELETE-CONFIRMED] Deleted ${confirmedDeleteResult.affectedRows} records`);
  
  // 3. Verify deletion
  const [remaining] = await connection.query(
    'SELECT COUNT(*) as count FROM ConfirmedRota WHERE day = ?',
    [exactDayFormat]
  );
  console.log(`[POST-DELETE] Remaining records: ${remaining[0].count}`);
            const [rotaDeleteResult] = await connection.query(
                'DELETE FROM rota WHERE day = ?', 
                [day]
            );
            console.log(`[DELETE-RESULTS] ConfirmedRota: ${confirmedDeleteResult.affectedRows}, rota: ${rotaDeleteResult.affectedRows} records deleted`);

            // 2. Insert new confirmed rota entries
            if (confirmedRotaValues.length > 0) {
                console.log('[INSERT] Adding new confirmed rota entries:', confirmedRotaValues.length);
                const [insertResult] = await connection.query(
                    `INSERT INTO ConfirmedRota 
                    (name, lastName, wage, day, startTime, endTime, who) 
                    VALUES ?`,
                    [confirmedRotaValues]
                );
                console.log(`[INSERT-RESULT] ${insertResult.affectedRows} records inserted`);
            }

            // 3. Insert new rota entries with unique IDs
            console.log('[ROTA-INSERTS] Starting individual rota inserts...');
            let rotaInsertCount = 0;
            
            for (const entry of rotaData) {
                if (!entry.times || !Array.isArray(entry.times)) {
                    console.log(`[SKIP-ENTRY] No times array for ${entry.name} ${entry.lastName}`);
                    continue;
                }
                
                for (const time of entry.times) {
                    if (!time.startTime || !time.endTime) {
                        console.log(`[SKIP-TIME] Missing times for ${entry.name} ${entry.lastName}`);
                        continue;
                    }
                    
                    const uniqueId = await generateUniqueId(pool);
                    console.log(`[INSERT-ROTA] ${uniqueId}: ${entry.name} ${entry.lastName} | ${day} | ${time.startTime}-${time.endTime}`);
                    
                    await connection.query(
                        'INSERT INTO rota (id, name, lastName, day, startTime, endTime) VALUES (?, ?, ?, ?, ?, ?)',
                        [uniqueId, entry.name, entry.lastName, day, time.startTime, time.endTime]
                    );
                    rotaInsertCount++;
                }
            }
            console.log(`[ROTA-INSERTS] Completed ${rotaInsertCount} inserts`);

            // Calculate cost difference
            console.log('[COST-CALCULATION] Starting...');
            const [[taxInfo]] = await connection.query('SELECT holiday, pension, tax FROM rota_tax WHERE id = "1"');
            console.log('[TAX-INFO]', taxInfo);
            
            const taxMultiplier = 1 + (taxInfo.holiday + taxInfo.pension + taxInfo.tax) / 100;
            console.log(`[TAX-MULTIPLIER] ${taxMultiplier}`);

            const calculateCost = (entries) => {
                return entries.reduce((total, entry) => {
                    const start = entry.startTime || entry[4];
                    const end = entry.endTime || entry[5];
                    const wage = entry.wage || entry[2];
                    
                    if (!start || !end || isNaN(wage)) {
                        console.log(`[INVALID-ENTRY] Skipping cost calculation for`, entry);
                        return total;
                    }
                    
                    const hours = calculateHours(start, end);
                    const cost = hours * wage * taxMultiplier;
                    console.log(`[COST-BREAKDOWN] ${entry.name} ${entry.lastName}: ${hours}h × £${wage} × ${taxMultiplier} = £${cost.toFixed(2)}`);
                    return total + cost;
                }, 0);
            };

            const oldCost = calculateCost(await connection.query('SELECT * FROM ConfirmedRota WHERE day = ?', [day]));
            const newCost = calculateCost(confirmedRotaValues);
            console.log(`[COST-SUMMARY] Old: £${oldCost.toFixed(2)}, New: £${newCost.toFixed(2)}, Difference: £${(newCost - oldCost).toFixed(2)}`);

            // Update Weekly_Cost_After
            console.log('[WEEKLY-COST] Updating...');
            const [[dataRow]] = await connection.query('SELECT Weekly_Cost_After FROM Data WHERE WeekStart = ?', [day]);
            if (dataRow) {
                const currentValue = parseFloat(dataRow.Weekly_Cost_After) || 0;
                const newValue = currentValue + (newCost - oldCost);
                console.log(`[WEEKLY-UPDATE] From £${currentValue.toFixed(2)} to £${newValue.toFixed(2)}`);
                
                await connection.query(
                    'UPDATE Data SET Weekly_Cost_After = ? WHERE WeekStart = ?',
                    [newValue.toFixed(2), day]
                );
            }

            await connection.commit();
            console.log('[TRANSACTION] Successfully committed');
            res.status(200).send('Rota Confirmed and Updated Successfully.');
        } catch (err) {
            await connection.rollback();
            console.error('[TRANSACTION-ERROR] Rollback initiated:', err);
            res.status(500).send('Internal Server Error');
        } finally {
            connection.release();
            console.log('[CONNECTION] Released');
        }
    } catch (err) {
        console.error('[TOP-LEVEL-ERROR]', err);
        res.status(500).send('Internal Server Error');
    }
});

// Helper function to calculate hours between two times
function calculateHours(startTime, endTime) {
    if (!startTime || !endTime) return 0;
    
    const [sh, sm] = startTime.split(':').map(Number);
    const [eh, em] = endTime.split(':').map(Number);
    const start = new Date(0, 0, 0, sh, sm);
    const end = new Date(0, 0, 0, eh, em);
    let diff = (end - start) / (1000 * 60 * 60); // Convert to hours
    if (diff < 0) diff += 24;
    
    return diff;
}
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