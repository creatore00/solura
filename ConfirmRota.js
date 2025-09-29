const express = require('express');
const mysql = require('mysql2');
const bodyParser = require('body-parser');
const nodemailer = require('nodemailer');
const http = require('http');
const fs = require('fs');
const path = require('path');
const { getPool, mainPool } = require('./db.js');
const { sessionMiddleware, isAuthenticated, isAdmin, isSupervisor } = require('./sessionConfig');

const app = express();

// Middleware
app.use(sessionMiddleware);
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Enhanced mobile detection function
function isMobile(userAgent) {
    return /android|iphone|ipad|ipod|mobile/i.test(userAgent.toLowerCase());
}

// Enhanced mobile detection with tablet consideration
function getDeviceType(userAgent) {
    const ua = userAgent.toLowerCase();
    
    if (/mobile|android|iphone|ipod/.test(ua)) {
        return 'mobile';
    } else if (/ipad|tablet/.test(ua)) {
        return 'tablet';
    } else {
        return 'desktop';
    }
}

// CRITICAL FIX: Enhanced session restoration middleware for iOS
app.use((req, res, next) => {
    const userAgent = req.headers['user-agent'] || '';
    const isIOS = /iPhone|iPad|iPod/.test(userAgent);
    
    console.log('=== CONFIRMROTA SESSION DEBUG ===');
    console.log('Path:', req.path);
    console.log('Session ID:', req.sessionID);
    console.log('Session User:', req.session?.user);
    console.log('User Role:', req.session?.user?.role);
    console.log('Database:', req.session?.user?.dbName);
    console.log('Device Type:', getDeviceType(userAgent));
    console.log('Is iOS:', isIOS);
    console.log('=== END DEBUG ===');
    
    if (isIOS && (!req.session.user || !req.session.user.dbName)) {
        console.log('📱 iOS Session Restoration Needed - ConfirmRota');
        
        // Try multiple methods to restore session
        const urlParams = new URLSearchParams(req.url.includes('?') ? req.url.split('?')[1] : '');
        const sessionId = urlParams.get('sessionId');
        const email = urlParams.get('email');
        const dbName = urlParams.get('dbName');
        const name = urlParams.get('name');
        const lastName = urlParams.get('lastName');
        
        console.log('🔄 Attempting session restoration with:', { sessionId, email, dbName });
        
        if (email && dbName) {
            console.log('✅ Restoring session from URL parameters');
            req.session.user = {
                email: email,
                dbName: dbName,
                name: name || '',
                lastName: lastName || '',
                role: 'admin' // Default to admin for confirmrota access
            };
            
            // If sessionId is provided, sync the session ID
            if (sessionId && req.sessionID !== sessionId) {
                console.log('🔄 Syncing session ID to:', sessionId);
                req.sessionID = sessionId;
            }
            
            // Save the restored session
            req.session.save((err) => {
                if (err) {
                    console.error('❌ Failed to save restored session:', err);
                } else {
                    console.log('✅ Session restored successfully for:', email);
                }
                next();
            });
        } else {
            console.log('❌ No restoration parameters found');
            next();
        }
    } else {
        next();
    }
});

// Route to serve the appropriate confirmrota app based on device
app.get('/', isAuthenticated, (req, res) => {
    const userAgent = req.headers['user-agent'] || '';
    const deviceType = getDeviceType(userAgent);
    
    console.log('ConfirmRota route - Device Type:', deviceType, 'User-Agent:', userAgent);

    if (req.session.user.role === 'admin' || req.session.user.role === 'AM') {
        // Add mobile-specific headers
        res.header('Cache-Control', 'no-cache, no-store, must-revalidate');
        res.header('Pragma', 'no-cache');
        res.header('Expires', '0');
        
        // For iOS, ensure session ID is preserved in response
        if (deviceType === 'mobile' || deviceType === 'tablet') {
            const sessionId = req.query.sessionId || req.sessionID;
            console.log('📱 Serving mobile confirmrota app with session ID:', sessionId);
            res.sendFile(path.join(__dirname, 'ConfirmRotaApp.html'));
        } else {
            console.log('💻 Serving desktop confirmrota app');
            res.sendFile(path.join(__dirname, 'ConfirmRota.html'));
        }
    } else {
        console.warn(`Access denied for user ${req.session.user.email} with role ${req.session.user.role}`);
        res.status(403).json({ error: 'Access denied' });
    }
});

// Route to serve mobile confirmrota app directly
app.get('/mobile', isAuthenticated, (req, res) => {
    if (req.session.user.role === 'admin' || req.session.user.role === 'AM') {
        res.sendFile(path.join(__dirname, 'ConfirmRotaApp.html'));
    } else {
        res.status(403).json({ error: 'Access denied' });
    }
});

// Route to serve desktop confirmrota app directly
app.get('/desktop', isAuthenticated, (req, res) => {
    if (req.session.user.role === 'admin' || req.session.user.role === 'AM') {
        res.sendFile(path.join(__dirname, 'ConfirmRota.html'));
    } else {
        res.status(403).json({ error: 'Access denied' });
    }
});

// Enhanced health endpoint for mobile
app.get('/health', (req, res) => {
    const userAgent = req.headers['user-agent'] || '';
    const isIOS = /iPhone|iPad|iPod/.test(userAgent);
    
    console.log('🏥 ConfirmRota Health check - iOS:', isIOS, 'Session User:', req.session?.user);
    
    // For iOS, be more lenient with health checks
    if (isIOS && (!req.session.user || !req.session.user.dbName)) {
        console.log('📱 iOS health check - session incomplete but allowing');
        return res.json({
            status: 'degraded',
            deviceType: getDeviceType(userAgent),
            isIOS: isIOS,
            session: !!req.session,
            user: req.session.user ? {
                email: req.session.user.email,
                role: req.session.user.role,
                name: req.session.user.name
            } : null,
            message: 'Session may need restoration'
        });
    }
    
    // Normal health check for authenticated sessions
    if (req.session?.user) {
        res.json({
            status: 'healthy',
            deviceType: getDeviceType(userAgent),
            isIOS: isIOS,
            session: true,
            user: {
                email: req.session.user.email,
                role: req.session.user.role,
                name: req.session.user.name
            }
        });
    } else {
        res.status(401).json({
            status: 'unauthenticated',
            deviceType: getDeviceType(userAgent),
            isIOS: isIOS,
            session: false,
            message: 'No active session'
        });
    }
});

// Function to generate a unique ID
const generateUniqueId = async (pool) => {
    let id;
    let isUnique = false;

    while (!isUnique) {
        id = Math.floor(Math.random() * 1e16).toString().padStart(16, '0');
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
        console.error('No dbName in session for /api/rota');
        return res.status(401).json({ message: 'User not authenticated' });
    }

    const pool = getPool(dbName);
    const day = req.query.day;
    if (!day) {
        return res.status(400).json({ error: 'Day is required' });
    }

    console.log(`Fetching rota data for day: ${day}, db: ${dbName}`);

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
            console.error('Error fetching rota data:', err);
            return res.status(500).json({ error: err.message });
        }

        pool.query(confirmedRotaQuery, (err, confirmedRotaResults) => {
            if (err) {
                console.error('Error fetching confirmed rota data:', err);
                return res.status(500).json({ error: err.message });
            }

            const confirmedRotaSet = new Set(
                confirmedRotaResults.map(entry => `${entry.name} ${entry.lastName} ${entry.designation} ${entry.day} ${entry.startTime} ${entry.endTime}`)
            );

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
    const dbName = req.session.user.dbName;

    if (!dbName) {
        console.error('No dbName in session for /api/confirmed-rota');
        return res.status(401).json({ message: 'User not authenticated' });
    }

    const pool = getPool(dbName);
    const day = req.query.day;

    if (!day) {
        return res.status(400).json({ error: 'Day is required' });
    }

    console.log(`Fetching confirmed rota for day: ${day}, db: ${dbName}`);

    const sql = `SELECT * FROM ConfirmedRota WHERE day = ?`;
    pool.query(sql, [day], (err, results) => {
        if (err) {
            console.error('Error fetching confirmed rota:', err);
            return res.status(500).json({ error: 'Internal Server Error' });
        }

        console.log(`Found ${results.length} confirmed rota entries for ${day}`);
        res.json(results);
    });
});

// Function to remove Employee from Rota
app.delete('/delete-employee', isAuthenticated, (req, res) => {
    const dbName = req.session.user.dbName;

    if (!dbName) {
        console.error('No dbName in session for /delete-employee');
        return res.status(401).json({ message: 'User not authenticated' });
    }

    const pool = getPool(dbName);
    const { name, lastName, designation, day } = req.body;

    if (!name || !lastName || !designation || !day) {
        return res.status(400).send('Missing required parameters.');
    }

    console.log(`Deleting employee: ${name} ${lastName} (${designation}) from ${day}, db: ${dbName}`);

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

    pool.query(deleteRotaQuery, [name, lastName, designation, day], (err, results) => {
        if (err) {
            console.error('Error deleting from rota:', err);
            return res.status(500).send('Internal Server Error');
        }

        if (results.affectedRows === 0) {
            console.log(`No matching entry found in rota for ${name} ${lastName} (${designation}) on ${day}`);
        }

        pool.query(deleteConfirmedRotaQuery, [name, lastName, designation, day], (err, results) => {
            if (err) {
                console.error('Error deleting from ConfirmedRota:', err);
                return res.status(500).send('Internal Server Error');
            }

            if (results.affectedRows === 0) {
                console.log(`No matching entry found in ConfirmedRota for ${name} ${lastName} (${designation}) on ${day}`);
            }

            pool.query(deleteConfirmedRota2Query, [name, lastName, designation, day], (err, results) => {
                if (err) {
                    console.error('Error deleting from ConfirmedRota2:', err);
                    return res.status(500).send('Internal Server Error');
                }

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

    const deleteConfirmedRotaQuery = 'DELETE FROM ConfirmedRota WHERE day = ?';
    const insertConfirmedRotaQuery = `
        INSERT INTO ConfirmedRota (name, lastName, wage, day, startTime, endTime, designation, who) 
        VALUES ?`;
    const deleteRotaQuery = `DELETE FROM rota WHERE day = ?`;
    const insertRotaQuery = `
        INSERT INTO rota (id, name, lastName, designation, day, startTime, endTime)
        VALUES ?`;

    const confirmedRotaValues = rotaData.flatMap(entry => {
        const { name, lastName, wage, day, designation, times } = entry;
        return times.map(time => [name, lastName, wage, day, time.startTime, time.endTime, designation, userEmail]);
    });

    console.log(`Preparing to insert ${confirmedRotaValues.length} confirmed rota entries`);

    pool.query(deleteConfirmedRotaQuery, [day], async (err) => {
        if (err) {
            console.error('Error deleting old confirmed rota:', err);
            return res.status(500).send('Internal Server Error');
        }

        pool.query(insertConfirmedRotaQuery, [confirmedRotaValues], async (err) => {
            if (err) {
                console.error('Error inserting confirmed rota:', err);
                return res.status(500).send('Internal Server Error');
            }

            try {
                const rotaValues = await Promise.all(
                    rotaData.flatMap(async entry => {
                        const { name, lastName, day, designation, times } = entry;
                        return await Promise.all(times.map(async time => {
                            const uniqueId = await generateUniqueId(pool);
                            return [uniqueId, name, lastName, designation, day, time.startTime, time.endTime];
                        }));
                    })
                );

                const flattenedRotaValues = rotaValues.flat();

                console.log(`Preparing to insert ${flattenedRotaValues.length} rota entries`);

                pool.query(deleteRotaQuery, [day], (err) => {
                    if (err) {
                        console.error('Error deleting old rota:', err);
                        return res.status(500).send('Internal Server Error');
                    }

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
    const dbName = req.session.user.dbName;

    if (!dbName) {
        console.error('No dbName in session for /updateRotaData');
        return res.status(401).json({ message: 'User not authenticated' });
    }

    const pool = getPool(dbName);
    const updatedData = req.body;

    console.log(`Updating rota data for ${updatedData.length} entries, db: ${dbName}`);

    try {
        if (!updatedData || !Array.isArray(updatedData)) {
            return res.status(400).send({ success: false, message: 'Invalid input data.' });
        }

        const connection = await pool.promise().getConnection();
        await connection.beginTransaction();

        const uniqueDays = [...new Set(updatedData.map(entry => entry.day))];

        console.log(`Processing days: ${uniqueDays.join(', ')}`);

        for (const day of uniqueDays) {
            await connection.query(`DELETE FROM rota WHERE day = ?`, [day]);
            await connection.query(`DELETE FROM ConfirmedRota WHERE day = ?`, [day]);

            const clientDataForDay = updatedData.filter(entry => entry.day === day);

            console.log(`Processing ${clientDataForDay.length} entries for ${day}`);

            for (const entry of clientDataForDay) {
                const { name, lastName, designation, startTime, endTime } = entry;

                if (!day || !name || !lastName || !designation || !startTime || !endTime) {
                    console.warn(`Skipping invalid entry for ${day}:`, entry);
                    continue;
                }

                const id = await generateUniqueId(pool);
                await connection.query(
                    `INSERT INTO rota (id, day, name, lastName, designation, startTime, endTime) VALUES (?, ?, ?, ?, ?, ?, ?)`,
                    [id, day, name, lastName, designation, startTime, endTime]
                );

                await connection.query(
                    `INSERT INTO ConfirmedRota (day, name, lastName, designation, startTime, endTime, who) VALUES (?, ?, ?, ?, ?, ?, ?)`,
                    [day, name, lastName, designation, startTime, endTime, req.session.user.email]
                );
            }
        }

        await connection.commit();
        connection.release();

        console.log('Successfully updated rota data');
        res.send({ success: true });
    } catch (err) {
        console.error('Error updating rota data:', err);

        if (connection) {
            await connection.rollback();
            connection.release();
        }

        res.status(500).send({ success: false, message: 'An error occurred while updating rota data.' });
    }
});

// Route to fetch employees' name, last name, and designation
app.get('/api/employees', isAuthenticated, (req, res) => {
    const dbName = req.session.user.dbName;

    if (!dbName) {
        console.error('No dbName in session for /api/employees');
        return res.status(401).json({ message: 'User not authenticated' });
    }

    const pool = getPool(dbName);

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
    if (req.session && req.session.user) {
        req.session.destroy(err => {
            if (err) {
                console.error('Failed to logout:', err);
                return res.status(500).json({ error: 'Failed to logout' });
            }
            res.clearCookie('connect.sid');
            res.redirect('/');
        });
    } else {
        res.redirect('/');
    }
});

module.exports = app;