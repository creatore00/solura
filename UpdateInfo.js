const express = require('express');
const mysql = require('mysql2');
const bodyParser = require('body-parser');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const { getPool, mainPool } = require('./db.js');
const { sessionMiddleware, isAuthenticated, isAdmin } = require('./sessionConfig');

const app = express();

// Apply session middleware FIRST
app.use(sessionMiddleware);

// Enhanced CORS and security headers for mobile
app.use((req, res, next) => {
    // Allow credentials for mobile apps
    res.header('Access-Control-Allow-Credentials', 'true');
    res.header('Access-Control-Allow-Origin', req.headers.origin || '*');
    res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization, X-Session-ID, X-User-Email, X-DB-Name, X-Mobile-App');
    
    // Security headers for mobile
    res.header('X-Frame-Options', 'SAMEORIGIN');
    res.header('X-Content-Type-Options', 'nosniff');
    res.header('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    
    if (req.method === 'OPTIONS') {
        return res.status(200).end();
    }
    next();
});

// Enhanced body parsing
app.use(bodyParser.json({ limit: '10mb' }));
app.use(bodyParser.urlencoded({ extended: true, limit: '10mb' }));

// Enhanced mobile detection
function isMobile(userAgent) {
    return /android|iphone|ipad|ipod|mobile/i.test(userAgent.toLowerCase());
}

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

// SIMPLIFIED authentication middleware - like the working holiday app
const isAuthenticatedWithIOS = (req, res, next) => {
    console.log('=== AUTH DEBUG ===');
    console.log('Session exists:', !!req.session);
    console.log('Session User:', req.session?.user);
    console.log('Path:', req.path);
    console.log('=== END DEBUG ===');

    const userAgent = req.headers['user-agent'] || '';
    const isIOS = /iPhone|iPad|iPod/.test(userAgent);

    // For iOS, check if we have a session but missing user data
    if (isIOS && req.session && !req.session.user) {
        console.log('📱 iOS detected with session but no user data');
        
        // Try to recover from URL parameters
        const urlParams = new URLSearchParams(req.url.includes('?') ? req.url.split('?')[1] : '');
        const email = urlParams.get('email');
        const dbName = urlParams.get('dbName');
        
        if (email && dbName) {
            console.log('🔄 Attempting iOS session recovery from URL');
            req.session.user = {
                email: email,
                dbName: dbName,
                name: urlParams.get('name') || '',
                lastName: urlParams.get('lastName') || '',
                role: 'admin'
            };
            
            return req.session.save((err) => {
                if (err) {
                    console.error('❌ Failed to save recovered session:', err);
                    return sendAuthError(res, true);
                }
                console.log('✅ iOS session recovered successfully');
                next();
            });
        }
    }

    // Normal authentication check
    if (req.session && req.session.user) {
        console.log('✅ Authentication SUCCESS');
        next();
    } else {
        console.log('❌ Authentication FAILED: No valid session');
        sendAuthError(res, isMobile(userAgent));
    }
};

function sendAuthError(res, isMobile) {
    if (isMobile) {
        return res.status(401).json({ 
            error: 'Authentication required',
            requiresReauth: true
        });
    } else {
        res.redirect('/');
    }
}

// Health check endpoint - no authentication required
app.get('/health', (req, res) => {
    const userAgent = req.headers['user-agent'] || '';
    
    const healthData = {
        status: req.session?.user ? 'healthy' : 'unauthenticated',
        deviceType: getDeviceType(userAgent),
        isMobile: isMobile(userAgent),
        session: !!req.session,
        user: req.session?.user ? {
            email: req.session.user.email,
            role: req.session.user.role,
            name: req.session.user.name
        } : null,
        timestamp: new Date().toISOString()
    };
    
    res.json(healthData);
});

// Session recovery endpoint - like the working holiday app
app.get('/recover', (req, res) => {
    const { sessionId, email, dbName, name, lastName } = req.query;
    
    console.log('🔄 Session recovery request:', { email, dbName });
    
    if (email && dbName) {
        req.session.user = {
            email: email,
            dbName: dbName,
            name: name || '',
            lastName: lastName || '',
            role: 'admin'
        };
        
        req.session.save((err) => {
            if (err) {
                console.error('❌ Session recovery failed:', err);
                return res.status(500).json({ error: 'Recovery failed' });
            }
            
            console.log('✅ Session recovered successfully');
            res.json({ 
                success: true, 
                message: 'Session recovered',
                newSessionId: req.sessionID,
                user: {
                    email: req.session.user.email,
                    name: req.session.user.name
                }
            });
        });
    } else {
        res.status(400).json({ error: 'Missing recovery parameters' });
    }
});

// Route to serve appropriate version based on device
app.get('/', isAuthenticatedWithIOS, isAdmin, (req, res) => {
    const userAgent = req.headers['user-agent'] || '';
    const deviceType = getDeviceType(userAgent);
    
    console.log('Personal Info route - Device Type:', deviceType, 'User:', req.session.user.email);

    // Add mobile-specific headers
    res.header('Cache-Control', 'no-cache, no-store, must-revalidate');
    res.header('Pragma', 'no-cache');
    res.header('Expires', '0');
    
    // For mobile/tablet, serve mobile app with session parameters
    if (deviceType === 'mobile' || deviceType === 'tablet') {
        console.log('📱 Serving mobile personal info app');
        
        const sessionParams = new URLSearchParams({
            email: req.session.user.email,
            dbName: req.session.user.dbName,
            name: req.session.user.name || '',
            lastName: req.session.user.lastName || '',
            sessionId: req.sessionID,
            mobile: 'true',
            timestamp: Date.now()
        });
        
        // Redirect to the mobile app with session parameters
        res.redirect(`/updateinfo/mobile?${sessionParams.toString()}`);
    } else {
        console.log('💻 Serving desktop personal info app');
        res.sendFile(path.join(__dirname, 'PersonalInfo.html'));
    }
});

// Route to serve mobile app directly
app.get('/mobile', isAuthenticatedWithIOS, isAdmin, (req, res) => {
    console.log('📱 Direct mobile access - serving PersonalInfoApp.html');
    
    // Set mobile-specific headers
    res.header('Cache-Control', 'no-cache, no-store, must-revalidate');
    res.header('Pragma', 'no-cache');
    res.header('Expires', '0');
    
    // Send the mobile app HTML
    res.sendFile(path.join(__dirname, 'PersonalInfoApp.html'));
});

// Route to serve desktop app directly
app.get('/desktop', isAuthenticatedWithIOS, isAdmin, (req, res) => {
    res.sendFile(path.join(__dirname, 'PersonalInfo.html'));
});

// File upload configuration
const storage = multer.memoryStorage();
const upload = multer({ 
    storage: storage,
    limits: {
        fileSize: 10 * 1024 * 1024 // 10MB limit
    }
}).fields([
    { name: 'passportImage', maxCount: 1 },
    { name: 'visa', maxCount: 1 }
]);

// Endpoint to Send Data
app.post('/', isAuthenticatedWithIOS, isAdmin, upload, (req, res) => {
    const dbName = req.session.user.dbName;

    if (!dbName) {
        return res.status(401).json({ success: false, message: 'User not authenticated' });
    }

    const pool = getPool(dbName);

    console.log('Request Body:', req.body);
    const { name, lastName, email, phone, address, nin, wage, designation, position, contractHours, Salary, SalaryPrice, holiday, dateStart, pension_payer } = req.body;
    const passportImageFile = req.files['passportImage'] ? req.files['passportImage'][0] : null;
    const visaFile = req.files['visa'] ? req.files['visa'][0] : null;

    if (!passportImageFile) {
        return res.status(400).json({ success: false, message: 'Passport image is required' });
    }

    const passportImageContent = passportImageFile.buffer;
    const visaContent = visaFile ? visaFile.buffer : null;

    const query = 'INSERT INTO Employees (name, lastName, email, phone, address, nin, wage, designation, position, contractHours, Salary, SalaryPrice, passportImage, visa, TotalHoliday, startHoliday, dateStart, pension_payer) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)';

    pool.query(query, [name, lastName, email, phone, address, nin, wage, designation, position, contractHours, Salary, SalaryPrice, passportImageContent, visaContent, holiday, holiday, dateStart, pension_payer], (err, result) => {
        if (err) {
            console.error('Error inserting data:', err);
            res.status(500).json({ success: false, message: 'Server error' });
            return;
        }
        res.json({ success: true, message: 'Employee data successfully inserted' });
    });
});

// Endpoint to Retrieve Data
app.get('/employees', isAuthenticatedWithIOS, isAdmin, (req, res) => {
    const dbName = req.session.user.dbName;

    if (!dbName) {
        return res.status(401).json({ success: false, message: 'User not authenticated' });
    }

    const pool = getPool(dbName);

    const query = `
        SELECT id, name, lastName, email, phone, address, nin, wage, designation, 
               position, contractHours, Salary, SalaryPrice, dateStart, startHoliday, 
               TotalHoliday, Accrued, pension_payer
        FROM Employees 
        WHERE situation IS NULL OR situation = ''
    `;
    
    pool.query(query, (err, results) => {
        if (err) {
            console.error('Error fetching data:', err);
            res.status(500).json({ success: false, message: 'Server error' });
            return;
        }
        res.json(results);
    });
});

// GET endpoint to fetch employee data for editing
app.get('/edit-employee/:id', isAuthenticatedWithIOS, isAdmin, (req, res) => {
    const dbName = req.session.user.dbName;
    if (!dbName) {
        return res.status(401).json({ success: false, message: 'User not authenticated' });
    }

    const pool = getPool(dbName);
    const { id } = req.params;

    pool.query(
        `SELECT id, name, lastName, email, phone, address, nin, wage, 
         designation, position, contractHours, Salary, SalaryPrice, dateStart, startHoliday, pension_payer 
         FROM Employees WHERE id = ?`,
        [id],
        (err, rows) => {
            if (err) {
                console.error('Error fetching employee data:', err);
                return res.status(500).json({ 
                    success: false, 
                    message: 'Server error'
                });
            }

            if (rows.length === 0) {
                return res.status(404).json({ success: false, message: 'Employee not found' });
            }

            const employeeData = rows[0];
            
            if (employeeData.dateStart instanceof Date) {
                employeeData.dateStart = employeeData.dateStart.toISOString().split('T')[0];
            }

            res.json({
                success: true,
                data: employeeData
            });
        }
    );
});

// POST endpoint to update employee data
app.post('/edit-employee/:id', isAuthenticatedWithIOS, isAdmin, upload, (req, res) => {
    const dbName = req.session.user.dbName;
    if (!dbName) {
        return res.status(401).json({ success: false, message: 'User not authenticated' });
    }

    const pool = getPool(dbName);
    const { id } = req.params;
    const { name, lastName, email, phone, address, nin, wage, 
           designation, position, contractHours, Salary, SalaryPrice, holiday, dateStart, pension_payer } = req.body;

    pool.query('SELECT startHoliday, TotalHoliday FROM Employees WHERE id = ?', [id], (err, currentData) => {
        if (err) {
            console.error('Error fetching current employee data:', err);
            return res.status(500).json({ 
                success: false, 
                message: 'Server error fetching current employee data'
            });
        }

        if (!currentData || currentData.length === 0) {
            return res.status(404).json({ success: false, message: 'Employee not found' });
        }

        const oldHoliday = parseFloat(currentData[0].startHoliday) || 0;
        const newHoliday = parseFloat(holiday) || 0;
        const holidayDifference = newHoliday - oldHoliday;
        const currentTotalHoliday = parseFloat(currentData[0].TotalHoliday) || 0;
        const updatedTotalHoliday = currentTotalHoliday + holidayDifference;

        const passportImageFile = req.files['passportImage'] ? req.files['passportImage'][0] : null;
        const visaFile = req.files['visa'] ? req.files['visa'][0] : null;

        let query = `UPDATE Employees SET 
            name = ?, lastName = ?, email = ?, phone = ?, address = ?,
            nin = ?, wage = ?, designation = ?, position = ?, contractHours = ?, Salary = ?, SalaryPrice =?,
            dateStart = ?, startHoliday = ?, TotalHoliday = ?, pension_payer = ?`;
        
        const queryParams = [
            name, lastName, email, phone, address, 
            nin, wage, designation, position, contractHours, Salary, SalaryPrice,
            dateStart, holiday, updatedTotalHoliday, pension_payer
        ];

        if (passportImageFile) {
            query += ', passportImage = ?';
            queryParams.push(passportImageFile.buffer);
        }
        if (visaFile) {
            query += ', visa = ?';
            queryParams.push(visaFile.buffer);
        }

        query += ' WHERE id = ?';
        queryParams.push(id);

        pool.query(query, queryParams, (err, result) => {
            if (err) {
                console.error('Error updating employee:', err);
                return res.status(500).json({ 
                    success: false, 
                    message: 'Server error'
                });
            }

            res.json({ 
                success: true, 
                message: 'Employee updated successfully'
            });
        });
    });
});

// Endpoint to download passport file
app.get('/api/download-file/:id', isAuthenticatedWithIOS, isAdmin, (req, res) => {
    const dbName = req.session.user.dbName;

    if (!dbName) {
        return res.status(401).json({ success: false, message: 'User not authenticated' });
    }

    const pool = getPool(dbName);
    const { id } = req.params;

    const query = 'SELECT passportImage FROM Employees WHERE id = ?';
    pool.query(query, [id], (err, results) => {
        if (err) {
            console.error('Error fetching data:', err);
            res.status(500).json({ error: 'Database query error' });
            return;
        }
        if (results.length === 0) {
            res.status(404).json({ error: 'Passport not found' });
            return;
        }
        const passportImage = results[0].passportImage;

        res.setHeader('Content-Type', 'application/pdf');
        res.setHeader('Content-Disposition', `attachment; filename=Passport_${id}.pdf`);
        res.send(passportImage);
    });
});

// Endpoint to download visa file
app.get('/api/download-visa/:id', isAuthenticatedWithIOS, isAdmin, (req, res) => {
    const dbName = req.session.user.dbName;

    if (!dbName) {
        return res.status(401).json({ success: false, message: 'User not authenticated' });
    }

    const pool = getPool(dbName);
    const { id } = req.params;

    const query = 'SELECT visa FROM Employees WHERE id = ?';
    pool.query(query, [id], (err, results) => {
        if (err) {
            console.error('Error fetching data:', err);
            res.status(500).json({ error: 'Database query error' });
            return;
        }
        if (results.length === 0) {
            res.status(404).json({ error: 'Visa not found' });
            return;
        }
        const visa = results[0].visa;

        res.setHeader('Content-Type', 'application/pdf');
        res.setHeader('Content-Disposition', `attachment; filename=Visa_${id}.pdf`);
        res.send(visa);
    });
});

// DELETE endpoint to remove an employee
app.delete('/employee/:id', isAuthenticatedWithIOS, isAdmin, async (req, res) => {
    const dbName = req.session.user.dbName;

    if (!dbName) {
        return res.status(401).json({ success: false, message: 'User not authenticated' });
    }

    const pool = getPool(dbName);
    const { id } = req.params;
    const { ended } = req.body;

    try {
        const getEmployeeQuery = 'SELECT email FROM Employees WHERE id = ?';
        const [employeeRows] = await pool.promise().query(getEmployeeQuery, [id]);

        if (employeeRows.length === 0) {
            return res.status(404).json({ success: false, message: 'Employee not found' });
        }

        const employeeEmail = employeeRows[0].email;

        const updateQuery = 'UPDATE Employees SET situation = ?, ended = ? WHERE id = ?';
        await pool.promise().query(updateQuery, ['past', ended, id]);

        const deleteUserQuery = 'DELETE FROM users WHERE email = ?';
        const [result] = await mainPool.promise().query(deleteUserQuery, [employeeEmail]);

        if (result.affectedRows > 0) {
            console.log(`Removed user access for ${employeeEmail}`);
        }

        res.json({ 
            success: true, 
            message: 'Employee marked as past, leaving date stored, and system access removed'
        });

    } catch (err) {
        console.error('Error during employee status update:', err);
        res.status(500).json({ 
            success: false, 
            message: 'Server error during employee status update'
        });
    }
});

module.exports = app;