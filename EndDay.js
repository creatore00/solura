const http = require('http');
const fs = require('fs');
const ejs = require('ejs');
const mysql = require('mysql2');
const path = require('path');
const express = require('express');
const bodyParser = require('body-parser');
const { v4: uuidv4 } = require('uuid');
const { getPool, mainPool } = require('./db.js');
const { sessionMiddleware, isAuthenticated, isAdmin, isSupervisor } = require('./sessionConfig');

const app = express();

// Middleware
app.use(sessionMiddleware);
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

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
    
    if (isIOS && (!req.session.user || !req.session.user.dbName)) {
        console.log('📱 iOS Session Restoration Needed - EndDay');
        
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
                role: 'admin' // Default to admin for endday access
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

// Route to serve the appropriate endday app based on device
app.get('/', isAuthenticated, (req, res) => {
    const userAgent = req.headers['user-agent'] || '';
    const deviceType = getDeviceType(userAgent);
    
    console.log('EndDay route - Device Type:', deviceType, 'User-Agent:', userAgent);

    if (req.session.user.role === 'admin' || req.session.user.role === 'AM' || req.session.user.role === 'supervisor') {
        // Add mobile-specific headers
        res.header('Cache-Control', 'no-cache, no-store, must-revalidate');
        res.header('Pragma', 'no-cache');
        res.header('Expires', '0');
        
        // For iOS, ensure session ID is preserved in response
        if (deviceType === 'mobile' || deviceType === 'tablet') {
            const sessionId = req.query.sessionId || req.sessionID;
            console.log('📱 Serving mobile endday app with session ID:', sessionId);
            res.sendFile(path.join(__dirname, 'EndDayApp.html'));
        } else {
            console.log('💻 Serving desktop endday app');
            res.sendFile(path.join(__dirname, 'EndDay.html'));
        }
    } else {
        res.status(403).json({ error: 'Access denied' });
    }
});

// Route to serve mobile endday app directly
app.get('/mobile', isAuthenticated, (req, res) => {
    if (req.session.user.role === 'admin' || req.session.user.role === 'AM' || req.session.user.role === 'supervisor') {
        res.sendFile(path.join(__dirname, 'EndDayApp.html'));
    } else {
        res.status(403).json({ error: 'Access denied' });
    }
});

// Route to serve desktop endday app directly
app.get('/desktop', isAuthenticated, (req, res) => {
    if (req.session.user.role === 'admin' || req.session.user.role === 'AM' || req.session.user.role === 'supervisor') {
        res.sendFile(path.join(__dirname, 'EndDay.html'));
    } else {
        res.status(403).json({ error: 'Access denied' });
    }
});

// Enhanced health endpoint for mobile
app.get('/health', (req, res) => {
    const userAgent = req.headers['user-agent'] || '';
    const isIOS = /iPhone|iPad|iPod/.test(userAgent);
    
    console.log('🏥 EndDay Health check - iOS:', isIOS, 'Session User:', req.session?.user);
    
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

// ... rest of your existing endpoints (api/cash-reports, cashreport, cash) remain the same ...

// Endpoint to insert cash reports
app.post('/api/cash-reports', isAuthenticated, (req, res) => {
    const dbName = req.session.user.dbName;

    if (!dbName) {
        return res.status(401).json({ message: 'User not authenticated' });
    }

    const pool = getPool(dbName);
    const weekData = req.body;

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

    const promises = weekData.map(data => {
        const values = [
            data.day,
            data.zReport || 0,
            data.fifty || 0,
            data.twenty || 0,
            data.ten || 0,
            data.five || 0,
            data.two || 0,
            data.one || 0,
            data.fiftyPence || 0,
            data.twentyPence || 0,
            data.tenPence || 0,
            data.fivePence || 0,
            data.cash || 0,
            data.cc || 0,
            data.service || 0,
            data.pettyCash || 0,
            data.onAccount || 0,
            data.float || 0,
            data.total || 0,
            data.missing || 0
        ];

        return new Promise((resolve, reject) => {
            pool.query(sql, values, (err, result) => {
                if (err) {
                    console.error('Error inserting/updating data: ', err);
                    return reject(err);
                }
                resolve(result.insertId);
            });
        });
    });

    Promise.all(promises)
        .then(results => {
            res.status(201).json({
                message: 'Cash reports created/updated successfully!',
                reportIds: results
            });
        })
        .catch(err => {
            console.error('Error during batch insert/update: ', err);
            res.status(500).json({ error: 'Database error.' });
        });
});

// Route to retrieve cash report data based on week
app.get('/cashreport', isAuthenticated, (req, res) => {
    const dbName = req.session.user.dbName;

    if (!dbName) {
        return res.status(401).json({ message: 'User not authenticated' });
    }

    const pool = getPool(dbName);
    const { startDate, endDate } = req.query;

    const start = new Date(startDate.split('/').reverse().join('-'));
    const end = new Date(endDate.split('/').reverse().join('-'));

    const firstMonday = new Date(start);
    firstMonday.setDate(start.getDate() + (1 - start.getDay() + 7) % 7);

    const lastSunday = new Date(end);
    lastSunday.setDate(end.getDate() + (7 - end.getDay()) % 7);

    const dateArray = [];
    for (let d = firstMonday; d <= lastSunday; d.setDate(d.getDate() + 1)) {
        const formattedDate = `${d.toLocaleString('en-US', { weekday: 'long' })} ${d.getDate().toString().padStart(2, '0')}/${(d.getMonth() + 1).toString().padStart(2, '0')}/${d.getFullYear()}`;
        dateArray.push(formattedDate);
    }

    const placeholders = dateArray.map(() => '?').join(', ');
    const sql = `
        SELECT day, zreport, fifty_pounds, twenty_pounds, ten_pounds, five_pounds, 
            two_pounds, one_pound, fifty_pence, twenty_pence, ten_pence, 
            five_pence, totalcash, card, service, petty, onaccount, 
            floatday, total, eod
        FROM cash_reports
        WHERE day IN (${placeholders})
    `;
    
    pool.query(sql, dateArray, (err, results) => {
        if (err) {
            console.error('Error retrieving data:', err);
            return res.status(500).json({ error: 'Database error.' });
        }
        res.status(200).json(results);
        console.log(results);
    });
});

// Endpoint to retrieve cash reports by date range
app.get('/cash', isAuthenticated, (req, res) => {
    const dbName = req.session.user.dbName;

    if (!dbName) {
        return res.status(401).json({ message: 'User not authenticated' });
    }

    const pool = getPool(dbName);
    const { startdate, enddate } = req.query;

    if (!startdate || !enddate) {
        return res.status(400).json({ error: 'Start date and end date are required.' });
    }

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

module.exports = app;