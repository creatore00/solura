// Import required modules
const express = require('express');
const mysql = require('mysql2');
const nodemailer = require('nodemailer');
const bodyParser = require('body-parser');
const path = require('path');
const { getPool, mainPool } = require('./db.js');
const { sessionMiddleware, isAuthenticated, isAdmin, isSupervisor, isUser } = require('./sessionConfig');

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
    
    console.log('=== HOLIDAY SESSION DEBUG ===');
    console.log('Path:', req.path);
    console.log('Session ID:', req.sessionID);
    console.log('Session exists:', !!req.session);
    console.log('Session User:', req.session?.user);
    console.log('Is iOS:', isIOS);
    console.log('=== END DEBUG ===');

    // If iOS and session exists but user data is missing, try to restore
    if (isIOS && req.session && !req.session.user) {
        console.log('📱 iOS Session Restoration Needed - Holiday');
        
        // Try multiple recovery methods
        const urlParams = new URLSearchParams(req.url.includes('?') ? req.url.split('?')[1] : '');
        const sessionId = urlParams.get('sessionId');
        const email = urlParams.get('email');
        const dbName = urlParams.get('dbName');
        const name = urlParams.get('name');
        const lastName = urlParams.get('lastName');
        
        // Also check headers for recovery data
        const headerSessionId = req.headers['x-session-id'];
        const headerEmail = req.headers['x-user-email'];
        const headerDbName = req.headers['x-db-name'];
        
        console.log('🔄 Attempting session restoration with:', { 
            urlParams: { sessionId, email, dbName },
            headers: { headerSessionId, headerEmail, headerDbName }
        });
        
        // Use URL params first, then headers
        const recoveryEmail = email || headerEmail;
        const recoveryDbName = dbName || headerDbName;
        const recoverySessionId = sessionId || headerSessionId;
        
        if (recoveryEmail && recoveryDbName) {
            console.log('✅ Restoring session for:', recoveryEmail);
            
            req.session.user = {
                email: recoveryEmail,
                dbName: recoveryDbName,
                name: name || '',
                lastName: lastName || '',
                role: 'user' // Default for holiday access
            };
            
            // Sync session ID if provided
            if (recoverySessionId && req.sessionID !== recoverySessionId) {
                console.log('🔄 Syncing session ID to:', recoverySessionId);
                req.sessionID = recoverySessionId;
            }
            
            // Save the restored session
            return req.session.save((err) => {
                if (err) {
                    console.error('❌ Failed to save restored session:', err);
                } else {
                    console.log('✅ Session restored successfully for:', recoveryEmail);
                }
                next();
            });
        } else {
            console.log('❌ No restoration parameters found');
        }
    }
    next();
});

// Enhanced authentication middleware with iOS support
const isAuthenticatedWithIOS = (req, res, next) => {
    console.log('=== AUTH MIDDLEWARE DEBUG ===');
    console.log('Session ID:', req.sessionID);
    console.log('Session exists:', !!req.session);
    console.log('Session User:', req.session?.user);
    console.log('Path:', req.path);
    console.log('Method:', req.method);
    console.log('=== END DEBUG ===');

    const userAgent = req.headers['user-agent'] || '';
    const isIOS = /iPhone|iPad|iPod/.test(userAgent);

    // For iOS, check if we have a session but missing user data
    if (isIOS && req.session && !req.session.user) {
        console.log('📱 iOS detected with session but no user data');
        
        // For API requests, return a specific error that frontend can handle
        if (req.path.startsWith('/api/')) {
            return res.status(401).json({ 
                error: 'Session recovery needed',
                requiresReauth: true,
                sessionId: req.sessionID,
                message: 'Session data missing, please refresh'
            });
        }
    }

    // Normal authentication check
    if (req.session && req.session.user) {
        console.log('✅ Authentication SUCCESS');
        next();
    } else {
        console.log('❌ Authentication FAILED: No valid session');
        
        // For API requests, return JSON error
        if (req.path.startsWith('/api/')) {
            return res.status(401).json({ 
                error: 'Authentication required',
                requiresReauth: true
            });
        } else {
            // For page requests, redirect to login
            res.redirect('/');
        }
    }
};

// Route to serve the appropriate holiday app based on device
app.get('/', isAuthenticatedWithIOS, (req, res) => {
    const userAgent = req.headers['user-agent'] || '';
    const deviceType = getDeviceType(userAgent);
    
    console.log('Holiday route - Device Type:', deviceType, 'User:', req.session.user.email);

    if (req.session.user.role === 'admin' || req.session.user.role === 'AM' || 
        req.session.user.role === 'supervisor' || req.session.user.role === 'user') {
        
        // Add mobile-specific headers
        res.header('Cache-Control', 'no-cache, no-store, must-revalidate');
        res.header('Pragma', 'no-cache');
        res.header('Expires', '0');
        
        // For mobile/tablet, serve mobile app with session parameters
        if (deviceType === 'mobile' || deviceType === 'tablet') {
            console.log('📱 Serving mobile holiday app');
            
            // CRITICAL: Pass session data via URL parameters for iOS
            const sessionParams = new URLSearchParams({
                email: req.session.user.email,
                dbName: req.session.user.dbName,
                name: req.session.user.name || '',
                lastName: req.session.user.lastName || '',
                sessionId: req.sessionID
            });
            
            // Redirect to the mobile app with session parameters
            res.redirect(`/userholidays/mobile?${sessionParams.toString()}`);
        } else {
            console.log('💻 Serving desktop holiday app');
            res.sendFile(path.join(__dirname, 'Holidays.html'));
        }
    } else {
        res.status(403).json({ error: 'Access denied' });
    }
});

// Route to serve mobile holiday app directly with session handling
app.get('/mobile', isAuthenticatedWithIOS, (req, res) => {
    if (req.session.user.role === 'admin' || req.session.user.role === 'AM' || 
        req.session.user.role === 'supervisor' || req.session.user.role === 'user') {
        
        console.log('📱 Direct mobile access - serving HolidayApp.html');
        
        // Add session parameters to the response for the mobile app
        const sessionData = {
            email: req.session.user.email,
            dbName: req.session.user.dbName,
            name: req.session.user.name || '',
            lastName: req.session.user.lastName || '',
            sessionId: req.sessionID
        };
        
        // Set headers for mobile
        res.header('Cache-Control', 'no-cache, no-store, must-revalidate');
        res.header('Pragma', 'no-cache');
        res.header('Expires', '0');
        
        res.sendFile(path.join(__dirname, 'HolidayApp.html'));
    } else {
        res.status(403).json({ error: 'Access denied' });
    }
});

// Route to serve desktop holiday app directly
app.get('/desktop', isAuthenticatedWithIOS, (req, res) => {
    if (req.session.user.role === 'admin' || req.session.user.role === 'AM' || 
        req.session.user.role === 'supervisor' || req.session.user.role === 'user') {
        res.sendFile(path.join(__dirname, 'Holidays.html'));
    } else {
        res.status(403).json({ error: 'Access denied' });
    }
});

// Enhanced health endpoint for mobile with session recovery support
app.get('/health', (req, res) => {
    const userAgent = req.headers['user-agent'] || '';
    const isIOS = /iPhone|iPad|iPod/.test(userAgent);
    
    console.log('🏥 Holiday Health check - iOS:', isIOS, 'Session User:', req.session?.user);
    
    const healthData = {
        status: req.session?.user ? 'healthy' : 'unauthenticated',
        deviceType: getDeviceType(userAgent),
        isIOS: isIOS,
        session: !!req.session,
        user: req.session?.user ? {
            email: req.session.user.email,
            role: req.session.user.role,
            name: req.session.user.name
        } : null,
        timestamp: new Date().toISOString()
    };
    
    // For iOS with session issues, provide recovery info
    if (isIOS && req.session && !req.session.user) {
        healthData.status = 'needs_recovery';
        healthData.sessionId = req.sessionID;
        healthData.recoveryUrl = `/userholidays/recover?sessionId=${req.sessionID}`;
    }
    
    res.json(healthData);
});

// Session recovery endpoint for iOS
app.get('/recover', (req, res) => {
    const { sessionId, email, dbName, name, lastName } = req.query;
    
    console.log('🔄 Session recovery request:', { sessionId, email, dbName });
    
    if (email && dbName) {
        req.session.user = {
            email: email,
            dbName: dbName,
            name: name || '',
            lastName: lastName || '',
            role: 'user'
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
                redirect: '/userholidays'
            });
        });
    } else {
        res.status(400).json({ error: 'Missing recovery parameters' });
    }
});

// Configure the email transporter
const transporter = nodemailer.createTransport({
    host: 'smtp0001.neo.space',
    port: 465,
    secure: true,
    auth: {
        user: 'no-reply@solura.uk',
        pass: 'Salvemini01@'
    }
});

// Route to submit a holiday request
app.post('/submitHolidayRequest', isAuthenticatedWithIOS, (req, res) => {
    const dbName = req.session.user.dbName;

    if (!dbName) {
        return res.status(401).json({ message: 'User not authenticated' });
    }

    const pool = getPool(dbName);

    const { startDate, endDate } = req.body;
    const { email, name, lastName } = req.session.user;
    const today = new Date();
    const fourteenDaysLater = new Date(today);
    fourteenDaysLater.setDate(today.getDate() + 14);

    const start = new Date(startDate);
    const end = new Date(endDate);
    const maxEndDate = new Date(start);
    maxEndDate.setDate(start.getDate() + 13);

    // Calculate days including both start and end dates
    const daysDiff = Math.floor((end - start) / (1000 * 60 * 60 * 24)) + 1;

    if (start < fourteenDaysLater) {
        return res.status(400).json({ success: false, message: 'Holiday requests must be made at least 14 days in advance.' });
    }

    if (end > maxEndDate) {
        return res.status(400).json({ success: false, message: 'Holiday requests can be for a maximum of two consecutive weeks.' });
    }

    // Format dates to dd/mm/yyyy (DayName)
    const formatDateWithDay = (date) => {
        const day = String(date.getDate()).padStart(2, '0');
        const month = String(date.getMonth() + 1).padStart(2, '0');
        const year = date.getFullYear();
        const days = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];
        const dayName = days[date.getDay()];
        return `${day}/${month}/${year} (${dayName})`;
    };

    const formattedStartDate = formatDateWithDay(start);
    const formattedEndDate = formatDateWithDay(end);
    const requestDate = formatDateWithDay(new Date());

    // Include email in the INSERT statement
    const sql = 'INSERT INTO Holiday (name, lastName, startDate, endDate, requestDate, days) VALUES (?, ?, ?, ?, ?, ?)';
    const values = [name, lastName, formattedStartDate, formattedEndDate, requestDate, daysDiff];

    pool.query(sql, values, async (error, results) => {
        if (error) {
            console.error('Error submitting holiday request:', error);
            return res.status(500).json({ success: false, message: 'Error submitting holiday request' });
        }

        console.log('Holiday request submitted successfully');
        try {
            await sendEmailNotification(dbName, email, name, formattedStartDate, formattedEndDate, daysDiff);
            return res.json({ 
                success: true, 
                message: 'Holiday request submitted successfully',
                daysRequested: daysDiff,
                requestDate: requestDate
            });
        } catch (emailError) {
            console.error('Email notification failed:', emailError);
            return res.json({
                success: true,
                message: 'Holiday submitted but email notification failed',
                daysRequested: daysDiff,
                requestDate: requestDate
            });
        }
    });
});

// Improved email function
async function getAllEmails(dbName) {
    const pool = getPool(dbName);
    const query = 'SELECT email FROM Employees WHERE position = "manager" OR position = "AM"';
    const [results] = await pool.promise().query(query);
    return results.map(row => row.email);
}

// Improved email notification function
async function sendEmailNotification(dbName, requesterEmail, requesterName, startDate, endDate, days) {
    try {
        const emails = await getAllEmails(dbName);
        if (!emails.length) return;

        const mailOptions = {
            from: 'Solura WorkForce <no-reply@solura.uk>',
            to: emails.join(', '),
            subject: 'New Holiday Request Submitted',
            text: `A new holiday request has been submitted by ${requesterName} (${requesterEmail}).\n\n` +
                  `Dates: ${startDate} to ${endDate}\n` +
                  `Total days: ${days}\n\n` +
                  `Please review the request in the system.`,
            html: `<p>A new holiday request has been submitted by <strong>${requesterName}</strong> (${requesterEmail}).</p>
                   <p><strong>Dates:</strong> ${startDate} to ${endDate}</p>
                   <p><strong>Total days:</strong> ${days}</p>
                   <p>Please review the request in the system.</p>`
        };

        const info = await transporter.sendMail(mailOptions);
        console.log('Email sent:', info.response);
        return info;
    } catch (error) {
        console.error('Error sending email notification:', error);
        throw error;
    }
}

module.exports = app;