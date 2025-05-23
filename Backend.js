// Import required modules
const express = require('express');
const mysql = require('mysql2');
const nodemailer = require('nodemailer');
const server = require('./server.js');
const path = require('path');
const bodyParser = require('body-parser');
const { getPool, mainPool } = require('./db.js'); // Import the connection pool functions
const { sessionMiddleware, isAuthenticated, isAdmin } = require('./sessionConfig'); // Adjust the path as needed
const app = express();
// Middleware
app.use(sessionMiddleware);
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
const puppeteer = require('puppeteer');

// Labor settings routes
app.get('/api/labor-settings', isAuthenticated, isAdmin, (req, res) => {
    const dbName = req.session.user.dbName; // Get the database name from the session

    if (!dbName) {
        return res.status(401).json({ message: 'User not authenticated' });
    }

    const pool = getPool(dbName); // Get the correct connection pool
    
    pool.query('SELECT base_hours, times FROM labor LIMIT 1', (error, results) => {
        if (error) {
            console.error('Error fetching labor settings:', error);
            return res.status(500).json({ error: 'Database error' });
        }
        
        if (results.length === 0) {
            return res.json({ base_hours: 0, times: 0 });
        }
        
        res.json(results[0]);
    });
});

app.post('/api/update-labor-settings', isAuthenticated, isAdmin, (req, res) => {
    const dbName = req.session.user.dbName; // Get the database name from the session

    if (!dbName) {
        return res.status(401).json({ message: 'User not authenticated' });
    }

    const pool = getPool(dbName); // Get the correct connection pool
    const { base_hours, times } = req.body;

    
    pool.query('UPDATE labor SET base_hours = ?, times = ?', 
        [base_hours, times], 
        (error, results) => {
            if (error) {
                console.error('Error updating labor settings:', error);
                return res.status(500).json({ success: false, error: 'Database error' });
            }
            
            res.json({ success: true });
        }
    );
});

// Percentage settings routes
app.get('/api/percentage-settings', isAuthenticated, isAdmin, (req, res) => {
    const dbName = req.session.user.dbName; // Get the database name from the session

    if (!dbName) {
        return res.status(401).json({ message: 'User not authenticated' });
    }

    const pool = getPool(dbName); // Get the correct connection pool
    
    pool.query('SELECT FOH, BOH FROM percentages LIMIT 1', (error, results) => {
        if (error) {
            console.error('Error fetching percentage settings:', error);
            return res.status(500).json({ error: 'Database error' });
        }
        
        if (results.length === 0) {
            return res.json({ FOH: 0, BOH: 0 });
        }
        
        res.json(results[0]);
    });
});

app.post('/api/update-percentage-settings', isAuthenticated, isAdmin, (req, res) => {
    const dbName = req.session.user.dbName; // Get the database name from the session

    if (!dbName) {
        return res.status(401).json({ message: 'User not authenticated' });
    }

    const pool = getPool(dbName); // Get the correct connection pool
    const { FOH, BOH } = req.body;
    
    pool.query('UPDATE percentages SET FOH = ?, BOH = ?', 
        [FOH, BOH], 
        (error, results) => {
            if (error) {
                console.error('Error updating percentage settings:', error);
                return res.status(500).json({ success: false, error: 'Database error' });
            }
            
            res.json({ success: true });
        }
    );
});

// Holiday settings routes
app.get('/api/holiday-settings', isAuthenticated, isAdmin, (req, res) => {
    const dbName = req.session.user.dbName; // Get the database name from the session

    if (!dbName) {
        return res.status(401).json({ message: 'User not authenticated' });
    }

    const pool = getPool(dbName); // Get the correct connection pool
    
    pool.query('SELECT HolidayYearStart, HolidayYearEnd FROM HolidayYearSettings LIMIT 1', (error, results) => {
        if (error) {
            console.error('Error fetching holiday settings:', error);
            return res.status(500).json({ error: 'Database error' });
        }
        
        if (results.length === 0) {
            return res.json({ HolidayYearStart: '', HolidayYearEnd: '' });
        }
        
        res.json(results[0]);
    });
});

app.post('/api/update-holiday-settings', isAuthenticated, isAdmin, (req, res) => {
    const dbName = req.session.user.dbName; // Get the database name from the session

    if (!dbName) {
        return res.status(401).json({ message: 'User not authenticated' });
    }
    const pool = getPool(dbName); // Get the correct connection pool
    const { HolidayYearStart, HolidayYearEnd } = req.body;
    
    pool.query('UPDATE HolidayYearSettings SET HolidayYearStart = ?, HolidayYearEnd = ?', 
        [HolidayYearStart, HolidayYearEnd], 
        (error, results) => {
            if (error) {
                console.error('Error updating holiday settings:', error);
                return res.status(500).json({ success: false, error: 'Database error' });
            }
            
            res.json({ success: true });
        }
    );
});

// Route to serve HTML files
app.get('/', isAuthenticated, isAdmin, (req, res) => {
    res.sendFile(path.join(__dirname, 'Backend.html'));
});
module.exports = app; // Export the entire Express application