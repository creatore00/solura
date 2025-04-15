const server = require('./server.js');
const http = require('http');
const fs = require('fs');
const mysql = require('mysql2');
const express = require('express');
const bodyParser = require('body-parser');
const { PDFDocument, rgb } = require('pdf-lib');
const { v4: uuidv4 } = require('uuid');
const nodemailer = require('nodemailer');
const puppeteer = require('puppeteer');
const path = require('path');
const { getPool, mainPool } = require('./db.js'); // Import the connection pool functions
const pdf = require('html-pdf');
const { sessionMiddleware, isAuthenticated, isAdmin, isSupervisor, isUser } = require('./sessionConfig'); // Adjust the path as needed

const app = express();

// Middleware
app.use(sessionMiddleware);
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Route to retrieve data from the "ConfirmedRota" table
app.get('/rota', isAuthenticated, (req, res) => {
    const dbName = req.session.user.dbName; // Get the database name from the session

    if (!dbName) {
        return res.status(401).json({ message: 'User not authenticated' });
    }

    const pool = getPool(dbName); // Get the correct connection pool

    const selectedMonth = req.query.month || new Date().toISOString().slice(0, 7); // Default to current month in YYYY-MM format

    const query = `
        SELECT 
            cr.name,
            cr.lastName,
            e.wage,
            cr.startTime,
            cr.endTime
        FROM 
            ConfirmedRota cr
        JOIN 
            Employees e
        ON 
            cr.name = e.name AND cr.lastName = e.lastName
        WHERE 
            DATE_FORMAT(STR_TO_DATE(cr.day, '%d/%m/%Y'), '%Y-%m') = ?
    `;

    pool.query(query, [selectedMonth], (err, results) => {
        if (err) {
            console.error('Error fetching rota data:', err);
            res.status(500).json({ success: false, message: 'Server error' });
            return;
        }
        res.json(results);
    });
});

// Route to retrieve holiday data with proper overlapping support
app.get('/holidays', isAuthenticated, (req, res) => {
    const dbName = req.session.user.dbName;
    const selectedMonth = req.query.month || new Date().toISOString().slice(0, 7); // e.g. "2025-04"

    const pool = getPool(dbName);

    // Start of month (e.g. 2025-04-01)
    const monthStart = `${selectedMonth}-01`;

    // End of month (e.g. 2025-04-30)
    monthEnd = `${selectedMonth}-31`;

    // Query to find any overlapping holidays
    const query = `
        SELECT 
            name,
            lastName,
            startDate,
            endDate
        FROM 
            Holiday
        WHERE
            accepted = 'true'
            AND (
                (STR_TO_DATE(startDate, '%d/%m/%Y') BETWEEN ? AND ?) OR
                (STR_TO_DATE(endDate, '%d/%m/%Y') BETWEEN ? AND ?) OR
                (STR_TO_DATE(startDate, '%d/%m/%Y') <= ? AND STR_TO_DATE(endDate, '%d/%m/%Y') >= ?)
            );
    `;

    pool.query(query, [monthStart, monthEnd, monthStart, monthEnd, monthStart, monthEnd], (err, results) => {
        if (err) {
            console.error('[GET /holidays] Error fetching holiday data:', err);
            return res.status(500).json({ success: false, message: 'Server error' });
        }
        
        // Process the results to ensure proper date format (without day names in parentheses)
        const processedResults = results.map(holiday => ({
            ...holiday,
            startDate: holiday.startDate.split(' ')[0], // Removing any extra text like day names
            endDate: holiday.endDate.split(' ')[0]
        }));
        res.json(processedResults);
    });
});

// Route to retrieve holiday year settings
app.get('/holiday-year-settings', isAuthenticated, (req, res) => {
    const dbName = req.session.user.dbName;
    const pool = getPool(dbName);
    
    const query = `
        SELECT 
            HolidayYearStart,
            HolidayYearEnd
        FROM 
            HolidayYearSettings
        LIMIT 1;
    `;

    pool.query(query, (err, results) => {
        if (err) {
            console.error('Error fetching holiday year settings:', err);
            res.status(500).json({ success: false, message: 'Server error' });
            return;
        }
        res.json(results[0] || {});
    });
});

// Route to retrieve employees' start dates
app.get('/employees-start-dates', isAuthenticated, (req, res) => {
    const dbName = req.session.user.dbName;
    const pool = getPool(dbName);
    
    const query = `
        SELECT 
            name,
            lastName,
            dateStart
        FROM 
            Employees;
    `;

    pool.query(query, (err, results) => {
        if (err) {
            console.error('Error fetching employees start dates:', err);
            res.status(500).json({ success: false, message: 'Server error' });
            return;
        }
        res.json(results);
    });
});

// Route to retrieve data from the "Tip" table
app.get('/tip', isAuthenticated, (req, res) => {
    const dbName = req.session.user.dbName; // Get the database name from the session

    if (!dbName) {
        return res.status(401).json({ message: 'User not authenticated' });
    }

    const pool = getPool(dbName); // Get the correct connection pool

    const selectedMonth = req.query.month || new Date().toISOString().slice(0, 7); // Default to current month
    const query = `
        SELECT 
            name,
            lastName,
            tip
        FROM 
            tip
        WHERE
            DATE_FORMAT(day, '%Y-%m') = ?;
    `;

    pool.query(query, [selectedMonth], (err, results) => {
        if (err) {
            console.error('Error fetching tip data:', err);
            res.status(500).json({ success: false, message: 'Server error' });
            return;
        }
        res.json(results);
    });
});

// Route to generate PDF
app.post('/generate-pdf', isAuthenticated, async (req, res) => {
    const { htmlContent, month } = req.body;
    let browser;

    try {
        const launchOptions = {
            headless: 'new',
            args: [
                '--no-sandbox',
                '--disable-setuid-sandbox',
                '--disable-dev-shm-usage',
                '--disable-gpu'
            ]
        };

        // Dev on Windows
        if (process.env.NODE_ENV !== 'production' && process.platform === 'win32') {
            launchOptions.executablePath = 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe';
        }
        // Heroku production
        else if (process.env.NODE_ENV === 'production') {
            launchOptions.executablePath = '/app/.chrome-for-testing/chrome-linux64/chrome';
        }

        browser = await puppeteer.launch(launchOptions);
        const page = await browser.newPage();

        await page.setContent(htmlContent, {
            waitUntil: 'networkidle0',
            timeout: 30000
        });

        const pdfBuffer = await page.pdf({
            format: 'A4',
            landscape: true,
            printBackground: true,
            margin: {
                top: '20mm',
                right: '10mm',
                bottom: '20mm',
                left: '10mm'
            }
        });

        // ✅ Correct way to send PDF as a downloadable file
        res.setHeader('Content-Type', 'application/pdf');
        res.setHeader('Content-Disposition', `attachment; filename="Monthly_Report_${month}.pdf"`);
        res.end(pdfBuffer);

    } catch (error) {
        console.error('PDF Generation Error:', error);
        if (!res.headersSent) {
            res.status(500).json({ error: 'Failed to generate PDF' });
        }
    } finally {
        if (browser) await browser.close();
    }
});

// Route to serve the Hours.html file
app.get('/', isAuthenticated, isAdmin, (req, res) => {
    res.sendFile(path.join(__dirname, 'Hours.html'));
});

module.exports = app; // Export the entire Express application