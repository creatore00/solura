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

// New endpoint to get holiday year start date
app.get('/holiday-settings', isAuthenticated, (req, res) => {
    const dbName = req.session.user.dbName;
    if (!dbName) {
        return res.status(401).json({ message: 'User not authenticated' });
    }

    const pool = getPool(dbName);
    pool.query('SELECT HolidayYearStart FROM HolidayYearSettings LIMIT 1', (err, results) => {
        if (err) {
            console.error('Error fetching holiday settings:', err);
            return res.status(500).json({ success: false, message: 'Server error' });
        }
        res.json(results[0] || {});
    });
});

// Modified rota endpoint to accept date range with added logs
app.get('/rota-since-date', isAuthenticated, (req, res) => {
    const dbName = req.session.user.dbName;

    if (!dbName) {
        console.warn('Access denied: User not authenticated or dbName missing in session');
        return res.status(401).json({ message: 'User not authenticated' });
    }

    let startDate = req.query.startDate; // Expected format: YYYY-MM-DD
    let endDate = req.query.endDate;     // Expected format: YYYY-MM-DD

    // Validate and adjust end date to last day of month if needed
    try {
        const endDateObj = new Date(endDate);
        const lastDayOfMonth = new Date(endDateObj.getFullYear(), endDateObj.getMonth() + 1, 0);
        
        if (endDateObj.getDate() !== lastDayOfMonth.getDate()) {
            console.log(`Adjusting end date from ${endDate} to last day of month: ${lastDayOfMonth.toISOString().split('T')[0]}`);
            endDate = lastDayOfMonth.toISOString().split('T')[0];
        }
    } catch (e) {
        console.warn('Invalid end date format:', endDate);
        return res.status(400).json({ message: 'Invalid end date format' });
    }

    console.log(`[rota-since-date] Requested by DB: ${dbName}`);
    console.log(`[rota-since-date] Final date range: ${startDate} to ${endDate}`);

    if (!startDate || !endDate) {
        console.warn('Missing startDate or endDate in request');
        return res.status(400).json({ message: 'Both startDate and endDate parameters are required' });
    }

    const pool = getPool(dbName);
    const query = `
        SELECT 
            cr.name,
            cr.lastName,
            cr.day AS originalDay,
            DATE_FORMAT(
                STR_TO_DATE(
                    REGEXP_REPLACE(cr.day, '\\\\s*\\\\([^)]*\\\\)', ''),
                    '%d/%m/%Y'
                ),
                '%Y-%m-%d'
            ) AS formattedDay,
            cr.startTime,
            cr.endTime,
            e.contractHours
        FROM 
            ConfirmedRota cr
        JOIN 
            Employees e ON cr.name = e.name AND cr.lastName = e.lastName
        WHERE 
            STR_TO_DATE(
                REGEXP_REPLACE(cr.day, '\\\\s*\\\\([^)]*\\\\)', ''),
                '%d/%m/%Y'
            ) BETWEEN STR_TO_DATE(?, '%Y-%m-%d') AND STR_TO_DATE(?, '%Y-%m-%d')
        ORDER BY
            cr.name, cr.lastName, STR_TO_DATE(
                REGEXP_REPLACE(cr.day, '\\\\s*\\\\([^)]*\\\\)', ''),
                '%d/%m/%Y'
            )
    `;

    console.log('[rota-since-date] Executing SQL query with parameters:', [startDate, endDate]);

    pool.query(query, [startDate, endDate], (err, results) => {
        if (err) {
            console.error('[rota-since-date] Error fetching rota data:', err);
            return res.status(500).json({ success: false, message: 'Server error' });
        }

        // Log some details about the results
        console.log(`[rota-since-date] Retrieved ${results.length} records`);
        if (results.length > 0) {
            console.log('[rota-since-date] Date range in results:',
                results[0].formattedDay, 'to', results[results.length-1].formattedDay);
        }

        res.json(results.map(row => ({
            name: row.name,
            lastName: row.lastName,
            day: row.formattedDay, // Using the already formatted YYYY-MM-DD date
            startTime: row.startTime,
            endTime: row.endTime,
            contractHours: row.contractHours
        })));
    });
});

// Modified holiday endpoint to accept date range with added logs
app.get('/holidays-since-date', isAuthenticated, (req, res) => {
    const dbName = req.session.user.dbName;
    const { startDate, endDate } = req.query;

    if (!dbName || !startDate || !endDate) {
        return res.status(400).json({ message: 'Missing parameters' });
    }

    const pool = getPool(dbName);
    const query = `
        SELECT 
            id,
            name,
            lastName,
            startDate,
            endDate,
            days AS holidayDays,
            accepted
        FROM 
            Holiday
        WHERE 
            accepted = true
            AND (
                (STR_TO_DATE(REGEXP_REPLACE(startDate, '\\\\s*\\\\([^)]*\\\\)', ''), '%d/%m/%Y') BETWEEN ? AND ?)
                OR
                (STR_TO_DATE(REGEXP_REPLACE(endDate, '\\\\s*\\\\([^)]*\\\\)', ''), '%d/%m/%Y') BETWEEN ? AND ?)
                OR
                (STR_TO_DATE(REGEXP_REPLACE(startDate, '\\\\s*\\\\([^)]*\\\\)', ''), '%d/%m/%Y') <= ?
                    AND STR_TO_DATE(REGEXP_REPLACE(endDate, '\\\\s*\\\\([^)]*\\\\)', ''), '%d/%m/%Y') >= ?)
            )
        ORDER BY
            name, lastName, STR_TO_DATE(REGEXP_REPLACE(startDate, '\\\\s*\\\\([^)]*\\\\)', ''), '%d/%m/%Y')
    `;

    console.log('Executing holiday query with params:', [startDate, endDate, startDate, endDate, startDate, endDate]);

    pool.query(query, [startDate, endDate, startDate, endDate, startDate, endDate], (err, results) => {
        if (err) {
            console.error('Error fetching holiday data:', err);
            return res.status(500).json({ success: false, message: 'Server error' });
        }

        // Format the results to include clean dates
        const formattedResults = results.map(row => {
            const cleanStartDate = row.startDate.replace(/\s*\([^)]*\)$/, '');
            const cleanEndDate = row.endDate.replace(/\s*\([^)]*\)$/, '');
            
            return {
                id: row.id,
                name: row.name,
                lastName: row.lastName,
                startDate: cleanStartDate,
                endDate: cleanEndDate,
                holidayDays: row.holidayDays,
                accepted: row.accepted,
                formattedStartDate: formatDateToISO(cleanStartDate),
                formattedEndDate: formatDateToISO(cleanEndDate)
            };
        });

        console.log(`Found ${formattedResults.length} holiday records`);
        res.json(formattedResults);
    });
});

// Helper function to format date (if still needed)
function formatDateToISO(dateString) {
    // First remove the weekday part if present
    const cleanDate = dateString.replace(/\s*\([^)]*\)$/, '');
    const [day, month, year] = cleanDate.split('/');
    return `${year}-${month.padStart(2, '0')}-${day.padStart(2, '0')}`;
}

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