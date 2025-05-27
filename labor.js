// Import required modules
const express = require('express');
const mysql = require('mysql2');
const nodemailer = require('nodemailer');
const server = require('./server.js');
const path = require('path');
const bodyParser = require('body-parser');
const { getPool, mainPool } = require('./db.js'); // Import the connection pool functions
const { sessionMiddleware, isAuthenticated, isAM } = require('./sessionConfig'); // Adjust the path as needed
const app = express();
// Middleware
app.use(sessionMiddleware);
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
const puppeteer = require('puppeteer');

app.post('/api/generate-rota-pdf', isAuthenticated, async (req, res) => {
    const { htmlContent, dateRange } = req.body;
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
    
            // Windows development
            if (process.env.NODE_ENV !== 'production' && process.platform === 'win32') {
                launchOptions.executablePath = 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe';
            }
            // Heroku production - let Puppeteer handle it automatically
            else if (process.env.NODE_ENV === 'production') {
                // Use Puppeteer's bundled Chrome
                launchOptions.executablePath = '/app/.chrome-for-testing/chrome-linux64/chrome';
            }
    
            const browser = await puppeteer.launch(launchOptions);
            const page = await browser.newPage();
            await page.setContent(htmlContent, { waitUntil: 'networkidle0' });

        // Replace waitForTimeout with traditional promise-based timeout
        await new Promise(resolve => setTimeout(resolve, 1000));

        const pdfBuffer = await page.pdf({
            format: 'A4',
            landscape: true,
            printBackground: true,
            margin: {
                top: '20mm',
                right: '10mm',
                bottom: '20mm',
                left: '10mm'
            },
            displayHeaderFooter: true,
            headerTemplate: '<div style="font-size: 10px; width: 100%; text-align: center;">Solura Rota Report - ${weekRange}</div>',
            footerTemplate: '<div style="font-size: 8px; width: 100%; text-align: center; padding: 5px;">Page <span class="pageNumber"></span> of <span class="totalPages"></span></div>'
        });

        res.setHeader('Content-Type', 'application/pdf');
        res.setHeader('Content-Disposition', `attachment; filename="Rota_Report_${dateRange.replace(/ /g, '_')}.pdf"`);
        res.end(pdfBuffer);

    } catch (error) {
        console.error('PDF Generation Error:', error);
        if (!res.headersSent) {
            res.status(500).json({ error: 'Failed to generate PDF: ' + error.message });
        }
    } finally {
        if (browser) await browser.close();
    }
});

app.post('/api/rota-data', (req, res) => {
    const dbName = req.session.user.dbName;
    const pool = getPool(dbName);
    const { startDate, endDate } = req.body;
    console.log(startDate, endDate);
    if (!startDate || !endDate) {
        return res.status(400).json({ error: 'Start date and end date are required' });
    }

    // First check if the dates are in the future
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    const requestEndDate = new Date(endDate);
    
    if (requestEndDate > today) {
        // For future dates, return empty rota but with tax info
        const taxQuery = `SELECT holiday, tax, pension FROM rota_tax LIMIT 1`;
        pool.query(taxQuery, (taxErr, taxResults) => {
            if (taxErr) {
                console.error('Error fetching tax data:', taxErr);
                return res.status(500).json({ 
                    error: 'Failed to fetch tax data',
                    details: taxErr.message
                });
            }

            const taxInfo = taxResults[0] || { holiday: 0, tax: 0, pension: 0 };
            
            return res.json({ 
                rota: [], // Empty array for future dates
                taxInfo: {
                    holiday: taxInfo.holiday,
                    tax: taxInfo.tax,
                    pension: taxInfo.pension
                },
                isFutureDate: true
            });
        });
        return;
    }

    // Rest of your existing code for past/present dates...
    const extractDatePart = (formattedDate) => {
        return formattedDate.split(' (')[0];
    };

    const generateDateRange = (start, end) => {
        const startDate = new Date(extractDatePart(start).split('/').reverse().join('-'));
        const endDate = new Date(extractDatePart(end).split('/').reverse().join('-'));
        const dates = [];
        
        let currentDate = new Date(startDate);
        while (currentDate <= endDate) {
            const day = String(currentDate.getDate()).padStart(2, '0');
            const month = String(currentDate.getMonth() + 1).padStart(2, '0');
            const year = currentDate.getFullYear();
            const dayName = currentDate.toLocaleDateString('en-US', { weekday: 'long' });
            dates.push(`${day}/${month}/${year} (${dayName})`);
            currentDate.setDate(currentDate.getDate() + 1);
        }
        return dates;
    };
    const dateRange = generateDateRange(startDate, endDate);

    const taxQuery = `SELECT holiday, tax, pension FROM rota_tax LIMIT 1`;
    pool.query(taxQuery, (taxErr, taxResults) => {
        if (taxErr) {
            console.error('Error fetching tax data:', taxErr);
            return res.status(500).json({ 
                error: 'Failed to fetch tax data',
                details: taxErr.message
            });
        }

        const taxInfo = taxResults[0] || { holiday: 0, tax: 0, pension: 0 };

        const rotaQuery = `
            SELECT 
                cr.day,
                cr.name,
                cr.lastName,
                cr.designation,
                cr.startTime,
                cr.endTime,
                IFNULL(e.wage, 0) AS wage
            FROM 
                ConfirmedRota cr
            LEFT JOIN 
                Employees e ON cr.name = e.name AND cr.lastName = e.lastName
            WHERE 
                cr.day IN (?)
            ORDER BY 
                cr.day, cr.name, cr.lastName
        `;

        
        pool.query(rotaQuery, [dateRange], (err, results) => {
            if (err) {
                console.error('Database error:', err);
                return res.status(500).json({ 
                    error: 'Failed to fetch rota data',
                    details: err.message
                });
            }

            const filteredResults = results.filter(shift => 
                shift.name && shift.lastName && shift.day
            );

            if (filteredResults.length === 0) {
                return res.status(200).json({ 
                    rota: [],
                    taxInfo: {
                        holiday: taxInfo.holiday,
                        tax: taxInfo.tax,
                        pension: taxInfo.pension
                    },
                    isEmpty: true
                });
            }

            res.json({ 
                rota: filteredResults,
                taxInfo: {
                    holiday: taxInfo.holiday,
                    tax: taxInfo.tax,
                    pension: taxInfo.pension
                }
            });
        });
    });
});


app.get('/api/getWeeklySalesComparison', (req, res) => {
    let { startDate } = req.query;
    console.log('Received startDate:', startDate); // Debug what's actually received
    const dbName = req.session.user.dbName;
    
    if (!dbName) {
        return res.status(401).json({ error: 'User not authenticated' });
    }
    // Ensure startDate is in yyyy-mm-dd format
    const parsedDate = new Date(startDate);
    if (isNaN(parsedDate)) {
        return res.status(400).json({ error: 'Invalid startDate format' });
    }
    const pool = getPool(dbName);
    // Format to yyyy-mm-dd
    const yyyy = parsedDate.getFullYear();
    const mm = String(parsedDate.getMonth() + 1).padStart(2, '0');
    const dd = String(parsedDate.getDate()).padStart(2, '0');
    startDate = `${yyyy}-${mm}-${dd}`;
    // Query for forecasted sales from labor_reports
    const forecastQuery = `
        SELECT forecast 
        FROM labor_reports 
        WHERE week_start = ?
    `;

    // Query for actual sales from cash_reports for the week
    const actualQuery = `
        SELECT 
            SUM(zreport) as zreport,
            SUM(onaccount) as onaccount
        FROM cash_reports
        WHERE STR_TO_DATE(SUBSTRING_INDEX(day, ' ', -1), '%d/%m/%Y') 
        BETWEEN ? AND DATE_ADD(?, INTERVAL 6 DAY)
    `;

    pool.query(forecastQuery, [startDate], (forecastErr, forecastResults) => {
        if (forecastErr) {
            console.error('Forecast query error:', forecastErr);
            return res.status(500).json({ error: 'Database error' });
        }

        pool.query(actualQuery, [startDate, startDate], (actualErr, actualResults) => {
            if (actualErr) {
                console.error('Actual sales query error:', actualErr);
                return res.status(500).json({ error: 'Database error' });
            }

            const forecast = forecastResults[0] ? parseFloat(forecastResults[0].forecast) || 0 : 0;
            console.log(forecast);
            const actual = {
                zreport: actualResults[0] ? parseFloat(actualResults[0].zreport) || 0 : 0,
                onaccount: actualResults[0] ? parseFloat(actualResults[0].onaccount) || 0 : 0
            };

            res.json({
                forecast,
                actual
            });
        });
    });
});

app.get('/api/getWeeklyForecast', (req, res) => {
    const dbName = req.session.user.dbName;
    const pool = getPool(dbName);
    const { startDate } = req.query;

    // Convert the JavaScript Date string to yyyy-mm-dd format
    const formattedDate = new Date(startDate).toISOString().split('T')[0];

    const query = `
        SELECT Weekly_Cost_Before, Hours 
        FROM Data 
        WHERE WeekStart = ? 
        `;

    pool.query(query, [formattedDate], (err, results) => {
        if (err) {
            console.error('Forecast query error:', err);
            return res.status(500).json({ error: 'Internal server error' });
        }

        if (!results || results.length === 0) {
            return res.json({ Weekly_Cost_Before: 0, Hours: 0 });
        }

        res.json(results[0]);
    });
});

// Helper function to format date as dd/mm/yyyy
function formatDateForDB(date) {
    const day = String(date.getDate()).padStart(2, '0');
    const month = String(date.getMonth() + 1).padStart(2, '0');
    const year = date.getFullYear();
    return `${day}/${month}/${year}`;
}

// Add these helper functions to your server code
function formatDayWithName(date) {
    const day = String(date.getDate()).padStart(2, '0');
    const month = String(date.getMonth() + 1).padStart(2, '0');
    const year = date.getFullYear();
    const dayName = date.toLocaleDateString('en-US', { weekday: 'long' });
    return `${day}/${month}/${year} (${dayName})`;
}

function calculateHours(startTime, endTime) {
    const start = parseTime(startTime);
    const end = parseTime(endTime);
    
    if (end < start) {
        end.setDate(end.getDate() + 1);
    }
    
    return (end - start) / (1000 * 60 * 60);
}

function parseTime(timeString) {
    const [hours, minutes] = timeString.split(':').map(Number);
    const date = new Date();
    date.setHours(hours, minutes || 0, 0, 0);
    return date;
}

// Route to serve HTML files
app.get('/', isAuthenticated, isAM, (req, res) => {
    res.sendFile(path.join(__dirname, 'labor.html'));
});
module.exports = app; // Export the entire Express application