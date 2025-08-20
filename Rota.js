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

// Labor Cost Report Endpoint
app.get('/api/get-labor-values', isAuthenticated, (req, res) => {
    const dbName = req.session.user.dbName;
    if (!dbName) {
        return res.status(401).json({ success: false, message: 'User not authenticated' });
    }

    const pool = getPool(dbName);

    // Get percentages
    pool.query('SELECT FOH, BOH FROM percentages LIMIT 1', (percentagesError, percentages) => {
        if (percentagesError) {
            console.error(percentagesError);
            return res.status(500).json({ error: 'Error fetching percentage data' });
        }

        // Get labor values
        pool.query('SELECT base_hours, times FROM labor LIMIT 1', (laborError, labor) => {
            if (laborError) {
                console.error(laborError);
                return res.status(500).json({ error: 'Error fetching labor data' });
            }

            res.json({
                fohPercent: percentages[0]?.FOH || 0,
                bohPercent: percentages[0]?.BOH || 0,
                baseHours: labor[0]?.base_hours || 0,
                times: labor[0]?.times || 0
            });
        });
    });
});

app.post('/api/generate-labor-report', async (req, res) => {
    const dbName = req.session.user?.dbName;
    if (!dbName) {
        return res.status(401).json({ success: false, message: 'User not authenticated' });
    }

    const pool = getPool(dbName);
    const reportData = req.body;

    // Validate required fields
    if (!reportData.weekStart || !reportData.forecast) {
        return res.status(400).json({ error: 'Missing required fields' });
    }

    // Parse date
    const parseFormattedDate = (dateStr) => {
        try {
            const [datePart] = dateStr.split(' (');
            const [day, month, year] = datePart.split('/');
            return new Date(`${year}-${month}-${day}`);
        } catch {
            return null;
        }
    };

    const weekStartDate = parseFormattedDate(reportData.weekStart);
    if (!weekStartDate || isNaN(weekStartDate.getTime())) {
        return res.status(400).json({ error: 'Invalid week start date format. Expected dd/mm/yyyy (Monday)' });
    }

    const dbFormattedDate = weekStartDate.toISOString().split('T')[0];

    // Extract target hours from strings like "45.50 (Target: 48.00)"
    const extractTargetHours = (hoursStr) => {
        const match = hoursStr.match(/Target: (\d+\.\d+)/);
        return match ? parseFloat(match[1]) : null;
    };

    const insertQuery = `
        INSERT INTO labor_reports 
        (week_start, forecast, last_year, vs_budget, actual_hours, actual_spent, 
         target_hours, vs_target, foh_hours, boh_hours, foh_percent, boh_percent,
         target_foh_hours, target_boh_hours, labor_cost_percentage, schedule_summary, manager_comment)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `;

        const insertParams = [
        dbFormattedDate,
        reportData.forecast,
        reportData.lastYear,
        reportData.vsBudget,
        reportData.actualHours,
        reportData.actualSpent,
        reportData.targetHours,
        reportData.vsTarget,
        reportData.fohHours,
        reportData.bohHours,
        reportData.fohPercent,
        reportData.bohPercent,
        reportData.fohTarget,   // <--- no longer extracted from fohHours
        reportData.bohTarget,   // <--- same here
        parseFloat(reportData.laborCostPercentage) || null,
        reportData.scheduleSummary || null,
        reportData.comment || null
    ];


    try {
        const [insertResult] = await pool.promise().query(insertQuery, insertParams);
        console.log('Report inserted successfully.');

        const pdfBuffer = await generateReportPDF(reportData);
        console.log('PDF generated successfully.');

        await sendEmailReport(pdfBuffer, reportData.weekStart, req, pool);
        console.log('Emails sent successfully.');

        res.json({
            success: true,
            affectedRows: insertResult.affectedRows,
            insertId: insertResult.insertId
        });

    } catch (error) {
        console.error('Error generating labor report:', error);
        res.status(500).json({
            error: 'Failed to process labor report',
            details: error.message
        });
    }
});

const generateReportPDF = async (data) => {

    const fohActual = data.fohHours;
const bohActual = data.bohHours;
const fohTarget = data.fohTarget;
const bohTarget = data.bohTarget;


    const html = `
    <html>
    <head>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .report-header { text-align: center; margin-bottom: 30px; }
        .report-title { font-size: 24px; font-weight: bold; margin-bottom: 10px; }
        .report-date { color: #555; margin-bottom: 20px; }
        .section { margin-bottom: 30px; }
        .section-title { background-color: #f2f2f2; padding: 8px; font-weight: bold; border-left: 4px solid #3498db; }
        table { width: 100%; border-collapse: collapse; margin-top: 15px; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
        .metrics-table { width: 80%; margin: 0 auto; }
        .positive { color: #27ae60; }
        .negative { color: #e74c3c; }
        .comment-box { border: 1px solid #ddd; padding: 15px; margin-top: 20px; background-color: #f9f9f9; }
        .schedule-table { width: 100%; font-size: 10px; }
        .schedule-table th { background-color: #e9ecef; }
    </style>
    </head>
    <body>
        <div class="report-header">
            <div class="report-title">Weekly Labor Cost Report</div>
            <div class="report-date">Week Starting: ${data.weekStart}</div>
        </div>
        
        <div class="section">
            <div class="section-title">Key Metrics</div>
            <table class="metrics-table">
                <tr><th>Metric</th><th>Actual / Target</th></tr>
                <tr><td>Sales Forecast</td><td>${data.forecast}</td></tr>
                <tr><td>Last Year</td><td>${data.lastYear}</td></tr>
                <tr><td>Budget Variance</td><td class="${parseFloat(data.vsBudget) >= 0 ? 'positive' : 'negative'}">${data.vsBudget}</td></tr>
                <tr><td>Hours</td><td>${data.actualHours} / ${data.targetHours}</td></tr>
                <tr><td>Target Variance</td><td class="${parseFloat(data.vsTarget) <= 0 ? 'positive' : 'negative'}">${data.vsTarget}</td></tr>
                <tr><td>Total Labor Cost</td><td>${data.actualSpent}</td></tr>
                <tr><td>Labor Cost % of Forecast</td><td>${data.laborCostPercentage || 'N/A'}%</td></tr>
            </table>
        </div>
        
        <div class="section">
            <div class="section-title">Labor Distribution</div>
            <table class="metrics-table">
                <tr>
                    <th>Department</th>
                    <th>Actual / Target Hours</th>
                    <th>Percentage of Total</th>
                </tr>
                <tr>
                    <td>Front of House (FOH)</td>
                    <td>${fohActual} / ${fohTarget}</td>
                    <td>${data.fohPercent}</td>
                </tr>
                <tr>
                    <td>Back of House (BOH)</td>
                    <td>${bohActual} / ${bohTarget}</td>
                    <td>${data.bohPercent}</td>
                </tr>
            </table>
        </div>

        ${data.scheduleSummary ? `
        <div class="section">
            <div class="section-title">Schedule Summary</div>
            ${data.scheduleSummary}
        </div>` : ''}

        ${data.comment ? `
        <div class="section">
            <div class="section-title">Manager Comments</div>
            <div class="comment-box">${data.comment}</div>
        </div>` : ''}
    </body>
    </html>
    `;
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

    // Windows development executable path
    if (process.env.NODE_ENV !== 'production' && process.platform === 'win32') {
      launchOptions.executablePath = 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe';
    }
    // Heroku production executable path
    else if (process.env.NODE_ENV === 'production') {
      launchOptions.executablePath = '/app/.chrome-for-testing/chrome-linux64/chrome';
    }

    const browser = await puppeteer.launch(launchOptions);
    const page = await browser.newPage();
    await page.setContent(html, { waitUntil: 'networkidle0' });

    const pdfBuffer = await page.pdf({
      format: 'A4',
      landscape: true,  // <-- Landscape orientation
      printBackground: true // optional: print background graphics
    });

    await browser.close();
    return pdfBuffer;

  } catch (error) {
    console.error('Error generating PDF:', error);
    throw error;
  }
}

const sendEmailReport = async (pdfBuffer, weekStart, req, pool) => {
    const userEmail = req.session.user?.email;
    const dbName = req.session.user?.dbName;

    if (!userEmail || !dbName) {
        throw new Error('User email or database name missing from session.');
    }

    // Get sender's name from Employees table
    const [userResult] = await pool.promise().query(
        'SELECT name, lastName FROM Employees WHERE email = ? LIMIT 1',
        [userEmail]
    );

    if (userResult.length === 0) {
        throw new Error(`No employee found with email ${userEmail}`);
    }

    const senderName = `${userResult[0].name} ${userResult[0].lastName}`;

    // Get recipient list (e.g. all managers, or just the owner)
    const [recipientResult] = await pool.promise().query(
        'SELECT email FROM Employees WHERE position = "AM"',
    );

    const emailAddresses = recipientResult.map(row => row.email);

    // Configure transporter
    const transporter = nodemailer.createTransport({
        host: 'smtp0001.neo.space',
        port: 465,
        secure: true,
        auth: {
            user: 'no-reply@solura.uk',
            pass: 'Salvemini01@'
        }
    });

    // Send to all recipients
    const sendPromises = emailAddresses.map(email => {
        const mailOptions = {
            from: `Solura WorkForce - <no-reply@solura.uk>`,
            to: email,
            subject: `Weekly Labor Report - ${weekStart}`,
            text: `Hello,\n\nPlease find attached the weekly labor report for the week starting ${weekStart}.\n\nSent by: ${senderName}\nBranch: ${dbName}\n\nBest regards,\nSolura WorkForce`,
            attachments: [{
                filename: `labor_report_${weekStart.replace(/\//g, '-')}.pdf`,
                content: pdfBuffer
            }]
        };

        return transporter.sendMail(mailOptions)
            .then(() => console.log(`Email sent to ${email}`))
            .catch(err => {
                console.error(`Failed to send to ${email}:`, err);
                throw err;
            });
    });

    return Promise.all(sendPromises);
};

// Update submitData to include PDF generation and email sending
app.post('/submitData', isAuthenticated, async (req, res) => {
    const dbName = req.session.user.dbName;
    if (!dbName) {
        return res.status(401).json({ success: false, message: 'User not authenticated' });
    }

    const pool = getPool(dbName);
    const tableData = req.body;

    try {
        // 1. First process all database operations
        await processDatabaseOperations(pool, tableData);

        // 2. Generate PDF
        const pdfBuffer = await generatePDF(tableData);
        console.log('PDF generated successfully');

        // 3. Get recipient emails and send
        const [results] = await pool.promise().query(`SELECT email FROM Employees WHERE situation IS NULL OR situation = ''`);
        const emailAddresses = results.map(result => result.email);
            
        await sendEmail(pdfBuffer, emailAddresses);
        console.log('Emails sent successfully');

        res.status(200).send('Rota saved and emails sent successfully!');
    } catch (error) {
        console.error('Error in /submitData:', error);
        res.status(500).send('Error processing request: ' + error.message);
    }
});

// Function to generate PDF to be sent as Email
const generatePDF = async (tableData) => {
    // Define the mapping of specific RGB colors to designations
    const colorToDesignation = {
        'rgb(255, 250, 205)': 'BOH', // Light yellow
        'rgb(173, 216, 230)': 'FOH', // Light blue
    };

    // Function to sort days to start from Monday
    const sortDaysByWeek = (dates) => {
        const weekOrder = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday'];
        return dates.sort((a, b) => {
            const dayA = a.match(/\((\w+)\)$/)?.[1];
            const dayB = b.match(/\((\w+)\)$/)?.[1];
            return weekOrder.indexOf(dayA) - weekOrder.indexOf(dayB);
        });
    };

    // Extract unique dates from tableData and sort them by week starting on Monday
    let weekDates = [...new Set(tableData.map(row => row.day))];
    weekDates = sortDaysByWeek(weekDates);

    // Group tableData by role and adjust designation based on color
    const groupedData = tableData.reduce((acc, row) => {
        const match = row.day.match(/\((\w+)\)$/);
        const dayOfWeek = match ? match[1] : null;

        if (!dayOfWeek) {
            console.warn(`Invalid day format: ${row.day}`);
            return acc;
        }

        // Determine the designation based on color
        const adjustedDesignation = colorToDesignation[row.color] || row.designation;

        if (!acc[adjustedDesignation]) {
            acc[adjustedDesignation] = {};
        }

        if (!acc[adjustedDesignation][row.name]) {
            acc[adjustedDesignation][row.name] = {
                lastName: row.lastName,
                days: {},
            };
        }

        if (!acc[adjustedDesignation][row.name].days[row.day]) {
            acc[adjustedDesignation][row.name].days[row.day] = [];
        }

        // Format time to `hh:mm`
        const formatTime = (time) => {
            const [hours, minutes] = time.split(':');
            return `${hours.padStart(2, '0')}:${minutes.padStart(2, '0')}`;
        };

        acc[adjustedDesignation][row.name].days[row.day].push({
            startTime: formatTime(row.startTime),
            endTime: formatTime(row.endTime),
        });

        return acc;
    }, {});

    // Generate HTML content
    const htmlContent = `
    <html>
    <head>
    <style>
        table { width: 100%; border-collapse: collapse; }
        th, td { border: 1px solid #ddd; text-transform: uppercase; }
        th { background-color: #f2f2f2; text-align: center; padding: 8px; }
        td:not(:nth-child(1)):not(:nth-child(2)) { text-align: center; }
        td:nth-child(1), td:nth-child(2) { padding: 8px; }
        .role-header { background-color: #add8e6; text-align: center; font-weight: bold; padding: 10px; }
    </style>
    </head>
    <body>
    ${Object.entries(groupedData).map(([role, employees]) => `
        <div>
            <div class="role-header">${role}</div>
            <table>
                <thead>
                    <tr>
                        <th>NAME</th>
                        <th>LASTNAME</th>
                        ${weekDates.map(date => `<th>${date}</th>`).join('')}
                    </tr>
                </thead>
                <tbody>
                    ${Object.entries(employees).map(([name, data]) => `
                        <tr>
                            <td>${name}</td>
                            <td>${data.lastName}</td>
                            ${weekDates.map(day => `
                                <td>
                                    ${(data.days[day] || []).map(shift => `
                                        ${shift.startTime} - ${shift.endTime}
                                    `).join('<br>') || ''}
                                </td>
                            `).join('')}
                        </tr>
                    `).join('')}
                </tbody>
            </table>
        </div>
    `).join('')}
    </body>
    </html>
    `;

    // Generate PDF with landscape orientation
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
        
        const pdfBuffer = await page.pdf({
            format: 'A4',
            landscape: true,
            printBackground: true
        });

        await browser.close();
        return pdfBuffer;
    } catch (error) {
        console.error("PDF Generation Error:", error);
        throw error;
    }
};

// Helper function to process database operations
async function processDatabaseOperations(pool, tableData) {
    const updateQuery = `UPDATE rota SET wage = ?, designation = ?, color = ? 
                       WHERE name = ? AND lastName = ? AND day = ? AND startTime = ? AND endTime = ?`;
    const insertQuery = `INSERT INTO rota (id, name, lastName, wage, day, startTime, endTime, designation, color) 
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`;

    for (const row of tableData) {
        const { name, lastName, wage, designation, day, startTime, endTime, color } = row;

        // Check if record exists
        const [existing] = await pool.promise().query(
            'SELECT id FROM rota WHERE name = ? AND lastName = ? AND day = ? AND startTime = ? AND endTime = ?',
            [name, lastName, day, startTime, endTime]
        );

        if (existing.length > 0) {
            await pool.promise().query(updateQuery, 
                [wage, designation, color, name, lastName, day, startTime, endTime]);
            console.log(`Updated: ${name} ${lastName} (${day})`);
        } else {
            const newId = await generateUniqueId(pool);
            await pool.promise().query(insertQuery,
                [newId, name, lastName, wage, day, startTime, endTime, designation, color]);
            console.log(`Inserted: ${name} ${lastName} (${day})`);
        }
    }
}

// Helper function to generate unique ID
async function generateUniqueId(pool) {
    let id;
    do {
        id = crypto.randomBytes(4).toString('hex');
        const [existing] = await pool.promise().query('SELECT id FROM rota WHERE id = ?', [id]);
        if (existing.length === 0) return id;
    } while (true);
}

// Modified sendEmail function (make it return a promise)
const sendEmail = (pdfBuffer, emailAddresses) => {
    const transporter = nodemailer.createTransport({
        host: 'smtp0001.neo.space',
        port: 465,
        secure: true,
        auth: {
            user: 'no-reply@solura.uk',
            pass: 'Salvemini01@'
        }
    });

    const sendPromises = emailAddresses.map(email => {
        const mailOptions = {
            from: 'Solura WorkForce <no-reply@solura.uk>',
            to: email,
            subject: 'Your Weekly Work Schedule',
            text: `Hello,\n\nAttached is your rota for the upcoming week.\n\nBest regards,\nManagement Team`,
            attachments: [{
                filename: 'Weekly_Rota.pdf',
                content: pdfBuffer
            }]
        };

        return transporter.sendMail(mailOptions)
            .then(() => console.log(`Email sent to ${email}`))
            .catch(err => {
                console.error(`Failed to send to ${email}:`, err);
                throw err; // Rethrow to catch in the main flow
            });
    });

    return Promise.all(sendPromises);
};
// Function to insert weekly cost
app.post('/api/updateWeeklyCost', (req, res) => {
    const dbName = req.session.user.dbName;
    if (!dbName) {
        return res.status(401).json({ success: false, message: 'User not authenticated' });
    }

    const pool = getPool(dbName);
    const { weekly_cost_before, week_start, hours } = req.body; // Added hours parameter

    // Enhanced validation
    if (typeof weekly_cost_before !== 'number' || isNaN(weekly_cost_before)) {
        return res.status(400).json({ error: 'Invalid weekly cost value' });
    }

    // Validate hours (should be a positive number)
    if (typeof hours !== 'number' || isNaN(hours) || hours < 0) {
        return res.status(400).json({ error: 'Invalid hours value' });
    }

    // Parse the formatted date
    function parseFormattedDate(dateStr) {
        try {
            const [datePart] = dateStr.split(' (');
            const [day, month, year] = datePart.split('/');
            return new Date(`${year}-${month}-${day}`);
        } catch (e) {
            return null;
        }
    }

    const weekStartDate = parseFormattedDate(week_start);
    if (!weekStartDate || isNaN(weekStartDate.getTime())) {
        return res.status(400).json({ error: 'Invalid week start date format. Expected dd/mm/yyyy (Monday)' });
    }

    // Format for database (YYYY-MM-DD)
    const dbFormattedDate = weekStartDate.toISOString().split('T')[0];

    console.log('Attempting to insert:', {
        cost: weekly_cost_before,
        hours: hours, // Added hours to log
        date: dbFormattedDate
    });

    const query = `
        INSERT INTO Data (Weekly_Cost_Before, Weekly_Cost_After, WeekStart, Hours)
        VALUES (?, ?, ?, ?)
        ON DUPLICATE KEY UPDATE
            Weekly_Cost_Before = VALUES(Weekly_Cost_Before),
            WeekStart = VALUES(WeekStart),
            Hours = VALUES(Hours)
    `;

    pool.query(query, [weekly_cost_before, weekly_cost_before, dbFormattedDate, hours], (err, result) => {
        if (err) {
            console.error('Database error details:', {
                code: err.code,
                sqlMessage: err.sqlMessage,
                sql: err.sql
            });
            return res.status(500).json({ 
                error: 'Internal server error',
                details: err.message
            });
        }

        console.log('Insert result:', result);
        res.json({ 
            success: true,
            affectedRows: result.affectedRows,
            insertId: result.insertId
        });
    });
});

// Helper function to validate date
function isValidDate(dateString) {
    return !isNaN(Date.parse(dateString));
}

// Function to generate a unique 16-digit ID
function generateUniqueId() {
    return Math.floor(1000000000000000 + Math.random() * 9000000000000000).toString();
}

// Function to retrieve Taxes
app.get('/get-tax-holiday-percentages', (req, res) => {
    const dbName = req.session.user.dbName;
    const pool = getPool(dbName);

    pool.query(
        `SELECT tax, holiday, pension FROM rota_tax LIMIT 1`,
        (err, results) => {
            if (err) {
                console.error('Error fetching tax/holiday percentages:', err);
                return res.status(500).json({ 
                    success: false, 
                    message: 'Failed to fetch tax and holiday percentages' 
                });
            }

            if (results.length === 0) {
                // Return default values if no record found
                return res.json({ 
                    success: true,
                    tax: 0,
                    holiday: 0,
                    pension: 0
                });
            }

            res.json({ 
                success: true,
                tax: results[0].tax || 0,
                holiday: results[0].holiday || 0,
                pension: results[0].pension || 0
            });
        }
    );
});

// Add a new endpoint to get employee pension status
app.get('/get-employees-pension-status', (req, res) => {
    const dbName = req.session.user.dbName;
    const pool = getPool(dbName);

    pool.query(
        `SELECT name, lastName, pension_payer FROM Employees`,
        (err, results) => {
            if (err) {
                console.error('Error fetching employee pension status:', err);
                return res.status(500).json({ 
                    success: false, 
                    message: 'Failed to fetch employee pension status' 
                });
            }

            res.json({ 
                success: true,
                data: results
            });
        }
    );
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

// Helper function to format date for SQL query
function formatDateForQuery(date) {
    const dd = String(date.getDate()).padStart(2, '0');
    const mm = String(date.getMonth() + 1).padStart(2, '0');
    const yyyy = date.getFullYear();
    return `${dd}/${mm}/${yyyy}`;
}

// Helper function to format date as dd/mm/yyyy
function formatDate(date) {
    const day = String(date.getDate()).padStart(2, '0');
    const month = String(date.getMonth() + 1).padStart(2, '0');
    const year = date.getFullYear();
    return `${day}/${month}/${year}`;
}

// Function to Save new Data into db
app.post('/saveData', isAuthenticated, (req, res) => {
    const dbName = req.session.user.dbName;
    if (!dbName) {
        return res.status(401).json({ success: false, message: 'User not authenticated' });
    }

    const pool = getPool(dbName);
    const tableData = req.body;
    const operationMessages = [];

    // Validate input data
    if (!tableData || !Array.isArray(tableData)) {
        return res.status(400).json({ success: false, message: 'Invalid data format' });
    }

    // Get connection from pool
    pool.getConnection((err, connection) => {
        if (err) {
            console.error('Error getting database connection:', err);
            return res.status(500).send('Database connection error');
        }

        // Begin transaction
        connection.beginTransaction((beginErr) => {
            if (beginErr) {
                connection.release();
                console.error('Error beginning transaction:', beginErr);
                return res.status(500).send('Transaction error');
            }

            // Extract unique days
            const uniqueDays = [...new Set(tableData.map(row => row.day))];

            // 1. Delete existing data if needed
            const deleteData = (callback) => {
                if (uniqueDays.length === 0) {
                    operationMessages.push('No days to delete.');
                    return callback(null);
                }

                const deleteQuery = `DELETE FROM rota WHERE day IN (?)`;
                connection.query(deleteQuery, [uniqueDays], (deleteErr) => {
                    if (deleteErr) {
                        return callback(deleteErr);
                    }
                    operationMessages.push(`Deleted existing data for days: ${uniqueDays.join(', ')}`);
                    callback(null);
                });
            };

            // 2. Insert new data
            const insertData = (callback) => {
                const insertQuery = `
                    INSERT INTO rota (id, name, lastName, wage, day, startTime, endTime, designation, color) 
                    VALUES ?
                `;

                // Generate all values with unique IDs
                const generateValues = (valuesCallback) => {
                    const values = [];
                    let processed = 0;

                    const checkNext = (index) => {
                        if (index >= tableData.length) {
                            return valuesCallback(null, values);
                        }

                        const row = tableData[index];
                        let newId = generateUniqueId();

                        const checkId = (id) => {
                            connection.query(
                                'SELECT id FROM rota WHERE id = ?',
                                [id],
                                (checkErr, checkResult) => {
                                    if (checkErr) {
                                        return valuesCallback(checkErr);
                                    }

                                    if (checkResult.length > 0) {
                                        // ID exists, generate new one
                                        newId = generateUniqueId();
                                        return checkId(newId);
                                    }

                                    // ID is unique, add to values
                                    values.push([
                                        newId,
                                        row.name,
                                        row.lastName,
                                        row.wage,
                                        row.day,
                                        row.startTime,
                                        row.endTime,
                                        row.designation,
                                        row.color
                                    ]);

                                    operationMessages.push(`Inserted: ${row.name} ${row.lastName} (${row.day})`);
                                    checkNext(index + 1);
                                }
                            );
                        };

                        checkId(newId);
                    };

                    checkNext(0);
                };

                generateValues((genErr, values) => {
                    if (genErr) {
                        return callback(genErr);
                    }

                    if (values.length === 0) {
                        return callback(null);
                    }

                    connection.query(insertQuery, [values], (insertErr) => {
                        callback(insertErr);
                    });
                });
            };
           
            // Execute operations in sequence
            deleteData((delErr) => {
                if (delErr) {
                    return rollback(connection, delErr);
                }

                insertData((insErr) => {
                    if (insErr) {
                        return rollback(connection, insErr);
                    }

                    // Commit transaction
                    connection.commit((commitErr) => {
                        if (commitErr) {
                            return rollback(connection, commitErr);
                        }

                        connection.release();
                        res.status(200).send(operationMessages.join('\n'));
                    });
                });
            });
        });
    });
});

// Helper function for transaction rollback
function rollback(connection, error) {
    connection.rollback(() => {
        connection.release();
        console.error('Transaction error:', error);
        res.status(500).send('Error saving data');
    });
}

// Function to Delete time frame
app.delete('/removeDayData', isAuthenticated, (req, res) => {
    const dbName = req.session.user.dbName; // Get the database name from the session

    if (!dbName) {
        return res.status(401).json({ success: false, message: 'User not authenticated' });
    }

    const pool = getPool(dbName); // Get the correct connection pool

    const { name, lastName, fullDay } = req.body;
    console.log('Day: ', fullDay,
        'Name: ', name,
        'Lastname: ', lastName
    );

    // SQL queries to delete from the rota, ConfirmedRota, and ConfirmedRota2 tables
    const deleteRotaSql = `
        DELETE FROM rota
        WHERE name = ? AND lastName = ? AND day = ?`;

    const deleteConfirmedRotaSql = `
        DELETE FROM ConfirmedRota
        WHERE name = ? AND lastName = ? AND day = ?`;

    const deleteConfirmedRota2Sql = `
        DELETE FROM ConfirmedRota2
        WHERE name = ? AND lastName = ? AND day = ?`;

    // Start a transaction to ensure all deletes are performed together
    pool.getConnection((err, connection) => {
        if (err) {
            console.error('Database connection error:', err);
            return res.status(500).send('Failed to connect to the database.');
        }

        connection.beginTransaction((err) => {
            if (err) {
                console.error('Error starting transaction:', err);
                return connection.release();
            }

            // Perform the delete operations in sequence and track whether any rows are deleted
            let deletedRota = false;
            let deletedConfirmedRota = false;
            let deletedConfirmedRota2 = false;

            connection.query(deleteRotaSql, [name, lastName, fullDay], (err, result) => {
                if (err) {
                    return connection.rollback(() => {
                        console.error('Error deleting from rota:', err);
                        connection.release();
                        return res.status(500).send('Failed to remove data from rota.');
                    });
                }
                if (result.affectedRows > 0) deletedRota = true;

                connection.query(deleteConfirmedRotaSql, [name, lastName, fullDay], (err, result) => {
                    if (err) {
                        return connection.rollback(() => {
                            console.error('Error deleting from ConfirmedRota:', err);
                            connection.release();
                            return res.status(500).send('Failed to remove data from ConfirmedRota.');
                        });
                    }
                    if (result.affectedRows > 0) deletedConfirmedRota = true;

                    connection.query(deleteConfirmedRota2Sql, [name, lastName, fullDay], (err, result) => {
                        if (err) {
                            return connection.rollback(() => {
                                console.error('Error deleting from ConfirmedRota2:', err);
                                connection.release();
                                return res.status(500).send('Failed to remove data from ConfirmedRota2.');
                            });
                        }
                        if (result.affectedRows > 0) deletedConfirmedRota2 = true;

                        // Commit the transaction if all deletions were successful
                        connection.commit((err) => {
                            if (err) {
                                return connection.rollback(() => {
                                    console.error('Error committing transaction:', err);
                                    connection.release();
                                    return res.status(500).send('Failed to commit transaction.');
                                });
                            }

                            // Send the response based on whether any records were deleted
                            if (deletedRota || deletedConfirmedRota || deletedConfirmedRota2) {
                                console.log('Data removed successfully from one or more tables.');
                                connection.release();
                                res.send('Data removed successfully.');
                            } else {
                                console.log('No records found for deletion.');
                                connection.release();
                                res.status(404).send('No matching records found to delete.');
                            }
                        });
                    });
                });
            });
        });
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

    // SQL query to fetch data for the specified days
    const query = `
        SELECT name, lastName, wage, day, startTime, endTime, designation, color
        FROM rota
        WHERE day IN (?)`;

    pool.query(query, [weekDates], (err, results) => {
        if (err) {
            console.error('Error fetching employee data:', err);
            return res.status(500).send('Error fetching employee data');
        }

        // Group results by day
        const groupedData = {};
        results.forEach(row => {
            if (!groupedData[row.day]) groupedData[row.day] = [];
            groupedData[row.day].push(row);
        });

        res.json(groupedData);
    });
});

// Route to handle fetching employee data
app.get('/employees', isAuthenticated, (req, res) => {
    const dbName = req.session.user.dbName; // Get the database name from the session

    if (!dbName) {
        return res.status(401).json({ success: false, message: 'User not authenticated' });
    }

    const pool = getPool(dbName); // Get the correct connection pool

    pool.query(`SELECT name, lastName, wage, designation, position FROM Employees WHERE situation IS NULL OR situation = ''`, (err, results) => {
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

// Route to handle fetching holidays and unpaid leave data
app.get('/holidays', isAuthenticated, (req, res) => {
    const dbName = req.session.user.dbName;

    if (!dbName) {
        return res.status(401).json({ success: false, message: 'User not authenticated' });
    }

    const pool = getPool(dbName);

    // Fix the SQL query (removed trailing comma)
    const query = `
        SELECT 
            name, 
            lastname, 
            startDate, 
            endDate,
            accepted,
            days
        FROM Holiday
        WHERE accepted IN ("true", "unpaid")
        ORDER BY startDate DESC;
    `;

    // Set response headers for streaming
    res.setHeader('Content-Type', 'application/json');
    res.write('['); // Start of JSON array

    let firstRow = true;

    pool.query(query)
        .on('result', (row) => {
            // Add comma before each row except the first
            if (!firstRow) {
                res.write(',');
            } else {
                firstRow = false;
            }

            // Transform the row
            const transformedRow = {
                ...row,
                type: row.accepted === 'true' ? 'holiday' : 'unpaid leave',
                status: row.accepted === 'true' ? 'approved' : 'unpaid'
            };

            res.write(JSON.stringify(transformedRow));
        })
        .on('end', () => {
            res.end(']'); // End of JSON array
        })
        .on('error', (err) => {
            console.error('Database query failed:', err);
            if (!res.headersSent) {
                res.status(500).json({ 
                    success: false,
                    error: 'Database query failed',
                    message: err.message 
                });
            }
        });
});

// Submit new holiday or unpaid leave
app.post('/submit-holiday', (req, res) => {
    const dbName = req.session.user?.dbName;
    const userEmail = req.session.user?.email;

    if (!dbName || !userEmail) {
        return res.status(401).json({ success: false, message: 'User not authenticated' });
    }

    const pool = getPool(dbName);
    const { name, lastName, startDate, endDate, requestType } = req.body;

    const start = new Date(startDate);
    const end = new Date(endDate);
    const days = Math.ceil((end - start) / (1000 * 60 * 60 * 24)) + 1;

    const formatDate = (date) => {
        const day = date.getDate().toString().padStart(2, '0');
        const month = (date.getMonth() + 1).toString().padStart(2, '0');
        const year = date.getFullYear();
        const dayName = date.toLocaleDateString('en-US', { weekday: 'long' });
        return `${day}/${month}/${year} (${dayName})`;
    };

    const formattedStartDate = formatDate(start);
    const formattedEndDate = formatDate(end);
    const currentDate = formatDate(new Date());
    const acceptedValue = requestType === 'holiday' ? 'true' : 'unpaid';

    // 1. First fetch name and lastName of the logged-in user from Employees
    const fetchUserSql = `SELECT name, lastName FROM Employees WHERE email = ? LIMIT 1`;
    pool.query(fetchUserSql, [userEmail], (userErr, userResults) => {
        if (userErr) {
            console.error('Error fetching user info:', userErr);
            return res.status(500).json({ success: false, message: 'Error fetching user info' });
        }

        if (userResults.length === 0) {
            return res.status(404).json({ success: false, message: 'User not found in Employees table' });
        }

        const whoName = userResults[0].name;
        const whoLastName = userResults[0].lastName;
        const who = `${whoName} ${whoLastName}`;

        // 2. Insert holiday request
        const insertHolidaySql = `
            INSERT INTO Holiday (name, lastName, startDate, endDate, requestDate, days, accepted, who)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)`;
        const insertValues = [
            name, lastName, formattedStartDate, formattedEndDate,
            currentDate, days, acceptedValue, who
        ];

        pool.query(insertHolidaySql, insertValues, (insertErr, insertResult) => {
            if (insertErr) {
                console.error('Error inserting holiday:', insertErr);
                return res.status(500).json({
                    success: false,
                    message: insertErr.message || 'Failed to insert holiday request'
                });
            }

            // 3. Update holiday balance only if it's a paid holiday
            if (requestType !== 'holiday') {
                return res.json({
                    success: true,
                    id: insertResult.insertId,
                    name,
                    lastName,
                    startDate: formattedStartDate,
                    endDate: formattedEndDate,
                    requestDate: currentDate,
                    days,
                    accepted: acceptedValue,
                    daysDeducted: 0
                });
            }

            const updateHolidaySql = `
                UPDATE Employees SET TotalHoliday = TotalHoliday - ?
                WHERE name = ? AND lastName = ?`;
            const updateValues = [days, name, lastName];

            pool.query(updateHolidaySql, updateValues, (updateErr) => {
                if (updateErr) {
                    console.error('Error updating TotalHoliday:', updateErr);
                    return res.status(500).json({
                        success: false,
                        message: updateErr.message || 'Failed to update holiday balance'
                    });
                }

                res.json({
                    success: true,
                    id: insertResult.insertId,
                    name,
                    lastName,
                    startDate: formattedStartDate,
                    endDate: formattedEndDate,
                    requestDate: currentDate,
                    days,
                    accepted: acceptedValue,
                    daysDeducted: days
                });
            });
        });
    });
});

// Get all employees for dropdown
app.get('/employees-holiday', (req, res) => {
    const dbName = req.session.user.dbName;
    
    if (!dbName) {
        return res.status(401).json({ success: false, message: 'User not authenticated' });
    }

    const pool = getPool(dbName);
    pool.query(
        'SELECT name, lastName, Accrued, TotalHoliday FROM Employees',
        (err, result) => {
            if (err) {
                console.error(err.message);
                return res.status(500).json({ error: 'Server error' });
            }
            res.json(result.map(row => ({
                name: row.name,
                lastname: row.lastname || row.lastName, // Handle both casing variations
                Accrued: row.Accrued,
                TotalHoliday: row.TotalHoliday
            })));
        }
    );
});

// Get holidays and unpaid leave for a specific week
app.get('/holidays-by-week', (req, res) => {
    const dbName = req.session.user.dbName;
    const { start, end } = req.query;
    
    if (!dbName) {
        return res.status(401).json({ success: false, message: 'User not authenticated' });
    }

    const pool = getPool(dbName);
    
    const query = `
    SELECT name, lastName, startDate, endDate, accepted
    FROM Holiday 
    WHERE accepted IN ('true', 'unpaid')
    AND STR_TO_DATE(SUBSTRING_INDEX(startDate, ' (', 1), '%d/%m/%Y') <= STR_TO_DATE(?, '%d/%m/%Y')
    AND STR_TO_DATE(SUBSTRING_INDEX(endDate, ' (', 1), '%d/%m/%Y') >= STR_TO_DATE(?, '%d/%m/%Y')
`;
    
    pool.query(query, [
        end, start,    // For first condition
        start, start,  // For second condition
        start, end,    // For third condition
        start, end     // For fourth condition
    ], (err, result) => {
        if (err) {
            console.error('Database error:', err);
            return res.status(500).json({ 
                success: false, 
                error: 'Database error',
                message: err.message 
            });
        }
        // Process results to include type information
        const processedResults = result.map(record => {
            return {
                ...record,
                type: record.accepted === 'true' ? 'holiday' : 'unpaid',
                // Ensure we return the original start/end dates
                startDate: record.startDate,
                endDate: record.endDate
            };
        });
        res.json(processedResults);
    });
});

// Route to serve the Rota.html file
app.get('/', isAuthenticated, (req, res) => {
    if (req.session.user.role === 'admin' || req.session.user.role === 'AM') {
        res.sendFile(path.join(__dirname, 'Rota.html'));
    } else {
        res.status(403).json({ error: 'Access denied' });
    }
});

module.exports = app; // Export the entire Express application