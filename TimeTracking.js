const express = require('express');
const path = require('path');
const puppeteer = require('puppeteer');
const { getPool } = require('./db.js');
const { sessionMiddleware, isAuthenticated, isAM } = require('./sessionConfig');

const app = express();

// Middleware
app.use(sessionMiddleware);
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Helper function to parse date from "dd/mm/yyyy (Dayname)" format
function parseCustomDate(dateString) {
    if (!dateString) return null;
    
    // Handle "dd/mm/yyyy (Dayname)" format
    const match = dateString.match(/^(\d{2})\/(\d{2})\/(\d{4}) \(([^)]+)\)$/);
    if (match) {
        const [, day, month, year] = match;
        return new Date(year, month - 1, day);
    }
    
    // Fallback for other formats
    return new Date(dateString);
}

// Helper function to format date for display
function formatDateForDisplay(date) {
    const days = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];
    const dd = String(date.getDate()).padStart(2, '0');
    const mm = String(date.getMonth() + 1).padStart(2, '0');
    const yyyy = date.getFullYear();
    const weekday = days[date.getDay()];
    return `${dd}/${mm}/${yyyy} (${weekday})`;
}

// Calculate hours between start and end time
function calculateHours(startTime, endTime) {
    if (!startTime || !endTime) return 0;
    
    try {
        const start = new Date(`1970-01-01T${startTime}`);
        const end = new Date(`1970-01-01T${endTime}`);
        
        if (isNaN(start.getTime()) || isNaN(end.getTime())) return 0;
        
        // Handle overnight shifts (end time is next day)
        if (end < start) {
            end.setDate(end.getDate() + 1);
        }
        
        const diffMs = end - start;
        return diffMs / (1000 * 60 * 60); // Convert to hours
    } catch (error) {
        console.error('Error calculating hours:', error);
        return 0;
    }
}

// Get all unique employees from Employees table
app.get('/api/employees', isAuthenticated, isAM, async (req, res) => {
    try {
        const dbName = req.session.user.dbName;
        if (!dbName) {
            return res.status(401).json({ error: 'User not authenticated' });
        }

        const pool = getPool(dbName);
        
        const [results] = await pool.promise().query(`
            SELECT DISTINCT name, lastName, designation, wage
            FROM Employees 
            ORDER BY name, lastName
        `);

        console.log('👥 Retrieved employees:', results.length);
        res.json(results);
    } catch (error) {
        console.error('❌ Error fetching employees:', error);
        res.status(500).json({ error: 'Failed to fetch employees' });
    }
});

// Get current month data for all employees (only those in Employees table)
app.get('/api/hours/current-month', isAuthenticated, isAM, async (req, res) => {
    try {
        const dbName = req.session.user.dbName;
        if (!dbName) {
            return res.status(401).json({ error: 'User not authenticated' });
        }

        const pool = getPool(dbName);
        
        // Get current month range
        const now = new Date();
        const firstDay = new Date(now.getFullYear(), now.getMonth(), 1);
        const lastDay = new Date(now.getFullYear(), now.getMonth() + 1, 0);
        
        const formattedDays = [];
        const current = new Date(firstDay);
        while (current <= lastDay) {
            formattedDays.push(formatDateForDisplay(new Date(current)));
            current.setDate(current.getDate() + 1);
        }

        console.log('📅 Current month days:', formattedDays.length);

        // Get employees from Employees table to ensure we only include valid employees
        const [employees] = await pool.promise().query(`
            SELECT name, lastName, wage, designation 
            FROM Employees 
            ORDER BY name, lastName
        `);

        console.log('👥 Valid employees from Employees table:', employees.length);

        // Get rota data for current month, joined with Employees to get proper wage
        const [results] = await pool.promise().query(`
            SELECT 
                cr.name,
                cr.lastName,
                cr.day,
                cr.startTime,
                cr.endTime,
                cr.designation,
                cr.who,
                e.wage as employee_wage
            FROM ConfirmedRota cr
            INNER JOIN Employees e ON cr.name = e.name AND cr.lastName = e.lastName
            WHERE cr.day IN (?)
            ORDER BY cr.day, cr.name, cr.lastName, cr.startTime
        `, [formattedDays]);

        console.log('📊 Current month records with valid employees:', results.length);

        // Process data to calculate totals using wage from Employees table
        const employeeData = {};
        let grandTotalHours = 0;
        let grandTotalCost = 0;

        results.forEach(shift => {
            const key = `${shift.name} ${shift.lastName}`;
            const hours = calculateHours(shift.startTime, shift.endTime);
            // Use wage from Employees table, not from ConfirmedRota
            const cost = hours * parseFloat(shift.employee_wage || 0);

            if (!employeeData[key]) {
                employeeData[key] = {
                    name: shift.name,
                    lastName: shift.lastName,
                    designation: shift.designation,
                    wage: parseFloat(shift.employee_wage || 0),
                    totalHours: 0,
                    totalCost: 0,
                    shifts: []
                };
            }

            employeeData[key].totalHours += hours;
            employeeData[key].totalCost += cost;
            employeeData[key].shifts.push({
                day: shift.day,
                startTime: shift.startTime,
                endTime: shift.endTime,
                hours: hours,
                cost: cost,
                who: shift.who
            });

            grandTotalHours += hours;
            grandTotalCost += cost;
        });

        const report = Object.values(employeeData).map(emp => ({
            ...emp,
            totalHours: parseFloat(emp.totalHours.toFixed(2)),
            totalCost: parseFloat(emp.totalCost.toFixed(2))
        }));

        res.json({
            report,
            summary: {
                totalEmployees: report.length,
                grandTotalHours: parseFloat(grandTotalHours.toFixed(2)),
                grandTotalCost: parseFloat(grandTotalCost.toFixed(2)),
                period: `Current Month (${firstDay.toLocaleDateString('en-GB')} - ${lastDay.toLocaleDateString('en-GB')})`
            }
        });

    } catch (error) {
        console.error('❌ Error fetching current month data:', error);
        res.status(500).json({ error: 'Failed to fetch current month data' });
    }
});

// Get filtered data by employee and date range
app.post('/api/hours/filtered', isAuthenticated, isAM, async (req, res) => {
    try {
        const dbName = req.session.user.dbName;
        if (!dbName) {
            return res.status(401).json({ error: 'User not authenticated' });
        }

        const { startDate, endDate, employeeName } = req.body;
        const pool = getPool(dbName);

        if (!startDate || !endDate) {
            return res.status(400).json({ error: 'Start and end dates are required' });
        }

        const start = new Date(startDate);
        const end = new Date(endDate);

        if (isNaN(start.getTime()) || isNaN(end.getTime())) {
            return res.status(400).json({ error: 'Invalid dates provided' });
        }

        if (start > end) {
            return res.status(400).json({ error: 'Start date must be before end date' });
        }

        // Generate all dates in the range
        const formattedDays = [];
        const current = new Date(start);
        while (current <= end) {
            formattedDays.push(formatDateForDisplay(new Date(current)));
            current.setDate(current.getDate() + 1);
        }

        console.log('🔍 Filtering data:', {
            employeeName,
            dateRange: `${startDate} to ${endDate}`,
            daysCount: formattedDays.length
        });

        let query = `
            SELECT 
                cr.name,
                cr.lastName,
                cr.day,
                cr.startTime,
                cr.endTime,
                cr.designation,
                cr.who,
                e.wage as employee_wage
            FROM ConfirmedRota cr
            INNER JOIN Employees e ON cr.name = e.name AND cr.lastName = e.lastName
            WHERE cr.day IN (?)
        `;
        let params = [formattedDays];

        if (employeeName && employeeName !== 'all') {
            const [firstName, lastName] = employeeName.split(' ');
            query += ` AND cr.name = ? AND cr.lastName = ?`;
            params.push(firstName, lastName);
        }

        query += ` ORDER BY cr.day, cr.name, cr.lastName, cr.startTime`;

        const [results] = await pool.promise().query(query, params);

        console.log('📊 Filtered records found:', results.length);

        // Process data using wage from Employees table
        const employeeData = {};
        let grandTotalHours = 0;
        let grandTotalCost = 0;

        results.forEach(shift => {
            const key = `${shift.name} ${shift.lastName}`;
            const hours = calculateHours(shift.startTime, shift.endTime);
            // Use wage from Employees table
            const cost = hours * parseFloat(shift.employee_wage || 0);

            if (!employeeData[key]) {
                employeeData[key] = {
                    name: shift.name,
                    lastName: shift.lastName,
                    designation: shift.designation,
                    wage: parseFloat(shift.employee_wage || 0),
                    totalHours: 0,
                    totalCost: 0,
                    shifts: []
                };
            }

            employeeData[key].totalHours += hours;
            employeeData[key].totalCost += cost;
            employeeData[key].shifts.push({
                day: shift.day,
                startTime: shift.startTime,
                endTime: shift.endTime,
                hours: hours,
                cost: cost,
                who: shift.who
            });

            grandTotalHours += hours;
            grandTotalCost += cost;
        });

        const report = Object.values(employeeData).map(emp => ({
            ...emp,
            totalHours: parseFloat(emp.totalHours.toFixed(2)),
            totalCost: parseFloat(emp.totalCost.toFixed(2))
        }));

        res.json({
            report,
            summary: {
                totalEmployees: report.length,
                grandTotalHours: parseFloat(grandTotalHours.toFixed(2)),
                grandTotalCost: parseFloat(grandTotalCost.toFixed(2)),
                period: `${startDate} to ${endDate}`,
                employeeFilter: employeeName
            }
        });

    } catch (error) {
        console.error('❌ Error fetching filtered data:', error);
        res.status(500).json({ error: 'Failed to fetch filtered data' });
    }
});

// Generate PDF endpoint
app.post('/generate-pdf', isAuthenticated, isAM, async (req, res) => {
    const { htmlContent, filename } = req.body;
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
        // Production - use Puppeteer's bundled Chrome
        else if (process.env.NODE_ENV === 'production') {
            launchOptions.executablePath = '/app/.chrome-for-testing/chrome-linux64/chrome';
        }

        browser = await puppeteer.launch(launchOptions);
        const page = await browser.newPage();
        await page.setContent(htmlContent, { waitUntil: 'networkidle0' });

        // Wait for content to render
        await new Promise(resolve => setTimeout(resolve, 1000));

        const pdfBuffer = await page.pdf({
            format: 'A4',
            printBackground: true,
            margin: {
                top: '15mm',
                right: '10mm',
                bottom: '15mm',
                left: '10mm'
            },
            displayHeaderFooter: true,
            headerTemplate: '<div style="font-size: 10px; width: 100%; text-align: center; color: #666;">Employee Hours Report</div>',
            footerTemplate: '<div style="font-size: 8px; width: 100%; text-align: center; color: #666;">Page <span class="pageNumber"></span> of <span class="totalPages"></span> - Generated on ' + new Date().toLocaleDateString('en-GB') + '</div>'
        });

        res.setHeader('Content-Type', 'application/pdf');
        res.setHeader('Content-Disposition', `attachment; filename="${filename}.pdf"`);
        res.end(pdfBuffer);

    } catch (error) {
        console.error('❌ PDF Generation Error:', error);
        res.status(500).json({ error: 'Failed to generate PDF: ' + error.message });
    } finally {
        if (browser) await browser.close();
    }
});

// Serve HTML file
app.get('/', isAuthenticated, isAM, (req, res) => {
    res.sendFile(path.join(__dirname, 'TimeTracking.html'));
});

module.exports = app;