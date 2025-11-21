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

// Helper functions
function formatDateWithWeekday(date) {
    const days = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];
    const dd = String(date.getDate()).padStart(2, '0');
    const mm = String(date.getMonth() + 1).padStart(2, '0');
    const yyyy = date.getFullYear();
    const weekday = days[date.getDay()];
    return `${dd}/${mm}/${yyyy} (${weekday})`;
}

function getCashReportDay(date) {
    const days = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];
    const dd = String(date.getDate()).padStart(2, '0');
    const mm = String(date.getMonth() + 1).padStart(2, '0');
    const yyyy = date.getFullYear();
    const weekday = days[date.getDay()];
    return `${weekday} ${dd}/${mm}/${yyyy}`;
}

function calculateHours(startTime, endTime) {
    if (!startTime || !endTime) return 0;
    
    const start = new Date(`1970-01-01T${startTime}`);
    const end = new Date(`1970-01-01T${endTime}`);
    
    if (isNaN(start.getTime()) || isNaN(end.getTime())) return 0;
    
    // Handle overnight shifts (end time is next day)
    if (end < start) {
        end.setDate(end.getDate() + 1);
    }
    
    const diffMs = end - start;
    return diffMs / (1000 * 60 * 60); // Convert to hours
}

// Report generation endpoint
app.post('/generate-report', async (req, res) => {
    try {
        if (!req.session.user || !req.session.user.dbName) {
            return res.status(401).json({ error: 'Unauthorized - No session or database specified' });
        }

        const dbName = req.session.user.dbName;
        const pool = getPool(dbName);
        const { startDate, endDate } = req.body;

        if (!startDate || !endDate) {
            return res.status(400).json({ error: 'Start and end dates are required' });
        }

        const start = new Date(startDate);
        const end = new Date(endDate);

        if (isNaN(start.getTime())) {
            return res.status(400).json({ error: 'Invalid start date' });
        }
        
        if (isNaN(end.getTime())) {
            return res.status(400).json({ error: 'Invalid end date' });
        }
        
        if (start > end) {
            return res.status(400).json({ error: 'Start date must be before end date' });
        }

        const formattedDays = [];
        const dayMap = new Map();
        const current = new Date(start);
        
        while (current <= end) {
            const formatted = formatDateWithWeekday(new Date(current));
            const key = getCashReportDay(new Date(current));
            formattedDays.push(formatted);
            dayMap.set(key, true);
            current.setDate(current.getDate() + 1);
        }

        if (formattedDays.length === 0) {
            return res.status(400).json({ error: 'No days in selected date range' });
        }

        // Fetch tax rates
        const [taxRows] = await pool.promise().query(`SELECT tax, pension, holiday FROM rota_tax LIMIT 1`);
        const { tax = 0, pension = 0, holiday = 0 } = taxRows[0] || {};

        console.log('📊 TAX RATES:', { tax, pension, holiday });

        // Fetch rota data with pension_payer information
        const [rotaResults] = await pool.promise().query(`
            SELECT 
                cr.day,
                cr.name,
                cr.lastName,
                cr.designation,
                cr.startTime,
                cr.endTime,
                IFNULL(e.wage, 0) AS wage,
                IFNULL(e.pension_payer, 'No') AS pension_payer
            FROM 
                ConfirmedRota cr
            LEFT JOIN 
                Employees e ON cr.name = e.name AND cr.lastName = e.lastName
            WHERE 
                cr.day IN (?)
            ORDER BY 
                cr.day, cr.name, cr.lastName
        `, [formattedDays]);

        console.log('👥 ROTA RESULTS COUNT:', rotaResults.length);
        console.log('📋 PENSION PAYER BREAKDOWN:');
        
        const employeeData = {};
        let totalCost = 0;
        let pensionPayerCount = 0;
        let nonPensionPayerCount = 0;

        rotaResults.forEach(shift => {
            const key = `${shift.name} ${shift.lastName}`;
            const day = shift.day;
            const isPensionPayer = shift.pension_payer === 'Yes';

            if (isPensionPayer) {
                pensionPayerCount++;
            } else {
                nonPensionPayerCount++;
            }

            if (!employeeData[key]) {
                employeeData[key] = {
                    name: key,
                    designation: shift.designation,
                    wage: parseFloat(shift.wage) || 0,
                    pension_payer: isPensionPayer,
                    shifts: {}
                };
            }

            if (!employeeData[key].shifts[day]) {
                employeeData[key].shifts[day] = [];
            }

            employeeData[key].shifts[day].push({
                startTime: shift.startTime,
                endTime: shift.endTime
            });
        });

        console.log('💰 PENSION PAYER STATS:', {
            totalEmployees: Object.keys(employeeData).length,
            pensionPayers: pensionPayerCount,
            nonPensionPayers: nonPensionPayerCount,
            pensionRate: pension + '%'
        });

        const report = Object.values(employeeData).map(employee => {
            let employeeBaseTotal = 0;

            Object.entries(employee.shifts).forEach(([day, shifts]) => {
                shifts.forEach(shift => {
                    const hours = calculateHours(shift.startTime, shift.endTime);
                    employeeBaseTotal += hours * employee.wage;
                });
            });

            const taxAmount = (tax / 100) * employeeBaseTotal;
            
            // Only calculate pension for pension payers
            let pensionAmount = 0;
            if (employee.pension_payer) {
                pensionAmount = (pension / 100) * employeeBaseTotal;
                console.log(`💰 PENSION APPLIED for ${employee.name}: £${pensionAmount.toFixed(2)} (${pension}% of £${employeeBaseTotal.toFixed(2)})`);
            } else {
                console.log(`❌ NO PENSION for ${employee.name}: Not a pension payer`);
            }

            const holidayAmount = (holiday / 100) * employeeBaseTotal;

            const employeeTotalCost = employeeBaseTotal + taxAmount + pensionAmount + holidayAmount;
            totalCost += employeeTotalCost;

            return {
                name: employee.name,
                designation: employee.designation,
                baseCost: parseFloat(employeeBaseTotal.toFixed(2)),
                tax: parseFloat(taxAmount.toFixed(2)),
                pension: parseFloat(pensionAmount.toFixed(2)),
                holiday: parseFloat(holidayAmount.toFixed(2)),
                totalWithExtras: parseFloat(employeeTotalCost.toFixed(2)),
                isPensionPayer: employee.pension_payer // Include for debugging
            };
        });

        // Fetch cash reports
        const [cashResults] = await pool.promise().query(`
            SELECT day, zreport, onaccount 
            FROM cash_reports
            WHERE day IN (?)
        `, [Array.from(dayMap.keys())]);

        let zReportTotal = 0;
        let onAccountTotal = 0;

        cashResults.forEach(entry => {
            zReportTotal += parseFloat(entry.zreport || 0);
            onAccountTotal += parseFloat(entry.onaccount || 0);
        });

        console.log('💳 CASH REPORT TOTALS:', {
            zReportTotal: zReportTotal.toFixed(2),
            onAccountTotal: onAccountTotal.toFixed(2),
            totalSales: (zReportTotal + onAccountTotal).toFixed(2)
        });

        console.log('📊 FINAL REPORT SUMMARY:', {
            totalCost: totalCost.toFixed(2),
            employeeCount: report.length,
            pensionPayersInReport: report.filter(emp => emp.isPensionPayer).length
        });

        return res.json({
            totalCost: parseFloat(totalCost.toFixed(2)),
            report,
            zReportTotal: parseFloat(zReportTotal.toFixed(2)),
            onAccountTotal: parseFloat(onAccountTotal.toFixed(2)),
            appliedRates: { tax, pension, holiday },
            pensionStats: {
                totalEmployees: Object.keys(employeeData).length,
                pensionPayers: pensionPayerCount,
                nonPensionPayers: nonPensionPayerCount
            }
        });

    } catch (err) {
        console.error('❌ Error in generate-report:', err);
        return res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.post('/generate-pdf', isAuthenticated, async (req, res) => {
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
                top: '20mm',
                right: '10mm',
                bottom: '20mm',
                left: '10mm'
            },
            displayHeaderFooter: true,
            headerTemplate: '<div style="font-size: 10px; width: 100%; text-align: center;">Financial Report - ' + dateRange + '</div>',
            footerTemplate: '<div style="font-size: 8px; width: 100%; text-align: center;">Page <span class="pageNumber"></span> of <span class="totalPages"></span></div>'
        });

        res.setHeader('Content-Type', 'application/pdf');
        res.setHeader('Content-Disposition', `attachment; filename="Financial_Report_${dateRange.replace(/\//g, '-')}.pdf"`);
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
    res.sendFile(path.join(__dirname, 'FinancialSummary.html'));
});

module.exports = app;