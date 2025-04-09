const server = require('./server.js');
const http = require('http');
const fs = require('fs');
const mysql = require('mysql2');
const express = require('express');
const { query } = require('./dbPromise');
const bodyParser = require('body-parser');
const path = require('path');
const { v4: uuidv4 } = require('uuid');
const { getPool, mainPool } = require('./db.js');
const { sessionMiddleware, isAuthenticated, isAdmin, isSupervisor } = require('./sessionConfig');

const app = express();

// Middleware
app.use(sessionMiddleware);
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Route to fetch rota data (updated with better error handling)
app.get('/rota', isAuthenticated, async (req, res) => {
    try {
        const dbName = req.session.user.dbName;
        const startDate = req.query.startDate;

        if (!dbName) {
            return res.status(401).json({ success: false, message: 'User not authenticated' });
        }

        if (!startDate) {
            return res.status(400).json({ success: false, message: 'Start date is required' });
        }

        const pool = getPool(dbName);
        const sql = `
            SELECT 
                name,
                lastName, 
                DATE_FORMAT(STR_TO_DATE(day, '%d/%m/%Y'), '%d/%m/%Y') as day, 
                startTime, 
                endTime
            FROM ConfirmedRota
            WHERE STR_TO_DATE(day, '%d/%m/%Y') = STR_TO_DATE(?, '%Y-%m-%d')
        `;

        const results = await query(pool, sql, [startDate]);
        res.json(results);
    } catch (error) {
        console.error('Rota fetch error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Server error',
            error: error.message 
        });
    }
});

// Route to fetch existing tips (updated)
app.get('/existing', isAuthenticated, async (req, res) => {
    try {
        const dbName = req.session.user.dbName;
        const date = req.query.date;

        if (!dbName) {
            return res.status(401).json({ success: false, message: 'User not authenticated' });
        }

        if (!date) {
            return res.status(400).json({ success: false, message: 'Date is required' });
        }

        const pool = getPool(dbName);
        const sql = `
            SELECT CONCAT(name, ' ', lastName) AS name, 
                   CAST(tip AS DECIMAL(10,2)) AS tip, 
                   totalHours
            FROM tip
            WHERE day = ?
        `;

        const results = await query(pool, sql, [date]);
        res.json(results);
    } catch (error) {
        console.error('Existing tips error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Database error',
            error: error.message 
        });
    }
});

// Route to submit payslips (fixed)
app.post('/submitPayslips', isAuthenticated, async (req, res) => {
    try {
        const dbName = req.session.user.dbName;
        const payslipData = req.body;

        if (!dbName) {
            return res.status(401).json({ success: false, message: 'User not authenticated' });
        }

        if (!payslipData || !Array.isArray(payslipData)) {
            return res.status(400).json({ success: false, message: 'Invalid payslip data' });
        }

        const pool = getPool(dbName);
        const uniqueDates = [...new Set(payslipData.map(item => item.monthStart))];
        
        // Delete existing tips
        for (const date of uniqueDates) {
            await query(pool, 'DELETE FROM tip WHERE day = ?', [date]);
        }

        // Insert new tips
        const insertPromises = payslipData.map(entry => {
            return query(
                pool,
                'INSERT INTO tip (name, lastName, totalHours, tip, day) VALUES (?, ?, ?, ?, ?)',
                [entry.firstName, entry.lastName, entry.totalHours, entry.tip, entry.monthStart]
            );
        });

        await Promise.all(insertPromises);
        
        res.status(200).json({ success: true, message: 'Tips saved successfully' });
    } catch (error) {
        console.error('Submit payslips error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Error saving tips',
            error: error.message 
        });
    }
});

// Cancel tips for the day (fixed)
app.delete('/cancel', isAuthenticated, async (req, res) => {
    try {
        const dbName = req.session.user.dbName;
        const date = req.query.date;

        if (!dbName) {
            return res.status(401).json({ success: false, message: 'User not authenticated' });
        }

        if (!date) {
            return res.status(400).json({ success: false, message: 'Date is required' });
        }

        const pool = getPool(dbName);
        const result = await query(pool, 'DELETE FROM tip WHERE day = ?', [date]);
        
        res.status(200).json({ 
            success: true, 
            message: 'Tips cancelled successfully',
            affectedRows: result.affectedRows 
        });
    } catch (error) {
        console.error('Cancel tips error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Error cancelling tips',
            error: error.message 
        });
    }
});

// Route to fetch cash report (updated with better error handling)
app.get('/cashReport', isAuthenticated, async (req, res) => {
    try {
        const dbName = req.session.user.dbName;
        const date = req.query.date;

        if (!dbName) {
            return res.status(401).json({ success: false, message: 'User not authenticated' });
        }

        if (!date) {
            return res.status(400).json({ success: false, message: 'Date is required' });
        }

        const pool = getPool(dbName);
        const sql = 'SELECT service, eod FROM cash_reports WHERE day = ?';
        const [result] = await query(pool, sql, [date]);

        const cashReport = processCashReport(result || { service: 0, eod: '' });
        res.json(cashReport);
    } catch (error) {
        console.error('Cash report error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Error fetching cash report',
            error: error.message 
        });
    }
});

// Function to get Values for the Monthly Calendar
app.get('/calendar-status', isAuthenticated, (req, res) => {
    const dbName = req.session.user.dbName;
    const { year, month } = req.query;

    if (!dbName) {
        return res.status(401).json({ message: 'User not authenticated' });
    }

    const pool = getPool(dbName);
    const formattedMonth = String(month).padStart(2, '0');
    
    // Pattern for ConfirmedRota (dd/mm/yyyy format)
    const rotaDatePattern = `__/${formattedMonth}/${year}%`;
    // Pattern for tip table (yyyy-mm-dd format)
    const tipDatePattern = `${year}-${formattedMonth}-__`;

    // Get confirmed tips for the month (from tip table)
    pool.query(`
        SELECT DATE_FORMAT(day, '%d/%m/%Y') as formattedDate, 
               SUM(tip) as totalTips
        FROM tip
        WHERE day LIKE ?
        GROUP BY day
    `, [tipDatePattern], (err, tipsResults) => {
        if (err) {
            console.error('Error fetching tips:', err);
            return res.status(500).json({ error: 'Internal Server Error' });
        }
        
        // Get all days with rota data (from ConfirmedRota table)
        pool.query(`
            SELECT DISTINCT SUBSTRING_INDEX(day, ' ', 1) as date
            FROM ConfirmedRota
            WHERE day LIKE ?
        `, [rotaDatePattern], (err, rotaResults) => {
            if (err) {
                console.error('Error fetching rota data:', err);
                return res.status(500).json({ error: 'Internal Server Error' });
            }

            // Convert to objects for easy lookup (using dd/mm/yyyy format)
            const tipsByDate = {};
            tipsResults.forEach(row => {
                tipsByDate[row.formattedDate] = parseFloat(row.totalTips);
            });

            const rotaDates = {};
            rotaResults.forEach(row => {
                rotaDates[row.date] = true;
            });

            res.json({
                month: `${year}-${formattedMonth}`,
                data: {
                    tips: tipsByDate,
                    rotaDays: rotaDates
                }
            });
        });
    });
});

function processCashReport(report) {
    report.service = parseFloat(report.service) || 0;
    
    if (report.eod?.includes('Missing')) {
        const missingMatch = report.eod.match(/Missing:\s*£([\d.]+)/);
        if (missingMatch) report.service -= parseFloat(missingMatch[1]);
    }
    
    report.service = report.service.toFixed(2);
    return report;
}

// Route to serve the Tip.html file
app.get('/', isAuthenticated, isAdmin, (req, res) => {
    if (req.session.user.role === 'admin') {
        res.sendFile(path.join(__dirname, 'Tip.html'));
    } else {
        res.status(403).json({ error: 'Access denied' });
    }
});

module.exports = app;