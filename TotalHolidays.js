const express = require('express');
const mysql = require('mysql2');
const bodyParser = require('body-parser');
const path = require('path');
const { getPool, mainPool } = require('./db.js');
const { sessionMiddleware, isAuthenticated, isAdmin} = require('./sessionConfig');

const app = express();

// Middleware
app.use(sessionMiddleware);
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Get all employees with holiday data
app.get('/api/holidays/employees', isAuthenticated, isAdmin, (req, res) => {
    const dbName = req.session.user.dbName;
    if (!dbName) {
        return res.status(401).json({ message: 'User not authenticated' });
    }

    const pool = getPool(dbName);
    
    pool.query(`
        SELECT id, name, lastName, dateStart, startHoliday, TotalHoliday, Accrued 
        FROM Employees
    `, (error, results) => {
        if (error) {
            console.error('Error fetching employees:', error);
            return res.status(500).json({ message: 'Error fetching employee data' });
        }
        res.json(results);
    });
});

// Update employee holiday data (changed from PUT to POST)
app.post('/api/holidays/employees/:id', isAuthenticated, isAdmin, (req, res) => {
    const dbName = req.session.user.dbName;
    if (!dbName) {
        return res.status(401).json({ message: 'User not authenticated' });
    }

    const pool = getPool(dbName);
    const { id } = req.params;
    const { dateStart, startHoliday, TotalHoliday, Accrued } = req.body;

    pool.query(`
        UPDATE Employees 
        SET dateStart = ?, startHoliday = ?, TotalHoliday = ?, Accrued = ?
        WHERE id = ?
    `, [dateStart, startHoliday, TotalHoliday, Accrued, id], (error, results) => {
        if (error) {
            console.error('Error updating employee:', error);
            return res.status(500).json({ message: 'Error updating employee data' });
        }
        res.json({ success: true,});
    });
});

// Get all holiday requests
app.get('/api/holidays/requests', isAuthenticated, isAdmin, (req, res) => {
    const dbName = req.session.user.dbName;
    if (!dbName) {
        return res.status(401).json({ message: 'User not authenticated' });
    }

    const pool = getPool(dbName);
    
    pool.query(`
        SELECT id, name, lastName, startDate, endDate, days, accepted
        FROM Holiday
    `, (error, results) => {
        if (error) {
            console.error('Error fetching holiday requests:', error);
            return res.status(500).json({ message: 'Error fetching holiday requests' });
        }
        res.json(results);
    });
});

// Update holiday request (changed from PUT to POST)
app.post('/api/holidays-update/requests/:id', isAuthenticated, isAdmin, (req, res) => {
    const dbName = req.session.user.dbName;
    if (!dbName) {
        return res.status(401).json({ message: 'User not authenticated' });
    }

    const pool = getPool(dbName);
    const { id } = req.params;
    const { startDate, endDate, days, accepted } = req.body;

    pool.query(`
        UPDATE Holiday 
        SET startDate = ?, endDate = ?, days = ?, accepted = ?
        WHERE id = ?
    `, [startDate, endDate, days, accepted, id], (error, results) => {
        if (error) {
            console.error('Error updating holiday request:', error);
            return res.status(500).json({ message: 'Error updating holiday request' });
        }
        res.json({ success: true, message: 'Holiday request updated successfully' });
    });
});

// Delete holiday request (changed from DELETE to POST)
app.post('/api/holidays/requests/:id', isAuthenticated, isAdmin, (req, res) => {
    const dbName = req.session.user.dbName;
    if (!dbName) {
        return res.status(401).json({ message: 'User not authenticated' });
    }

    const pool = getPool(dbName);
    const { id } = req.params;

    // Step 1: Get the holiday details
    pool.query(
        'SELECT name, lastName, days, accepted FROM Holiday WHERE id = ?',
        [id],
        (err, results) => {
            if (err) {
                console.error('Error fetching holiday:', err);
                return res.status(500).json({ message: 'Error retrieving holiday details' });
            }

            if (!results || results.length === 0) {
                return res.status(404).json({ message: 'Holiday request not found' });
            }

            const holiday = results[0];

            // Step 2: Delete the holiday
            pool.query('DELETE FROM Holiday WHERE id = ?', [id], (err) => {
                if (err) {
                    console.error('Error deleting holiday:', err);
                    return res.status(500).json({ message: 'Error deleting holiday request' });
                }

                // Step 3: Restore days if paid leave
                if (holiday.accepted === 'true') {
                    pool.query(
                        'UPDATE Employees SET TotalHoliday = TotalHoliday + ? WHERE name = ? AND lastName = ?',
                        [holiday.days, holiday.name, holiday.lastName],
                        (err, result) => {
                            if (err) {
                                console.error('Error updating holiday balance by name:', err);
                                return res.status(500).json({ message: 'Error restoring holiday days' });
                            }

                            if (result.affectedRows === 0) {
                                return res.status(404).json({ message: 'Employee not found by name and lastName' });
                            }

                            res.json({
                                success: true,
                                message: 'Holiday request deleted successfully',
                                daysRestored: holiday.days,
                                wasPaidLeave: true
                            });
                        }
                    );
                } else {
                    if (holiday.accepted === 'unpaid') {
                        console.log(`Unpaid leave deleted - no days restored for employee ${holiday.name} ${holiday.lastName}`);
                    }

                    res.json({
                        success: true,
                        message: 'Holiday request deleted successfully',
                        daysRestored: 0,
                        wasPaidLeave: false
                    });
                }
            });
        }
    );
});

// Helper function to calculate months between dates
function monthDiff(startDate, endDate) {
    let months = (endDate.getFullYear() - startDate.getFullYear()) * 12;
    months -= startDate.getMonth();
    months += endDate.getMonth();
    return months <= 0 ? 0 : months + 1; // Include both start and end months
}

// Route to serve the main page
app.get('/', isAuthenticated, isAdmin, (req, res) => {
    res.sendFile(path.join(__dirname, 'TotalHolidays.html'));
});

module.exports = app;