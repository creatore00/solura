const express = require('express');
const mysql = require('mysql2');
const bodyParser = require('body-parser');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const { getPool, mainPool } = require('./db.js'); // Import the connection pool functions
const { sessionMiddleware, isAuthenticated, isAdmin } = require('./sessionConfig'); // Adjust the path as needed

const app = express();

// Middleware
app.use(sessionMiddleware);
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

const storage = multer.memoryStorage();
const upload = multer({ storage: storage }).fields([
    { name: 'passportImage', maxCount: 1 },
    { name: 'visa', maxCount: 1 }
]);

// Endpoint to Send Data
app.post('/', isAuthenticated, upload, (req, res) => {
    const dbName = req.session.user.dbName; // Get the database name from the session

    if (!dbName) {
        return res.status(401).json({ success: false, message: 'User not authenticated' });
    }

    const pool = getPool(dbName); // Get the correct connection pool

    console.log('Request Body:', req.body);
    // Destructure fields from req.body
    const { name, lastName, email, phone, address, nin, wage, designation, position, contractHours, Salary, SalaryPrice, holiday, dateStart } = req.body;
    const passportImageFile = req.files['passportImage'] ? req.files['passportImage'][0] : null;
    const visaFile = req.files['visa'] ? req.files['visa'][0] : null;

    // Check if required files were uploaded
    if (!passportImageFile) {
        return res.status(400).json({ success: false, message: 'Both passport image and visa files are required' });
    }

    // Extract file content (buffer) and MIME type
    const passportImageContent = passportImageFile.buffer;
    const visaContent = visaFile ? visaFile.buffer : null;  // Visa can be null

    // Insert data into the database
    const query = 'INSERT INTO Employees (name, lastName, email, phone, address, nin, wage, designation, position, contractHours, Salary, SalaryPrice, passportImage, visa, TotalHoliday, startHoliday, dateStart) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)';

    pool.query(query, [name, lastName, email, phone, address, nin, wage, designation, position, contractHours, Salary, SalaryPrice, passportImageContent, visaContent, holiday, holiday, dateStart], (err, result) => {
        if (err) {
            console.error('Error inserting data:', err);
            res.status(500).json({ success: false, message: 'Server error' });
            return;
        }
        res.json({ success: true, message: 'Employee data successfully inserted' });
    });
});

// Endpoint to Retrieve Data
app.get('/employees', isAuthenticated, (req, res) => {
    const dbName = req.session.user.dbName; // Get the database name from the session

    if (!dbName) {
        return res.status(401).json({ success: false, message: 'User not authenticated' });
    }

    const pool = getPool(dbName); // Get the correct connection pool

    const query = `
        SELECT id, name, lastName, email, phone, address, nin, wage, designation, 
               position, contractHours, Salary, SalaryPrice, dateStart, startHoliday, 
               TotalHoliday, Accrued 
        FROM Employees 
        WHERE situation IS NULL OR situation = ''
    `;
    
    pool.query(query, (err, results) => {
        if (err) {
            console.error('Error fetching data:', err);
            res.status(500).json({ success: false, message: 'Server error' });
            return;
        }
        res.json(results);
    });
});

// GET endpoint to fetch employee data for editing (using callbacks)
app.get('/edit-employee/:id', isAuthenticated, (req, res) => {
    const dbName = req.session.user.dbName;
    if (!dbName) {
        return res.status(401).json({ success: false, message: 'User not authenticated' });
    }

    const pool = getPool(dbName);
    const { id } = req.params;

    pool.query(
        `SELECT id, name, lastName, email, phone, address, nin, wage, 
         designation, position, contractHours, Salary, SalaryPrice, dateStart, startHoliday 
         FROM Employees WHERE id = ?`,
        [id],
        (err, rows) => {
            if (err) {
                console.error('Error fetching employee data:', err);
                return res.status(500).json({ 
                    success: false, 
                    message: 'Server error',
                    error: process.env.NODE_ENV === 'development' ? err.message : undefined
                });
            }

            if (rows.length === 0) {
                return res.status(404).json({ success: false, message: 'Employee not found' });
            }

            const employeeData = rows[0];
            
            // Format date if needed
            if (employeeData.dateStart instanceof Date) {
                employeeData.dateStart = employeeData.dateStart.toISOString().split('T')[0];
            }

            res.json({
                success: true,
                data: employeeData
            });
        }
    );
});

// POST endpoint to update employee data (using callbacks)
app.post('/edit-employee/:id', isAuthenticated, upload, (req, res) => {
    const dbName = req.session.user.dbName;
    if (!dbName) {
        return res.status(401).json({ success: false, message: 'User not authenticated' });
    }

    const pool = getPool(dbName);
    const { id } = req.params;
    const { name, lastName, email, phone, address, nin, wage, 
           designation, position, contractHours, Salary, SalaryPrice, holiday, dateStart } = req.body;

    // First get the current employee data to compare holiday values
    pool.query('SELECT startHoliday, TotalHoliday FROM Employees WHERE id = ?', [id], (err, currentData) => {
        if (err) {
            console.error('Error fetching current employee data:', err);
            return res.status(500).json({ 
                success: false, 
                message: 'Server error fetching current employee data',
                error: process.env.NODE_ENV === 'development' ? err.message : undefined
            });
        }

        if (!currentData || currentData.length === 0) {
            return res.status(404).json({ success: false, message: 'Employee not found' });
        }

        const oldHoliday = parseFloat(currentData[0].startHoliday) || 0;
        const newHoliday = parseFloat(holiday) || 0;
        const holidayDifference = newHoliday - oldHoliday;
        const currentTotalHoliday = parseFloat(currentData[0].TotalHoliday) || 0;
        const updatedTotalHoliday = currentTotalHoliday + holidayDifference;

        // Handle file uploads - these will be undefined if not provided
        const passportImageFile = req.files['passportImage'] ? req.files['passportImage'][0] : null;
        const visaFile = req.files['visa'] ? req.files['visa'][0] : null;

        // Build the dynamic query based on what's being updated
        let query = `UPDATE Employees SET 
            name = ?, lastName = ?, email = ?, phone = ?, address = ?,
            nin = ?, wage = ?, designation = ?, position = ?, contractHours = ?, Salary = ?, SalaryPrice =?,
            dateStart = ?, startHoliday = ?, TotalHoliday = ?`;
        
        const queryParams = [
            name, lastName, email, phone, address, 
            nin, wage, designation, position, contractHours, Salary, SalaryPrice,
            dateStart, holiday, updatedTotalHoliday
        ];

        // Add file updates if provided
        if (passportImageFile) {
            query += ', passportImage = ?';
            queryParams.push(passportImageFile.buffer);
        }
        if (visaFile) {
            query += ', visa = ?';
            queryParams.push(visaFile.buffer);
        }

        query += ' WHERE id = ?';
        queryParams.push(id);

        pool.query(query, queryParams, (err, result) => {
            if (err) {
                console.error('Error updating employee:', err);
                return res.status(500).json({ 
                    success: false, 
                    message: 'Server error',
                    error: process.env.NODE_ENV === 'development' ? err.message : undefined
                });
            }

            res.json({ 
                success: true, 
                message: 'Employee updated successfully',
                data: {
                    startHoliday: newHoliday,
                    TotalHoliday: updatedTotalHoliday
                }
            });
        });
    });
});

// Endpoint to download a specific passport file based on employee ID
app.get('/api/download-file/:id', isAuthenticated, (req, res) => {
    const dbName = req.session.user.dbName; // Get the database name from the session

    if (!dbName) {
        return res.status(401).json({ success: false, message: 'User not authenticated' });
    }

    const pool = getPool(dbName); // Get the correct connection pool

    const { id } = req.params; // Extract employee ID from URL parameter

    const query = 'SELECT passportImage FROM Employees WHERE id = ?'; // SQL query to retrieve passportImage
    pool.query(query, [id], (err, results) => {
        if (err) {
            console.error('Error fetching data:', err);
            res.status(500).json({ error: 'Database query error' });
            return;
        }
        if (results.length === 0) {
            res.status(404).json({ error: 'Passport not found' });
            return;
        }
        const passportImage = results[0].passportImage; // Retrieve passportImage from query results

        // Set appropriate headers for file download
        res.setHeader('Content-Type', 'application/pdf'); // Set Content-Type as PDF
        res.setHeader('Content-Disposition', `attachment; filename=Passport_${id}.pdf`); // Set filename for download

        // Send the file content as response
        res.send(passportImage);
    });
});

// Endpoint to download a specific visa file based on employee ID
app.get('/api/download-visa/:id', isAuthenticated, (req, res) => {
    const dbName = req.session.user.dbName; // Get the database name from the session

    if (!dbName) {
        return res.status(401).json({ success: false, message: 'User not authenticated' });
    }

    const pool = getPool(dbName); // Get the correct connection pool

    const { id } = req.params; // Extract employee ID from URL parameter

    const query = 'SELECT visa FROM Employees WHERE id = ?'; // SQL query to retrieve visa
    pool.query(query, [id], (err, results) => {
        if (err) {
            console.error('Error fetching data:', err);
            res.status(500).json({ error: 'Database query error' });
            return;
        }
        if (results.length === 0) {
            res.status(404).json({ error: 'Visa not found' });
            return;
        }
        const visa = results[0].visa; // Retrieve visa from query results

        // Set appropriate headers for file download
        res.setHeader('Content-Type', 'application/pdf'); // Set Content-Type as PDF
        res.setHeader('Content-Disposition', `attachment; filename=Visa_${id}.pdf`); // Set filename for download

        // Send the file content as response
        res.send(visa);
    });
});

// DELETE endpoint to remove an employee and their system access
app.delete('/employee/:id', isAuthenticated, async (req, res) => {
    const dbName = req.session.user.dbName;

    if (!dbName) {
        return res.status(401).json({ success: false, message: 'User not authenticated' });
    }

    const pool = getPool(dbName);
    const { id } = req.params;
    const { ended } = req.body; // get date from frontend

    try {
        // First get employee email before updating
        const getEmployeeQuery = 'SELECT email FROM Employees WHERE id = ?';
        const [employeeRows] = await pool.promise().query(getEmployeeQuery, [id]);

        if (employeeRows.length === 0) {
            return res.status(404).json({ success: false, message: 'Employee not found' });
        }

        const employeeEmail = employeeRows[0].email;

        // Update employee situation and ended date
        const updateQuery = 'UPDATE Employees SET situation = ?, ended = ? WHERE id = ?';
        await pool.promise().query(updateQuery, ['past', ended, id]);

        // Delete from main users table if exists
        const deleteUserQuery = 'DELETE FROM users WHERE email = ?';
        const [result] = await mainPool.promise().query(deleteUserQuery, [employeeEmail]);

        if (result.affectedRows > 0) {
            console.log(`Removed user access for ${employeeEmail}`);
        }

        res.json({ 
            success: true, 
            message: 'Employee marked as past, leaving date stored, and system access removed'
        });

    } catch (err) {
        console.error('Error during employee status update:', err);
        res.status(500).json({ 
            success: false, 
            message: 'Server error during employee status update',
            error: process.env.NODE_ENV === 'development' ? err.message : undefined
        });
    }
});

// Function to Update Accrued Holidays
function updateAccruedHolidays(pool, callback) {
    // 1. Get holiday year settings
    pool.query('SELECT HolidayYearStart, HolidayYearEnd FROM HolidayYearSettings LIMIT 1', (err, yearSettings) => {
        if (err) return callback(err);
        if (!yearSettings || yearSettings.length === 0) {
            return callback(new Error('Holiday year settings not found'));
        }

        const holidayYearStart = new Date(yearSettings[0].HolidayYearStart);
        const holidayYearEnd = new Date(yearSettings[0].HolidayYearEnd);
        const currentDate = new Date();

        // Only run if current date is within holiday year
        if (currentDate < holidayYearStart || currentDate > holidayYearEnd) {
            return callback(null, { message: 'Not currently within holiday year - no updates made' });
        }

        // 2. Get all employees
        pool.query(`SELECT id, name, lastName, startHoliday, dateStart, Accrued FROM Employees WHERE situation IS NULL OR situation = ''`, (err, employees) => {
            if (err) return callback(err);

            let updatedCount = 0;
            const updatePromises = employees.map(employee => {
                return new Promise((resolve) => {
                    const employeeStartDate = new Date(employee.dateStart);
                    const startHoliday = parseFloat(employee.startHoliday) || 0;
                    let monthlyAccrual = 0;

                    if (employeeStartDate <= holidayYearStart) {
                        // Full year entitlement
                        monthlyAccrual = startHoliday / 12;
                    } else if (employeeStartDate <= holidayYearEnd) {
                        // Pro-rated for mid-year starters
                        const monthsRemaining = monthDiff(employeeStartDate, holidayYearEnd);
                        monthlyAccrual = monthsRemaining > 0 ? startHoliday / monthsRemaining : 0;
                    }

                    monthlyAccrual = Math.round(monthlyAccrual * 100) / 100;
                    const newAccrued = (parseFloat(employee.Accrued) || 0 + monthlyAccrual);

                    pool.query(
                        'UPDATE Employees SET Accrued = ? WHERE id = ?',
                        [newAccrued, employee.id],
                        (err) => {
                            if (err) {
                                console.error(`Error updating ${employee.name} ${employee.lastName}:`, err);
                                return resolve();
                            }
                            updatedCount++;
                            resolve();
                        }
                    );
                });
            });

            Promise.all(updatePromises)
                .then(() => callback(null, { 
                    message: `Successfully updated ${updatedCount} employees`,
                    updatedCount
                }))
                .catch(err => callback(err));
        });
    });
}

// Helper function to calculate months between dates
function monthDiff(startDate, endDate) {
    let months = (endDate.getFullYear() - startDate.getFullYear()) * 12;
    months -= startDate.getMonth();
    months += endDate.getMonth();
    return months <= 0 ? 0 : months + 1; // Include both start and end months
}

app.post('/update-accrued-holidays', isAuthenticated, isAdmin, (req, res) => {
    const dbName = req.session.user.dbName;
    if (!dbName) {
        return res.status(401).json({ success: false, message: 'User not authenticated' });
    }

    const pool = getPool(dbName);
    
    updateAccruedHolidays(pool, (err, result) => {
        if (err) {
            console.error('Error updating accrued holidays:', err);
            return res.status(500).json({ 
                success: false, 
                message: 'Error updating accrued holidays',
                error: process.env.NODE_ENV === 'development' ? err.message : undefined
            });
        }
        
        res.json({ 
            success: true, 
            message: result.message,
            updatedCount: result.updatedCount
        });
    });
});

// Route to serve the PersonalInfo.html file
app.get('/', isAuthenticated, isAdmin, (req, res) => {
    res.sendFile(path.join(__dirname, 'PersonalInfo.html'));
});

module.exports = app; // Export the entire Express application