const express = require('express');
const mysql = require('mysql2');
const bodyParser = require('body-parser');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const nodemailer = require('nodemailer');
const { getPool, mainPool } = require('./db.js'); // Import the connection pool functions
const { sessionMiddleware, isAuthenticated, isAdmin } = require('./sessionConfig'); // Adjust the path as needed

const app = express();

// Middleware
app.use(sessionMiddleware);
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Function to send email
function sendEmail(recipients, message) {
    // Create a transporter
    const transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: {
            user: 'oxfordbbuona@gmail.com',
            pass: 'vkav xtuc ufwz sphn'
        }
    });

    // Setup email data
    const mailOptions = {
        from: 'oxfordbbuona@gmail.com',
        to: recipients.join(','), // Convert array of emails to comma-separated string
        subject: 'Updates on your Holiday Request',
        text: message // Include the message retrieved from the request body
    };

    // Send email
    transporter.sendMail(mailOptions, (error, info) => {
        if (error) {
            console.error('Error sending email:', error);
        } else {
            console.log('Email sent:', info.response);
        }
    });
}

// Route to get all holiday requests
app.get('/holidays', isAuthenticated, (req, res) => {
    const dbName = req.session.user.dbName; // Get the database name from the session

    if (!dbName) {
        return res.status(401).json({ success: false, message: 'User not authenticated' });
    }

    const pool = getPool(dbName); // Get the correct connection pool

    // Query the database to get holiday requests
    pool.query('SELECT * FROM Holiday', (err, results) => {
        if (err) {
            console.error('Error fetching holiday requests:', err);
            res.status(500).send('Error fetching holiday requests');
        } else {
            res.json(results); // Send holiday requests as JSON response
        }
    });
});

// Route to update a holiday request
app.post('/updateRequest/:id', isAuthenticated, (req, res) => {
    const dbName = req.session.user.dbName; // Get the database name from the session

    if (!dbName) {
        return res.status(401).json({ success: false, message: 'User not authenticated' });
    }

    const pool = getPool(dbName); // Get the correct connection pool

    const requestId = req.params.id;

    // Query to get the holiday request details
    const getHolidaySql = 'SELECT startDate, endDate, name, lastName FROM Holiday WHERE id = ?';
    pool.query(getHolidaySql, [requestId], (error, results) => {
        if (error) {
            console.error('Error fetching holiday details:', error);
            return res.sendStatus(500); // Send internal server error response
        }

        if (results.length === 0) {
            return res.status(404).send('Holiday request not found');
        }

        const holiday = results[0];
        const startDate = new Date(holiday.startDate);
        const endDate = new Date(holiday.endDate);
        const daysAccepted = (endDate - startDate) / (1000 * 60 * 60 * 24) + 1; // Calculate total days
        const name = holiday.name;
        const lastName = holiday.lastName;

        // Query to update the 'accepted' column
        const updateHolidaySql = 'UPDATE Holiday SET accepted = ? WHERE id = ?';
        const updateValues = ['Accepted', requestId];

        pool.query(updateHolidaySql, updateValues, (updateError) => {
            if (updateError) {
                console.error('Error accepting request:', updateError);
                return res.sendStatus(500); // Send internal server error response
            }

            // Query to update the 'TotalHoliday' column in the Employees table
            const getEmployeeSql = 'SELECT TotalHoliday FROM Employees WHERE name = ? AND lastName = ?';
            pool.query(getEmployeeSql, [name, lastName], (employeeError, employeeResults) => {
                if (employeeError) {
                    console.error('Error fetching employee details:', employeeError);
                    return res.sendStatus(500); // Send internal server error response
                }

                if (employeeResults.length === 0) {
                    return res.status(404).send('Employee not found');
                }

                const totalHolidayLeft = employeeResults[0].TotalHoliday;
                const updatedTotalHoliday = totalHolidayLeft - daysAccepted;

                const updateEmployeeSql = 'UPDATE Employees SET TotalHoliday = ? WHERE name = ? AND lastName = ?';
                pool.query(updateEmployeeSql, [updatedTotalHoliday, name, lastName], (updateEmployeeError) => {
                    if (updateEmployeeError) {
                        console.error('Error updating employee total holidays:', updateEmployeeError);
                        return res.sendStatus(500); // Send internal server error response
                    }

                    console.log('Total holidays updated successfully');
                    res.sendStatus(200); // Send success response
                });
            });
        });
    });
});

// Route to delete a holiday request
app.post('/deleteRequest/:id', isAuthenticated, (req, res) => {
    const dbName = req.session.user.dbName; // Get the database name from the session

    if (!dbName) {
        return res.status(401).json({ success: false, message: 'User not authenticated' });
    }

    const pool = getPool(dbName); // Get the correct connection pool

    const requestId = req.params.id;
    const message = req.body.message;
    const name = req.body.name;
    const lastName = req.body.lastName;

    // Delete the row from the database for the specified request ID
    const sql = 'DELETE FROM Holiday WHERE id = ?';
    // Execute the SQL query
    pool.query(sql, [requestId], (error, results) => {
        if (error) {
            console.error('Error deleting request:', error);
            res.sendStatus(500); // Send internal server error response
        } else {
            console.log('Request deleted successfully');
            res.sendStatus(200); // Send success response

            // Get email addresses from the database based on employee name and last name
            pool.query('SELECT email FROM Employees WHERE name = ? AND lastName = ?', [name, lastName], (emailErr, emailResults) => {
                if (emailErr) {
                    console.error('Error fetching emails from the database:', emailErr);
                    return res.status(500).send('Error sending emails');
                }

                const recipients = emailResults.map(row => row.email);

                // Send email to recipients
                sendEmail(recipients, message);
            });
        }
    });
});

// Route to serve the Request.html file
app.get('/', isAuthenticated, isAdmin, (req, res) => {
    res.sendFile(path.join(__dirname, 'Request.html'));
});

module.exports = app; // Export the entire Express application