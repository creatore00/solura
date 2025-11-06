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
            host: 'smtp0001.neo.space', // Your SMTP Host
            port: 465, // SSL Port
            secure: true, // `true` for SSL (port 465)
            auth: {
                user: 'no-reply@solura.uk',
                pass: 'Salvemini01@'
            }
        });

    // Setup email data
    const mailOptions = {
        from: 'Solura WorkForce <no-reply@solura.uk>',
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

// Route to get all holiday requests with employee emails
app.get('/holidays', isAuthenticated, (req, res) => {
    const dbName = req.session.user.dbName; // Get the database name from the session

    if (!dbName) {
        return res.status(401).json({ success: false, message: 'User not authenticated' });
    }

    const pool = getPool(dbName); // Get the correct connection pool

    // Query the database to get holiday requests with employee emails
    pool.query(`
        SELECT 
            h.*, 
            e.email 
        FROM 
            Holiday h
        JOIN 
            Employees e ON h.name = e.name AND h.lastName = e.lastName
        ORDER BY 
            h.requestDate DESC
    `, (err, results) => {
        if (err) {
            console.error('Error fetching holiday requests:', err);
            res.status(500).send('Error fetching holiday requests');
        } else {
            res.json(results); // Send holiday requests with emails as JSON response
        }
    });
});

// Route to update a holiday request
app.post('/updateRequest/:id', isAuthenticated, async (req, res) => {
    const dbName = req.session.user.dbName;
    const userEmail = req.session.user.email;

    if (!dbName || !userEmail) {
        return res.status(401).json({ success: false, message: 'User not authenticated' });
    }

    const pool = getPool(dbName).promise();
    const requestId = req.params.id;

    try {
        // Get holiday details
        const [holidayResults] = await pool.query(
            'SELECT startDate, endDate, name, lastName FROM Holiday WHERE id = ?',
            [requestId]
        );

        if (holidayResults.length === 0) {
            return res.status(404).send('Holiday request not found');
        }

        const holiday = holidayResults[0];
        const startDate = new Date(holiday.startDate);
        const endDate = new Date(holiday.endDate);
        const daysAccepted = (endDate - startDate) / (1000 * 60 * 60 * 24) + 1;

        const employeeName = holiday.name;
        const employeeLastName = holiday.lastName;

        // Get approver name from session email
        const [approverResults] = await pool.query(
            'SELECT name, lastName FROM Employees WHERE email = ?',
            [userEmail]
        );

        if (approverResults.length === 0) {
            return res.status(404).send('Approver not found');
        }

        const who = `${approverResults[0].name} ${approverResults[0].lastName}`;

        // Update holiday to accepted
        await pool.query(
            'UPDATE Holiday SET accepted = ?, who = ? WHERE id = ?',
            ['true', who, requestId]
        );

        // Get employee's remaining holiday
        const [employeeData] = await pool.query(
            'SELECT TotalHoliday FROM Employees WHERE name = ? AND lastName = ?',
            [employeeName, employeeLastName]
        );

        if (employeeData.length === 0) {
            return res.status(404).send('Employee not found');
        }

        const totalHolidayLeft = employeeData[0].TotalHoliday;
        const updatedTotalHoliday = totalHolidayLeft - daysAccepted;

        // Update employee's remaining holiday
        await pool.query(
            'UPDATE Employees SET TotalHoliday = ? WHERE name = ? AND lastName = ?',
            [updatedTotalHoliday, employeeName, employeeLastName]
        );

        console.log('Holiday request approved and total holidays updated');
        res.sendStatus(200);
    } catch (error) {
        console.error('Error processing holiday request:', error);
        res.sendStatus(500);
    }
});

// In your deleteRequest route
app.post('/deleteRequest/:id', isAuthenticated, (req, res) => {
    const dbName = req.session.user.dbName;
    if (!dbName) {
        return res.status(401).json({ success: false, message: 'User not authenticated' });
    }

    const pool = getPool(dbName);
    const requestId = req.params.id;
    const { message, name, lastName, declineReason } = req.body;

    // First update the request with decline reason before deleting
    const updateSql = 'UPDATE Holiday SET accepted = "declined", declineReason = ? WHERE id = ?';
    pool.query(updateSql, [declineReason, requestId], (updateError) => {
        if (updateError) {
            console.error('Error updating request with decline reason:', updateError);
            return res.sendStatus(500);
        }

        // Then delete the request
        const deleteSql = 'DELETE FROM Holiday WHERE id = ?';
        pool.query(deleteSql, [requestId], (deleteError) => {
            if (deleteError) {
                console.error('Error deleting request:', deleteError);
                return res.sendStatus(500);
            }

            console.log('Request declined and deleted successfully');
            res.sendStatus(200);

            // Send email notification
            pool.query('SELECT email FROM Employees WHERE name = ? AND lastName = ?', 
                [name, lastName], (emailErr, emailResults) => {
                    if (emailErr) {
                        console.error('Error fetching emails:', emailErr);
                        return;
                    }
                    
                    const recipients = emailResults.map(row => row.email);
                    const emailMessage = `Your holiday request has been declined.\n\nReason: ${message}`;
                    sendEmail(recipients, emailMessage);
                });
        });
    });
});

// Route to serve the Request.html file
app.get('/', isAuthenticated, isAdmin, (req, res) => {
    res.sendFile(path.join(__dirname, 'Request.html'));
});

module.exports = app; // Export the entire Express application