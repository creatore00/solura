// Import required modules
const express = require('express');
const mysql = require('mysql2');
const nodemailer = require('nodemailer');
const bodyParser = require('body-parser');
const path = require('path');
const { getPool, mainPool } = require('./db.js'); // Import the connection pool functions
const { sessionMiddleware, isAuthenticated, isAdmin, isSupervisor, isUser } = require('./sessionConfig'); // Adjust the path as needed

const app = express();

// Middleware
app.use(sessionMiddleware);
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Configure the email transporter
const transporter = nodemailer.createTransport({
    host: 'smtp0001.neo.space', // Your SMTP Host
    port: 465, // SSL Port
    secure: true, // `true` for SSL (port 465)
    auth: {
        user: 'no-reply@solura.uk',
        pass: 'Salvemini01@'
    }
});
// Route to submit a holiday request
app.post('/submitHolidayRequest', isAuthenticated, (req, res) => {
    const dbName = req.session.user.dbName;

    if (!dbName) {
        return res.status(401).json({ message: 'User not authenticated' });
    }

    const pool = getPool(dbName);

    const { startDate, endDate } = req.body;
    const { email, name, lastName } = req.session.user;
    const today = new Date();
    const fourteenDaysLater = new Date(today);
    fourteenDaysLater.setDate(today.getDate() + 14);

    const start = new Date(startDate);
    const end = new Date(endDate);
    const maxEndDate = new Date(start);
    maxEndDate.setDate(start.getDate() + 13);

    // Calculate days including both start and end dates
    const daysDiff = Math.floor((end - start) / (1000 * 60 * 60 * 24)) + 1;

    if (start < fourteenDaysLater) {
        return res.status(400).json({ success: false, message: 'Holiday requests must be made at least 14 days in advance.' });
    }

    if (end > maxEndDate) {
        return res.status(400).json({ success: false, message: 'Holiday requests can be for a maximum of two consecutive weeks.' });
    }

    const requestDate = new Date().toISOString().slice(0, 19).replace('T', ' ');

    // Include email in the INSERT statement
    const sql = 'INSERT INTO Holiday (name, lastName, startDate, endDate, requestDate, days) VALUES (?, ?, ?, ?, ?, ?)';
    const values = [name, lastName, startDate, endDate, requestDate, daysDiff];

    pool.query(sql, values, async (error, results) => {
        if (error) {
            console.error('Error submitting holiday request:', error);
            return res.status(500).json({ success: false, message: 'Error submitting holiday request' });
        }

        console.log('Holiday request submitted successfully');
        try {
            await sendEmailNotification(dbName, email, name, startDate, endDate, daysDiff);
            return res.json({ 
                success: true, 
                message: 'Holiday request submitted successfully',
                daysRequested: daysDiff,
                requestDate: requestDate
            });
        } catch (emailError) {
            console.error('Email notification failed:', emailError);
            return res.json({
                success: true,
                message: 'Holiday submitted but email notification failed',
                daysRequested: daysDiff,
                requestDate: requestDate
            });
        }
    });
});
// Improved email function
async function getAllEmails(dbName) {
    const pool = getPool(dbName);
    const query = 'SELECT email FROM Employees WHERE position = "manager"'; // Only active users
    const [results] = await pool.promise().query(query);
    return results.map(row => row.email);
}
// Improved email notification function
async function sendEmailNotification(dbName, requesterEmail, requesterName, startDate, endDate, days) {
    try {
        const emails = await getAllEmails(dbName);
        if (!emails.length) return;

        const mailOptions = {
            from: 'Solura WorkForce <no-reply@solura.uk>',
            to: emails.join(', '),
            subject: 'New Holiday Request Submitted',
            text: `A new holiday request has been submitted by ${requesterName} (${requesterEmail}).\n\n` +
                  `Dates: ${startDate} to ${endDate}\n` +
                  `Total days: ${days}\n\n` +
                  `Please review the request in the system.`,
            html: `<p>A new holiday request has been submitted by <strong>${requesterName}</strong> (${requesterEmail}).</p>
                   <p><strong>Dates:</strong> ${startDate} to ${endDate}</p>
                   <p><strong>Total days:</strong> ${days}</p>
                   <p>Please review the request in the system.</p>`
        };

        const info = await transporter.sendMail(mailOptions);
        console.log('Email sent:', info.response);
        return info;
    } catch (error) {
        console.error('Error sending email notification:', error);
        throw error;
    }
}
// Route to serve the Holidays.html file
app.get('/', isAuthenticated, (req, res) => {
    if (req.session.user.role === 'admin') {
        res.sendFile(path.join(__dirname, 'Holidays.html'));
    } else if (req.session.user.role === 'supervisor') {
        res.sendFile(path.join(__dirname, 'Holidays.html'));
    } else if (req.session.user.role === 'user') {
        res.sendFile(path.join(__dirname, 'Holidays.html'));
    } else {
        res.status(403).json({ error: 'Access denied' });
    }
});

module.exports = app; // Export the entire Express application