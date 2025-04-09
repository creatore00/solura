const express = require('express');
const bodyParser = require('body-parser');
const { getPool, mainPool } = require('./db.js'); // Import the connection pool functions
const path = require('path');
const { sessionMiddleware, isAuthenticated, isAdmin, isSupervisor, isUser } = require('./sessionConfig'); // Adjust the path as needed

const app = express();

// Middleware
app.use(sessionMiddleware);
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Endpoint to fetch payslips data
app.get('/api/payslips', isAuthenticated, (req, res) => {
    const dbName = req.session.user.dbName; // Get the database name from the session

    if (!dbName) {
        return res.status(401).json({ message: 'User not authenticated' });
    }

    const pool = getPool(dbName); // Get the correct connection pool

    const email = req.session.user.email;
    const query = 'SELECT * FROM payslips WHERE email = ?';
    pool.query(query, [email], (err, results) => {
        if (err) {
            console.error('Error fetching data:', err);
            return res.status(500).json({ error: 'Database query error' });
        }
        res.json(results);
    });
});

// Endpoint to download a specific payslip file
app.get('/api/download-file/:id', isAuthenticated, (req, res) => {
    const dbName = req.session.user.dbName; // Get the database name from the session

    if (!dbName) {
        return res.status(401).json({ message: 'User not authenticated' });
    }

    const pool = getPool(dbName); // Get the correct connection pool

    const payslipId = req.params.id;
    const query = 'SELECT fileContent FROM payslips WHERE id = ?'; // Only retrieve fileContent
    pool.query(query, [payslipId], (err, results) => {
        if (err) {
            console.error('Error fetching data:', err);
            res.status(500).json({ error: 'Database query error' });
            return;
        }
        if (results.length === 0) {
            res.status(404).json({ error: 'Payslip not found' });
            return;
        }
        const payslip = results[0];
        const fileContent = payslip.fileContent;

        // Set appropriate headers for file download
        res.setHeader('Content-Type', 'application/pdf'); // Default to octet-stream if MIME type is unknown
        res.setHeader('Content-Disposition', `attachment; filename=Payslip_${payslipId}.pdf`); // Set default filename extension to PDF

        // Send the file content as response
        res.send(fileContent);
    });
});

// Route to serve the PastPayslips.html file
app.get('/', isAuthenticated, (req, res) => {
    if (req.session.user.role === 'admin') {
        res.sendFile(path.join(__dirname, '/PastPayslips.html'));
    } else if (req.session.user.role === 'supervisor') {
        res.sendFile(path.join(__dirname, '/PastPayslips.html'));
    } else if (req.session.user.role === 'user') {
        res.sendFile(path.join(__dirname, '/PastPayslips.html'));
    } else {
        res.status(403).json({ error: 'Access denied' });
    }
});

module.exports = app; // Export the entire Express application