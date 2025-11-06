const express = require('express');
const mysql = require('mysql2');
const bodyParser = require('body-parser');
const multer = require('multer');
const nodemailer = require('nodemailer');
const fs = require('fs');
const path = require('path');
const { PDFDocument, rgb } = require('pdf-lib');
const { getPool, mainPool } = require('./db.js'); // Import the connection pool functions
const pdf = require('html-pdf');
const { sessionMiddleware, isAuthenticated, isAdmin, isSupervisor, isUser } = require('./sessionConfig'); // Adjust the path as needed

const app = express();

// Middleware
app.use(sessionMiddleware);
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Endpoint to fetch all employees
app.get('/api/employees', isAuthenticated, (req, res) => {
    const dbName = req.session.user.dbName; // Get the database name from the session

    if (!dbName) {
        return res.status(401).json({ message: 'User not authenticated' });
    }

    const pool = getPool(dbName); // Get the correct connection pool

    const query = 'SELECT name, lastName, email FROM Employees';
    pool.query(query, (err, results) => {
        if (err) {
            console.error('Error fetching employees data:', err);
            res.status(500).json({ error: 'Database query error' });
            return;
        }
        res.json(results);
    });
});

// Multer configuration for file upload
const storage = multer.memoryStorage();
const upload = multer({ storage: storage });

// Endpoint to handle payslip upload
app.post('/api/upload-payslip', isAuthenticated, upload.single('payslip'), (req, res) => {
    const dbName = req.session.user.dbName; // Get the database name from the session

    if (!dbName) {
        return res.status(401).json({ message: 'User not authenticated' });
    }

    const pool = getPool(dbName); // Get the correct connection pool

    const { name, lastName, email } = req.body;
    const payslipFile = req.file;
    const uploadDate = new Date().toISOString().split('T')[0];

    if (!payslipFile) {
        return res.status(400).json({ error: 'No file uploaded' });
    }

    // Insert the payslip data into the payslips table
    const insertQuery = 'INSERT INTO payslips (name, lastName, email, fileContent, date) VALUES (?, ?, ?, ?, ?)';
    const values = [name, lastName, email, payslipFile.buffer, uploadDate];

    pool.query(insertQuery, values, (insertErr, insertResults) => {
        if (insertErr) {
            console.error('Error inserting payslip data:', insertErr);
            res.status(500).json({ error: 'Database insert error' });
            return;
        }
        res.json({ success: true, insertedId: insertResults.insertId });
    });
});

// Route to serve the InsertPayslip.html file
app.get('/', isAuthenticated, isAdmin, (req, res) => {
    res.sendFile(path.join(__dirname, 'InsertPayslip.html'));
});

module.exports = app; // Export the entire Express application