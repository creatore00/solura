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

// Endpoint to Retrieve Data
app.get('/employees', isAuthenticated, (req, res) => {
    const dbName = req.session.user.dbName;

    if (!dbName) {
        return res.status(401).json({ success: false, message: 'User not authenticated' });
    }

    const pool = getPool(dbName);

    const query = `
        SELECT id, name, lastName, email, phone, address, nin, wage, designation, 
               position, contractHours, Salary, SalaryPrice, dateStart, startHoliday, 
               passportImage, visa, TotalHoliday, Accrued, ended
        FROM Employees 
        WHERE situation = 'past'
        ORDER BY name, lastName
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

// Combined endpoint to download passport or visa file
app.get('/api/download-document/:id/:type', isAuthenticated, (req, res) => {
    const dbName = req.session.user.dbName;

    if (!dbName) {
        return res.status(401).json({ success: false, message: 'User not authenticated' });
    }

    const pool = getPool(dbName);
    const { id, type } = req.params;

    if (type !== 'passport' && type !== 'visa') {
        return res.status(400).json({ error: 'Invalid document type' });
    }

    const column = type === 'passport' ? 'passportImage' : 'visa';
    const query = `SELECT ${column} FROM Employees WHERE id = ?`;

    pool.query(query, [id], (err, results) => {
        if (err) {
            console.error('Error fetching document:', err);
            return res.status(500).json({ error: 'Database query error' });
        }
        
        if (results.length === 0 || !results[0][column]) {
            return res.status(404).json({ error: `${type} not found` });
        }

        const documentData = results[0][column];
        const filename = `${type.charAt(0).toUpperCase() + type.slice(1)}_${id}.pdf`;

        res.setHeader('Content-Type', 'application/pdf');
        res.setHeader('Content-Disposition', `attachment; filename=${filename}`);
        res.send(documentData);
    });
});

// Endpoint to restore employee (clear situation column)
app.post('/api/restore-employee/:id', isAuthenticated, (req, res) => {
    const dbName = req.session.user.dbName;

    if (!dbName) {
        return res.status(401).json({ success: false, message: 'User not authenticated' });
    }

    const pool = getPool(dbName);
    const { id } = req.params;

    const query = 'UPDATE Employees SET situation = NULL, ended = NULL WHERE id = ?';
    
    pool.query(query, [id], (err, results) => {
        if (err) {
            console.error('Error restoring employee:', err);
            return res.status(500).json({ 
                success: false, 
                message: 'Server error during restoration' 
            });
        }

        if (results.affectedRows === 0) {
            return res.status(404).json({ 
                success: false, 
                message: 'Employee not found' 
            });
        }

        res.json({ 
            success: true, 
            message: 'Employee restored successfully' 
        });
    });
});

// Route to serve the PersonalInfo.html file
app.get('/', isAuthenticated, isAdmin, (req, res) => {
    res.sendFile(path.join(__dirname, 'PastEmployees.html'));
});

module.exports = app; // Export the entire Express application