// Import required modules
const express = require('express');
const mysql = require('mysql2');
const nodemailer = require('nodemailer');
const bodyParser = require('body-parser');
const multer = require('multer');
const path = require('path');
const fs = require('fs'); // Added fs module for file system operations
const { getPool, mainPool } = require('./db.js'); // Import the connection pool functions
const { sessionMiddleware, isAuthenticated, isAdmin, isSupervisor, isUser } = require('./sessionConfig'); // Adjust the path as needed
const app = express();

// Middleware
app.use(sessionMiddleware);
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(bodyParser.json()); // Parse JSON request bodies

// List of tables to exclude
const excludedTables = ['sessions', 'comments', 'Sessions', 'payslips', 'users', 'forecast', 'rota', 'Holiday'];

// Configure Multer for file uploads
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        const uploadDir = './uploads';
        if (!fs.existsSync(uploadDir)) {
            fs.mkdirSync(uploadDir);
        }
        cb(null, uploadDir);
    },
    filename: function (req, file, cb) {
        cb(null, file.fieldname + '-' + Date.now() + path.extname(file.originalname));
    }
});

const upload = multer({ storage: storage });

// Retrieve the list of tables
app.get('/tables', isAuthenticated, (req, res) => {
    const dbName = req.session.user.dbName; // Get the database name from the session

    if (!dbName) {
        return res.status(401).json({ message: 'User not authenticated' });
    }

    const pool = getPool(dbName); // Get the correct connection pool

    pool.query('SHOW TABLES', (err, tables) => {
        if (err) {
            console.error('Error retrieving tables: ' + err.stack);
            res.status(500).send('Error retrieving tables');
            return;
        }

        const tableNames = tables
            .map(tableObj => tableObj[`Tables_in_${dbName}`])
            .filter(tableName => !excludedTables.includes(tableName)); // Exclude specific tables

        res.json(tableNames);
    });
});

// Retrieve data from a specific table
app.get('/table/:tableName', isAuthenticated, (req, res) => {
    const dbName = req.session.user.dbName; // Get the database name from the session
    const tableName = req.params.tableName;

    if (!dbName) {
        return res.status(401).json({ message: 'User not authenticated' });
    }

    const pool = getPool(dbName); // Get the correct connection pool

    // Check if the table is excluded
    if (excludedTables.includes(tableName)) {
        res.status(400).send('This table is excluded');
        return;
    }

    pool.query(`SELECT * FROM ${tableName}`, (err, results) => {
        if (err) {
            console.error(`Error retrieving data from ${tableName}: ` + err.stack);
            res.status(500).send(`Error retrieving data from ${tableName}`);
            return;
        }

        res.json(results);
    });
});

// Update a specific cell in the table
app.post('/table/:tableName/update', isAuthenticated, (req, res) => {
    const dbName = req.session.user.dbName; // Get the database name from the session
    const tableName = req.params.tableName;
    const { primaryKey, primaryKeyValue, column, value } = req.body;

    if (!dbName) {
        return res.status(401).json({ message: 'User not authenticated' });
    }

    const pool = getPool(dbName); // Get the correct connection pool

    // Check if the table is excluded
    if (excludedTables.includes(tableName)) {
        res.status(400).send('This table is excluded');
        return;
    }

    const sql = `UPDATE ?? SET ?? = ? WHERE ?? = ?`;
    const inserts = [tableName, column, value, primaryKey, primaryKeyValue];
    pool.query(mysql.format(sql, inserts), (err, results) => {
        if (err) {
            console.error(`Error updating data in ${tableName}: ` + err.stack);
            res.status(500).send(`Error updating data in ${tableName}`);
            return;
        }

        res.json({ success: true });
    });
});

// Upload or update a PDF file in the table
app.post('/table/:tableName/upload', isAuthenticated, upload.single('pdf'), (req, res) => {
    const dbName = req.session.user.dbName; // Get the database name from the session
    const tableName = req.params.tableName;
    const { primaryKey, primaryKeyValue, column } = req.body;

    if (!dbName) {
        return res.status(401).json({ message: 'User not authenticated' });
    }

    const pool = getPool(dbName); // Get the correct connection pool

    // Check if the table is excluded
    if (excludedTables.includes(tableName)) {
        res.status(400).send('This table is excluded');
        return;
    }

    const filePath = req.file.path;
    const sql = `UPDATE ?? SET ?? = ? WHERE ?? = ?`;
    const inserts = [tableName, column, filePath, primaryKey, primaryKeyValue];
    pool.query(mysql.format(sql, inserts), (err, results) => {
        if (err) {
            console.error(`Error updating data in ${tableName}: ` + err.stack);
            res.status(500).send(`Error updating data in ${tableName}`);
            return;
        }

        res.json({ success: true, filePath });
    });
});

// Delete a PDF file from the table
app.post('/table/:tableName/delete', isAuthenticated, (req, res) => {
    const dbName = req.session.user.dbName; // Get the database name from the session
    const tableName = req.params.tableName;
    const { primaryKey, primaryKeyValue, column } = req.body;

    if (!dbName) {
        return res.status(401).json({ message: 'User not authenticated' });
    }

    const pool = getPool(dbName); // Get the correct connection pool

    // Check if the table is excluded
    if (excludedTables.includes(tableName)) {
        res.status(400).send('This table is excluded');
        return;
    }

    const sql = `UPDATE ?? SET ?? = NULL WHERE ?? = ?`;
    const inserts = [tableName, column, primaryKey, primaryKeyValue];
    pool.query(mysql.format(sql, inserts), (err, results) => {
        if (err) {
            console.error(`Error deleting file in ${tableName}: ` + err.stack);
            res.status(500).send(`Error deleting file in ${tableName}`);
            return;
        }

        res.json({ success: true });
    });
});

// Serve the uploaded files
app.use('/uploads', express.static('uploads'));

// Route to serve the Modify.html file
app.get('/', isAuthenticated, isAdmin, (req, res) => {
    res.sendFile(path.join(__dirname, 'Modify.html'));
});

module.exports = app; // Export the entire Express application