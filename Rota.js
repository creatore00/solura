const nodemailer = require('nodemailer');
const http = require('http');
const fs = require('fs');
const pdf = require('html-pdf');
const ejs = require('ejs');
const mysql = require('mysql2');
const path = require('path');
const express = require('express');
const puppeteer = require('puppeteer');
const bodyParser = require('body-parser');
const { v4: uuidv4 } = require('uuid');
const { getPool, mainPool } = require('./db.js'); // Import the connection pool functions
const { sessionMiddleware, isAuthenticated, isAdmin } = require('./sessionConfig'); // Adjust the path as needed

const app = express();

// Middleware
app.use(sessionMiddleware);
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));  

// Function to generate PDF to be sent as Email
const generatePDF = async (tableData) => {
    // Define the mapping of specific RGB colors to designations
    const colorToDesignation = {
        'rgb(255, 250, 205)': 'BOH', // Light yellow
        'rgb(173, 216, 230)': 'FOH', // Light blue
    };

    // Function to sort days to start from Monday
    const sortDaysByWeek = (dates) => {
        const weekOrder = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday'];
        return dates.sort((a, b) => {
            const dayA = a.match(/\((\w+)\)$/)?.[1];
            const dayB = b.match(/\((\w+)\)$/)?.[1];
            return weekOrder.indexOf(dayA) - weekOrder.indexOf(dayB);
        });
    };

    // Extract unique dates from tableData and sort them by week starting on Monday
    let weekDates = [...new Set(tableData.map(row => row.day))];
    weekDates = sortDaysByWeek(weekDates);

    // Group tableData by role and adjust designation based on color
    const groupedData = tableData.reduce((acc, row) => {
        const match = row.day.match(/\((\w+)\)$/);
        const dayOfWeek = match ? match[1] : null;

        if (!dayOfWeek) {
            console.warn(`Invalid day format: ${row.day}`);
            return acc;
        }

        // Determine the designation based on color
        const adjustedDesignation = colorToDesignation[row.color] || row.designation;

        if (!acc[adjustedDesignation]) {
            acc[adjustedDesignation] = {};
        }

        if (!acc[adjustedDesignation][row.name]) {
            acc[adjustedDesignation][row.name] = {
                lastName: row.lastName,
                days: {},
            };
        }

        if (!acc[adjustedDesignation][row.name].days[row.day]) {
            acc[adjustedDesignation][row.name].days[row.day] = [];
        }

        // Format time to `hh:mm`
        const formatTime = (time) => {
            const [hours, minutes] = time.split(':');
            return `${hours.padStart(2, '0')}:${minutes.padStart(2, '0')}`;
        };

        acc[adjustedDesignation][row.name].days[row.day].push({
            startTime: formatTime(row.startTime),
            endTime: formatTime(row.endTime),
        });

        return acc;
    }, {});

    // Generate HTML content
    const htmlContent = `
    <html>
    <head>
    <style>
        table { width: 100%; border-collapse: collapse; }
        th, td { border: 1px solid #ddd; text-transform: uppercase; }
        th { background-color: #f2f2f2; text-align: center; padding: 8px; }
        td:not(:nth-child(1)):not(:nth-child(2)) { text-align: center; }
        td:nth-child(1), td:nth-child(2) { padding: 8px; }
        .role-header { background-color: #add8e6; text-align: center; font-weight: bold; padding: 10px; }
    </style>
    </head>
    <body>
    ${Object.entries(groupedData).map(([role, employees]) => `
        <div>
            <div class="role-header">${role}</div>
            <table>
                <thead>
                    <tr>
                        <th>NAME</th>
                        <th>LASTNAME</th>
                        ${weekDates.map(date => `<th>${date}</th>`).join('')}
                    </tr>
                </thead>
                <tbody>
                    ${Object.entries(employees).map(([name, data]) => `
                        <tr>
                            <td>${name}</td>
                            <td>${data.lastName}</td>
                            ${weekDates.map(day => `
                                <td>
                                    ${(data.days[day] || []).map(shift => `
                                        ${shift.startTime} - ${shift.endTime}
                                    `).join('<br>') || ''}
                                </td>
                            `).join('')}
                        </tr>
                    `).join('')}
                </tbody>
            </table>
        </div>
    `).join('')}
    </body>
    </html>
    `;

    // Generate PDF with landscape orientation
        try {            
            const launchOptions = {
                args: [
                    '--no-sandbox',
                    '--disable-setuid-sandbox',
                    '--disable-dev-shm-usage',
                    '--disable-accelerated-2d-canvas',
                    '--no-first-run',
                    '--no-zygote',
                    '--single-process',
                    '--disable-gpu'
                ],
                headless: 'new',
                executablePath: process.env.CHROME_BIN || undefined
            };
    
            const browser = await puppeteer.launch(launchOptions);
            
            const page = await browser.newPage();
            await page.setContent(htmlContent, { waitUntil: 'networkidle0' });
            
            const pdfBuffer = await page.pdf({ 
                format: 'A4', 
                landscape: true,
                printBackground: true
            });

            await browser.close();
            return pdfBuffer;
        } catch (error) {
            console.error("PDF Generation Error:", error);
            throw error;
        }
};

// Update submitData to include PDF generation and email sending
app.post('/submitData', isAuthenticated, async (req, res) => {
    const dbName = req.session.user.dbName;
    if (!dbName) {
        return res.status(401).json({ success: false, message: 'User not authenticated' });
    }

    const pool = getPool(dbName);
    const tableData = req.body;

    try {
        // 1. First process all database operations
        await processDatabaseOperations(pool, tableData);

        // 2. Generate PDF
        const pdfBuffer = await generatePDF(tableData);
        console.log('PDF generated successfully');

        // 3. Get recipient emails and send
        const [results] = await pool.promise().query('SELECT email FROM Employees WHERE email = "yassir.nini27@gmail.com"');
        const emailAddresses = results.map(result => result.email);
        
        await sendEmail(pdfBuffer, emailAddresses);
        console.log('Emails sent successfully');

        res.status(200).send('Rota saved and emails sent successfully!');
    } catch (error) {
        console.error('Error in /submitData:', error);
        res.status(500).send('Error processing request: ' + error.message);
    }
});

// Helper function to process database operations
async function processDatabaseOperations(pool, tableData) {
    const updateQuery = `UPDATE rota SET wage = ?, designation = ?, color = ? 
                       WHERE name = ? AND lastName = ? AND day = ? AND startTime = ? AND endTime = ?`;
    const insertQuery = `INSERT INTO rota (id, name, lastName, wage, day, startTime, endTime, designation, color) 
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`;

    for (const row of tableData) {
        const { name, lastName, wage, designation, day, startTime, endTime, color } = row;

        // Check if record exists
        const [existing] = await pool.promise().query(
            'SELECT id FROM rota WHERE name = ? AND lastName = ? AND day = ? AND startTime = ? AND endTime = ?',
            [name, lastName, day, startTime, endTime]
        );

        if (existing.length > 0) {
            await pool.promise().query(updateQuery, 
                [wage, designation, color, name, lastName, day, startTime, endTime]);
            console.log(`Updated: ${name} ${lastName} (${day})`);
        } else {
            const newId = await generateUniqueId(pool);
            await pool.promise().query(insertQuery,
                [newId, name, lastName, wage, day, startTime, endTime, designation, color]);
            console.log(`Inserted: ${name} ${lastName} (${day})`);
        }
    }
}

// Helper function to generate unique ID
async function generateUniqueId(pool) {
    let id;
    do {
        id = crypto.randomBytes(4).toString('hex');
        const [existing] = await pool.promise().query('SELECT id FROM rota WHERE id = ?', [id]);
        if (existing.length === 0) return id;
    } while (true);
}

// Modified sendEmail function (make it return a promise)
const sendEmail = (pdfBuffer, emailAddresses) => {
    const transporter = nodemailer.createTransport({
        host: 'smtp0001.neo.space',
        port: 465,
        secure: true,
        auth: {
            user: 'founder@solura.uk',
            pass: 'Salvemini01@'
        }
    });

    const sendPromises = emailAddresses.map(email => {
        const mailOptions = {
            from: 'Solura WorkForce <founder@solura.uk>',
            to: email,
            subject: 'Your Weekly Work Schedule',
            text: `Hello,\n\nAttached is your rota for the upcoming week.\n\nBest regards,\nManagement Team`,
            attachments: [{
                filename: 'Weekly_Rota.pdf',
                content: pdfBuffer
            }]
        };

        return transporter.sendMail(mailOptions)
            .then(() => console.log(`Email sent to ${email}`))
            .catch(err => {
                console.error(`Failed to send to ${email}:`, err);
                throw err; // Rethrow to catch in the main flow
            });
    });

    return Promise.all(sendPromises);
};

// Function to generate a unique 16-digit ID
function generateUniqueId() {
    return Math.floor(1000000000000000 + Math.random() * 9000000000000000).toString();
}

// Function to retrieve previous week's rota data for entire week
app.get('/get-previous-week-rota', (req, res) => {
    const dbName = req.session.user.dbName;
    const { prevWeek } = req.query;
    const pool = getPool(dbName);

    // Extract the Monday date from the formatted string "dd/mm/yyyy (Monday)"
    const datePart = prevWeek.split(' (')[0];
    const [day, month, year] = datePart.split('/');
    
    // Create Date object for Monday of previous week
    const mondayDate = new Date(`${year}-${month}-${day}`);
    
    // Calculate Sunday of the same week (6 days after Monday)
    const sundayDate = new Date(mondayDate);
    sundayDate.setDate(mondayDate.getDate() + 6);

    // Format dates to match database format (dd/mm/yyyy)
    const formatToDB = (date) => {
        const dd = String(date.getDate()).padStart(2, '0');
        const mm = String(date.getMonth() + 1).padStart(2, '0');
        const yyyy = date.getFullYear();
        return `${dd}/${mm}/${yyyy}`;
    };

    // Get all days between Monday and Sunday in db format
    const days = [];
    for (let d = new Date(mondayDate); d <= sundayDate; d.setDate(d.getDate() + 1)) {
        days.push(formatToDB(d));
    }

    pool.query(
        `SELECT name, lastName, wage, day, startTime, endTime, designation, color
         FROM rota 
         WHERE SUBSTRING_INDEX(day, ' (', 1) IN (?)`,
        [days],
        (err, results) => {
            if (err) {
                console.error('Error fetching previous week rota:', err);
                return res.status(500).json({ 
                    success: false, 
                    message: 'Failed to fetch previous week rota' 
                });
            }

            res.json({ 
                success: true,
                data: results 
            });
        }
    );
});

// Function to insert previous week's rota data into new week
app.post('/insert-copied-rota', (req, res) => {
    const dbName = req.session.user.dbName;
    const { currentWeek, rotaData } = req.body;
    const pool = getPool(dbName);

    // Extract the Monday date from currentWeek (format: "dd/mm/yyyy (Monday)")
    const mondayDate = currentWeek.split(' (')[0];
    const [day, month, year] = mondayDate.split('/');

    // Calculate date range for the full current week (Monday to Sunday)
    const startDate = new Date(`${year}-${month}-${day}`);
    const endDate = new Date(startDate);
    endDate.setDate(startDate.getDate() + 6);

    // Format dates for SQL query (dd/mm/yyyy)
    const formatDateForQuery = (date) => {
        const dd = String(date.getDate()).padStart(2, '0');
        const mm = String(date.getMonth() + 1).padStart(2, '0');
        const yyyy = date.getFullYear();
        return `${dd}/${mm}/${yyyy}`;
    };

    // First delete existing entries for the entire current week
    pool.query(
        `DELETE FROM rota 
         WHERE SUBSTRING_INDEX(day, ' (', 1) 
         BETWEEN ? AND ?`,
        [formatDateForQuery(startDate), formatDateForQuery(endDate)],
        (deleteErr, deleteResult) => {
            if (deleteErr) {
                console.error('Error deleting existing entries:', deleteErr);
                return res.status(500).json({ 
                    success: false, 
                    message: 'Delete operation failed' 
                });
            }

            console.log(`Deleted ${deleteResult.affectedRows} existing entries`);

            if (rotaData.length === 0) {
                return res.json({ success: true });
            }

            let completed = 0;
            let hasError = false;

            // Function to check if ID exists
            const checkIdExists = (id, callback) => {
                pool.query(
                    'SELECT id FROM rota WHERE id = ?',
                    [id],
                    (err, results) => {
                        if (err) return callback(err);
                        callback(null, results.length > 0);
                    }
                );
            };

            // Function to insert entry with unique ID and proper date mapping
            const insertEntryWithUniqueId = (entry, callback) => {
                // Extract day name from original entry (e.g., "Monday")
                const dayName = entry.day.match(/\(([^)]+)\)/)[1];
                
                // Calculate the corresponding date in the current week
                const currentWeekDay = new Date(startDate);
                const dayOffset = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']
                    .indexOf(dayName);
                
                currentWeekDay.setDate(startDate.getDate() + dayOffset);
                
                // Format the new date with day name (dd/mm/yyyy (Dayname))
                const formattedDate = formatDate(currentWeekDay);
                const newDay = `${formattedDate} (${dayName})`;

                const attemptInsert = () => {
                    const newId = generateUniqueId();
                    
                    checkIdExists(newId, (err, exists) => {
                        if (err) return callback(err);
                        
                        if (exists) {
                            // If ID exists, try again
                            return attemptInsert();
                        }

                        // Insert with the unique ID and properly mapped date
                        pool.query(
                            `INSERT INTO rota
                            (id, name, lastName, wage, designation, day, startTime, endTime, color) 
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
                            [
                                newId,
                                entry.name,
                                entry.lastName,
                                entry.wage,
                                entry.designation,
                                newDay,
                                entry.startTime,
                                entry.endTime,
                                entry.color
                            ],
                            (insertErr) => {
                                if (insertErr) return callback(insertErr);
                                callback(null);
                            }
                        );
                    });
                };

                attemptInsert();
            };

            // Process all entries
            rotaData.forEach(entry => {
                insertEntryWithUniqueId(entry, (err) => {
                    if (hasError) return;

                    if (err) {
                        hasError = true;
                        console.error('Error inserting entry:', err);
                        return res.status(500).json({ 
                            success: false, 
                            message: 'Insert operation failed' 
                        });
                    }

                    completed++;
                    if (completed === rotaData.length) {
                        res.json({ success: true });
                    }
                });
            });
        }
    );
});

// Helper function to format date for SQL query
function formatDateForQuery(date) {
    const dd = String(date.getDate()).padStart(2, '0');
    const mm = String(date.getMonth() + 1).padStart(2, '0');
    const yyyy = date.getFullYear();
    return `${dd}/${mm}/${yyyy}`;
}

// Function to generate a unique 16-digit ID
function generateUniqueId() {
    return Math.floor(1000000000000000 + Math.random() * 9000000000000000).toString();
}

// Helper function to format date as dd/mm/yyyy
function formatDate(date) {
    const day = String(date.getDate()).padStart(2, '0');
    const month = String(date.getMonth() + 1).padStart(2, '0');
    const year = date.getFullYear();
    return `${day}/${month}/${year}`;
}

// Function to Save new Data into db
app.post('/saveData', isAuthenticated, (req, res) => {
    const dbName = req.session.user.dbName; // Get the database name from the session

    if (!dbName) {
        return res.status(401).json({ success: false, message: 'User not authenticated' });
    }

    const pool = getPool(dbName); // Get the correct connection pool

    console.log('Request Body:', req.body);
    const tableData = req.body;

    // Extract unique days from the incoming data
    const uniqueDays = [...new Set(tableData.map(row => row.day))];

    const deleteQuery = `
        DELETE FROM rota WHERE day IN (?)
    `;

    const insertQuery = `
        INSERT INTO rota (id, name, lastName, wage, day, startTime, endTime, designation, color) 
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `;

    const operationMessages = []; // Store messages for logging operations

    // Function to delete existing data for the specified days
    const deleteExistingData = () => {
        return new Promise((resolve, reject) => {
            pool.query(deleteQuery, [uniqueDays], (deleteErr, deleteResult) => {
                if (deleteErr) {
                    console.error('Error deleting existing data:', deleteErr);
                    return reject(deleteErr);
                }
                console.log(`Deleted existing data for days: ${uniqueDays.join(', ')}`);
                operationMessages.push(`Deleted existing data for days: ${uniqueDays.join(', ')}`);
                resolve();
            });
        });
    };

    // Function to insert new data
    const insertNewData = () => {
        return Promise.all(tableData.map(row => {
            return new Promise((resolve, reject) => {
                const { name, lastName, wage, designation, day, startTime, endTime, color } = row;

                // Generate a unique ID for new data
                let newId = generateUniqueId();

                // Ensure the generated ID is unique
                const ensureUniqueId = () => {
                    return new Promise((resolveUnique, rejectUnique) => {
                        pool.query(
                            'SELECT id FROM rota WHERE id = ?',
                            [newId],
                            (checkErr, checkResult) => {
                                if (checkErr) {
                                    console.error('Error checking unique ID:', checkErr);
                                    return rejectUnique(checkErr);
                                }

                                if (checkResult.length > 0) {
                                    // ID already exists, generate a new one
                                    newId = generateUniqueId();
                                    return resolveUnique(ensureUniqueId());
                                }
                                resolveUnique(newId);
                            }
                        );
                    });
                };

                // Ensure unique ID and insert the record
                ensureUniqueId().then(() => {
                    pool.query(
                        insertQuery,
                        [newId, name, lastName, wage, day, startTime, endTime, designation, color],
                        (insertErr) => {
                            if (insertErr) {
                                console.error('Error inserting record:', insertErr);
                                return reject(insertErr);
                            }
                            console.log(`New record inserted for ${name} ${lastName} on ${day}.`);
                            operationMessages.push(`Inserted: ${name} ${lastName} (${day})`);
                            resolve();
                        }
                    );
                }).catch(reject);
            });
        }));
    };

    // First, delete existing data for the specified days
    deleteExistingData()
        .then(() => {
            // Then, insert the new data
            return insertNewData();
        })
        .then(() => {
            res.status(200).send(operationMessages.join('\n'));
        })
        .catch((error) => {
            console.error('Error saving data:', error);
            res.status(500).send('Error saving data.');
        });
});

// Function to Delete time frame
app.delete('/removeDayData', isAuthenticated, (req, res) => {
    const dbName = req.session.user.dbName; // Get the database name from the session

    if (!dbName) {
        return res.status(401).json({ success: false, message: 'User not authenticated' });
    }

    const pool = getPool(dbName); // Get the correct connection pool

    const { name, lastName, fullDay } = req.body;
    console.log('Day: ', fullDay,
        'Name: ', name,
        'Lastname: ', lastName
    );

    // SQL queries to delete from the rota, ConfirmedRota, and ConfirmedRota2 tables
    const deleteRotaSql = `
        DELETE FROM rota
        WHERE name = ? AND lastName = ? AND day = ?`;

    const deleteConfirmedRotaSql = `
        DELETE FROM ConfirmedRota
        WHERE name = ? AND lastName = ? AND day = ?`;

    const deleteConfirmedRota2Sql = `
        DELETE FROM ConfirmedRota2
        WHERE name = ? AND lastName = ? AND day = ?`;

    // Start a transaction to ensure all deletes are performed together
    pool.getConnection((err, connection) => {
        if (err) {
            console.error('Database connection error:', err);
            return res.status(500).send('Failed to connect to the database.');
        }

        connection.beginTransaction((err) => {
            if (err) {
                console.error('Error starting transaction:', err);
                return connection.release();
            }

            // Perform the delete operations in sequence and track whether any rows are deleted
            let deletedRota = false;
            let deletedConfirmedRota = false;
            let deletedConfirmedRota2 = false;

            connection.query(deleteRotaSql, [name, lastName, fullDay], (err, result) => {
                if (err) {
                    return connection.rollback(() => {
                        console.error('Error deleting from rota:', err);
                        connection.release();
                        return res.status(500).send('Failed to remove data from rota.');
                    });
                }
                if (result.affectedRows > 0) deletedRota = true;

                connection.query(deleteConfirmedRotaSql, [name, lastName, fullDay], (err, result) => {
                    if (err) {
                        return connection.rollback(() => {
                            console.error('Error deleting from ConfirmedRota:', err);
                            connection.release();
                            return res.status(500).send('Failed to remove data from ConfirmedRota.');
                        });
                    }
                    if (result.affectedRows > 0) deletedConfirmedRota = true;

                    connection.query(deleteConfirmedRota2Sql, [name, lastName, fullDay], (err, result) => {
                        if (err) {
                            return connection.rollback(() => {
                                console.error('Error deleting from ConfirmedRota2:', err);
                                connection.release();
                                return res.status(500).send('Failed to remove data from ConfirmedRota2.');
                            });
                        }
                        if (result.affectedRows > 0) deletedConfirmedRota2 = true;

                        // Commit the transaction if all deletions were successful
                        connection.commit((err) => {
                            if (err) {
                                return connection.rollback(() => {
                                    console.error('Error committing transaction:', err);
                                    connection.release();
                                    return res.status(500).send('Failed to commit transaction.');
                                });
                            }

                            // Send the response based on whether any records were deleted
                            if (deletedRota || deletedConfirmedRota || deletedConfirmedRota2) {
                                console.log('Data removed successfully from one or more tables.');
                                connection.release();
                                res.send('Data removed successfully.');
                            } else {
                                console.log('No records found for deletion.');
                                connection.release();
                                res.status(404).send('No matching records found to delete.');
                            }
                        });
                    });
                });
            });
        });
    });
});

// Route to Insert Holiday% data
app.post('/save-holiday-percentage', isAuthenticated, (req, res) => {
    const dbName = req.session.user.dbName; // Get the database name from the session

    if (!dbName) {
        return res.status(401).json({ success: false, message: 'User not authenticated' });
    }

    const pool = getPool(dbName); // Get the correct connection pool

    const { holiday } = req.body;

    // Validate the input
    if (holiday === undefined || holiday < 0 || holiday > 100) {
        return res.status(400).send('Invalid holiday percentage.');
    }

    // Update the rota_tax table
    const sql = 'UPDATE rota_tax SET holiday = ? WHERE id = 1'; // 
    pool.query(sql, [holiday], (err) => {
        if (err) {
            console.error('Database error:', err);
            return res.status(500).send('Failed to save holiday percentage.');
        }
        res.send('Holiday percentage saved.');
    });
});

// Route to handle Holiday% data
app.get('/get-holiday-percentage', isAuthenticated, (req, res) => {
    const dbName = req.session.user.dbName; // Get the database name from the session

    if (!dbName) {
        return res.status(401).json({ success: false, message: 'User not authenticated' });
    }

    const pool = getPool(dbName); // Get the correct connection pool

    const sql = 'SELECT holiday FROM rota_tax WHERE id = 1'; // Assuming 'id = 1' identifies the relevant row

    pool.query(sql, (err, results) => {
        if (err) {
            console.error('Database error:', err);
            return res.status(500).send('Failed to retrieve holiday percentage.');
        }
        if (results.length > 0) {
            res.json({ holiday: results[0].holiday });
        } else {
            res.json({ holiday: 0 }); // Default value if no record is found
        }
    });
});

// Route to Insert Tax% data
app.post('/save-tax-percentage', isAuthenticated, (req, res) => {
    const dbName = req.session.user.dbName; // Get the database name from the session

    if (!dbName) {
        return res.status(401).json({ success: false, message: 'User not authenticated' });
    }

    const pool = getPool(dbName); // Get the correct connection pool

    const { tax } = req.body;

    // Validate the input
    if (tax === undefined || tax < 0 || tax > 100) {
        return res.status(400).send('Invalid tax percentage.');
    }

    // Update the rota_tax table
    const sql = 'UPDATE rota_tax SET tax = ? WHERE id = 1'; // 
    pool.query(sql, [tax], (err) => {
        if (err) {
            console.error('Database error:', err);
            return res.status(500).send('Failed to save tax percentage.');
        }
        res.send('Tax percentage saved.');
    });
});

// Route to handle Tax% data
app.get('/get-tax-percentage', isAuthenticated, (req, res) => {
    const dbName = req.session.user.dbName; // Get the database name from the session

    if (!dbName) {
        return res.status(401).json({ success: false, message: 'User not authenticated' });
    }

    const pool = getPool(dbName); // Get the correct connection pool

    const sql = 'SELECT tax FROM rota_tax WHERE id = 1'; // Assuming 'id = 1' identifies the relevant row

    pool.query(sql, (err, results) => {
        if (err) {
            console.error('Database error:', err);
            return res.status(500).send('Failed to retrieve tax percentage.');
        }
        if (results.length > 0) {
            res.json({ tax: results[0].tax });
        } else {
            res.json({ tax: 0 }); // Default value if no record is found
        }
    });
});

// Route to Insert Pension% data
app.post('/save-pension-percentage', isAuthenticated, (req, res) => {
    const dbName = req.session.user.dbName; // Get the database name from the session

    if (!dbName) {
        return res.status(401).json({ success: false, message: 'User not authenticated' });
    }

    const pool = getPool(dbName); // Get the correct connection pool

    const { pension } = req.body;

    // Validate the input
    if (pension === undefined || pension < 0 || pension > 100) {
        return res.status(400).send('Invalid pension percentage.');
    }

    // Update the rota_tax table
    const sql = 'UPDATE rota_tax SET pension = ? WHERE id = 1'; // 
    pool.query(sql, [pension], (err) => {
        if (err) {
            console.error('Database error:', err);
            return res.status(500).send('Failed to save pension percentage.');
        }
        res.send('Pension percentage saved.');
    });
});

// Route to handle Pension% data
app.get('/get-pension-percentage', isAuthenticated, (req, res) => {
    const dbName = req.session.user.dbName; // Get the database name from the session

    if (!dbName) {
        return res.status(401).json({ success: false, message: 'User not authenticated' });
    }

    const pool = getPool(dbName); // Get the correct connection pool

    const sql = 'SELECT pension FROM rota_tax WHERE id = 1'; // Assuming 'id = 1' identifies the relevant row

    pool.query(sql, (err, results) => {
        if (err) {
            console.error('Database error:', err);
            return res.status(500).send('Failed to retrieve pension percentage.');
        }
        if (results.length > 0) {
            res.json({ pension: results[0].pension });
        } else {
            res.json({ pension: 0 }); // Default value if no record is found
        }
    });
});

// Route to handle fetching rota data
app.get('/rota', isAuthenticated, (req, res) => {
    const dbName = req.session.user.dbName; // Get the database name from the session

    if (!dbName) {
        return res.status(401).json({ success: false, message: 'User not authenticated' });
    }

    const pool = getPool(dbName); // Get the correct connection pool

    const { days } = req.query; // Get the days parameter from the query string
    if (!days) {
        return res.status(400).send('Missing "days" query parameter');
    }

    // Split the comma-separated string of days into an array
    const weekDates = days.split(',');

    // SQL query to fetch data for the specified days
    const query = `
        SELECT name, lastName, wage, day, startTime, endTime, designation, color
        FROM rota
        WHERE day IN (?)`;

    pool.query(query, [weekDates], (err, results) => {
        if (err) {
            console.error('Error fetching employee data:', err);
            return res.status(500).send('Error fetching employee data');
        }

        // Group results by day
        const groupedData = {};
        results.forEach(row => {
            if (!groupedData[row.day]) groupedData[row.day] = [];
            groupedData[row.day].push(row);
        });

        res.json(groupedData);
    });
});

// Function to get forecast data for specific days
app.get('/forecast/get', isAuthenticated, async (req, res) => {
    const dbName = req.session.user.dbName; // Get the database name from the session

    if (!dbName) {
        return res.status(401).json({ success: false, message: 'User not authenticated' });
    }

    const pool = getPool(dbName); // Get the correct connection pool
    const { dates } = req.query;

    try {
        const dateList = dates.split(',');

        // Modified query to work without the date field
        pool.query(
            'SELECT day, customers, sales, labor FROM Forecast WHERE day IN (?) ORDER BY FIELD(day, ?)',
            [dateList, dateList], // Pass the array twice for both IN and FIELD clauses
            (err, results) => {
                if (err) {
                    console.error('Error fetching forecast data:', err);
                    return res.status(500).json({ 
                        success: false, 
                        message: 'Error fetching forecast data' 
                    });
                }

                res.json({ 
                    success: true,
                    data: results 
                });
            }
        );
    } catch (error) {
        console.error('Error processing forecast request:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Error processing request' 
        });
    }
});

// Function to save forecast data
app.post('/forecast/save', isAuthenticated, async (req, res) => {
    const dbName = req.session.user.dbName; // Get the database name from the session

    if (!dbName) {
        return res.status(401).json({ success: false, message: 'User not authenticated' });
    }

    const pool = getPool(dbName); // Get the correct connection pool
    const forecastData = req.body;

    // Start transaction
    pool.getConnection((err, connection) => {
        if (err) {
            console.error('Error getting database connection:', err);
            return res.status(500).json({ 
                success: false, 
                message: 'Database connection error' 
            });
        }

        connection.beginTransaction(async (err) => {
            if (err) {
                connection.release();
                console.error('Error starting transaction:', err);
                return res.status(500).json({ 
                    success: false, 
                    message: 'Transaction error' 
                });
            }

            try {
                // Process each day's forecast data
                for (const dayData of forecastData) {
                    const { day, date, customers, sales, labor } = dayData;
                    
                    // Check if record exists
                    const [existing] = await connection.promise().query(
                        'SELECT id FROM Forecast WHERE day = ?', 
                        [day]
                    );

                    if (existing.length > 0) {
                        // Update existing record
                        await connection.promise().query(
                            `UPDATE Forecast 
                             SET customers = ?, sales = ?, labor = ?
                             WHERE day = ?`,
                            [customers, sales, labor, day]
                        );
                    } else {
                        // Insert new record
                        await connection.promise().query(
                            `INSERT INTO Forecast 
                             (day, customers, sales, labor)
                             VALUES (?, ?, ?, ?)`,
                            [day, customers, sales, labor]
                        );
                    }
                }

                // Commit transaction
                await connection.promise().commit();
                connection.release();
                
                res.json({ 
                    success: true, 
                    message: 'Forecast saved successfully' 
                });
            } catch (error) {
                // Rollback on error
                await connection.promise().rollback();
                connection.release();
                
                console.error('Error saving forecast:', error);
                res.status(500).json({ 
                    success: false, 
                    message: 'Error saving forecast data' 
                });
            }
        });
    });
});

// Route to handle fetching employee data
app.get('/employees', isAuthenticated, (req, res) => {
    const dbName = req.session.user.dbName; // Get the database name from the session

    if (!dbName) {
        return res.status(401).json({ success: false, message: 'User not authenticated' });
    }

    const pool = getPool(dbName); // Get the correct connection pool

    pool.query('SELECT name, lastName, wage, designation, position FROM Employees', (err, results) => {
        if (err) {
            console.error('Error fetching employee data:', err);
            return res.status(500).send('Error fetching employee data');
        }
        const employees = results.map(row => ({
            name: row.name,
            lastName: row.lastName,
            wage: row.wage,
            designation: row.designation,
            position: row.position
        }));
        res.json(employees);
    });
});

// Route to handle fetching holidays and unpaid leave data
app.get('/holidays', isAuthenticated, (req, res) => {
    const dbName = req.session.user.dbName;

    if (!dbName) {
        return res.status(401).json({ success: false, message: 'User not authenticated' });
    }

    const pool = getPool(dbName);

    // Fix the SQL query (removed trailing comma)
    const query = `
        SELECT 
            name, 
            lastname, 
            startDate, 
            endDate,
            accepted,
            days
        FROM Holiday
        WHERE accepted IN ("true", "unpaid")
        ORDER BY startDate DESC;
    `;

    // Set response headers for streaming
    res.setHeader('Content-Type', 'application/json');
    res.write('['); // Start of JSON array

    let firstRow = true;

    pool.query(query)
        .on('result', (row) => {
            // Add comma before each row except the first
            if (!firstRow) {
                res.write(',');
            } else {
                firstRow = false;
            }

            // Transform the row
            const transformedRow = {
                ...row,
                type: row.accepted === 'true' ? 'holiday' : 'unpaid leave',
                status: row.accepted === 'true' ? 'approved' : 'unpaid'
            };

            res.write(JSON.stringify(transformedRow));
        })
        .on('end', () => {
            res.end(']'); // End of JSON array
        })
        .on('error', (err) => {
            console.error('Database query failed:', err);
            if (!res.headersSent) {
                res.status(500).json({ 
                    success: false,
                    error: 'Database query failed',
                    message: err.message 
                });
            }
        });
});

// Submit new holiday or unpaid leave
app.post('/submit-holiday', (req, res) => {
    const dbName = req.session.user.dbName;

    if (!dbName) {
        return res.status(401).json({ success: false, message: 'User not authenticated' });
    }

    const pool = getPool(dbName);
    const { name, lastName, startDate, endDate, requestType } = req.body;

    // Convert to Date objects
    const start = new Date(startDate);
    const end = new Date(endDate);
    const days = Math.ceil((end - start) / (1000 * 60 * 60 * 24)) + 1;

    // Format dates as dd/mm/yyyy (Day)
    const formatDate = (date) => {
        const day = date.getDate().toString().padStart(2, '0');
        const month = (date.getMonth() + 1).toString().padStart(2, '0');
        const year = date.getFullYear();
        const dayName = date.toLocaleDateString('en-US', { weekday: 'long' });
        return `${day}/${month}/${year} (${dayName})`;
    };

    const formattedStartDate = formatDate(start);
    const formattedEndDate = formatDate(end);
    const currentDate = formatDate(new Date());

    // Determine the value for the accepted column
    const acceptedValue = requestType === 'holiday' ? 'true' : 'unpaid';

    pool.getConnection((err, connection) => {
        if (err) {
            console.error('Error getting database connection:', err);
            return res.status(500).json({ 
                success: false, 
                message: 'Database connection error' 
            });
        }

        // Start transaction
        connection.beginTransaction((beginErr) => {
            if (beginErr) {
                connection.release();
                console.error('Error starting transaction:', beginErr);
                return res.status(500).json({ message: 'Transaction error' });
            }

            // 1. Insert the holiday request
            connection.query(
                `INSERT INTO Holiday 
                 (name, lastName, startDate, endDate, requestDate, days, accepted) 
                 VALUES (?, ?, ?, ?, ?, ?, ?)`,
                [name, lastName, formattedStartDate, formattedEndDate, currentDate, days, acceptedValue],
                (insertErr, insertResult) => {
                    if (insertErr) {
                        return connection.rollback(() => {
                            connection.release();
                            console.error('Error inserting holiday:', insertErr);
                            res.status(500).json({ 
                                success: false,
                                message: insertErr.message || 'Error inserting holiday request'
                            });
                        });
                    }

                    // 2. Only update TotalHoliday if it's a paid leave
                    if (requestType === 'holiday') {
                        connection.query(
                            `UPDATE Employees 
                             SET TotalHoliday = TotalHoliday - ? 
                             WHERE name = ? AND lastName = ?`,
                            [days, name, lastName],
                            (updateErr, updateResult) => {
                                if (updateErr) {
                                    return connection.rollback(() => {
                                        connection.release();
                                        console.error('Error updating TotalHoliday:', updateErr);
                                        res.status(500).json({ 
                                            success: false,
                                            message: updateErr.message || 'Error updating holiday balance'
                                        });
                                    });
                                }

                                // Commit transaction
                                connection.commit((commitErr) => {
                                    if (commitErr) {
                                        return connection.rollback(() => {
                                            connection.release();
                                            console.error('Error committing transaction:', commitErr);
                                            res.status(500).json({ 
                                                success: false,
                                                message: commitErr.message || 'Error committing transaction'
                                            });
                                        });
                                    }

                                    connection.release();
                                    res.json({ 
                                        success: true,
                                        id: insertResult.insertId,
                                        name,
                                        lastName,
                                        startDate: formattedStartDate,
                                        endDate: formattedEndDate,
                                        requestDate: currentDate,
                                        days,
                                        accepted: acceptedValue,
                                        daysDeducted: requestType === 'holiday' ? days : 0
                                    });
                                });
                            }
                        );
                    } else {
                        // For unpaid leave, just commit without updating TotalHoliday
                        connection.commit((commitErr) => {
                            if (commitErr) {
                                return connection.rollback(() => {
                                    connection.release();
                                    console.error('Error committing transaction:', commitErr);
                                    res.status(500).json({ 
                                        success: false,
                                        message: commitErr.message || 'Error committing transaction'
                                    });
                                });
                            }

                            connection.release();
                            res.json({ 
                                success: true,
                                id: insertResult.insertId,
                                name,
                                lastName,
                                startDate: formattedStartDate,
                                endDate: formattedEndDate,
                                requestDate: currentDate,
                                days,
                                accepted: acceptedValue,
                                daysDeducted: 0
                            });
                        });
                    }
                }
            );
        });
    });
});

// Get all employees for dropdown
app.get('/employees-holiday', (req, res) => {
    const dbName = req.session.user.dbName;
    
    if (!dbName) {
        return res.status(401).json({ success: false, message: 'User not authenticated' });
    }

    const pool = getPool(dbName);
    pool.query(
        'SELECT name, lastName, Accrued, TotalHoliday FROM Employees',
        (err, result) => {
            if (err) {
                console.error(err.message);
                return res.status(500).json({ error: 'Server error' });
            }
            res.json(result.map(row => ({
                name: row.name,
                lastname: row.lastname || row.lastName // Handle both casing variations
            })));
        }
    );
});

// Get holidays and unpaid leave for a specific week
app.get('/holidays-by-week', (req, res) => {
    const dbName = req.session.user.dbName;
    const { start, end } = req.query;
    
    if (!dbName) {
        return res.status(401).json({ success: false, message: 'User not authenticated' });
    }

    const pool = getPool(dbName);
    
    const query = `
    SELECT name, lastName, startDate, endDate, accepted
    FROM Holiday 
    WHERE accepted IN ('true', 'unpaid')
    AND STR_TO_DATE(SUBSTRING_INDEX(startDate, ' (', 1), '%d/%m/%Y') <= STR_TO_DATE(?, '%d/%m/%Y')
    AND STR_TO_DATE(SUBSTRING_INDEX(endDate, ' (', 1), '%d/%m/%Y') >= STR_TO_DATE(?, '%d/%m/%Y')
`;
    
    pool.query(query, [
        end, start,    // For first condition
        start, start,  // For second condition
        start, end,    // For third condition
        start, end     // For fourth condition
    ], (err, result) => {
        if (err) {
            console.error('Database error:', err);
            return res.status(500).json({ 
                success: false, 
                error: 'Database error',
                message: err.message 
            });
        }
        // Process results to include type information
        const processedResults = result.map(record => {
            return {
                ...record,
                type: record.accepted === 'true' ? 'holiday' : 'unpaid',
                // Ensure we return the original start/end dates
                startDate: record.startDate,
                endDate: record.endDate
            };
        });
        res.json(processedResults);
    });
});

// Route to serve the Rota.html file
app.get('/', isAuthenticated, (req, res) => {
    if (req.session.user.role === 'admin') {
        res.sendFile(path.join(__dirname, 'Rota.html'));
    } else {
        res.status(403).json({ error: 'Access denied' });
    }
});

module.exports = app; // Export the entire Express application