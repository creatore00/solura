// holidayAccrual.js
const { getPool } = require('./db.js');

// Function to calculate and update accrued holidays
function updateAccruedHolidaysDaily(dbName, callback) {
    if (!dbName) {
        return callback(new Error('Database name not provided'));
    }

    const pool = getPool(dbName);
    if (!pool) {
        return callback(new Error(`Could not get connection pool for database ${dbName}`));
    }

    const today = new Date();
    console.log(`[${new Date().toISOString()}] Running holiday accrual update for ${dbName}`);
    
    pool.getConnection((err, connection) => {
        if (err) {
            return callback(err);
        }
        
        connection.query('SELECT HolidayYearStart, HolidayYearEnd FROM HolidayYearSettings LIMIT 1', (err, results) => {
            if (err) {
                connection.release();
                return callback(err);
            }
            
            if (results.length === 0) {
                connection.release();
                return callback(new Error('No holiday year settings found'));
            }
            
            const holidayYearSettings = results[0];
            const holidayYearStart = new Date(holidayYearSettings.HolidayYearStart);
            const holidayYearEnd = new Date(holidayYearSettings.HolidayYearEnd);
            
            connection.query('SELECT id, name, lastName, dateStart, startHoliday, accrued FROM Employees', (err, employees) => {
                if (err) {
                    connection.release();
                    return callback(err);
                }
                
                let processed = 0;
                if (employees.length === 0) {
                    connection.release();
                    return callback(null, { message: 'No employees to process' });
                }
                
                employees.forEach(employee => {
                    const employeeStartDate = new Date(employee.dateStart);
                    
                    if (employeeStartDate > holidayYearEnd) {
                        processed++;
                        if (processed === employees.length) {
                            connection.release();
                            callback(null, { message: 'Processing complete' });
                        }
                        return;
                    }
                    
                    const daysInHolidayYear = Math.ceil((holidayYearEnd - holidayYearStart) / (1000 * 60 * 60 * 24));
                    const accrualRatePerDay = employee.startHoliday / daysInHolidayYear;
                    
                    let effectiveStartDate = employeeStartDate;
                    if (employeeStartDate < holidayYearStart) {
                        effectiveStartDate = holidayYearStart;
                    }
                    
                    const daysSinceStart = Math.ceil((today - effectiveStartDate) / (1000 * 60 * 60 * 24));
                    let accruedHolidays = daysSinceStart * accrualRatePerDay;
                    accruedHolidays = Math.min(accruedHolidays, employee.startHoliday);
                    
                    connection.query(
                        'UPDATE Employees SET accrued = ? WHERE id = ?',
                        [accruedHolidays, employee.id],
                        (err) => {
                            if (err) {
                                console.error(`Error updating employee ${employee.id}:`, err);
                            }
                            
                            processed++;
                            if (processed === employees.length) {
                                connection.release();
                                callback(null, { message: 'Processing complete' });
                            }
                        }
                    );
                });
            });
        });
    });
}

// Function to run the update every minute for testing
function scheduleTestUpdates(databaseNames) {
    if (!Array.isArray(databaseNames)) {
        console.error('Database names must be provided as an array');
        return;
    }

    console.log('Starting test mode - will run every day');
    
    // Immediate first run
    databaseNames.forEach(dbName => {
        updateAccruedHolidaysDaily(dbName, (err, result) => {
            if (err) {
                console.error(`Error in test update for ${dbName}:`, err);
            } else {
                console.log(`Test update completed for ${dbName}:`, result.message);
            }
        });
    });

    // Set interval for subsequent runs
    return setInterval(() => {
        console.log(`\n[${new Date().toISOString()}] Running test update`);
        
        databaseNames.forEach(dbName => {
            updateAccruedHolidaysDaily(dbName, (err, result) => {
                if (err) {
                    console.error(`Error in test update for ${dbName}:`, err);
                } else {
                    console.log(`Test update completed for ${dbName}:`, result.message);
                }
            });
        });
    }, 86400000); // 60 seconds
}

module.exports = {
    updateAccruedHolidaysDaily,
    scheduleTestUpdates
};