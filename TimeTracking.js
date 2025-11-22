const express = require('express');
const path = require('path');
const puppeteer = require('puppeteer');
const { getPool } = require('./db.js');
const { sessionMiddleware, isAuthenticated, isAM } = require('./sessionConfig');

const app = express();

// Middleware
app.use(sessionMiddleware);
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Helper function to parse date from "dd/mm/yyyy (Dayname)" format
function parseCustomDate(dateString) {
    if (!dateString) return null;
    
    // Handle "dd/mm/yyyy (Dayname)" format
    const match = dateString.match(/^(\d{2})\/(\d{2})\/(\d{4}) \(([^)]+)\)$/);
    if (match) {
        const [, day, month, year] = match;
        return new Date(year, month - 1, day);
    }
    
    // Fallback for other formats
    return new Date(dateString);
}

// Helper function to format date for display
function formatDateForDisplay(date) {
    const days = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];
    const dd = String(date.getDate()).padStart(2, '0');
    const mm = String(date.getMonth() + 1).padStart(2, '0');
    const yyyy = date.getFullYear();
    const weekday = days[date.getDay()];
    return `${dd}/${mm}/${yyyy} (${weekday})`;
}

// Calculate hours between start and end time
function calculateHours(startTime, endTime) {
    if (!startTime || !endTime) return 0;
    
    try {
        const start = new Date(`1970-01-01T${startTime}`);
        const end = new Date(`1970-01-01T${endTime}`);
        
        if (isNaN(start.getTime()) || isNaN(end.getTime())) return 0;
        
        // Handle overnight shifts (end time is next day)
        if (end < start) {
            end.setDate(end.getDate() + 1);
        }
        
        const diffMs = end - start;
        return diffMs / (1000 * 60 * 60); // Convert to hours
    } catch (error) {
        console.error('Error calculating hours:', error);
        return 0;
    }
}

// Calculate holiday hours based on salary status and average weekly hours
async function calculateHolidayHours(pool, employeeName, employeeLastName, holidayStart, holidayEnd) {
    try {
        // Get employee salary status
        const [employeeData] = await pool.promise().query(`
            SELECT Salary, wage 
            FROM Employees 
            WHERE name = ? AND lastName = ? 
            AND (situation != 'past' OR situation IS NULL)
        `, [employeeName, employeeLastName]);

        if (employeeData.length === 0) {
            console.log(`❌ Employee ${employeeName} ${employeeLastName} not found`);
            return { hours: 0, cost: 0 };
        }

        const isSalary = employeeData[0].Salary === 'Yes';
        const wage = parseFloat(employeeData[0].wage || 0);

        if (isSalary) {
            // Salary employee: 8 hours per day
            const hoursPerDay = 8;
            const totalHours = hoursPerDay;
            const cost = totalHours * wage;
            console.log(`💰 Salary employee ${employeeName} ${employeeLastName}: ${hoursPerDay} hours/day`);
            return { hours: totalHours, cost: cost };
        } else {
            // Non-salary: Calculate average daily hours from ConfirmedRota
            // Get total hours worked in the last 3 months (approx 12.9 weeks)
            const threeMonthsAgo = new Date();
            threeMonthsAgo.setMonth(threeMonthsAgo.getMonth() - 3);
            
            const [workData] = await pool.promise().query(`
                SELECT day, startTime, endTime 
                FROM ConfirmedRota 
                WHERE name = ? AND lastName = ? 
                AND STR_TO_DATE(SUBSTRING_INDEX(day, ' (', 1), '%d/%m/%Y') >= ?
            `, [employeeName, employeeLastName, threeMonthsAgo]);

            let totalWorkHours = 0;
            let totalWorkDays = 0;

            workData.forEach(shift => {
                const hours = calculateHours(shift.startTime, shift.endTime);
                totalWorkHours += hours;
                totalWorkDays++;
            });

            if (totalWorkDays === 0) {
                console.log(`📊 No work data found for ${employeeName} ${employeeLastName}, using default 8 hours`);
                const hoursPerDay = 8;
                const totalHours = hoursPerDay;
                const cost = totalHours * wage;
                return { hours: totalHours, cost: cost };
            }

            // Calculate average daily hours: total hours ÷ 12.9 weeks ÷ 5 days
            const averageWeeklyHours = totalWorkHours / 12.9;
            const averageDailyHours = averageWeeklyHours / 5;
            
            const totalHours = Math.round(averageDailyHours * 100) / 100; // Round to 2 decimal places
            const cost = totalHours * wage;

            console.log(`📊 Non-salary employee ${employeeName} ${employeeLastName}:`);
            console.log(`   Total hours worked: ${totalWorkHours}`);
            console.log(`   Total days worked: ${totalWorkDays}`);
            console.log(`   Average weekly hours: ${Math.round(averageWeeklyHours * 100) / 100}`);
            console.log(`   Average daily hours: ${totalHours}`);
            console.log(`   Holiday cost: £${cost.toFixed(2)}`);

            return { hours: totalHours, cost: cost };
        }
    } catch (error) {
        console.error(`❌ Error calculating holiday hours for ${employeeName} ${employeeLastName}:`, error);
        return { hours: 8, cost: 8 * parseFloat(wage || 0) }; // Fallback to 8 hours
    }
}

// Get all unique employees from Employees table where situation is not 'past'
app.get('/api/employees', isAuthenticated, isAM, async (req, res) => {
    try {
        const dbName = req.session.user.dbName;
        if (!dbName) {
            return res.status(401).json({ error: 'User not authenticated' });
        }

        const pool = getPool(dbName);
        
        const [results] = await pool.promise().query(`
            SELECT DISTINCT name, lastName, designation, wage, Salary
            FROM Employees 
            WHERE situation != 'past' OR situation IS NULL
            ORDER BY name, lastName
        `);

        console.log('👥 Retrieved active employees:', results.length);
        res.json(results);
    } catch (error) {
        console.error('❌ Error fetching employees:', error);
        res.status(500).json({ error: 'Failed to fetch employees' });
    }
});

// Get current month data for all active employees (only those in Employees table where situation is not 'past')
app.get('/api/hours/current-month', isAuthenticated, isAM, async (req, res) => {
    try {
        const dbName = req.session.user.dbName;
        if (!dbName) {
            return res.status(401).json({ error: 'User not authenticated' });
        }

        const pool = getPool(dbName);
        
        // Get current month range
        const now = new Date();
        const firstDay = new Date(now.getFullYear(), now.getMonth(), 1);
        const lastDay = new Date(now.getFullYear(), now.getMonth() + 1, 0);
        
        const formattedDays = [];
        const current = new Date(firstDay);
        while (current <= lastDay) {
            formattedDays.push(formatDateForDisplay(new Date(current)));
            current.setDate(current.getDate() + 1);
        }

        console.log('📅 Current month days:', formattedDays.length);
        console.log('📅 Sample formatted days:', formattedDays.slice(0, 5));

        // Get active employees from Employees table
        const [employees] = await pool.promise().query(`
            SELECT name, lastName, wage, designation, Salary
            FROM Employees 
            WHERE situation != 'past' OR situation IS NULL
            ORDER BY name, lastName
        `);

        console.log('👥 Active employees from Employees table:', employees.length);

        // Get rota data for current month, joined with Employees to get proper wage
        const [rotaResults] = await pool.promise().query(`
            SELECT 
                cr.name,
                cr.lastName,
                cr.day,
                cr.startTime,
                cr.endTime,
                cr.designation,
                cr.who,
                e.wage as employee_wage,
                e.Salary
            FROM ConfirmedRota cr
            INNER JOIN Employees e ON cr.name = e.name AND cr.lastName = e.lastName
            WHERE cr.day IN (?) 
            AND (e.situation != 'past' OR e.situation IS NULL)
            ORDER BY cr.day, cr.name, cr.lastName, cr.startTime
        `, [formattedDays]);

        console.log('📊 Current month rota records with active employees:', rotaResults.length);

        // Get ALL holidays for active employees first
        const [allHolidays] = await pool.promise().query(`
            SELECT 
                h.name,
                h.lastName,
                h.startDate,
                h.endDate,
                h.accepted,
                e.wage as employee_wage,
                e.designation,
                e.Salary
            FROM Holiday h
            INNER JOIN Employees e ON h.name = e.name AND h.lastName = e.lastName
            WHERE h.accepted = 'true' 
            AND (e.situation != 'past' OR e.situation IS NULL)
        `);

        console.log('🏖️ All holidays found:', allHolidays.length);

        // Filter holidays to find those that overlap with current month days
        const holidayResults = allHolidays.filter(holiday => {
            const holidayStart = parseCustomDate(holiday.startDate);
            const holidayEnd = parseCustomDate(holiday.endDate);
            
            // Check if any day in the holiday range matches any day in our current month
            return formattedDays.some(day => {
                const currentDay = parseCustomDate(day);
                return currentDay >= holidayStart && currentDay <= holidayEnd;
            });
        });

        console.log('🏖️ Current month holiday records:', holidayResults.length);
        console.log('🏖️ Holiday results details:', holidayResults);

        // Process data to calculate totals using wage from Employees table
        const employeeData = {};
        let grandTotalHours = 0;
        let grandTotalCost = 0;

        // Process rota shifts
        rotaResults.forEach(shift => {
            const key = `${shift.name} ${shift.lastName}`;
            const hours = calculateHours(shift.startTime, shift.endTime);
            const cost = hours * parseFloat(shift.employee_wage || 0);

            if (!employeeData[key]) {
                employeeData[key] = {
                    name: shift.name,
                    lastName: shift.lastName,
                    designation: shift.designation,
                    wage: parseFloat(shift.employee_wage || 0),
                    Salary: shift.Salary,
                    totalHours: 0,
                    totalCost: 0,
                    shifts: []
                };
            }

            employeeData[key].totalHours += hours;
            employeeData[key].totalCost += cost;
            employeeData[key].shifts.push({
                day: shift.day,
                startTime: shift.startTime,
                endTime: shift.endTime,
                hours: hours,
                cost: cost,
                who: shift.who,
                holidayType: null // This is a regular shift
            });

            grandTotalHours += hours;
            grandTotalCost += cost;
        });

        console.log('📊 After processing rota shifts - employeeData keys:', Object.keys(employeeData));

        // Process holidays - handle each day of multi-day holidays
        for (const holiday of holidayResults) {
            const key = `${holiday.name} ${holiday.lastName}`;
            const holidayType = holiday.accepted === 'unpaid' ? 'unpaid' : 'paid';
            
            // Parse start and end dates
            const holidayStart = parseCustomDate(holiday.startDate);
            const holidayEnd = parseCustomDate(holiday.endDate);
            
            console.log(`🏖️ Processing holiday for ${key}:`, {
                startDate: holiday.startDate,
                endDate: holiday.endDate,
                holidayStart: holidayStart,
                holidayEnd: holidayEnd,
                type: holidayType
            });

            if (!employeeData[key]) {
                employeeData[key] = {
                    name: holiday.name,
                    lastName: holiday.lastName,
                    designation: holiday.designation,
                    wage: parseFloat(holiday.employee_wage || 0),
                    Salary: holiday.Salary,
                    totalHours: 0,
                    totalCost: 0,
                    shifts: []
                };
                console.log(`🏖️ Created new employee entry for holiday: ${key}`);
            }

            // Generate all days in the holiday range
            const currentHolidayDay = new Date(holidayStart);
            while (currentHolidayDay <= holidayEnd) {
                const formattedHolidayDay = formatDateForDisplay(new Date(currentHolidayDay));
                
                // Only include holidays that fall within our current month days
                if (formattedDays.includes(formattedHolidayDay)) {
                    // Calculate holiday hours based on salary status and work history
                    const holidayCalculation = await calculateHolidayHours(
                        pool, 
                        holiday.name, 
                        holiday.lastName, 
                        holidayStart, 
                        holidayEnd
                    );

                    const hours = holidayType === 'paid' ? holidayCalculation.hours : 0;
                    const cost = holidayType === 'paid' ? holidayCalculation.cost : 0;

                    // Check if this day already has a shift entry
                    const existingShiftIndex = employeeData[key].shifts.findIndex(
                        shift => shift.day === formattedHolidayDay
                    );

                    console.log(`🏖️ Checking for existing shift on ${formattedHolidayDay}:`, existingShiftIndex);

                    if (existingShiftIndex === -1) {
                        // No existing shift for this day, add holiday
                        employeeData[key].totalHours += hours;
                        employeeData[key].totalCost += cost;
                        employeeData[key].shifts.push({
                            day: formattedHolidayDay,
                            startTime: null,
                            endTime: null,
                            hours: hours,
                            cost: cost,
                            who: 'Holiday',
                            holidayType: holidayType,
                            calculatedHours: hours,
                            isSalary: holiday.Salary === 'Yes'
                        });

                        grandTotalHours += hours;
                        grandTotalCost += cost;
                        console.log(`🏖️ Added holiday for ${key} on ${formattedHolidayDay}: ${hours} hours, £${cost.toFixed(2)}`);
                    } else {
                        console.log(`🏖️ Skipping holiday for ${key} on ${formattedHolidayDay} - shift already exists`);
                    }
                }
                
                currentHolidayDay.setDate(currentHolidayDay.getDate() + 1);
            }
        }

        console.log('📊 After processing holidays - employeeData keys:', Object.keys(employeeData));

        // Sort shifts by date for each employee
        Object.values(employeeData).forEach(employee => {
            employee.shifts.sort((a, b) => {
                return new Date(parseCustomDate(a.day)) - new Date(parseCustomDate(b.day));
            });
        });

        const report = Object.values(employeeData).map(emp => ({
            ...emp,
            totalHours: parseFloat(emp.totalHours.toFixed(2)),
            totalCost: parseFloat(emp.totalCost.toFixed(2))
        }));

        res.json({
            report,
            summary: {
                totalEmployees: report.length,
                grandTotalHours: parseFloat(grandTotalHours.toFixed(2)),
                grandTotalCost: parseFloat(grandTotalCost.toFixed(2)),
                period: `Current Month (${firstDay.toLocaleDateString('en-GB')} - ${lastDay.toLocaleDateString('en-GB')})`
            }
        });

    } catch (error) {
        console.error('❌ Error fetching current month data:', error);
        res.status(500).json({ error: 'Failed to fetch current month data' });
    }
});

// Get filtered data by employee and date range
app.post('/api/hours/filtered', isAuthenticated, isAM, async (req, res) => {
    try {
        const dbName = req.session.user.dbName;
        if (!dbName) {
            return res.status(401).json({ error: 'User not authenticated' });
        }

        const { startDate, endDate, employeeName } = req.body;
        const pool = getPool(dbName);

        if (!startDate || !endDate) {
            return res.status(400).json({ error: 'Start and end dates are required' });
        }

        const start = new Date(startDate);
        const end = new Date(endDate);

        if (isNaN(start.getTime()) || isNaN(end.getTime())) {
            return res.status(400).json({ error: 'Invalid dates provided' });
        }

        if (start > end) {
            return res.status(400).json({ error: 'Start date must be before end date' });
        }

        // Generate all dates in the range
        const formattedDays = [];
        const current = new Date(start);
        while (current <= end) {
            formattedDays.push(formatDateForDisplay(new Date(current)));
            current.setDate(current.getDate() + 1);
        }

        console.log('🔍 Filtering data:', {
            employeeName,
            dateRange: `${startDate} to ${endDate}`,
            daysCount: formattedDays.length
        });
        console.log('🔍 Sample formatted days for filtering:', formattedDays.slice(0, 5));

        // Build query for rota data
        let rotaQuery = `
            SELECT 
                cr.name,
                cr.lastName,
                cr.day,
                cr.startTime,
                cr.endTime,
                cr.designation,
                cr.who,
                e.wage as employee_wage,
                e.Salary
            FROM ConfirmedRota cr
            INNER JOIN Employees e ON cr.name = e.name AND cr.lastName = e.lastName
            WHERE cr.day IN (?)
            AND (e.situation != 'past' OR e.situation IS NULL)
        `;
        let rotaParams = [formattedDays];

        if (employeeName && employeeName !== 'all') {
            const [firstName, lastName] = employeeName.split(' ');
            rotaQuery += ` AND cr.name = ? AND cr.lastName = ?`;
            rotaParams.push(firstName, lastName);
        }

        rotaQuery += ` ORDER BY cr.day, cr.name, cr.lastName, cr.startTime`;

        const [rotaResults] = await pool.promise().query(rotaQuery, rotaParams);

        console.log('📊 Filtered rota records found:', rotaResults.length);

        // Get ALL holidays for active employees first
        let holidayQuery = `
            SELECT 
                h.name,
                h.lastName,
                h.startDate,
                h.endDate,
                h.accepted,
                e.wage as employee_wage,
                e.designation,
                e.Salary
            FROM Holiday h
            INNER JOIN Employees e ON h.name = e.name AND h.lastName = e.lastName
            WHERE h.accepted = 'true' 
            AND (e.situation != 'past' OR e.situation IS NULL)
        `;
        let holidayParams = [];

        if (employeeName && employeeName !== 'all') {
            const [firstName, lastName] = employeeName.split(' ');
            holidayQuery += ` AND h.name = ? AND h.lastName = ?`;
            holidayParams.push(firstName, lastName);
        }

        const [allHolidays] = await pool.promise().query(holidayQuery, holidayParams);
        console.log('🏖️ All holidays found:', allHolidays.length);
        console.log('🏖️ Sample holidays:', allHolidays.slice(0, 5));

        // Filter holidays in JavaScript to find overlaps with our date range
        const holidayResults = allHolidays.filter(holiday => {
            const holidayStart = parseCustomDate(holiday.startDate);
            const holidayEnd = parseCustomDate(holiday.endDate);
            
            // Check if holiday overlaps with any day in our range
            return formattedDays.some(day => {
                const currentDay = parseCustomDate(day);
                return currentDay >= holidayStart && currentDay <= holidayEnd;
            });
        });

        console.log('🏖️ Filtered holiday records found:', holidayResults.length);
        console.log('🏖️ Filtered holiday results details:', holidayResults);

        // Process data using wage from Employees table
        const employeeData = {};
        let grandTotalHours = 0;
        let grandTotalCost = 0;

        // Process rota shifts
        rotaResults.forEach(shift => {
            const key = `${shift.name} ${shift.lastName}`;
            const hours = calculateHours(shift.startTime, shift.endTime);
            const cost = hours * parseFloat(shift.employee_wage || 0);

            if (!employeeData[key]) {
                employeeData[key] = {
                    name: shift.name,
                    lastName: shift.lastName,
                    designation: shift.designation,
                    wage: parseFloat(shift.employee_wage || 0),
                    Salary: shift.Salary,
                    totalHours: 0,
                    totalCost: 0,
                    shifts: []
                };
            }

            employeeData[key].totalHours += hours;
            employeeData[key].totalCost += cost;
            employeeData[key].shifts.push({
                day: shift.day,
                startTime: shift.startTime,
                endTime: shift.endTime,
                hours: hours,
                cost: cost,
                who: shift.who,
                holidayType: null // This is a regular shift
            });

            grandTotalHours += hours;
            grandTotalCost += cost;
        });

        console.log('📊 After processing filtered rota shifts - employeeData keys:', Object.keys(employeeData));

        // Process holidays - handle each day of multi-day holidays
        for (const holiday of holidayResults) {
            const key = `${holiday.name} ${holiday.lastName}`;
            const holidayType = holiday.accepted === 'unpaid' ? 'unpaid' : 'paid';
            
            // Parse start and end dates
            const holidayStart = parseCustomDate(holiday.startDate);
            const holidayEnd = parseCustomDate(holiday.endDate);
            
            console.log(`🏖️ Processing filtered holiday for ${key}:`, {
                startDate: holiday.startDate,
                endDate: holiday.endDate,
                holidayStart: holidayStart,
                holidayEnd: holidayEnd,
                type: holidayType
            });

            if (!employeeData[key]) {
                employeeData[key] = {
                    name: holiday.name,
                    lastName: holiday.lastName,
                    designation: holiday.designation,
                    wage: parseFloat(holiday.employee_wage || 0),
                    Salary: holiday.Salary,
                    totalHours: 0,
                    totalCost: 0,
                    shifts: []
                };
                console.log(`🏖️ Created new employee entry for filtered holiday: ${key}`);
            }

            // Generate all days in the holiday range
            const currentHolidayDay = new Date(holidayStart);
            while (currentHolidayDay <= holidayEnd) {
                const formattedHolidayDay = formatDateForDisplay(new Date(currentHolidayDay));
                
                // Only include holidays that fall within our filtered days
                if (formattedDays.includes(formattedHolidayDay)) {
                    // Calculate holiday hours based on salary status and work history
                    const holidayCalculation = await calculateHolidayHours(
                        pool, 
                        holiday.name, 
                        holiday.lastName, 
                        holidayStart, 
                        holidayEnd
                    );

                    const hours = holidayType === 'paid' ? holidayCalculation.hours : 0;
                    const cost = holidayType === 'paid' ? holidayCalculation.cost : 0;

                    // Check if this day already has a shift entry
                    const existingShiftIndex = employeeData[key].shifts.findIndex(
                        shift => shift.day === formattedHolidayDay
                    );

                    console.log(`🏖️ Checking for existing shift on ${formattedHolidayDay}:`, existingShiftIndex);

                    if (existingShiftIndex === -1) {
                        // No existing shift for this day, add holiday
                        employeeData[key].totalHours += hours;
                        employeeData[key].totalCost += cost;
                        employeeData[key].shifts.push({
                            day: formattedHolidayDay,
                            startTime: null,
                            endTime: null,
                            hours: hours,
                            cost: cost,
                            who: 'Holiday',
                            holidayType: holidayType,
                            calculatedHours: hours,
                            isSalary: holiday.Salary === 'Yes'
                        });

                        grandTotalHours += hours;
                        grandTotalCost += cost;
                        console.log(`🏖️ Added filtered holiday for ${key} on ${formattedHolidayDay}: ${hours} hours, £${cost.toFixed(2)}`);
                    } else {
                        console.log(`🏖️ Skipping filtered holiday for ${key} on ${formattedHolidayDay} - shift already exists`);
                    }
                }
                
                currentHolidayDay.setDate(currentHolidayDay.getDate() + 1);
            }
        }

        console.log('📊 After processing filtered holidays - employeeData keys:', Object.keys(employeeData));

        // Sort shifts by date for each employee
        Object.values(employeeData).forEach(employee => {
            employee.shifts.sort((a, b) => {
                return new Date(parseCustomDate(a.day)) - new Date(parseCustomDate(b.day));
            });
        });

        const report = Object.values(employeeData).map(emp => ({
            ...emp,
            totalHours: parseFloat(emp.totalHours.toFixed(2)),
            totalCost: parseFloat(emp.totalCost.toFixed(2))
        }));

        res.json({
            report,
            summary: {
                totalEmployees: report.length,
                grandTotalHours: parseFloat(grandTotalHours.toFixed(2)),
                grandTotalCost: parseFloat(grandTotalCost.toFixed(2)),
                period: `${startDate} to ${endDate}`,
                employeeFilter: employeeName
            }
        });

    } catch (error) {
        console.error('❌ Error fetching filtered data:', error);
        res.status(500).json({ error: 'Failed to fetch filtered data' });
    }
});

// Generate PDF endpoint
app.post('/generate-pdf', isAuthenticated, isAM, async (req, res) => {
    const { htmlContent, filename } = req.body;
    let browser;

    try {
        const launchOptions = {
            headless: 'new',
            args: [
                '--no-sandbox',
                '--disable-setuid-sandbox',
                '--disable-dev-shm-usage',
                '--disable-gpu'
            ]
        };

        // Windows development
        if (process.env.NODE_ENV !== 'production' && process.platform === 'win32') {
            launchOptions.executablePath = 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe';
        }
        // Production - use Puppeteer's bundled Chrome
        else if (process.env.NODE_ENV === 'production') {
            launchOptions.executablePath = '/app/.chrome-for-testing/chrome-linux64/chrome';
        }

        browser = await puppeteer.launch(launchOptions);
        const page = await browser.newPage();
        await page.setContent(htmlContent, { waitUntil: 'networkidle0' });

        // Wait for content to render
        await new Promise(resolve => setTimeout(resolve, 1000));

        const pdfBuffer = await page.pdf({
            format: 'A4',
            printBackground: true,
            margin: {
                top: '15mm',
                right: '10mm',
                bottom: '15mm',
                left: '10mm'
            },
            displayHeaderFooter: true,
            headerTemplate: '<div style="font-size: 10px; width: 100%; text-align: center; color: #666;">Employee Hours Report</div>',
            footerTemplate: '<div style="font-size: 8px; width: 100%; text-align: center; color: #666;">Page <span class="pageNumber"></span> of <span class="totalPages"></span> - Generated on ' + new Date().toLocaleDateString('en-GB') + '</div>'
        });

        res.setHeader('Content-Type', 'application/pdf');
        res.setHeader('Content-Disposition', `attachment; filename="${filename}.pdf"`);
        res.end(pdfBuffer);

    } catch (error) {
        console.error('❌ PDF Generation Error:', error);
        res.status(500).json({ error: 'Failed to generate PDF: ' + error.message });
    } finally {
        if (browser) await browser.close();
    }
});

// Serve HTML file
app.get('/', isAuthenticated, isAM, (req, res) => {
    res.sendFile(path.join(__dirname, 'TimeTracking.html'));
});

module.exports = app;