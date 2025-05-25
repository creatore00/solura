const session = require('express-session');
const MySQLStore = require('express-mysql-session')(session);
const { mainPool } = require('./db.js');

// Configure the MySQL session store
const sessionStore = new MySQLStore({
    expiration: 60 * 10 * 1000, // 1 hour (session timeout)
    schema: {
        tableName: 'sessions', // Name of the sessions table
    },
    createDatabaseTable: true, // Automatically create the sessions table if it doesn't exist
    clearExpired: true, // Automatically clear expired sessions
    checkExpirationInterval: 60000, // Check for expired sessions every minute
    connectionLimit: 1, // Limit the number of connections for session storage
    endConnectionOnClose: true, // Close the connection when the session store is closed
}, mainPool); // Use the mainPool for session storage

// Session middleware configuration
const sessionMiddleware = session({
    key: 'session_cookie_name', // Name of the session cookie
    secret: 'your_secret_here', // Replace with a secret key for session encryption
    resave: false, // Don't resave the session if it hasn't changed
    saveUninitialized: false, // Don't save uninitialized sessions
    store: sessionStore, // Use the MySQL session store
    cookie: {
        maxAge: 60 * 60 * 1000, // 1 hour (session cookie expiration)
        secure: false, // Set to true if using HTTPS
        httpOnly: true, // Prevent client-side JavaScript from accessing the cookie
    },
});


// Middleware to check if the user is authenticated
function isAuthenticated(req, res, next) {
    if (req.session.user) {
        return next();
    }
    res.redirect('/');
}

// Middleware to check if the user is an admin or assistant manager
function isAdmin(req, res, next) {
    const role = req.session.user?.role;
    if (role === 'admin' || role === 'AM') {
        return next();
    } else {
        return res.status(403).json({ error: 'Access denied' });
    }
}


// Middleware to check if the user is a supervisor
function isSupervisor(req, res, next) {
    if (req.session.user && req.session.user.role === 'supervisor') {
        return next();
    } else {
        return res.status(403).json({ error: 'Access denied' });
    }
}

// Middleware to check if the user is a regular user
function isUser(req, res, next) {
    if (req.session.user && req.session.user.role === 'user') {
        return next();
    } else {
        return res.status(403).json({ error: 'Access denied' });
    }
}

// Export the session middleware and role-based middleware
module.exports = { sessionMiddleware, isAuthenticated, isAdmin, isSupervisor, isUser };