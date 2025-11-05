const session = require('express-session');
const MySQLStore = require('express-mysql-session')(session);
const { mainPool } = require('./db.js');

// Configure the MySQL session store
const sessionStore = new MySQLStore({
    expiration: 60 * 60 * 1000, // 1 hour (session timeout)
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
    secret: process.env.SESSION_SECRET || 'your_secret_here', // Use environment variable for security
    resave: false, // Don't resave the session if it hasn't changed
    saveUninitialized: false, // Don't save uninitialized sessions
    store: sessionStore, // Use the MySQL session store
    cookie: {
        maxAge: 24 * 60 * 60 * 1000, // 24 hours (session cookie expiration)
        secure: process.env.NODE_ENV === 'production', // Set to true in production with HTTPS
        httpOnly: true, // Prevent client-side JavaScript from accessing the cookie
        sameSite: 'lax', // CSRF protection
    },
    name: 'connect.sid', // Standard session cookie name
    proxy: true, // Trust proxy for secure cookies
    rolling: true, // Reset maxAge on every request
});

// Enhanced middleware to check if the user is authenticated
function isAuthenticated(req, res, next) {
    console.log('=== AUTH MIDDLEWARE DEBUG ===');
    console.log('Session ID:', req.sessionID);
    console.log('Session exists:', !!req.session);
    console.log('Session User:', req.session?.user);
    console.log('Path:', req.path);
    console.log('Method:', req.method);
    console.log('Cookies:', req.headers.cookie);
    
    // Check if session exists
    if (!req.session) {
        console.log('❌ No session object found');
        return handleAuthError(req, res, 'No session found');
    }
    
    // Check if user exists in session
    if (!req.session.user) {
        console.log('❌ No user in session');
        return handleAuthError(req, res, 'No user in session');
    }
    
    // Check if user has required properties
    if (!req.session.user.dbName || !req.session.user.email) {
        console.log('❌ Incomplete user data in session');
        return handleAuthError(req, res, 'Incomplete session data');
    }
    
    console.log('✅ Authentication SUCCESS for user:', req.session.user.email);
    
    // Update session to extend expiration
    req.session.touch();
    next();
}

// Helper function to handle authentication errors
function handleAuthError(req, res, errorMessage) {
    console.log('Authentication FAILED:', errorMessage);
    
    // For API routes, return JSON error
    if (req.path.startsWith('/api/') || req.path.startsWith('/tip/') || req.xhr) {
        return res.status(401).json({ 
            success: false, 
            error: 'Unauthorized',
            message: 'Please log in again',
            details: errorMessage,
            sessionInfo: {
                hasSession: !!req.session,
                hasUser: !!req.session?.user,
                sessionId: req.sessionID
            }
        });
    }
    
    // For HTML routes, redirect to login
    res.redirect('/');
}

// Enhanced isAdmin middleware with proper checks
function isAdmin(req, res, next) {
    if (!req.session?.user) {
        return handleAuthError(req, res, 'No user session for admin check');
    }
    
    if (req.session.user.role === 'admin' || req.session.user.role === 'AM') {
        console.log('✅ Admin access granted for:', req.session.user.email);
        return next();
    }
    
    console.log('❌ Admin access denied for:', req.session.user.email);
    
    if (req.path.startsWith('/api/') || req.path.startsWith('/tip/') || req.xhr) {
        return res.status(403).json({ 
            success: false, 
            error: 'Forbidden',
            message: 'Admin access required'
        });
    }
    
    res.redirect('/');
}

// isAM is an alias for isAdmin (removed duplicate)
function isAM(req, res, next) {
    return isAdmin(req, res, next);
}

// Enhanced isSupervisor middleware
function isSupervisor(req, res, next) {
    if (!req.session?.user) {
        return handleAuthError(req, res, 'No user session for supervisor check');
    }
    
    if (req.session.user.role === 'supervisor') {
        console.log('✅ Supervisor access granted for:', req.session.user.email);
        return next();
    }
    
    console.log('❌ Supervisor access denied for:', req.session.user.email);
    
    if (req.path.startsWith('/api/') || req.path.startsWith('/tip/') || req.xhr) {
        return res.status(403).json({ 
            success: false, 
            error: 'Forbidden',
            message: 'Supervisor access required'
        });
    }
    
    res.redirect('/');
}

// Enhanced isUser middleware
function isUser(req, res, next) {
    if (!req.session?.user) {
        return handleAuthError(req, res, 'No user session for user check');
    }
    
    if (req.session.user.role === 'user') {
        console.log('✅ User access granted for:', req.session.user.email);
        return next();
    }
    
    console.log('❌ User access denied for:', req.session.user.email);
    
    if (req.path.startsWith('/api/') || req.path.startsWith('/tip/') || req.xhr) {
        return res.status(403).json({ 
            success: false, 
            error: 'Forbidden',
            message: 'User access required'
        });
    }
    
    res.redirect('/');
}

// Export the session middleware and role-based middleware
module.exports = { 
    sessionMiddleware, 
    isAuthenticated, 
    isAM, 
    isAdmin, 
    isSupervisor, 
    isUser 
};