const mysql = require('mysql2');

// Common database connection settings
const commonConfig = {
  host: 'sv41.byethost41.org',
  user: 'yassir_yassir',
  password: 'Qazokm123890',
  connectionLimit: 350, // Limit the number of connections
  waitForConnections: true,
  queueLimit: 0,
  connectTimeout: 10000, // Timeout for connecting
};

// Database configurations for each company
const dbConfigs = {
  '100%pastaoxford': {
    ...commonConfig,
    database: 'yassir_100%pastaoxford',
  },
  'bbuonaoxford': {
    ...commonConfig,
    database: 'yassir_bbuonaoxford',
  },
  main: {
    ...commonConfig,
    database: 'yassir_access',
  },
};

// Cache for storing connection pools for each database
const pools = {};

// Create a connection pool for the main database
const mainPool = mysql.createPool(dbConfigs.main);
pools['main'] = mainPool;

// Function to get a connection pool based on the database name
function getPool(dbName) {
  if (pools[dbName]) {
    // Return cached pool if it exists
    return pools[dbName];
  }

  if (!dbConfigs[dbName]) {
    throw new Error(`Database configuration for ${dbName} not found.`);
  }

  // Create and cache a new pool for the database
  const newPool = mysql.createPool(dbConfigs[dbName]);
  pools[dbName] = newPool;

  return newPool;
}

// Close unused connections after 10 minutes for each pool
function closeIdleConnections() {
  console.log('Checking for idle connections...');
  
  Object.keys(pools).forEach((dbName) => {
    const pool = pools[dbName];
    
    pool.getConnection((err, connection) => {
      if (err) {
        console.error(`Error getting connection for ${dbName}:`, err);
        return;
      }

      // Fetch process list to identify idle connections
      connection.query('SHOW PROCESSLIST', (err, results) => {
        if (err) {
          console.error(`Error fetching process list for ${dbName}:`, err);
        } else {
          results.forEach((process) => {
            if (process.Time > 600) { // 600 seconds = 10 minutes
              console.log(`Closing idle connection (ID: ${process.Id}) in database ${dbName}`);
              connection.query(`KILL ${process.Id}`);
            }
          });
        }
        connection.release(); // Always release connection after query
      });
    });
  });
}

// Run idle connection cleanup every 10 minutes
setInterval(closeIdleConnections, 60000); // Run every minute to check idle connections

// Export the main pool and getPool function for use in other files
module.exports = { getPool, mainPool };
