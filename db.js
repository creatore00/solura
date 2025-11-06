const mysql = require('mysql2');

// Base configuration with common settings
const baseConfig = {
  host: 'sv41.byethost41.org',
  connectionLimit: 350,
  waitForConnections: true,
  queueLimit: 0,
  connectTimeout: 10000,
};

// Database configurations for each company with specific users
const dbConfigs = {
  '100%pastaoxford': {
    ...baseConfig,
    database: 'yassir_100%pastaoxford',
    user: 'yassir_100pastaoxford',
    password: 'Qazokm123890'
  },
  'bbuonaoxford': {
    ...baseConfig,
    database: 'yassir_bbuonaoxford',
    user: 'yassir_bbuonaoxford',
    password: 'Qazokm123890'
  },
  main: {
    ...baseConfig,
    database: 'yassir_access',
    user: 'yassir_yassir',
    password: 'Qazokm123890'
  },
};
Object.keys(dbConfigs).forEach(db => {
});

// Cache for storing connection pools for each database
const pools = {};

// Create a connection pool for the main database
const mainPool = mysql.createPool(dbConfigs.main);
pools['main'] = mainPool;

// Log main pool creation
mainPool.on('connection', (connection) => {
});

// Function to get a connection pool based on the database name
function getPool(dbName) {
  
  if (pools[dbName]) {
    return pools[dbName];
  }

  if (!dbConfigs[dbName]) {
    console.error(`Configuration for ${dbName} not found!`);
    throw new Error(`Database configuration for ${dbName} not found.`);
  }
  
  // Create and cache a new pool for the database
  const newPool = mysql.createPool(dbConfigs[dbName]);
  pools[dbName] = newPool;

  // Add connection event logging for this pool
  newPool.on('connection', (connection) => {
  });

  newPool.on('acquire', (connection) => {
  });

  newPool.on('release', (connection) => {
  });

  return newPool;
}

// Close unused connections after 10 minutes for each pool
function closeIdleConnections() {
  
  Object.keys(pools).forEach((dbName) => {
    const pool = pools[dbName];
    
    pool.getConnection((err, connection) => {
      if (err) {
        console.error(`[${dbName.toUpperCase()}] Error getting connection:`, err);
        return;
      }

      // Fetch process list to identify idle connections
      connection.query('SHOW PROCESSLIST', (err, results) => {
        if (err) {
          console.error(`[${dbName.toUpperCase()}] Error fetching process list:`, err);
        } else {
          results.forEach((process) => {
            if (process.Time > 600) { // 600 seconds = 10 minutes
              connection.query(`KILL ${process.Id}`);
            }
          });
        }
        connection.release();
      });
    });
  });
}

// Run idle connection cleanup every 10 minutes
setInterval(closeIdleConnections, 60000);

// Export the main pool and getPool function for use in other files
module.exports = { getPool, mainPool };
