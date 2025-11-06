// utils/dbPromise.js
module.exports = {
    query: (pool, sql, params) => {
        return new Promise((resolve, reject) => {
            pool.query(sql, params, (err, results) => {
                if (err) return reject(err);
                resolve(results);
            });
        });
    }
};