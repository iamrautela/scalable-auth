const { Pool } = require('pg');
const fs = require('fs');
const path = require('path');

const pool = new Pool({
  user: process.env.DB_USER || 'auth_user',
  host: process.env.DB_HOST || 'localhost',
  database: process.env.DB_NAME || 'auth_db',
  password: process.env.DB_PASSWORD || 'auth_password',
  port: process.env.DB_PORT || 5432,
});

async function setupDatabase() {
  try {
    // Read the SQL file
    const sql = fs.readFileSync(path.join(__dirname, 'init-database.sql'), 'utf8');
    
    // Execute the SQL commands
    await pool.query(sql);
    
    console.log('Database setup completed successfully');
  } catch (error) {
    console.error('Error setting up database:', error);
  } finally {
    await pool.end();
  }
}

setupDatabase();