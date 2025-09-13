const pool = require('../config/database');

class User {
  static async findById(id) {
    const result = await pool.query(
      'SELECT id, email, first_name, last_name, is_verified, created_at FROM users WHERE id = $1',
      [id]
    );
    return result.rows[0];
  }

  static async findByEmail(email) {
    const result = await pool.query(
      'SELECT id, email, password_hash, first_name, last_name, is_verified FROM users WHERE email = $1',
      [email]
    );
    return result.rows[0];
  }

  static async create(userData) {
    const { email, password_hash, first_name, last_name } = userData;
    const result = await pool.query(
      'INSERT INTO users (email, password_hash, first_name, last_name) VALUES ($1, $2, $3, $4) RETURNING id, email, first_name, last_name, is_verified, created_at',
      [email, password_hash, first_name, last_name]
    );
    return result.rows[0];
  }

  static async updateVerificationStatus(userId, isVerified) {
    const result = await pool.query(
      'UPDATE users SET is_verified = $1 WHERE id = $2 RETURNING id, email, first_name, last_name, is_verified',
      [isVerified, userId]
    );
    return result.rows[0];
  }

  static async updatePassword(userId, passwordHash) {
    await pool.query(
      'UPDATE users SET password_hash = $1 WHERE id = $2',
      [passwordHash, userId]
    );
  }
}

module.exports = User;