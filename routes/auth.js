const express = require('express');
const {
  register,
  login,
  refreshToken,
  verifyEmail,
  forgotPassword,
  resetPassword,
  getProfile
} = require('../controllers/authController');
const { authenticateToken } = require('../middleware/auth');
const { authRateLimit } = require('../middleware/rateLimit');
const {
  registerValidation,
  loginValidation,
  refreshTokenValidation,
  forgotPasswordValidation,
  resetPasswordValidation
} = require('../middleware/validation');

const router = express.Router();

// Public routes
router.post('/register', authRateLimit, registerValidation, register);
router.post('/login', authRateLimit, loginValidation, login);
router.post('/refresh-token', refreshTokenValidation, refreshToken);
router.get('/verify-email/:token', verifyEmail);
router.post('/forgot-password', authRateLimit, forgotPasswordValidation, forgotPassword);
router.post('/reset-password', authRateLimit, resetPasswordValidation, resetPassword);

// Protected routes
router.get('/profile', authenticateToken, getProfile);

module.exports = router;