const express = require('express');
const bcrypt = require('bcryptjs');
const { query } = require('../config/database');
const { generateToken, generateRefreshToken } = require('../middleware/auth');
const { validateRegistration, validateLogin } = require('../middleware/validation');
const { requireRecaptchaForRegistration, requireRecaptchaForLogin } = require('../middleware/recaptcha');
const { asyncHandler, AppError } = require('../middleware/errorHandler');

const router = express.Router();

// Register new user (with reCAPTCHA)
router.post('/register', 
  requireRecaptchaForRegistration, 
  validateRegistration, 
  asyncHandler(async (req, res) => {
    const { email, password, first_name, last_name } = req.body;

    // Check if user already exists
    const existingUser = await query(
      'SELECT id FROM users WHERE email = $1',
      [email]
    );

    if (existingUser.rows.length > 0) {
      throw new AppError('User with this email already exists', 409);
    }

    // Hash password
    const saltRounds = 12;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // Insert new user
    const result = await query(
      `INSERT INTO users (email, password, first_name, last_name) 
       VALUES ($1, $2, $3, $4) 
       RETURNING id, email, first_name, last_name, created_at`,
      [email, hashedPassword, first_name || null, last_name || null]
    );

    const newUser = result.rows[0];

    // Generate tokens
    const token = generateToken(newUser);
    const refreshToken = generateRefreshToken(newUser);

    // Log successful registration with reCAPTCHA info
    console.log(`✅ New user registered: ${email}, reCAPTCHA score: ${req.recaptcha?.score || 'N/A'}`);

    res.status(201).json({
      message: 'User registered successfully',
      user: {
        id: newUser.id,
        email: newUser.email,
        first_name: newUser.first_name,
        last_name: newUser.last_name,
        created_at: newUser.created_at
      },
      token,
      refreshToken
    });
  })
);

// Login user (with reCAPTCHA)
router.post('/login', 
  requireRecaptchaForLogin, 
  validateLogin, 
  asyncHandler(async (req, res) => {
    const { email, password } = req.body;

    // Find user
    const result = await query(
      'SELECT id, email, password, first_name, last_name, is_active FROM users WHERE email = $1',
      [email]
    );

    if (result.rows.length === 0) {
      throw new AppError('Invalid email or password', 401);
    }

    const user = result.rows[0];

    // Check if user is active
    if (!user.is_active) {
      throw new AppError('Account has been deactivated', 401);
    }

    // Verify password
    const isValidPassword = await bcrypt.compare(password, user.password);

    if (!isValidPassword) {
      throw new AppError('Invalid email or password', 401);
    }

    // Generate tokens
    const token = generateToken(user);
    const refreshToken = generateRefreshToken(user);

    // Log successful login with reCAPTCHA info
    console.log(`✅ User logged in: ${email}, reCAPTCHA score: ${req.recaptcha?.score || 'N/A'}`);

    res.json({
      message: 'Login successful',
      user: {
        id: user.id,
        email: user.email,
        first_name: user.first_name,
        last_name: user.last_name
      },
      token,
      refreshToken
    });
  })
);

// Refresh token
router.post('/refresh', asyncHandler(async (req, res) => {
  const { refreshToken } = req.body;

  if (!refreshToken) {
    throw new AppError('Refresh token is required', 400);
  }

  try {
    const jwt = require('jsonwebtoken');
    const decoded = jwt.verify(refreshToken, process.env.JWT_SECRET);

    if (decoded.type !== 'refresh') {
      throw new AppError('Invalid refresh token', 401);
    }

    // Check if user still exists and is active
    const userResult = await query(
      'SELECT id, email, first_name, last_name, is_active FROM users WHERE id = $1',
      [decoded.userId]
    );

    if (userResult.rows.length === 0 || !userResult.rows[0].is_active) {
      throw new AppError('User not found or inactive', 401);
    }

    const user = userResult.rows[0];

    // Generate new tokens
    const newToken = generateToken(user);
    const newRefreshToken = generateRefreshToken(user);

    res.json({
      message: 'Token refreshed successfully',
      token: newToken,
      refreshToken: newRefreshToken
    });

  } catch (error) {
    if (error.name === 'JsonWebTokenError' || error.name === 'TokenExpiredError') {
      throw new AppError('Invalid or expired refresh token', 401);
    }
    throw error;
  }
}));

// Forgot password (placeholder - you would implement email sending here)
router.post('/forgot-password', asyncHandler(async (req, res) => {
  const { email } = req.body;

  if (!email) {
    throw new AppError('Email is required', 400);
  }

  // Check if user exists
  const userResult = await query(
    'SELECT id FROM users WHERE email = $1 AND is_active = true',
    [email.toLowerCase().trim()]
  );

  // Always return success message for security (don't reveal if email exists)
  res.json({
    message: 'If an account with that email exists, a password reset link has been sent'
  });

  // TODO: Implement password reset token generation and email sending
  // if (userResult.rows.length > 0) {
  //   // Generate reset token
  //   // Save token to database with expiry
  //   // Send email with reset link
  // }
}));

// Logout (for token blacklisting in production)
router.post('/logout', asyncHandler(async (req, res) => {
  // In production, you might want to implement token blacklisting
  // For now, just return success (client should delete the token)
  res.json({ 
    message: 'Logged out successfully'
  });
}));

module.exports = router;