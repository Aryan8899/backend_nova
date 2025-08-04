// routes/auth.js
const express = require('express');
const bcrypt = require('bcryptjs');
const { query } = require('../config/database');
const { generateToken, generateRefreshToken } = require('../middleware/auth');
const { validateRegistration, validateLogin } = require('../middleware/validation');
const { requireRecaptchaForRegistration, requireRecaptchaForLogin } = require('../middleware/recaptcha');
const { asyncHandler, AppError } = require('../middleware/errorHandler');
// const { sendVerificationEmail, sendWelcomeEmail } = require('../config/email');
const { sendEmail } = require('../config/email');

const router = express.Router();


// Send verification email after user registration
const sendVerificationEmail = async (userId, verificationCode, firstName) => {
  const subject = 'Email Verification';
  const text = `Hello ${firstName || 'User'},\n\nPlease verify your email by entering the following code: ${verificationCode}\n\nThe code expires in 10 minutes.\n\nThank you!`;

  const emailResult = await sendEmail(userId, subject, text);

  if (emailResult.success) {
    console.log(`✅ Verification email sent to user: ${firstName}`);
  } else {
    console.error('❌ Failed to send verification email');
  }
};

// Generate random 6-digit verification code
const generateVerificationCode = () => {
  return Math.floor(100000 + Math.random() * 900000).toString();
};

// Register new user (with reCAPTCHA and email verification)
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

    // Generate verification code
    const verificationCode = generateVerificationCode();
    const verificationExpires = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes

    // Insert new user (unverified)
    const result = await query(
      `INSERT INTO users (
        email, password, first_name, last_name, 
        is_verified, verification_code, verification_expires
      ) VALUES ($1, $2, $3, $4, $5, $6, $7) 
      RETURNING id, email, first_name, last_name, created_at`,
      [email, hashedPassword, first_name || null, last_name || null, false, verificationCode, verificationExpires]
    );

    const newUser = result.rows[0];

    // Send verification email
    try {
      await sendVerificationEmail(email, verificationCode, first_name);
      console.log(`✅ User registered and verification email sent: ${email}, reCAPTCHA score: ${req.recaptcha?.score || 'N/A'}`);
    } catch (emailError) {
      console.error('❌ Failed to send verification email:', emailError);
      // Delete the user if email fails to send
      await query('DELETE FROM users WHERE id = $1', [newUser.id]);
      throw new AppError('Failed to send verification email. Please try again.', 500);
    }

    res.status(201).json({
      message: 'User registered successfully. Please check your email for verification code.',
      user: {
        id: newUser.id,
        email: newUser.email,
        first_name: newUser.first_name,
        last_name: newUser.last_name,
        created_at: newUser.created_at,
        is_verified: false
      },
      next_step: 'Please verify your email using the code sent to your email address'
    });
  })
);

// Verify email with code
router.post('/verify-email', asyncHandler(async (req, res) => {
  const { email, verificationCode } = req.body;

  if (!email || !verificationCode) {
    throw new AppError('Email and verification code are required', 400);
  }

  // Find user with matching email and verification code
  const result = await query(
    `SELECT id, email, first_name, last_name, verification_code, verification_expires, is_verified 
     FROM users 
     WHERE email = $1 AND is_active = true`,
    [email]
  );

  if (result.rows.length === 0) {
    throw new AppError('User not found', 404);
  }

  const user = result.rows[0];

  // Check if already verified
  if (user.is_verified) {
    throw new AppError('Email is already verified', 400);
  }

  // Check if verification code matches
  if (user.verification_code !== verificationCode) {
    throw new AppError('Invalid verification code', 400);
  }

  // Check if code has expired
  if (new Date() > new Date(user.verification_expires)) {
    throw new AppError('Verification code has expired. Please request a new one.', 400);
  }

  // Update user as verified
  await query(
    `UPDATE users 
     SET is_verified = true, verification_code = NULL, verification_expires = NULL, updated_at = CURRENT_TIMESTAMP
     WHERE id = $1`,
    [user.id]
  );

  // Generate tokens for verified user
  const token = generateToken(user);
  const refreshToken = generateRefreshToken(user);

  // Send welcome email
  try {
    await sendWelcomeEmail(user.email, user.first_name);
  } catch (emailError) {
    console.error('❌ Failed to send welcome email:', emailError);
    // Don't fail the verification if welcome email fails
  }

  console.log(`✅ Email verified for user: ${email}`);

  res.json({
    message: 'Email verified successfully! Your account is now active.',
    user: {
      id: user.id,
      email: user.email,
      first_name: user.first_name,
      last_name: user.last_name,
      is_verified: true
    },
    token,
    refreshToken
  });
}));

// Resend verification code
router.post('/resend-verification', asyncHandler(async (req, res) => {
  const { email } = req.body;

  if (!email) {
    throw new AppError('Email is required', 400);
  }

  // Find unverified user
  const result = await query(
    'SELECT id, first_name, is_verified FROM users WHERE email = $1 AND is_active = true',
    [email]
  );

  if (result.rows.length === 0) {
    throw new AppError('User not found', 404);
  }

  const user = result.rows[0];

  if (user.is_verified) {
    throw new AppError('Email is already verified', 400);
  }

  // Generate new verification code
  const verificationCode = generateVerificationCode();
  const verificationExpires = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes

  // Update verification code
  await query(
    'UPDATE users SET verification_code = $1, verification_expires = $2 WHERE id = $3',
    [verificationCode, verificationExpires, user.id]
  );

  // Send new verification email
  try {
    await sendVerificationEmail(email, verificationCode, user.first_name);
    console.log(`✅ Verification code resent to: ${email}`);
  } catch (emailError) {
    console.error('❌ Failed to resend verification email:', emailError);
    throw new AppError('Failed to send verification email. Please try again.', 500);
  }

  res.json({
    message: 'Verification code sent successfully. Please check your email.'
  });
}));

// Login user (with reCAPTCHA) - Only allow verified users
router.post('/login', 
  requireRecaptchaForLogin, 
  validateLogin, 
  asyncHandler(async (req, res) => {
    const { email, password } = req.body;

    // Find user
    const result = await query(
      'SELECT id, email, password, first_name, last_name, is_active, is_verified FROM users WHERE email = $1',
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

    // Check if email is verified
    if (!user.is_verified) {
      throw new AppError('Please verify your email address before logging in', 401);
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
        last_name: user.last_name,
        is_verified: user.is_verified
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

    // Check if user still exists, is active, and verified
    const userResult = await query(
      'SELECT id, email, first_name, last_name, is_active, is_verified FROM users WHERE id = $1',
      [decoded.userId]
    );

    if (userResult.rows.length === 0 || !userResult.rows[0].is_active || !userResult.rows[0].is_verified) {
      throw new AppError('User not found, inactive, or unverified', 401);
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

  // Check if user exists and is verified
  const userResult = await query(
    'SELECT id FROM users WHERE email = $1 AND is_active = true AND is_verified = true',
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