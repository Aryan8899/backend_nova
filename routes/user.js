const express = require('express');
const bcrypt = require('bcryptjs');
const { query } = require('../config/database');
const { authenticateToken } = require('../middleware/auth');
const { validatePasswordChange, validateProfileUpdate } = require('../middleware/validation');
const { requireRecaptchaForSensitive } = require('../middleware/recaptcha');
const { asyncHandler, AppError } = require('../middleware/errorHandler');

const router = express.Router();

// Get user profile (protected route)
router.get('/profile', authenticateToken, asyncHandler(async (req, res) => {
  const result = await query(
    'SELECT id, email, first_name, last_name, created_at, updated_at FROM users WHERE id = $1',
    [req.user.userId]
  );

  if (result.rows.length === 0) {
    throw new AppError('User not found', 404);
  }

  res.json({
    user: result.rows[0]
  });
}));

// Update user profile (protected route)
router.put('/profile', authenticateToken, validateProfileUpdate, asyncHandler(async (req, res) => {
  const { first_name, last_name, email } = req.body;
  const updates = [];
  const values = [];
  let paramCount = 1;

  // Build dynamic update query
  if (first_name !== undefined) {
    updates.push(`first_name = $${paramCount}`);
    values.push(first_name);
    paramCount++;
  }

  if (last_name !== undefined) {
    updates.push(`last_name = $${paramCount}`);
    values.push(last_name);
    paramCount++;
  }

  if (email !== undefined) {
    // Check if email is already taken by another user
    const emailCheck = await query(
      'SELECT id FROM users WHERE email = $1 AND id != $2',
      [email, req.user.userId]
    );

    if (emailCheck.rows.length > 0) {
      throw new AppError('Email is already taken by another user', 409);
    }

    updates.push(`email = $${paramCount}`);
    values.push(email);
    paramCount++;
  }

  if (updates.length === 0) {
    throw new AppError('No valid fields to update', 400);
  }

  // Add user ID to values array
  values.push(req.user.userId);

  const updateQuery = `
    UPDATE users 
    SET ${updates.join(', ')}, updated_at = CURRENT_TIMESTAMP 
    WHERE id = ${paramCount} 
    RETURNING id, email, first_name, last_name, updated_at
  `;

  const result = await query(updateQuery, values);

  res.json({
    message: 'Profile updated successfully',
    user: result.rows[0]
  });
}));

// Change password (protected route with reCAPTCHA)
router.put('/change-password', 
  authenticateToken, 
  requireRecaptchaForSensitive,
  validatePasswordChange, 
  asyncHandler(async (req, res) => {
    const { currentPassword, newPassword } = req.body;

    // Get current user password
    const userResult = await query(
      'SELECT password FROM users WHERE id = $1',
      [req.user.userId]
    );

    if (userResult.rows.length === 0) {
      throw new AppError('User not found', 404);
    }

    // Verify current password
    const isValidPassword = await bcrypt.compare(
      currentPassword, 
      userResult.rows[0].password
    );

    if (!isValidPassword) {
      throw new AppError('Current password is incorrect', 401);
    }

    // Hash new password
    const saltRounds = 12;
    const hashedNewPassword = await bcrypt.hash(newPassword, saltRounds);

    // Update password
    await query(
      'UPDATE users SET password = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2',
      [hashedNewPassword, req.user.userId]
    );

    console.log(`🔒 Password changed for user ${req.user.email}, reCAPTCHA score: ${req.recaptcha?.score || 'N/A'}`);

    res.json({ 
      message: 'Password updated successfully' 
    });
  })
);

// Get all users (protected route - admin only in future)
router.get('/list', authenticateToken, asyncHandler(async (req, res) => {
  // Add pagination
  const page = parseInt(req.query.page) || 1;
  const limit = parseInt(req.query.limit) || 10;
  const offset = (page - 1) * limit;

  // Get total count
  const countResult = await query('SELECT COUNT(*) as total FROM users WHERE is_active = true');
  const totalUsers = parseInt(countResult.rows[0].total);
  const totalPages = Math.ceil(totalUsers / limit);

  // Get users with pagination
  const result = await query(
    `SELECT id, email, first_name, last_name, created_at 
     FROM users 
     WHERE is_active = true 
     ORDER BY created_at DESC 
     LIMIT $1 OFFSET $2`,
    [limit, offset]
  );

  res.json({
    users: result.rows,
    pagination: {
      currentPage: page,
      totalPages,
      totalUsers,
      hasNextPage: page < totalPages,
      hasPrevPage: page > 1
    }
  });
}));

// Deactivate account (protected route with reCAPTCHA)
router.delete('/account', 
  authenticateToken, 
  requireRecaptchaForSensitive,
  asyncHandler(async (req, res) => {
    const { password } = req.body;

    if (!password) {
      throw new AppError('Password is required to deactivate account', 400);
    }

    // Verify password
    const userResult = await query(
      'SELECT password FROM users WHERE id = $1',
      [req.user.userId]
    );

    if (userResult.rows.length === 0) {
      throw new AppError('User not found', 404);
    }

    const isValidPassword = await bcrypt.compare(password, userResult.rows[0].password);

    if (!isValidPassword) {
      throw new AppError('Invalid password', 401);
    }

    // Deactivate account (soft delete)
    await query(
      'UPDATE users SET is_active = false, updated_at = CURRENT_TIMESTAMP WHERE id = $1',
      [req.user.userId]
    );

    console.log(`🗑️  Account deactivated for user ${req.user.email}, reCAPTCHA score: ${req.recaptcha?.score || 'N/A'}`);

    res.json({
      message: 'Account deactivated successfully'
    });
  })
);

// Get user statistics (protected route)
router.get('/stats', authenticateToken, asyncHandler(async (req, res) => {
  const userResult = await query(
    'SELECT created_at FROM users WHERE id = $1',
    [req.user.userId]
  );

  if (userResult.rows.length === 0) {
    throw new AppError('User not found', 404);
  }

  const user = userResult.rows[0];
  const accountAge = Math.floor((new Date() - new Date(user.created_at)) / (1000 * 60 * 60 * 24));

  res.json({
    stats: {
      accountCreated: user.created_at,
      accountAgeDays: accountAge,
      lastLogin: new Date().toISOString() // In production, you'd track this
    }
  });
}));

module.exports = router;