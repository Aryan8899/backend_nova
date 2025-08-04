const express = require('express');
const nodemailer = require('nodemailer');
const { query } = require('../config/database');
const { AppError } = require('../middleware/errorHandler');

const router = express.Router();

// Store user email settings in the database
router.post('/set-email-config', async (req, res) => {
  const { userId, email, password, smtpHost, smtpPort } = req.body;

  if (!userId || !email || !password || !smtpHost || !smtpPort) {
    throw new AppError('All fields are required', 400);
  }

  try {
    // Store email configuration in the database (This could be encrypted)
    const result = await query(
      'INSERT INTO user_email_config (user_id, email, password, smtp_host, smtp_port) VALUES ($1, $2, $3, $4, $5) RETURNING id',
      [userId, email, password, smtpHost, smtpPort]
    );

    res.status(200).json({
      message: 'Email configuration saved successfully.',
      emailConfigId: result.rows[0].id,
    });
  } catch (error) {
    console.error('❌ Error saving email config:', error);
    throw new AppError('Failed to save email configuration.', 500);
  }
});

module.exports = router;
