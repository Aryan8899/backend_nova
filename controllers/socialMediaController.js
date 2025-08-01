// controllers/socialMediaController.js
const { query } = require('../config/database');
const axios = require('axios');
const { AppError, asyncHandler } = require('../middleware/errorHandler');

// Utility: Save verification to DB
async function saveVerification(userId, platform, status, username) {
  console.log('saveVerification called with:', { userId, platform, status, username });
  
  try {
    const result = await query(
      `INSERT INTO user_social_verification (user_id, platform, status, username, verified_at)
       VALUES ($1, $2, $3, $4, NOW())
       ON CONFLICT (user_id, platform) 
       DO UPDATE SET status = $3, username = $4, verified_at = NOW()`,
      [userId, platform, status, username]
    );
    console.log('Database query executed successfully');
    return result;
  } catch (error) {
    console.error('Database query error:', error);
    throw new AppError(`Database error: ${error.message}`, 500);
  }
}

// GET user's social stats
exports.getUserSocialStats = asyncHandler(async (req, res) => {
  console.log('=== Getting user social stats ===');
  console.log('User ID:', req.user?.userId);
  
  const userId = req.user.userId;
  
  try {
    const result = await query(
      `SELECT platform, status, username, verified_at 
       FROM user_social_verification 
       WHERE user_id = $1`,
      [userId]
    );
    
    console.log('Social stats retrieved:', result.rows);
    res.json({ 
      success: true,
      social: result.rows 
    });
  } catch (error) {
    console.error('Error getting social stats:', error);
    throw new AppError('Failed to get social verification status', 500);
  }
});

// Twitter/X follow check (Mock implementation)
exports.verifyTwitterFollow = asyncHandler(async (req, res) => {
  console.log('=== Twitter verification request received ===');
  console.log('User ID:', req.user?.userId);
  console.log('Request body:', req.body);
  console.log('Headers:', req.headers);
  
  const userId = req.user.userId;
  const { twitterUsername } = req.body;

  console.log('Checking if username exists:', twitterUsername);
  if (!twitterUsername) {
    console.log('ERROR: Twitter username missing');
    throw new AppError('Twitter username is required', 400);
  }

  // Validate username format
  if (!twitterUsername.startsWith('@')) {
    console.log('ERROR: Invalid Twitter username format');
    throw new AppError('Twitter username must start with @', 400);
  }

  console.log('About to check follow status (mock implementation)...');
  
  // ---- MOCK LOGIC (replace with Twitter API OAuth2 flow in production) ----
  // In production, you would:
  // 1. Have user authenticate with Twitter OAuth
  // 2. Get their access token
  // 3. Call Twitter API to check if they follow your account
  // 4. For now, we'll simulate this with a mock response
  
  const FOLLOWS = true; // For demo, always returns true
  console.log('Mock follow status:', FOLLOWS);

  try {
    if (FOLLOWS) {
      console.log('User is following - saving verification to database...');
      await saveVerification(userId, 'twitter', true, twitterUsername);
      console.log('Verification saved successfully');
      
      res.json({ 
        success: true,
        message: 'Twitter follow verified successfully',
        platform: 'twitter', 
        username: twitterUsername,
        verified_at: new Date().toISOString()
      });
    } else {
      console.log('User not following - saving failed verification');
      await saveVerification(userId, 'twitter', false, twitterUsername);
      
      res.status(400).json({ 
        success: false,
        error: 'Twitter follow not verified',
        message: 'Please follow our Twitter account first',
        platform: 'twitter',
        username: twitterUsername
      });
    }
  } catch (error) {
    console.error('Error in Twitter verification:', error);
    throw error;
  }
});

// Telegram group join check (Mock implementation)
exports.verifyTelegramJoin = asyncHandler(async (req, res) => {
  console.log('=== Telegram verification request received ===');
  console.log('User ID:', req.user?.userId);
  console.log('Request body:', req.body);
  
  const userId = req.user.userId;
  const { telegramUsername } = req.body;

  console.log('Checking if Telegram username exists:', telegramUsername);
  if (!telegramUsername) {
    console.log('ERROR: Telegram username missing');
    throw new AppError('Telegram username is required', 400);
  }

  // Validate username format
  if (!telegramUsername.startsWith('@')) {
    console.log('ERROR: Invalid Telegram username format');
    throw new AppError('Telegram username must start with @', 400);
  }

  console.log('About to check Telegram join status (mock implementation)...');
  
  // ---- MOCK LOGIC (replace with Telegram Bot API in production) ----
  // In production, you would:
  // 1. Use Telegram Bot API
  // 2. Call getChatMember to check if user is in your channel/group
  // 3. For now, we'll simulate this with a mock response
  
  const JOINED = true; // For demo, always returns true
  console.log('Mock join status:', JOINED);

  try {
    if (JOINED) {
      console.log('User has joined - saving verification to database...');
      await saveVerification(userId, 'telegram', true, telegramUsername);
      console.log('Telegram verification saved successfully');
      
      res.json({ 
        success: true,
        message: 'Telegram join verified successfully',
        platform: 'telegram', 
        username: telegramUsername,
        verified_at: new Date().toISOString()
      });
    } else {
      console.log('User not in group - saving failed verification');
      await saveVerification(userId, 'telegram', false, telegramUsername);
      
      res.status(400).json({ 
        success: false,
        error: 'Telegram join not verified',
        message: 'Please join our Telegram channel first',
        platform: 'telegram',
        username: telegramUsername
      });
    }
  } catch (error) {
    console.error('Error in Telegram verification:', error);
    throw error;
  }
});

// Instagram follow check (Mock implementation - currently disabled in routes)
exports.verifyInstagramFollow = asyncHandler(async (req, res) => {
  console.log('=== Instagram verification request received ===');
  console.log('User ID:', req.user?.userId);
  console.log('Request body:', req.body);
  
  const userId = req.user.userId;
  const { instagramUsername } = req.body;

  if (!instagramUsername) {
    throw new AppError('Instagram username is required', 400);
  }

  // ---- MOCK LOGIC (Instagram API is more complex) ----
  // Instagram's API requires business accounts and app review
  // This is a placeholder for future implementation
  
  const FOLLOWS = true; // Mock response
  
  try {
    if (FOLLOWS) {
      await saveVerification(userId, 'instagram', true, instagramUsername);
      res.json({ 
        success: true,
        message: 'Instagram follow verified successfully',
        platform: 'instagram', 
        username: instagramUsername,
        verified_at: new Date().toISOString()
      });
    } else {
      await saveVerification(userId, 'instagram', false, instagramUsername);
      res.status(400).json({ 
        success: false,
        error: 'Instagram follow not verified',
        platform: 'instagram',
        username: instagramUsername
      });
    }
  } catch (error) {
    console.error('Error in Instagram verification:', error);
    throw error;
  }
});

// Reset verification status (for testing or admin purposes)
exports.resetSocialVerification = asyncHandler(async (req, res) => {
  console.log('=== Reset verification request received ===');
  console.log('User ID:', req.user?.userId);
  console.log('Platform:', req.params.platform);
  
  const userId = req.user.userId;
  const { platform } = req.params;
  
  // Validate platform
  const validPlatforms = ['twitter', 'telegram', 'instagram'];
  if (!validPlatforms.includes(platform)) {
    throw new AppError(`Invalid platform. Must be one of: ${validPlatforms.join(', ')}`, 400);
  }
  
  try {
    const result = await query(
      `DELETE FROM user_social_verification 
       WHERE user_id = $1 AND platform = $2`,
      [userId, platform]
    );
    
    console.log(`Verification reset for ${platform}, rows affected:`, result.rowCount);
    
    res.json({ 
      success: true,
      message: `Verification reset for ${platform}`,
      platform: platform,
      rowsAffected: result.rowCount
    });
  } catch (error) {
    console.error('Error resetting verification:', error);
    throw new AppError('Failed to reset verification', 500);
  }
});

// Get verification status for a specific platform
exports.getPlatformStatus = asyncHandler(async (req, res) => {
  console.log('=== Get platform status request received ===');
  console.log('User ID:', req.user?.userId);
  console.log('Platform:', req.params.platform);
  
  const userId = req.user.userId;
  const { platform } = req.params;
  
  try {
    const result = await query(
      `SELECT platform, status, username, verified_at 
       FROM user_social_verification 
       WHERE user_id = $1 AND platform = $2`,
      [userId, platform]
    );
    
    if (result.rows.length === 0) {
      res.json({
        success: true,
        platform: platform,
        verified: false,
        message: 'No verification found for this platform'
      });
    } else {
      const verification = result.rows[0];
      res.json({
        success: true,
        platform: verification.platform,
        verified: verification.status,
        username: verification.username,
        verified_at: verification.verified_at
      });
    }
  } catch (error) {
    console.error('Error getting platform status:', error);
    throw new AppError('Failed to get platform verification status', 500);
  }
});