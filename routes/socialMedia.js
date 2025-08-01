const express = require('express');
const { authenticateToken } = require('../middleware/auth');
const { verifyRecaptcha } = require('../middleware/recaptcha');
const { 
  verifyTwitterFollow, 
  verifyTelegramJoin, 
  verifyInstagramFollow,
  getUserSocialStats,
  resetSocialVerification
} = require('../controllers/socialMediaController');

const router = express.Router();

// Get user's social media verification status
router.get('/status', authenticateToken, getUserSocialStats);

// Verify Twitter/X follow
router.post('/verify/twitter', 
  authenticateToken, 
 // verifyRecaptcha, 
  verifyTwitterFollow
);

// Verify Telegram channel join
router.post('/verify/telegram', 
  authenticateToken, 
 // verifyRecaptcha, 
  verifyTelegramJoin
);

// // Verify Instagram follow
// router.post('/verify/instagram', 
//   authenticateToken, 
//   verifyRecaptcha, 
//   verifyInstagramFollow
// );

// Reset verification status (admin only or for testing)
router.post('/reset/:platform', 
  authenticateToken, 
  verifyRecaptcha, 
  resetSocialVerification
);

module.exports = router;