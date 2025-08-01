const axios = require('axios');

const RECAPTCHA_SECRET_KEY = process.env.RECAPTCHA_SECRET_KEY;
const RECAPTCHA_VERIFY_URL = 'https://www.google.com/recaptcha/api/siteverify';

// Verify reCAPTCHA token
const verifyRecaptcha = async (token, userIP = null) => {
  try {
    if (!RECAPTCHA_SECRET_KEY) {
      throw new Error('reCAPTCHA secret key not configured');
    }

    if (!token) {
      throw new Error('reCAPTCHA token is required');
    }

    const params = new URLSearchParams();
    params.append('secret', RECAPTCHA_SECRET_KEY);
    params.append('response', token);
    if (userIP) {
      params.append('remoteip', userIP);
    }

    const response = await axios.post(RECAPTCHA_VERIFY_URL, params, {
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      timeout: 10000 // 10 seconds timeout
    });

    const data = response.data;

    return {
      success: data.success,
      challengeTs: data.challenge_ts,
      hostname: data.hostname,
      errorCodes: data['error-codes'] || [],
      score: data.score || null, // For reCAPTCHA v3
      action: data.action || null // For reCAPTCHA v3
    };

  } catch (error) {
    console.error('reCAPTCHA verification error:', error.message);
    return {
      success: false,
      error: error.message,
      errorCodes: ['network-error']
    };
  }
};

// Middleware to verify reCAPTCHA for routes
const requireRecaptcha = (options = {}) => {
  const {
    skipInDevelopment = false,
    minimumScore = 0.5, // For reCAPTCHA v3
    expectedAction = null // For reCAPTCHA v3
  } = options;

  return async (req, res, next) => {
    try {
      // Skip reCAPTCHA in development if configured
      if (skipInDevelopment && process.env.NODE_ENV === 'development') {
        console.log('⚠️  reCAPTCHA verification skipped in development mode');
        return next();
      }

      const recaptchaToken = req.body.recaptchaToken || req.headers['x-recaptcha-token'];
      
      if (!recaptchaToken) {
        return res.status(400).json({
          error: 'reCAPTCHA verification required',
          code: 'RECAPTCHA_MISSING'
        });
      }

      // Get user's IP address
      const userIP = req.ip || 
                    req.connection.remoteAddress || 
                    req.socket.remoteAddress ||
                    (req.connection.socket ? req.connection.socket.remoteAddress : null);

      // Verify reCAPTCHA
      const verification = await verifyRecaptcha(recaptchaToken, userIP);

      if (!verification.success) {
        const errorMessage = getRecaptchaErrorMessage(verification.errorCodes);
        return res.status(400).json({
          error: errorMessage,
          code: 'RECAPTCHA_FAILED',
          details: verification.errorCodes
        });
      }

      // Additional checks for reCAPTCHA v3
      if (verification.score !== null) {
        if (verification.score < minimumScore) {
          return res.status(400).json({
            error: 'reCAPTCHA score too low - please try again',
            code: 'RECAPTCHA_SCORE_LOW',
            score: verification.score
          });
        }

        if (expectedAction && verification.action !== expectedAction) {
          return res.status(400).json({
            error: 'reCAPTCHA action mismatch',
            code: 'RECAPTCHA_ACTION_MISMATCH',
            expected: expectedAction,
            received: verification.action
          });
        }
      }

      // Add verification details to request for logging
      req.recaptcha = {
        success: true,
        score: verification.score,
        action: verification.action,
        hostname: verification.hostname,
        challengeTs: verification.challengeTs
      };

      next();

    } catch (error) {
      console.error('reCAPTCHA middleware error:', error);
      return res.status(500).json({
        error: 'reCAPTCHA verification failed',
        code: 'RECAPTCHA_ERROR'
      });
    }
  };
};

// Helper function to get user-friendly error messages
const getRecaptchaErrorMessage = (errorCodes) => {
  if (!errorCodes || errorCodes.length === 0) {
    return 'reCAPTCHA verification failed';
  }

  const errorMessages = {
    'missing-input-secret': 'reCAPTCHA configuration error',
    'invalid-input-secret': 'reCAPTCHA configuration error',
    'missing-input-response': 'reCAPTCHA token is required',
    'invalid-input-response': 'Invalid reCAPTCHA token',
    'bad-request': 'reCAPTCHA request error',
    'timeout-or-duplicate': 'reCAPTCHA token expired or already used',
    'network-error': 'reCAPTCHA service temporarily unavailable'
  };

  // Return the first known error message, or a generic one
  for (const code of errorCodes) {
    if (errorMessages[code]) {
      return errorMessages[code];
    }
  }

  return 'reCAPTCHA verification failed - please try again';
};

// Middleware specifically for registration (stricter)
const requireRecaptchaForRegistration = requireRecaptcha({
  skipInDevelopment: false, // Always require for registration
  minimumScore: 0.7, // Higher score for registration
  expectedAction: 'register'
});

// Middleware for login (more lenient)
const requireRecaptchaForLogin = requireRecaptcha({
  skipInDevelopment: true, // Can skip in development
  minimumScore: 0.5,
  expectedAction: 'login'
});

// Middleware for sensitive operations
const requireRecaptchaForSensitive = requireRecaptcha({
  skipInDevelopment: false,
  minimumScore: 0.8,
  expectedAction: 'sensitive'
});

module.exports = {
  verifyRecaptcha,
  requireRecaptcha,
  requireRecaptchaForRegistration,
  requireRecaptchaForLogin,
  requireRecaptchaForSensitive,
  getRecaptchaErrorMessage
};