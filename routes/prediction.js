const express = require('express');
const { authenticateToken } = require('../middleware/auth');
const { submitPrediction } = require('../controllers/predictionController');

const router = express.Router();

// Prediction submit (protected)
router.post('/submit', authenticateToken, submitPrediction);

module.exports = router;
