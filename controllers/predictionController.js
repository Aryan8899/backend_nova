const { query } = require('../config/database');
const { asyncHandler, AppError } = require('../middleware/errorHandler');

// Prediction submit controller
exports.submitPrediction = asyncHandler(async (req, res) => {
  const userId = req.user.userId;
  const { coin, prediction_value, round_id } = req.body;

  // Simple validation
  if (!coin || !prediction_value || !round_id) {
    throw new AppError('coin, prediction_value, and round_id are required', 400);
  }

  // Optional: Prevent multiple predictions for same user/coin/round
  const exists = await query(
    `SELECT id FROM predictions WHERE user_id = $1 AND coin = $2 AND round_id = $3`,
    [userId, coin, round_id]
  );
  if (exists.rows.length > 0) {
    throw new AppError('Prediction already submitted for this round', 409);
  }

  // Insert prediction
  const result = await query(
    `INSERT INTO predictions (user_id, coin, prediction_value, round_id)
     VALUES ($1, $2, $3, $4) RETURNING id, coin, prediction_value, round_id, created_at`,
    [userId, coin, prediction_value, round_id]
  );

  res.status(201).json({
    message: 'Prediction submitted successfully',
    prediction: result.rows[0]
  });
});
