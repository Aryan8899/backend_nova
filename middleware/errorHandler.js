// Global error handling middleware
const errorHandler = (err, req, res, next) => {
  console.error('Error stack:', err.stack);

  // Default error
  let error = {
    message: err.message || 'Internal Server Error',
    status: err.status || 500
  };

  // PostgreSQL errors
  if (err.code) {
    switch (err.code) {
      case '23505': // Unique violation
        error = {
          message: 'A record with this information already exists',
          status: 409,
          field: err.constraint
        };
        break;
      case '23503': // Foreign key violation
        error = {
          message: 'Referenced record does not exist',
          status: 400
        };
        break;
      case '23502': // Not null violation
        error = {
          message: 'Required field is missing',
          status: 400,
          field: err.column
        };
        break;
      case '42P01': // Undefined table
        error = {
          message: 'Database table not found',
          status: 500
        };
        break;
      case '28P01': // Invalid password
        error = {
          message: 'Database authentication failed',
          status: 500
        };
        break;
      case 'ECONNREFUSED':
        error = {
          message: 'Database connection refused',
          status: 500
        };
        break;
      default:
        error = {
          message: 'Database error occurred',
          status: 500
        };
    }
  }

  // JWT errors
  if (err.name === 'JsonWebTokenError') {
    error = {
      message: 'Invalid token',
      status: 401
    };
  }

  if (err.name === 'TokenExpiredError') {
    error = {
      message: 'Token expired',
      status: 401
    };
  }

  // Validation errors
  if (err.name === 'ValidationError') {
    error = {
      message: 'Validation failed',
      status: 400,
      details: err.details
    };
  }

  // Mongoose cast errors (if using MongoDB in the future)
  if (err.name === 'CastError') {
    error = {
      message: 'Invalid ID format',
      status: 400
    };
  }

  // Development vs Production error response
  const response = {
    error: error.message,
    status: error.status,
    ...(error.field && { field: error.field }),
    ...(error.details && { details: error.details })
  };

  // Include stack trace in development
  if (process.env.NODE_ENV === 'development') {
    response.stack = err.stack;
  }

  res.status(error.status).json(response);
};

// Async error wrapper
const asyncHandler = (fn) => (req, res, next) => {
  Promise.resolve(fn(req, res, next)).catch(next);
};

// Custom error class
class AppError extends Error {
  constructor(message, statusCode) {
    super(message);
    this.status = statusCode;
    this.isOperational = true;

    Error.captureStackTrace(this, this.constructor);
  }
}

module.exports = {
  errorHandler,
  asyncHandler,
  AppError
};