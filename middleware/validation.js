// Validation functions
const validateEmail = (email) => {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
};

const validatePassword = (password) => {
  if (!password || password.length < 6) {
    return false;
  }
  // Optional: Add more complex password requirements
  // const hasUpperCase = /[A-Z]/.test(password);
  // const hasLowerCase = /[a-z]/.test(password);
  // const hasNumbers = /\d/.test(password);
  // const hasSpecialChar = /[!@#$%^&*(),.?":{}|<>]/.test(password);
  // return hasUpperCase && hasLowerCase && hasNumbers && hasSpecialChar;
  return true;
};

const validateName = (name) => {
  return name && name.trim().length >= 1 && name.trim().length <= 100;
};

// Validation middleware for registration
const validateRegistration = (req, res, next) => {
  const { email, password, first_name, last_name } = req.body;
  const errors = [];

  // Required fields
  if (!email) {
    errors.push('Email is required');
  } else if (!validateEmail(email)) {
    errors.push('Please provide a valid email address');
  }

  if (!password) {
    errors.push('Password is required');
  } else if (!validatePassword(password)) {
    errors.push('Password must be at least 6 characters long');
  }

  // Optional fields validation
  if (first_name && !validateName(first_name)) {
    errors.push('First name must be between 1 and 100 characters');
  }

  if (last_name && !validateName(last_name)) {
    errors.push('Last name must be between 1 and 100 characters');
  }

  if (errors.length > 0) {
    return res.status(400).json({
      error: 'Validation failed',
      details: errors
    });
  }

  // Sanitize data
  req.body.email = email.toLowerCase().trim();
  if (first_name) req.body.first_name = first_name.trim();
  if (last_name) req.body.last_name = last_name.trim();

  next();
};

// Validation middleware for login
const validateLogin = (req, res, next) => {
  const { email, password } = req.body;
  const errors = [];

  if (!email) {
    errors.push('Email is required');
  } else if (!validateEmail(email)) {
    errors.push('Please provide a valid email address');
  }

  if (!password) {
    errors.push('Password is required');
  }

  if (errors.length > 0) {
    return res.status(400).json({
      error: 'Validation failed',
      details: errors
    });
  }

  // Sanitize email
  req.body.email = email.toLowerCase().trim();

  next();
};

// Validation middleware for password change
const validatePasswordChange = (req, res, next) => {
  const { currentPassword, newPassword } = req.body;
  const errors = [];

  if (!currentPassword) {
    errors.push('Current password is required');
  }

  if (!newPassword) {
    errors.push('New password is required');
  } else if (!validatePassword(newPassword)) {
    errors.push('New password must be at least 6 characters long');
  }

  if (currentPassword === newPassword) {
    errors.push('New password must be different from current password');
  }

  if (errors.length > 0) {
    return res.status(400).json({
      error: 'Validation failed',
      details: errors
    });
  }

  next();
};

// Validation middleware for profile update
const validateProfileUpdate = (req, res, next) => {
  const { first_name, last_name, email } = req.body;
  const errors = [];

  if (email && !validateEmail(email)) {
    errors.push('Please provide a valid email address');
  }

  if (first_name && !validateName(first_name)) {
    errors.push('First name must be between 1 and 100 characters');
  }

  if (last_name && !validateName(last_name)) {
    errors.push('Last name must be between 1 and 100 characters');
  }

  if (errors.length > 0) {
    return res.status(400).json({
      error: 'Validation failed',
      details: errors
    });
  }

  // Sanitize data
  if (email) req.body.email = email.toLowerCase().trim();
  if (first_name) req.body.first_name = first_name.trim();
  if (last_name) req.body.last_name = last_name.trim();

  next();
};

module.exports = {
  validateEmail,
  validatePassword,
  validateName,
  validateRegistration,
  validateLogin,
  validatePasswordChange,
  validateProfileUpdate
};