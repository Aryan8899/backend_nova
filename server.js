const express = require('express');
const cors = require('cors');
require('dotenv').config();
const socialMediaRoutes = require('./routes/socialMedia');
const predictionRoutes = require('./routes/prediction');

// Import database and middleware
const { initializeDatabase } = require('./config/database');
const { errorHandler } = require('./middleware/errorHandler');

// Import routes
const authRoutes = require('./routes/auth');
const userRoutes = require('./routes/user');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

app.use(cors({
  origin: [
    'http://localhost:3001',
    'http://localhost:5500',
    'http://127.0.0.1:5500'
  ],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'x-recaptcha-token']
}));


// Trust proxy for getting real IP addresses (important for reCAPTCHA)
app.set('trust proxy', true);

// Health check route
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    environment: process.env.NODE_ENV || 'development',
    recaptchaConfigured: !!process.env.RECAPTCHA_SECRET_KEY
  });
});

app.use('/api/social', socialMediaRoutes);

// Root route with API documentation
app.get('/', (req, res) => {
  res.json({
    message: 'Authentication API Server with reCAPTCHA',
    version: '2.0.0',
    features: [
      'User Registration with reCAPTCHA',
      'User Login with reCAPTCHA', 
      'JWT Authentication',
      'Password Change with reCAPTCHA',
      'Account Deactivation with reCAPTCHA',
      'Refresh Tokens',
      'PostgreSQL Database',
      'Comprehensive Error Handling'
    ],
    endpoints: {
      health: 'GET /api/health',
      auth: {
        register: 'POST /api/auth/register (requires reCAPTCHA)',
        login: 'POST /api/auth/login (requires reCAPTCHA)',
        refresh: 'POST /api/auth/refresh',
        forgotPassword: 'POST /api/auth/forgot-password',
        logout: 'POST /api/auth/logout'
      },
      user: {
        profile: 'GET /api/user/profile (protected)',
        updateProfile: 'PUT /api/user/profile (protected)',
        changePassword: 'PUT /api/user/change-password (requires reCAPTCHA)',
        listUsers: 'GET /api/user/list (protected)',
        deactivateAccount: 'DELETE /api/user/account (requires reCAPTCHA)',
        stats: 'GET /api/user/stats (protected)'
      }
    },
    recaptcha: {
      enabled: !!process.env.RECAPTCHA_SECRET_KEY,
      requiredFor: ['registration', 'login', 'password-change', 'account-deactivation'],
      note: 'Include recaptchaToken in request body or x-recaptcha-token in headers'
    }
  });
});

// API Routes - Use your modular route files
app.use('/api/auth', authRoutes);
app.use('/api/user', userRoutes);

app.use('/api/prediction', predictionRoutes);

// Error handling middleware (must be after routes)
app.use(errorHandler);

// Handle 404 - Route not found
app.use('*', (req, res) => {
  res.status(404).json({ 
    error: 'Route not found',
    path: req.originalUrl,
    method: req.method,
    availableEndpoints: {
      health: 'GET /api/health',
      docs: 'GET /',
      auth: 'POST /api/auth/register, POST /api/auth/login',
      user: 'GET /api/user/profile (requires auth)'
    }
  });
});

// Start server function
async function startServer() {
  try {
    // Initialize database
    await initializeDatabase();
    
    // Check required environment variables
    const requiredEnvVars = ['JWT_SECRET', 'DB_USER', 'DB_HOST', 'DB_NAME', 'DB_PASSWORD'];
    const missingEnvVars = requiredEnvVars.filter(envVar => !process.env[envVar]);
    
    if (missingEnvVars.length > 0) {
      console.error('❌ Missing required environment variables:', missingEnvVars.join(', '));
      console.error('   Please check your .env file');
      process.exit(1);
    }
    
    // Check optional but recommended environment variables
    if (!process.env.RECAPTCHA_SECRET_KEY) {
      console.warn('⚠️  RECAPTCHA_SECRET_KEY not configured');
      console.warn('   reCAPTCHA protection will be disabled in development mode');
      console.warn('   Get your secret key from: https://www.google.com/recaptcha/admin');
    }
    
    // Start the server
    const server = app.listen(PORT, () => {
      console.log('\n🎉 Server started successfully!');
      console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
      console.log(`🚀 Server running on port ${PORT}`);
      console.log(`📊 Health check: http://localhost:${PORT}/api/health`);
      console.log(`📚 API docs: http://localhost:${PORT}/`);
      console.log(`🔒 reCAPTCHA: ${process.env.RECAPTCHA_SECRET_KEY ? '✅ Enabled' : '❌ Disabled'}`);
      console.log(`🌍 Environment: ${process.env.NODE_ENV || 'development'}`);
      console.log(`🗄️  Database: ${process.env.DB_HOST}:${process.env.DB_PORT}/${process.env.DB_NAME}`);
      console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
      
      // Log available endpoints
      console.log('\n📋 Available endpoints:');
      console.log('   POST /api/auth/register   - Register new user (reCAPTCHA)');
      console.log('   POST /api/auth/login      - Login user (reCAPTCHA)');
      console.log('   POST /api/auth/refresh    - Refresh JWT token');
      console.log('   GET  /api/user/profile    - Get user profile (auth)');
      console.log('   PUT  /api/user/change-password - Change password (reCAPTCHA)');
      console.log('   DELETE /api/user/account  - Deactivate account (reCAPTCHA)\n');
    });

    // Handle server errors
    server.on('error', (error) => {
      if (error.code === 'EADDRINUSE') {
        console.error(`❌ Port ${PORT} is already in use`);
        console.error('   Try a different port or stop the process using this port');
      } else if (error.code === 'EACCES') {
        console.error(`❌ Permission denied to bind to port ${PORT}`);
        console.error('   Try using a port number above 1024');
      } else {
        console.error('❌ Server error:', error.message);
      }
      process.exit(1);
    });

  } catch (error) {
    console.error('❌ Failed to start server:', error.message);
    
    // Provide helpful error messages for common issues
    if (error.code === 'ECONNREFUSED') {
      console.error('   Database connection refused. Check if PostgreSQL is running.');
    } else if (error.code === '28P01') {
      console.error('   Database authentication failed. Check your credentials.');
    } else if (error.code === '3D000') {
      console.error('   Database does not exist. Create the database first.');
    }
    
    process.exit(1);
  }
}

// Graceful shutdown handling
const gracefulShutdown = (signal) => {
  console.log(`\n🛑 Received ${signal}. Shutting down gracefully...`);
  
  // Close database connections
  const { pool } = require('./config/database');
  pool.end(() => {
    console.log('✅ Database connections closed');
    console.log('👋 Server shutdown complete');
    process.exit(0);
  });
  
  // Force exit after 10 seconds
  setTimeout(() => {
    console.error('❌ Forced shutdown after timeout');
    process.exit(1);
  }, 10000);
};

// Handle shutdown signals
process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

// Handle uncaught exceptions
process.on('uncaughtException', (error) => {
  console.error('❌ Uncaught Exception:', error);
  console.error('   This should not happen. Please check your code.');
  process.exit(1);
});

// Handle unhandled promise rejections
process.on('unhandledRejection', (reason, promise) => {
  console.error('❌ Unhandled Rejection at:', promise, 'reason:', reason);
  console.error('   This indicates a missing .catch() on a Promise.');
  process.exit(1);
});

// Start the server
startServer();