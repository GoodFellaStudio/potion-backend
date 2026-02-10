import express from 'express';
import { connectDB } from './config/database';
import authRoutes from './routes/authRoutes';
import adminRoutes from './routes/adminRoutes';
import clientRoutes from './routes/clientRoutes';
import globalsRoutes from './routes/userGlobalsRoutes';
import userWriteOffRoutes from './routes/userWriteOffRoutes';
import projectRoutes from './routes/projectRoutes';
import contractRoutes from './routes/contractRoutes';
import invoiceRoutes from './routes/invoiceRoutes';
import crmRoutes from './routes/crmRoutes';
import subcontractorRoutes from './routes/subcontractorRoutes';
import waitlistRoutes from './routes/waitlistRoutes';
import transactionRoutes from './routes/transactionRoutes';
// import transactionCategoryRoutes from './routes/transactionCategoryRoutes';
import timeTrackerRoutes from './routes/timeTrackerRoutes';
import searchRoute from './routes/searchRoute';
import stripeRoutes from './routes/stripeRoutes';
import chatRoute from './routes/chatRoute';
import accountantRoutes from './routes/accountantRoutes';
import aiRoutes from './routes/aiRoutes';
import cors from 'cors';
import dotenv from 'dotenv';
import swaggerJsdoc from 'swagger-jsdoc';
import swaggerUi from 'swagger-ui-express';
import { checkSubscriptionAccess } from './middleware/subscription';
import mongooseToSwagger from 'mongoose-to-swagger';
import { User } from './models/User';
import { Client } from './models/Client';
import { Invoice } from './models/Invoice';
import { Contract } from './models/Contract';
import { Project } from './models/Project';
import { Transaction } from './models/Transaction';
import { uploadFileController } from './controllers/uploadController';
import { PlaidItem } from './models/PlaidItem';
import cron from 'node-cron';
import initSubscriptionStatusCron from './cron/updateSubscriptionStatues';
import { updateEmptyCRMActions } from './cron/getCRMAction';
import { config } from './config/config';
import { uploadF } from './middleware/upload';
import http from 'http';
import { initSocketIo } from './services/socket';
import reportsRoutes from './routes/reportsRoutes';
import plaidRoutes from './routes/plaidRoutes';
import analyticsRoutes from './routes/analyticsRoutes';
import anomalyRoutes from './routes/anomalyRoutes';
import { auth, unifiedAuth } from './middleware/auth';
import devRoutes from './routes/devRoutes';
import unifiedAuthRoutes from './routes/unifiedAuthRoutes';
import externalProfileRoutes from './routes/externalProfileRoutes';
import { handleStripeWebhook } from './controllers/webhookController';
import { UserRoleType } from './models/UserRoles';
import notificationRoutes from './routes/notificationRoutes';

// Import the new RBAC middleware
import {
  rbacAuth,
  checkWritePermission,
  enforceProjectAccess,
  requireRole,
} from './middleware/rbac';
import { agenda } from './queue/agenda';

dotenv.config();

const app = express();
const PORT = config.port || 5000;

// Webhook routes MUST come before express.json() to receive raw body
app.post(
  '/api/pay/webhook',
  express.raw({ type: 'application/json' }),
  handleStripeWebhook,
);

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.post('/api/pay/webhook-parsed', handleStripeWebhook);

// CORS configuration
app.use(
  cors({
    origin: config.allowedOrigins,
    credentials: true,
  }),
);

// Connect to MongoDB
connectDB();

// Health check endpoint
app.get('/health', (req, res) => {
  res.status(200).json({
    message: 'Server is running',
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV || 'development',
  });
});

// Swagger setup
const options = {
  definition: {
    openapi: '3.0.0',
    info: {
      title: 'Potion API',
      version: '1.0.0',
      description: 'API documentation for Potion application',
    },
    servers: [
      {
        url: config.baseURL,
        description: 'Development server',
      },
    ],
    components: {
      securitySchemes: {
        bearerAuth: {
          type: 'http',
          scheme: 'bearer',
          bearerFormat: 'JWT',
        },
      },
      schemas: {
        User: mongooseToSwagger(User),
        Client: mongooseToSwagger(Client),
        Invoice: mongooseToSwagger(Invoice),
        Contract: mongooseToSwagger(Contract),
        Project: mongooseToSwagger(Project),
        Transaction: mongooseToSwagger(Transaction),
        PlaidItem: mongooseToSwagger(PlaidItem),
      },
    },
    security: [
      {
        bearerAuth: [],
      },
    ],
  },
  apis: ['./src/routes/*.ts'],
};

const specs = swaggerJsdoc(options);
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(specs));

// Public routes (no authentication required)
app.use('/api/auth', authRoutes); // Login, signup, password reset, etc.
app.use('/api/unified-auth', unifiedAuthRoutes); // New unified role-based authentication
app.use('/api/pay', stripeRoutes); // Stripe payment routes
app.use('/api/waitlist', waitlistRoutes);
app.use('/api/admin', adminRoutes);

// Legacy external user auth routes removed (use /api/unified-auth/*)

// NEW: Unified authentication system routes (multi-role system)
app.use('/api/unified-auth', unifiedAuthRoutes);

// External user profile management routes (accountants and subcontractors)
app.use('/api/external-profile', externalProfileRoutes);

// File upload endpoint with basic auth (will be updated for RBAC)
app.post('/api/upload', uploadF, uploadFileController);

// RBAC-protected routes with subscription check for main users
const protectedWithSubscription = [
  rbacAuth,
  checkSubscriptionAccess,
  checkWritePermission,
];

// RBAC-protected routes without subscription check (for external users)
const protectedExternal = [rbacAuth, checkWritePermission];

// Main user routes (require subscription)
app.use(
  '/api/client',
  ...protectedWithSubscription,
  requireRole(UserRoleType.BUSINESS_OWNER, UserRoleType.ACCOUNTANT),
  clientRoutes,
);

app.use(
  '/api/transaction',
  ...protectedWithSubscription,
  requireRole(UserRoleType.BUSINESS_OWNER, UserRoleType.ACCOUNTANT),
  transactionRoutes,
);

// // Transaction categorization routes
// app.use(
//   '/api/transaction-category',
//   ...protectedWithSubscription,
//   requireRole(UserRoleType.BUSINESS_OWNER, UserRoleType.ACCOUNTANT),
//   transactionCategoryRoutes,
// );

// app.use(
//   '/api/transaction-category-messages',
//   ...protectedWithSubscription,
//   requireRole(UserRoleType.BUSINESS_OWNER, UserRoleType.ACCOUNTANT),
//   transactionCategoryRoutes,
// );

app.use(
  '/api/plaid',
  ...protectedWithSubscription,
  requireRole(UserRoleType.BUSINESS_OWNER, UserRoleType.ACCOUNTANT),
  plaidRoutes,
);

app.use(
  '/api/analytics',
  ...protectedWithSubscription,
  requireRole(UserRoleType.BUSINESS_OWNER, UserRoleType.ACCOUNTANT),
  analyticsRoutes,
);

app.use(
  '/api/anomalies',
  ...protectedWithSubscription,
  requireRole(UserRoleType.BUSINESS_OWNER, UserRoleType.ACCOUNTANT),
  anomalyRoutes,
);

app.use(
  '/api/project',
  ...protectedWithSubscription,
  requireRole(
    UserRoleType.BUSINESS_OWNER,
    UserRoleType.ACCOUNTANT,
    UserRoleType.SUBCONTRACTOR,
  ),
  enforceProjectAccess,
  projectRoutes,
);

app.use(
  '/api/contract',
  ...protectedWithSubscription,
  requireRole(UserRoleType.BUSINESS_OWNER, UserRoleType.ACCOUNTANT),
  contractRoutes,
);

app.use(
  '/api/invoice',
  ...protectedWithSubscription,
  requireRole(UserRoleType.BUSINESS_OWNER, UserRoleType.ACCOUNTANT),
  invoiceRoutes,
);

app.use(
  '/api/crm',
  ...protectedWithSubscription,
  requireRole(UserRoleType.BUSINESS_OWNER, UserRoleType.ACCOUNTANT),
  crmRoutes,
);

app.use(
  '/api/reports',
  ...protectedWithSubscription,
  requireRole(UserRoleType.BUSINESS_OWNER, UserRoleType.ACCOUNTANT),
  reportsRoutes,
);

app.use(
  '/api/timetracker',
  ...protectedWithSubscription,
  requireRole(
    UserRoleType.BUSINESS_OWNER,
    UserRoleType.ACCOUNTANT,
    UserRoleType.SUBCONTRACTOR,
  ),
  timeTrackerRoutes,
);

app.use(
  '/api/chat',
  ...protectedWithSubscription,
  requireRole(UserRoleType.BUSINESS_OWNER, UserRoleType.ACCOUNTANT),
  chatRoute,
);

// Thread suggestions endpoint (separate from chat routes)
app.get(
  '/api/thread-suggestions',
  ...protectedWithSubscription,
  requireRole(UserRoleType.BUSINESS_OWNER, UserRoleType.ACCOUNTANT),
  async (req: any, res: any) => {
    try {
      // Return predefined conversation starters
      const suggestions = [
        'What are my biggest expenses this month?',
        'Show me my income trends',
        'What tax deductions can I claim?',
        'Analyze my spending patterns',
        'Help me categorize recent transactions',
        "What's my profit margin for this quarter?",
        'Show me outstanding invoices',
        'Create a financial summary report',
      ];

      res.json({
        success: true,
        suggestions: suggestions.slice(0, 4), // Return 4 suggestions
      });
    } catch (error: any) {
      console.error('Error fetching thread suggestions:', error);
      res.status(500).json({
        success: false,
        error: 'Internal server error',
      });
    }
  },
);

// AI Service integration routes
app.use(
  '/api/ai',
  ...protectedWithSubscription,
  requireRole(UserRoleType.BUSINESS_OWNER, UserRoleType.ACCOUNTANT),
  aiRoutes,
);

app.use(
  '/api/search',
  ...protectedWithSubscription,
  requireRole(UserRoleType.BUSINESS_OWNER, UserRoleType.ACCOUNTANT),
  searchRoute,
);

app.use(
  '/api/user-globals',
  ...protectedWithSubscription,
  requireRole(UserRoleType.BUSINESS_OWNER, UserRoleType.ACCOUNTANT),
  globalsRoutes,
);

app.use(
  '/api/notifications',
  rbacAuth,
  requireRole(
    UserRoleType.BUSINESS_OWNER,
    UserRoleType.ACCOUNTANT,
    UserRoleType.SUBCONTRACTOR,
  ),
  notificationRoutes,
);

app.use(
  '/api/user-write-offs',
  ...protectedWithSubscription,
  requireRole(UserRoleType.BUSINESS_OWNER, UserRoleType.ACCOUNTANT),
  userWriteOffRoutes,
);

// External user routes (no subscription required)
// Note: setup-account and login are handled as public routes above
app.use(
  '/api/accountant',
  ...protectedExternal,
  requireRole(UserRoleType.BUSINESS_OWNER, UserRoleType.ACCOUNTANT), // Users can manage accountants, accountants can access their own data
  accountantRoutes,
);

// Mount subcontractor routes with RBAC (external users - no subscription required)
app.use(
  '/api/subcontractor',
  ...protectedExternal,
  requireRole(UserRoleType.BUSINESS_OWNER, UserRoleType.SUBCONTRACTOR), // Allow both users and subcontractors
  subcontractorRoutes,
);

// Development routes
if (process.env.NODE_ENV === 'development') {
  app.use(
    '/api/dev',
    rbacAuth,
    requireRole(UserRoleType.ADMIN, UserRoleType.BUSINESS_OWNER),
    devRoutes,
  );
}

// Error handling middleware
app.use((err: any, req: any, res: any, next: any) => {
  console.error('Error:', err);

  // Handle specific error types
  if (err.name === 'ValidationError') {
    return res.status(400).json({
      message: 'Validation Error',
      errors: Object.values(err.errors).map((e: any) => e.message),
    });
  }

  if (err.name === 'CastError') {
    return res.status(400).json({
      message: 'Invalid ID format',
    });
  }

  // Default error response
  res.status(500).json({
    message: 'Internal Server Error',
    ...(process.env.NODE_ENV === 'development' && {
      error: err.message,
      stack: err.stack,
    }),
  });
});

// 404 handler for undefined routes
app.use('*', (req, res) => {
  res.status(404).json({
    message: 'Route not found',
    path: req.originalUrl,
    method: req.method,
  });
});

const server = http.createServer(app);

// Initialize Socket.IO
initSocketIo(server, config.allowedOrigins);

server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`API Documentation: ${config.baseURL}/api-docs`);

  // Initialize cron jobs
  if (process.env.NODE_ENV === 'production') {
    initSubscriptionStatusCron();
    updateEmptyCRMActions();
  }
});


(async function () {
  // IIFE to give access to async/await
  await agenda.start();
  await agenda.every("1 minute", "add Transaction");
  await agenda.every("2 minute", "predict category");
  console.log('Agenda startet')
})();

export default app;
