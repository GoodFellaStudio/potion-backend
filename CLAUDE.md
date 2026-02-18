# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Potion Backend (potionbk) is a Node.js/Express/TypeScript API server for a financial management application. It provides functionality for business owners to manage clients, invoices, contracts, projects, transactions, time tracking, and more. The system supports multiple user roles including business owners, accountants, and subcontractors.

## Commands

```bash
# Development
npm run dev          # Start dev server with nodemon + ts-node

# Build
npm run build        # Compile TypeScript to dist/

# Production
npm start            # Run compiled dist/app.js

# Email templates (React Email)
npm run email:preview  # Preview email templates in browser
npm run email:build    # Build email templates
```

## Architecture

### Core Structure

- **Entry Point**: `src/app.ts` - Express app setup, route mounting, middleware configuration, Swagger docs, Socket.IO initialization, Agenda job scheduler startup
- **Database**: MongoDB via Mongoose, connection in `src/config/database.ts`
- **Config**: `src/config/config.ts` - Environment variables, CORS origins, API keys

### MVC-Style Organization

```
src/
├── models/        # Mongoose schemas (User, Client, Invoice, Project, Transaction, etc.)
├── controllers/   # Request handlers
├── routes/        # Express routers with Swagger JSDoc annotations
├── services/      # Business logic (email, Stripe, Plaid, storage, notifications)
├── middleware/    # Auth, RBAC, subscription checks, validators, file upload
├── queue/         # Agenda job definitions (transaction processing, category prediction)
├── cron/          # Scheduled tasks (subscription status updates, CRM actions)
├── templates/     # React Email templates for transactional emails
└── config/        # Database, Plaid, app configuration
```

### Authentication & Authorization

The RBAC system (`src/middleware/rbac.ts`) handles multiple user types:

- **Business Owners** (USER role): Full access to their own data
- **Accountants**: Access to assigned clients' data with read/edit levels
- **Subcontractors**: Access to assigned projects only
- **Admins**: System-wide access

Key middleware chain for protected routes:
```typescript
[rbacAuth, checkSubscriptionAccess, checkWritePermission]
```

Headers used:
- `Authorization: Bearer <JWT>` - Required for all authenticated routes
- `X-User-ID` - Accountants specify which client's data to access
- `X-Project-ID` - Subcontractors specify which project to access

### Key Integrations

- **Stripe**: Payments and subscriptions (`src/services/stripeService.ts`, webhook at `/api/pay/webhook`)
- **Plaid**: Bank account connections (`src/services/plaidService.ts`, `src/config/plaid.ts`)
- **AWS S3**: File storage (`src/services/storageService.ts`)
- **Resend**: Email delivery (`src/services/reactEmailService.ts`)
- **Socket.IO**: Real-time updates (`src/services/socket.ts`)
- **Agenda**: Background job processing (`src/queue/agenda.ts`)

### API Documentation

Swagger docs available at `/api-docs` endpoint. Route files contain JSDoc annotations for automatic spec generation.

### Environment Variables

Required in `.env`:
- `MONGODB_URI` - MongoDB connection string
- `JWT_SECRET` - JWT signing key
- `STRIPE_SECRET_KEY`, `STRIPE_WEBHOOK_SECRET` - Stripe integration
- `PLAID_CLIENT_ID`, `PLAID_SECRET` - Plaid integration
- `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_REGION`, `S3_BUCKET_NAME` - S3 storage
- `RESEND_API_KEY` - Email service

### Deployment

- AWS Elastic Beanstalk configuration in `.ebextensions/`
- Procfile for process management
- Node.js 22.x required
