import express from 'express';
import {
  login,
  forgotPassword,
  verifyOTPAndResetPassword,
  refreshToken,
  logout,
  verifyOTp,
  updateUser,
  getUser,
  deleteUser,
  updateProfilePicture,
  setupPassword,
  validatePasswordToken,
  resendPasswordSetup,
  googleCheck,
} from '../controllers/authController';
import { auth } from '../middleware/auth';
import { rbacAuth, getCurrentUser } from '../middleware/rbac';
import { uploadF } from '../middleware/upload';
import { User } from '../models/User';

const router = express.Router();

/**
 * @swagger
 * tags:
 *   name: Auth
 *   description: Authentication related endpoints
 */

/**
 * @swagger
 * /api/auth/login:
 *   post:
 *     summary: User login
 *     tags: [Auth]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *               $ref: '#/components/schemas/LoginDto'
 *     responses:
 *       200:
 *         description: Login successful
 *       401:
 *         description: Unauthorized
 */
router.post('/login', login);

// Password setup routes for checkout flow
/**
 * @swagger
 * /api/auth/setup-password/{token}:
 *   post:
 *     summary: Set password using email token
 *     tags: [Auth]
 *     parameters:
 *       - in: path
 *         name: token
 *         required: true
 *         schema:
 *           type: string
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               password:
 *                 type: string
 *                 minLength: 8
 *     responses:
 *       200:
 *         description: Password set successfully
 *       400:
 *         description: Invalid or expired token
 */
router.post('/setup-password/:token', setupPassword);

/**
 * @swagger
 * /api/auth/validate-token/{token}:
 *   get:
 *     summary: Validate password setup token
 *     tags: [Auth]
 *     parameters:
 *       - in: path
 *         name: token
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Token is valid
 *       400:
 *         description: Invalid or expired token
 */
router.get('/validate-token/:token', validatePasswordToken);

/**
 * @swagger
 * /api/auth/resend-password-setup:
 *   post:
 *     summary: Resend password setup email
 *     tags: [Auth]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               email:
 *                 type: string
 *                 format: email
 *     responses:
 *       200:
 *         description: Password setup email sent
 *       404:
 *         description: User not found
 */
router.post('/resend-password-setup', resendPasswordSetup);

/**
 * @swagger
 * /api/auth/google-check:
 *   post:
 *     summary: Check if Google user exists and login
 *     tags: [Auth]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               email:
 *                 type: string
 *                 format: email
 *               googleId:
 *                 type: string
 *               name:
 *                 type: string
 *     responses:
 *       200:
 *         description: User check completed
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 userExists:
 *                   type: boolean
 *                 accessToken:
 *                   type: string
 *                 user:
 *                   type: object
 *       400:
 *         description: Invalid request data
 *       500:
 *         description: Server error
 */
router.post('/google-check', googleCheck);

/**
 * @swagger
 * /api/auth/forgot-password:
 *   post:
 *     summary: Request password reset
 *     tags: [Auth]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               email:
 *                 type: string
 *     responses:
 *       200:
 *         description: OTP sent to email
 *       400:
 *         description: Invalid email
 */
router.post('/forgot-password', forgotPassword);

/**
 * @swagger
 * /api/auth/unified-forgot-password:
 *   post:
 *     summary: Unified forgot password for all user types
 *     tags: [Auth]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               email:
 *                 type: string
 *               roleType:
 *                 type: string
 *                 enum: [user, accountant, subcontractor]
 *     responses:
 *       200:
 *         description: Password reset email sent
 *       404:
 *         description: Account not found
 */

/**
 * @swagger
 * /api/auth/verify-otp:
 *   post:
 *     summary: Verify OTP for password reset
 *     tags: [Auth]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               email:
 *                 type: string
 *               otp:
 *                 type: string
 *     responses:
 *       200:
 *         description: OTP verified
 *       400:
 *         description: Invalid OTP
 */
router.post('/verify-otp', verifyOTp);

/**
 * @swagger
 * /api/auth/reset-password:
 *   post:
 *     summary: Reset password
 *     tags: [Auth]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               email:
 *                 type: string
 *               otp:
 *                 type: string
 *               newPassword:
 *                 type: string
 *     responses:
 *       200:
 *         description: Password reset successful
 *       400:
 *         description: Invalid request
 */
router.post('/reset-password', verifyOTPAndResetPassword);

/**
 * @swagger
 * /api/auth/refresh-token:
 *   post:
 *     summary: Refresh access token
 *     tags: [Auth]
 *     responses:
 *       200:
 *         description: Token refreshed successfully
 *       401:
 *         description: Invalid refresh token
 */
router.post('/refresh-token', refreshToken);

/**
 * @swagger
 * /api/auth/logout:
 *   post:
 *     summary: User logout
 *     tags: [Auth]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Logout successful
 */
router.post('/logout', auth, logout);

/**
 * @swagger
 * /api/auth/info:
 *   get:
 *     summary: Get current user info (works for all user types)
 *     tags: [Auth]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: User info retrieved successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 user:
 *                   type: object
 *                   properties:
 *                     id:
 *                       type: string
 *                     role:
 *                       type: string
 *                       enum: [user, accountant, subcontractor, admin]
 *                     permissions:
 *                       type: array
 *                       items:
 *                         type: string
 *                     profile:
 *                       type: object
 *       401:
 *         description: Unauthorized
 */
router.get('/info', rbacAuth, async (req, res): Promise<void> => {
  try {
    const authInfo = getCurrentUser(req);

    if (!authInfo.userId) {
      res.status(401).json({ message: 'User not authenticated' });
      return;
    }

    const user = await User.findById(authInfo.userId).select(
      'firstName lastName email businessName profilePicture phoneNumber address city state country postalCode subscription',
    );

    const response = {
      user: {
        id: authInfo.userId,
        firstName: user?.firstName,
        lastName: user?.lastName,
        email: user?.email,
        businessName: user?.businessName,
        profilePicture: user?.profilePicture,
        phoneNumber: user?.phoneNumber,
        address: user?.address,
        city: user?.city,
        state: user?.state,
        country: user?.country,
        postalCode: user?.postalCode,
        subscription: user?.subscription,
        roleType: authInfo.role,
        permissions: authInfo.permissions,
        accessLevel: authInfo.accessLevel,
        currentRole: authInfo.currentRole,
        availableRoles: authInfo.availableRoles,
      },
    };

    res.json(response);
  } catch (error) {
    console.error('Error getting user info:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Protected routes
/**
 * @swagger
 * /api/auth/update:
 *   put:
 *     summary: Update user profile
 *     tags: [Auth]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               firstName:
 *                 type: string
 *               lastName:
 *                 type: string
 *               email:
 *                 type: string
 *                 format: email
 *     responses:
 *       200:
 *         description: Profile updated successfully
 *       400:
 *         description: Invalid request
 */
router.put('/update', auth, updateUser);

/**
 * @swagger
 * /api/auth:
 *   get:
 *     summary: Get authenticated user
 *     tags: [Auth]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: User data retrieved
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/User'
 *       401:
 *         description: Unauthorized
 */
router.get('/', auth, getUser);

/**
 * @swagger
 * /api/auth:
 *   delete:
 *     summary: Delete user account
 *     tags: [Auth]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: User deleted successfully
 *       400:
 *         description: Invalid request
 */
router.delete('/', auth, deleteUser);

/**
 * @swagger
 * /api/auth/profile-picture:
 *   put:
 *     summary: Update profile picture
 *     tags: [Auth]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         multipart/form-data:
 *           schema:
 *             type: object
 *             properties:
 *               profilePicture:
 *                 type: string
 *                 format: binary
 *     responses:
 *       200:
 *         description: Profile picture updated
 *       400:
 *         description: Invalid request
 */
router.put('/profile-picture', auth, uploadF, updateProfilePicture);

// Unified authentication moved to /api/unified-auth/*

export default router;
