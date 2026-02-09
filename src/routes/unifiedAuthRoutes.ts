import express from 'express';
import {
  checkAvailableRoles,
  unifiedLogin,
  selectRole,
  switchRole,
  inviteUserRole,
  setupRolePassword,
  validatePasswordToken,
  getTeamMembers,
  unifiedForgotPassword,
} from '../controllers/unifiedAuthController';
import {
  rbacAuth,
  businessOwnerOnly,
  requirePermission,
} from '../middleware/rbac';

const router = express.Router();

// Public routes (no authentication required)
router.post('/check-roles', checkAvailableRoles);
router.post('/login', unifiedLogin);
router.post('/select-role', selectRole);
router.post('/forgot-password', unifiedForgotPassword);
router.post('/setup-password/:token', setupRolePassword);
router.get('/validate-token/:token', validatePasswordToken);

// Protected routes (authentication required)
router.use(rbacAuth); // Apply RBAC middleware to all routes below

// Role switching (any authenticated user)
router.post('/switch-role', switchRole);

// Team management (business owners only)
router.post('/invite', businessOwnerOnly, inviteUserRole);

// Role management endpoints (require specific permissions)
router.get('/my-roles', (req, res) => {
  const response = {
    currentRole: req.auth?.currentRole,
    availableRoles: req.auth?.availableRoles,
    user: {
      userId: req.auth?.userId,
      email: req.auth?.email,
    },
  };

  res.json(response);
});

// Get team members (business owners only)
router.get('/team', businessOwnerOnly, getTeamMembers);

// Update team member access level (business owners only)
router.patch(
  '/team/:roleId',
  businessOwnerOnly,
  async (req, res): Promise<void> => {
    try {
      const { roleId } = req.params;
      const { accessLevel } = req.body;
      const { UserRoles, AccessLevel } = await import('../models/UserRoles');
      const businessOwnerId = req.auth?.userId;

      // Validate access level
      if (!Object.values(AccessLevel).includes(accessLevel)) {
        res.status(400).json({ error: 'Invalid access level' });
        return;
      }

      // Find and update the role
      const userRole = await UserRoles.findOne({
        _id: roleId,
        businessOwner: businessOwnerId,
        deleted: false,
      });

      if (!userRole) {
        res.status(404).json({ error: 'Team member not found' });
        return;
      }

      userRole.accessLevel = accessLevel;
      await userRole.save();

      res.json({
        success: true,
        message: 'Access level updated successfully',
        roleId: userRole._id,
        newAccessLevel: accessLevel,
      });
    } catch (error) {
      console.error('Update team member error:', error);
      res.status(500).json({
        error: 'Failed to update team member',
      });
    }
  },
);

// Remove team member (business owners only)
router.delete(
  '/team/:roleId',
  businessOwnerOnly,
  async (req, res): Promise<void> => {
    try {
      const { roleId } = req.params;
      const { UserRoles } = await import('../models/UserRoles');
      const businessOwnerId = req.auth?.userId;

      // Find and soft delete the role
      const userRole = await UserRoles.findOne({
        _id: roleId,
        businessOwner: businessOwnerId,
        deleted: false,
      });

      if (!userRole) {
        res.status(404).json({ error: 'Team member not found' });
        return;
      }

      userRole.deleted = true;
      userRole.deletedAt = new Date();
      userRole.deletedBy = businessOwnerId as any;
      await userRole.save();

      res.json({
        success: true,
        message: 'Team member removed successfully',
      });
    } catch (error) {
      console.error('Remove team member error:', error);
      res.status(500).json({
        error: 'Failed to remove team member',
      });
    }
  },
);

// Resend invitation (business owners only)
router.post(
  '/team/:roleId/resend-invite',
  businessOwnerOnly,
  async (req, res): Promise<void> => {
    try {
      const { roleId } = req.params;
      const { UserRoles } = await import('../models/UserRoles');
      const businessOwnerId = req.auth?.userId;
      const crypto = await import('crypto');

      // Find the role
      const userRole = await UserRoles.findOne({
        _id: roleId,
        businessOwner: businessOwnerId,
        deleted: false,
        status: 'invited', // Only resend for invited users
      }).populate('user');

      if (!userRole) {
        res.status(404).json({
          error: 'Invited team member not found or already active',
        });
        return;
      }

      // Generate new invite token
      const inviteToken = crypto.randomBytes(32).toString('hex');
      userRole.inviteToken = inviteToken;
      userRole.inviteTokenExpiry = new Date(
        Date.now() + 7 * 24 * 60 * 60 * 1000,
      );
      await userRole.save();

      const user = userRole.user as any;
      if (!user.isPasswordSet) {
        user.passwordSetupToken = crypto.randomBytes(32).toString('hex');
        user.passwordSetupTokenExpiry = new Date(
          Date.now() + 7 * 24 * 60 * 60 * 1000,
        );
        await user.save();
      }

      // Resend invitation email
      const { sendEmail } = await import('../services/emailService');
      const { config } = await import('../config/config');

      const tokenForLink = user.passwordSetupToken || userRole.inviteToken;
      const setupUrl = `${config.frontURL}/setup-password/${tokenForLink}`;

      await sendEmail({
        to: user.email,
        subject: `Reminder: Set up your ${userRole.roleType} account`,
        html: `
        <p>Hi there,</p>
        <p>This is a reminder to set up your ${userRole.roleType} account.</p>
        <p><a href="${setupUrl}">Set up your account now</a></p>
        <p>This link expires in 7 days.</p>
      `,
      });

      res.json({
        success: true,
        message: 'Invitation resent successfully',
      });
    } catch (error) {
      console.error('Resend invitation error:', error);
      res.status(500).json({
        error: 'Failed to resend invitation',
      });
    }
  },
);

export default router;
