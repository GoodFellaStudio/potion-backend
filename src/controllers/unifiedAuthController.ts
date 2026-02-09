import { Request, Response } from 'express';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import { config } from '../config/config';
import { User } from '../models/User';
import { UserRoles, UserRoleType, AccessLevel } from '../models/UserRoles';
import { sendEmail } from '../services/emailService';
import crypto from 'crypto';

/**
 * Generate unified JWT token
 */
export const generateUnifiedToken = (
  userId: string,
  roleId: string,
  email: string,
  roleType?: UserRoleType,
  businessOwnerId?: string,
): string => {
  return jwt.sign(
    {
      userId,
      roleId,
      email,
      roleType,
      businessOwnerId,
    },
    config.jwtSecret!,
    { expiresIn: '30d' },
  );
};

/**
 * Generate pre-auth token (password verified, role not selected)
 */
export const generatePreAuthToken = (
  userId: string,
  email: string,
): string => {
  return jwt.sign(
    {
      userId,
      email,
      tokenType: 'preauth',
    },
    config.jwtSecret!,
    { expiresIn: '15m' },
  );
};

/**
 * Get role display name for UI
 */
const getRoleDisplayName = (
  roleType: UserRoleType,
  businessOwner?: any,
): string => {
  const roleNames = {
    [UserRoleType.BUSINESS_OWNER]: 'Business Owner',
    [UserRoleType.ACCOUNTANT]: 'Accountant',
    [UserRoleType.SUBCONTRACTOR]: 'Subcontractor',
    [UserRoleType.ADMIN]: 'Admin',
  };

  let baseName = roleNames[roleType];

  if (businessOwner && roleType !== UserRoleType.BUSINESS_OWNER) {
    const ownerName =
      businessOwner.businessName ||
      `${businessOwner.firstName} ${businessOwner.lastName}`.trim() ||
      businessOwner.email;
    baseName += ` for ${ownerName}`;
  }

  return baseName;
};

/**
 * Get full display name for role
 */
const getFullDisplayName = (
  roleType: UserRoleType,
  businessOwner: any,
  user: any,
): string => {
  if (roleType === UserRoleType.BUSINESS_OWNER) {
    return (
      user.businessName ||
      `${user.firstName} ${user.lastName}`.trim() ||
      user.email
    );
  }

  const ownerName =
    businessOwner?.businessName ||
    `${businessOwner?.firstName} ${businessOwner?.lastName}`.trim() ||
    businessOwner?.email;

  return ownerName || 'Unknown Business Owner';
};

/**
 * Permissions matrix for unified roles
 */
const getRolePermissions = (
  roleType: UserRoleType,
  accessLevel: AccessLevel,
): string[] => {
  const permissionMatrix = {
    [UserRoleType.BUSINESS_OWNER]: [
      'read',
      'write',
      'delete',
      'manage_team',
      'billing',
      'invite_users',
    ],
    [UserRoleType.ACCOUNTANT]: {
      [AccessLevel.VIEWER]: ['read'],
      [AccessLevel.CONTRIBUTOR]: ['read', 'write'],
      [AccessLevel.EDITOR]: ['read', 'write', 'manage_data'],
      [AccessLevel.ADMIN]: ['read', 'write', 'manage_data', 'manage_team'],
    },
    [UserRoleType.SUBCONTRACTOR]: {
      [AccessLevel.VIEWER]: ['read'],
      [AccessLevel.CONTRIBUTOR]: ['read', 'write', 'manage_tasks'],
      [AccessLevel.EDITOR]: ['read', 'write', 'manage_tasks', 'manage_data'],
      [AccessLevel.ADMIN]: ['read', 'write', 'manage_tasks', 'manage_data'],
    },
    [UserRoleType.ADMIN]: [
      'read',
      'write',
      'delete',
      'manage_team',
      'billing',
      'system_admin',
      'invite_users',
    ],
  };

  const rolePermissions = permissionMatrix[roleType];
  if (Array.isArray(rolePermissions)) {
    return rolePermissions;
  }

  return rolePermissions[accessLevel] || [];
};

/**
 * Check available roles for an email address
 */
export const checkAvailableRoles = async (
  req: Request,
  res: Response,
): Promise<void> => {
  try {
    const { email } = req.body;

    if (!email) {
      res.status(400).json({ error: 'Email is required' });
      return;
    }

    // Find user by email
    const normalizedEmail = email.toLowerCase();
    const user = await User.findOne({ email: normalizedEmail });
    if (!user) {
      res.json({
        success: true,
        email,
        roles: [],
        multipleRoles: false,
      });
      return;
    }

    // Find all roles for this user
    const roles = await UserRoles.find({
      user: user._id,
      deleted: false,
      status: { $in: ['invited', 'active'] },
    }).populate('businessOwner', 'firstName lastName businessName email');

    const availableRoles = roles.map((role) => ({
      id: role._id.toString(),
      type: role.roleType,
      name: getRoleDisplayName(role.roleType, role.businessOwner),
      email: role.email,
      businessOwner: role.businessOwner
        ? {
            id: (role.businessOwner as any)._id,
            name: getFullDisplayName(
              role.roleType,
              role.businessOwner as any,
              user,
            ),
            email: (role.businessOwner as any).email,
          }
        : null,
      accessLevel: role.accessLevel,
      status: role.status,
      hasPassword: user.isPasswordSet,
      displayName: getFullDisplayName(
        role.roleType,
        role.businessOwner as any,
        user,
      ),
    }));

    res.json({
      success: true,
      email,
      user: {
        id: user._id,
        firstName: user.firstName,
        lastName: user.lastName,
        email: user.email,
      },
      roles: availableRoles,
      multipleRoles: availableRoles.length > 1,
    });
  } catch (error) {
    console.error('Check available roles error:', error);
    res.status(500).json({
      error: 'Internal server error',
    });
  }
};

/**
 * Unified login with role selection
 */
export const unifiedLogin = async (
  req: Request,
  res: Response,
): Promise<void> => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      res.status(400).json({
        error: 'Email and password are required',
      });
      return;
    }

    // Find user by email
    const user = await User.findOne({ email: email.toLowerCase() }).select(
      '+password',
    );
    if (!user) {
      res.status(401).json({ error: 'Invalid credentials' });
      return;
    }

    if (user.password && !user.isPasswordSet) {
      user.isPasswordSet = true;
      await user.save();
    }

    if (!user.password || !user.isPasswordSet) {
      res.status(401).json({
        error:
          'Password not set. Please check your email for setup instructions.',
        passwordNotSet: true,
      });
      return;
    }

    if (!user.password || !user.isPasswordSet) {
      res.status(401).json({
        error:
          'Password not set. Please check your email for setup instructions.',
        passwordNotSet: true,
      });
      return;
    }

    // Verify password
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      res.status(401).json({ error: 'Invalid credentials' });
      return;
    }

    // Ensure business owner role exists for legacy users
    let availableRoles = await UserRoles.find({
      user: user._id,
      deleted: false,
      status: { $in: ['invited', 'active'] },
    }).populate('businessOwner', 'firstName lastName businessName email');

    if (availableRoles.length === 0) {
      const businessOwnerRole = new UserRoles({
        user: user._id,
        email: user.email,
        roleType: UserRoleType.BUSINESS_OWNER,
        accessLevel: AccessLevel.ADMIN,
        status: 'active',
      });
      await businessOwnerRole.save();

      availableRoles = await UserRoles.find({
        user: user._id,
        deleted: false,
        status: { $in: ['invited', 'active'] },
      }).populate('businessOwner', 'firstName lastName businessName email');
    }

    const mappedRoles = availableRoles.map((role) => ({
      id: role._id.toString(),
      type: role.roleType,
      name: getRoleDisplayName(role.roleType, role.businessOwner),
      businessOwner: role.businessOwner
        ? {
            id: (role.businessOwner as any)._id,
            name: getFullDisplayName(
              role.roleType,
              role.businessOwner as any,
              user,
            ),
            email: (role.businessOwner as any).email,
          }
        : null,
      accessLevel: role.accessLevel,
      status: role.status,
    }));

    const preAuthToken = generatePreAuthToken(
      user._id.toString(),
      user.email,
    );

    res.json({
      success: true,
      preAuthToken,
      user: {
        id: user._id,
        firstName: user.firstName,
        lastName: user.lastName,
        email: user.email,
        businessName: user.businessName,
      },
      roles: mappedRoles,
      multipleRoles: mappedRoles.length > 1,
    });
  } catch (error) {
    console.error('Unified login error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
};

/**
 * Select a role after password login
 */
export const selectRole = async (
  req: Request,
  res: Response,
): Promise<void> => {
  try {
    const { roleId } = req.body;
    const token = req.header('Authorization')?.replace('Bearer ', '');

    if (!token) {
      res.status(401).json({ error: 'Missing pre-auth token' });
      return;
    }

    if (!roleId) {
      res.status(400).json({ error: 'Role ID is required' });
      return;
    }

    const decoded = jwt.verify(token, config.jwtSecret!) as {
      userId?: string;
      email?: string;
      tokenType?: string;
    };

    if (!decoded.userId || decoded.tokenType !== 'preauth') {
      res.status(401).json({ error: 'Invalid pre-auth token' });
      return;
    }

    const user = await User.findById(decoded.userId);
    if (!user) {
      res.status(401).json({ error: 'User not found' });
      return;
    }

    const userRole = await UserRoles.findOne({
      _id: roleId,
      user: user._id,
      deleted: false,
      status: { $in: ['invited', 'active'] },
    }).populate('businessOwner', 'firstName lastName businessName email');

    if (!userRole) {
      res.status(401).json({ error: 'Invalid role or access denied' });
      return;
    }

    if (userRole.status === 'invited') {
      userRole.status = 'active';
      await userRole.save();
    }

    const tokenWithRole = generateUnifiedToken(
      user._id.toString(),
      userRole._id.toString(),
      user.email,
      userRole.roleType,
      userRole.businessOwner?._id?.toString(),
    );

    const availableRoles = await UserRoles.find({
      user: user._id,
      deleted: false,
      status: { $in: ['invited', 'active'] },
    }).populate('businessOwner', 'firstName lastName businessName email');

    const currentRole = {
      id: userRole._id.toString(),
      type: userRole.roleType,
      name: getRoleDisplayName(userRole.roleType, userRole.businessOwner),
      businessOwner: userRole.businessOwner
        ? {
            id: (userRole.businessOwner as any)._id,
            name: getFullDisplayName(
              userRole.roleType,
              userRole.businessOwner as any,
              user,
            ),
            email: (userRole.businessOwner as any).email,
          }
        : null,
      accessLevel: userRole.accessLevel,
      permissions: getRolePermissions(userRole.roleType, userRole.accessLevel),
    };

    const mappedRoles = availableRoles.map((role) => ({
      id: role._id.toString(),
      type: role.roleType,
      name: getRoleDisplayName(role.roleType, role.businessOwner),
      businessOwner: role.businessOwner
        ? {
            id: (role.businessOwner as any)._id,
            name: getFullDisplayName(
              role.roleType,
              role.businessOwner as any,
              user,
            ),
            email: (role.businessOwner as any).email,
          }
        : null,
      accessLevel: role.accessLevel,
    }));

    res.json({
      success: true,
      token: tokenWithRole,
      user: {
        id: user._id,
        firstName: user.firstName,
        lastName: user.lastName,
        email: user.email,
        businessName: user.businessName,
      },
      currentRole,
      availableRoles: mappedRoles,
      permissions: currentRole.permissions,
      userRole:
        userRole.roleType === UserRoleType.BUSINESS_OWNER
          ? 'user'
          : userRole.roleType,
      redirectTo:
        userRole.roleType === UserRoleType.ACCOUNTANT
          ? '/transactions'
          : userRole.roleType === UserRoleType.SUBCONTRACTOR
            ? '/projects'
            : '/dashboard',
    });
  } catch (error) {
    console.error('Select role error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
};

/**
 * Switch role without re-authentication
 */
export const switchRole = async (
  req: Request,
  res: Response,
): Promise<void> => {
  try {
    const { roleId } = req.body;
    const userId = req.auth?.userId;

    if (!roleId || !userId) {
      res.status(400).json({ error: 'Role ID is required' });
      return;
    }

    // Find the target role and populate businessOwner
    const targetRole = await UserRoles.findOne({
      _id: roleId,
      user: userId,
      deleted: false,
      status: 'active',
    }).populate('businessOwner', 'firstName lastName businessName email _id');


    console.log("----------------------------------", targetRole)

    if (!targetRole) {
      res.status(404).json({ error: 'Role not found or access denied' });
      return;
    }

    const user = await User.findById(userId);
    if (!user) {
      res.status(404).json({ error: 'User not found' });
      return;
    }

    // Generate new token with all necessary information
    const token = jwt.sign(
      {
        userId,
        roleId: targetRole._id.toString(),
        email: user.email,
        roleType: targetRole.roleType,
        // Include businessOwnerId for accountant access
        businessOwnerId: targetRole.businessOwner?._id?.toString(),
      },
      config.jwtSecret!,
      { expiresIn: '24h' }
    );

    // Map currentRole and availableRoles for response
    const currentRole = {
      id: targetRole._id.toString(),
      type: targetRole.roleType,
      name: getRoleDisplayName(targetRole.roleType, targetRole.businessOwner),
      businessOwner: targetRole.businessOwner
        ? {
            id: (targetRole.businessOwner as any)._id,
            name: getFullDisplayName(
              targetRole.roleType,
              targetRole.businessOwner as any,
              user,
            ),
            email: (targetRole.businessOwner as any).email,
          }
        : null,
      accessLevel: targetRole.accessLevel,
      permissions: getRolePermissions(targetRole.roleType, targetRole.accessLevel),
    };

    const mappedRoles = await UserRoles.find({
      user: userId,
      deleted: false,
      status: { $in: ['invited', 'active'] },
    }).populate('businessOwner', 'firstName lastName businessName email').then(roles =>
      roles.map((role) => ({
        id: role._id.toString(),
        type: role.roleType,
        name: getRoleDisplayName(role.roleType, role.businessOwner),
        businessOwner: role.businessOwner
          ? {
              id: (role.businessOwner as any)._id,
              name: getFullDisplayName(
                role.roleType,
                role.businessOwner as any,
                user,
              ),
              email: (role.businessOwner as any).email,
            }
          : null,
        accessLevel: role.accessLevel,
      }))
    );

    // Add businessOwnerId to response for frontend use
    res.json({
      success: true,
      token,
      currentRole: {
        ...currentRole,
        // Add businessOwnerId for X-User-ID header
        businessOwnerId: targetRole.businessOwner?._id?.toString(),
      },
      availableRoles: mappedRoles,
      permissions: currentRole.permissions,
      userRole: targetRole.roleType === UserRoleType.BUSINESS_OWNER
        ? 'user'
        : targetRole.roleType,
    });
  } catch (error) {
    console.error('Switch role error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
};

/**
 * Invite user to a specific role (business owners only)
 */
export const inviteUserRole = async (
  req: Request,
  res: Response,
): Promise<void> => {
  try {
    const {
      email,
      roleType,
      accessLevel = AccessLevel.CONTRIBUTOR,
      subcontractorData,
    } = req.body;
    const businessOwnerId = req.auth?.userId;

    if (!email || !roleType) {
      res.status(400).json({ error: 'Email and role type are required' });
      return;
    }

    if (!Object.values(UserRoleType).includes(roleType)) {
      res.status(400).json({ error: 'Invalid role type' });
      return;
    }

    if (
      roleType === UserRoleType.BUSINESS_OWNER ||
      roleType === UserRoleType.ADMIN
    ) {
      res
        .status(400)
        .json({ error: 'Cannot invite business owners or admins' });
      return;
    }

    // Find or create user
    let user = await User.findOne({ email: email.toLowerCase() });
    if (!user) {
      // Create new user with subcontractor data if provided
      const userData: any = {
        email: email.toLowerCase(),
        firstName: subcontractorData?.fullName?.split(' ')[0] || '',
        lastName:
          subcontractorData?.fullName?.split(' ').slice(1).join(' ') || '',
        password: 'temp_password_' + Date.now(), // Temporary password
        authProvider: 'password',
        isPasswordSet: false,
      };

      // Add subcontractor-specific data if this is a subcontractor invitation
      if (roleType === UserRoleType.SUBCONTRACTOR && subcontractorData) {
        userData.businessName = subcontractorData.businessName;
        userData.country = subcontractorData.country;
        userData.businessType = subcontractorData.taxType;
        userData.taxId = subcontractorData.taxId;

        // Store payment information
        if (subcontractorData.paymentInformation) {
          const paymentInfo = subcontractorData.paymentInformation;
          const paymentMethods = [];

          if (paymentInfo.paymentType === 'bank') {
            paymentMethods.push({
              id: Date.now().toString(),
              type: 'bank',
              accountName: paymentInfo.accountHolderName,
              accountNumber: paymentInfo.accountNumber
                ? `****${paymentInfo.accountNumber.slice(-4)}`
                : '',
              routingNumber: paymentInfo.routingNumber || paymentInfo.swiftCode,
              isDefault: true,
            });
          } else if (paymentInfo.paymentType === 'paypal') {
            // For PayPal, we might store it differently
            userData.paypalEmail = paymentInfo.paypalEmail;
          }

          if (paymentMethods.length > 0) {
            userData.paymentMethods = paymentMethods;
          }
        }
      }

      user = new User(userData);
      await user.save();
    } else if (roleType === UserRoleType.SUBCONTRACTOR && subcontractorData) {
      // Update existing user with subcontractor data if not already set
      let shouldUpdate = false;

      if (!user.firstName && subcontractorData.fullName) {
        user.firstName = subcontractorData.fullName.split(' ')[0] || '';
        user.lastName =
          subcontractorData.fullName.split(' ').slice(1).join(' ') || '';
        shouldUpdate = true;
      }

      if (!user.businessName && subcontractorData.businessName) {
        user.businessName = subcontractorData.businessName;
        shouldUpdate = true;
      }

      if (!user.country && subcontractorData.country) {
        user.country = subcontractorData.country;
        shouldUpdate = true;
      }

      if (shouldUpdate) {
        await user.save();
      }
    }

    // Check if role already exists (including deleted ones)
    const existingRole = await UserRoles.findOne({
      user: user._id,
      roleType,
      businessOwner: businessOwnerId,
    });

    if (existingRole) {
      if (existingRole.deleted) {
        // Reactivate the deleted role instead of creating a new one
        existingRole.deleted = false;
        existingRole.status = 'invited';
        existingRole.accessLevel = accessLevel;
        existingRole.invitedAt = new Date();
        existingRole.invitedBy = businessOwnerId as any;

        // Generate new invite token
        const inviteToken = jwt.sign(
          { userId: user._id, businessOwnerId, roleType },
          config.jwtSecret!,
          { expiresIn: '7d' },
        );

        existingRole.inviteToken = inviteToken;
        existingRole.inviteTokenExpiry = new Date(
          Date.now() + 7 * 24 * 60 * 60 * 1000,
        );

        await existingRole.save();

        const needsPasswordSetup = !user.isPasswordSet;
        if (needsPasswordSetup) {
          const passwordSetupToken = crypto.randomBytes(32).toString('hex');
          user.passwordSetupToken = passwordSetupToken;
          user.passwordSetupTokenExpiry = new Date(
            Date.now() + 7 * 24 * 60 * 60 * 1000,
          );
          await user.save();
        }

        // Populate businessOwner for email template
        await existingRole.populate(
          'businessOwner',
          'firstName lastName businessName email',
        );

        // Send invitation email
        await sendRoleInvitationEmail(user, existingRole);

        res.json({
          success: true,
          message: 'Invitation sent successfully (role reactivated)',
          role: {
            id: existingRole._id,
            email: user.email,
            roleType,
            accessLevel,
            status: 'invited',
          },
        });
        return;
      } else {
        // Active role already exists
        res.status(400).json({
          error: 'User already has this role with you',
          details: `${user.email} is already invited/active as ${roleType}`,
        });
        return;
      }
    }

    // Generate invite token
    const inviteToken = jwt.sign(
      { userId: user._id, businessOwnerId, roleType },
      config.jwtSecret!,
      { expiresIn: '7d' },
    );

    // Create role
    const userRole = new UserRoles({
      user: user._id,
      email: user.email,
      roleType,
      businessOwner: businessOwnerId,
      accessLevel,
      status: 'invited',
      inviteToken,
      inviteTokenExpiry: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // 7 days
      invitedBy: businessOwnerId as any,
      invitedAt: new Date(),
    });

    await userRole.save();

    if (!user.isPasswordSet) {
      const passwordSetupToken = crypto.randomBytes(32).toString('hex');
      user.passwordSetupToken = passwordSetupToken;
      user.passwordSetupTokenExpiry = new Date(
        Date.now() + 7 * 24 * 60 * 60 * 1000,
      );
      await user.save();
    }

    // Populate businessOwner for email template
    await userRole.populate(
      'businessOwner',
      'firstName lastName businessName email',
    );

    // Send invitation email
    await sendRoleInvitationEmail(user, userRole);

    res.json({
      success: true,
      message: 'Invitation sent successfully',
      role: {
        id: userRole._id,
        email: user.email,
        roleType,
        accessLevel,
        status: 'invited',
      },
    });
  } catch (error) {
    console.error('Invite user role error:', error);

    // Handle specific MongoDB duplicate key error
    if (error.code === 11000) {
      res.status(400).json({
        error: 'User already has this role',
        details:
          'This user already has the specified role with your organization',
      });
      return;
    }

    res.status(500).json({
      error: 'Internal server error',
      details:
        process.env.NODE_ENV === 'development' ? error.message : undefined,
    });
  }
};

/**
 * Get team members for a business owner
 */
export const getTeamMembers = async (
  req: Request,
  res: Response,
): Promise<void> => {
  try {
    const businessOwnerId = req.auth?.userId;
    const { roleType } = req.query;

    let query: any = {
      businessOwner: businessOwnerId,
      deleted: false,
      status: { $in: ['invited', 'active'] },
    };

    // Filter by role type if specified
    if (roleType && roleType !== 'all') {
      query.roleType = roleType;
    }

    const teamMembers = await UserRoles.find(query)
      .populate('user', 'firstName lastName email')
      .populate('businessOwner', 'firstName lastName businessName')
      .sort({ createdAt: -1 });

    const formattedMembers = teamMembers.map((role) => {
      const user = role.user as any;
      const businessOwner = role.businessOwner as any;

      return {
        _id: role._id,
        email: role.email || user?.email,
        fullName:
          user?.firstName && user?.lastName
            ? `${user.firstName} ${user.lastName}`.trim()
            : role.email?.split('@')[0] || 'Unknown',
        firstName: user?.firstName || '',
        lastName: user?.lastName || '',
        roleType: role.roleType,
        status: role.status,
        accessLevel: role.accessLevel,
        invitedAt: role.invitedAt,
        lastAccessed: role.lastAccessed,
        businessOwner: {
          id: businessOwner?._id,
          name:
            businessOwner?.firstName && businessOwner?.lastName
              ? `${businessOwner.firstName} ${businessOwner.lastName}`.trim()
              : businessOwner?.businessName || 'Business Owner',
          email: businessOwner?.email,
        },
        // For backward compatibility
        isPasswordSet: role.status === 'active',
        deleted: false,
        createdAt: role.createdAt,
        updatedAt: role.updatedAt,
      };
    });

    res.json(formattedMembers);
  } catch (error) {
    console.error('Get team members error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
};

/**
 * Set up password for a role (supports both unified and legacy systems)
 */
export const setupRolePassword = async (
  req: Request,
  res: Response,
): Promise<void> => {
  try {
    const { token } = req.params;
    const { password, firstName, lastName } = req.body;

    if (!password) {
      res.status(400).json({ error: 'Password is required' });
      return;
    }

    // First, try to find token on User (password setup/reset)
    const user = await User.findOne({
      passwordSetupToken: token,
      passwordSetupTokenExpiry: { $gt: new Date() },
    });

    if (user) {
      if (firstName || lastName) {
        user.firstName = firstName || user.firstName;
        user.lastName = lastName || user.lastName;
      }

      const hashedPassword = await bcrypt.hash(password, 12);
      user.password = hashedPassword;
      user.isPasswordSet = true;
      user.passwordSetupToken = undefined;
      user.passwordSetupTokenExpiry = undefined;
      await user.save();

      // Ensure business owner role exists
      let businessOwnerRole = await UserRoles.findOne({
        user: user._id,
        roleType: UserRoleType.BUSINESS_OWNER,
        deleted: false,
      });

      if (!businessOwnerRole) {
        businessOwnerRole = new UserRoles({
          user: user._id,
          email: user.email,
          roleType: UserRoleType.BUSINESS_OWNER,
          accessLevel: AccessLevel.ADMIN,
          status: 'active',
        });
        await businessOwnerRole.save();
      }

      const authToken = generateUnifiedToken(
        user._id.toString(),
        businessOwnerRole._id.toString(),
        user.email,
        businessOwnerRole.roleType,
        businessOwnerRole.businessOwner?._id?.toString(),
      );

      res.json({
        success: true,
        message: 'Password set successfully',
        roleType: 'business_owner',
        token: authToken,
        user: {
          firstName: user.firstName,
          lastName: user.lastName,
          email: user.email,
        },
      });
      return;
    }

    // If not found on User, check role invite token
    const userRole = await UserRoles.findOne({
      inviteToken: token,
      inviteTokenExpiry: { $gt: new Date() },
      deleted: false,
    }).populate('user');

    if (userRole) {
      const invitedUser = userRole.user as any;

      if (firstName || lastName) {
        invitedUser.firstName = firstName || invitedUser.firstName;
        invitedUser.lastName = lastName || invitedUser.lastName;
      }

      if (!invitedUser.isPasswordSet) {
        const hashedPassword = await bcrypt.hash(password, 12);
        invitedUser.password = hashedPassword;
        invitedUser.isPasswordSet = true;
      }

      userRole.status = 'active';
      userRole.inviteToken = undefined;
      userRole.inviteTokenExpiry = undefined;

      await invitedUser.save();
      await userRole.save();

      const authToken = generateUnifiedToken(
        invitedUser._id.toString(),
        userRole._id.toString(),
        invitedUser.email,
        userRole.roleType,
        userRole.businessOwner?._id?.toString(),
      );

      res.json({
        success: true,
        message: 'Password set successfully',
        roleType: userRole.roleType,
        token: authToken,
        user: {
          firstName: invitedUser.firstName,
          lastName: invitedUser.lastName,
          email: invitedUser.email,
        },
      });
      return;
    }

    res.status(400).json({ error: 'Invalid or expired token' });
  } catch (error) {
    console.error('Setup role password error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
};

/**
 * Validate password setup token (supports both unified and legacy systems)
 */
export const validatePasswordToken = async (
  req: Request,
  res: Response,
): Promise<void> => {
  try {
    const { token } = req.params;
    // First, check User password setup/reset token
    const user = await User.findOne({
      passwordSetupToken: token,
      passwordSetupTokenExpiry: { $gt: new Date() },
    });

    if (user) {
      res.json({
        valid: true,
        user: {
          email: user.email,
          firstName: user.firstName,
          lastName: user.lastName,
        },
        roleType: 'business_owner',
        businessOwner: null,
      });
      return;
    }

    // Then check role invite token
    const userRole = await UserRoles.findOne({
      inviteToken: token,
      inviteTokenExpiry: { $gt: new Date() },
      deleted: false,
    }).populate('user businessOwner');

    if (userRole) {
      const roleUser = userRole.user as any;
      const businessOwner = userRole.businessOwner as any;

      res.json({
        valid: true,
        user: {
          email: roleUser.email,
          firstName: roleUser.firstName,
          lastName: roleUser.lastName,
        },
        roleType: userRole.roleType,
        businessOwner: businessOwner
          ? {
              firstName: businessOwner.firstName,
              lastName: businessOwner.lastName,
              businessName: businessOwner.businessName,
            }
          : null,
      });
      return;
    }

    // Token not found in either system
    res.status(400).json({
      valid: false,
      error: 'Invalid or expired token',
    });
  } catch (error) {
    console.error('Validate password token error:', error);
    res.status(500).json({
      valid: false,
      error: 'Internal server error',
    });
  }
};

/**
 * Unified password reset for role-based system
 */
export const unifiedForgotPassword = async (
  req: Request,
  res: Response,
): Promise<void> => {
  try {
    const { email } = req.body;

    if (!email) {
      res.status(400).json({ error: 'Email is required' });
      return;
    }

    const normalizedEmail = email.toLowerCase();
    const user = await User.findOne({ email: normalizedEmail });
    if (!user) {
      res.status(404).json({ error: 'No account found with this email' });
      return;
    }

    const token = crypto.randomBytes(32).toString('hex');
    const expiry = new Date(Date.now() + 48 * 60 * 60 * 1000); // 48 hours

    user.passwordSetupToken = token;
    user.passwordSetupTokenExpiry = expiry;
    await user.save();

    const resetUrl = `${config.frontURL}/setup-password/${token}`;

    await sendEmail({
      to: email,
      subject: `Reset your Potion password`,
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
          <h1 style="color: #1f2937;">Hi ${user.firstName || 'there'},</h1>
          <p>We received a request to reset your password for your Potion account.</p>
          <div style="margin: 30px 0; text-align: center;">
            <a href="${resetUrl}" style="background: #1EC64C; color: white; padding: 14px 28px; text-decoration: none; border-radius: 8px; display: inline-block; font-weight: 600;">Reset My Password</a>
          </div>
          <p><strong>This link expires in 48 hours</strong> - please reset your password soon to avoid having to request a new link.</p>
          <p style="color: #6b7280; font-size: 14px; margin-top: 30px;">If you didn't request this password reset, you can safely ignore this email. Your account remains secure.</p>
        </div>
      `,
    });

    console.log(
      `Unified password reset sent to ${normalizedEmail}`,
    );

    res.json({
      success: true,
      message: 'Password reset email sent',
      roleType: 'business_owner',
    });
  } catch (error) {
    console.error('Unified forgot password error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
};

/**
 * Send role invitation email
 */
export const sendRoleInvitationEmail = async (
  user: any,
  userRole: any,
  isNew = true,
): Promise<void> => {
  try {
    // Get business owner info
    const businessOwner = await User.findById(
      userRole.businessOwner,
    ).select('firstName lastName businessName email');
    const businessOwnerName = businessOwner
      ? `${businessOwner.firstName} ${businessOwner.lastName}`.trim() ||
        businessOwner.businessName ||
        'Your Business Partner'
      : 'Your Business Partner';

    const tokenForLink = user.passwordSetupToken || userRole.inviteToken;
    const setupLink = tokenForLink
      ? `${config.frontURL}/setup-password/${tokenForLink}`
      : `${config.frontURL}`;

    let subject = '';
    let htmlContent = '';

    if (userRole?.roleType === UserRoleType.ACCOUNTANT && isNew) {
      subject = `Invitation: Join ${businessOwnerName}'s team as Accountant`;
      htmlContent = `
        <div style="font-family: -apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif; max-width: 600px; margin: 0 auto;">
          <h1>Hello!</h1>
          <p><strong>${businessOwnerName}</strong> has invited you to join their team as an <strong>Accountant</strong> on Potion.</p>
          <p>You'll have access to their financial data and can help manage their accounting needs.</p>
          <div style="text-align: center; margin: 30px 0;">
            <a href="${setupLink}" style="background: #1EC64C; color: white; padding: 14px 28px; text-decoration: none; border-radius: 8px; display: inline-block; font-weight: 600;">Accept Invitation & Set Password</a>
          </div>
          <p style="color: #666; font-size: 14px;">This invitation will expire in 7 days. If you have any questions, contact ${businessOwnerName} directly.</p>
        </div>
      `;
    } else if (userRole?.roleType === UserRoleType.ACCOUNTANT) {
      subject = `Invitation: Join ${businessOwnerName}'s team as Accountant`;
      htmlContent = `
        <div style="font-family: -apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif; max-width: 600px; margin: 0 auto;">
          <h1>Hello!</h1>
          <p><strong>${businessOwnerName}</strong> has invited you to join their team as an <strong>Accountant</strong> on Potion.</p>
          <p>You'll have access to their financial data and can help manage their accounting needs.</p>
          <div style="text-align: center; margin: 30px 0;">
            <a href="${setupLink}" style="background: #1EC64C; color: white; padding: 14px 28px; text-decoration: none; border-radius: 8px; display: inline-block; font-weight: 600;">Accept Invitation</a>
          </div>
          <p style="color: #666; font-size: 14px;">This invitation will expire in 7 days. If you have any questions, contact ${businessOwnerName} directly.</p>
        </div>
      `;
    } else if (userRole.roleType === UserRoleType.SUBCONTRACTOR) {
      subject = `Project Invitation: Join ${businessOwnerName}'s team`;
      htmlContent = `
        <div style="font-family: -apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif; max-width: 600px; margin: 0 auto;">
          <h1>Hello!</h1>
          <p><strong>${businessOwnerName}</strong> has invited you to join their project as a <strong>Subcontractor</strong> on Potion.</p>
          <p>You'll be able to collaborate on projects, track your time, and manage your work seamlessly.</p>
          <div style="text-align: center; margin: 30px 0;">
            <a href="${setupLink}" style="background: #1EC64C; color: white; padding: 14px 28px; text-decoration: none; border-radius: 8px; display: inline-block; font-weight: 600;">Accept Invitation & Set Password</a>
          </div>
          <p style="color: #666; font-size: 14px;">This invitation will expire in 7 days. Welcome to the team!</p>
        </div>
      `;
    } else {
      subject = `Invitation: Join ${businessOwnerName}'s team`;
      htmlContent = `
        <div style="font-family: -apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif; max-width: 600px; margin: 0 auto;">
          <h1>Hello!</h1>
          <p><strong>${businessOwnerName}</strong> has invited you to join their team on Potion.</p>
          <div style="text-align: center; margin: 30px 0;">
            <a href="${setupLink}" style="background: #1EC64C; color: white; padding: 14px 28px; text-decoration: none; border-radius: 8px; display: inline-block; font-weight: 600;">Accept Invitation & Set Password</a>
          </div>
          <p style="color: #666; font-size: 14px;">This invitation will expire in 7 days.</p>
        </div>
      `;
    }

    await sendEmail({
      to: user.email,
      subject,
      html: htmlContent,
    });

    console.log(
      `✅ Role invitation email sent to ${user.email} for ${userRole.roleType} role`,
    );
  } catch (error) {
    console.error('❌ Error sending role invitation email:', error);
    throw error;
  }
};
