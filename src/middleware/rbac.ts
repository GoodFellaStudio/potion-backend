import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import { config } from '../config/config';
import { User } from '../models/User';
import { UserRoles, UserRoleType, AccessLevel } from '../models/UserRoles';

// Extended request interface for RBAC
declare global {
  namespace Express {
    interface Request {
      auth?: {
        userId: string;
        roleType: UserRoleType;
        permissions: string[];
        accessLevel?: AccessLevel;
        projectIds?: string[];

        // New unified system fields
        email?: string;
        currentRole?: {
          id: string;
          type: UserRoleType;
          accessLevel: AccessLevel;
          businessOwnerId?: string;
          permissions: string[];
        };
        availableRoles?: Array<{
          id: string;
          type: UserRoleType;
          businessOwnerName?: string;
          accessLevel: AccessLevel;
        }>;
      };
      user?: {
        userId: string;
        id?: string;
        createdBy?: string;
      };
    }
  }
}

interface TokenPayload {
  userId?: string;
  // New unified system fields
  roleId?: string; // The specific UserRoles document ID
  email?: string;
  tokenType?: string;
}

/**
 * Unified RBAC middleware that handles both old and new systems
 */
export const rbacAuth = async (
  req: Request,
  res: Response,
  next: NextFunction,
): Promise<void> => {
  try {
    const token = req.header('Authorization')?.replace('Bearer ', '');
    if (!token) {
      res.status(401).json({
        message: 'No token, authorization denied',
        code: 'NO_TOKEN',
      });
      return;
    }

    // Decode token to determine authentication type
    const decoded = jwt.verify(token, config.jwtSecret!) as TokenPayload;

    if (decoded.roleId && decoded.userId && decoded.tokenType !== 'preauth') {
      await handleUnifiedAuth(decoded, req, res);
    } else {
      res.status(401).json({
        message: 'Invalid token format',
        code: 'INVALID_TOKEN',
      });
      return;
    }

    next();
  } catch (error) {
    console.error('RBAC Auth Error:', error);
    res.status(401).json({
      message: 'Token is not valid',
      code: 'INVALID_TOKEN',
    });
  }
};

/**
 * Handle new unified authentication system
 */
async function handleUnifiedAuth(
  decoded: TokenPayload,
  req: Request,
  res: Response,
): Promise<void> {
  // Find the user
  const user = await User.findById(decoded.userId);
  if (!user) {
    res.status(401).json({
      message: 'User not found',
      code: 'USER_NOT_FOUND',
    });
    return;
  }

  // Find the specific role being used
  const currentRole = await UserRoles.findById(decoded.roleId)
    .populate('businessOwner', 'firstName lastName businessName email');

  if (!currentRole || currentRole.user.toString() !== decoded.userId) {
    res.status(401).json({
      message: 'Invalid role or insufficient permissions',
      code: 'INVALID_ROLE',
    });
    return;
  }

  // Check if role is active
  if (currentRole.status !== 'active') {
    res.status(403).json({
      message: 'Role is not active',
      code: 'ROLE_INACTIVE',
      status: currentRole.status,
    });
    return;
  }

  // Get all available roles for this user
  const availableRoles = await UserRoles.find({
    user: decoded.userId,
    deleted: false,
    status: { $in: ['invited', 'active'] },
  })
    .populate('businessOwner', 'firstName lastName businessName')
    .select('roleType accessLevel businessOwner');

  // Build permissions array
  const permissions = getUnifiedPermissions(
    currentRole.roleType,
    currentRole.accessLevel,
  );

  const projectIds = currentRole.roleContext?.projectIds?.map((id) =>
    id.toString(),
  );

  // Set auth context
  const authData = {
    userId: decoded.userId!,
    roleType: currentRole.roleType,
    permissions,
    accessLevel: currentRole.accessLevel,
    projectIds,

    // New unified system fields
    email: user.email,
    currentRole: {
      id: currentRole._id.toString(),
      type: currentRole.roleType,
      accessLevel: currentRole.accessLevel,
      businessOwnerId: currentRole.businessOwner?._id.toString(),
      permissions,
    },
    availableRoles: availableRoles.map((role) => ({
      id: role._id.toString(),
      type: role.roleType,
      businessOwnerName: role.businessOwner
        ? `${(role.businessOwner as any).firstName} ${(role.businessOwner as any).lastName}`.trim() ||
          (role.businessOwner as any).businessName
        : undefined,
      accessLevel: role.accessLevel,
    })),
  };

  req.auth = authData;

  // Set user context for data filtering
  const targetUserId =
    currentRole.roleType === UserRoleType.BUSINESS_OWNER
      ? decoded.userId!
      : currentRole.businessOwner?._id.toString() || decoded.userId!;

  req.user = {
    userId: targetUserId,
    id: targetUserId,
    createdBy: targetUserId,
  };

  // Update last accessed time
  currentRole.lastAccessed = new Date();
  await currentRole.save();
}

/**
 * Get permissions for unified system
 */
function getUnifiedPermissions(
  roleType: UserRoleType,
  accessLevel: AccessLevel,
): string[] {
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
}


/**
 * Middleware factory to check specific permissions
 */
export const requirePermission = (permission: string) => {
  return (req: Request, res: Response, next: NextFunction) => {
    if (!req.auth?.permissions.includes(permission)) {
      res.status(403).json({
        message: `Access denied: ${permission} permission required`,
        code: 'PERMISSION_DENIED',
        required: permission,
      });
      return;
    }
    next();
  };
};

/**
 * Middleware factory to check specific roles
 */
export const requireRole = (...roles: UserRoleType[]) => {
  return (req: Request, res: Response, next: NextFunction) => {
    if (!req.auth || !roles.includes(req.auth.roleType)) {
      res.status(403).json({
        message: `Access denied: One of these roles required: ${roles.join(', ')}`,
        code: 'ROLE_DENIED',
        required: roles,
      });
      return;
    }

    next();
  };
};

/**
 * Middleware to check write operations for read-only users
 */
export const checkWritePermission = (
  req: Request,
  res: Response,
  next: NextFunction,
) => {
  const method = req.method.toUpperCase();
  const writeOperations = ['POST', 'PUT', 'PATCH', 'DELETE'];

  if (writeOperations.includes(method)) {
    if (!req.auth?.permissions.includes('write')) {
      res.status(403).json({
        message: 'Access denied: Write permission required',
        code: 'WRITE_PERMISSION_DENIED',
        accessLevel: req.auth?.accessLevel,
      });
      return;
    }
  }

  next();
};

/**
 * Enhanced middleware to ensure subcontractors can only access their assigned projects
 */
export const enforceProjectAccess = (
  req: Request,
  res: Response,
  next: NextFunction,
) => {
  if (req.auth?.roleType === UserRoleType.SUBCONTRACTOR) {
    const requestedProjectId =
      req.params.projectId || req.body.projectId || req.query.projectId;

    if (requestedProjectId) {
      const hasAccess = req.auth.projectIds?.includes(requestedProjectId);

      if (!hasAccess) {
        res.status(403).json({
          message: 'Access denied: You can only access your assigned projects',
          code: 'PROJECT_ACCESS_DENIED',
        });
        return;
      }
    }
  }

  next();
};

/**
 * Get user info for the current authenticated request
 */
export const getCurrentUser = (req: Request) => {
  return {
    userId: req.auth?.userId,
    role: req.auth?.roleType,
    permissions: req.auth?.permissions,
    accessLevel: req.auth?.accessLevel,
    projectIds: req.auth?.projectIds,

    // New unified system fields
    email: req.auth?.email,
    currentRole: req.auth?.currentRole,
    availableRoles: req.auth?.availableRoles,
  };
};

/**
 * Middleware to ensure only business owners can access certain endpoints (unified system)
 */
export const businessOwnerOnly = (
  req: Request,
  res: Response,
  next: NextFunction,
) => {
  if (req.auth?.currentRole?.type !== UserRoleType.BUSINESS_OWNER) {
    res.status(403).json({
      message: 'Access denied: Business owner access required',
      code: 'BUSINESS_OWNER_ONLY',
    });
    return;
  }
  next();
};
