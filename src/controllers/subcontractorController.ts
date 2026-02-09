import { Request, Response } from 'express';
import { Subcontractor } from '../models/Subcontractor';
import { SubcontractorProjectAccess } from '../models/SubcontractorProjectAccess';
import { Project } from '../models/Project';
import { AccessLevel, UserRoleType } from '../models/UserRoles';
import { sendEmail } from '../services/emailService';
import { reactEmailService } from '../services/reactEmailService';
import type { SubcontractorInvitationProps } from '../templates/react-email/subcontractor-invitation';
import type { SubcontractorLoginReadyProps } from '../templates/react-email/subcontractor-login-ready';
import type { SubcontractorRemovedProps } from '../templates/react-email/subcontractor-removed';
import type { SubcontractorSetupProps } from '../templates/react-email/subcontractor-setup';
import type { SubcontractorProjectAssignedProps } from '../templates/react-email/subcontractor-project-assigned';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { config } from '../config/config';
import { v4 as uuidv4 } from 'uuid';
import { User } from '../models/User'; // Added import for User
import crypto from 'crypto'; // Added import for crypto

// Send email to subcontractor when they are added to a new business owner (existing subcontractor)
const sendSubcontractorBusinessOwnerAddedEmail = async (
  email: string,
  subcontractorName: string,
  businessOwnerName: string,
  businessOwnerBusinessName?: string,
  projectsCount?: number,
  projectNames?: string[],
): Promise<void> => {
  try {
    // For now, use a simple template until the proper one is created
    await sendEmail({
      to: email,
      subject: `New Project Access - ${businessOwnerName}`,
      html: `
        <div style="font-family: -apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif; max-width: 600px; margin: 0 auto;">
          <h1>Hello ${subcontractorName},</h1>
          <p><strong>${businessOwnerName}</strong> has given you access to ${projectsCount || 1} project(s)${businessOwnerBusinessName ? ` at ${businessOwnerBusinessName}` : ''}.</p>
          ${projectNames && projectNames.length > 0 ? `<p><strong>Projects:</strong> ${projectNames.join(', ')}</p>` : ''}
          <div style="text-align: center; margin: 30px 0;">
            <a href="${config.frontURL}/login" style="background: #1EC64C; color: white; padding: 14px 28px; text-decoration: none; border-radius: 8px; display: inline-block; font-weight: 600;">Login to View Projects</a>
          </div>
          <p style="color: #666; font-size: 14px;">You can now access your projects using your existing Potion account.</p>
        </div>
      `,
    });
  } catch (error) {
    console.error(
      '❌ Error in sendSubcontractorBusinessOwnerAddedEmail:',
      error,
    );
    throw error;
  }
};

// Email service functions
const sendSubcontractorInvitationEmail = async (
  email: string,
  projectName: string,
  inviteUrl: string,
  subcontractorName?: string,
  clientName?: string,
  senderName?: string,
) => {
  try {
    const props = {
      projectName,
      inviteUrl,
      subcontractorName: subcontractorName || 'there',
      clientName,
      senderName: senderName || 'Project Manager',
    };

    const { subject, html } = await reactEmailService.renderTemplate(
      'subcontractor-invitation',
      props,
    );

    return sendEmail({
      to: email,
      subject,
      html,
    });
  } catch (error) {
    console.error('❌ Error sending subcontractor invitation email:', error);

    // Fallback to basic email
    return sendEmail({
      to: email,
      subject: 'Project Invitation - Join Our Team',
      html: `
        <div style="font-family: -apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif; max-width: 600px; margin: 0 auto;">
          <h1>Hello ${subcontractorName || 'there'},</h1>
          <p><strong>${senderName || 'Project Manager'}</strong> has invited you to join the <strong>"${projectName}"</strong> project as a subcontractor${clientName ? ` for ${clientName}` : ''}.</p>
          <div style="text-align: center; margin: 30px 0;">
            <a href="${inviteUrl}" style="background: #1EC64C; color: white; padding: 14px 28px; text-decoration: none; border-radius: 8px; display: inline-block; font-weight: 600;">Accept Invitation</a>
          </div>
          <p style="color: #666; font-size: 14px;">Welcome to the team! We're excited to work with you on this project.</p>
        </div>
      `,
    });
  }
};

const sendSubcontractorLoginReadyEmail = async (
  email: string,
  firstName: string,
  projectName?: string,
  clientName?: string,
) => {
  try {
    const loginUrl = `${config.frontURL}/login`;

    const props: SubcontractorLoginReadyProps = {
      firstName: firstName || 'there',
      loginUrl,
      projectName,
      clientName,
    };

    const { subject, html } = await reactEmailService.renderTemplate(
      'subcontractor-login-ready',
      props,
    );

    return sendEmail({
      to: email,
      subject,
      html,
    });
  } catch (error) {
    console.error('Error sending subcontractor login ready email:', error);

    // Fallback to basic HTML email
    return sendEmail({
      to: email,
      subject: 'Your Potion account is ready - You can now login!',
      html: `
        <div style="font-family: -apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif; max-width: 600px; margin: 0 auto;">
          <h1>Hi ${firstName},</h1>
          <p><strong>Great news!</strong> Your password has been set successfully.</p>
          <p>Your Potion account is now ready to use! You can login and access your project dashboard anytime.</p>
          ${projectName ? `<p><strong>Project:</strong> ${projectName}${clientName ? `<br><strong>Client:</strong> ${clientName}` : ''}</p>` : ''}
          <div style="text-align: center; margin: 30px 0;">
            <a href="${config.frontURL}/login" style="background: #1EC64C; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; display: inline-block;">Login to Your Account</a>
          </div>
          <p style="font-size: 14px; color: #666;">Need help? Just reply to this email - our support team is here to assist you.</p>
        </div>
      `,
    });
  }
};

// Send generic setup email to new subcontractor (no project mentioned)
const sendSubcontractorSetupEmail = async (
  email: string,
  subcontractorName: string,
  setupUrl: string,
  clientName?: string,
  senderName?: string,
): Promise<void> => {
  try {
    const emailData =
      await reactEmailService.renderTemplateWithValidation<SubcontractorSetupProps>(
        'subcontractor-setup',
        {
          ...reactEmailService.getDefaultProps(),
          subcontractorName,
          setupUrl,
          clientName,
          senderName,
        },
        ['subcontractorName', 'setupUrl'],
      );

    await sendEmail({
      to: email,
      subject: emailData.subject,
      html: emailData.html,
    });
  } catch (error) {
    console.error('❌ Error in sendSubcontractorSetupEmail:', error);
    throw error;
  }
};

// Send project assignment notification to existing subcontractor
const sendSubcontractorProjectAssignedEmail = async (
  email: string,
  subcontractorName: string,
  projectName: string,
  clientName?: string,
  senderName?: string,
  projectDescription?: string,
): Promise<void> => {
  try {
    const emailData =
      await reactEmailService.renderTemplateWithValidation<SubcontractorProjectAssignedProps>(
        'subcontractor-project-assigned',
        {
          ...reactEmailService.getDefaultProps(),
          subcontractorName,
          projectName,
          clientName,
          senderName,
          projectDescription,
          loginUrl: config.frontURL + '/login',
        },
        ['subcontractorName', 'projectName'],
      );

    await sendEmail({
      to: email,
      subject: emailData.subject,
      html: emailData.html,
    });
  } catch (error) {
    console.error('❌ Error in sendSubcontractorProjectAssignedEmail:', error);
    throw error;
  }
};

/**
 * Get all projects accessible to a subcontractor
 */
export const getSubcontractorProjects = async (req: Request, res: Response) => {
  try {
    const roleType = req.auth?.roleType;
    const projectIds = req.auth?.projectIds || [];

    if (roleType !== UserRoleType.SUBCONTRACTOR) {
      return res.status(400).json({
        message: 'Subcontractor role required',
        code: 'INVALID_ROLE',
      });
    }

    if (!projectIds.length) {
      return res.status(404).json({
        message: 'No projects assigned',
        code: 'NO_PROJECTS_ASSIGNED',
      });
    }

    const projectsData = await Project.find({
      _id: { $in: projectIds },
      deleted: false,
    })
      .populate({
        path: 'createdBy',
        select: 'firstName lastName email businessName profilePicture',
      })
      .sort({ createdAt: -1 });

    const projects = projectsData.map((project: any) => ({
      id: project._id,
      projectId: project._id,
      userId: project.createdBy?._id,
      projectName: project.name,
      projectDescription: project.description,
      projectStatus: project.status,
      clientName:
        project.createdBy?.firstName && project.createdBy?.lastName
          ? `${project.createdBy.firstName} ${project.createdBy.lastName}`.trim()
          : project.createdBy?.businessName || '',
      clientEmail: project.createdBy?.email,
      clientBusinessName: project.createdBy?.businessName,
      accessLevel: req.auth?.accessLevel || AccessLevel.CONTRIBUTOR,
      status: 'active',
      lastAccessed: project.updatedAt,
    }));

    res.json({
      success: true,
      projects,
      total: projects.length,
    });
  } catch (error) {
    console.error('Error fetching subcontractor projects:', error);
    res.status(500).json({
      message: 'Failed to fetch projects',
      code: 'FETCH_PROJECTS_ERROR',
    });
  }
};

/**
 * Assign a subcontractor to a project (for project owners)
 */
export const assignSubcontractorToProject = async (
  req: Request,
  res: Response,
) => {
  try {
    const { userId } = req.auth!;
    const {
      subcontractorId,
      projectId,
      accessLevel = 'contributor',
      role = 'Contractor',
      paymentTerms,
    } = req.body;

    // Validate required fields
    if (!subcontractorId || !projectId) {
      return res.status(400).json({
        message: 'Subcontractor ID and Project ID are required',
        code: 'MISSING_REQUIRED_FIELDS',
      });
    }

    // Verify the project belongs to the authenticated user
    const project = await Project.findOne({
      _id: projectId,
      createdBy: userId,
    });
    if (!project) {
      return res.status(404).json({
        message: 'Project not found or you do not have permission to manage it',
        code: 'PROJECT_NOT_FOUND',
      });
    }

    // Verify the subcontractor exists
    const subcontractor = await Subcontractor.findById(subcontractorId);
    if (!subcontractor) {
      return res.status(404).json({
        message: 'Subcontractor not found',
        code: 'SUBCONTRACTOR_NOT_FOUND',
      });
    }

    // Check if assignment already exists
    const existingAccess: any = await SubcontractorProjectAccess.findOne({
      subcontractor: subcontractorId,
      project: projectId,
    });

    if (existingAccess) {
      // Update existing access
      existingAccess.accessLevel = accessLevel;
      existingAccess.role = role;
      existingAccess.paymentTerms = paymentTerms;
      existingAccess.status = 'active';
      await existingAccess.save();

      return res.json({
        success: true,
        message: 'Subcontractor assignment updated successfully',
        access: existingAccess,
      });
    }

    // Create new project access
    const projectAccess = new SubcontractorProjectAccess({
      subcontractor: subcontractorId,
      project: projectId,
      user: userId,
      accessLevel,
      role,
      paymentTerms,
      status: 'active',
    });

    await projectAccess.save();

    // Populate the created access for response
    await projectAccess.populate([
      { path: 'subcontractor', select: 'fullName email' },
      { path: 'project', select: 'name description' },
      { path: 'user', select: 'firstName lastName businessName' },
    ]);

    // Send project assignment email to subcontractor
    try {
      const populatedAccess = projectAccess as any;
      const subcontractorEmail = populatedAccess.subcontractor.email;
      const subcontractorName =
        populatedAccess.subcontractor.fullName ||
        subcontractorEmail.split('@')[0];
      const projectName = populatedAccess.project.name;
      const projectDescription = populatedAccess.project.description;
      const clientName =
        `${populatedAccess.user.firstName} ${populatedAccess.user.lastName}`.trim();
      const senderName = clientName || 'Project Manager';

      await sendSubcontractorProjectAssignedEmail(
        subcontractorEmail,
        subcontractorName,
        projectName,
        clientName,
        senderName,
        projectDescription,
      );
    } catch (emailError) {
      console.error('Error sending project assignment email:', emailError);
      // Don't fail the assignment if email fails - just log the error
    }

    res.status(201).json({
      success: true,
      message: 'Subcontractor assigned to project successfully',
      access: projectAccess,
    });
  } catch (error) {
    console.error('Error assigning subcontractor to project:', error);
    res.status(500).json({
      message: 'Failed to assign subcontractor to project',
      code: 'ASSIGNMENT_ERROR',
    });
  }
};

/**
 * Get all subcontractors assigned to a specific project (for project owners)
 */
export const getProjectSubcontractors = async (req: Request, res: Response) => {
  try {
    const { userId } = req.auth!;
    const { projectId } = req.params;

    // Verify the project belongs to the authenticated user
    const project = await Project.findOne({
      _id: projectId,
      createdBy: userId,
    });
    if (!project) {
      return res.status(404).json({
        message: 'Project not found or you do not have permission to view it',
        code: 'PROJECT_NOT_FOUND',
      });
    }

    // Get all subcontractors assigned to this project
    const projectAccesses = await SubcontractorProjectAccess.find({
      project: projectId,
      status: { $ne: 'terminated' },
    })
      .populate({
        path: 'subcontractor',
        select: 'fullName email businessName status',
      })
      .sort({ createdAt: -1 });

    const subcontractors = projectAccesses.map((access: any) => ({
      id: access._id,
      subcontractorId: access.subcontractor._id,
      fullName: access.subcontractor.fullName,
      email: access.subcontractor.email,
      businessName: access.subcontractor.businessName,
      accessLevel: access.accessLevel,
      role: access.role,
      paymentTerms: access.paymentTerms,
      status: access.status,
      startDate: access.startDate,
      endDate: access.endDate,
      assignedAt: access.createdAt,
    }));

    res.json({
      success: true,
      project: {
        id: project._id,
        name: project.name,
        description: project.description,
      },
      subcontractors,
      total: subcontractors.length,
    });
  } catch (error) {
    console.error('Error fetching project subcontractors:', error);
    res.status(500).json({
      message: 'Failed to fetch project subcontractors',
      code: 'FETCH_ERROR',
    });
  }
};

/**
 * Remove a subcontractor from a project
 */
export const removeSubcontractorFromProject = async (
  req: Request,
  res: Response,
) => {
  try {
    const { userId } = req.auth!;
    const { accessId } = req.params;

    // Find the project access record
    const projectAccess: any =
      await SubcontractorProjectAccess.findById(accessId).populate('project');

    if (!projectAccess) {
      return res.status(404).json({
        message: 'Project access record not found',
        code: 'ACCESS_NOT_FOUND',
      });
    }

    // Verify the project belongs to the authenticated user
    if (projectAccess.user.toString() !== userId) {
      return res.status(403).json({
        message: 'You do not have permission to manage this project assignment',
        code: 'PERMISSION_DENIED',
      });
    }

    // Set status to terminated instead of deleting
    projectAccess.status = 'terminated';
    projectAccess.endDate = new Date();
    await projectAccess.save();

    res.json({
      success: true,
      message: 'Subcontractor removed from project successfully',
    });
  } catch (error) {
    console.error('Error removing subcontractor from project:', error);
    res.status(500).json({
      message: 'Failed to remove subcontractor from project',
      code: 'REMOVAL_ERROR',
    });
  }
};

/**
 * Bulk assign multiple subcontractors to a project
 */
export const bulkAssignSubcontractors = async (req: Request, res: Response) => {
  try {
    const { userId } = req.auth!;
    const { projectId, assignments } = req.body;

    if (!projectId || !Array.isArray(assignments) || assignments.length === 0) {
      return res.status(400).json({
        message: 'Project ID and assignments array are required',
        code: 'MISSING_REQUIRED_FIELDS',
      });
    }

    // Verify the project belongs to the authenticated user
    const project = await Project.findOne({
      _id: projectId,
      createdBy: userId,
    });
    if (!project) {
      return res.status(404).json({
        message: 'Project not found or you do not have permission to manage it',
        code: 'PROJECT_NOT_FOUND',
      });
    }

    const results = {
      successful: [],
      failed: [],
      updated: [],
    };

    // Process each assignment
    for (const assignment of assignments) {
      try {
        const {
          subcontractorId,
          accessLevel = 'contributor',
          role = 'Contractor',
          paymentTerms,
        } = assignment;

        // Verify subcontractor exists
        const subcontractor: any =
          await Subcontractor.findById(subcontractorId);
        if (!subcontractor) {
          results.failed.push({
            subcontractorId,
            error: 'Subcontractor not found',
          });
          continue;
        }

        // Check if assignment already exists
        const existingAccess: any = await SubcontractorProjectAccess.findOne({
          subcontractor: subcontractorId,
          project: projectId,
        });

        if (existingAccess) {
          // Update existing
          existingAccess.accessLevel = accessLevel;
          existingAccess.role = role;
          existingAccess.paymentTerms = paymentTerms;
          existingAccess.status = 'active';
          await existingAccess.save();

          results.updated.push({
            subcontractorId,
            subcontractorName: subcontractor.fullName,
            accessLevel,
            role,
          });

          // Send project assignment email for updated assignments too
          try {
            const user = await User.findById(userId);
            const clientName = user
              ? `${user.firstName} ${user.lastName}`.trim()
              : undefined;
            const senderName = clientName || 'Project Manager';
            const subcontractorName =
              subcontractor.fullName || subcontractor.email.split('@')[0];

            await sendSubcontractorProjectAssignedEmail(
              subcontractor.email,
              subcontractorName,
              project.name,
              clientName,
              senderName,
              project.description,
            );
          } catch (emailError) {
    
          }
        } else {
          // Create new
          const projectAccess = new SubcontractorProjectAccess({
            subcontractor: subcontractorId,
            project: projectId,
            user: userId,
            accessLevel,
            role,
            paymentTerms,
            status: 'active',
          });

          await projectAccess.save();

          results.successful.push({
            subcontractorId,
            subcontractorName: subcontractor.fullName,
            accessLevel,
            role,
          });

          // Send project assignment email
          try {
            const user = await User.findById(userId);
            const clientName = user
              ? `${user.firstName} ${user.lastName}`.trim()
              : undefined;
            const senderName = clientName || 'Project Manager';
            const subcontractorName =
              subcontractor.fullName || subcontractor.email.split('@')[0];

            await sendSubcontractorProjectAssignedEmail(
              subcontractor.email,
              subcontractorName,
              project.name,
              clientName,
              senderName,
              project.description,
            );

            console.log(
              '✅ Project assignment email sent to:',
              subcontractor.email,
            );
          } catch (emailError) {
            console.error(
              '❌ Error sending project assignment email to',
              subcontractor.email,
              ':',
              emailError,
            );
            // Don't fail the assignment if email fails
          }
        }
      } catch (error) {
        results.failed.push({
          subcontractorId: assignment.subcontractorId,
          error: error.message,
        });
      }
    }

    res.json({
      success: true,
      message: 'Bulk assignment completed',
      results,
      summary: {
        total: assignments.length,
        successful: results.successful.length,
        updated: results.updated.length,
        failed: results.failed.length,
      },
    });
  } catch (error) {
    console.error('Error in bulk assignment:', error);
    res.status(500).json({
      message: 'Failed to complete bulk assignment',
      code: 'BULK_ASSIGNMENT_ERROR',
    });
  }
};

export const subcontractorController = {
  async createSubcontractor(req: Request, res: Response): Promise<any> {
    try {
      console.log(
        '\n📝 [DEBUG] createSubcontractor controller function called',
      );
      console.log('[DEBUG] Request body:', JSON.stringify(req.body, null, 2));
      console.log('[DEBUG] User auth data:', JSON.stringify(req.auth, null, 2));
      console.log('[DEBUG] User object:', JSON.stringify(req.user, null, 2));

      const { email, fullName, isUSCitizen, paymentInformation, projectId } =
        req.body;
      const userId = req.user?.userId;

      console.log('[DEBUG] Extracted values:', {
        email,
        fullName,
        isUSCitizen,
        paymentInformation,
        projectId,
        userId,
      });

      // Create subcontractorData object for easier reference
      const subcontractorData = {
        email,
        fullName,
        isUSCitizen,
        paymentInformation,
      };

      if (!email || !fullName) {
        console.log('[DEBUG] ❌ Missing required fields (email or fullName)');
        return res.status(400).json({
          message: 'Email and full name are required',
        });
      }

      console.log(
        '[DEBUG] ✅ All required fields present, proceeding with creation...',
      );

      // Validate payment information
      const paymentInfo = paymentInformation;
      if (
        paymentInfo?.paymentType === 'bank' &&
        (!paymentInfo?.routingNumber || !paymentInfo?.accountNumber)
      ) {
        return res.status(400).json({ message: 'Missing bank information' });
      }
      if (paymentInfo?.paymentType === 'paypal' && !paymentInfo?.paypalEmail) {
        return res.status(400).json({ message: 'PayPal email required' });
      }
      if (
        paymentInfo?.paymentType === 'other' &&
        !paymentInfo?.paymentDescription
      ) {
        return res
          .status(400)
          .json({ message: 'Payment description required' });
      }

      let projectData;
      if (!!projectId) {
        projectData = await Project.findById(projectId).lean();
        if (!projectData) {
          return res.status(404).json({ message: 'Project not found' });
        }
      }

      const hasData = Object.keys(subcontractorData || {}).length > 0;

      // Check if subcontractor already exists by email (unified approach like accountants)
      let subcontractor = null;
      let isNewSubcontractor = false;

      if (subcontractorData.email) {
        subcontractor = await Subcontractor.findOne({
          email: subcontractorData.email.toLowerCase(),
        });
      }

      if (!subcontractor) {
        // Create new subcontractor record (unified approach)
        const inviteKey = `project-${uuidv4()}`;
        subcontractor = new Subcontractor({
          ...subcontractorData,
          email: subcontractorData.email?.toLowerCase(),
          inviteKey: inviteKey, // Keep for backward compatibility
          // Don't set createdBy for unified records - they can work for multiple business owners
        });

        // Generate password setup token for new subcontractor
        if (subcontractorData.email) {
          const passwordSetupToken = crypto.randomBytes(32).toString('hex');
          const passwordSetupTokenExpiry = new Date(
            Date.now() + 48 * 60 * 60 * 1000,
          ); // 48 hours

          subcontractor.passwordSetupToken = passwordSetupToken;
          subcontractor.passwordSetupTokenExpiry = passwordSetupTokenExpiry;
        }

        await subcontractor.save();
        isNewSubcontractor = true;
      } else {
        // Update existing subcontractor with any new data (excluding email and password fields)
        const updateData = { ...subcontractorData };
        delete updateData.email; // Don't update email
        // Note: password and isPasswordSet are not in subcontractorData, so no need to delete them

        // Update the existing subcontractor with new information
        await Subcontractor.findByIdAndUpdate(subcontractor._id, updateData);
      }

      // Create SubcontractorProjectAccess relationship
      // If project is specified, use it; otherwise create relationship with first available project
      let projectToAssign = projectId;
      if (!projectToAssign) {
        // Find the business owner's first project to create a general relationship
        const userProjects = await Project.find({
          createdBy: userId,
          deleted: { $ne: true },
        }).limit(1);

        if (userProjects.length > 0) {
          projectToAssign = userProjects[0]._id;
        }
      }

      // Create the access relationship if we have a project
      if (projectToAssign) {
        const existingAccess = await SubcontractorProjectAccess.findOne({
          subcontractor: subcontractor._id,
          project: projectToAssign,
          user: userId,
        });

        if (!existingAccess) {
          // Create the project access relationship
          const projectAccess = new SubcontractorProjectAccess({
            subcontractor: subcontractor._id,
            project: projectToAssign,
            user: userId,
            accessLevel: 'contributor', // Default access level
            role: 'Contractor', // Default role
            status: 'active',
          });

          await projectAccess.save();
        }
      }

      // Send appropriate email based on subcontractor status
      if (subcontractorData?.email && hasData) {
        try {
          // Get user info for email context
          const user = await User.findById(userId);
          const clientName = user
            ? `${user.firstName} ${user.lastName}`.trim()
            : undefined;
          const senderName = clientName || 'Project Manager';

          // Check if this is a first-time subcontractor or existing one without password
          const existingActiveProjects = await SubcontractorProjectAccess.find({
            subcontractor: subcontractor._id,
            status: 'active',
          });

          const shouldSendSetupEmail =
            isNewSubcontractor ||
            (!subcontractor.password && existingActiveProjects.length === 0);

          if (shouldSendSetupEmail) {
            // Send setup invitation email for new subcontractor
            const setupLink = `${req?.headers?.origin || config.frontURL}/setup-password/${subcontractor.passwordSetupToken}`;

            await sendSubcontractorSetupEmail(
              subcontractorData.email,
              subcontractorData.fullName ||
                subcontractorData.email.split('@')[0],
              setupLink,
              clientName,
              senderName,
            );
          } else if (subcontractor.password && !isNewSubcontractor) {
            // Existing subcontractor with password - send "added to new business owner" email
            await sendSubcontractorBusinessOwnerAddedEmail(
              subcontractorData.email,
              subcontractorData.fullName ||
                subcontractorData.email.split('@')[0],
              clientName || senderName || 'Project Manager',
              user?.businessName,
              1, // New business owner with 1 project access
              [projectData?.name].filter(Boolean),
            );
          }
        } catch (emailError) {
          console.error(
            'Error sending email during subcontractor creation:',
            emailError,
          );
          return res.status(201).json({
            ...subcontractor.toObject(),
            emailWarning:
              'Subcontractor created successfully, but invitation email could not be sent.',
          });
        }
      }

      res.status(201).json(subcontractor);
    } catch (error) {
      console.error('Error creating subcontractor:', error);
      res.status(500).json({ message: 'Server error', error });
    }
  },

  async generateInviteLink(req: Request, res: Response): Promise<any> {
    try {
      const { id } = req.params;
      const subcontractor = await Subcontractor.findById(id); // Remove invalid populate
      if (!subcontractor) {
        return res.status(404).json({ message: 'Subcontractor not found' });
      }
      const inviteKey = `subcontractor-${uuidv4()}`; // Use generic name since no project field
      await Subcontractor.findByIdAndUpdate(id, { inviteKey }, { new: true });

      res.json({ inviteKey });
    } catch (error) {
      res.status(500).json({ message: 'Server error', error });
    }
  },

  async inviteSubcontractor(req: Request, res: Response): Promise<any> {
    try {
      console.log(
        '\n🎯 [DEBUG] inviteSubcontractor controller function called',
      );
      console.log(
        '[DEBUG] Request params:',
        JSON.stringify(req.params, null, 2),
      );
      console.log('[DEBUG] Request body:', JSON.stringify(req.body, null, 2));
      console.log('[DEBUG] User auth data:', JSON.stringify(req.auth, null, 2));
      console.log('[DEBUG] User object:', JSON.stringify(req.user, null, 2));

      const { id } = req.params;
      const { email, projectId, note, passkey } = req.body;
      const userId = req.user?.userId;

      console.log('[DEBUG] Extracted values:', {
        id,
        email,
        projectId,
        note,
        passkey: passkey ? '[SET]' : '[NOT SET]',
        userId,
      });

      if (!email) {
        console.log('[DEBUG] ❌ Missing email field');
        return res.status(400).json({ message: 'Missing required fields' });
      }

      console.log(
        '[DEBUG] ✅ All required fields present, proceeding with invitation...',
      );

      // Use unified approach - find existing subcontractor by email
      let subcontractor = await Subcontractor.findOne({
        email: email.toLowerCase(),
      });

      let isNewSubcontractor = false;

      if (!subcontractor) {
        console.log('[DEBUG] ✨ Creating new subcontractor');
        // Create new unified subcontractor record
        subcontractor = new Subcontractor({
          email: email.toLowerCase(),
          passkey,
          note,
          status: 'invited',
          inviteKey: uuidv4(),
        });

        // Generate password setup token for new subcontractor
        const passwordSetupToken = crypto.randomBytes(32).toString('hex');
        const passwordSetupTokenExpiry = new Date(
          Date.now() + 48 * 60 * 60 * 1000,
        ); // 48 hours

        subcontractor.passwordSetupToken = passwordSetupToken;
        subcontractor.passwordSetupTokenExpiry = passwordSetupTokenExpiry;

        await subcontractor.save();
        console.log('[DEBUG] ✅ New subcontractor created:', subcontractor._id);
        isNewSubcontractor = true;
      } else {
        console.log(
          '[DEBUG] 📝 Updating existing subcontractor:',
          subcontractor._id,
        );
        // Update existing subcontractor
        await Subcontractor.findByIdAndUpdate(subcontractor._id, {
          passkey,
          note,
          status: 'invited',
        });

        // Generate new password setup token if they don't have password
        if (!subcontractor.password) {
          const passwordSetupToken = crypto.randomBytes(32).toString('hex');
          const passwordSetupTokenExpiry = new Date(
            Date.now() + 48 * 60 * 60 * 1000,
          ); // 48 hours

          subcontractor.passwordSetupToken = passwordSetupToken;
          subcontractor.passwordSetupTokenExpiry = passwordSetupTokenExpiry;
          await subcontractor.save();
          console.log(
            '[DEBUG] 🔑 Updated password setup token for existing subcontractor',
          );
        }
      }

      // Create SubcontractorProjectAccess relationship
      // If projectId is provided, use it; otherwise create a general relationship with first available project
      let projectToAssign = projectId;
      if (!projectToAssign) {
        console.log(
          '[DEBUG] 🔍 Looking for user projects to assign general relationship',
        );
        // Find the business owner's first project to create a general relationship
        const userProjects = await Project.find({
          createdBy: userId,
          deleted: { $ne: true },
        }).limit(1);

        if (userProjects.length > 0) {
          projectToAssign = userProjects[0]._id;
          console.log('[DEBUG] 📂 Found project to assign:', projectToAssign);
        } else {
          console.log('[DEBUG] ⚠️ No projects found for user:', userId);
        }
      }

      // Create the access relationship if we have a project
      if (projectToAssign) {
        console.log(
          '[DEBUG] 🔗 Creating SubcontractorProjectAccess relationship',
        );
        const existingAccess = await SubcontractorProjectAccess.findOne({
          subcontractor: subcontractor._id,
          project: projectToAssign,
          user: userId,
        });

        if (!existingAccess) {
          const projectAccess = new SubcontractorProjectAccess({
            subcontractor: subcontractor._id,
            project: projectToAssign,
            user: userId,
            accessLevel: 'contributor', // Default access level
            role: 'Contractor', // Default role
            status: 'active',
          });

          await projectAccess.save();
          console.log(
            '[DEBUG] ✅ SubcontractorProjectAccess created:',
            projectAccess._id,
          );
        } else {
          console.log(
            '[DEBUG] 📋 SubcontractorProjectAccess already exists:',
            existingAccess._id,
          );
        }
      } else {
        console.log(
          '[DEBUG] ⚠️ No project to assign - skipping access creation',
        );
      }

      // Get user info for email context
      const user = await User.findById(userId);
      const clientName = user
        ? `${user.firstName} ${user.lastName}`.trim()
        : undefined;
      const senderName = clientName || 'Project Manager';

      console.log('[DEBUG] 👤 User info for email:', {
        clientName,
        senderName,
        businessName: user?.businessName,
      });

      // Check if subcontractor has any existing active project relationships
      const existingActiveProjects = await SubcontractorProjectAccess.find({
        subcontractor: subcontractor._id,
        status: 'active',
      });

      // Check if this subcontractor already has projects with THIS business owner
      const existingProjectsWithThisUser =
        await SubcontractorProjectAccess.find({
          subcontractor: subcontractor._id,
          user: userId,
          status: 'active',
        });

      // CORRECTED EMAIL LOGIC:
      // - New subcontractor (never existed) → Setup email
      // - Existing subcontractor without password → Setup email
      // - Existing subcontractor with password + first time with this business owner → Business owner added email
      // - Existing subcontractor with password + already working with this business owner → Business owner added email
      const shouldSendSetupEmail =
        isNewSubcontractor || !subcontractor.password;

      console.log('[DEBUG] 📧 Email decision:', {
        isNewSubcontractor,
        hasPassword: !!subcontractor.password,
        totalActiveProjects: existingActiveProjects.length,
        activeProjectsWithThisUser: existingProjectsWithThisUser.length,
        shouldSendSetupEmail,
        logic: isNewSubcontractor
          ? 'New subcontractor → Setup email'
          : !subcontractor.password
            ? 'Existing subcontractor, no password → Setup email'
            : existingProjectsWithThisUser.length <= 1
              ? 'Existing subcontractor with password, first time with this business owner → Business owner added email'
              : 'Existing subcontractor with password, additional project with same business owner → Business owner added email',
      });

      // Send appropriate email based on subcontractor status
      if (shouldSendSetupEmail) {
        console.log('[DEBUG] 📨 Sending setup email...');
        // First time invitation - send setup email
        const setupLink = `${req?.headers?.origin || config.frontURL}/setup-password/${subcontractor.passwordSetupToken}`;

        try {
          await sendSubcontractorSetupEmail(
            email,
            subcontractor.fullName || email.split('@')[0],
            setupLink,
            clientName,
            senderName,
          );
          console.log('[DEBUG] ✅ Setup email sent successfully');
        } catch (emailError) {
          console.error(
            '[DEBUG] ❌ Error sending setup invitation email:',
            emailError,
          );
          throw emailError;
        }
      } else if (subcontractor.password && !isNewSubcontractor) {
        console.log('[DEBUG] 📨 Sending business owner added email...');
        // Existing subcontractor with password - send "added to new business owner" email
        try {
          // Get current business owner's projects for this subcontractor to show count
          const existingProjects = await SubcontractorProjectAccess.find({
            subcontractor: subcontractor._id,
            user: userId,
            status: 'active',
          }).populate('project');

          const projectNames = existingProjects
            .map((access: any) => access.project?.name)
            .filter(Boolean);

          await sendSubcontractorBusinessOwnerAddedEmail(
            email,
            subcontractor.fullName || email.split('@')[0],
            clientName || senderName || 'Project Manager',
            user?.businessName,
            existingProjects.length,
            projectNames,
          );
          console.log(
            '[DEBUG] ✅ Business owner added email sent successfully',
          );
        } catch (emailError) {
          console.error(
            '[DEBUG] ❌ Error sending new business owner notification email:',
            emailError,
          );
          throw emailError;
        }
      }

      console.log('[DEBUG] 🎉 inviteSubcontractor completed successfully');
      res.status(201).json(subcontractor);
    } catch (error) {
      console.error('[DEBUG] ❌ Error in inviteSubcontractor:', error);
      res.status(500).json({ message: 'Server error', error });
    }
  },

  async getByInviteKey(req: Request, res: Response): Promise<any> {
    try {
      const { inviteKey } = req.params;
      const subcontractor = await Subcontractor.findOne({ inviteKey }).populate(
        'createdBy',
      ); // Only populate valid reference fields

      if (!subcontractor) {
        return res.status(404).json({ message: 'Invalid invite key' });
      }

      res.json(subcontractor);
    } catch (error) {
      res.status(500).json({ message: 'Server error', error });
    }
  },

  async acceptInvite(req: Request, res: Response): Promise<any> {
    try {
      const { inviteKey } = req.params;
      const updates = req.body;

      const subcontractor = await Subcontractor.findOneAndUpdate(
        { inviteKey },
        { ...updates, status: 'active', inviteKey: null },
        { new: true },
      );

      if (!subcontractor) {
        return res.status(404).json({ message: 'Invalid invite key' });
      }

      res.json(subcontractor);
    } catch (error) {
      res.status(500).json({ message: 'Server error', error });
    }
  },

  // Standard CRUD operations
  async updateSubcontractor(req: Request, res: Response): Promise<any> {
    try {
      let { _id, createdBy, createdAt, updatedAt, ...rest } = req.body;
      const subcontractor = await Subcontractor.findByIdAndUpdate(
        req.params.id,
        { ...rest, status: 'active' },
        { new: true },
      );
      res.json(subcontractor);
    } catch (error) {
      res.status(500).json({ message: 'Server error', error });
    }
  },
  async setSubcontractorPasswordByInviteKey(
    req: Request,
    res: Response,
  ): Promise<any> {
    try {
      const { password } = req.body;
      if (!password) {
        return res.status(400).json({ message: 'Password is required' });
      }

      const subcontractor = await Subcontractor.findOne({
        inviteKey: req.params.inviteKey,
      }).populate('createdBy'); // Only populate valid reference fields

      if (!subcontractor) {
        return res.status(404).json({ message: 'Subcontractor not found' });
      }
      if (subcontractor.isPasswordSet) {
        return res.status(400).json({ message: 'Password already set' });
      }

      const updatedSubcontractor = await Subcontractor.findOneAndUpdate(
        { inviteKey: req.params.inviteKey },
        { password: password, isPasswordSet: true }, // Pre-save hook will hash the password
        { new: true },
      ).populate('createdBy'); // Only populate valid reference fields

      // Get project information using the new SubcontractorProjectAccess relationship
      const projectAccess = await SubcontractorProjectAccess.findOne({
        subcontractor: subcontractor._id,
        status: 'active',
      }).populate('project');

      const projectName = projectAccess?.project
        ? (projectAccess.project as any).name
        : 'Your Project';
      const clientName = (subcontractor as any).createdBy
        ? `${(subcontractor as any).createdBy.firstName} ${(subcontractor as any).createdBy.lastName}`.trim()
        : undefined;

      await sendSubcontractorLoginReadyEmail(
        subcontractor.email,
        subcontractor.fullName || subcontractor.email.split('@')[0],
        projectName,
        clientName,
      );

      res.json(updatedSubcontractor);
    } catch (error) {
      res.status(500).json({ message: 'Server error', error });
    }
  },

  // Subcontractor login
  async subcontractorLogin(req: Request, res: Response): Promise<any> {
    try {
      const { email, password } = req.body;

      // Find the subcontractor
      const subcontractor = await Subcontractor.findOne({ email }).populate(
        'createdBy',
      ); // Only populate valid reference fields

      if (!subcontractor) {
        return res.status(400).json({ message: 'Invalid credentials' });
      }

      // Check if password is set
      if (!subcontractor.isPasswordSet || !subcontractor.password) {
        return res.status(400).json({
          message:
            'Password not set. Please check your email for setup instructions.',
          passwordNotSet: true,
        });
      }

      // Check password
      const isMatch = await bcrypt.compare(password, subcontractor.password);
      if (!isMatch) {
        return res.status(400).json({ message: 'Invalid credentials' });
      }

      // Generate token
      const token = jwt.sign(
        {
          subcontractorId: subcontractor._id,
        },
        config.jwtSecret!,
        { expiresIn: '1d' },
      );

      // Format response data similar to accountant login
      // Cast to any to access legacy fields for backward compatibility
      const legacySubcontractor = subcontractor as any;
      const responseData = {
        id: subcontractor._id,
        email: subcontractor.email,
        fullName: subcontractor.fullName,
        businessName: subcontractor.businessName,
        project: legacySubcontractor.project,
        createdBy: subcontractor.createdBy,
      };

      res.json({
        token,
        subcontractor: responseData,
      });
    } catch (error) {
      console.error('Error during subcontractor login:', error);
      res.status(500).json({ message: 'Server error' });
    }
  },

  async updateSubcontractorByInviteKey(
    req: Request,
    res: Response,
  ): Promise<any> {
    try {
      let { _id, project, createdBy, createdAt, updatedAt, ...rest } = req.body;
      const subcontractor = await Subcontractor.findOneAndUpdate(
        { inviteKey: req.params.inviteKey },
        { ...rest, status: 'active' },
        { new: true },
      );
      res.json(subcontractor);
    } catch (error) {
      res.status(500).json({ message: 'Server error', error });
    }
  },

  async getSubcontractors(req: Request, res: Response): Promise<any> {
    try {
      // Use the new SubcontractorProjectAccess model to find subcontractors for a project
      const projectAccesses = await SubcontractorProjectAccess.find({
        project: req.params.projectId,
        status: 'active',
      })
        .populate({
          path: 'subcontractor',
          match: { deleted: { $ne: true } }, // Only include non-deleted subcontractors
        })
        .populate('project')
        .populate('user');

      // Filter out any null subcontractors (in case they were deleted)
      const validAccesses = projectAccesses.filter(
        (access) => access.subcontractor,
      );

      // Transform the data to match the expected format
      const subcontractors = validAccesses.map((access) => ({
        ...(access.subcontractor as any).toObject(),
        projectAccess: {
          id: access._id,
          accessLevel: access.accessLevel,
          role: access.role,
          paymentTerms: access.paymentTerms,
          startDate: access.startDate,
          endDate: access.endDate,
        },
      }));

      res.json(subcontractors);
    } catch (error) {
      console.error('Error fetching subcontractors:', error);
      res.status(500).json({ message: 'Server error', error });
    }
  },

  async getAllSubcontractors(req: Request, res: Response): Promise<any> {
    try {
      console.log('[getAllSubcontractors] Starting...');
      console.log('[getAllSubcontractors] User ID:', req.user?.userId);

      // NEW: Use the unified UserRoles system instead of SubcontractorProjectAccess
      const { UserRoles, UserRoleType } = await import('../models/UserRoles');

      const subcontractorRoles = await UserRoles.find({
        businessOwner: req.user?.userId, // Find all subcontractor roles for this business owner
        roleType: UserRoleType.SUBCONTRACTOR,
        deleted: false,
        status: { $in: ['invited', 'active'] },
      })
        .populate('user', 'firstName lastName email')
        .populate('businessOwner', 'firstName lastName businessName')
        .lean();

      console.log(
        '[getAllSubcontractors] Found',
        subcontractorRoles.length,
        'subcontractor roles',
      );

      // Transform UserRoles data to match the expected frontend format
      const subcontractors = subcontractorRoles.map((role) => {
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
          status: role.status,
          roleType: role.roleType,
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
          // For backward compatibility with frontend expectations
          isPasswordSet: role.status === 'active',
          deleted: false,
          createdAt: role.createdAt,
          updatedAt: role.updatedAt,
        };
      });

      console.log(
        '[getAllSubcontractors] Transformed subcontractors:',
        subcontractors.map((s) => ({
          email: s.email,
          fullName: s.fullName,
          status: s.status,
          accessLevel: s.accessLevel,
        })),
      );

      res.json(subcontractors);
    } catch (error) {
      console.error('[getAllSubcontractors] Error:', error);
      res.status(500).json({ message: 'Server error', error: error.message });
    }
  },

  async getSubcontractorById(req: Request, res: Response): Promise<any> {
    try {
      const subcontractor = await Subcontractor.findById(
        req?.params?.id,
      ).populate('createdBy'); // Only populate valid reference fields
      if (!subcontractor) {
        return res.status(404).json({ message: 'Subcontractor not found' });
      }
      res.json(subcontractor);
    } catch (error) {
      res.status(500).json({ message: 'Server error', error });
    }
  },

  async deleteSubcontractor(req: Request, res: Response): Promise<any> {
    try {
      console.log('\n🗑️ [DEBUG] deleteSubcontractor called');
      console.log('[DEBUG] Subcontractor ID:', req.params.id);
      console.log('[DEBUG] User ID:', req.user?.userId);
      console.log(
        '[DEBUG] Call stack origin:',
        new Error().stack?.split('\n')[2],
      );

      const subcontractor = await Subcontractor.findById(
        req.params.id,
      ).populate('createdBy'); // Only populate valid reference fields

      if (!subcontractor) {
        console.log('[DEBUG] ❌ Subcontractor not found');
        return res.status(404).json({ message: 'Subcontractor not found' });
      }

      console.log('[DEBUG] 🔍 Subcontractor details:', {
        id: subcontractor._id,
        email: subcontractor.email,
        fullName: subcontractor.fullName,
        hasPassword: !!subcontractor.password,
        status: subcontractor.status,
        deleted: subcontractor.deleted,
      });

      // Get client info for the removal email
      const createdBy = subcontractor.createdBy as any;
      const clientName = createdBy
        ? `${createdBy.firstName} ${createdBy.lastName}`.trim()
        : undefined;

      console.log('[DEBUG] 📧 Sending removal email to:', subcontractor.email);

      // Send removal email - note: no project info since this is a general removal
      const props: SubcontractorRemovedProps = {
        subcontractorName:
          subcontractor.fullName || subcontractor.email.split('@')[0],
        projectName: 'Project', // Generic since subcontractor can be in multiple projects
        clientName,
        senderName: clientName || 'Project Manager',
      };

      const { subject, html } = await reactEmailService.renderTemplate(
        'subcontractor-removed',
        props,
      );

      await sendEmail({
        to: subcontractor.email,
        subject,
        html,
      });

      console.log('[DEBUG] ✅ Removal email sent successfully');

      await Subcontractor.findByIdAndUpdate(req.params.id, { deleted: true });

      console.log('[DEBUG] ✅ Subcontractor marked as deleted');

      res.json({ message: 'Subcontractor removed successfully' });
    } catch (error) {
      console.error('[DEBUG] ❌ Error deleting subcontractor:', error);
      res.status(500).json({ message: 'Server error', error });
    }
  },
};
