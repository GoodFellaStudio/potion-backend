import { Request, Response } from 'express';
import { User } from '../models/User';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { sendEmail } from '../services/emailService';
import { Tokens } from '../types';
import { config } from '../config/config';
import { getSignedDownloadUrl } from '../services/storageService';

import crypto from 'crypto';
import { reactEmailService } from '../services/reactEmailService';
import type { PasswordSetupProps } from '../templates/react-email/password-setup';
import type { PasswordResetProps } from '../templates/react-email/password-reset';

// Role-specific password reset email function
const sendPasswordResetEmail = async (
  email: string,
  firstName: string,
  token: string,
  roleType: 'user' | 'accountant' | 'subcontractor',
) => {
  try {
    const resetUrl = `${config.frontURL}/setup-password/${token}`;

    const props: PasswordResetProps = {
      firstName,
      resetUrl,
      tokenExpiry: '48 hours',
      roleType,
    };

    const { subject, html } = await reactEmailService.renderTemplate(
      'password-reset',
      props,
    );

    await sendEmail({
      to: email,
      subject,
      html,
    });
  } catch (templateError) {
    console.error(
      'Password reset template error, using fallback:',
      templateError,
    );

    const resetUrl = `${config.frontURL}/setup-password/${token}`;
    const roleContext = {
      user: 'Reset your Potion business account password',
      accountant: 'Reset your Potion accountant password',
      subcontractor: 'Reset your Potion password',
    };

    // Simple HTML fallback
    await sendEmail({
      to: email,
      subject: roleContext[roleType],
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
          <h1 style="color: #1f2937;">Hi ${firstName},</h1>
          <p>We received a request to reset your password for your Potion account.</p>
          <div style="margin: 30px 0; text-align: center;">
            <a href="${resetUrl}" style="background: #1EC64C; color: white; padding: 14px 28px; text-decoration: none; border-radius: 8px; display: inline-block; font-weight: 600;">Reset My Password</a>
          </div>
          <p><strong>This link expires in 48 hours</strong> - please reset your password soon to avoid having to request a new link.</p>
          <p style="color: #6b7280; font-size: 14px; margin-top: 30px;">If you didn't request this password reset, you can safely ignore this email. Your account remains secure.</p>
        </div>
      `,
    });
  }
};
import { Accountant, UserAccountantAccess } from '../models/AccountantAccess';
import { Subcontractor } from '../models/Subcontractor';
import { SubcontractorProjectAccess } from '../models/SubcontractorProjectAccess';
import { Transaction } from '../models/Transaction';
import { PlaidItem } from '../models/PlaidItem';
import { UserRoles } from '../models/UserRoles';
import { UserGlobalValues } from '../models/UserGlobalValues';
import { Chat } from '../models/Chat';
import { Report } from '../models/Report';
import { Invoice } from '../models/Invoice';
import { Client } from '../models/Client';
import { Project } from '../models/Project';
import { Message } from '../models/Message';

export const generateTokens = (userId: string): Tokens => {
  const accessToken = jwt.sign({ userId }, config.jwtSecret!, {
    expiresIn: '1d',
  });

  const refreshToken = jwt.sign({ userId }, config.jwtSecret!, {
    expiresIn: '7d',
  });

  return { accessToken, refreshToken };
};

export const setupPassword = async (
  req: Request,
  res: Response,
): Promise<any> => {
  try {
    const { token } = req.params;
    const { password } = req.body;

    // Validate input
    if (!password || password.length < 8) {
      return res
        .status(400)
        .json({ message: 'Password must be at least 8 characters long' });
    }

    // Check all user types for the password setup token
    let foundUser = null;
    let userType = null;

    // Try to find a regular user first
    const user = await User.findOne({
      passwordSetupToken: token,
      passwordSetupTokenExpiry: { $gt: new Date() },
    });

    if (user) {
      foundUser = user;
      userType = 'user';
    } else {
      // Check accountants (both invitation and password reset tokens)
      const accountantAccess = await UserAccountantAccess.findOne({
        inviteToken: token,
        inviteTokenExpiry: { $gt: new Date() },
      }).populate('accountant');

      if (accountantAccess && accountantAccess.accountant) {
        foundUser = accountantAccess.accountant;
        userType = 'accountant';
      } else {
        // Check for accountant password reset tokens (stored directly in accountant model)
        const accountantReset = await Accountant.findOne({
          passwordResetToken: token,
          passwordResetTokenExpiry: { $gt: new Date() },
        });

        if (accountantReset) {
          foundUser = accountantReset;
          userType = 'accountant';
        } else {
          // Check subcontractors for password reset or setup tokens
          const subcontractor = await Subcontractor.findOne({
            $or: [
              {
                passwordResetToken: token,
                passwordResetTokenExpiry: { $gt: new Date() },
              },
              {
                passwordSetupToken: token,
                passwordSetupTokenExpiry: { $gt: new Date() },
              },
            ],
          });

          if (subcontractor) {
            foundUser = subcontractor;
            userType = 'subcontractor';
          } else {
            console.log(
              'No valid token found for user, accountant, or subcontractor in setupPassword',
            );
          }
        }
      }
    }

    if (!foundUser) {
      return res.status(400).json({
        message:
          'Invalid or expired token. Please request a new password setup link.',
        expired: true,
      });
    }

    // Set password and clear setup token based on user type
    if (userType === 'subcontractor') {
      // For subcontractors, set password directly - pre-save hook will hash it
      foundUser.password = password;
    } else {
      // For users and accountants, hash manually (they have their own hashing logic)
      const hashedPassword = await bcrypt.hash(password, 12);
      foundUser.password = hashedPassword;
    }

    if (userType === 'user') {
      foundUser.isPasswordSet = true;
      foundUser.passwordSetupToken = undefined;
      foundUser.passwordSetupTokenExpiry = undefined;

      // Generate tokens for regular users
      const tokens = generateTokens(foundUser._id.toString());
      foundUser.refreshToken = tokens.refreshToken;
      await foundUser.save();

      // Set refresh token cookie
      res.cookie('refreshToken', tokens.refreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
      });

      // Get profile picture URL if exists
      let uri = foundUser?.profilePicture?.fileName
        ? await getSignedDownloadUrl(
            foundUser!.profilePicture!.fileName || '',
            foundUser!.profilePicture!.fileType || '',
          )
        : '';

      res.json({
        accessToken: tokens.accessToken,
        user: {
          firstName: foundUser.firstName,
          lastName: foundUser.lastName,
          email: foundUser.email,
          profilePicture: uri,
          subscription: foundUser.subscription?.status || null,
        },
        message: 'Password set successfully',
      });
    } else {
      // Handle token cleanup based on user type
      if (userType === 'accountant') {
        // Check if it's an invitation token (UserAccountantAccess) or password reset token (Accountant)
        const accountantAccessRecord = await UserAccountantAccess.findOne({
          inviteToken: token,
        });

        if (accountantAccessRecord) {
          // It's an invitation token - clear from UserAccountantAccess
          accountantAccessRecord.inviteToken = undefined;
          accountantAccessRecord.inviteTokenExpiry = undefined;
          await accountantAccessRecord.save();
        } else {
          // It's a password reset token - clear from Accountant model
          foundUser.passwordResetToken = undefined;
          foundUser.passwordResetTokenExpiry = undefined;
        }
        await foundUser.save();
      } else if (userType === 'subcontractor') {
        // For subcontractors, clear both password setup and reset tokens
        foundUser.passwordSetupToken = undefined;
        foundUser.passwordSetupTokenExpiry = undefined;
        foundUser.passwordResetToken = undefined;
        foundUser.passwordResetTokenExpiry = undefined;
        foundUser.isPasswordSet = true;
        await foundUser.save();
      }

      const userData =
        userType === 'accountant'
          ? {
              firstName: foundUser.name ? foundUser.name.split(' ')[0] : '',
              lastName: foundUser.name
                ? foundUser.name.split(' ').slice(1).join(' ')
                : '',
              email: foundUser.email,
              name: foundUser.name,
            }
          : userType === 'subcontractor'
            ? {
                firstName: foundUser.fullName
                  ? foundUser.fullName.split(' ')[0]
                  : '',
                lastName: foundUser.fullName
                  ? foundUser.fullName.split(' ').slice(1).join(' ')
                  : '',
                email: foundUser.email,
                fullName: foundUser.fullName,
              }
            : {
                firstName: foundUser.fullName
                  ? foundUser.fullName.split(' ')[0]
                  : '',
                lastName: foundUser.fullName
                  ? foundUser.fullName.split(' ').slice(1).join(' ')
                  : '',
                email: foundUser.email,
                fullName: foundUser.fullName,
              };

      res.json({
        user: userData,
        userType: userType,
        message: 'Password set successfully. You can now login.',
      });
    }
  } catch (error) {
    console.error('Setup password error:', error);
    res.status(500).json({ message: 'Server error' });
  }
};

// Check if token is valid (for frontend validation)
export const validatePasswordToken = async (
  req: Request,
  res: Response,
): Promise<any> => {
  try {
    const { token } = req.params;

    // Check all user types for the password setup token
    let foundUser = null;
    let userType = null;

    // Try to find a regular user first
    const user = await User.findOne({
      passwordSetupToken: token,
      passwordSetupTokenExpiry: { $gt: new Date() },
    }).select('firstName lastName email isPasswordSet');

    if (user) {
      foundUser = user;
      userType = 'user';
    } else {
      // Check accountants - first check if token exists at all (expired or not)
      const accountantAccessAny = await UserAccountantAccess.findOne({
        inviteToken: token,
      })
        .populate('accountant', 'name email password')
        .select('inviteTokenExpiry');

      if (accountantAccessAny) {
      }

      // Check accountants with valid (non-expired) tokens
      const accountantAccess = await UserAccountantAccess.findOne({
        inviteToken: token,
        inviteTokenExpiry: { $gt: new Date() },
      }).populate('accountant', 'name email password');

      if (accountantAccess && accountantAccess.accountant) {
        console.log('Found valid accountant token');
        foundUser = accountantAccess.accountant;
        userType = 'accountant';
      } else {
        // Check subcontractors for password setup or reset tokens
        const subcontractor = await Subcontractor.findOne({
          $or: [
            {
              passwordSetupToken: token,
              passwordSetupTokenExpiry: { $gt: new Date() },
            },
            {
              passwordResetToken: token,
              passwordResetTokenExpiry: { $gt: new Date() },
            },
          ],
        }).select('fullName email password isPasswordSet');

        if (subcontractor) {
          console.log('Found valid subcontractor token');
          foundUser = subcontractor;
          userType = 'subcontractor';
        } else {
          console.log(
            'No valid token found for user, accountant, or subcontractor',
          );
        }
      }
    }

    if (!foundUser) {
      console.log('No valid token found');
      return res.status(400).json({
        message: 'Invalid or expired token',
        expired: true,
      });
    }

    // Format user data based on type
    const userData =
      userType === 'user'
        ? {
            firstName: foundUser.firstName,
            lastName: foundUser.lastName,
            email: foundUser.email,
          }
        : userType === 'accountant'
          ? {
              firstName: foundUser.name ? foundUser.name.split(' ')[0] : '',
              lastName: foundUser.name
                ? foundUser.name.split(' ').slice(1).join(' ')
                : '',
              email: foundUser.email,
            }
          : userType === 'subcontractor'
            ? {
                firstName: foundUser.fullName
                  ? foundUser.fullName.split(' ')[0]
                  : '',
                lastName: foundUser.fullName
                  ? foundUser.fullName.split(' ').slice(1).join(' ')
                  : '',
                email: foundUser.email,
              }
            : {
                firstName: foundUser.fullName
                  ? foundUser.fullName.split(' ')[0]
                  : '',
                lastName: foundUser.fullName
                  ? foundUser.fullName.split(' ').slice(1).join(' ')
                  : '',
                email: foundUser.email,
              };

    res.json({
      valid: true,
      isPasswordReset: !!foundUser.password, // true if user already has password (reset), false if new setup
      userType: userType,
      user: userData,
    });
  } catch (error) {
    console.error('Validate password token error:', error);
    res.status(500).json({ message: 'Server error' });
  }
};

// Resend password setup email
export const resendPasswordSetup = async (
  req: Request,
  res: Response,
): Promise<any> => {
  try {
    const { email } = req.body;

    const user = await User.findOne({ email });

    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Determine if this is password setup or reset
    const isPasswordReset = user.isPasswordSet && user.password;

    // Generate new token
    const token = crypto.randomBytes(32).toString('hex');
    const expiry = new Date(Date.now() + 48 * 60 * 60 * 1000); // 48 hours

    user.passwordSetupToken = token;
    user.passwordSetupTokenExpiry = expiry;
    await user.save();

    // Send new setup/reset email using React Email
    try {
      const setupUrl = `${config.frontURL}/setup-password/${token}`;

      const props: PasswordSetupProps = {
        firstName: user.firstName,
        setupUrl,
        trialDays: 7,
        monthlyPrice: 29,
        tokenExpiry: '48 hours',
      };

      const { subject, html } = await reactEmailService.renderTemplate(
        'password-setup',
        props,
      );

      await sendEmail({
        to: email,
        subject,
        html,
      });
    } catch (templateError) {
      // Fallback to React Email fallback template
      console.error('Template error, using fallback:', templateError);
      const setupUrl = `${config.frontURL}/setup-password/${token}`;
      const actionText = isPasswordReset ? 'Reset Password' : 'Set Up Password';
      const subjectText = isPasswordReset
        ? 'Reset your Potion password'
        : 'Set up your Potion password';
      const messageBody = isPasswordReset
        ? "Here's your password reset link:"
        : "Here's your password setup link:";

      try {
        const fallbackProps = {
          firstName: user.firstName,
          subject: subjectText,
          actionUrl: setupUrl,
          actionText,
          messageBody,
          tokenExpiry: '48 hours',
        };

        const { subject: fallbackSubject, html: fallbackHtml } =
          await reactEmailService.renderTemplate(
            'email-fallback',
            fallbackProps,
          );

        await sendEmail({
          to: email,
          subject: fallbackSubject,
          html: fallbackHtml,
        });
      } catch (fallbackError) {
        console.error('Fallback template also failed', fallbackError);
      }
    }

    res.json({
      message: isPasswordReset
        ? 'Password reset email sent'
        : 'Password setup email sent',
    });
  } catch (error) {
    console.error('Resend password setup error:', error);
    res.status(500).json({ message: 'Server error' });
  }
};

// Google authentication check and login
export const googleCheck = async (
  req: Request,
  res: Response,
): Promise<any> => {
  try {
    const { email, googleId, name } = req.body;

    if (!email || !googleId) {
      return res
        .status(400)
        .json({ message: 'Email and Google ID are required' });
    }

    // Check if user exists (by email or googleId)
    let user = await User.findOne({
      $or: [{ email }, { googleId }],
    });

    if (user) {
      // User exists - log them in

      // If user exists but doesn't have Google auth set up, link the Google account
      if (!user.googleId) {
        user.googleId = googleId;
        // Keep the original authProvider - don't change it
        // This allows users to have both email/password AND Google auth
        await user.save();
      }

      // Generate tokens for existing user
      const tokens = generateTokens(user._id.toString());

      // Update refresh token
      user.refreshToken = tokens.refreshToken;
      await user.save();

      // Get profile picture URL if available
      let uri = user?.profilePicture?.fileName
        ? await getSignedDownloadUrl(
            user.profilePicture.fileName,
            user.profilePicture.fileType || '',
          )
        : '';

      res.json({
        userExists: true,
        accessToken: tokens.accessToken,
        user: {
          firstName: user.firstName,
          lastName: user.lastName,
          email: user.email,
          profilePicture: uri,
          subscription: user.subscription?.status || null,
        },
      });
    } else {
      // User doesn't exist - they need to sign up
      res.json({
        userExists: false,
        message: 'User needs to complete signup',
      });
    }
  } catch (error) {
    console.error('Google check error:', error);
    res.status(500).json({ message: 'Server error' });
  }
};

// Update login function to handle password setup scenarios
export const login = async (req: Request, res: Response): Promise<any> => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }

    // Check if user actually has a password
    if (!user.password || user.password.length === 0) {
      return res.status(400).json({
        message:
          'Password not set. Please check your email for setup instructions.',
        passwordNotSet: true,
        canResend: true,
      });
    }

    // If user has password but flag is wrong, fix the flag (supports current users - with old login flow)
    if (!user.isPasswordSet && user.password && user.password.length > 0) {
      user.isPasswordSet = true;
      await user.save();
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }

    const tokens = generateTokens(user._id.toString());

    // Save refresh token to user document
    user.refreshToken = tokens.refreshToken;
    await user.save();

    // Set refresh token as HTTP-only cookie
    res.cookie('refreshToken', tokens.refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    });

    let uri = user?.profilePicture?.fileName
      ? await getSignedDownloadUrl(
          user!.profilePicture!.fileName || '',
          user!.profilePicture!.fileType || '',
        )
      : '';

    // Check subscription status for user feedback
    const subscriptionInfo = {
      status: user.subscription?.status || null,
      currentPeriodEnd: user.subscription?.currentPeriodEnd || null,
      trialEndsAt: user.subscription?.trialEndsAt || null,
      requiresSubscription: false,
      accessDeniedReason: null,
    };

    // Evaluate subscription access for user awareness
    if (user.subscription) {
      const currentDate = new Date();

      // Check if subscription has ended
      if (user.subscription.status === 'canceled') {
        if (
          user.subscription.currentPeriodEnd &&
          new Date(user.subscription.currentPeriodEnd) <= currentDate
        ) {
          subscriptionInfo.requiresSubscription = true;
          subscriptionInfo.accessDeniedReason =
            'Your subscription has ended. Please resubscribe to continue using the app.';
        }
      } else if (user.subscription.status === 'trialing') {
        if (
          user.subscription.trialEndsAt &&
          new Date(user.subscription.trialEndsAt) <= currentDate
        ) {
          subscriptionInfo.requiresSubscription = true;
          subscriptionInfo.accessDeniedReason =
            'Your trial period has ended. Please subscribe to continue using the app.';
        }
      } else if (
        ['past_due', 'unpaid', 'incomplete'].includes(user.subscription.status)
      ) {
        subscriptionInfo.requiresSubscription = true;
        subscriptionInfo.accessDeniedReason =
          'There is an issue with your subscription. Please update your payment method.';
      }
    }

    res.json({
      accessToken: tokens.accessToken,
      user: {
        firstName: user.firstName,
        lastName: user.lastName,
        email: user.email,
        profilePicture: uri,
        subscription: subscriptionInfo,
        id: user._id,
      },
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ message: 'Server error', error });
  }
};

// refresh token endpoint
export const refreshToken = async (
  req: Request,
  res: Response,
): Promise<any> => {
  try {
    const refreshToken = req.cookies.refreshToken;

    if (!refreshToken) {
      return res.status(401).json({ message: 'Refresh token not found' });
    }

    // Verify refresh token
    const decoded = jwt.verify(
      refreshToken,
      config.jwtSecret!,
    ) as jwt.JwtPayload;

    // Find user and check if refresh token matches
    const user = await User.findById(decoded.userId);
    if (!user || user.refreshToken !== refreshToken) {
      return res.status(401).json({ message: 'Invalid refresh token' });
    }

    // Generate new tokens
    const tokens = generateTokens(user._id.toString());

    // Update refresh token in database
    user.refreshToken = tokens.refreshToken;
    await user.save();

    // Set new refresh token as HTTP-only cookie
    res.cookie('refreshToken', tokens.refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    });

    res.json({ accessToken: tokens.accessToken });
  } catch (error) {
    res.status(401).json({ message: 'Invalid refresh token' });
  }
};

// Add logout endpoint
export const logout = async (req: Request, res: Response): Promise<any> => {
  try {
    const refreshToken = req.cookies.refreshToken;

    if (refreshToken) {
      // Find user and clear refresh token
      await User.findOneAndUpdate(
        { refreshToken },
        { $set: { refreshToken: null } },
      );
    }

    // Clear refresh token cookie
    res.clearCookie('refreshToken');

    res.json({ message: 'Logged out successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
};

// Unified forgot password for all user types
export const unifiedForgotPassword = async (
  req: Request,
  res: Response,
): Promise<any> => {
  try {
    const { email, roleType } = req.body;

    if (!email) {
      return res.status(400).json({ message: 'Email is required' });
    }

    let foundUser = null;
    let userType = null;
    let userName = '';

    switch (roleType) {
      case 'business_owner':
        const businessOwner = await User.findOne({
          email: email.toLowerCase(),
        });
        if (businessOwner) {
          foundUser = businessOwner;
          userType = 'business_owner';
          userName = businessOwner.firstName;

          // Generate password reset token
          const token = crypto.randomBytes(32).toString('hex');
          const expiry = new Date(Date.now() + 48 * 60 * 60 * 1000); // 48 hours

          businessOwner.passwordSetupToken = token;
          businessOwner.passwordSetupTokenExpiry = expiry;
          await businessOwner.save();

          // Send password reset email
          await sendPasswordResetEmail(email, userName, token, 'user');
        }
        break;

      case 'user':
        const user = await User.findOne({ email: email.toLowerCase() });
        if (user) {
          foundUser = user;
          userType = 'user';
          userName = user.firstName;

          // Generate password reset token
          const token = crypto.randomBytes(32).toString('hex');
          const expiry = new Date(Date.now() + 48 * 60 * 60 * 1000); // 48 hours

          user.passwordSetupToken = token;
          user.passwordSetupTokenExpiry = expiry;
          await user.save();

          // Send password reset email
          await sendPasswordResetEmail(email, userName, token, 'user');
        }
        break;

      case 'accountant':
        const accountant = await Accountant.findOne({
          email: email.toLowerCase(),
        });
        if (accountant) {
          foundUser = accountant;
          userType = 'accountant';
          userName = accountant.name.split(' ')[0] || accountant.name;

          // For accountants, add reset token directly to accountant record
          const token = crypto.randomBytes(32).toString('hex');
          const expiry = new Date(Date.now() + 48 * 60 * 60 * 1000); // 48 hours

          // Add reset token directly to accountant
          accountant.passwordResetToken = token;
          accountant.passwordResetTokenExpiry = expiry;
          await accountant.save();

          await sendPasswordResetEmail(email, userName, token, 'accountant');
        }
        break;

      case 'subcontractor':
        const subcontractor = await Subcontractor.findOne({
          email: email.toLowerCase(),
        });
        if (subcontractor) {
          foundUser = subcontractor;
          userType = 'subcontractor';
          userName =
            subcontractor.fullName?.split(' ')[0] ||
            subcontractor.email.split('@')[0];

          // Generate password reset token for subcontractor
          const token = crypto.randomBytes(32).toString('hex');
          const expiry = new Date(Date.now() + 48 * 60 * 60 * 1000); // 48 hours

          // Store reset token on subcontractor directly
          subcontractor.passwordResetToken = token;
          subcontractor.passwordResetTokenExpiry = expiry;
          await subcontractor.save();

          await sendPasswordResetEmail(email, userName, token, 'subcontractor');
        }
        break;

      default:
        return res.status(400).json({ message: 'Invalid role type' });
    }

    if (!foundUser) {
      return res.status(404).json({
        message: `No ${roleType} account found with this email address`,
      });
    }

    res.json({
      message: 'Password reset email sent',
      roleType: userType,
    });
  } catch (error) {
    console.error('Unified forgot password error:', error);
    res.status(500).json({ message: 'Server error' });
  }
};

// Legacy forgot password (keep for backward compatibility)
export const forgotPassword = async (
  req: Request,
  res: Response,
): Promise<any> => {
  try {
    const { email } = req.body;

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Generate password setup token (same system as signup)
    const token = crypto.randomBytes(32).toString('hex');
    const expiry = new Date(Date.now() + 48 * 60 * 60 * 1000); // 48 hours

    // Save token to user document (reuse password setup fields)
    user.passwordSetupToken = token;
    user.passwordSetupTokenExpiry = expiry;
    await user.save();

    // Send password reset email
    await sendPasswordResetEmail(email, user.firstName, token, 'user');

    res.json({ message: 'Password reset email sent' });
  } catch (error) {
    console.error('Forgot password error:', error);
    res.status(500).json({ message: 'Server error' });
  }
};

export const verifyOTp = async (req: Request, res: Response): Promise<any> => {
  const { email, otp } = req.body;

  const user = await User.findOne({
    email,
    resetPasswordOTP: otp,
    resetPasswordOTPExpiry: { $gt: new Date() },
  });

  if (!user) {
    return res.status(400).json({ message: 'Invalid or expired OTP' });
  }

  return res.status(200).json({ message: 'OTP verified' });
};

export const verifyOTPAndResetPassword = async (
  req: Request,
  res: Response,
): Promise<any> => {
  try {
    const { email, otp, newPassword } = req.body;

    const user = await User.findOne({
      email,
      resetPasswordOTP: otp,
      resetPasswordOTPExpiry: { $gt: new Date() },
    });

    if (!user) {
      return res.status(400).json({ message: 'Invalid or expired OTP' });
    }

    // Update password and clear OTP fields
    user.password = newPassword;
    user.resetPasswordOTP = '';
    user.resetPasswordOTPExpiry = new Date();
    await user.save();

    res.json({ message: 'Password successfully reset' });
  } catch (error) {
    console.error('Reset password error:', error);
    res.status(500).json({ message: 'Server error' });
  }
};

export const updateUser = async (req: Request, res: Response): Promise<any> => {
  try {
    const userId = req.user?.userId; // Assuming user ID is passed as a URL parameter
    const {
      password,
      id,
      resetPasswordOTP,
      resetPasswordOTPExpiry,
      email,
      profilePicture,
      ...updates
    } = req.body;
    // Find the user by ID and update their information
    const user = await User.findByIdAndUpdate(userId, updates, { new: true });

    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    let uri = user?.profilePicture?.fileName
      ? await getSignedDownloadUrl(
          user!.profilePicture!.fileName || '',
          user!.profilePicture!.fileType || '',
        )
      : '';

    res.json({
      message: 'User updated successfully',
      user: {
        ...user.toObject(),
        profilePicture: uri,
      },
    });
  } catch (error) {
    console.error('Update user error:', error);
    res.status(500).json({ message: 'Server error', error });
  }
};

export const getUser = async (req: Request, res: Response): Promise<any> => {
  try {
    const userId = req.user?.userId;

    // Find the user by ID and update their information
    const user = await User.findById(userId);

    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    let uri = user?.profilePicture?.fileName
      ? await getSignedDownloadUrl(
          user!.profilePicture!.fileName || '',
          user!.profilePicture!.fileType || '',
        )
      : '';

    // Add subscription info to user data
    const subscriptionInfo = user.subscription
      ? {
          status: user.subscription.status,
          trialEndsAt: user.subscription.trialEndsAt,
          currentPeriodEnd: user.subscription.currentPeriodEnd,
        }
      : null;

    res.json({
      message: 'User fetched successfully',
      user: {
        ...user.toObject(),
        profilePicture: uri,
        subscription: subscriptionInfo,
      },
    });
  } catch (error) {
    console.error('Get user error:', error);
    res.status(500).json({ message: 'Server error', error });
  }
};

export const deleteUser = async (req: Request, res: Response): Promise<any> => {
  try {
    const userId = req.user?.userId;
    console.log('Deleting user with ID:', userId);
    const user = await User.findById(userId);

    if (!user) {
      return res.status(404).json({
        message: 'User not found',
      });
    }
    const plaidItems = await PlaidItem.find({ userId: userId });
    console.log(plaidItems.length, 'Plaid items found for user');

    plaidItems?.map(async (item) => {
      item?.accounts?.map(async (account) => {
        await Transaction.deleteMany({
          bankAccount: account.accountId
        });
      });

      await PlaidItem.deleteOne({ _id: item._id });
    });

    UserRoles.deleteMany({ user: userId });
    UserGlobalValues.deleteMany({ user: userId });
    UserAccountantAccess.deleteMany({ user: userId });
    Chat.deleteMany({ createdBy: userId });
    SubcontractorProjectAccess.deleteMany({ user: userId });
    Subcontractor.deleteMany({ user: userId });
    Report.deleteMany({ userId });
    Invoice.deleteMany({ createdBy: userId });
    Client.deleteMany({ createdBy: userId });
    Project.deleteMany({ createdBy: userId });
    Message.deleteMany({ createdBy: userId });

    await User.deleteOne({ _id: userId });

    res.status(200).json({ message: 'User deleted' });
  } catch (error) {
    console.error('Delete user error:', error);
    res.status(500).json({ message: 'Server error', error });
  }
};

export const updateProfilePicture = async (
  req: Request & { filesInfo?: any[]; user?: { userId: string } },
  res: Response,
): Promise<any> => {
  try {
    const userId = req.user?.userId; // Assuming user ID is passed in the request

    const filesInfo: any = req.filesInfo;

    if (!filesInfo) {
      return res.status(400).json({ message: 'No file uploaded' });
    }

    // Update user profile picture URL in the database
    const user = await User.findById(userId);

    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    user.profilePicture = filesInfo[0];

    user.save();

    let uri = await getSignedDownloadUrl(
      filesInfo[0]?.fileName,
      filesInfo[0]?.fileType,
    );

    res.json({
      message: 'Profile picture updated successfully',
      user: {
        ...user.toObject(),
        profilePicture: uri,
      },
    });
  } catch (error) {
    console.error('Update profile picture error:', error);
    res.status(500).json({ message: 'Server error', error });
  }
};

/**
 * Unified Authentication - Check all available roles for an email
 */
export const checkAvailableRoles = async (req: Request, res: Response) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({
        error: 'Email is required',
      });
    }

    const availableRoles = [];

    // Check for regular user
    const user = await User.findOne({ email: email.toLowerCase() }).select(
      '+password',
    );
    if (user) {
      availableRoles.push({
        type: 'user',
        id: user._id,
        name: `${user.firstName} ${user.lastName}`.trim() || user.email,
        email: user.email,
        profilePicture: user.profilePicture,
        businessName: user.businessName,
        subscription: user.subscription,
        hasPassword: !!user.password,
      });
    }

    // Check for accountant
    const accountant = await Accountant.findOne({
      email: email.toLowerCase(),
    }).populate({
      path: 'userAccesses',
      populate: {
        path: 'user',
        select: 'firstName lastName email businessName profilePicture',
      },
    });
    if (accountant) {
      const accountantData = accountant as any;
      availableRoles.push({
        type: 'accountant',
        id: accountant._id,
        name: accountant.name || accountant.email,
        email: accountant.email,
        businessName: '', // Accountants don't have business names in this schema
        clientCount: accountantData.userAccesses?.length || 0,
        hasPassword: !!accountant.password,
      });
    }

    // Check for subcontractor (unified approach - one subcontractor per email)
    const subcontractor = await Subcontractor.findOne({
      email: email.toLowerCase(),
    });
    if (subcontractor) {
      // Get project count and business owner count for this subcontractor
      const projectAccesses = await SubcontractorProjectAccess.find({
        subcontractor: subcontractor._id,
        status: 'active',
      }).populate('user', 'firstName lastName businessName');

      const projectCount = projectAccesses.length;
      const businessOwners = projectAccesses.map((access: any) => ({
        id: access.user._id,
        name: `${access.user.firstName} ${access.user.lastName}`.trim(),
        businessName: access.user.businessName,
      }));

      availableRoles.push({
        type: 'subcontractor',
        id: subcontractor._id,
        name: subcontractor.fullName || subcontractor.email,
        email: subcontractor.email,
        businessName: subcontractor.businessName,
        projectCount,
        businessOwners, // Multiple business owners for unified subcontractor
        hasPassword: !!subcontractor.password,
      });
    }

    if (availableRoles.length === 0) {
      return res.status(404).json({
        error: 'No account found with this email address',
      });
    }

    res.json({
      success: true,
      email,
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
 * Unified Login - Authenticate with specific role
 */
export const unifiedLogin = async (req: Request, res: Response) => {
  try {
    const { email, password, roleType, roleId } = req.body;

    if (!email || !password || !roleType || !roleId) {
      return res.status(400).json({
        error: 'Email, password, role type, and role ID are required',
      });
    }

    let authenticatedUser = null;
    let token = null;
    let responseData = null;

    switch (roleType) {
      case 'user':
        // Regular user login
        const user = await User.findById(roleId).select('+password');
        if (!user || user.email.toLowerCase() !== email.toLowerCase()) {
          return res.status(401).json({ error: 'Invalid credentials' });
        }

        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
          return res.status(401).json({ error: 'Invalid credentials' });
        }

        token = jwt.sign(
          { userId: user._id, role: 'user' },
          process.env.JWT_SECRET as string,
          { expiresIn: '7d' },
        );

        responseData = {
          user: {
            id: user._id,
            firstName: user.firstName,
            lastName: user.lastName,
            email: user.email,
            role: 'user',
            profilePicture: user.profilePicture,
            businessName: user.businessName,
            subscription: user.subscription,
            // ... other user fields
            phoneNumber: user.phoneNumber || '',
            address: user.address || '',
            city: user.city || '',
            state: user.state || '',
            country: user.country || '',
            postalCode: user.postalCode || '',
          },
          accessToken: token,
        };
        break;

      case 'accountant':
        // Accountant login
        const accountant = await Accountant.findById(roleId).populate({
          path: 'userAccesses',
          populate: {
            path: 'user',
            select: 'firstName lastName email businessName profilePicture',
          },
        });

        if (
          !accountant ||
          accountant.email.toLowerCase() !== email.toLowerCase()
        ) {
          return res.status(401).json({ error: 'Invalid credentials' });
        }

        const isAccountantPasswordValid = await bcrypt.compare(
          password,
          accountant.password,
        );
        if (!isAccountantPasswordValid) {
          return res.status(401).json({ error: 'Invalid credentials' });
        }

        token = jwt.sign(
          { accountantId: accountant._id, role: 'accountant' },
          process.env.JWT_SECRET as string,
          { expiresIn: '7d' },
        );

        const accountantData = accountant as any;
        // Transform userAccesses to match expected clients format
        const clients =
          accountantData.userAccesses?.map((access: any) => ({
            userId: access.user._id,
            user: access.user,
            accessLevel: access.accessLevel,
            status: access.status,
          })) || [];

        responseData = {
          token,
          accountant: {
            id: accountant._id,
            name: accountant.name,
            email: accountant.email,
            businessName: '', // Accountants don't have business names in this schema
            clients: clients,
          },
        };
        break;

      case 'subcontractor':
        // Subcontractor login
        const subcontractor = await Subcontractor.findById(roleId).populate(
          'createdBy',
          'firstName lastName businessName',
        );

        if (
          !subcontractor ||
          subcontractor.email.toLowerCase() !== email.toLowerCase()
        ) {
          return res.status(401).json({ error: 'Invalid credentials' });
        }

        // Check if password is set
        if (!subcontractor.password) {
          return res.status(401).json({
            error:
              'Password not set. Please check your email for setup instructions.',
            passwordNotSet: true,
          });
        }

        const isSubcontractorPasswordValid = await bcrypt.compare(
          password,
          subcontractor.password,
        );
        if (!isSubcontractorPasswordValid) {
          return res.status(401).json({ error: 'Invalid credentials' });
        }

        token = jwt.sign(
          { subcontractorId: subcontractor._id, role: 'subcontractor' },
          process.env.JWT_SECRET as string,
          { expiresIn: '7d' },
        );

        responseData = {
          token,
          subcontractor: {
            id: subcontractor._id,
            fullName: subcontractor.fullName,
            email: subcontractor.email,
            businessName: subcontractor.businessName,
            createdBy: subcontractor.createdBy,
          },
        };
        break;

      default:
        return res.status(400).json({ error: 'Invalid role type' });
    }

    res.json({
      success: true,
      roleType,
      ...responseData,
    });
  } catch (error) {
    console.error('Unified login error:', error);
    res.status(500).json({
      error: 'Internal server error',
    });
  }
};
