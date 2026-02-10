import nodemailer from "nodemailer";
import { Notification, NotificationLevel } from "../models/Notification";
import { broadcastToUserSessions } from "./socket";

interface CreateNotificationInput {
  userId: string;
  roleId?: string;
  level: NotificationLevel;
  titleKey: string;
  messageKey: string;
  params?: Record<string, string | number>;
  locale?: string;
  data?: Record<string, unknown>;
  sendEmail?: boolean;
  emailTo?: string;
  emailSubject?: string;
  emailText?: string;
}

class NotificationService {
  private transporter: nodemailer.Transporter;

  constructor() {
    this.transporter = nodemailer.createTransport({
      // Configure email transport
    });
  }

  async createNotification(input: CreateNotificationInput) {
    const notification = await Notification.create({
      user: input.userId,
      role: input.roleId,
      level: input.level,
      titleKey: input.titleKey,
      messageKey: input.messageKey,
      params: input.params || {},
      locale: input.locale || "en",
      data: input.data || {},
    });

    broadcastToUserSessions(input.userId, "notification:new", notification);

    if (input.sendEmail && input.emailTo && input.emailSubject && input.emailText) {
      await this.sendEmail(input.emailTo, input.emailSubject, input.emailText);
    }

    return notification;
  }

  async sendEmail(to: string, subject: string, text: string) {
    await this.transporter.sendMail({
      from: process.env.EMAIL_FROM,
      to,
      subject,
      text,
    });
  }
}

export const notificationService = new NotificationService();
