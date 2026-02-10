import mongoose from "mongoose";

export type NotificationLevel = "success" | "warning" | "info" | "error";

const notificationSchema = new mongoose.Schema(
  {
    user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
      index: true,
    },
    role: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "UserRoles",
    },
    level: {
      type: String,
      enum: ["success", "warning", "info", "error"],
      required: true,
      index: true,
    },
    titleKey: {
      type: String,
      required: true,
    },
    messageKey: {
      type: String,
      required: true,
    },
    params: {
      type: mongoose.Schema.Types.Mixed,
      default: {},
    },
    locale: {
      type: String,
      default: "en",
    },
    isRead: {
      type: Boolean,
      default: false,
      index: true,
    },
    archived: {
      type: Boolean,
      default: false,
      index: true,
    },
    data: {
      type: mongoose.Schema.Types.Mixed,
      default: {},
    },
  },
  { timestamps: true }
);

notificationSchema.index({ user: 1, createdAt: -1 });

export const Notification = mongoose.model("Notification", notificationSchema);
