import { Notification } from "../models/Notification";

const getUserId = (req: any) => req.auth?.userId || req.user?.userId;

export const notificationController = {
  async list(req, res) {
    try {
      const userId = getUserId(req);
      if (!userId) {
        return res.status(401).json({ message: "Unauthorized" });
      }

      const status = String(req.query.status || "all");
      const includeArchived = String(req.query.includeArchived || "false") === "true";
      const page = Math.max(parseInt(String(req.query.page || "1"), 10), 1);
      const limit = Math.min(Math.max(parseInt(String(req.query.limit || "20"), 10), 1), 100);
      const skip = (page - 1) * limit;

      const query: any = { user: userId };
      if (!includeArchived) {
        query.archived = false;
      }

      if (status === "unread") {
        query.isRead = false;
      } else if (status === "read") {
        query.isRead = true;
      }

      const [items, total] = await Promise.all([
        Notification.find(query)
          .sort({ createdAt: -1 })
          .skip(skip)
          .limit(limit)
          .lean(),
        Notification.countDocuments(query),
      ]);

      return res.status(200).json({
        items,
        page,
        limit,
        total,
        hasMore: skip + items.length < total,
      });
    } catch (error: any) {
      console.error("Error listing notifications:", error);
      return res.status(500).json({ message: "Server error" });
    }
  },

  async unreadCount(req, res) {
    try {
      const userId = getUserId(req);
      if (!userId) {
        return res.status(401).json({ message: "Unauthorized" });
      }

      const count = await Notification.countDocuments({
        user: userId,
        isRead: false,
        archived: false,
      });

      return res.status(200).json({ count });
    } catch (error: any) {
      console.error("Error getting unread count:", error);
      return res.status(500).json({ message: "Server error" });
    }
  },

  async update(req, res) {
    try {
      const userId = getUserId(req);
      if (!userId) {
        return res.status(401).json({ message: "Unauthorized" });
      }

      const { id } = req.params;
      const { isRead, archived } = req.body || {};

      if (typeof isRead !== "boolean" && typeof archived !== "boolean") {
        return res.status(400).json({ message: "No valid fields to update" });
      }

      const updates: any = {};
      if (typeof isRead === "boolean") updates.isRead = isRead;
      if (typeof archived === "boolean") updates.archived = archived;

      const notification = await Notification.findOneAndUpdate(
        { _id: id, user: userId },
        { $set: updates },
        { new: true },
      ).lean();

      if (!notification) {
        return res.status(404).json({ message: "Notification not found" });
      }

      return res.status(200).json(notification);
    } catch (error: any) {
      console.error("Error updating notification:", error);
      return res.status(500).json({ message: "Server error" });
    }
  },

  async bulkUpdate(req, res) {
    try {
      const userId = getUserId(req);
      if (!userId) {
        return res.status(401).json({ message: "Unauthorized" });
      }

      const { ids, isRead, archived, markAllRead, archiveAll } = req.body || {};

      const updates: any = {};
      if (typeof isRead === "boolean") updates.isRead = isRead;
      if (typeof archived === "boolean") updates.archived = archived;

      if (markAllRead === true) {
        updates.isRead = true;
      }

      if (archiveAll === true) {
        updates.archived = true;
      }

      if (Object.keys(updates).length === 0) {
        return res.status(400).json({ message: "No valid fields to update" });
      }

      const query: any = { user: userId };
      if (Array.isArray(ids) && ids.length > 0) {
        query._id = { $in: ids };
      }

      const result = await Notification.updateMany(query, { $set: updates });

      return res.status(200).json({ updated: result.modifiedCount });
    } catch (error: any) {
      console.error("Error bulk updating notifications:", error);
      return res.status(500).json({ message: "Server error" });
    }
  },
};
