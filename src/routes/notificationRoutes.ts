import express from "express";
import { notificationController } from "../controllers/notificationController";

const router = express.Router();

router.get("/", notificationController.list);
router.get("/unread-count", notificationController.unreadCount);
router.patch("/:id", notificationController.update);
router.patch("/", notificationController.bulkUpdate);

export default router;
