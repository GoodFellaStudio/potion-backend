import express from 'express';
import {
  subcontractorController,
  getSubcontractorProjects,
  assignSubcontractorToProject,
  getProjectSubcontractors,
  removeSubcontractorFromProject,
  bulkAssignSubcontractors,
} from '../controllers/subcontractorController';
import {
  checkWritePermission,
  requireRole,
} from '../middleware/rbac';
import { UserRoleType } from '../models/UserRoles';

const router = express.Router();

/**
 * @swagger
 * tags:
 *   name: Subcontractors
 *   description: Subcontractor management endpoints
 */

/**
 * @swagger
 * components:
 *   schemas:
 *     PaymentInformation:
 *       type: object
 *       properties:
 *         paymentType:
 *           type: string
 *           enum: [bank, paypal, other]
 *         routingNumber:
 *           type: string
 *           example: "484515545784"
 *         accountNumber:
 *           type: string
 *           example: "1545454578489664458"
 *         accountHolderName:
 *           type: string
 *           example: "Ibrahim Karl Bileri"
 *         paypalEmail:
 *           type: string
 *           example: "payment@example.com"
 *         paymentDescription:
 *           type: string
 *           example: "Cash payments preferred"
 *     Subcontractor:
 *       type: object
 *       properties:
 *         firstName:
 *           type: string
 *           example: "Ibrahim"
 *         lastName:
 *           type: string
 *           example: "Bileri"
 *         email:
 *           type: string
 *           example: "ibrahim@example.com"
 *         businessName:
 *           type: string
 *           example: "Bil's Studio"
 *         country:
 *           type: string
 *           example: "TG"
 *         isUSCitizen:
 *           type: boolean
 *           example: false
 *         taxType:
 *           type: string
 *           enum: [individual, business]
 *         paymentInformation:
 *           $ref: '#/components/schemas/PaymentInformation'
 */

// ==================== Invitation Routes ====================
/**
 * @swagger
 * /subcontractor/invite/{inviteKey}:
 *   get:
 *     summary: Get subcontractor by invite key
 *     tags: [Subcontractors]
 *     parameters:
 *       - in: path
 *         name: inviteKey
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Subcontractor details retrieved
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Subcontractor'
 *       404:
 *         description: Invalid invite key
 */
router.get('/invite/:inviteKey', subcontractorController.getByInviteKey);

/**
 * @swagger
 * /subcontractor/invite/{inviteKey}:
 *   put:
 *     summary: Udpate subcontractor by invite key
 *     tags: [Subcontractors]
 *     parameters:
 *       - in: path
 *         name: inviteKey
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Subcontractor details updated
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Subcontractor'
 *       404:
 *         description: Invalid invite key
 */
router.put(
  '/invite/:inviteKey',
  subcontractorController.updateSubcontractorByInviteKey,
);

/**
 * @swagger
 * /subcontractor/invite/{inviteKey}/set-password:
 *   put:
 *     summary: Set subcontractor password by invite key
 *     tags: [Subcontractors]
 *     parameters:
 *       - in: path
 *         name: inviteKey
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
 *                 format: password
 *     responses:
 *       200:
 *         description: Password set successfully
 *       404:
 *         description: Invalid invite key
 */
router.put(
  '/invite/:inviteKey/set-password',
  subcontractorController.setSubcontractorPasswordByInviteKey,
);

/**
 * @swagger
 * /subcontractor/accept-invite/{inviteKey}:
 *   post:
 *     summary: Accept subcontractor invitation
 *     tags: [Subcontractors]
 *     parameters:
 *       - in: path
 *         name: inviteKey
 *         required: true
 *         schema:
 *           type: string
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/Subcontractor'
 *     responses:
 *       200:
 *         description: Invitation accepted successfully
 *       400:
 *         description: Invalid data
 *       404:
 *         description: Invalid invite key
 */
router.post('/accept-invite/:inviteKey', subcontractorController.acceptInvite);

/**
 * @swagger
 * /subcontractor/login:
 *   post:
 *     summary: Subcontractor login
 *     tags: [Subcontractors]
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
 *               password:
 *                 type: string
 *                 format: password
 *             required:
 *               - email
 *               - password
 *     responses:
 *       200:
 *         description: Login successful
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 token:
 *                   type: string
 *                 subcontractor:
 *                   type: object
 *       400:
 *         description: Invalid credentials or password not set
 *       500:
 *         description: Server error
 */
router.post('/login', subcontractorController.subcontractorLogin);

// ==================== CRUD Routes ====================
/**
 * @swagger
 * /subcontractor/invite/{id}:
 *   post:
 *     summary: Invite a subcontractor to a project
 *     tags: [Subcontractors]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *         description: Project ID (optional - can be empty string for general invitation)
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - email
 *             properties:
 *               email:
 *                 type: string
 *                 format: email
 *               note:
 *                 type: string
 *               passkey:
 *                 type: string
 *     responses:
 *       201:
 *         description: Subcontractor invited successfully
 *       400:
 *         description: Invalid input
 *       500:
 *         description: Server error
 */
router.post('/invite/:id', async (req, res) => {
  try {
    await subcontractorController.inviteSubcontractor(req, res);
  } catch (error) {
    console.error('[DEBUG] ❌ Error in POST /invite/:id route:', error);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

/**
 * @swagger
 * /subcontractor:
 *   post:
 *     summary: Create a new subcontractor
 *     tags: [Subcontractors]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - email
 *               - fullName
 *             properties:
 *               email:
 *                 type: string
 *                 format: email
 *               fullName:
 *                 type: string
 *               isUSCitizen:
 *                 type: boolean
 *               paymentInformation:
 *                 type: object
 *     responses:
 *       201:
 *         description: Subcontractor created successfully
 *       400:
 *         description: Invalid input
 *       500:
 *         description: Server error
 */
router.post('/', async (req, res) => {
  try {
    await subcontractorController.createSubcontractor(req, res);
  } catch (error) {
    console.error('[DEBUG] ❌ Error in POST / route:', error);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

/**
 * @swagger
 * /subcontractor/all:
 *   get:
 *     summary: Get all subcontractors
 *     tags: [Subcontractors]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: List of all subcontractors
 *         content:
 *           application/json:
 *             schema:
 *               type: array
 *               items:
 *                 $ref: '#/components/schemas/Subcontractor'
 *       401:
 *         description: Unauthorized
 */
router.get('/all', async (req, res) => {
  try {
    await subcontractorController.getAllSubcontractors(req, res);
  } catch (error) {
    console.error('[DEBUG] Error in /all route:', error);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

/**
 * @swagger
 * /subcontractor/project/{projectId}:
 *   get:
 *     summary: Get all subcontractors for a project
 *     tags: [Subcontractors]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: projectId
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: List of subcontractors
 *         content:
 *           application/json:
 *             schema:
 *               type: array
 *               items:
 *                 $ref: '#/components/schemas/Subcontractor'
 *       401:
 *         description: Unauthorized
 */
router.get('/project/:projectId', subcontractorController.getSubcontractors);

/**
 * @swagger
 * /subcontractor/{id}:
 *   get:
 *     summary: Get subcontractor by id
 *     tags: [Subcontractors]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Get subcontractor by id
 *         content:
 *           application/json:
 *             schema:
 *               type: array
 *               items:
 *                 $ref: '#/components/schemas/Subcontractor'
 *       401:
 *         description: Unauthorized
 */
router.get('/:id', subcontractorController.getSubcontractorById);

/**
 * @swagger
 * /subcontractor/{id}:
 *   put:
 *     summary: Update a subcontractor
 *     tags: [Subcontractors]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/Subcontractor'
 *     responses:
 *       200:
 *         description: Subcontractor updated successfully
 *       404:
 *         description: Subcontractor not found
 *       401:
 *         description: Unauthorized
 */
router.put('/:id', subcontractorController.updateSubcontractor);

/**
 * @swagger
 * /subcontractor/{id}:
 *   delete:
 *     summary: Delete a subcontractor (soft delete)
 *     tags: [Subcontractors]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Subcontractor marked as deleted
 *       404:
 *         description: Subcontractor not found
 *       401:
 *         description: Unauthorized
 */
router.delete('/:id', subcontractorController.deleteSubcontractor);

/**
 * @swagger
 * /subcontractor/{id}/generate-invite:
 *   post:
 *     summary: Generate new invite link for subcontractor
 *     tags: [Subcontractors]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Invite link generated
 *         content:
 *           application/json:
 *             example:
 *               inviteKey: "abc123"
 *       404:
 *         description: Subcontractor not found
 *       401:
 *         description: Unauthorized
 */
router.post('/:id/generate-invite', subcontractorController.generateInviteLink);
/**
 * @swagger
 * /subcontractor/{id}/invite:
 *   post:
 *     summary: Invite a new subcontractor
 *     tags: [Subcontractors]
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
 *               passkey:
 *                 type: string
 *               lastName:
 *                 type: string
 *               email:
 *                 type: string
 *               projectId:
 *                 type: string
 *             required:
 *               - firstName
 *               - lastName
 *               - email
 *               - passkey
 *               - projectId
 *     responses:
 *       201:
 *         description: Subcontractor invited successfully
 *       400:
 *         description: Missing required fields
 *       401:
 *         description: Unauthorized
 */
router.post('/:id/invite', subcontractorController.inviteSubcontractor);

// New multi-project routes
// Get all projects for a subcontractor (requires subcontractor auth)
router.get(
  '/my/projects',
  requireRole(UserRoleType.SUBCONTRACTOR),
  async (req, res) => {
    await getSubcontractorProjects(req, res);
  },
);

// Project assignment management (requires user auth)
router.post(
  '/assign-to-project',
  requireRole(UserRoleType.BUSINESS_OWNER),
  checkWritePermission,
  async (req, res) => {
    await assignSubcontractorToProject(req, res);
  },
);

// Get all subcontractors for a specific project (requires user auth)
router.get(
  '/by-project/:projectId',
  requireRole(UserRoleType.BUSINESS_OWNER),
  async (req, res) => {
    await getProjectSubcontractors(req, res);
  },
);

// Remove subcontractor from project (requires user auth)
router.delete(
  '/project-access/:accessId',
  requireRole(UserRoleType.BUSINESS_OWNER),
  checkWritePermission,
  async (req, res) => {
    await removeSubcontractorFromProject(req, res);
  },
);

// Bulk assign subcontractors to project (requires user auth)
router.post(
  '/bulk-assign',
  requireRole(UserRoleType.BUSINESS_OWNER),
  checkWritePermission,
  async (req, res) => {
    await bulkAssignSubcontractors(req, res);
  },
);

export default router;
