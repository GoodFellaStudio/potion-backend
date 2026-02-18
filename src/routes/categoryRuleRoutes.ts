import express from 'express';
import { categoryRuleController } from '../controllers/categoryRuleController';

const router = express.Router();

router.get('/', categoryRuleController.list);
router.post('/', categoryRuleController.create);
router.post('/apply', categoryRuleController.applyToExisting);
router.patch('/:id', categoryRuleController.update);
router.delete('/:id', categoryRuleController.remove);

export default router;
