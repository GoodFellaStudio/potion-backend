import { CategoryRule } from '../models/CategoryRule';
import { Transaction, aiCategoryPlaceholder } from '../models/Transaction';
import { findMatchingCategoryRule } from '../services/categoryRuleService';

const getUserId = (req: any) => req.user?.userId || req.auth?.userId;

export const categoryRuleController = {
  async list(req, res) {
    try {
      const userId = getUserId(req);
      if (!userId) {
        return res.status(401).json({ message: 'Unauthorized' });
      }

      const rules = await CategoryRule.find({ userId })
        .sort({ priority: 1, createdAt: 1 })
        .lean();

      return res.status(200).json(rules);
    } catch (error: any) {
      console.error('Error listing category rules:', error);
      return res.status(500).json({ message: 'Server error' });
    }
  },

  async create(req, res) {
    try {
      const userId = getUserId(req);
      if (!userId) {
        return res.status(401).json({ message: 'Unauthorized' });
      }

      const {
        name,
        category,
        group = null,
        target = null,
        operator = null,
        value = null,
        includes = [],
        excludes = [],
        minAmount = null,
        maxAmount = null,
        applyToAllAccounts = true,
        accountIds = [],
        priority = 100,
        enabled = true,
      } = req.body || {};

      if (!name || !category) {
        return res.status(400).json({ message: 'name and category are required' });
      }

      if (target && target !== 'transaction' && (!operator || value == null || value === '')) {
        return res
          .status(400)
          .json({ message: 'target, operator and value are required together' });
      }

      if (
        typeof minAmount === 'number' &&
        typeof maxAmount === 'number' &&
        minAmount > maxAmount
      ) {
        return res.status(400).json({ message: 'minAmount cannot exceed maxAmount' });
      }

      const rule = await CategoryRule.create({
        userId,
        name,
        category,
        group,
        target,
        operator,
        value,
        includes,
        excludes,
        minAmount,
        maxAmount,
        applyToAllAccounts,
        accountIds,
        priority,
        enabled,
      });

      return res.status(201).json(rule);
    } catch (error: any) {
      console.error('Error creating category rule:', error);
      return res.status(500).json({ message: 'Server error' });
    }
  },

  async update(req, res) {
    try {
      const userId = getUserId(req);
      if (!userId) {
        return res.status(401).json({ message: 'Unauthorized' });
      }

      const { id } = req.params;
      const updates = req.body || {};

      if (
        typeof updates.minAmount === 'number' &&
        typeof updates.maxAmount === 'number' &&
        updates.minAmount > updates.maxAmount
      ) {
        return res.status(400).json({ message: 'minAmount cannot exceed maxAmount' });
      }

      if (
        updates.target &&
        updates.target !== 'transaction' &&
        (!updates.operator || updates.value == null || updates.value === '')
      ) {
        return res
          .status(400)
          .json({ message: 'target, operator and value are required together' });
      }

      const rule = await CategoryRule.findOneAndUpdate(
        { _id: id, userId },
        { $set: updates },
        { new: true },
      ).lean();

      if (!rule) {
        return res.status(404).json({ message: 'Rule not found' });
      }

      return res.status(200).json(rule);
    } catch (error: any) {
      console.error('Error updating category rule:', error);
      return res.status(500).json({ message: 'Server error' });
    }
  },

  async remove(req, res) {
    try {
      const userId = getUserId(req);
      if (!userId) {
        return res.status(401).json({ message: 'Unauthorized' });
      }

      const { id } = req.params;
      const result = await CategoryRule.deleteOne({ _id: id, userId });

      if (!result.deletedCount) {
        return res.status(404).json({ message: 'Rule not found' });
      }

      return res.status(200).json({ success: true });
    } catch (error: any) {
      console.error('Error deleting category rule:', error);
      return res.status(500).json({ message: 'Server error' });
    }
  },

  async applyToExisting(req, res) {
    try {
      const userId = getUserId(req);
      if (!userId) {
        return res.status(401).json({ message: 'Unauthorized' });
      }

      const { scope = 'uncategorized' } = req.body || {};

      const query: any = { createdBy: userId };
      if (scope === 'uncategorized') {
        query.$or = [
          { category: null },
          { category: '' },
          { category: aiCategoryPlaceholder },
        ];
      }

      let applied = 0;
      const cursor = Transaction.find(query).cursor();

      for await (const txn of cursor) {
        const match = await findMatchingCategoryRule({
          userId: txn.createdBy?.toString(),
          description: txn.description,
          counterparty: txn.counterparty,
          amount: txn.amount,
          bankAccount: txn.bankAccount,
          date: txn.date,
          project: txn.project?.toString?.(),
        });

        if (!match) continue;

        await Transaction.updateOne(
          { _id: txn._id },
          {
            $set: {
              category: match.category,
              aiDescription: null,
              isUserConfirmed: true,
            },
          },
        );
        applied += 1;
      }

      return res.status(200).json({ applied });
    } catch (error: any) {
      console.error('Error applying category rules:', error);
      return res.status(500).json({ message: 'Server error' });
    }
  },
};
