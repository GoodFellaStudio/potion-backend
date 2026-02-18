import mongoose from 'mongoose';

const categoryRuleSchema = new mongoose.Schema(
  {
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: true,
      index: true,
    },
    name: {
      type: String,
      required: true,
    },
    category: {
      type: String,
      required: true,
    },
    group: {
      type: String,
      default: null,
    },
    target: {
      type: String,
      default: null,
    },
    operator: {
      type: String,
      default: null,
    },
    value: {
      type: String,
      default: null,
    },
    includes: {
      type: [String],
      default: [],
    },
    excludes: {
      type: [String],
      default: [],
    },
    minAmount: {
      type: Number,
      default: null,
    },
    maxAmount: {
      type: Number,
      default: null,
    },
    applyToAllAccounts: {
      type: Boolean,
      default: true,
    },
    accountIds: {
      type: [String],
      default: [],
    },
    priority: {
      type: Number,
      default: 100,
    },
    enabled: {
      type: Boolean,
      default: true,
    },
  },
  { timestamps: true }
);

categoryRuleSchema.index({ userId: 1, priority: 1, createdAt: 1 });

export const CategoryRule = mongoose.model('CategoryRule', categoryRuleSchema);
