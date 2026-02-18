import { CategoryRule } from '../models/CategoryRule';

interface TransactionLike {
  userId: string;
  description?: string;
  counterparty?: string;
  amount?: number;
  bankAccount?: string;
  project?: string;
  date?: Date | string;
}

const normalizeTerms = (terms: string[] = []) =>
  terms
    .map((t) => String(t || '').trim().toLowerCase())
    .filter((t) => t.length > 0);

const normalizeText = (value?: string) => String(value || '').trim().toLowerCase();

const compareText = (text: string, operator: string, value: string) => {
  const normalizedText = normalizeText(text);
  const normalizedValue = normalizeText(value);

  switch (operator) {
    case 'equals':
      return normalizedText === normalizedValue;
    case 'starts_with':
      return normalizedText.startsWith(normalizedValue);
    case 'ends_with':
      return normalizedText.endsWith(normalizedValue);
    case 'contains':
    default:
      return normalizedText.includes(normalizedValue);
  }
};

const toDayString = (value?: Date | string) => {
  if (!value) return null;
  const date = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(date.getTime())) return null;
  return date.toISOString().slice(0, 10);
};

const matchTargetCondition = (rule: any, txn: TransactionLike) => {
  if (!rule?.target || !rule?.operator || rule?.value == null || rule?.value === '') {
    return true;
  }

  const operator = String(rule.operator);
  const value = String(rule.value);

  switch (rule.target) {
    case 'transaction': {
      const source = txn.counterparty || txn.description || '';
      return compareText(source, operator, value);
    }
    case 'description': {
      return compareText(txn.description || '', operator, value);
    }
    case 'bank': {
      return compareText(txn.bankAccount || '', operator, value);
    }
    case 'project': {
      return compareText(txn.project || '', operator, value);
    }
    case 'date': {
      const txnDay = toDayString(txn.date);
      const ruleDay = toDayString(value);
      if (!txnDay || !ruleDay) return false;
      if (operator === 'before') return txnDay < ruleDay;
      if (operator === 'after') return txnDay > ruleDay;
      return txnDay === ruleDay;
    }
    default:
      return true;
  }
};

export const findMatchingCategoryRule = async (txn: TransactionLike) => {
  if (!txn?.userId) return null;

  const rules = await CategoryRule.find({
    userId: txn.userId,
    enabled: true,
  })
    .sort({ priority: 1, createdAt: 1 })
    .lean();

  if (!rules.length) return null;

  const text = `${txn.description || ''} ${txn.counterparty || ''}`
    .toLowerCase()
    .trim();

  for (const rule of rules) {
    if (!rule.applyToAllAccounts) {
      if (!txn.bankAccount) continue;
      if (!Array.isArray(rule.accountIds) || rule.accountIds.length === 0) {
        continue;
      }
      if (!rule.accountIds.includes(txn.bankAccount)) continue;
    }

    if (!matchTargetCondition(rule, txn)) {
      continue;
    }

    const includes = normalizeTerms(rule.includes || []);
    const excludes = normalizeTerms(rule.excludes || []);

    if (includes.length > 0 && !includes.every((t) => text.includes(t))) {
      continue;
    }

    if (excludes.length > 0 && excludes.some((t) => text.includes(t))) {
      continue;
    }

    const amount = Math.abs(Number(txn.amount || 0));
    if (typeof rule.minAmount === 'number' && amount < rule.minAmount) {
      continue;
    }
    if (typeof rule.maxAmount === 'number' && amount > rule.maxAmount) {
      continue;
    }

    return rule;
  }

  return null;
};
