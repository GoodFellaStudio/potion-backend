import { plaidController } from './../controllers/plaidController';
import { P90 } from './../../node_modules/aws-sdk/clients/iotwireless.d';
import { plaidClient } from '../config/plaid';
import { PlaidItem } from '../models/PlaidItem';
import {
  aiCategoryPlaceholder,
  predictCategory,
  Transaction,
} from '../models/Transaction';
import { Types } from 'mongoose';
import { CountryCode, LinkTokenCreateRequest, Products } from 'plaid';
import { BalanceCalculationService } from './balanceCalculationService';
import { use } from 'react';
import { agenda } from '../queue/agenda';
import { notificationService } from './notificationService';
import crypto from 'crypto';

enum PlaidWebhookCode {
  'userPermissionRevoked' = 'USER_PERMISSION_REVOKED',
  'initialUpdate' = 'INITIAL_UPDATE',
  'historicalUpdate' = 'HISTORICAL_UPDATE',
  'defaultUpdate' = 'DEFAULT_UPDATE',
  'syncUpdatesAvailable' = 'SYNC_UPDATES_AVAILABLE',
}
export class PlaidService {
  private static readonly maxRequestsPerMinute = Number(
    process.env.PLAID_MAX_RPM || 60,
  );
  private static readonly plaidRequestTimestamps: number[] = [];
  private static readonly plaidRequestQueue: Array<{
    run: () => Promise<any>;
    resolve: (value: any) => void;
    reject: (reason: any) => void;
  }> = [];
  private static processingQueue = false;

  private static readonly minSyncIntervalMs = Number(
    process.env.PLAID_MIN_SYNC_INTERVAL_MS || 60000,
  );
  private static readonly syncLockTtlMs = Number(
    process.env.PLAID_SYNC_LOCK_TTL_MS || 120000,
  );

  static async createLinkToken(userId: string, existingToken?: string) {
    try {
      const configs: LinkTokenCreateRequest = {
        user: {
          client_user_id: userId,
        },
        client_name: 'Potion Finance',
        products: [Products.Transactions],
        country_codes: [CountryCode.Us],
        language: 'en',
        webhook: `${process.env.API_URL}api/plaid/webhook`,
        transactions: {
          days_requested: 730,
        },
        update: {
          account_selection_enabled: !!existingToken,
        },
        access_token: existingToken ? existingToken : undefined,
      };

      const response = await plaidClient.linkTokenCreate(configs);
      return response.data;
    } catch (error) {
      console.error('Error creating link token:', error);
      throw error;
    }
  }

  static async removeItem(access_token: string) {
    try {
      const response = await plaidClient.itemRemove({
        access_token,
      });

      return response.data;
    } catch (error) {
      console.error('Error creating link token:', error);
      throw error;
    }
  }

  static async exchangePublicToken(publicToken: string, userId: string) {
    try {
      const response = await plaidClient.itemPublicTokenExchange({
        public_token: publicToken,
      });

      const { access_token, item_id } = response.data;

      // Get institution info
      const itemResponse = await plaidClient.itemGet({
        access_token: access_token,
      });

      const institutionResponse = await plaidClient.institutionsGetById({
        institution_id: itemResponse.data.item.institution_id,
        country_codes: [CountryCode.Us],
      });

      // Get accounts
      const accountsResponse = await plaidClient.accountsGet({
        access_token: access_token,
      });

      // Create or update PlaidItem
      const plaidItem = await PlaidItem.findOneAndUpdate(
        { itemId: item_id },
        {
          userId: new Types.ObjectId(userId),
          accessToken: access_token,
          itemId: item_id,
          institutionId: itemResponse.data.item.institution_id,
          institutionName: institutionResponse.data.institution.name,
          accounts: accountsResponse.data.accounts.map((account) => ({
            accountId: account.account_id,
            name: account.name,
            type: account.type,
            subtype: account.subtype,
            mask: account.mask,
            institutionId: itemResponse.data.item.institution_id,
            institutionName: institutionResponse.data.institution.name,
          })),
        },
        { upsert: true, new: true },
      );

      // Sync transactions immediately after linking account
      const transactionCount = await PlaidService.syncTransactions(
        plaidItem._id.toString(),
        { notify: false },
      );

      if (transactionCount > 0) {
        await notificationService.createNotification({
          userId: plaidItem.userId.toString(),
          level: 'success',
          titleKey: 'notifications.new_transactions.title',
          messageKey: 'notifications.new_transactions.message',
          params: {
            count: transactionCount,
            totalCount: transactionCount,
            autoCategorizedCount: transactionCount,
          },
          data: { plaidItemId: plaidItem._id.toString() },
        });
      }

      return {
        ...plaidItem.toObject(),
        newTransactionsCount: transactionCount,
      };
    } catch (error) {
      console.error('Error exchanging public token:', error);
      throw error;
    }
  }

  static async syncTransactions(
    plaidItemId: string,
    options?: { notify?: boolean },
  ) {
    try {
      const plaidItem = await PlaidItem.findById(plaidItemId);
      if (!plaidItem) {
        throw new Error('Plaid item not found');
      }

      const now = Date.now();
      if (
        plaidItem.lastSync &&
        now - new Date(plaidItem.lastSync).getTime() <
          PlaidService.minSyncIntervalMs
      ) {
        return 0;
      }

      const lockOwner = await PlaidService.acquireSyncLock(plaidItemId);
      if (!lockOwner) {
        return 0;
      }

      let hasMore = true;
      let createdCount = 0;
      let cursor = plaidItem.transactionsCursor;
      let preservedCursor = cursor; // Keep track of the last successful cursor

      try {
        while (hasMore) {
          try {
            // Make the sync request
            const response = await PlaidService.executeSyncWithRetry(
              plaidItem.accessToken,
              cursor,
            );

          const { added, modified, removed, next_cursor, has_more } =
            response.data;

          const accountMap = {};
          response.data.accounts.forEach((account) => {
            accountMap[account.account_id] = account;
          });

          // Process added transactions
          for (const [index, plaidTransaction] of added.entries()) {
            const transaction = {
              date: new Date(plaidTransaction.date),
              type: classifyTransaction(plaidTransaction),
              amount: Math.abs(plaidTransaction.amount),
              description: plaidTransaction.name,
              bankAccount: plaidTransaction.account_id,
              cardLastFour: accountMap[plaidTransaction.account_id]?.mask || '',
              account: JSON.stringify(accountMap[plaidTransaction.account_id]),
              counterparty:
                plaidTransaction.merchant_name || plaidTransaction.name,
              category: aiCategoryPlaceholder,
              createdBy: plaidItem.userId,
              plaidTransactionId: plaidTransaction.transaction_id,
            };

            await agenda.create('add Transaction', {transaction: transaction}).save();
            createdCount++;
          }

          // Process modified transactions
          for (const [index, plaidTransaction] of modified.entries()) {
            const updatedTransaction = await Transaction.findOneAndUpdate(
              { plaidTransactionId: plaidTransaction.transaction_id },
              {
                amount: Math.abs(plaidTransaction.amount),
                description: plaidTransaction.name,
                counterparty:
                  plaidTransaction.merchant_name || plaidTransaction.name,
                category: '',
              },
            );

             await agenda.create('predict category', {transaction: updatedTransaction}).save();
          }

          // Process removed transactions
          for (const removedTransaction of removed) {
            await Transaction.deleteOne({
              plaidTransactionId: removedTransaction.transaction_id,
            });
          }

          // Update cursor and hasMore flag
          cursor = next_cursor;
          hasMore = has_more;

          // If this sync was successful, update the preserved cursor
          preservedCursor = cursor;

            // Update the cursor in the database after each successful sync
            await PlaidItem.findByIdAndUpdate(plaidItemId, {
              transactionsCursor: cursor,
              lastSync: new Date(),
            });
          } catch (error: any) {
            if (
              error.response?.data?.error_code ===
              'TRANSACTIONS_SYNC_MUTATION_DURING_PAGINATION'
            ) {
              console.log(
                '[PlaidService] Mutation detected during pagination, restarting from preserved cursor',
              );
              cursor = preservedCursor;
              continue;
            }
            throw error;
          }
        }

      // Update balances after transaction sync
      try {
        await BalanceCalculationService.updateBalancesAfterSync(
          plaidItem.userId.toString(),
          plaidItemId,
        );
      } catch (error) {
        console.error(
          `[PlaidService] Error updating balances after sync:`,
          error,
        );
        // Don't fail the sync if balance calculation fails
      }

        const shouldNotify = options?.notify !== false;
        if (createdCount > 0 && shouldNotify) {
          await notificationService.createNotification({
            userId: plaidItem.userId.toString(),
            level: 'success',
            titleKey: 'notifications.new_transactions.title',
            messageKey: 'notifications.new_transactions.message',
            params: {
              count: createdCount,
              totalCount: createdCount,
              autoCategorizedCount: createdCount,
            },
            data: { plaidItemId },
          });
        }

        return createdCount;
      } finally {
        await PlaidService.releaseSyncLock(plaidItemId, lockOwner);
      }
    } catch (error) {
      console.error('Error syncing transactions:', error);
      throw error;
    }
  }

  private static async executeSyncWithRetry(
    accessToken: string,
    cursor: string | null,
  ) {
    const maxAttempts = 5;
    let attempt = 0;
    let lastError: any;

    while (attempt < maxAttempts) {
      attempt += 1;
      try {
        return await PlaidService.queuePlaidRequest(() =>
          plaidClient.transactionsSync({
            access_token: accessToken,
            cursor: cursor,
            options: {
              include_personal_finance_category: true,
            },
          }),
        );
      } catch (error: any) {
        lastError = error;
        const status = error?.response?.status;
        const errorCode = error?.response?.data?.error_code;

        if (status === 429 || errorCode === 'TRANSACTIONS_SYNC_LIMIT') {
          const retryAfterHeader =
            Number(error?.response?.headers?.['retry-after']) ||
            Number(error?.response?.headers?.['x-ratelimit-reset']) ||
            0;
          const backoffMs = retryAfterHeader
            ? retryAfterHeader * 1000
            : Math.min(30000, 1000 * 2 ** (attempt - 1)) +
              Math.floor(Math.random() * 250);
          await PlaidService.sleep(backoffMs);
          continue;
        }

        throw error;
      }
    }

    throw lastError;
  }

  private static async queuePlaidRequest<T>(fn: () => Promise<T>): Promise<T> {
    return new Promise<T>((resolve, reject) => {
      PlaidService.plaidRequestQueue.push({
        run: fn,
        resolve,
        reject,
      });

      if (!PlaidService.processingQueue) {
        PlaidService.processQueue().catch((error) => {
          console.error('Plaid queue processing error:', error);
        });
      }
    });
  }

  private static async processQueue(): Promise<void> {
    if (PlaidService.processingQueue) return;
    PlaidService.processingQueue = true;

    try {
      while (PlaidService.plaidRequestQueue.length > 0) {
        const now = Date.now();
        PlaidService.cleanupOldTimestamps(now);

        if (
          PlaidService.plaidRequestTimestamps.length >=
          PlaidService.maxRequestsPerMinute
        ) {
          const oldest = Math.min(...PlaidService.plaidRequestTimestamps);
          const waitTime = Math.max(0, 60000 - (now - oldest));
          await PlaidService.sleep(waitTime);
          continue;
        }

        const item = PlaidService.plaidRequestQueue.shift();
        if (!item) continue;

        try {
          PlaidService.plaidRequestTimestamps.push(Date.now());
          const result = await item.run();
          item.resolve(result);
        } catch (error) {
          item.reject(error);
        }

        if (PlaidService.plaidRequestQueue.length > 0) {
          await PlaidService.sleep(100);
        }
      }
    } finally {
      PlaidService.processingQueue = false;
    }
  }

  private static cleanupOldTimestamps(now: number) {
    const cutoff = now - 60000;
    while (
      PlaidService.plaidRequestTimestamps.length > 0 &&
      PlaidService.plaidRequestTimestamps[0] < cutoff
    ) {
      PlaidService.plaidRequestTimestamps.shift();
    }
  }

  private static async acquireSyncLock(plaidItemId: string) {
    const lockOwner = crypto.randomUUID();
    const now = new Date();
    const lockUntil = new Date(now.getTime() + PlaidService.syncLockTtlMs);

    const locked = await PlaidItem.findOneAndUpdate(
      {
        _id: plaidItemId,
        $or: [
          { syncLockUntil: null },
          { syncLockUntil: { $lt: now } },
        ],
      },
      {
        syncLockUntil: lockUntil,
        syncLockOwner: lockOwner,
      },
      { new: true },
    );

    return locked ? lockOwner : null;
  }

  private static async releaseSyncLock(
    plaidItemId: string,
    lockOwner: string,
  ) {
    await PlaidItem.updateOne(
      { _id: plaidItemId, syncLockOwner: lockOwner },
      { $set: { syncLockUntil: null, syncLockOwner: null } },
    );
  }

  private static sleep(ms: number) {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }

  static async deletePlaidItem(itemId: string) {
    try {
      let plaidItem = await PlaidItem.findOne({
        itemId,
      });

      if (!plaidItem) {
        return;
      }

      plaidItem.accounts?.map(async (account) => {
        await Transaction.deleteMany({ bankAccount: account.accountId });
      });

      await PlaidService.removeItem(plaidItem.accessToken);
      await PlaidItem.deleteOne({ _id: plaidItem._id });
    } catch (error: any) {
      console.error('[PlaidService] Error deleting Plaid item:', error.message);
      throw error;
    }
  }

  static async handleWebhook(webhookData: any) {
    try {
      const { webhook_type, webhook_code, item_id } = webhookData;

      if (webhook_type === 'ITEM') {
        if (webhook_code === PlaidWebhookCode.userPermissionRevoked) {
          this.deletePlaidItem(item_id);
        }
      }

      if (webhook_type === 'TRANSACTIONS') {
        const plaidItem = await PlaidItem.findOne({ itemId: item_id });
        if (!plaidItem) {
          console.error(`Plaid item not found for item_id: ${item_id}`);
          throw new Error('Plaid item not found');
        }

        // Handle all types of transaction updates
        const validUpdateCodes = [
          'INITIAL_UPDATE',
          'HISTORICAL_UPDATE',
          'DEFAULT_UPDATE',
          'SYNC_UPDATES_AVAILABLE',
          'TRANSACTIONS_REMOVED',
        ];

        if (validUpdateCodes.includes(webhook_code)) {
          await this.syncTransactions(plaidItem._id.toString());
        } else {
          console.log(`Ignoring unhandled webhook code: ${webhook_code}`);
        }
      }

      return true;
    } catch (error) {
      console.error('Error handling webhook:', error);
      throw error;
    }
  }
}

function classifyTransaction(txn) {
  if (txn.amount < 0) {
    return 'Income';
  }

  const incomeKeywords = ['deposit', 'payroll', 'refund', 'cashback', 'rebate'];
  const nameLower = txn.name?.toLowerCase() || '';
  const categoryLower = (txn.category || []).join(',').toLowerCase();

  if (
    incomeKeywords.some(
      (keyword) =>
        nameLower.includes(keyword) || categoryLower.includes(keyword),
    )
  ) {
    return 'Income';
  }

  return 'Expense';
}
