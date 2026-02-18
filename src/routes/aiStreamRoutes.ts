import express from 'express';
import { auth } from '../middleware/auth';
import { Transaction } from '../models/Transaction';
import { streamTransactionChat } from '../services/aiStreamService';

const router = express.Router();

/**
 * POST /api/ai/transaction/:transactionId/stream-chat
 * Streaming chat endpoint for transaction categorization
 */
router.post(
  '/transaction/:transactionId/stream-chat',
  auth,
  async (req: any, res: any) => {
    try {
      const { transactionId } = req.params;
      const { messages, currentCategory } = req.body;

      console.log('[STREAM-ROUTE] Request received:', {
        transactionId,
        messageCount: messages?.length,
        currentCategory,
        userId: req.user?.userId,
      });

      if (!messages || !Array.isArray(messages)) {
        console.log('[STREAM-ROUTE] Invalid messages array');
        return res.status(400).json({ error: 'messages array is required' });
      }

      // Load transaction and verify ownership
      const transaction = await Transaction.findOne({
        _id: transactionId,
        createdBy: req.user.userId,
      });

      console.log('[STREAM-ROUTE] Transaction lookup:', {
        found: !!transaction,
        transactionId,
        userId: req.user.userId,
      });

      if (!transaction) {
        return res.status(404).json({ error: 'Transaction not found' });
      }

      const txContext = {
        amount: transaction.amount,
        type: transaction.type || (transaction.amount > 0 ? 'Income' : 'Expense'),
        description: transaction.description || '',
        merchant:
          (transaction as any).recipient ||
          (transaction as any).counterparty ||
          transaction.description ||
          'Unknown',
        date: transaction.date
          ? new Date(transaction.date).toISOString()
          : new Date().toISOString(),
      };

      console.log('[STREAM-ROUTE] Transaction context:', txContext);
      // Sanitize messages: strip extra fields, enforce user/assistant alternation
      const cleanMessages: Array<{ role: 'user' | 'assistant'; content: string }> = [];
      for (const msg of messages) {
        const role = msg.role === 'user' ? 'user' : 'assistant';
        const content = typeof msg.content === 'string' ? msg.content : '';
        if (!content) continue;
        // Skip if same role as previous (Perplexity requires alternation)
        if (cleanMessages.length > 0 && cleanMessages[cleanMessages.length - 1].role === role) {
          // Merge consecutive same-role messages
          cleanMessages[cleanMessages.length - 1].content += '\n' + content;
          continue;
        }
        cleanMessages.push({ role, content });
      }
      // Ensure first message is from user (skip leading assistant messages like welcome)
      while (cleanMessages.length > 0 && cleanMessages[0].role === 'assistant') {
        cleanMessages.shift();
      }

      console.log('[STREAM-ROUTE] Clean messages:', JSON.stringify(cleanMessages));

      if (cleanMessages.length === 0) {
        return res.status(400).json({ error: 'No user messages provided' });
      }

      const result = streamTransactionChat(
        txContext,
        cleanMessages,
        currentCategory || transaction.category
      );

      console.log('[STREAM-ROUTE] streamText called, streaming to response...');

      // Stream headers
      res.setHeader('Content-Type', 'text/plain; charset=utf-8');
      res.setHeader('Cache-Control', 'no-cache');
      res.setHeader('X-Accel-Buffering', 'no');

      // Stream text chunks
      for await (const chunk of result.textStream) {
        res.write(chunk);
      }

      // Append Perplexity citation sources at the end
      try {
        const sources = await result.sources;
        if (sources && sources.length > 0) {
          const urls = sources
            .filter((s: any) => s.sourceType === 'url' && s.url)
            .map((s: any) => s.url);
          if (urls.length > 0) {
            res.write(`\n[SOURCES]${JSON.stringify({ urls })}[/SOURCES]`);
          }
        }
      } catch (e) {
        // Sources not available — fine, just skip
      }

      res.end();
    } catch (error: any) {
      console.error('[STREAM-ROUTE] Error:', error.message || error);
      if (!res.headersSent) {
        res.status(500).json({ error: 'Internal server error' });
      }
    }
  }
);

export default router;
