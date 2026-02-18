import { streamText } from 'ai';
import { createPerplexity } from '@ai-sdk/perplexity';
import {
  getBusinessExpenseCategories,
  getIncomeCategories,
} from '../config/categories';

const apiKey = process.env.PERPLEXITY_API_KEY || '';
console.log('[AI-SERVICE] Perplexity API key configured:', apiKey ? `${apiKey.slice(0, 8)}...` : 'MISSING');

const perplexity = createPerplexity({ apiKey });

interface TransactionContext {
  amount: number;
  type: string;
  description: string;
  merchant: string;
  date: string;
}

function getCategoriesForType(type: string, amount: number): string[] {
  if (type === 'Income' || amount > 0) {
    return getIncomeCategories();
  }
  return getBusinessExpenseCategories();
}

function buildSystemPrompt(
  tx: TransactionContext,
  currentCategory?: string
): string {
  const categories = getCategoriesForType(tx.type, tx.amount);
  const typeLabel = tx.type === 'Income' ? 'Income' : 'Business Expense';

  return `You are a transaction categorization assistant. EVERY message from the user is about THIS specific transaction — never interpret questions as general or unrelated.

Transaction: $${Math.abs(tx.amount).toFixed(2)} ${tx.type} at "${tx.merchant}" on ${tx.date}. Description: "${tx.description}".${currentCategory ? ` Current category: "${currentCategory}".` : ' Currently uncategorized.'}

Available ${typeLabel} categories: ${categories.join(', ')}

Rules:
- Be extremely concise — 1-3 short sentences max. No filler, no preambles
- ALWAYS assume the user is asking about THIS transaction${!currentCategory ? '\n- The transaction is uncategorized — proactively suggest the best category' : ''}
- Suggest the best category immediately based on what you know
- If you need info, ask ONE short question about the transaction purpose
- Never repeat transaction details back to the user
- Never list all categories
- Always include the category JSON block when suggesting

End your response with: [CATEGORIES]{"categories":[{"name":"Category Name","confidence":0.9}]}[/CATEGORIES]
Use exact names from the available categories.`;
}

export function streamTransactionChat(
  transaction: TransactionContext,
  messages: Array<{ role: 'user' | 'assistant'; content: string }>,
  currentCategory?: string
) {
  const systemPrompt = buildSystemPrompt(transaction, currentCategory);
  console.log('[AI-SERVICE] streamText called with:', {
    model: 'sonar',
    messageCount: messages.length,
    systemPromptLength: systemPrompt.length,
    temperature: 0.4,
  });

  const result = streamText({
    model: perplexity('sonar'),
    system: systemPrompt,
    messages,
    temperature: 0.3,
    maxOutputTokens: 400,
  });

  // Log when the stream produces text (non-blocking)
  Promise.resolve(result.text).then((text) => {
    console.log('[AI-SERVICE] Stream completed. Full text length:', text.length);
    console.log('[AI-SERVICE] First 300 chars:', text.slice(0, 300));
  }).catch((err) => {
    console.error('[AI-SERVICE] Stream error:', err.message || err);
  });

  return result;
}
