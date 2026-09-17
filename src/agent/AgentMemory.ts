/**
 * AgentMemory — Persistent task memory for the autonomous agent.
 *
 * Tracks the full execution history: plan steps, completed actions,
 * extracted data (prices, product names), and conversation context.
 * Survives pause/resume cycles. Serialisable for future persistence.
 */

export interface ExtractedProduct {
  name: string;
  price: string;
  rating: string;
  reviews: string;
  delivery: string;
  url: string;
  vendor: string;
}

export interface PlanStep {
  id: number;
  description: string;
  status: 'pending' | 'active' | 'done' | 'failed' | 'skipped';
  result?: string;
}

export interface TaskMemory {
  goal: string;
  plan: PlanStep[];
  currentStepIndex: number;
  extractedProducts: ExtractedProduct[];
  visitedUrls: string[];
  actionHistory: ActionRecord[];
  requiresConfirmation: boolean;
  confirmationMessage: string;
  errorCount: number;
  maxErrors: number;
  startedAt: number;
  lastActionAt: number;
  visionMode: boolean;
}

export interface ActionRecord {
  timestamp: number;
  tool: string;
  args: Record<string, any>;
  result: string;
  stepId: number;
}

// Memory limits to prevent unbounded growth
const MAX_ACTION_HISTORY = 50;
const MAX_VISITED_URLS = 100;
const MAX_EXTRACTED_PRODUCTS = 50;

export function createTaskMemory(goal: string, vision: boolean = false): TaskMemory {
  return {
    goal,
    plan: [],
    currentStepIndex: 0,
    extractedProducts: [],
    visitedUrls: [],
    actionHistory: [],
    requiresConfirmation: false,
    confirmationMessage: '',
    errorCount: 0,
    maxErrors: 5,
    startedAt: Date.now(),
    lastActionAt: Date.now(),
    visionMode: vision,
  };
}

export function addActionToMemory(
  memory: TaskMemory,
  tool: string,
  args: Record<string, any>,
  result: string
): TaskMemory {
  const newAction: ActionRecord = {
    timestamp: Date.now(),
    tool,
    args,
    result,
    stepId: memory.currentStepIndex,
  };
  // Cap action history to prevent memory growth
  const history = memory.actionHistory.length >= MAX_ACTION_HISTORY
    ? [...memory.actionHistory.slice(1), newAction]
    : [...memory.actionHistory, newAction];
  return {
    ...memory,
    actionHistory: history,
    lastActionAt: Date.now(),
  };
}

export function addProductToMemory(
  memory: TaskMemory,
  product: ExtractedProduct
): TaskMemory {
  // Deduplicate by name + vendor
  const exists = memory.extractedProducts.some(
    (p) => p.name === product.name && p.vendor === product.vendor
  );
  if (exists) return memory;
  // Cap products to prevent memory growth
  const products = memory.extractedProducts.length >= MAX_EXTRACTED_PRODUCTS
    ? [...memory.extractedProducts.slice(1), product]
    : [...memory.extractedProducts, product];
  return {
    ...memory,
    extractedProducts: products,
  };
}

export function addVisitedUrl(memory: TaskMemory, url: string): TaskMemory {
  // Cap visited URLs to prevent memory growth
  const urls = memory.visitedUrls.length >= MAX_VISITED_URLS
    ? [...memory.visitedUrls.slice(1), url]
    : [...memory.visitedUrls, url];
  return {
    ...memory,
    visitedUrls: urls,
  };
}

export function advanceStep(memory: TaskMemory): TaskMemory {
  const plan = [...memory.plan];
  if (plan[memory.currentStepIndex]) {
    plan[memory.currentStepIndex] = {
      ...plan[memory.currentStepIndex],
      status: 'done',
    };
  }
  const nextIndex = memory.currentStepIndex + 1;
  if (plan[nextIndex]) {
    plan[nextIndex] = { ...plan[nextIndex], status: 'active' };
  }
  return { ...memory, plan, currentStepIndex: nextIndex };
}

export function markStepFailed(memory: TaskMemory, reason: string): TaskMemory {
  const plan = [...memory.plan];
  if (plan[memory.currentStepIndex]) {
    plan[memory.currentStepIndex] = {
      ...plan[memory.currentStepIndex],
      status: 'failed',
      result: reason,
    };
  }
  return {
    ...memory,
    plan,
    errorCount: memory.errorCount + 1,
  };
}

export function getMemorySummary(memory: TaskMemory): string {
  const parts: string[] = [];
  parts.push('=== TASK MEMORY ===');
  parts.push('Goal: ' + memory.goal);

  if (memory.plan.length > 0) {
    parts.push('');
    parts.push('Plan:');
    memory.plan.forEach((step) => {
      const marker =
        step.status === 'done' ? '[DONE]' :
        step.status === 'active' ? '[ACTIVE]' :
        step.status === 'failed' ? '[FAILED]' :
        step.status === 'skipped' ? '[SKIP]' :
        '[    ]';
      parts.push('  ' + marker + ' Step ' + step.id + ': ' + step.description);
    });
  }

  if (memory.extractedProducts.length > 0) {
    parts.push('');
    parts.push('Extracted Products (' + memory.extractedProducts.length + '):');
    memory.extractedProducts.forEach((p, i) => {
      parts.push(
        '  ' + (i + 1) + '. ' + p.name +
        ' | Price: ' + p.price +
        ' | Rating: ' + p.rating +
        ' | Reviews: ' + p.reviews +
        ' | Delivery: ' + p.delivery +
        ' | Vendor: ' + p.vendor
      );
    });
  }

  if (memory.visitedUrls.length > 0) {
    parts.push('');
    parts.push('Visited URLs: ' + memory.visitedUrls.slice(-5).join(', '));
  }

  parts.push('');
  parts.push('Actions taken: ' + memory.actionHistory.length);
  parts.push('Errors so far: ' + memory.errorCount + '/' + memory.maxErrors);
  parts.push('===================');
  return parts.join('\n');
}
