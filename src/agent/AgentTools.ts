/**
 * AgentTools — Complete tool definitions for the autonomous browser agent.
 *
 * Provides an expanded set of browser-control primitives far beyond
 * the original navigate/click/type/done set: scrolling, hovering, text
 * extraction, product comparison, waiting, form submission, key presses,
 * and a critical "request_user_confirmation" gate for irreversible actions.
 */

export const AGENT_TOOLS = [
  {
    type: 'function' as const,
    function: {
      name: 'navigate',
      description: 'Navigate the browser to a specific URL. Use this to open websites or go to specific pages.',
      parameters: {
        type: 'object',
        properties: {
          url: { type: 'string', description: 'The full URL to navigate to (must start with http:// or https://)' },
        },
        required: ['url'],
      },
    },
  },
  {
    type: 'function' as const,
    function: {
      name: 'click',
      description: 'Click an interactive element on the page by its numerical [ID]. Use for buttons, links, checkboxes, etc.',
      parameters: {
        type: 'object',
        properties: {
          id: { type: 'integer', description: 'The numerical ID of the element to click' },
          description: { type: 'string', description: 'Brief description of what you are clicking and why' },
        },
        required: ['id'],
      },
    },
  },
  {
    type: 'function' as const,
    function: {
      name: 'click_at',
      description: 'Click at exact pixel coordinates (x, y) on the page. Use when the target element is visible in the screenshot but NOT listed in the tagged element list, or when you want to use the visual coordinates directly.',
      parameters: {
        type: 'object',
        properties: {
          x: { type: 'integer', description: 'Horizontal pixel coordinate to click' },
          y: { type: 'integer', description: 'Vertical pixel coordinate to click' },
          description: { type: 'string', description: 'What you are clicking and why' },
        },
        required: ['x', 'y'],
      },
    },
  },
  {
    type: 'function' as const,
    function: {
      name: 'type_text',
      description: 'Type or replace text in an input field, textarea, or search box by its numerical [ID]. Also fires input/change events to trigger frontend updates.',
      parameters: {
        type: 'object',
        properties: {
          id: { type: 'integer', description: 'The numerical ID of the input element' },
          text: { type: 'string', description: 'The text to type into the field' },
          clear_first: { type: 'boolean', description: 'Whether to clear existing text before typing. Default true.' },
          press_enter: { type: 'boolean', description: 'Whether to press Enter after typing. Useful for search boxes.' },
        },
        required: ['id', 'text'],
      },
    },
  },
  {
    type: 'function' as const,
    function: {
      name: 'scroll',
      description: 'Scroll the page up or down to reveal more content. Use when elements are not visible or you need to see more products/results.',
      parameters: {
        type: 'object',
        properties: {
          direction: { type: 'string', enum: ['up', 'down'], description: 'Direction to scroll' },
          amount: { type: 'integer', description: 'Pixels to scroll. Default 500. Use 1000+ for large jumps.' },
        },
        required: ['direction'],
      },
    },
  },
  {
    type: 'function' as const,
    function: {
      name: 'read_page_text',
      description: 'Read the visible text content of the current page (excluding interactive elements). Use this to understand page content, read product details, reviews, prices, or article text.',
      parameters: {
        type: 'object',
        properties: {
          max_length: { type: 'integer', description: 'Maximum characters to return. Default 3000.' },
        },
      },
    },
  },
  {
    type: 'function' as const,
    function: {
      name: 'extract_product_data',
      description: 'Extract structured product information from the current page. Returns name, price, rating, reviews, delivery estimate if available. Use on product listing or detail pages.',
      parameters: {
        type: 'object',
        properties: {
          vendor: { type: 'string', description: 'The vendor/store name (e.g., Amazon, Flipkart, Croma)' },
          max_products: { type: 'integer', description: 'Maximum number of products to extract. Default 5.' },
        },
        required: ['vendor'],
      },
    },
  },
  {
    type: 'function' as const,
    function: {
      name: 'press_key',
      description: 'Press a keyboard key. Useful for Enter, Escape, Tab, Arrow keys, etc.',
      parameters: {
        type: 'object',
        properties: {
          key: { type: 'string', description: 'Key to press: Enter, Escape, Tab, ArrowDown, ArrowUp, Backspace, etc.' },
        },
        required: ['key'],
      },
    },
  },
  {
    type: 'function' as const,
    function: {
      name: 'wait',
      description: 'Wait for a specified duration. Use after navigation, clicking, or form submission to let the page load.',
      parameters: {
        type: 'object',
        properties: {
          seconds: { type: 'number', description: 'Seconds to wait. Range: 0.5 to 10.' },
          reason: { type: 'string', description: 'Why you are waiting (e.g., "waiting for page to load")' },
        },
        required: ['seconds'],
      },
    },
  },
  {
    type: 'function' as const,
    function: {
      name: 'go_back',
      description: 'Navigate back to the previous page in browser history.',
      parameters: { type: 'object', properties: {} },
    },
  },
  {
    type: 'function' as const,
    function: {
      name: 'click_by_text',
      description: 'Click any element on the page by matching its visible text. PREFERRED for quiz/exam pages where answer options are labels or divs (not just radio buttons). Use this when you know the text of the answer choice you want to select.',
      parameters: {
        type: 'object',
        properties: {
          text: { type: 'string', description: 'The text content of the element to click (e.g., the answer option text like "Right-click on the desktop")' },
        },
        required: ['text'],
      },
    },
  },
  {
    type: 'function' as const,
    function: {
      name: 'quiz_answer',
      description: 'PRIMARY TOOL FOR QUIZZES AND EXAMS. Selects the correct answer option AND automatically clicks the Next/Submit button in one step. Use this for every single quiz question. Call read_page_text first to read the question, then call quiz_answer with the correct answer text.',
      parameters: {
        type: 'object',
        properties: {
          answer: {
            type: 'string',
            description: 'The exact text of the correct answer option as it appears on the page (e.g., "Right-click on the desktop, select Change Desktop Background and select a wallpaper"). Use a distinctive substring if the full text is very long.',
          },
          question_summary: {
            type: 'string',
            description: 'Brief summary of what the question was about (for logging)',
          },
        },
        required: ['answer'],
      },
    },
  },
  {
    type: 'function' as const,
    function: {
      name: 'request_user_confirmation',
      description: 'CRITICAL: You MUST call this before ANY purchase, payment, checkout, account change, form submission with personal data, or other irreversible action. The agent will pause and wait for the user to approve or reject. Describe exactly what will happen if the user approves.',
      parameters: {
        type: 'object',
        properties: {
          action_description: {
            type: 'string',
            description: 'Clear description of the irreversible action about to be taken. E.g., "Place order for Torch X at Rs. 499 on Amazon" or "Submit your credit card details"',
          },
          details: {
            type: 'string',
            description: 'Additional details: total price, items, quantities, delivery date, etc.',
          },
        },
        required: ['action_description'],
      },
    },
  },
  {
    type: 'function' as const,
    function: {
      name: 'save_product',
      description: 'Save a product to the comparison memory for later analysis. Call this when you find a product worth comparing.',
      parameters: {
        type: 'object',
        properties: {
          name: { type: 'string', description: 'Product name' },
          price: { type: 'string', description: 'Price as displayed (e.g., "Rs. 499")' },
          rating: { type: 'string', description: 'Rating (e.g., "4.5/5")' },
          reviews: { type: 'string', description: 'Number of reviews (e.g., "1,234 reviews")' },
          delivery: { type: 'string', description: 'Delivery estimate (e.g., "Tomorrow by 9 PM")' },
          url: { type: 'string', description: 'Product URL' },
          vendor: { type: 'string', description: 'Store/vendor name' },
        },
        required: ['name', 'price', 'vendor'],
      },
    },
  },
  {
    type: 'function' as const,
    function: {
      name: 'present_comparison',
      description: 'Present the saved products to the user in a formatted comparison table. Call this after extracting products from multiple sources to let the user choose the best option.',
      parameters: {
        type: 'object',
        properties: {
          recommendation: {
            type: 'string',
            description: 'Your recommendation and reasoning for the best product choice',
          },
        },
        required: ['recommendation'],
      },
    },
  },
  {
    type: 'function' as const,
    function: {
      name: 'update_plan',
      description: 'Update or create the step-by-step execution plan. Call this at the start to break the goal into steps, or mid-task to revise the plan based on new information.',
      parameters: {
        type: 'object',
        properties: {
          steps: {
            type: 'array',
            items: { type: 'string' },
            description: 'Array of step descriptions in execution order',
          },
          current_step: { type: 'integer', description: 'Index of the currently active step (0-based)' },
        },
        required: ['steps'],
      },
    },
  },
  {
    type: 'function' as const,
    function: {
      name: 'done',
      description: 'Call this when the user goal has been completely achieved OR when you cannot proceed further.',
      parameters: {
        type: 'object',
        properties: {
          message: { type: 'string', description: 'Summary of what was accomplished' },
          success: { type: 'boolean', description: 'Whether the goal was achieved successfully' },
        },
        required: ['message', 'success'],
      },
    },
  },
];

/** Dangerous actions that MUST trigger confirmation before execution */
export const DANGEROUS_ACTIONS = [
  'place order',
  'buy now',
  'purchase',
  'checkout',
  'pay',
  'payment',
  'confirm order',
  'submit order',
  'complete purchase',
  'add to cart and checkout',
  'delete account',
  'change password',
  'send money',
  'transfer',
  'unsubscribe',
  'wire transfer',
  'authorize payment',
  'confirm transfer',
  'close account',
  'revoke access',
  'install software',
  'grant permissions',
  'share credentials',
];
