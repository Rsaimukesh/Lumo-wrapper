/**
 * Application constants
 */

// Application Info
export const APP_NAME = 'Lumo Browser';
export const APP_VERSION = '0.2.0';
export const APP_DESCRIPTION = 'AI-powered browser built on Chromium';

// Timeouts (milliseconds)
export const DEFAULT_TIMEOUT = 30000;
export const API_TIMEOUT = 60000;
export const AUTOMATION_TIMEOUT = 45000;
export const PAGE_LOAD_TIMEOUT = 30000;

// Limits
export const MAX_HISTORY_ENTRIES = 1000;
export const MAX_CONVERSATION_LENGTH = 100;
export const MAX_CONCURRENT_TABS = 20;
export const MAX_AUTOMATION_RETRIES = 3;
export const MAX_TOKENS_PER_REQUEST = 4096;

// Memory Targets
export const TARGET_MEMORY_USAGE = 2 * 1024 * 1024 * 1024; // 2 GB
export const MEMORY_WARNING_THRESHOLD = 1.5 * 1024 * 1024 * 1024; // 1.5 GB
export const MEMORY_CRITICAL_THRESHOLD = 1.8 * 1024 * 1024 * 1024; // 1.8 GB

const getEnvVar = (key: string): string | undefined => {
  if (typeof process !== 'undefined' && process.env) {
    return process.env[key];
  }
  return undefined;
};

// API Keys
export const OPENAI_API_KEY = getEnvVar('VITE_OPENAI_API_KEY') || '';
export const CLAUDE_API_KEY = getEnvVar('VITE_CLAUDE_API_KEY') || '';
export const GEMINI_API_KEY = getEnvVar('VITE_GEMINI_API_KEY') || '';

// LLM Models
export const LLM_MODELS = {
  OPENAI: {
    GPT4: 'gpt-4',
    GPT4_TURBO: 'gpt-4-turbo-preview',
    GPT35_TURBO: 'gpt-3.5-turbo',
  },
  CLAUDE: {
    CLAUDE3_OPUS: 'claude-3-opus-20240229',
    CLAUDE3_SONNET: 'claude-3-sonnet-20240229',
    CLAUDE3_HAIKU: 'claude-3-haiku-20240307',
  },
  GEMINI: {
    GEMINI_PRO: 'gemini-pro',
  },
};

// Default LLM Configuration
export const DEFAULT_LLM_CONFIG = {
  provider: 'openai' as const,
  model: LLM_MODELS.OPENAI.GPT35_TURBO,
  temperature: 0.7,
  maxTokens: 2048,
};

// System Prompts
export const SYSTEM_PROMPTS = {
  PLANNER: `You are an expert workflow planner. Your job is to break down user goals into concrete, actionable steps.
Each step should be clear, specific, and executable by a browser automation system.
Return a JSON array of actions with this format:
[
  {
    "type": "click|type|scroll|navigate|extract|wait|screenshot",
    "selector": "CSS selector (if applicable)",
    "value": "text value (if applicable)",
    "description": "human readable description"
  }
]`,

  BROWSER_AGENT: `You are a browser control agent. Execute the actions provided to you using the browser API.
Handle errors gracefully and report what you see on the page.
Confirm each action before executing it.`,

  VERIFICATION_AGENT: `You are a verification agent. Check if the outcome matches the expected result.
Provide detailed feedback about what succeeded and what failed.
Suggest corrections if needed.`,

  MEMORY_AGENT: `You are a memory agent. Store workflows, log executions, and maintain context.
Keep organized records of what the user has done and what they want to do.`,
};

// Database
export const DATABASE_NAME = 'lumo_browser.db';
export const DATABASE_VERSION = 1;

// UI Constants
export const SIDEBAR_WIDTH = 400;
export const MIN_SIDEBAR_WIDTH = 300;
export const MAX_SIDEBAR_WIDTH = 600;
export const TOOLBAR_HEIGHT = 48;
export const ADDRESS_BAR_HEIGHT = 40;

// Theme
export const THEME = {
  LIGHT: 'light',
  DARK: 'dark',
  SYSTEM: 'system',
} as const;

// Permissions
export const SENSITIVE_SCOPES = [
  'execute:purchase',
  'execute:payment',
  'execute:password_change',
  'execute:send_message',
] as const;

// Logging
export enum LogLevel {
  TRACE = 'trace',
  DEBUG = 'debug',
  INFO = 'info',
  WARN = 'warn',
  ERROR = 'error',
}

export const LOG_LEVEL = getEnvVar('VITE_DEBUG') ? LogLevel.DEBUG : LogLevel.INFO;

// File Paths (for Electron context)
export const CONFIG_PATHS = {
  HOME: typeof process !== 'undefined' ? (process.env.HOME || '') : '',
  CONFIG_DIR: typeof process !== 'undefined' && process.env.HOME ? `${process.env.HOME}/.lumo` : '',
  DB_PATH: typeof process !== 'undefined' && process.env.HOME ? `${process.env.HOME}/.lumo/lumo_browser.db` : '',
  CACHE_DIR: typeof process !== 'undefined' && process.env.HOME ? `${process.env.HOME}/.lumo/cache` : '',
};

// Automation
export const AUTOMATION = {
  DEFAULT_WAIT_TIME: 1000,
  MAX_WAIT_TIME: 10000,
  RETRY_INTERVAL: 1000,
  PAGE_READY_TIMEOUT: 5000,
};

// Cache
export const CACHE = {
  TTL_SHORT: 5 * 60 * 1000, // 5 minutes
  TTL_MEDIUM: 30 * 60 * 1000, // 30 minutes
  TTL_LONG: 24 * 60 * 60 * 1000, // 24 hours
};
