/**
 * Security Detector — Phase 2: The Detect Stage
 *
 * Analyzes SecurityEvents from the Monitor stage and determines whether
 * they represent malicious, suspicious, or safe activity.
 *
 * This module runs in the Main Process (Node.js) so the detection logic
 * is secure and cannot be tampered with by web pages.
 *
 * Detection is PASSIVE — it flags and reports, but does NOT block.
 * Blocking is handled in Phase 3 (Mitigate).
 */

// ── Types (mirrored from src/types/electron.d.ts) ─────────────────────────────
type DetectionCategory = 'phishing' | 'malware' | 'cryptominer' | 'data_theft' | 'injection' | 'safe';
type DetectionAction = 'allow' | 'warn' | 'block';

interface DetectionResult {
  safe: boolean;
  threat?: string;
  confidence: number;
  category: DetectionCategory;
  action?: DetectionAction;
}

interface SecurityEvent {
  type: string;
  details: string;
  timestamp: string;
  source?: string;
  suspicious?: boolean;
  detection?: DetectionResult;
}

// ── Allow-List for Zero-Trust Mode ────────────────────────────────────────────
// Known-safe domains that are always allowed in zero-trust mode.
// This list ships as the default; users can extend it via the permission dialog.

const ALLOW_LIST_DOMAINS: string[] = [
  'google.com', 'www.google.com', 'accounts.google.com', 'apis.google.com',
  'fonts.googleapis.com', 'fonts.gstatic.com', 'www.gstatic.com', 'gstatic.com',
  'recaptcha.net', 'www.recaptcha.net',
  'github.com', 'www.github.com', 'api.github.com', 'raw.githubusercontent.com',
  'openrouter.ai', 'api.openrouter.ai',
  'bing.com', 'www.bing.com', 'api.bing.com',
  'duckduckgo.com', 'www.duckduckgo.com',
  'brave.com', 'www.brave.com', 'api.brave.com',
  'chatgpt.com', 'www.chatgpt.com', 'api.openai.com',
  'claude.ai', 'www.claude.ai',
  'gemini.google.com',
  'perplexity.ai', 'www.perplexity.ai',
  'deepseek.com', 'www.deepseek.com', 'api.deepseek.com',
  'grok.com', 'x.ai',
  'facebook.com', 'www.facebook.com', 'connect.facebook.net',
  'twitter.com', 'www.twitter.com', 'x.com', 'www.x.com',
  'instagram.com', 'www.instagram.com',
  'linkedin.com', 'www.linkedin.com',
  'youtube.com', 'www.youtube.com', 'ytimg.com',
  'reddit.com', 'www.reddit.com',
  'amazon.com', 'www.amazon.com', 'amazon.in', 'www.amazon.in',
  'flipkart.com', 'www.flipkart.com',
  'croma.com', 'www.croma.com',
  'cloudflare.com', 'cdnjs.cloudflare.com', 'ajax.cloudflare.com',
  'jsdelivr.net', 'cdn.jsdelivr.net',
  'unpkg.com',
  'fontawesome.com', 'use.fontawesome.com',
  'stripe.com', 'js.stripe.com',
  'paypal.com', 'www.paypal.com',
  'datadoghq.com', 'www.datadoghq.com',
  'sentry.io',
  'hotjar.com',
  'hubspot.com',
];

const USER_ALLOW_LIST: string[] = [];

function isDomainAllowListed(host: string): boolean {
  const lower = host.toLowerCase();
  for (const allowed of ALLOW_LIST_DOMAINS) {
    if (lower === allowed || lower.endsWith('.' + allowed)) {
      return true;
    }
  }
  for (const allowed of USER_ALLOW_LIST) {
    const a = allowed.toLowerCase();
    if (lower === a || lower.endsWith('.' + a)) {
      return true;
    }
  }
  return false;
}

export function addUserAllowListDomain(domain: string): void {
  const d = domain.toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '').trim();
  if (d && !USER_ALLOW_LIST.includes(d)) {
    USER_ALLOW_LIST.push(d);
  }
}

import { isZeroTrustMode } from './ipc-guard';

// ── Malicious Domain Blocklist ────────────────────────────────────────────────
// Patterns for known malicious TLDs, phishing domains, and suspicious hosts.

const MALICIOUS_TLD_PATTERNS: string[] = [
  '.zip', '.mov', '.gq', '.click', '.tk', '.ml', '.cf', '.ga',
  '.su', '.top', '.buzz', '.xyz', '.icu', '.rest', '.cam',
  '.ru', '.cn', '.cc', '.ws', '.work', '.life', '.fun', '.vip',
  '.today', '.date', '.racing', '.review', '.stream', '.trade',
  '.webcam', '.win', '.accountant', '.science', '.party', '.faith',
  '.loan', '.cricket',
];

const PHISHING_DOMAIN_PATTERNS: RegExp[] = [
  /login[_-]?verify[_-]?account/i,
  /paypal[_-]?secure/i,
  /google\.com[_-]/i,
  /apple[_-]?id[_-]?verify/i,
  /microsoft[_-]?login/i,
  /secure[_-]?banking/i,
  /account[_-]?confirm/i,
  /verify[_-]?identity/i,
  /update[_-]?payment/i,
  /suspended[_-]?account/i,
  /unusual[_-]?activity/i,
  /security[_-]?alert/i,
  /recover[_-]?password/i,
  /signin[_-]?help/i,
  /icloud[_-]?verify/i,
  /dropbox[_-]?share/i,
  /wetransfer[_-]?download/i,
  /invoice[_-]?payment/i,
  /fedex[_-]?tracking/i,
  /dhl[_-]?delivery/i,
  /amazon[_-]?order/i,
  /netflix[_-]?update/i,
  /facebook[_-]?security/i,
  /instagram[_-]?verify/i,
  /linkedin[_-]?confirm/i,
  /twitter[_-]?verify/i,
  /chase[_-]?secure/i,
  /wellsfargo[_-]?alert/i,
  /bankofamerica[_-]?secure/i,
  /citi[_-]?alert/i,
  /usps[_-]?tracking/i,
  /irs[_-]?refund/i,
  /coinbase[_-]?verify/i,
  /binance[_-]?security/i,
  /metamask[_-]?connect/i,
  /wallet[_-]?connect[_-]?verify/i,
];

const CRYPTO_MINING_DOMAINS: string[] = [
  'coinhive.com', 'coin-hive.com', 'crypto-loot.com', 'cryptoloot.pro',
  'minero.cc', 'monerominer.rocks', 'webmine.cz', 'jsecoin.com',
  'authedmine.com', 'ppoi.org', 'cryptonight.wasm', 'coinimp.com',
  'mineralt.io', 'webminepool.com', 'cloudcoins.co',
];

// ── Script Obfuscation Signatures ─────────────────────────────────────────────
const OBFUSCATION_PATTERNS: RegExp[] = [
  /eval\s*\(/i,
  /atob\s*\(/i,
  /String\.fromCharCode/i,
  /document\.write\s*\(/i,
  /\\x[0-9a-f]{2}/i,
  /\\u00[0-9a-f]{2}/i,
  /unescape\s*\(/i,
  /decodeURIComponent\s*\(/i,
  /Function\s*\(\s*["']/i,
  /\bcharCodeAt\b.*\bfromCharCode\b/i,
  /window\s*\[\s*["']eval["']\s*\]/i,
];

const CRYPTO_MINING_SIGNATURES: RegExp[] = [
  /coinhive/i,
  /cryptonight/i,
  /minero/i,
  /xmrig/i,
  /hashrate/i,
  /stratum\+tcp/i,
  /monero/i,
  /CryptoNight/i,
  /wasm.*miner/i,
  /mining[_-]?pool/i,
  /coin[_-]?imp/i,
];

// Crypto wallet address patterns for clipboard hijack detection
const CRYPTO_WALLET_PATTERNS: RegExp[] = [
  /^0x[0-9a-fA-F]{40}$/,                      // Ethereum
  /^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$/,        // Bitcoin legacy
  /^bc1[a-zA-HJ-NP-Z0-9]{39,59}$/,            // Bitcoin bech32
  /^[LM3][a-km-zA-HJ-NP-Z1-9]{26,33}$/,       // Litecoin
  /^4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}$/,       // Monero
  /^T[A-Za-z1-9]{33}$/,                         // Tron
  /^r[0-9a-zA-Z]{24,34}$/,                      // Ripple
  /^[A-Z2-7]{56}$/,                             // Stellar
];

// ── Helper: Extract hostname from URL ─────────────────────────────────────────
export function extractHost(url: string): string {
  try {
    const parsed = new URL(url);
    return parsed.hostname.toLowerCase();
  } catch {
    // Try to extract from malformed URLs
    const match = url.match(/https?:\/\/([^/:?#]+)/i);
    return match ? match[1].toLowerCase() : '';
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// PUBLIC DETECTION FUNCTIONS
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Validate a URL against the local blocklist and heuristic checks.
 */
export function validateUrl(url: string): DetectionResult {
  if (!url || url.startsWith('lumo://') || url.startsWith('chrome://') || url.startsWith('devtools://')) {
    return { safe: true, confidence: 100, category: 'safe', action: 'allow' };
  }

  const host = extractHost(url);
  if (!host) {
    return { safe: true, confidence: 50, category: 'safe', action: 'allow' };
  }

  // 1. Check against known crypto mining domains
  for (const domain of CRYPTO_MINING_DOMAINS) {
    if (host === domain || host.endsWith('.' + domain)) {
      console.log(`[SecurityDetector] BLOCKED mining domain: ${host}`);
      return {
        safe: false,
        threat: `Known cryptominer domain detected: ${host}`,
        confidence: 95,
        category: 'cryptominer',
        action: 'block',
      };
    }
  }

  // 2. Check against malicious TLDs
  for (const tld of MALICIOUS_TLD_PATTERNS) {
    if (host.endsWith(tld)) {
      console.log(`[SecurityDetector] Suspicious TLD: ${host}`);
      return {
        safe: false,
        threat: `High-risk TLD detected: ${tld}`,
        confidence: 60,
        category: 'phishing',
        action: 'warn',
      };
    }
  }

  // 3. Check against phishing domain patterns (test against full URL, not just host)
  for (const pattern of PHISHING_DOMAIN_PATTERNS) {
    if (pattern.test(url)) {
      console.log(`[SecurityDetector] Phishing pattern match: ${url}`);
      return {
        safe: false,
        threat: `Phishing pattern detected in URL: ${host}`,
        confidence: 85,
        category: 'phishing',
        action: 'block',
      };
    }
  }

  // 4. IP-address-only hosts (no domain name)
  const ipv4Pattern = /^(\d{1,3}\.){3}\d{1,3}$/;
  if (ipv4Pattern.test(host)) {
    // Allow localhost/private IPs (common in development)
    if (host.startsWith('127.') || host.startsWith('192.168.') || host === '0.0.0.0') {
      return { safe: true, confidence: 70, category: 'safe', action: 'allow' };
    }
    console.log(`[SecurityDetector] IP-based host: ${host}`);
    return {
      safe: false,
      threat: `Direct IP address access — no domain name: ${host}`,
      confidence: 55,
      category: 'phishing',
      action: 'warn',
    };
  }

  // 5. Extremely long query strings (potential exfiltration)
  try {
    const parsed = new URL(url);
    if (parsed.search.length > 500) {
      console.log(`[SecurityDetector] Suspiciously long query string: ${parsed.search.length} chars`);
      return {
        safe: false,
        threat: `Abnormally long query string (${parsed.search.length} chars) — possible data exfiltration`,
        confidence: 50,
        category: 'data_theft',
        action: 'warn',
      };
    }
  } catch { /* ignore parse errors */ }

  // 6. Homograph / punycode attacks (xn-- encoded domains)
  if (host.includes('xn--')) {
    console.log(`[SecurityDetector] Punycode/IDN domain: ${host}`);
    return {
      safe: false,
      threat: `Internationalized Domain Name (punycode) detected: ${host} — potential homograph attack`,
      confidence: 65,
      category: 'phishing',
      action: 'warn',
    };
  }

  // 7. Data URIs with base64 (potential script injection)
  if (url.startsWith('data:') && url.includes('base64')) {
    console.log(`[SecurityDetector] Base64 data URI detected`);
    return {
      safe: false,
      threat: 'Base64-encoded data URI detected — potential script injection vector',
      confidence: 70,
      category: 'injection',
      action: 'warn',
    };
  }

  // 8. Zero-trust mode: check allow-list before defaulting
  if (isZeroTrustMode()) {
    if (isDomainAllowListed(host)) {
      return { safe: true, confidence: 90, category: 'safe', action: 'allow' };
    }
    // In ZT mode, unrecognized domains get a warning (block decision
    // is made by the monitor after checking for user permission)
    return {
      safe: false,
      threat: `Unrecognized domain in zero-trust mode: ${host}`,
      confidence: 40,
      category: 'safe',
      action: 'warn',
    };
  }

  return { safe: true, confidence: 90, category: 'safe', action: 'allow' };
}

/**
 * Analyze injected script characteristics for obfuscation or mining signatures.
 */
export function analyzeScriptHeuristics(details: string): DetectionResult {
  const lower = details.toLowerCase();

  // 1. Check for crypto mining signatures in script content/URL
  for (const pattern of CRYPTO_MINING_SIGNATURES) {
    if (pattern.test(details)) {
      console.log(`[SecurityDetector] Crypto mining script signature detected`);
      return {
        safe: false,
        threat: `Crypto mining script detected: ${pattern.source}`,
        confidence: 92,
        category: 'cryptominer',
        action: 'block',
      };
    }
  }

  // 2. Check for obfuscation patterns
  const obfuscationHits: string[] = [];
  for (const pattern of OBFUSCATION_PATTERNS) {
    if (pattern.test(details)) {
      obfuscationHits.push(pattern.source);
    }
  }

  if (obfuscationHits.length >= 2) {
    // Multiple obfuscation indicators = high confidence
    console.log(`[SecurityDetector] Multiple obfuscation patterns: ${obfuscationHits.join(', ')}`);
    return {
      safe: false,
      threat: `Obfuscated script detected (${obfuscationHits.length} indicators: ${obfuscationHits.slice(0, 3).join(', ')})`,
      confidence: 80,
      category: 'malware',
      action: 'block',
    };
  } else if (obfuscationHits.length === 1) {
    return {
      safe: false,
      threat: `Suspicious script pattern: ${obfuscationHits[0]}`,
      confidence: 45,
      category: 'injection',
      action: 'warn',
    };
  }

  // 3. External scripts from IP-based hosts
  const ipScriptMatch = details.match(/https?:\/\/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/);
  if (ipScriptMatch) {
    console.log(`[SecurityDetector] Script loaded from IP address: ${ipScriptMatch[1]}`);
    return {
      safe: false,
      threat: `External script loaded from raw IP: ${ipScriptMatch[1]}`,
      confidence: 65,
      category: 'injection',
      action: 'warn',
    };
  }

  // 4. Very large inline scripts (>10KB text content)
  const inlineMatch = details.match(/Inline <script> injected \((\d+) chars\)/);
  if (inlineMatch) {
    const charCount = parseInt(inlineMatch[1], 10);
    if (charCount > 10000) {
      return {
        safe: false,
        threat: `Large inline script injected (${(charCount / 1024).toFixed(1)}KB) — possible payload delivery`,
        confidence: 55,
        category: 'injection',
        action: 'warn',
      };
    }
  }

  // 5. Hidden iframe detection (already flagged by preload, but re-evaluate)
  if (lower.includes('[hidden]') && lower.includes('<iframe>')) {
    return {
      safe: false,
      threat: 'Hidden iframe injection — potential clickjacking or tracking pixel',
      confidence: 75,
      category: 'injection',
      action: 'block',
    };
  }

  return { safe: true, confidence: 85, category: 'safe', action: 'allow' };
}

/**
 * Evaluate whether clipboard access is suspicious.
 */
export function evaluateClipboardAccess(event: SecurityEvent): DetectionResult {
  const details = event.details.toLowerCase();

  // Clipboard readText() is always suspicious from scripts
  if (details.includes('readtext')) {
    console.log(`[SecurityDetector] Clipboard read intercepted from: ${event.source}`);
    return {
      safe: false,
      threat: 'Unauthorized clipboard read attempt — script tried to access clipboard contents',
      confidence: 75,
      category: 'data_theft',
      action: 'warn',
    };
  }

  // Clipboard writeText() — check for crypto wallet address replacement
  if (details.includes('writetext')) {
    // Extract the content from the details string — handle different quote styles
    const contentMatch = event.details.match(/content:\s*["']([^"']+)["']/);
    if (contentMatch) {
      const content = contentMatch[1].trim();

      // Check if the written content matches any crypto wallet pattern
      for (const pattern of CRYPTO_WALLET_PATTERNS) {
        if (pattern.test(content)) {
          console.log(`[SecurityDetector] CRITICAL: Clipboard hijack detected — crypto wallet address replacement`);
          return {
            safe: false,
            threat: `Clipboard hijack detected — script replaced clipboard with crypto wallet address: ${content.substring(0, 20)}...`,
            confidence: 95,
            category: 'data_theft',
            action: 'block',
          };
        }
      }
    }

    // Even non-wallet writes are mildly suspicious
    return {
      safe: false,
      threat: 'Script modified clipboard contents',
      confidence: 35,
      category: 'data_theft',
      action: 'allow',
    };
  }

  return { safe: true, confidence: 80, category: 'safe', action: 'allow' };
}

/**
 * Evaluate WebAssembly execution for cryptominer indicators.
 */
export function evaluateWasmExecution(event: SecurityEvent): DetectionResult {
  const details = event.details;

  // Parse binary size from the event details
  const sizeMatch = details.match(/binary size:\s*([\d.]+)KB/i);
  const sizeKB = sizeMatch ? parseFloat(sizeMatch[1]) : 0;

  // Check source URL against known mining pools
  const source = (event.source || '').toLowerCase();
  for (const domain of CRYPTO_MINING_DOMAINS) {
    if (source.includes(domain)) {
      console.log(`[SecurityDetector] CRITICAL: WebAssembly from known mining pool: ${domain}`);
      return {
        safe: false,
        threat: `WebAssembly binary loaded from known mining pool: ${domain}`,
        confidence: 98,
        category: 'cryptominer',
        action: 'block',
      };
    }
  }

  // Large WebAssembly binaries (>1MB) are highly suspicious
  if (sizeKB > 1024) {
    console.log(`[SecurityDetector] Large WebAssembly binary: ${sizeKB.toFixed(0)}KB`);
    return {
      safe: false,
      threat: `Oversized WebAssembly binary (${(sizeKB / 1024).toFixed(1)}MB) — likely crypto miner`,
      confidence: 85,
      category: 'cryptominer',
      action: 'block',
    };
  }

  // Medium-sized binaries (256KB-1MB) get a warning
  if (sizeKB > 256) {
    return {
      safe: false,
      threat: `Large WebAssembly binary (${sizeKB.toFixed(0)}KB) — requires evaluation`,
      confidence: 55,
      category: 'cryptominer',
      action: 'warn',
    };
  }

  // All Wasm execution is at least medium risk
  return {
    safe: false,
    threat: 'WebAssembly module instantiated — monitoring execution',
    confidence: 30,
    category: 'safe',
    action: 'allow',
  };
}

// ═══════════════════════════════════════════════════════════════════════════════
// LEGACY COMPATIBILITY WRAPPERS
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Legacy wrapper around analyzeScriptHeuristics.
 * Accepts raw HTML string; also detects hidden iframes via inline style attributes
 * (without requiring the preload-added [hidden] prefix).
 */
export function checkDomMutation(html: string): DetectionResult {
  const lower = html.toLowerCase();
  if (lower.includes('<iframe') && (lower.includes('[hidden]') || lower.includes('display:none') || lower.includes('display: none') || lower.includes('hidden=""'))) {
    return {
      safe: false,
      threat: 'Hidden iframe injection — potential clickjacking or tracking pixel',
      confidence: 75,
      category: 'injection',
      action: 'block',
    };
  }
  return analyzeScriptHeuristics(html);
}

/**
 * Legacy wrapper around evaluateClipboardAccess.
 * Accepts raw clipboard content string.
 */
export function checkClipboardWrite(content: string): DetectionResult {
  return evaluateClipboardAccess({
    type: 'browser_api',
    details: `clipboard writeText content: "${content}"`,
    timestamp: new Date().toISOString(),
  });
}

/**
 * Legacy wrapper around evaluateWasmExecution.
 * Accepts raw byte count.
 */
export function checkWasmExecution(sizeBytes: number): DetectionResult {
  const sizeKB = sizeBytes / 1024;
  return evaluateWasmExecution({
    type: 'wasm_exec',
    details: `WebAssembly binary loaded (binary size: ${sizeKB.toFixed(1)}KB)`,
    timestamp: new Date().toISOString(),
  });
}

// ═══════════════════════════════════════════════════════════════════════════════
// MAIN ANALYSIS ROUTER
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Route a SecurityEvent to the appropriate detector and return the result.
 * This is the single entry point called by securityMonitor.ts
 */
export function analyzeEvent(event: SecurityEvent): DetectionResult {
  switch (event.type) {
    case 'network_request': {
      // Extract URL from the details string: "[Script] GET https://..."
      const urlMatch = event.details.match(/(?:GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD)\s+(\S+)/i);
      const url = urlMatch ? urlMatch[1] : event.source || '';
      return validateUrl(url);
    }

    case 'dom_mutation':
      return analyzeScriptHeuristics(event.details);

    case 'browser_api':
      return evaluateClipboardAccess(event);

    case 'wasm_exec':
      return evaluateWasmExecution(event);

    default:
      return { safe: true, confidence: 100, category: 'safe', action: 'allow' };
  }
}
