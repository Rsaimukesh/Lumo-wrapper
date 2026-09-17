/**
 * Security Monitor — Phase 1 + Phase 2 + Phase 3 Pipeline
 *
 * Phase 1: Attaches real-time interception hooks to Electron sessions and relays
 * structured SecurityEvent payloads to the renderer process over IPC.
 *
 * Phase 2: Runs every event through the detection engine before sending it to
 * the renderer. High-confidence threats trigger additional security alerts.
 *
 * Phase 3: In zero-trust mode, actively blocks unrecognized network requests
 * and requests user permission before allowing them.
 */

import { BrowserWindow } from 'electron';
import { analyzeEvent } from './securityDetector';
import { guardedOn, guardedHandle } from './ipc-guard';

// ── Types (mirrored from src/types/electron.d.ts) ─────────────────────────────
interface DetectionResult {
  safe: boolean;
  threat?: string;
  confidence: number;
  category: 'phishing' | 'malware' | 'cryptominer' | 'data_theft' | 'injection' | 'safe';
  action?: 'allow' | 'warn' | 'block';
}

interface SecurityEvent {
  type: 'network_request' | 'dom_mutation' | 'browser_api' | 'wasm_exec' | 'file_io' | 'permission_request' | 'user_event';
  details: string;
  timestamp: string;
  source?: string;
  suspicious?: boolean;
  mitigated?: boolean;
  detection?: DetectionResult;
}

interface SecurityAlert {
  id: string;
  event: SecurityEvent;
  detection: DetectionResult;
  timestamp: string;
  acknowledged: boolean;
}

// ── State ─────────────────────────────────────────────────────────────────────
let monitorEnabled = true;
let alertCounter = 0;

// Rate-limit: don't flood the renderer with events faster than it can process
const THROTTLE_INTERVAL_MS = 100;
let lastSendTimestamp = 0;
const eventQueue: SecurityEvent[] = [];
const MAX_EVENT_QUEUE_SIZE = 500;
let flushTimer: NodeJS.Timeout | null = null;

// Alert threshold — only fire lumo:security-alert for high-confidence threats
const ALERT_CONFIDENCE_THRESHOLD = 70;

// Zero-trust permission cache: maps hostname → 'allow' | 'block'
const permissionCache = new Map<string, 'allow' | 'block'>();

import { isZeroTrustMode } from './ipc-guard';
import { addUserAllowListDomain } from './securityDetector';
import { extractHost } from './securityDetector';

export function isZeroTrustSession(): boolean {
  return isZeroTrustMode();
}

function getPermissionCacheKey(host: string): string {
  return host.toLowerCase();
}

function checkCachedPermission(host: string): 'allow' | 'block' | null {
  const cached = permissionCache.get(getPermissionCacheKey(host));
  return cached || null;
}

function cachePermission(host: string, decision: 'allow' | 'allow-once' | 'block'): void {
  if (decision === 'allow-once') {
    permissionCache.delete(getPermissionCacheKey(host));
    return;
  }
  permissionCache.set(getPermissionCacheKey(host), decision);
  if (decision === 'allow') {
    addUserAllowListDomain(host);
  }
}

/**
 * Send a security event to the active renderer window.
 * Phase 2: Events are analyzed by the detection engine before being sent.
 * Events are batched and rate-limited to avoid IPC flooding.
 */
function emitSecurityEvent(win: BrowserWindow | null, event: SecurityEvent): void {
  if (!monitorEnabled || !win || win.isDestroyed()) return;

  // ── Phase 2: Run detection analysis ────────────────────────────────────────
  const detection = analyzeEvent(event);
  event.detection = detection;

  // Update the suspicious flag based on detection
  if (!detection.safe) {
    event.suspicious = true;
  }

  // Queue the enriched event for batched delivery
  // Enforce queue size limit to prevent memory growth
  if (eventQueue.length >= MAX_EVENT_QUEUE_SIZE) {
    eventQueue.shift(); // Drop oldest event
  }
  eventQueue.push(event);

  // If the threat confidence exceeds the threshold, send an immediate alert
  if (!detection.safe && detection.confidence >= ALERT_CONFIDENCE_THRESHOLD) {
    // Auto-isolate in ZT mode for very high-confidence threats
    if (isZeroTrustMode() && detection.confidence >= 90 && detection.action === 'block') {
      win.webContents.send('lumo:isolate-tab', {
        threat: detection.threat,
        confidence: detection.confidence,
        category: detection.category,
        source: event.source,
        timestamp: new Date().toISOString(),
      });
      console.log(
        `[SecurityMonitor] 🔒 Auto-isolating tab: ${detection.category.toUpperCase()} — ${detection.threat}`
      );
    }
    const alert: SecurityAlert = {
      id: `alert-${Date.now()}-${++alertCounter}`,
      event,
      detection,
      timestamp: new Date().toISOString(),
      acknowledged: false,
    };

    win.webContents.send('lumo:security-alert', alert);
    console.log(
      `[SecurityDetector] ⚠ ALERT #${alertCounter}: ${detection.category.toUpperCase()} — ${detection.threat} (confidence: ${detection.confidence}%)`
    );
  }

  const now = Date.now();
  if (now - lastSendTimestamp >= THROTTLE_INTERVAL_MS) {
    flushEvents(win);
  } else if (!flushTimer) {
    flushTimer = setTimeout(() => {
      flushEvents(win);
    }, THROTTLE_INTERVAL_MS);
  }
}

function flushEvents(win: BrowserWindow | null): void {
  if (!win || win.isDestroyed() || eventQueue.length === 0) return;

  // Send all queued events in a batch
  for (const event of eventQueue) {
    win.webContents.send('lumo:security-event', event);
  }
  eventQueue.length = 0;
  lastSendTimestamp = Date.now();
  flushTimer = null;
}

/**
 * Truncate a URL to a reasonable display length for log readability.
 */
function truncateUrl(url: string, maxLen = 120): string {
  if (url.length <= maxLen) return url;
  return url.substring(0, maxLen - 3) + '...';
}

/**
 * Classify a network request by its resource type for human-readable logging.
 */
function classifyResourceType(url: string): string {
  const lower = url.toLowerCase();
  if (lower.match(/\.(js|mjs|cjs)(\?|$)/)) return 'Script';
  if (lower.match(/\.(css)(\?|$)/)) return 'Stylesheet';
  if (lower.match(/\.(png|jpg|jpeg|gif|svg|webp|ico|avif)(\?|$)/)) return 'Image';
  if (lower.match(/\.(woff2?|ttf|otf|eot)(\?|$)/)) return 'Font';
  if (lower.match(/\.(mp4|webm|ogg|mp3|wav|flac)(\?|$)/)) return 'Media';
  if (lower.match(/\.(json|xml)(\?|$)/)) return 'Data';
  if (lower.match(/\.(wasm)(\?|$)/)) return 'WebAssembly';
  if (lower.includes('/api/') || lower.includes('/graphql')) return 'API';
  return 'Document';
}

// ── Network Request Monitor ───────────────────────────────────────────────────

/**
 * Attach network request monitoring to an Electron session.
 * Logs all outbound requests and emits SecurityEvent payloads.
 * Phase 3: Actively blocks malicious requests using onBeforeRequest,
 * while preserving ad-blocker functionality.
 */
export interface AdBlockerResult {
  blocked: boolean;
  injectScript?: string;
}

const injectedPages = new Set<number>();
const INJECTED_PAGES_CLEANUP_INTERVAL = 60_000;
let lastInjectedPagesCleanup = Date.now();

// Clean up stale injectedPages entries periodically
function cleanupInjectedPages(): void {
  const now = Date.now();
  if (now - lastInjectedPagesCleanup < INJECTED_PAGES_CLEANUP_INTERVAL) return;
  lastInjectedPagesCleanup = now;
  // Note: We can't check if webContents is alive from the Set alone,
  // so we just cap the size. Entries will be naturally replaced as
  // webviews are recreated.
  if (injectedPages.size > 100) {
    // Clear half the oldest-looking entries (approximate)
    const arr = Array.from(injectedPages);
    for (let i = 0; i < Math.floor(arr.length / 2); i++) {
      injectedPages.delete(arr[i]);
    }
  }
}

const RESOURCE_TYPE_MAP: Record<string, string> = {
  mainFrame: 'document',
  subFrame: 'subdocument',
  script: 'script',
  image: 'image',
  stylesheet: 'stylesheet',
  xhr: 'xmlhttprequest',
  font: 'font',
  media: 'media',
  webSocket: 'websocket',
  ping: 'ping',
  other: 'other',
};

export function monitorNetworkRequests(
  sess: Electron.Session,
  getMainWindow: () => BrowserWindow | null,
  sessionLabel: string,
  adBlockerCheck?: (url: string, resourceType: string) => AdBlockerResult
): void {
  sess.webRequest.onBeforeRequest(
    { urls: ['<all_urls>'] },
    (details, callback) => {
      // Cleanup stale injectedPages entries periodically
      cleanupInjectedPages();

      // 1. Ad Blocker Check (preserve existing functionality)
      if (adBlockerCheck) {
        const resourceType = RESOURCE_TYPE_MAP[details.resourceType] ?? details.resourceType;
        const adResult = adBlockerCheck(details.url, resourceType);

        // Inject YouTube patch script into the page (once per page load)
        if (adResult.injectScript) {
          const wcId = details.webContentsId;
          if (wcId && !injectedPages.has(wcId)) {
            injectedPages.add(wcId);
            const { webContents } = require('electron');
            const wc = webContents.fromId(wcId);
            if (wc && !wc.isDestroyed()) {
              wc.executeJavaScript(adResult.injectScript)
                .then(() => console.log(`[${sessionLabel}] Injected YouTube patch script`))
                .catch((err: unknown) => console.warn(`[${sessionLabel}] Failed to inject script:`, err));
            }
          }
        }

        if (adResult.blocked) {
          return callback({ cancel: true });
        }
      }

      // 2. Phase 3 Security Mitigation Check
      if (monitorEnabled) {
        // Validate URL against Phase 2 detection engine
        const detection = analyzeEvent({
          type: 'network_request',
          details: `GET ${details.url}`,
          timestamp: new Date().toISOString(),
          source: sessionLabel,
        });

        const isMalicious = detection.action === 'block';
        const isWarn = detection.action === 'warn';
        const resourceType = classifyResourceType(details.url);
        const isNoise = ['Image', 'Font', 'Stylesheet'].includes(resourceType);

        if (isMalicious) {
          console.log(`[SecurityMonitor] 🛡️ MITIGATED: Blocked malicious network request: ${details.url}`);

          const event: SecurityEvent = {
            type: 'network_request',
            details: `[${resourceType}] Blocked ${details.method} ${truncateUrl(details.url)}`,
            timestamp: new Date().toISOString(),
            source: sessionLabel,
            suspicious: true,
            detection: detection,
            mitigated: true,
          };
          emitSecurityEvent(getMainWindow(), event);

          return callback({ cancel: true });
        }

        // Zero-trust mode: handle unrecognized domains via permission cache
        if (isZeroTrustMode() && isWarn) {
          const host = extractHost(details.url);
          const cached = checkCachedPermission(host);

          if (cached === 'allow') {
            // User previously allowed this domain — let it through
            return callback({ cancel: false });
          }

          if (cached !== 'block') {
            // First time seeing this domain in ZT mode — block and ask
            console.log(`[SecurityMonitor] 🔒 ZT mode: blocking unrecognized ${host}, requesting permission`);
            cachePermission(host, 'block'); // default to block until user responds

            const event: SecurityEvent = {
              type: 'network_request',
              details: `[${resourceType}] ZT-Blocked ${details.method} ${truncateUrl(details.url)} — awaiting permission`,
              timestamp: new Date().toISOString(),
              source: sessionLabel,
              suspicious: true,
              detection: detection,
              mitigated: true,
            };
            emitSecurityEvent(getMainWindow(), event);

            // Notify the renderer to show a permission dialog
            const win = getMainWindow();
            if (win && !win.isDestroyed()) {
              win.webContents.send('lumo:permission-request', {
                url: details.url,
                host,
                resourceType,
                sessionLabel,
                timestamp: new Date().toISOString(),
              });
            }
          }

          return callback({ cancel: true });
        }

        if (!isNoise) {
          const event: SecurityEvent = {
            type: 'network_request',
            details: `[${resourceType}] ${details.method} ${truncateUrl(details.url)}`,
            timestamp: new Date().toISOString(),
            source: sessionLabel,
          };
          emitSecurityEvent(getMainWindow(), event);
        }
      }

      // 3. Allow request if no checks failed
      callback({ cancel: false });
    }
  );

  console.log(`[SecurityMonitor] Network monitoring & mitigation attached to session: ${sessionLabel}`);
}

// ── IPC Handlers for Preload Bridge ───────────────────────────────────────────

/**
 * Register IPC handlers that the preload script uses to relay
 * DOM mutations, API hooks, and WebAssembly interceptions.
 */
export function registerSecurityIPC(getMainWindow: () => BrowserWindow | null): void {
  // Receive security events from the preload script (runs inside webview/renderer)
  guardedOn('lumo:security-event-from-preload', (_ipcEvent, payload: SecurityEvent) => {
    const win = getMainWindow();
    if (win && !win.isDestroyed()) {
      emitSecurityEvent(win, {
        ...payload,
        timestamp: payload.timestamp || new Date().toISOString(),
      });
    }
  });

  // Toggle monitoring on/off from the frontend
  guardedOn('lumo:set-security-monitor', (_event, enabled: boolean) => {
    monitorEnabled = enabled;
    console.log(`[SecurityMonitor] Monitoring ${enabled ? 'enabled' : 'disabled'}`);
  });

  // Provide current monitor state to the frontend
  guardedHandle('lumo:get-security-monitor-state', () => {
    return { enabled: monitorEnabled, alertCount: alertCounter };
  });

  // Handle user permission decisions for zero-trust mode
  guardedOn('lumo:permission-decision', (_event, { host, decision }: { host: string; decision: 'allow' | 'allow-once' | 'block' }) => {
    cachePermission(host, decision);
    console.log(`[SecurityMonitor] 🔒 ZT permission decision: ${decision} for ${host}`);
  });

  console.log('[SecurityMonitor] IPC handlers registered (Phase 1 + Phase 2 + ZT)');
}

