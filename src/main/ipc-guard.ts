/**
 * IPC Guard — origin validation and permission enforcement
 *
 * Wraps every IPC handler with origin/url validation.
 * In normal mode: blocks non-main-renderer calls to SENSITIVE/ADMIN channels.
 * In zero-trust mode: blocks non-main-renderer calls to SESSION/SENSITIVE/ADMIN channels.
 */

import { ipcMain, app } from 'electron';
import fs from 'fs';
import path from 'path';

type IpcPermission = 'PUBLIC' | 'SESSION' | 'SENSITIVE' | 'ADMIN';

const IPC_PERMISSIONS: Record<string, IpcPermission> = {
  'lumo:set-theme': 'PUBLIC',
  'lumo:set-default-zoom': 'PUBLIC',
  'lumo:window-minimize': 'PUBLIC',
  'lumo:window-maximize': 'PUBLIC',
  'lumo:window-close': 'PUBLIC',
  'lumo:set-spell-check': 'PUBLIC',
  'lumo:set-hardware-acceleration': 'PUBLIC',
  'lumo:set-memory-saver': 'PUBLIC',
  'lumo:toggle-devtools': 'PUBLIC',
  'lumo:set-ad-blocker': 'SESSION',
  'lumo:set-ad-blocker-config': 'SESSION',
  'lumo:get-ad-blocker-stats': 'SESSION',
  'lumo:reset-ad-blocker-stats': 'SESSION',
  'lumo:inspect-element': 'SESSION',
  'lumo:inspect-webview': 'SESSION',
  'lumo:save-screenshot': 'SESSION',
  'lumo:print-page': 'SESSION',
  'lumo:set-download-path': 'SESSION',
  'lumo:open-file': 'SESSION',
  'lumo:show-item-in-folder': 'SESSION',
  'lumo:open-downloads': 'SESSION',
  'lumo:set-proxy': 'SESSION',
  'lumo:set-private-proxy': 'SESSION',
  'lumo:test-proxy': 'SESSION',
  'lumo:resolve-dns': 'SESSION',
  'lumo:resolve-whois': 'SESSION',
  'lumo:resolve-headers': 'SESSION',
  'lumo:resolve-certificates': 'SESSION',
  'lumo:detect-tech': 'SESSION',
  'lumo:threat-intel': 'SESSION',
  'lumo:import-browser-data': 'SESSION',
  'lumo:save-key': 'SESSION',
  'lumo:load-key': 'SESSION',
  'lumo:openrouter-chat': 'SESSION',
  'lumo:capture-webview': 'SENSITIVE',
  'lumo:native-click': 'SENSITIVE',
  'lumo:native-key': 'SENSITIVE',
  'lumo:native-type': 'SENSITIVE',
  'lumo:security-event-from-preload': 'PUBLIC',
  'lumo:set-security-monitor': 'ADMIN',
  'lumo:get-security-monitor-state': 'SESSION',
  'lumo:new-disposable-window': 'ADMIN',
  'lumo:set-zero-trust-mode': 'ADMIN',
  'lumo:get-zero-trust-mode': 'PUBLIC',
  'lumo:permission-request': 'PUBLIC',
  'lumo:permission-decision': 'SESSION',
  'lumo:validate-agent-script': 'SESSION',
  'lumo:vault-get-all': 'SENSITIVE',
  'lumo:vault-save': 'SENSITIVE',
  'lumo:vault-delete': 'SENSITIVE',
};

let zeroTrustMode = false;
let _ztStorageReady = false;
const LOG_PREFIX = '[IPCGate]';

function ztStatePath(): string {
  return path.join(app.getPath('userData'), 'zero-trust-state.json');
}

function persistZeroTrustMode(enabled: boolean): void {
  try {
    const dir = path.dirname(ztStatePath());
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(ztStatePath(), JSON.stringify({ enabled }), 'utf-8');
  } catch (err) {
    console.warn(`${LOG_PREFIX} Failed to persist ZT state:`, err);
  }
}

function loadZeroTrustMode(): boolean {
  try {
    if (!fs.existsSync(ztStatePath())) return false;
    return JSON.parse(fs.readFileSync(ztStatePath(), 'utf-8')).enabled === true;
  } catch {
    return false;
  }
}

// Lazily load persisted state on first access (app may not be ready at import time)
function ensureZtLoaded(): void {
  if (!_ztStorageReady) {
    try {
      zeroTrustMode = loadZeroTrustMode();
    } finally {
      _ztStorageReady = true;
    }
  }
}

const MAIN_RENDERER_ORIGINS = ['http://127.0.0.1:5173', 'file://'];

export function isZeroTrustMode(): boolean {
  ensureZtLoaded();
  return zeroTrustMode;
}

export function setZeroTrustMode(enabled: boolean): void {
  ensureZtLoaded();
  zeroTrustMode = enabled;
  persistZeroTrustMode(enabled);
  console.log(`${LOG_PREFIX} Zero-trust mode ${enabled ? 'ENABLED' : 'DISABLED'}`);
}

function getPermission(channel: string): IpcPermission {
  return IPC_PERMISSIONS[channel] || 'SENSITIVE';
}

function getSenderUrl(event: { senderFrame?: { url: string } }): string | null {
  return event.senderFrame?.url || null;
}

function isMainRenderer(url: string | null): boolean {
  if (!url) return false;
  return MAIN_RENDERER_ORIGINS.some((origin) => url.startsWith(origin));
}

function checkPermission(
  event: { senderFrame?: { url: string } },
  channel: string,
): { allowed: boolean; reason?: string } {
  const level = getPermission(channel);
  if (level === 'PUBLIC') return { allowed: true };

  const senderUrl = getSenderUrl(event);
  const senderIsMain = isMainRenderer(senderUrl);

  // ADMIN channels: only main renderer in normal mode, only main renderer in ZT mode
  if (level === 'ADMIN') {
    if (!senderIsMain) {
      return { allowed: false, reason: `ADMIN channel '${channel}' called from non-main renderer: ${senderUrl || 'unknown'}` };
    }
  }

  // SENSITIVE channels: only main renderer in both modes
  if (level === 'SENSITIVE') {
    if (!senderIsMain) {
      return { allowed: false, reason: `SENSITIVE channel '${channel}' called from non-main renderer: ${senderUrl || 'unknown'}` };
    }
  }

  // SESSION channels: blocked from non-main renderer in ZT mode only
  if (level === 'SESSION' && zeroTrustMode) {
    if (!senderIsMain) {
      return { allowed: false, reason: `SESSION channel '${channel}' called from non-main renderer in zero-trust mode: ${senderUrl || 'unknown'}` };
    }
  }

  return { allowed: true };
}

function logViolation(_channel: string, reason: string): void {
  console.warn(`${LOG_PREFIX} ⚠ Violation: ${reason}`);
}

export function guardedOn(
  channel: string,
  handler: (event: Electron.IpcMainEvent, ...args: any[]) => void,
): void {
  ipcMain.on(channel, (event, ...args) => {
    const { allowed, reason } = checkPermission(event, channel);
    if (!allowed) {
      logViolation(channel, reason!);
      return;
    }
    handler(event, ...args);
  });
}

export function guardedHandle(
  channel: string,
  handler: (event: Electron.IpcMainInvokeEvent, ...args: any[]) => Promise<any> | any,
): void {
  ipcMain.handle(channel, async (event, ...args) => {
    const { allowed, reason } = checkPermission(event, channel);
    if (!allowed) {
      logViolation(channel, reason!);
      throw new Error(`Blocked: ${reason}`);
    }
    return handler(event, ...args);
  });
}
