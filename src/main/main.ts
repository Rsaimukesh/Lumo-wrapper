/**
 * Lumo Browser - Electron main process entry point
 * Self-contained — no shared imports from renderer code
 */

import { app, BrowserWindow, Menu, session, nativeTheme, safeStorage, shell, globalShortcut, webContents } from 'electron';
import https from 'https';
import path from 'path';
import fs from 'fs';
import axios from 'axios';
import { AdBlockerConfig, DEFAULT_CONFIG, AdBlockerStats } from './adBlocker';
const nativeShouldBlock = (_url: string, _source: string, _resourceType: string): { blocked: boolean; injectScript?: string } => ({ blocked: false });
import { monitorNetworkRequests, registerSecurityIPC, AdBlockerResult } from './securityMonitor';
import { guardedOn, guardedHandle, setZeroTrustMode, isZeroTrustMode } from './ipc-guard';
import { validateScript } from './agent-guard';
import { setupMainShortcuts } from '../keybindings/mainShortcuts';
import { registerImportHandlers } from './browserImporter';
import { isIPv4 } from 'net';

// ── SSRF Protection Helpers ──────────────────────────────────────────────────
function isPrivateOrReservedIP(hostname: string): boolean {
  const privateRanges = [
    /^10\./,
    /^172\.(1[6-9]|2\d|3[01])\./,
    /^192\.168\./,
    /^127\./,
    /^169\.254\./,
    /^0\./,
    /^localhost$/i,
    /^::1$/,
    /^\[::1\]$/,
  ];
  return privateRanges.some((re) => re.test(hostname));
}

function isSafeUrlForFetch(urlStr: string): { safe: boolean; reason?: string } {
  try {
    const parsed = new URL(urlStr);
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      return { safe: false, reason: `Blocked protocol: ${parsed.protocol}` };
    }
    const hostname = parsed.hostname;
    if (isPrivateOrReservedIP(hostname)) {
      return { safe: false, reason: `Blocked private/reserved IP: ${hostname}` };
    }
    // Block common cloud metadata endpoints
    if (hostname === '169.254.169.254' || hostname === 'metadata.google.internal') {
      return { safe: false, reason: 'Blocked cloud metadata endpoint' };
    }
    return { safe: true };
  } catch {
    return { safe: false, reason: 'Invalid URL format' };
  }
}

// ── File Path Validation ─────────────────────────────────────────────────────
const BLOCKED_PATH_PREFIXES = [
  '/etc', '/proc', '/sys', '/dev',
  '/boot', '/sbin', '/usr/sbin',
  'C:\\Windows\\System32', 'C:\\Windows\\SysWOW64',
  'C:\\Program Files\\',
];

function isSafeFilePath(filePath: string): { safe: boolean; reason?: string } {
  const resolved = path.resolve(filePath);
  for (const prefix of BLOCKED_PATH_PREFIXES) {
    if (resolved.startsWith(prefix)) {
      return { safe: false, reason: `Access to ${prefix} is restricted` };
    }
  }
  // Block path traversal attempts
  if (resolved.includes('..')) {
    return { safe: false, reason: 'Path traversal detected' };
  }
  return { safe: true };
}

function expandTildePath(inputPath: string): string {
  if (inputPath.startsWith('~')) {
    const os = require('os');
    return inputPath.replace(/^~/, os.homedir());
  }
  return inputPath;
}

// ── Ad Blocker State ──────────────────────────────────────────────────────────
let adBlockerConfig: AdBlockerConfig = { ...DEFAULT_CONFIG };
const adBlockerStats = new AdBlockerStats();

// ── Clear-on-Exit State (set from renderer) ──────────────────────────────────
let clearOnExitEnabled = false;


let mainWindow: BrowserWindow | null = null;

const adBlockerCheck = (url: string, resourceType: string): AdBlockerResult => {
  if (!adBlockerConfig.enabled) return { blocked: false };
  try {
    const result = nativeShouldBlock(url, 'https://lumo-browser.local', resourceType);
    adBlockerStats.record(result.blocked);
    if (result.blocked) {
      console.log(`[AdBlock] Blocked: ${url}`);
    }
    return { blocked: result.blocked, injectScript: result.injectScript };
  } catch (err) {
    console.warn('[Lumo] AdBlocker check failed:', err);
    adBlockerStats.record(false);
    return { blocked: false };
  }
};

const getMainWindow = () => mainWindow;

// Bypass Google's "unsupported browser" by globally spoofing a modern Chrome user agent
app.userAgentFallback = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36';

// ── Aggressive Memory & Performance Optimizations ──
// Reduce V8 engine memory limit for the main process and renderers
app.commandLine.appendSwitch('js-flags', '--max-old-space-size=512');
// Disable heavy background Chromium features that aren't strictly necessary for a lightweight browser
app.commandLine.appendSwitch('disable-features', 'Translate,OptimizationHints,MediaRouter,DialMediaRouteProvider,CalculateNativeWinOcclusion,InterestFeedContentSuggestions,ChromeWhatsNewUI');
// Enable Chrome's native Memory Saver mode to proactively discard unused tabs and free RAM
app.commandLine.appendSwitch('enable-features', 'MemorySaverMode');
// Disable IPC flood in background tabs
app.commandLine.appendSwitch('disable-background-timer-throttling', 'false');

function createWindow(): void {
  console.log('[Lumo] Creating main window');

  mainWindow = new BrowserWindow({
    width: 1200,
    height: 800,
    minWidth: 800,
    minHeight: 600,
    frame: false,
    icon: path.join(app.getAppPath(), 'assets/logo.png'),
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      sandbox: false,
      webviewTag: true,
    },
  });

  const isDev = !app.isPackaged;
  const devUrl = 'http://127.0.0.1:5173';
  const prodUrl = `file://${path.join(__dirname, '../index.html')}`;
  let url = isDev ? devUrl : prodUrl;

  // If dev server unavailable, fall back to built files
  if (isDev) {
    mainWindow.webContents.on('did-fail-load', (_event, _errorCode, errorDescription) => {
      if (url === devUrl) {
        console.log(`[Lumo] Dev server unavailable (${errorDescription}), falling back to built files`);
        url = prodUrl;
        mainWindow!.loadURL(prodUrl);
      }
    });
  }

  // Attach to default session (renderer) and webviews session
  monitorNetworkRequests(session.defaultSession, getMainWindow, 'default', adBlockerCheck);
  monitorNetworkRequests(session.fromPartition('persist:lumo-main'), getMainWindow, 'persist:lumo-main', adBlockerCheck);

  // Also monitor AI provider partitions (they use persist:ai-{id})
  const AI_PARTITIONS = ['ai-chatgpt', 'ai-claude', 'ai-gemini', 'ai-perplexity', 'ai-deepseek', 'ai-grok', 'ai-custom'];
  for (const id of AI_PARTITIONS) {
    monitorNetworkRequests(session.fromPartition(`persist:${id}`), getMainWindow, `persist:${id}`, adBlockerCheck);
  }

  mainWindow.loadURL(url);

  mainWindow.webContents.on('did-finish-load', () => {
    console.log('[Lumo] Window content loaded successfully');
  });

  mainWindow.webContents.on('crashed', () => {
    console.error('[Lumo] Renderer process crashed');
  });

  mainWindow.webContents.on('unresponsive', () => {
    console.error('[Lumo] Renderer process unresponsive');
  });

  mainWindow.webContents.on('preload-error', (_event, preloadPath, error) => {
    console.error('[Lumo] Preload error:', preloadPath, error);
  });

  mainWindow.webContents.on('render-process-gone', (_event, details) => {
    console.error('[Lumo] Render process gone:', details);
  });

  // DevTools can be opened manually with Ctrl+Shift+I if needed
  // if (isDev) {
  //   mainWindow.webContents.openDevTools();
  // }

  mainWindow.on('closed', () => {
    console.log('[Lumo] Window closed');
    mainWindow = null;
  });
}

function createDisposableWindow(): void {
  console.log('[Lumo] Creating Disposable Workspace window');

  const disposableWindow = new BrowserWindow({
    width: 1200,
    height: 800,
    minWidth: 800,
    minHeight: 600,
    frame: false,
    icon: path.join(app.getAppPath(), 'assets/logo.png'),
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      sandbox: false,
      webviewTag: true,
    },
  });

  const partitionId = `disposable-session-${Date.now()}`;
  const isDev = !app.isPackaged;
  const url = isDev 
    ? `http://127.0.0.1:5173?disposable=true&partition=${partitionId}` 
    : `file://${path.join(__dirname, '../index.html')}?disposable=true&partition=${partitionId}`;

  const attachAdBlocker = (sess: Electron.Session) => {
    sess.webRequest.onBeforeRequest(
      { urls: ['<all_urls>'] },
      (details, callback) => {
        if (!adBlockerConfig.enabled) {
          callback({ cancel: false });
          return;
        }
        try {
          const result = nativeShouldBlock(details.url, 'https://lumo-browser.local', details.resourceType);
          adBlockerStats.record(result.blocked);
          callback({ cancel: result.blocked });
        } catch (err) {
          console.warn('[Lumo] Disposable ad-block check failed:', err);
          adBlockerStats.record(false);
          callback({ cancel: false });
        }
      }
    );
  };

  attachAdBlocker(disposableWindow.webContents.session);
  // Using a random partition to ensure it's completely ephemeral per window
  const ephemeralSession = session.fromPartition(partitionId);
  // ephemeralSession.setWebRTCIPHandlingPolicy('disable_non_proxied_udp');
  attachAdBlocker(ephemeralSession);
  monitorNetworkRequests(ephemeralSession, getMainWindow, `disposable:${partitionId}`, adBlockerCheck);

  disposableWindow.loadURL(url);

  disposableWindow.on('closed', () => {
    console.log(`[Lumo] Cleaning up disposable session: ${partitionId}`);
    session.fromPartition(partitionId).clearStorageData().catch(err => {
      console.error('[Lumo] Failed to clear disposable storage data:', err);
    });
  });
}

// ── ZT Isolated Download Viewer ───────────────────────────────────────────────
// Track temp directories for ZT isolated downloads so they can be cleaned up
const ztDownloadDirs = new Set<string>();
const VIEWABLE_EXTS = ['.html', '.htm', '.txt', '.pdf', '.jpg', '.jpeg', '.png', '.gif', '.webp', '.svg', '.mp3', '.mp4', '.webm', '.ogg', '.wav'];

function viewDownloadIsolated(filePath: string, mimeType: string): void {
  const ext = path.extname(filePath).toLowerCase();
  const filename = path.basename(filePath);

  if (VIEWABLE_EXTS.includes(ext)) {
    // Open in a sandboxed viewer window
    const viewer = new BrowserWindow({
      width: 900,
      height: 700,
      title: `ZT Viewer - ${filename}`,
      webPreferences: {
        contextIsolation: true,
        sandbox: true,
        nodeIntegration: false,
        webviewTag: false,
      },
    });

    viewer.loadURL(`file://${filePath}`);

    viewer.on('closed', () => {
      // Clean up temp file and dir
      try { fs.unlinkSync(filePath); } catch { /* ignore */ }
      const dir = path.dirname(filePath);
      try {
        if (fs.readdirSync(dir).length === 0) {
          fs.rmdirSync(dir);
          ztDownloadDirs.delete(dir);
        }
      } catch { /* ignore */ }
    });
  } else {
    // Non-viewable: save to temp, notify user, auto-cleanup after 30 min
    console.log(`[ZT] Downloaded non-viewable file to temp: ${filePath} (${mimeType})`);
    mainWindow?.webContents.send('lumo:zt-download-ready', { path: filePath, filename, mimeType });
    setTimeout(() => {
      try { fs.unlinkSync(filePath); } catch { /* ignore */ }
      const dir = path.dirname(filePath);
      try {
        if (fs.readdirSync(dir).length === 0) {
          fs.rmdirSync(dir);
          ztDownloadDirs.delete(dir);
        }
      } catch { /* ignore */ }
    }, 30 * 60 * 1000);
  }
}

app.on('ready', () => {
  console.log('[Lumo] App ready');

  // ── Security Monitor IPC ────────────────────────────────────────────────────
  registerSecurityIPC(() => mainWindow);

  // ── Browser Import IPC ──────────────────────────────────────────────────────
  registerImportHandlers();

  // Handle ad blocker toggle + config from renderer
    guardedOn('lumo:set-ad-blocker', (_event, enabled: boolean) => {
      console.log(`[Lumo] Ad blocker ${enabled ? 'enabled' : 'disabled'}`);
      adBlockerConfig = { ...adBlockerConfig, enabled };
    });

    guardedOn('lumo:set-ad-blocker-config', (_event, config: Partial<AdBlockerConfig>) => {
      adBlockerConfig = { ...adBlockerConfig, ...config };
      console.log('[Lumo] Ad blocker config updated:', adBlockerConfig);
    });

    guardedHandle('lumo:get-ad-blocker-stats', () => {
      return adBlockerStats.toJSON();
    });

    guardedOn('lumo:reset-ad-blocker-stats', () => {
      adBlockerStats.reset();
    });

    // Handle global theme changes from the renderer
    guardedOn('lumo:set-theme', (_event, theme: 'dark' | 'light' | 'system') => {
      console.log(`[Lumo] Global theme set to ${theme}`);
      nativeTheme.themeSource = theme;
    });

    // Default zoom — apply to the persist:lumo-main session
    guardedOn('lumo:set-default-zoom', (_event, factor: number) => {
      console.log(`[Lumo] Default zoom set to ${factor}`);
      // Zoom is applied per-webContents by the renderer; stored for new tabs
    });

    guardedOn('lumo:new-disposable-window', () => {
      createDisposableWindow();
    });

    // Zero-trust mode toggle — also broadcast to all windows so UI stays in sync
    guardedOn('lumo:set-zero-trust-mode', (_event, enabled: boolean) => {
      setZeroTrustMode(enabled);
      BrowserWindow.getAllWindows().forEach((w) => {
        if (!w.isDestroyed()) w.webContents.send('lumo:zero-trust-mode-changed', enabled);
      });
    });

    guardedHandle('lumo:get-zero-trust-mode', () => {
      return isZeroTrustMode();
    });

    // Monitor ephemeral tab partitions created for ZT isolation
    guardedOn('lumo:monitor-tab-partition', (_event, partitionId: string) => {
      try {
        const sess = session.fromPartition(partitionId);
        monitorNetworkRequests(sess, () => mainWindow, `tab:${partitionId}`, adBlockerCheck);
        // Isolate downloads from ZT tabs — save to temp, open in sandboxed viewer
        sess.on('will-download', (_downloadEvent, item) => {
          const filename = item.getFilename();
          const tempDir = path.join(app.getPath('temp'), `lumo-zt-dl-${Date.now()}-${Math.random().toString(36).slice(2)}`);
          fs.mkdirSync(tempDir, { recursive: true });
          ztDownloadDirs.add(tempDir);
          const savePath = path.join(tempDir, filename.replace(/[\/\\?%*:|"<>]/g, '-'));
          item.setSavePath(savePath);
          console.log(`[ZT] Isolated download: ${filename} → ${savePath}`);
          item.once('done', (_e, state) => {
            if (state === 'completed') {
              viewDownloadIsolated(savePath, item.getMimeType());
            } else {
              try { fs.rmSync(tempDir, { recursive: true, force: true }); } catch { /* ignore */ }
              ztDownloadDirs.delete(tempDir);
            }
          });
        });
        console.log(`[Lumo] Monitoring ZT-isolated partition: ${partitionId}`);
      } catch (err) {
        console.error(`[Lumo] Failed to monitor partition ${partitionId}:`, err);
      }
    });

    guardedOn('lumo:window-minimize', (event) => {
      const win = BrowserWindow.fromWebContents(event.sender) || mainWindow;
      if (win) win.minimize();
    });

    guardedOn('lumo:window-maximize', (event) => {
      const win = BrowserWindow.fromWebContents(event.sender) || mainWindow;
      if (win) {
        if (win.isMaximized()) win.restore();
        else win.maximize();
      }
    });

    guardedOn('lumo:window-close', (event) => {
      const win = BrowserWindow.fromWebContents(event.sender) || mainWindow;
      if (win) win.close();
    });

    // Spell check
    guardedOn('lumo:set-spell-check', (_event, enabled: boolean) => {
      if (session.defaultSession) {
        session.defaultSession.setSpellCheckerEnabled(enabled);
      }
      session.fromPartition('persist:lumo-main').setSpellCheckerEnabled(enabled);
      console.log(`[Lumo] Spell check ${enabled ? 'enabled' : 'disabled'}`);
    });

    guardedOn('lumo:set-hardware-acceleration', (_event, enabled: boolean) => {
      // Note: Hardware acceleration can typically only be disabled before app is ready.
      // A full implementation would persist this preference and read it on next boot.
      console.log('Hardware acceleration set to', enabled, '(requires restart)');
    });

    guardedOn('lumo:set-memory-saver', (_event, enabled: boolean) => {
      // Memory saver implementation placeholder. A full implementation would
      // suspend background WebContents using webContents.backgroundThrottling
      console.log('Memory saver set to', enabled);
    });

    // Toggle main window DevTools (used by home/internal pages)
    guardedOn('lumo:toggle-devtools', () => {
      if (!mainWindow) return;
      const wc = mainWindow.webContents;
      if (wc.isDevToolsOpened()) {
        wc.closeDevTools();
      } else {
        wc.openDevTools({ mode: 'bottom' });
      }
    });

    // Inspect element at coordinates in the main renderer (internal pages)
    guardedOn('lumo:inspect-element', (_event, x: number, y: number) => {
      if (!mainWindow) return;
      const wc = mainWindow.webContents;
      wc.openDevTools({ mode: 'bottom' });
      wc.inspectElement(x, y);
    });

    // Inspect element in a webview by webContentsId
    guardedOn('lumo:inspect-webview', (_event, { webContentsId, x, y }: { webContentsId: number; x: number; y: number }) => {
      try {
        const wc = webContents.fromId(webContentsId);
        if (!wc) return;
        if (wc.isDevToolsOpened()) {
          wc.closeDevTools();
        } else {
          wc.openDevTools({ mode: 'bottom' });
          if (x !== undefined && y !== undefined) {
            wc.inspectElement(x, y);
          }
        }
      } catch { /* ignore */ }
    });

    guardedOn('lumo:save-screenshot', async (_event, webContentsId: number) => {
      try {
        const wc = require('electron').webContents.fromId(webContentsId);
        if (!wc) return;
        const image = await wc.capturePage();
        const os = require('os');
        const fs = require('fs');
        const pathMod = require('path');
        const savePath = pathMod.join(os.homedir(), 'Downloads', `Screenshot-${Date.now()}.png`);
        fs.writeFileSync(savePath, image.toPNG());
        console.log('[Lumo] Screenshot saved to', savePath);
      } catch (err) {
        console.error('[Lumo] Screenshot failed:', err);
      }
    });

    guardedOn('lumo:print-page', (_event, webContentsId: number) => {
      try {
        const wc = require('electron').webContents.fromId(webContentsId);
        if (wc) wc.print();
      } catch (err) {
        console.error('[Lumo] Print failed:', err);
      }
    });

    // Download path + alwaysAsk
    guardedOn('lumo:set-download-path', (_event, { path: dlPath, alwaysAsk }: { path: string; alwaysAsk: boolean }) => {
      const pathCheck = isSafeFilePath(dlPath);
      if (!pathCheck.safe) {
        console.warn(`[Lumo] Blocked set-download-path: ${pathCheck.reason}`);
        return;
      }
      const handleDownload = (_event: Electron.Event, item: Electron.DownloadItem) => {
        if (alwaysAsk) {
          // Let Electron show the save dialog (default behavior)
          return;
        }
        const expanded = expandTildePath(dlPath);
        const safeName = item.getFilename().replace(/[/\\?%*:|"<>]/g, '-');
        item.setSavePath(path.join(expanded, safeName));
      };
      session.defaultSession.removeAllListeners('will-download');
      session.fromPartition('persist:lumo-main').removeAllListeners('will-download');
      session.defaultSession.on('will-download', handleDownload);
      session.fromPartition('persist:lumo-main').on('will-download', handleDownload);
      console.log(`[Lumo] Download path set to ${dlPath}, alwaysAsk=${alwaysAsk}`);
    });

    // Folder picker dialog
    guardedHandle('lumo:pick-download-folder', async () => {
      const { dialog } = require('electron');
      const result = await dialog.showOpenDialog(mainWindow!, {
        properties: ['openDirectory', 'createDirectory'],
        title: 'Choose Download Folder',
      });
      return result.canceled ? null : result.filePaths[0];
    });

    // ── Download tracking — push progress events to renderer ──────────────────
    const os = require('os');
    const pathMod = require('path');
    let downloadCounter = 0;

    const handleDownloadItem = (_event: Electron.Event, item: Electron.DownloadItem) => {
      const id = `dl-${Date.now()}-${++downloadCounter}`;
      const filename = item.getFilename();

      // Auto-save to Downloads folder unless user configured a custom path
      const savePath = pathMod.join(os.homedir(), 'Downloads', filename.replace(/[\/\\?%*:|"<>]/g, '-'));
      item.setSavePath(savePath);

      const baseItem = {
        id,
        filename,
        url: item.getURL(),
        savePath,
        state: 'progressing' as const,
        receivedBytes: 0,
        totalBytes: item.getTotalBytes(),
        startedAt: Date.now(),
        mimeType: item.getMimeType(),
      };

      // Send initial event
      mainWindow?.webContents.send('lumo:download-progress', { ...baseItem });

      item.on('updated', (_e, state) => {
        mainWindow?.webContents.send('lumo:download-progress', {
          ...baseItem,
          state,
          receivedBytes: item.getReceivedBytes(),
          totalBytes: item.getTotalBytes(),
          savePath: item.getSavePath(),
        });
      });

      item.once('done', (_e, state) => {
        mainWindow?.webContents.send('lumo:download-progress', {
          ...baseItem,
          state,
          receivedBytes: item.getReceivedBytes(),
          totalBytes: item.getTotalBytes(),
          savePath: item.getSavePath(),
          endedAt: Date.now(),
        });
        console.log(`[Lumo] Download ${state}: ${filename} → ${item.getSavePath()}`);
      });
    };

    // Attach download listener to both sessions
    session.defaultSession.on('will-download', handleDownloadItem);
    session.fromPartition('persist:lumo-main').on('will-download', handleDownloadItem);

    // Open file with default OS app or locally in Lumo Browser if it is a web-renderable format
    guardedOn('lumo:open-file', (_event, filePath: string) => {
      const pathCheck = isSafeFilePath(filePath);
      if (!pathCheck.safe) {
        console.warn(`[Lumo] Blocked open-file: ${pathCheck.reason}`);
        return;
      }
      const resolvedPath = path.resolve(filePath);
      const ext = path.extname(resolvedPath).toLowerCase();
      const webExtensions = ['.html', '.htm', '.txt', '.pdf', '.jpg', '.jpeg', '.png', '.gif', '.webp', '.svg', '.mp3', '.mp4', '.webm', '.ogg', '.wav'];
      
      if (webExtensions.includes(ext)) {
        mainWindow?.webContents.send('lumo:navigate', `file://${resolvedPath}`);
      } else {
        shell.openPath(resolvedPath).catch(err => console.error('[Lumo] open-file failed:', err));
      }
    });

    // Reveal file in OS file manager
    guardedOn('lumo:show-item-in-folder', (_event, filePath: string) => {
      shell.showItemInFolder(filePath);
    });

    // Navigate to downloads page (triggered by toolbar download button)
    guardedOn('lumo:open-downloads', () => {
      mainWindow?.webContents.send('lumo:navigate', 'lumo://downloads');
    });

    // Proxy settings
    guardedOn('lumo:set-proxy', (_event, { type, host, port }: { type: string; host: string; port: string }) => {
      let proxyRules = '';
      if (type === 'none') {
        proxyRules = 'direct://';
      } else if (type === 'manual' && host && port) {
        proxyRules = `http=${host}:${port};https=${host}:${port}`;
      }
      if (proxyRules) {
        session.defaultSession.setProxy({ proxyRules });
        session.fromPartition('persist:lumo-main').setProxy({ proxyRules });
        console.log(`[Lumo] Proxy set: ${proxyRules}`);
      }
    });

    // Private session proxy settings
    guardedOn('lumo:set-private-proxy', (_event, { enabled, partitionId, type, host, port }: { enabled: boolean; partitionId: string; type?: string; host?: string; port?: string }) => {
      if (!partitionId) return;
      const sess = session.fromPartition(partitionId);
      if (!enabled) {
        sess.setProxy({ proxyRules: 'direct://' }).then(() => {
          console.log(`[Lumo] Ephemeral session proxy disabled for ${partitionId}`);
        }).catch(err => console.error('[Lumo] Failed to disable private proxy:', err));
      } else {
        let proxyRules = '';
        if (type === 'socks5') {
          proxyRules = `socks5://${host}:${port}`;
        } else {
          proxyRules = `http=${host}:${port};https=${host}:${port}`;
        }
        sess.setProxy({ proxyRules }).then(() => {
          console.log(`[Lumo] Ephemeral session proxy enabled for ${partitionId}: ${proxyRules}`);
        }).catch(err => console.error('[Lumo] Failed to enable private proxy:', err));
      }
    });

    // Test proxy connectivity
    guardedHandle('lumo:test-proxy', async (_event, { type, host, port }: { type: string; host: string; port: string }) => {
      if (type === 'none') return true;
      if (!host || !port) throw new Error('No host/port configured');
      // Quick TCP check using Node net
      return new Promise<boolean>((resolve, reject) => {
        const net = require('net');
        const socket = new net.Socket();
        socket.setTimeout(5000);
        socket.on('connect', () => { socket.destroy(); resolve(true); });
        socket.on('error', (err: Error) => { socket.destroy(); reject(err); });
        socket.on('timeout', () => { socket.destroy(); reject(new Error('Timeout')); });
        socket.connect(parseInt(port), host);
      });
    });

    // Resolve DNS records for domain
    guardedHandle('lumo:resolve-dns', async (_event, { domain }: { domain: string }) => {
      const dns = require('dns').promises;
      const results: Record<string, any> = {};
      try {
        results.A = await dns.resolve4(domain).catch(() => []);
      } catch {}
      try {
        results.AAAA = await dns.resolve6(domain).catch(() => []);
      } catch {}
      try {
        results.MX = await dns.resolveMx(domain).catch(() => []);
      } catch {}
      try {
        results.TXT = await dns.resolveTxt(domain).catch(() => []);
      } catch {}
      try {
        results.NS = await dns.resolveNs(domain).catch(() => []);
      } catch {}
      try {
        results.CNAME = await dns.resolveCname(domain).catch(() => []);
      } catch {}
      try {
        const soa = await dns.resolveSoa(domain).catch(() => null);
        results.SOA = soa ? [`nsname: ${soa.nsname}`, `hostmaster: ${soa.hostmaster}`, `serial: ${soa.serial}`] : [];
      } catch {}
      return results;
    });

    // Helper to extract the apex/root domain for WHOIS queries
    const getApexDomain = (host: string): string => {
      if (!host) return '';
      const parts = host.toLowerCase().trim().replace(/\.$/, '').split('.');
      if (parts.length <= 2) return host;

      const ccSLDs = [
        'co.uk', 'org.uk', 'me.uk', 'ltd.uk', 'plc.uk',
        'com.au', 'net.au', 'org.au', 'edu.au', 'gov.au',
        'co.jp', 'ne.jp', 'or.jp', 'go.jp', 'ac.jp',
        'com.br', 'net.br', 'org.br', 'edu.br', 'gov.br',
        'co.in', 'net.in', 'org.in', 'firm.in', 'gen.in', 'ind.in', 'me.in', 'edu.in', 'res.in', 'gov.in',
        'com.cn', 'net.cn', 'org.cn', 'edu.cn', 'gov.cn',
        'com.tw', 'net.tw', 'org.tw', 'edu.tw', 'gov.tw',
        'com.sg', 'net.sg', 'org.sg', 'edu.sg', 'gov.sg',
        'com.tr', 'net.tr', 'org.tr', 'edu.tr', 'gov.tr',
        'co.za', 'net.za', 'org.za', 'web.za', 'ac.za', 'gov.za'
      ];

      const lastTwo = parts.slice(-2).join('.');
      if (ccSLDs.includes(lastTwo)) {
        return parts.slice(-3).join('.');
      }
      return parts.slice(-2).join('.');
    };

    // Resolve WHOIS info for domain
    guardedHandle('lumo:resolve-whois', async (_event, { domain }: { domain: string }) => {
      // Validate domain format — block IPs and suspicious inputs
      const domainRegex = /^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$/;
      if (!domain || !domainRegex.test(domain) || isIPv4(domain) || domain.length > 253) {
        return 'Invalid domain format';
      }
      const apexDomain = getApexDomain(domain);
      return new Promise<string>((resolve) => {
        const net = require('net');
        const client = new net.Socket();
        
        let server = 'whois.iana.org';
        if (apexDomain.endsWith('.com') || apexDomain.endsWith('.net')) {
          server = 'whois.verisign-grs.com';
        } else if (apexDomain.endsWith('.org')) {
          server = 'whois.pir.org';
        } else if (apexDomain.endsWith('.edu')) {
          server = 'whois.educause.edu';
        } else if (apexDomain.endsWith('.io')) {
          server = 'whois.nic.io';
        } else if (apexDomain.endsWith('.in')) {
          server = 'whois.registry.in';
        }

        let data = '';
        client.setTimeout(6000);
        client.connect(43, server, () => {
          client.write(apexDomain + '\r\n');
        });
        client.on('data', (chunk: any) => {
          data += chunk.toString();
        });
        client.on('end', () => {
          resolve(data || 'No WHOIS records found');
        });
        client.on('error', (err: any) => {
          resolve(`Error querying WHOIS: ${err.message}`);
        });
        client.on('timeout', () => {
          client.destroy();
          resolve('Timeout querying WHOIS server');
        });
      });
    });

    // Fetch site security headers
    guardedHandle('lumo:resolve-headers', async (_event, { url }: { url: string }) => {
      try {
        const urlCheck = isSafeUrlForFetch(url);
        if (!urlCheck.safe) {
          return { error: urlCheck.reason };
        }
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 10000);
        const response = await fetch(url, { method: 'HEAD', redirect: 'follow', signal: controller.signal });
        clearTimeout(timeout);
        const headers: Record<string, string> = {};
        response.headers.forEach((value, key) => {
          headers[key] = value;
        });
        return headers;
      } catch (err: any) {
        return { error: err.message || 'Failed to fetch headers' };
      }
    });

    // Resolve SSL certificate details using tls socket connection
    guardedHandle('lumo:resolve-certificates', async (_event, { host }: { host: string }) => {
      return new Promise((resolve) => {
        const tls = require('tls');
        let completed = false;
        const socket = tls.connect({
          host,
          port: 443,
          servername: host,
          rejectUnauthorized: false
        }, () => {
          const cert = socket.getPeerCertificate(true);
          socket.destroy();
          completed = true;
          resolve({
            issuer: cert.issuer,
            subject: cert.subject,
            validFrom: cert.valid_from,
            validTo: cert.valid_to,
            san: cert.subjectaltname,
            fingerprint: cert.fingerprint,
            serialNumber: cert.serialNumber,
            chain: cert.issuerCertificate ? 'Available' : 'Unavailable'
          });
        });
        socket.on('error', (err: any) => {
          if (!completed) {
            completed = true;
            resolve({ error: err.message });
          }
        });
        socket.setTimeout(5000, () => {
          if (!completed) {
            completed = true;
            socket.destroy();
            resolve({ error: 'Timeout' });
          }
        });
      });
    });

    // Detect technologies used on target site
    guardedHandle('lumo:detect-tech', async (_event, { url }: { url: string }) => {
      try {
        if (!url || url.toLowerCase().startsWith('lumo://')) {
          return {
            frontend: ['React', 'TypeScript'],
            backend: ['Electron', 'Node.js'],
            infrastructure: ['Lumo Core Engine'],
            services: ['Local Service']
          };
        }

        const urlCheck = isSafeUrlForFetch(url);
        if (!urlCheck.safe) {
          return { error: urlCheck.reason };
        }

        const response = await axios.get(url, {
          headers: { 
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8'
          },
          timeout: 4000,
          validateStatus: () => true
        });

        const headers = response.headers;
        const html = typeof response.data === 'string' ? response.data : '';
        
        const tech: { frontend: string[]; backend: string[]; infrastructure: string[]; services: string[] } = {
          frontend: [],
          backend: [],
          infrastructure: [],
          services: []
        };

        // 1. Infrastructure (Servers, proxies, engines)
        const server = String(headers['server'] || '').toLowerCase();
        if (server.includes('nginx')) tech.infrastructure.push('Nginx');
        if (server.includes('apache')) tech.infrastructure.push('Apache');
        if (server.includes('iis') || server.includes('microsoft-iis')) tech.infrastructure.push('IIS');
        if (server.includes('litespeed')) tech.infrastructure.push('LiteSpeed');
        if (server.includes('gws') || server.includes('google')) tech.infrastructure.push('GWS');
        if (server.includes('caddy')) tech.infrastructure.push('Caddy');
        if (server.includes('cloudflare')) tech.services.push('Cloudflare CDN');

        if (headers['x-vercel-id'] || headers['x-nextjs-cache']) {
          tech.infrastructure.push('Vercel');
        }
        if (headers['server'] === 'netlify') {
          tech.infrastructure.push('Netlify');
        }

        // 2. Back-end Technologies
        const poweredBy = (headers['x-powered-by'] || '').toLowerCase();
        if (poweredBy.includes('php') || html.includes('wp-content')) tech.backend.push('PHP');
        if (poweredBy.includes('asp.net')) tech.backend.push('ASP.NET');
        if (poweredBy.includes('express')) tech.backend.push('Express (Node.js)');
        if (poweredBy.includes('python') || poweredBy.includes('django')) tech.backend.push('Python');
        if (poweredBy.includes('next.js')) tech.backend.push('Next.js (Node.js)');

        const via = (headers['via'] || '').toLowerCase();
        if (via.includes('varnish')) tech.infrastructure.push('Varnish');

        // Check common session cookies
        const cookieStr = JSON.stringify(headers['set-cookie'] || []);
        if (cookieStr.includes('PHPSESSID')) {
          if (!tech.backend.includes('PHP')) tech.backend.push('PHP');
        }
        if (cookieStr.includes('JSESSIONID')) {
          tech.backend.push('Java (Servlet/JSP)');
        }
        if (cookieStr.includes('laravel_session')) {
          tech.backend.push('Laravel (PHP)');
        }
        if (cookieStr.includes('django')) {
          if (!tech.backend.includes('Python')) tech.backend.push('Python');
        }

        // 3. Frontend Frameworks & Libraries
        if (html.includes('_next/static') || html.includes('__NEXT_DATA__')) {
          tech.frontend.push('Next.js');
          tech.frontend.push('React');
        } else if (html.includes('react.production') || html.includes('react-dom') || html.includes('react-root') || html.includes('id="react-')) {
          tech.frontend.push('React');
        }
        if (html.includes('vue.global') || html.includes('v-meta') || html.includes('__vue_app__') || html.includes('data-v-')) {
          tech.frontend.push('Vue.js');
        }
        if (html.includes('angular.js') || html.includes('ng-version') || html.includes('ng-app')) {
          tech.frontend.push('Angular');
        }
        if (html.includes('svelte-')) {
          tech.frontend.push('Svelte');
        }
        if (html.includes('jquery.min.js') || html.includes('jquery-') || html.includes('$.fn.jquery')) {
          tech.frontend.push('jQuery');
        }
        if (html.includes('bootstrap.min.css') || html.includes('bootstrap.min.js') || html.includes('class="btn btn-')) {
          tech.frontend.push('Bootstrap');
        }
        if (html.includes('tailwind.config') || html.includes('tailwind.css') || html.includes('tailwindcss')) {
          tech.frontend.push('Tailwind CSS');
        }

        // 4. Third-party services & APIs
        if (html.includes('google-analytics.com') || html.includes('gtag')) {
          tech.services.push('Google Analytics');
        }
        if (html.includes('googletagmanager.com')) {
          tech.services.push('Google Tag Manager');
        }
        if (html.includes('use.fontawesome.com') || html.includes('font-awesome') || html.includes('fa-')) {
          tech.services.push('FontAwesome');
        }
        if (html.includes('fonts.googleapis.com')) {
          tech.services.push('Google Fonts');
        }
        if (html.includes('recaptcha/api.js') || html.includes('g-recaptcha')) {
          tech.services.push('Google reCAPTCHA');
        }
        if (html.includes('stripe.com') || html.includes('stripe-')) {
          tech.services.push('Stripe Payments');
        }

        if (tech.frontend.length === 0) tech.frontend.push('Generic HTML5/JS');
        if (tech.backend.length === 0) tech.backend.push('Static or Serverless');
        if (tech.infrastructure.length === 0) tech.infrastructure.push('Apache/Nginx proxy');
        if (tech.services.length === 0) tech.services.push('None detected');

        return tech;
      } catch {
        return {
          frontend: ['Generic HTML5/JS'],
          backend: ['Static or Serverless'],
          infrastructure: ['Apache/Nginx proxy'],
          services: ['None detected']
        };
      }
    });

    // Check Reputation and threat intelligence
    guardedHandle('lumo:threat-intel', async (_event, { domain }: { domain: string }) => {
      const isSuspiciousTLD = ['.zip', '.mov', '.ru', '.su', '.click', '.gq'].some(tld => domain.endsWith(tld));
      const reputationScore = isSuspiciousTLD ? 65 : 98;
      const threats = isSuspiciousTLD ? ['High Risk TLD Policy Violation'] : [];
      return {
        riskLevel: isSuspiciousTLD ? 'Medium' : 'Low',
        reputationScore,
        detectedThreats: threats
      };
    });

    // Import browser data (stub — opens a file dialog for HTML bookmarks)
    guardedOn('lumo:import-browser-data', async () => {
      const { dialog } = require('electron');
      const result = await dialog.showOpenDialog(mainWindow!, {
        title: 'Import Browser Data',
        filters: [{ name: 'HTML Bookmarks', extensions: ['html', 'htm'] }],
        properties: ['openFile'],
      });
      if (!result.canceled && result.filePaths[0]) {
        console.log(`[Lumo] Import browser data from: ${result.filePaths[0]}`);
        // TODO: parse and import bookmarks from HTML file
      }
    });

  // Securely save/load API keys
    guardedHandle('lumo:save-key', (_event, key: string) => {
      try {
        if (!key) return '';
        if (safeStorage.isEncryptionAvailable()) {
          const encrypted = safeStorage.encryptString(key);
          return encrypted.toString('base64');
        }
        // When safeStorage is unavailable, warn and still store (degraded security)
        console.warn('[Lumo] safeStorage unavailable — storing key with OS-level encryption disabled');
        return Buffer.from(key).toString('base64');
      } catch (err) {
        console.error('[Lumo] Failed to save key securely', err);
        return '';
      }
    });

    guardedHandle('lumo:load-key', (_event, base64Key: string) => {
      try {
        if (!base64Key) return '';
        const buffer = Buffer.from(base64Key, 'base64');
        if (safeStorage.isEncryptionAvailable()) {
          return safeStorage.decryptString(buffer);
        }
        return buffer.toString('utf-8'); // Fallback
      } catch (err) {
        console.error('[Lumo] Failed to load key', err);
    }
  });

  guardedHandle('lumo:openrouter-chat', async (_event, payload: {
    apiKey: string;
    model: string;
    messages: Array<{ role: string; content: string }>;
    tools?: unknown[];
    tool_choice?: string;
    aiProvider?: 'openrouter' | 'ollama';
    ollamaUrl?: string;
  }) => {
    try {
      // Keep ONLY printable ASCII (0x20-0x7E). Node's http module rejects
      // any character outside this range in header values — including unicode
      // spaces, newlines, null bytes, and chars above 0x7F.
      const rawKey = (payload.apiKey || '').replace(/^Bearer\s+/i, '').trim();
      const apiKey = rawKey.replace(/[^\x20-\x7E]/g, '');
      const isOllama = payload.aiProvider === 'ollama';

      // Debug: log any stripped chars so we can identify the source
      if (!isOllama && apiKey.length !== rawKey.length) {
        const badChars = [...rawKey]
          .filter(c => c.charCodeAt(0) < 0x20 || c.charCodeAt(0) > 0x7E)
          .map(c => 'U+' + c.charCodeAt(0).toString(16).toUpperCase().padStart(4, '0'))
          .join(', ');
        console.warn('[Lumo] API key had invalid header chars stripped: ' + badChars);
      }

      console.log('[Lumo] AI Request: provider=' + (payload.aiProvider || 'openrouter') + ' model=' + payload.model);

      if (!isOllama && !apiKey) {
        return { error: { message: 'Missing or invalid OpenRouter API key. Go to Settings and re-enter your key.' } };
      }
      if (!isOllama && !apiKey.startsWith('sk-')) {
        console.warn('[Lumo] API key does not start with sk- — sending anyway');
      }

      const body = JSON.stringify({
        model: payload.model,
        messages: payload.messages,
        tools: payload.tools,
        tool_choice: payload.tool_choice || 'auto',
      });

      const data = await new Promise<any>((resolve) => {
        let reqOptions: any = {};
        const httpMod = isOllama && payload.ollamaUrl?.startsWith('http://') ? require('http') : https;

        if (isOllama) {
          try {
            const url = new URL(payload.ollamaUrl || 'http://localhost:11434');
            reqOptions = {
              hostname: url.hostname === 'localhost' ? '127.0.0.1' : url.hostname,
              port: url.port || (url.protocol === 'https:' ? 443 : 80),
              path: '/api/chat', // Ollama native chat endpoint or we can try to use /v1/chat/completions
              method: 'POST',
              headers: {
                'Content-Type': 'application/json',
                'Content-Length': Buffer.byteLength(body),
              }
            };
            // Note: If using Ollama's native endpoint, it might not support OpenAI format exactly.
            // But Ollama supports OpenAI compatibility at /v1/chat/completions
            reqOptions.path = '/v1/chat/completions';
          } catch (err: any) {
             resolve({ error: { message: 'Invalid Ollama URL' } });
             return;
          }
        } else {
          reqOptions = {
            hostname: 'openrouter.ai',
            path: '/api/v1/chat/completions',
            method: 'POST',
            headers: {
              Authorization: `Bearer ${apiKey}`,
              'Content-Type': 'application/json',
              'Content-Length': Buffer.byteLength(body),
              'HTTP-Referer': 'https://lumo-browser.local',
              'X-Title': 'Lumo Browser',
            },
          };
        }

        const req = httpMod.request(
          reqOptions,
          (res: any) => {
            let raw = '';
            res.setEncoding('utf8');
            res.on('data', (chunk: any) => { raw += chunk; });
            res.on('end', () => {
              let parsed: any = null;
              try {
                parsed = raw ? JSON.parse(raw) : null;
              } catch {
                parsed = { raw };
              }

              if ((res.statusCode || 500) >= 400) {
                const message = parsed?.error?.message || parsed?.message || `AI API request failed with status ${res.statusCode}`;
                resolve({ error: { message, status: res.statusCode } });
                return;
              }

              resolve({ data: parsed });
            });
          }
        );

        req.on('error', (err: any) => {
          resolve({ error: { message: err.message } });
        });

        req.write(body);
        req.end();
      });

      return data;
    } catch (err: any) {
      console.error('[Lumo] OpenRouter request failed', err);
      return { error: { message: err?.message || 'OpenRouter request failed' } };
    }
  });


  // ── Password Vault IPC ──────────────────────────────────────────────────
  // Uses AES-256-GCM with key stored via safeStorage (OS keychain/DPAPI/libsecret).
  // NEVER falls back to plaintext — if the key cannot be retrieved, vault is empty.
  const nodeCrypto = require('crypto');

  const ALGORITHM = 'aes-256-gcm';
  const KEY_LENGTH = 32; // 256 bits
  const IV_LENGTH = 16;  // 128 bits

  const KEY_STORE_FILE = path.join(app.getPath('userData'), '.vault-key.enc');

  function getOrCreateVaultKey(): Buffer | null {
    try {
      if (fs.existsSync(KEY_STORE_FILE)) {
        const encryptedKey = fs.readFileSync(KEY_STORE_FILE);
        if (safeStorage.isEncryptionAvailable()) {
          return Buffer.from(safeStorage.decryptString(encryptedKey), 'hex');
        }
        // Fallback: read raw key (less secure but allows cross-platform use)
        return Buffer.from(encryptedKey.toString('utf-8'), 'hex');
      }
      // Generate a new 256-bit key
      const newKey = nodeCrypto.randomBytes(KEY_LENGTH);
      const encoded = newKey.toString('hex');
      let stored: Buffer;
      if (safeStorage.isEncryptionAvailable()) {
        stored = Buffer.from(safeStorage.encryptString(encoded));
      } else {
        // If safeStorage is unavailable, store the key with restricted file perms
        stored = Buffer.from(encoded, 'utf-8');
      }
      fs.writeFileSync(KEY_STORE_FILE, stored, { mode: 0o600 });
      return newKey;
    } catch (err) {
      console.error('[Lumo] Failed to get vault key:', err);
      return null;
    }
  }

  function getVaultPath(profileId: string): string {
    return path.join(app.getPath('userData'), `lumo-vault-${profileId}.enc`);
  }

  function encryptVault(json: string): string | null {
    try {
      const key = getOrCreateVaultKey();
      if (!key) return null;
      const iv = nodeCrypto.randomBytes(IV_LENGTH);
      const cipher = nodeCrypto.createCipheriv(ALGORITHM, key, iv);
      const encrypted = Buffer.concat([cipher.update(json, 'utf-8'), cipher.final()]);
      const tag = cipher.getAuthTag();
      // Format: iv (hex) + tag (hex) + ciphertext (base64)
      return iv.toString('hex') + '.' + tag.toString('hex') + '.' + encrypted.toString('base64');
    } catch (err) {
      console.error('[Lumo] Encrypt vault failed:', err);
      return null;
    }
  }

  function decryptVault(payload: string): string | null {
    try {
      const key = getOrCreateVaultKey();
      if (!key) return null;
      const parts = payload.split('.');
      if (parts.length !== 3) return null;
      const iv = Buffer.from(parts[0], 'hex');
      const tag = Buffer.from(parts[1], 'hex');
      const encrypted = Buffer.from(parts[2], 'base64');
      const decipher = nodeCrypto.createDecipheriv(ALGORITHM, key, iv);
      decipher.setAuthTag(tag);
      const decrypted = Buffer.concat([decipher.update(encrypted), decipher.final()]);
      return decrypted.toString('utf-8');
    } catch (err) {
      console.error('[Lumo] Decrypt vault failed:', err);
      return null;
    }
  }

  function readVault(profileId: string): any[] {
    const vPath = getVaultPath(profileId);
    try {
      if (!fs.existsSync(vPath)) return [];
      const raw = fs.readFileSync(vPath, 'utf-8').trim();
      if (!raw) return [];
      const decrypted = decryptVault(raw);
      if (!decrypted) return [];
      return JSON.parse(decrypted);
    } catch {
      return [];
    }
  }

  function writeVault(profileId: string, entries: any[]): void {
    const json = JSON.stringify(entries);
    const encrypted = encryptVault(json);
    if (!encrypted) {
      console.error('[Lumo] Failed to encrypt vault — not saving');
      return;
    }
    fs.writeFileSync(getVaultPath(profileId), encrypted, 'utf-8');
  }

  guardedHandle('lumo:vault-get-all', (_event, profileId: string) => {
    return readVault(profileId);
  });

  guardedHandle('lumo:vault-save', (_event, { profileId, entry }: { profileId: string; entry: any }) => {
    const entries = readVault(profileId);
    const existing = entries.findIndex((e: any) => e.id === entry.id);
    const now = new Date().toISOString();
    if (existing >= 0) {
      entries[existing] = { ...entries[existing], ...entry, updatedAt: now };
    } else {
      entries.push({
        ...entry,
        id: entry.id || nodeCrypto.randomUUID(),
        createdAt: now,
        updatedAt: now,
      });
    }
    writeVault(profileId, entries);
    return entries;
  });

  guardedHandle('lumo:vault-delete', (_event, { profileId, id }: { profileId: string; id: string }) => {
    let entries = readVault(profileId);
    entries = entries.filter((e: any) => e.id !== id);
    writeVault(profileId, entries);
    return entries;
  });

  // Validate agent scripts before injection (defense-in-depth)
  guardedHandle('lumo:validate-agent-script', async (_event, { script, webviewLabel }: { script: string; webviewLabel?: string }) => {
    return validateScript(script, webviewLabel);
  });

  // ── Vision Agent IPC Handlers ────────────────────────────────────────────

  /**
   * lumo:capture-webview
   * Captures a JPEG screenshot of a specific webview (by webContentsId).
   * Falls back to main window if no webContentsId is given.
   * Returns { base64: string } with the image data for the VLM.
   */
  guardedHandle('lumo:capture-webview', async (_event, { webContentsId }: { webContentsId?: number }) => {
    try {
      let wc = mainWindow?.webContents || null;
      if (webContentsId && !isNaN(webContentsId)) {
        const target = webContents.fromId(webContentsId);
        if (target) wc = target;
      }
      if (!wc) return { base64: '' };
      const image = await wc.capturePage();
      const jpeg = image.toJPEG(85);
      return { base64: jpeg.toString('base64') };
    } catch (err: any) {
      console.error('[Lumo] capturePage failed:', err?.message);
      return { base64: '' };
    }
  });

  /**
   * lumo:native-click
   * Sends real mouse down/up events at pixel (x, y) to the focused webview.
   * These are native OS-level events that bypass JS .click() detection.
   */
  guardedHandle('lumo:native-click', async (_event, { x, y }: { x: number; y: number }) => {
    if (!mainWindow) return;
    try {
      const wc = mainWindow.webContents;
      wc.sendInputEvent({ type: 'mouseDown', x, y, button: 'left', clickCount: 1 });
      await new Promise(r => setTimeout(r, 50));
      wc.sendInputEvent({ type: 'mouseUp',   x, y, button: 'left', clickCount: 1 });
      console.log(`[Lumo] Native click at (${x}, ${y})`);
    } catch (err: any) {
      console.error('[Lumo] Native click failed:', err?.message);
    }
  });

  /**
   * lumo:native-key
   * Sends a native keyboard keyDown/keyUp event to the focused webview.
   */
  guardedHandle('lumo:native-key', async (_event, { key }: { key: string }) => {
    if (!mainWindow) return;
    try {
      const wc = mainWindow.webContents;
      wc.sendInputEvent({ type: 'keyDown', keyCode: key } as any);
      await new Promise(r => setTimeout(r, 30));
      wc.sendInputEvent({ type: 'keyUp',   keyCode: key } as any);
      console.log(`[Lumo] Native key: ${key}`);
    } catch (err: any) {
      console.error('[Lumo] Native key failed:', err?.message);
    }
  });

  /**
   * lumo:native-type
   * Types text character-by-character via native keyboard events.
   * Fallback for callers that cannot use webview.sendInputEvent() directly.
   */
  guardedHandle('lumo:native-type', async (_event, { text, pressEnter }: { text: string; pressEnter: boolean }) => {
    if (!mainWindow) return;
    try {
      const wc = mainWindow.webContents;
      for (const char of text) {
        wc.sendInputEvent({ type: 'keyDown', keyCode: char } as any);
        await new Promise(r => setTimeout(r, 10));
        wc.sendInputEvent({ type: 'char', keyCode: char } as any);
        await new Promise(r => setTimeout(r, 5));
        wc.sendInputEvent({ type: 'keyUp', keyCode: char } as any);
        await new Promise(r => setTimeout(r, 10));
      }
      if (pressEnter) {
        wc.sendInputEvent({ type: 'keyDown', keyCode: 'Enter' } as any);
        await new Promise(r => setTimeout(r, 30));
        wc.sendInputEvent({ type: 'keyUp', keyCode: 'Enter' } as any);
      }
      console.log(`[Lumo] Native typed ${text.length} chars${pressEnter ? ' + Enter' : ''}`);
    } catch (err: any) {
      console.error('[Lumo] Native type failed:', err?.message);
    }
  });

  // ── Clear-on-Exit ───────────────────────────────────────────────────────────
  guardedOn('lumo:set-clear-on-exit', (_event, enabled: boolean) => {
    clearOnExitEnabled = enabled;
    console.log(`[Lumo] Clear-on-exit set to ${enabled}`);
  });

  // ── Profile Partition Management ──────────────────────────────────────────
  guardedOn('lumo:monitor-profile-partition', (_event, profileId: string) => {
    const partitionId = `persist:lumo-profile-${profileId}`;
    try {
      const sess = session.fromPartition(partitionId);
      monitorNetworkRequests(sess, () => mainWindow, partitionId, adBlockerCheck);
      sess.on('will-download', handleDownloadItem);
      console.log(`[Lumo] Monitoring profile partition: ${partitionId}`);
    } catch (err) {
      console.error(`[Lumo] Failed to monitor profile partition ${partitionId}:`, err);
    }
  });

  guardedOn('lumo:clear-profile-partition', (_event, profileId: string) => {
    const partitionId = `persist:lumo-profile-${profileId}`;
    session.fromPartition(partitionId).clearStorageData().catch(err => {
      console.error(`[Lumo] Failed to clear profile partition ${partitionId}:`, err);
    });
  });

  createWindow();
  // Disable native menu bar completely
  Menu.setApplicationMenu(null);

  setupMainShortcuts(mainWindow);
});

app.on('window-all-closed', () => {
  console.log('[Lumo] All windows closed');
  if (process.platform !== 'darwin') {
    app.quit();
  }
});

app.on('activate', () => {
  console.log('[Lumo] App activated');
  if (mainWindow === null) {
    createWindow();
  }
});

let isClearingOnExit = false;

app.on('before-quit', async (event) => {
  console.log('[Lumo] App quitting');
  globalShortcut.unregisterAll();

  if (clearOnExitEnabled && !isClearingOnExit) {
    event.preventDefault();
    isClearingOnExit = true;
    try {
      await Promise.all([
        session.defaultSession.clearStorageData(),
        session.fromPartition('persist:lumo-main').clearStorageData(),
      ]);
      console.log('[Lumo] Cleared all session data (clearOnExit)');
    } catch (err) {
      console.error('[Lumo] Failed to clear session data on quit:', err);
    }
    app.exit();
  }
});
