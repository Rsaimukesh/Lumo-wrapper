/**
 * Shared security monitoring hooks
 *
 * Used by both the main renderer preload and webview preload scripts.
 * Each hook accepts a `reportEvent` callback so the caller controls
 * how events are dispatched (IPC, console, etc.).
 */

// ── Types ──────────────────────────────────────────────────────────────────────

type SecurityEventType =
  | 'network_request'
  | 'dom_mutation'
  | 'browser_api'
  | 'wasm_exec'
  | 'file_io'
  | 'permission_request'
  | 'user_event';

type DetectionCategory =
  | 'phishing'
  | 'malware'
  | 'cryptominer'
  | 'data_theft'
  | 'injection'
  | 'safe';

type DetectionAction = 'allow' | 'warn' | 'block';

interface DetectionResult {
  safe: boolean;
  threat?: string;
  confidence: number;
  category: DetectionCategory;
  action?: DetectionAction;
}

interface SecurityEventPayload {
  type: SecurityEventType;
  details: string;
  timestamp: string;
  source?: string;
  suspicious?: boolean;
  mitigated?: boolean;
  detection?: DetectionResult;
}

export type ReportSecurityEvent = (payload: SecurityEventPayload) => void;

// ── Crypto Wallet Patterns ─────────────────────────────────────────────────────

const CRYPTO_WALLET_PATTERNS = [
  /^0x[0-9a-fA-F]{40}$/,                      // Ethereum
  /^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$/,        // Bitcoin legacy
  /^bc1[a-zA-HJ-NP-Z0-9]{39,59}$/,            // Bitcoin bech32
  /^[LM3][a-km-zA-HJ-NP-Z1-9]{26,33}$/,       // Litecoin
  /^4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}$/,       // Monero
  /^T[A-Za-z1-9]{33}$/,                       // Tron
];

// ── Hook: Browser API Proxy (Clipboard Mitigation) ─────────────────────────────

export function isBrowserAPIsHooked(): boolean {
  return !!(typeof window !== 'undefined' && (window as any).__lumoClipboardHooked);
}

export function isNetworkAPIsHooked(): boolean {
  return !!(typeof window !== 'undefined' && (window as any).__lumoNetworkHooked);
}

export function hookBrowserAPIs(reportEvent: ReportSecurityEvent): void {
  if (typeof navigator !== 'undefined' && navigator.clipboard) {
    const originalReadText = navigator.clipboard.readText.bind(navigator.clipboard);
    const originalWriteText = navigator.clipboard.writeText.bind(navigator.clipboard);

    navigator.clipboard.readText = async function (): Promise<string> {
      reportEvent({
        type: 'browser_api',
        details: 'Clipboard readText() accessed by page script',
        source: window.location?.href,
        suspicious: true,
        timestamp: new Date().toISOString(),
      });
      return originalReadText();
    };

    navigator.clipboard.writeText = async function (data: string): Promise<void> {
      const preview = data.length > 60 ? data.substring(0, 60) + '...' : data;
      const isWalletAddress = CRYPTO_WALLET_PATTERNS.some((pattern) =>
        pattern.test(data.trim()),
      );

      if (isWalletAddress) {
        console.warn('[Lumo Security] Blocked clipboard overwrite with crypto wallet address.');
        reportEvent({
          type: 'browser_api',
          details: `Clipboard writeText() blocked — script tried to replace clipboard with crypto wallet address: "${preview}"`,
          source: window.location?.href || 'preload',
          suspicious: true,
          mitigated: true,
          timestamp: new Date().toISOString(),
          detection: {
            safe: false,
            threat: 'Clipboard hijack detected — crypto wallet address replacement',
            confidence: 95,
            category: 'data_theft',
            action: 'block',
          },
        });
        return Promise.resolve();
      }

      reportEvent({
        type: 'browser_api',
        details: `Clipboard writeText() called — content: "${preview}"`,
        source: window.location?.href,
        suspicious: false,
        timestamp: new Date().toISOString(),
      });
      return originalWriteText(data);
    };
  }
  (window as any).__lumoClipboardHooked = true;
}

// ── Hook: WebAssembly Execution Mitigation ─────────────────────────────────────

export function monitorWasmExecution(reportEvent: ReportSecurityEvent): void {
  if (typeof WebAssembly !== 'undefined') {
    const originalInstantiate = WebAssembly.instantiate.bind(WebAssembly);
    const originalInstantiateStreaming =
      WebAssembly.instantiateStreaming?.bind(WebAssembly);
    const originalCompile = WebAssembly.compile?.bind(WebAssembly);
    const originalCompileStreaming = WebAssembly.compileStreaming?.bind(WebAssembly);

    const checkWasmSize = (byteLength: number, label: string): boolean => {
      const sizeKB = byteLength / 1024;
      if (sizeKB > 1024) {
        console.warn(`[Lumo Security] Blocked large WebAssembly ${label} (${sizeKB.toFixed(1)}KB).`);
        reportEvent({
          type: 'wasm_exec',
          details: `WebAssembly ${label} blocked — oversized binary (${sizeKB.toFixed(1)}KB) likely crypto miner.`,
          source: window.location?.href || 'preload',
          suspicious: true,
          mitigated: true,
          timestamp: new Date().toISOString(),
          detection: {
            safe: false,
            threat: `Oversized WebAssembly binary (${(sizeKB / 1024).toFixed(1)}MB) — likely crypto miner`,
            confidence: 85,
            category: 'cryptominer',
            action: 'block',
          },
        });
        return false;
      }
      return true;
    };

    WebAssembly.instantiate = async function (
      bufferSource: BufferSource | WebAssembly.Module,
      importObject?: WebAssembly.Imports,
    ): Promise<WebAssembly.WebAssemblyInstantiatedSource | WebAssembly.Instance> {
      const byteLength =
        bufferSource instanceof ArrayBuffer ? bufferSource.byteLength : 0;
      const sizeKB = byteLength / 1024;
      const sizeStr =
        bufferSource instanceof ArrayBuffer
          ? `${sizeKB.toFixed(1)}KB`
          : 'Module';

      if (sizeKB > 1024 && !checkWasmSize(byteLength, 'instantiate')) {
        return Promise.reject(
          new Error('Lumo Security: WebAssembly execution blocked by active mitigation protocol.'),
        );
      }

      reportEvent({
        type: 'wasm_exec',
        details: `WebAssembly.instantiate() called — binary size: ${sizeStr}`,
        source: window.location?.href,
        suspicious: true,
        timestamp: new Date().toISOString(),
      });
      return originalInstantiate(bufferSource, importObject);
    } as typeof WebAssembly.instantiate;

    if (originalInstantiateStreaming) {
      WebAssembly.instantiateStreaming = async function (
        source: Response | PromiseLike<Response>,
        importObject?: WebAssembly.Imports,
      ): Promise<WebAssembly.WebAssemblyInstantiatedSource> {
        reportEvent({
          type: 'wasm_exec',
          details: 'WebAssembly.instantiateStreaming() called — streaming binary compilation',
          source: window.location?.href,
          suspicious: true,
          timestamp: new Date().toISOString(),
        });
        return originalInstantiateStreaming(source, importObject);
      };
    }

    // Hook WebAssembly.compile() to catch pre-compilation of large modules
    if (originalCompile) {
      WebAssembly.compile = async function (
        bufferSource: BufferSource,
      ): Promise<WebAssembly.Module> {
        const byteLength =
          bufferSource instanceof ArrayBuffer ? bufferSource.byteLength : 0;
        const sizeStr = `${(byteLength / 1024).toFixed(1)}KB`;

        if (!checkWasmSize(byteLength, 'compile')) {
          return Promise.reject(
            new Error('Lumo Security: WebAssembly compilation blocked by active mitigation protocol.'),
          );
        }

        reportEvent({
          type: 'wasm_exec',
          details: `WebAssembly.compile() called — binary size: ${sizeStr}`,
          source: window.location?.href,
          suspicious: true,
          timestamp: new Date().toISOString(),
        });
        return originalCompile(bufferSource);
      } as typeof WebAssembly.compile;
    }

    // Hook WebAssembly.compileStreaming()
    if (originalCompileStreaming) {
      WebAssembly.compileStreaming = async function (
        source: Response | PromiseLike<Response>,
      ): Promise<WebAssembly.Module> {
        reportEvent({
          type: 'wasm_exec',
          details: 'WebAssembly.compileStreaming() called — streaming binary compilation',
          source: window.location?.href,
          suspicious: true,
          timestamp: new Date().toISOString(),
        });
        return originalCompileStreaming(source);
      };
    }
  }
}

// ── Hook: DOM Mutation Observer ────────────────────────────────────────────────

export function observeDOMMutations(reportEvent: ReportSecurityEvent): void {
  const attach = (): void => {
    const observer = new MutationObserver((mutations) => {
      for (const mutation of mutations) {
        // Monitor attribute changes on security-sensitive attributes
        if (mutation.type === 'attributes' && mutation.attributeName) {
          const attr = mutation.attributeName;
          const target = mutation.target as HTMLElement;
          const tag = target.tagName?.toLowerCase();

          // Monitor href/src/action attribute changes on links, iframes, forms
          if (['href', 'src', 'action', 'formaction'].includes(attr)) {
            const newValue = target.getAttribute(attr);
            const suspicious = attr === 'href' && newValue?.startsWith('javascript:');
            if (suspicious) {
              reportEvent({
                type: 'dom_mutation',
                details: `Security-sensitive attribute changed on <${tag}>: ${attr}="${newValue?.substring(0, 100)}"`,
                source: window.location?.href,
                suspicious: true,
                timestamp: new Date().toISOString(),
              });
            }
          }
        }

        for (const node of Array.from(mutation.addedNodes)) {
          if (!(node instanceof HTMLElement)) continue;

          const tag = node.tagName?.toLowerCase();

          if (tag === 'script') {
            const src = (node as HTMLScriptElement).src;
            reportEvent({
              type: 'dom_mutation',
              details: src
                ? `Dynamic <script> injected: ${src}`
                : `Inline <script> injected (${(node.textContent || '').length} chars)`,
              source: window.location?.href,
              suspicious: true,
              timestamp: new Date().toISOString(),
            });
          }

          if (tag === 'iframe') {
            const src = (node as HTMLIFrameElement).src;
            const isHidden =
              node.style.display === 'none' ||
              node.style.visibility === 'hidden' ||
              node.style.opacity === '0' ||
              (node.offsetWidth === 0 && node.offsetHeight === 0);

            reportEvent({
              type: 'dom_mutation',
              details: `Dynamic <iframe> injected: ${src || '(no src)'}${isHidden ? ' [HIDDEN]' : ''}`,
              source: window.location?.href,
              suspicious: isHidden,
              timestamp: new Date().toISOString(),
            });
          }

          const innerScripts = node.querySelectorAll?.('script, iframe');
          if (innerScripts && innerScripts.length > 0) {
            reportEvent({
              type: 'dom_mutation',
              details: `Container element <${tag}> injected with ${innerScripts.length} nested script/iframe element(s)`,
              source: window.location?.href,
              suspicious: true,
              timestamp: new Date().toISOString(),
            });
          }
        }
      }
    });

    observer.observe(document.documentElement, {
      childList: true,
      subtree: true,
      attributes: true,
      attributeOldValue: false,
    });
  };

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', attach, { once: true });
  } else {
    attach();
  }
}

// ── Hook: Network API interception (fetch, XHR, WebSocket, sendBeacon) ─────────

export function hookNetworkAPIs(reportEvent: ReportSecurityEvent): void {
  // 1. Hook window.fetch()
  if (typeof fetch !== 'undefined') {
    const originalFetch = window.fetch.bind(window);
    window.fetch = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
      const method = (init?.method || 'GET').toUpperCase();
      const bodySize = init?.body ? (typeof init.body === 'string' ? init.body.length : 0) : 0;

      reportEvent({
        type: 'network_request',
        details: `fetch ${method} ${url}${bodySize > 0 ? ` (${bodySize} bytes body)` : ''}`,
        source: window.location?.href,
        timestamp: new Date().toISOString(),
      });

      return originalFetch(input, init);
    };
  }

  // 2. Hook XMLHttpRequest
  if (typeof XMLHttpRequest !== 'undefined') {
    const originalOpen = XMLHttpRequest.prototype.open;
    XMLHttpRequest.prototype.open = function (
      method: string,
      url: string | URL,
      async?: boolean,
      user?: string | null,
      password?: string | null,
    ): void {
      const urlStr = typeof url === 'string' ? url : url.href;
      reportEvent({
        type: 'network_request',
        details: `XHR ${(method || 'GET').toUpperCase()} ${urlStr}`,
        source: window.location?.href,
        timestamp: new Date().toISOString(),
      });
      return originalOpen.call(this, method, url, async ?? true, user ?? null, password ?? null);
    };
  }

  // 3. Hook WebSocket.send()
  if (typeof WebSocket !== 'undefined') {
    const originalSend = WebSocket.prototype.send;
    WebSocket.prototype.send = function (data: unknown): void {
      const size = typeof data === 'string' ? data.length : data instanceof Blob ? data.size : data instanceof ArrayBuffer ? data.byteLength : 0;
      reportEvent({
        type: 'network_request' as SecurityEventType,
        details: `WebSocket.send (${size} bytes) to ${this.url}`,
        source: window.location?.href,
        timestamp: new Date().toISOString(),
      });
      return originalSend.call(this, data as Parameters<typeof originalSend>[0]);
    };
  }

  // 4. Hook navigator.sendBeacon
  if (typeof navigator !== 'undefined' && navigator.sendBeacon) {
    const originalSendBeacon = navigator.sendBeacon.bind(navigator);
    navigator.sendBeacon = (url: string | URL, data?: BodyInit | null): boolean => {
      const urlStr = typeof url === 'string' ? url : url.href;
      const size = data ? (typeof data === 'string' ? data.length : data instanceof Blob ? data.size : data instanceof ArrayBuffer ? data.byteLength : 0) : 0;
      reportEvent({
        type: 'network_request' as SecurityEventType,
        details: `navigator.sendBeacon to ${urlStr}${size > 0 ? ` (${size} bytes)` : ''}`,
        source: window.location?.href,
        timestamp: new Date().toISOString(),
      });
      return originalSendBeacon(url, data);
    };
  }
  (window as any).__lumoNetworkHooked = true;
}
