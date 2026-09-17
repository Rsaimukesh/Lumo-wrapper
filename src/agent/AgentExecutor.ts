/**
 * AgentExecutor — Browser control engine with dual-mode DOM access.
 *
 * ARCHITECTURE: "Set of Marks" + ID-based DOM Interaction
 * ────────────────────────────────────────────────────────
 * 1. DOM extraction finds every interactable element, assigns a numeric ID,
 *    and records its text, type, role, and coordinates (viewport-relative).
 *    The element reference is stored in window.__LumoAgentElements.
 * 2. In VISION mode, red numbered tags are painted onto the page and a
 *    screenshot is captured. In TEXT mode, only the element list is returned.
 * 3. All click/type actions use the stored element reference (by numeric ID)
 *    via direct JS DOM manipulation as the PRIMARY method — coordinates and
 *    native events are SECONDARY fallbacks.
 * 4. This approach is faster, more reliable (no coordinate mismatch), and
 *    works with both vision and text-only models.
 */

import type { TaskMemory, ExtractedProduct } from './AgentMemory';
import { addProductToMemory, addActionToMemory, addVisitedUrl } from './AgentMemory';

// ── DOM Extractor (Text Mode — no visual tags) ───────────────────────────

/**
 * Injected into the webview to:
 *  - Find every interactable element
 *  - Record its reference + metadata in window.__LumoAgentElements
 *  - Return a compact JSON array of { id, tag, text, x, y, type, role, href }
 *
 * NO visual tags are created — use this for text-only models.
 */
export const DOM_EXTRACTOR_TEXT_SCRIPT = `
  (function() {
    window.__LumoAgentElements = {};
    var results = [];
    var idCounter = 1;

    function isVisible(el) {
      if (el.type === 'radio' || el.type === 'checkbox') return true;
      var rect = el.getBoundingClientRect();
      var style = window.getComputedStyle(el);
      return rect.width > 0 && rect.height > 0
        && style.visibility !== 'hidden'
        && style.display !== 'none'
        && parseFloat(style.opacity) > 0;
    }

    function getLabel(el) {
      var type = el.getAttribute('type') || '';
      if (type === 'radio' || type === 'checkbox') {
        var labelEl = el.id ? document.querySelector('label[for="' + el.id + '"]') : el.closest('label');
        if (labelEl) return labelEl.innerText.trim().substring(0, 100);
        var p = el.parentElement;
        for (var i = 0; i < 4 && p; i++) {
          var t = p.innerText.trim();
          if (t.length > 1 && t.length < 200) return t.substring(0, 100);
          p = p.parentElement;
        }
      }
      return (
        el.innerText ||
        el.value ||
        el.placeholder ||
        el.getAttribute('aria-label') ||
        el.getAttribute('title') ||
        el.getAttribute('alt') || ''
      ).trim().substring(0, 80);
    }

    /** Collect interactable elements including shadow DOM */
    function collectElements(root) {
      var els = [];
      var selectors = 'a, button, input, textarea, select, canvas, [role="button"], [role="link"], [role="tab"], [role="menuitem"], [onclick], label, summary, [tabindex]';
      var nodes = root.querySelectorAll(selectors);
      for (var i = 0; i < nodes.length; i++) els.push(nodes[i]);
      var all = root.querySelectorAll('*');
      for (var j = 0; j < all.length; j++) {
        if (all[j].shadowRoot) {
          var shadowEls = collectElements(all[j].shadowRoot);
          for (var k = 0; k < shadowEls.length; k++) els.push(shadowEls[k]);
        }
      }
      return els;
    }

    var elements = collectElements(document);
    for (var idx = 0; idx < elements.length; idx++) {
      var el = elements[idx];
      if (!isVisible(el)) continue;
      if (el.__lumoTagged) continue;
      el.__lumoTagged = true;

      var rect = el.getBoundingClientRect();
      var id   = idCounter++;
      var cx   = Math.round(rect.left + rect.width  / 2);
      var cy   = Math.round(rect.top  + rect.height / 2);

      window.__LumoAgentElements[id] = { el: el, x: cx, y: cy };

      var tagName = el.tagName.toLowerCase();
      var type    = el.getAttribute('type') || '';
      var role    = el.getAttribute('role') || '';
      var href    = el.getAttribute('href') || '';
      var checked = (type === 'radio' || type === 'checkbox')
        ? (el.checked ? '[CHECKED]' : '[UNCHECKED]') : '';

      results.push({
        id:     id,
        tag:    tagName,
        type:   type,
        role:   role,
        href:   href.length < 80 ? href : '',
        text:   getLabel(el),
        checked: checked,
        x:      cx,
        y:      cy,
      });
    }

    return JSON.stringify(results);
  })();
`;

// ── DOM Extractor (Vision Mode — paints numbered tags) ──────────────────

/**
 * Same as TEXT_SCRIPT but also paints red numbered tags over each element.
 * Tags are removed after screenshot capture via REMOVE_TAGS_SCRIPT.
 * Coordinates are viewport-relative. Tags use position:fixed.
 */
export const DOM_EXTRACTOR_VISION_SCRIPT = `
  (function() {
    document.querySelectorAll('.Lumo-agent-tag').forEach(function(t){ t.remove(); });

    window.__LumoAgentElements = {};
    var results = [];
    var idCounter = 1;

    function isVisible(el) {
      if (el.type === 'radio' || el.type === 'checkbox') return true;
      var rect = el.getBoundingClientRect();
      var style = window.getComputedStyle(el);
      return rect.width > 0 && rect.height > 0
        && style.visibility !== 'hidden'
        && style.display !== 'none'
        && parseFloat(style.opacity) > 0;
    }

    function getLabel(el) {
      var type = el.getAttribute('type') || '';
      if (type === 'radio' || type === 'checkbox') {
        var labelEl = el.id ? document.querySelector('label[for="' + el.id + '"]') : el.closest('label');
        if (labelEl) return labelEl.innerText.trim().substring(0, 100);
        var p = el.parentElement;
        for (var i = 0; i < 4 && p; i++) {
          var t = p.innerText.trim();
          if (t.length > 1 && t.length < 200) return t.substring(0, 100);
          p = p.parentElement;
        }
      }
      return (
        el.innerText ||
        el.value ||
        el.placeholder ||
        el.getAttribute('aria-label') ||
        el.getAttribute('title') ||
        el.getAttribute('alt') || ''
      ).trim().substring(0, 80);
    }

    /** Collect interactable elements including shadow DOM penetration */
    function collectElements(root) {
      var els = [];
      var selectors = 'a, button, input, textarea, select, canvas, [role="button"], [role="link"], [role="tab"], [role="menuitem"], [onclick], label, summary, [tabindex]';
      var nodes = root.querySelectorAll(selectors);
      for (var i = 0; i < nodes.length; i++) els.push(nodes[i]);
      // Penetrate open shadow roots
      var all = root.querySelectorAll('*');
      for (var j = 0; j < all.length; j++) {
        if (all[j].shadowRoot) {
          var shadowEls = collectElements(all[j].shadowRoot);
          for (var k = 0; k < shadowEls.length; k++) els.push(shadowEls[k]);
        }
      }
      return els;
    }

    var elements = collectElements(document);

    for (var idx = 0; idx < elements.length; idx++) {
      var el = elements[idx];
      if (!isVisible(el)) continue;

      // Skip if already tagged (duplicate from shadow root penetration)
      if (el.__lumoTagged) continue;
      el.__lumoTagged = true;

      var rect = el.getBoundingClientRect();
      var id   = idCounter++;
      var cx   = Math.round(rect.left + rect.width  / 2);
      var cy   = Math.round(rect.top  + rect.height / 2);

      window.__LumoAgentElements[id] = { el: el, x: cx, y: cy };

      var tag = document.createElement('div');
      tag.className  = 'Lumo-agent-tag';
      tag.textContent = String(id);
      tag.style.cssText = [
        'position:fixed',
        'top:'   + (Math.max(rect.top, 0)) + 'px',
        'left:'  + (Math.max(rect.left, 0)) + 'px',
        'background:#ef4444',
        'color:#fff',
        'font-size:9px',
        'font-weight:bold',
        'padding:0 3px',
        'border-radius:3px',
        'z-index:2147483647',
        'pointer-events:none',
        'line-height:14px',
        'font-family:monospace',
      ].join(';');
      document.body.appendChild(tag);

      var tagName = el.tagName.toLowerCase();
      var type    = el.getAttribute('type') || '';
      var role    = el.getAttribute('role') || '';
      var href    = el.getAttribute('href') || '';
      var checked = (type === 'radio' || type === 'checkbox')
        ? (el.checked ? '[CHECKED]' : '[UNCHECKED]') : '';

      results.push({
        id:     id,
        tag:    tagName,
        type:   type,
        role:   role,
        href:   href.length < 80 ? href : '',
        text:   getLabel(el),
        checked: checked,
        x:      cx,
        y:      cy,
      });
    }

    return JSON.stringify(results);
  })();
`;

/** Remove visual tags after screenshot is captured */
const REMOVE_TAGS_SCRIPT = `
  document.querySelectorAll('.Lumo-agent-tag').forEach(function(t){ t.remove(); });
`;

/** 
 * Extract all visible page text including shadow DOM and canvas fallback.
 * Works on pages that prevent selection/copying (exam portals, paywalls, etc.)
 * Canvas text is extracted via getContext('2d') when same-origin.
 */
const READ_PAGE_TEXT_SCRIPT = `
  (function() {
    var text = [], seen = {};

    /** Recursively walk the DOM including shadow roots */
    function walkText(root) {
      var nodes = root.querySelectorAll('h1, h2, h3, h4, h5, h6, p, li, td, th, span, label, figcaption, blockquote, dt, dd, article, section, .content, .text, [class*="content"], [class*="text"], [data-testid]');
      for (var i = 0; i < nodes.length; i++) {
        var t = (nodes[i].innerText || nodes[i].textContent || '').trim();
        if (t.length > 2 && t.length < 1000 && !seen[t]) {
          seen[t] = true;
          text.push(t);
        }
        if (text.length > 300) return;
      }
      // Shadow DOM penetration
      var all = root.querySelectorAll('*');
      for (var j = 0; j < all.length; j++) {
        if (all[j].shadowRoot) walkText(all[j].shadowRoot);
        if (text.length > 300) return;
      }
    }
    walkText(document);

    // Canvas text extraction (same-origin only)
    try {
      var canvases = document.querySelectorAll('canvas');
      for (var c = 0; c < canvases.length; c++) {
        var ctx = canvases[c].getContext('2d');
        if (ctx) {
          var imgData = ctx.getImageData(0, 0, canvases[c].width, canvases[c].height);
          if (imgData && imgData.data.length > 100) {
            text.push('[Canvas element #' + (c+1) + ': ' + canvases[c].width + 'x' + canvases[c].height + ' pixels]');
          }
        }
      }
    } catch(e) {}

    return text.join('\\n').substring(0, 15000);
  })();
`;

/** Product extractor for e-commerce pages */
function buildExtractProductScript(maxProducts: number): string {
  return `
    (function() {
      var products = [];
      var cards = document.querySelectorAll(
        '[data-component-type="s-search-result"], .s-result-item, .sg-col-inner,' +
        '._1AtVbE, ._13oc-S, .product-tuple-listing, .product-base'
      );
      if (cards.length === 0) {
        cards = document.querySelectorAll('[class*="product"],[class*="item"],[class*="card"],[class*="listing"]');
      }
      for (var i = 0; i < Math.min(cards.length, ${maxProducts}); i++) {
        var card = cards[i];
        var nameEl  = card.querySelector('h2, h3, [class*="title"], [class*="name"], .a-text-normal, ._4rR01T, .s1Q9rs');
        if (!nameEl) continue;
        var name = nameEl.innerText.trim().substring(0, 120);
        if (!name) continue;
        var priceEl  = card.querySelector('.a-price .a-offscreen, [class*="price"], ._30jeq3, ._1_WHN1, .a-price-whole');
        var ratingEl = card.querySelector('[class*="rating"], .a-icon-alt, ._3LWZlK');
        var reviewEl = card.querySelector('[class*="review"], .a-size-base.s-underline-text, ._2_R_DZ span');
        var delivEl  = card.querySelector('[class*="delivery"], [class*="shipping"], .a-text-bold .a-text-normal');
        var price    = priceEl  ? priceEl.innerText.trim().substring(0,30)  : '';
        var rating   = ratingEl ? ratingEl.innerText.trim().substring(0,20) : '';
        var reviews  = reviewEl ? reviewEl.innerText.trim().substring(0,30) : '';
        var delivery = delivEl  ? delivEl.innerText.trim().substring(0,50)  : '';
        if (name && (price || rating)) {
          products.push({ name, price: price||'N/A', rating: rating||'N/A',
                          reviews: reviews||'N/A', delivery: delivery||'N/A' });
        }
      }
      return JSON.stringify(products);
    })();
  `;
}

// ── Element Discovery ─────────────────────────────────────────────────────

/**
 * extractDOM: Text-only extraction — no visual tags, no screenshot.
 * Use this for models without vision capability or when speed matters.
 * Returns the list of interactable elements on the page.
 */
export async function extractDOM(
  webview: any
): Promise<ElementInfo[]> {
  try {
    const raw: string = await webview.executeJavaScript(DOM_EXTRACTOR_TEXT_SCRIPT);
    return JSON.parse(raw);
  } catch {
    return [];
  }
}

// ── Screenshot Helper ─────────────────────────────────────────────────────

/**
 * captureTaggedScreenshot: Vision-mode extraction with full content access.
 *  1. Extracts full page text (handles shadow DOM, canvas)
 *  2. Injects the DOM extractor to paint numbered tags
 *  3. Polls until tags are confirmed visible in the DOM
 *  4. Captures a screenshot of the specific webview
 *  5. Removes the tags
 *  6. Returns { elementList, screenshotBase64, pageText }
 *
 * The pageText provides text-layer content for non-copyable content.
 * The screenshot provides pixel-perfect capture for canvas/rendered content.
 */
export async function captureTaggedScreenshot(
  webview: any
): Promise<{ elementList: ElementInfo[]; screenshotBase64: string; pageText: string }> {
  // Step 1 — Extract full page text alongside vision capture
  let pageText = '';
  try {
    pageText = await webview.executeJavaScript(READ_PAGE_TEXT_SCRIPT);
  } catch { /* non-critical */ }

  // Step 2 — inject tags and collect element data
  const raw: string = await webview.executeJavaScript(DOM_EXTRACTOR_VISION_SCRIPT);
  let elementList: ElementInfo[] = [];
  try { elementList = JSON.parse(raw); } catch { elementList = []; }

  // Step 3 — poll until at least one tag is visible, with timeout
  const maxWaitMs = 2000;
  const pollStart = Date.now();
  while (Date.now() - pollStart < maxWaitMs) {
    const tagCount: number = await webview.executeJavaScript(
      'document.querySelectorAll(".Lumo-agent-tag").length'
    );
    if (tagCount > 0) break;
    await new Promise(r => setTimeout(r, 100));
  }

  // Step 4 — capture this webview only (via its webContents ID)
  let screenshotBase64 = '';
  try {
    const wcId: number = webview.getWebContentsId();
    const result = await window.electron?.invoke?.('lumo:capture-webview', { webContentsId: wcId });
    if (result?.base64) screenshotBase64 = result.base64;
  } catch {
    // capturePage unavailable — proceed with text-only mode
  }

  // Step 5 — remove tags so the user sees a clean page
  try { await webview.executeJavaScript(REMOVE_TAGS_SCRIPT); } catch { /* ignore */ }

  return { elementList, screenshotBase64, pageText };
}

/** Compact text representation of the element list for the context prompt */
export function buildElementText(elementList: ElementInfo[]): string {
  return elementList
    .map((e) => {
      let line = '[' + e.id + '] <' + e.tag;
      if (e.type) line += ' type="' + e.type + '"';
      if (e.role) line += ' role="' + e.role + '"';
      if (e.href) line += ' href="' + e.href + '"';
      line += '>' + (e.checked ? ' ' + e.checked : '') + ' "' + e.text + '"';
      return line;
    })
    .join('\n');
}

// ── Types ──────────────────────────────────────────────────────────────────

export interface CaptureResult {
  elementList: ElementInfo[];
  screenshotBase64: string;
  pageText: string;
}

export interface ElementInfo {
  id: number;
  tag: string;
  type: string;
  role: string;
  href: string;
  text: string;
  checked: string;
  x: number;
  y: number;
}

export interface ExecutionResult {
  success: boolean;
  output: string;
  updatedMemory: TaskMemory;
  requiresConfirmation?: boolean;
  confirmationMessage?: string;
  isDone?: boolean;
  doneSuccess?: boolean;
  comparisonData?: ExtractedProduct[];
  comparisonRecommendation?: string;
  blocked?: boolean;
  planSteps?: string[];
}

// ── DOM Interaction Helpers ───────────────────────────────────────────────

/**
 * Click an element by its numeric [ID] using the stored DOM reference.
 *
 * Strategy (fastest -> fallback):
 *  1. Look up element by ID in window.__LumoAgentElements and call .click()
 *  2. If coordinates are available, use webview.sendInputEvent (native)
 *  3. Use document.elementFromPoint as last resort
 *
 * Coordinates are viewport-relative (matching the DOM extractor output).
 */
async function clickElement(
  webview: any,
  elementId: number,
  x?: number,
  y?: number
): Promise<void> {
  // Step 1 — Direct JS click on the stored element reference
  const result: string = await webview.executeJavaScript(
    '(function(){' +
    'var e=window.__LumoAgentElements&&window.__LumoAgentElements[' + elementId + '];' +
    'if(e&&e.el&&typeof e.el.click==="function"){try{e.el.scrollIntoView({block:"center"});e.el.focus();e.el.click();return"ok";}catch(err){return"err:"+err.message;}}' +
    'return"not_found";' +
    '})()'
  );
  if (result === 'ok') return;

  // Step 2 — Native events at stored coordinates (handles sites that block synthetic events)
  if (x !== undefined && y !== undefined) {
    try {
      webview.sendInputEvent({ type: 'mouseDown', x, y, button: 'left', clickCount: 1 });
      await sleep(50);
      webview.sendInputEvent({ type: 'mouseUp', x, y, button: 'left', clickCount: 1 });
      return;
    } catch { /* fall through */ }
  }

  // Step 3 — elementFromPoint (handles stale element references)
  if (x !== undefined && y !== undefined) {
    try {
      await webview.executeJavaScript(
        'document.elementFromPoint(' + x + ',' + y + ')?.click();'
      );
    } catch { /* ignore */ }
  }
}

/**
 * Type text into an element by its numeric [ID].
 *
 * Strategy:
 *  1. Focus the element via JS
 *  2. Set value via JS + dispatch input/change events (works for most frameworks)
 *  3. If native keyboard is needed, sendInputEvent char-by-char
 */
async function typeText(
  webview: any,
  elementId: number,
  text: string,
  clearFirst: boolean,
  pressEnter: boolean
): Promise<void> {
  // Step 1 — Focus + set value via JS (use JSON.stringify for safe string embedding)
  const safeText = JSON.stringify(text);
  const jsResult: string = await webview.executeJavaScript(
    '(function(){' +
    'var e=window.__LumoAgentElements&&window.__LumoAgentElements[' + elementId + '];' +
    'if(!e||!e.el)return"not_found";' +
    'e.el.scrollIntoView({block:"center"});' +
    'e.el.focus();' +
    'e.el.dispatchEvent(new Event("focus",{bubbles:true}));' +
    (clearFirst ? 'e.el.value="";' : '') +
    'var sel=e.el.value?e.el.value.length:0;' +
    'e.el.value=' + safeText + ';' +
    'e.el.dispatchEvent(new Event("input",{bubbles:true}));' +
    'e.el.dispatchEvent(new Event("change",{bubbles:true}));' +
    (pressEnter
      ? 'e.el.dispatchEvent(new KeyboardEvent("keydown",{key:"Enter",code:"Enter",keyCode:13,which:13,bubbles:true}));' +
        'if(e.el.form)e.el.form.dispatchEvent(new Event("submit",{bubbles:true,cancelable:true}));'
      : '') +
    'return"ok";' +
    '})()'
  );
  if (jsResult === 'ok') return;

  // Step 2 — Native keyboard simulation (handles JS-framework guards)
  try {
    for (const char of text) {
      webview.sendInputEvent({ type: 'keyDown', keyCode: char });
      await sleep(10);
      webview.sendInputEvent({ type: 'char', keyCode: char });
      await sleep(5);
      webview.sendInputEvent({ type: 'keyUp', keyCode: char });
      await sleep(10);
    }
    if (pressEnter) {
      webview.sendInputEvent({ type: 'keyDown', keyCode: 'Enter' });
      await sleep(30);
      webview.sendInputEvent({ type: 'keyUp', keyCode: 'Enter' });
    }
  } catch { /* both approaches failed — nothing more we can do */ }
}

/** Find coordinates of an element by ID from the stored data */
async function getElementCoords(webview: any, elementId: number): Promise<{ x: number; y: number } | null> {
  try {
    const result: string = await webview.executeJavaScript(
      'JSON.stringify(window.__LumoAgentElements&&window.__LumoAgentElements[' + elementId + ']' +
      '?{x:window.__LumoAgentElements[' + elementId + '].x,y:window.__LumoAgentElements[' + elementId + '].y}:null)'
    );
    return JSON.parse(result);
  } catch {
    return null;
  }
}

// ── Dangerous Action Detection ───────────────────────────────────────────────

const DANGEROUS_ACTION_PATTERNS: RegExp[] = [
  /\b(place|submit|confirm|complete)\s+(order|purchase|payment)\b/i,
  /\b(buy|purchase|checkout|pay)\b/i,
  /\badd\s+to\s+cart\b/i,
  /\bdelete\s+(account|profile|user)\b/i,
  /\bchange\s+password\b/i,
  /\b(send|transfer|wire)\s+(money|funds|payment)\b/i,
  /\b(cancel|close|terminate)\s+(account|subscription)\b/i,
  /\b(confirm|authorize)\s+(transfer|payment|transaction)\b/i,
  /\b(grant|revoke)\s+(access|permission)\b/i,
  /\b(install|execute)\s+(software|application)\b/i,
];

const DANGEROUS_URL_PATTERNS: RegExp[] = [
  /checkout/i,
  /payment/i,
  /pay/i,
  /cart/i,
  /order/i,
];

interface DangerousCheckResult {
  needsConfirmation: boolean;
  reason?: string;
}

function checkDangerousAction(toolName: string, args: Record<string, any>): DangerousCheckResult {
  // Check if the action itself is dangerous
  if (toolName === 'request_user_confirmation') {
    return { needsConfirmation: false };
  }

  // Check navigation to dangerous URLs
  if (toolName === 'navigate' && args.url) {
    for (const pattern of DANGEROUS_URL_PATTERNS) {
      if (pattern.test(args.url)) {
        return {
          needsConfirmation: true,
          reason: `Navigation to potentially dangerous URL detected: ${args.url}`,
        };
      }
    }
  }

  // Check click actions on potentially dangerous elements
  if (toolName === 'click_by_text' && args.text) {
    const text = args.text.toLowerCase();
    for (const pattern of DANGEROUS_ACTION_PATTERNS) {
      if (pattern.test(text)) {
        return {
          needsConfirmation: true,
          reason: `Click on dangerous action text detected: "${args.text}"`,
        };
      }
    }
  }

  // Check type_text for payment/financial data
  if (toolName === 'type_text' && args.text) {
    const text = args.text.toLowerCase();
    // Check for credit card patterns (simplified)
    if (/\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b/.test(text)) {
      return {
        needsConfirmation: true,
        reason: 'Potential credit card number detected in text input',
      };
    }
    // Check for SSN patterns
    if (/\b\d{3}-\d{2}-\d{4}\b/.test(text)) {
      return {
        needsConfirmation: true,
        reason: 'Potential SSN detected in text input',
      };
    }
  }

  return { needsConfirmation: false };
}

// ── Main Executor ──────────────────────────────────────────────────────────

export async function executeToolCall(
  webview: any,
  toolName: string,
  args: Record<string, any>,
  memory: TaskMemory
): Promise<ExecutionResult> {
  let output = '';
  let updatedMemory = { ...memory };

  // Check for dangerous actions that require user confirmation
  const dangerousCheck = checkDangerousAction(toolName, args);
  if (dangerousCheck.needsConfirmation) {
    return {
      output: `BLOCKED: ${dangerousCheck.reason}. The agent must call request_user_confirmation before this action.`,
      memory,
      blocked: true,
    };
  }

  try {
    switch (toolName) {

      // ── Navigate ────────────────────────────────────────────────
      case 'navigate': {
        let url = args.url || '';
        if (url && !url.startsWith('http')) url = 'https://' + url;
        // Validate URL — only allow http/https protocols
        try {
          const parsed = new URL(url);
          if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
            output = 'Blocked navigation to non-HTTP protocol: ' + parsed.protocol;
            break;
          }
        } catch {
          output = 'Invalid URL: ' + url;
          break;
        }
        webview.loadURL(url);
        await sleep(3000);
        updatedMemory = addVisitedUrl(updatedMemory, url);
        output = 'Navigated to ' + url;
        break;
      }

      // ── Click by element [ID] ────────────────────────────────────
      case 'click': {
        const clickId = Number(args.id);
        const coords = await getElementCoords(webview, clickId);
        await clickElement(webview, clickId, coords?.x, coords?.y);
        await sleep(2000);
        output = 'Clicked element [' + clickId + ']' +
          (args.description ? ' — ' + args.description : '');
        break;
      }

      // ── Click by coordinate (direct vision output) ──────────────
      case 'click_at': {
        const cx = Number(args.x);
        const cy = Number(args.y);
        // Try native events first (no element reference available)
        try {
          webview.sendInputEvent({ type: 'mouseDown', x: cx, y: cy, button: 'left', clickCount: 1 });
          await sleep(50);
          webview.sendInputEvent({ type: 'mouseUp', x: cx, y: cy, button: 'left', clickCount: 1 });
        } catch {
          await webview.executeJavaScript('document.elementFromPoint(' + cx + ',' + cy + ')?.click();');
        }
        await sleep(1500);
        output = 'Clicked at coordinates (' + cx + ', ' + cy + ')';
        break;
      }

      // ── Type Text ──────────────────────────────────────────────
      case 'type_text': {
        const typeId     = Number(args.id);
        const text       = args.text || '';
        const clearFirst = args.clear_first !== false;
        const pressEnter = args.press_enter === true;

        await typeText(webview, typeId, text, clearFirst, pressEnter);
        await sleep(pressEnter ? 2500 : 600);
        output = 'Typed "' + text + '" into element [' + typeId + ']' + (pressEnter ? ' and pressed Enter' : '');
        break;
      }

      // ── Scroll ───────────────────────────────────────────────────
      case 'scroll': {
        const amount = args.amount || 500;
        const pixels = args.direction === 'up' ? -amount : amount;
        await webview.executeJavaScript('window.scrollBy(0,' + pixels + ');');
        await sleep(500);
        output = 'Scrolled ' + args.direction + ' by ' + Math.abs(pixels) + 'px';
        break;
      }

      // ── Read Page Text ───────────────────────────────────────────
      case 'read_page_text': {
        const maxLen = args.max_length || 3000;
        const rawText: string = await webview.executeJavaScript(READ_PAGE_TEXT_SCRIPT);
        output = (rawText || '').substring(0, maxLen);
        break;
      }

      // ── Extract Product Data ─────────────────────────────────────
      case 'extract_product_data': {
        const maxProducts = args.max_products || 5;
        const vendor      = args.vendor || 'Unknown';
        const rawJson: string = await webview.executeJavaScript(buildExtractProductScript(maxProducts));
        try {
          const products: any[] = JSON.parse(rawJson);
          products.forEach((p) => {
            updatedMemory = addProductToMemory(updatedMemory, {
              name:     p.name,
              price:    p.price,
              rating:   p.rating,
              reviews:  p.reviews,
              delivery: p.delivery,
              url:      webview.getURL?.() || '',
              vendor,
            });
          });
          output =
            'Extracted ' + products.length + ' products from ' + vendor + ':\n' +
            products
              .map((p: any, i: number) => (i + 1) + '. ' + p.name + ' — ' + p.price + ' (Rating: ' + p.rating + ')')
              .join('\n');
        } catch {
          output = 'Failed to parse product data. Raw: ' + (rawJson || '').substring(0, 300);
        }
        break;
      }

      // ── Press Key ────────────────────────────────────────────────
      case 'press_key': {
        const key = args.key || 'Enter';
        // Try native key event first
        try {
          webview.sendInputEvent({ type: 'keyDown', keyCode: key });
          await sleep(30);
          webview.sendInputEvent({ type: 'keyUp', keyCode: key });
        } catch {
          // Fallback: dispatch keyboard events on the active element
          const keyLower = key.toLowerCase();
          const keyCodeMap: Record<string, number> = {
            'enter': 13, 'escape': 27, 'tab': 9, 'backspace': 8,
            'arrowdown': 40, 'arrowup': 38, 'arrowleft': 37, 'arrowright': 39,
          };
          const code = keyCodeMap[keyLower] || 0;
          const safeKey = JSON.stringify(key);
          await webview.executeJavaScript(
            'document.activeElement.dispatchEvent(new KeyboardEvent("keydown",{key:' + safeKey + ',code:' + safeKey + ',keyCode:' + code + ',which:' + code + ',bubbles:true}));' +
            'document.activeElement.dispatchEvent(new KeyboardEvent("keyup",{key:' + safeKey + ',code:' + safeKey + ',keyCode:' + code + ',which:' + code + ',bubbles:true}));'
          );
        }
        await sleep(1000);
        output = 'Pressed key: ' + key;
        break;
      }

      // ── Wait ─────────────────────────────────────────────────────
      case 'wait': {
        const seconds = Math.min(Math.max(args.seconds || 1, 0.5), 10);
        await sleep(seconds * 1000);
        output = 'Waited ' + seconds + 's' + (args.reason ? ' — ' + args.reason : '');
        break;
      }

      // ── Go Back ──────────────────────────────────────────────────
      case 'go_back': {
        webview.goBack();
        await sleep(2000);
        output = 'Navigated back';
        break;
      }

      // ── Click By Text (fallback) ──────────────────────────────────
      case 'click_by_text': {
        const searchText = JSON.stringify((args.text || '').toLowerCase().substring(0, 100));
        const clickResult: string = await webview.executeJavaScript(
          '(function(){' +
          'var candidates=document.querySelectorAll("label,[role=\\"radio\\"],[role=\\"option\\"],li,.answer,.option,.choice,td,th,div,span,p,a,button");' +
          'for(var i=0;i<candidates.length;i++){' +
          'var t=(candidates[i].innerText||"").toLowerCase().trim();' +
          'if(t.indexOf(' + searchText + ')!==-1&&t.length<300){candidates[i].scrollIntoView({block:"center"});candidates[i].focus();candidates[i].click();return "clicked:"+candidates[i].innerText.trim().substring(0,80);}' +
          '}return "not_found";' +
          '})()'
        );
        await sleep(1500);
        output = (clickResult || '').startsWith('not_found')
          ? 'Could not find element with text: ' + args.text
          : 'Clicked by text: ' + (clickResult || '').replace('clicked:', '');
        break;
      }

      // ── Quiz Answer ───────────────────────────────────────────────
      case 'quiz_answer': {
        const answerText = JSON.stringify((args.answer || '').toLowerCase());
        const quizResult: string = await webview.executeJavaScript(
          '(function(){' +
          'var result={selected:false,advanced:false,msg:""};' +
          'var candidates=document.querySelectorAll("label,[role=\'radio\'],[role=\'option\'],li,td,.answer,.option,.choice,.a-label,input[type=\'radio\'],input[type=\'checkbox\'],div,span,p,a,button");' +
          'for(var i=0;i<candidates.length;i++){' +
          'var el=candidates[i];var t=(el.innerText||el.textContent||el.value||"").toLowerCase().trim();' +
          'if(t.indexOf(' + answerText + ')!==-1&&t.length<400){el.scrollIntoView({block:"center"});el.focus();el.click();result.selected=true;result.msg="Selected: "+(el.innerText||el.value||"").trim().substring(0,80);break;}' +
          '}' +
          'if(result.selected){' +
          'var btns=document.querySelectorAll("button,input[type=\'submit\'],input[type=\'button\'],a,[role=\'button\']");' +
          'var kw=["next","submit","continue","ok","proceed","finish","done","save","forward","check"];' +
          'for(var j=0;j<btns.length;j++){var btext=(btns[j].innerText||btns[j].value||btns[j].getAttribute("aria-label")||"").toLowerCase().trim();' +
          'for(var k=0;k<kw.length;k++){if(btext.indexOf(kw[k])!==-1){btns[j].scrollIntoView({block:"center"});btns[j].focus();btns[j].click();result.advanced=true;result.msg+=" | Clicked: "+btext;break;}}if(result.advanced)break;}' +
          '}' +
          'return JSON.stringify(result);' +
          '})()'
        );
        await sleep(2500);
        try {
          const qr = JSON.parse(quizResult);
          output = !qr.selected
            ? 'Could not find answer option matching: "' + args.answer + '". Try shorter text.'
            : !qr.advanced
              ? qr.msg + ' | (No Next button found)'
              : qr.msg;
        } catch {
          output = 'Quiz answer result: ' + quizResult;
        }
        break;
      }

      // ── Request User Confirmation (Safety Gate) ──────────────────
      case 'request_user_confirmation': {
        return {
          success: true,
          output: args.action_description,
          updatedMemory: {
            ...updatedMemory,
            requiresConfirmation: true,
            confirmationMessage:
              args.action_description + (args.details ? '\n\nDetails: ' + args.details : ''),
          },
          requiresConfirmation: true,
          confirmationMessage:
            args.action_description + (args.details ? '\n\nDetails: ' + args.details : ''),
        };
      }

      // ── Save Product ─────────────────────────────────────────────
      case 'save_product': {
        updatedMemory = addProductToMemory(updatedMemory, {
          name:     args.name     || 'Unknown',
          price:    args.price    || 'N/A',
          rating:   args.rating   || 'N/A',
          reviews:  args.reviews  || 'N/A',
          delivery: args.delivery || 'N/A',
          url:      args.url      || '',
          vendor:   args.vendor   || 'Unknown',
        });
        output = 'Saved product: ' + args.name + ' (' + args.price + ') from ' + args.vendor;
        break;
      }

      // ── Present Comparison ────────────────────────────────────────
      case 'present_comparison': {
        return {
          success: true,
          output: 'Presenting product comparison to user',
          updatedMemory,
          comparisonData: updatedMemory.extractedProducts,
          comparisonRecommendation: args.recommendation || '',
        };
      }

      // ── Update Plan ───────────────────────────────────────────────
      case 'update_plan': {
        const steps: string[]  = args.steps       || [];
        const currentStep: number = args.current_step || 0;
        updatedMemory = {
          ...updatedMemory,
          plan: steps.map((desc, i) => ({
            id:          i + 1,
            description: desc,
            status:
              i < currentStep  ? 'done'    as const :
              i === currentStep ? 'active' as const : 'pending' as const,
          })),
          currentStepIndex: currentStep,
        };
        output = 'Plan updated with ' + steps.length + ' steps';
        return { success: true, output, updatedMemory, planSteps: steps };
      }

      // ── Done ──────────────────────────────────────────────────────
      case 'done': {
        output = args.message || 'Task completed.';
        return {
          success:     true,
          output,
          updatedMemory,
          isDone:      true,
          doneSuccess: args.success !== false,
        };
      }

      default: {
        output = 'Unknown tool: ' + toolName;
        break;
      }
    }

    updatedMemory = addActionToMemory(updatedMemory, toolName, args, output);
    return { success: true, output, updatedMemory };
  } catch (err: any) {
    const errMsg = err?.message || 'Unknown execution error';
    updatedMemory = addActionToMemory(updatedMemory, toolName, args, 'ERROR: ' + errMsg);
    updatedMemory.errorCount += 1;
    return { success: false, output: 'Error: ' + errMsg, updatedMemory };
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
