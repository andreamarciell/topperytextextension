// Restored replacement engine: when user types a space, replace any matching triggers
// in inputs, textareas, and contenteditable elements. Triggers come from background cache.

let TRIGGERS = [];

function isSensitiveInput(el){ 
  try { 
    if (!el || !el.tagName) return false;
    const tagName = el.tagName.toLowerCase();
    const type = String(el.type || '').toLowerCase();
    const autocomplete = String(el.autocomplete || '').toLowerCase();
    
    // Password fields
    if (tagName === 'input' && type === 'password') return true;
    
    // Credit card fields
    if (autocomplete.includes('cc-') || autocomplete.includes('card')) return true;
    
    // Other sensitive autocomplete values
    const sensitiveAutocomplete = ['current-password', 'new-password', 'cc-number', 'cc-exp', 'cc-csc'];
    if (sensitiveAutocomplete.includes(autocomplete)) return true;
    
    // Name attributes that suggest sensitive data
    const name = String(el.name || '').toLowerCase();
    const sensitiveNames = ['password', 'passwd', 'pwd', 'pin', 'creditcard', 'ccnumber', 'cardnumber'];
    if (sensitiveNames.some(s => name.includes(s))) return true;
    
    return false; 
  } catch(_) { return false; } 
}

function fetchTriggers() {
  chrome.runtime.sendMessage({ type: 'CACHE_GET' }, (resp) => {
    TRIGGERS = (resp && Array.isArray(resp.items)) ? resp.items : [];
  });
}
fetchTriggers();

chrome.runtime.onMessage.addListener((msg) => {
  if (msg && msg.type === 'CACHE_UPDATED') {
    TRIGGERS = msg.payload.items || [];
  }
});

function sanitizeText(text) {
  if (typeof text !== 'string') return '';
  
  // Remove potentially dangerous characters and patterns
  return text
    .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '') // Remove script tags
    .replace(/<iframe\b[^<]*(?:(?!<\/iframe>)<[^<]*)*<\/iframe>/gi, '') // Remove iframe tags
    .replace(/javascript:/gi, '') // Remove javascript: protocols
    .replace(/data:/gi, '') // Remove data: protocols
    .replace(/vbscript:/gi, '') // Remove vbscript: protocols
    .replace(/on\w+\s*=/gi, ''); // Remove event handlers like onclick=
}

function validateTrigger(trigger) {
  if (typeof trigger !== 'string') return false;
  if (trigger.length === 0 || trigger.length > 50) return false;
  
  // Block dangerous characters and patterns
  const dangerousPatterns = [
    /<script/i, /<iframe/i, /javascript:/i, /data:/i, /vbscript:/i,
    /on\w+\s*=/i, /[<>\"'&]/
  ];
  
  return !dangerousPatterns.some(pattern => pattern.test(trigger));
}

function validateReplacement(replacement) {
  if (typeof replacement !== 'string') return false;
  if (replacement.length > 500) return false; // Reasonable limit
  
  // Allow some HTML but sanitize it
  return true;
}

function replaceInText(text) {
  let out = text;
  
  for (const t of TRIGGERS) {
    if (!t || !t.trigger || !validateTrigger(t.trigger)) continue;
    if (!validateReplacement(t.replacement)) continue;
    
    try {
      const escaped = String(t.trigger).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      // replace when trigger is a whole token separated by whitespace
      const re = new RegExp('(^|\\s)' + escaped + '(?=\\s|$)', 'g');
      const sanitizedReplacement = sanitizeText(t.replacement || '');
      out = out.replace(re, (m, p1) => p1 + sanitizedReplacement);
    } catch (error) {
      console.warn('Error processing trigger:', t.trigger, error);
      continue;
    }
  }
  
  return out;
}

function onEditableInput(e) {
  const target = e.target;
  // only act when a space was inserted (keyboard or inputType)
  const isSpace =
    (e && (e.key === ' ' || e.code === 'Space')) ||
    (e && e.inputType === 'insertText' && e.data === ' ');
  if (!isSpace) return;

  if (target instanceof HTMLInputElement || target instanceof HTMLTextAreaElement) {
    const value = target.value || '';
    const before = value;
    const after = replaceInText(before);
    if (after !== before) {
      const cursorPos = target.selectionStart;
      const delta = after.length - before.length;
      target.value = after;
      if (typeof cursorPos === 'number') {
        const pos = Math.max(0, cursorPos + delta);
        target.selectionStart = target.selectionEnd = pos;
      }
      target.dispatchEvent(new Event('input', { bubbles: true }));
    }
    return;
  }

  // contenteditable
  if (target && (target.isContentEditable || target.getAttribute?.('contenteditable') === 'true')) {
    try {
      const before = target.textContent || ''; // Use textContent instead of innerText for security
      const after = replaceInText(before);
      if (after !== before) {
        // Use textContent to prevent XSS
        target.textContent = after;
        // try to keep caret at end
        const sel = window.getSelection && window.getSelection();
        if (sel && sel.rangeCount) {
          try {
            sel.collapse(target, target.childNodes.length);
          } catch (selError) {
            // Ignore selection errors - not critical
          }
        }
      }
    } catch (error) {
      console.warn('Error processing contenteditable element:', error);
    }
  }
}

function attach(el){ if (!el || isSensitiveInput(el)) return;
  if (el._tt_attached) return;
  el.addEventListener('keyup', onEditableInput, true);
  el.addEventListener('input', onEditableInput, true);
  el._tt_attached = true;
}

function scan() {
  document.querySelectorAll('input, textarea, [contenteditable="true"]').forEach(attach);
}

scan();
// observe dynamically added nodes
const obs = new MutationObserver(() => scan());
obs.observe(document.documentElement || document.body, { childList: true, subtree: true });
