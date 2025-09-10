
const appSection = document.getElementById('app-section');
const saveBtn = document.getElementById('save-button');
const btnImport = document.getElementById('btn-import');
const btnExport = document.getElementById('btn-export');
const fileInput = document.getElementById('file-import');
const listEl = document.getElementById('trigger-list');
const countEl = document.getElementById('trigger-count');
const inputTrigger = document.getElementById('trigger');
const inputReplacement = document.getElementById('replacement');
const errorEl = document.getElementById('error');
const successEl = document.getElementById('success');
const logoutBtn = document.getElementById('btn-logout');

const authGate = document.getElementById('auth-gate');
const authEmail = document.getElementById('auth-email');
const authPass = document.getElementById('auth-pass');
const btnLogin = document.getElementById('btn-login');
const btnRegister = document.getElementById('btn-register');
const btnResend = document.getElementById('btn-resend');
const authErr = document.getElementById('auth-error');
const authOk = document.getElementById('auth-success');
const resendWrap = document.getElementById('resend-wrap');
function showResend(show){ if (resendWrap) resendWrap.style.display = show ? '' : 'none'; }
showResend(false);


// ---- Password strength helper (UI only; mirrors backend rules) ----
function analyzePasswordClient(pw, email) {
  const p = String(pw || '');
  const e = String(email || '').toLowerCase();
  const hasUpper = /[A-Z]/.test(p);
  const hasLower = /[a-z]/.test(p);
  const hasNumber = /[0-9]/.test(p);
  const hasSpecial = /[!@#$%^&*()_+\-={}\[\]|;:\'",.<>/?`~]/.test(p);
  const failures = {
    minLength: p.length < 8,
    letter: !(hasUpper || hasLower),
    number: !hasNumber,
  };
  const suggestions = [];
  if (!hasUpper) suggestions.push('aggiungi almeno una MAIUSCOLA');
  if (!hasLower) suggestions.push('aggiungi almeno una minuscola');
  if (!hasSpecial) suggestions.push('aggiungi un carattere speciale');
  if (e && p.toLowerCase().includes(e)) suggestions.push("non usare l'email dentro la password");
  const ok = !(failures.minLength || failures.letter || failures.number);
  return { ok, failures, suggestions, rules: 'min 8 caratteri, almeno una lettera e un numero', meta: { hasUpper, hasLower, hasNumber, hasSpecial } };
}

function formatPasswordErrors(info) {
  if (!info || info.ok) return '';
  const probs = [];
  if (info.failures?.minLength) probs.push('almeno 8 caratteri');
  if (info.failures?.letter) probs.push('almeno una lettera');
  if (info.failures?.number) probs.push('almeno un numero');
  let msg = 'password troppo debole: ' + (info.rules || 'min 8 caratteri, almeno una lettera e un numero');
  if (probs.length) msg += ' — mancano: ' + probs.join(', ');
  if (info.suggestions && info.suggestions.length) msg += '. suggerimenti: ' + info.suggestions.join(', ');
  return msg;
}

// ---- Live password indicator (requisiti + consigliati) ----
function ensurePwMeter() {
  try {
    const pass = document.getElementById('auth-pass');
    if (!pass) return null;
    let meter = document.getElementById('pw-meter');
    if (meter) return meter;
    meter = document.createElement('div');
    meter.id = 'pw-meter';
    meter.className = 'pw-meter';
    meter.innerHTML = `
      <div class="pw-group">
        <div class="pw-title">requisiti minimi</div>
        <ul class="pw-reqs" id="pw-reqs-required">
          <li data-key="min" class="bad">almeno 8 caratteri</li>
          <li data-key="letter" class="bad">una lettera</li>
          <li data-key="number" class="bad">un numero</li>
        </ul>
      </div>
      <div class="pw-group">
        <div class="pw-title">consigliati</div>
        <ul class="pw-reqs" id="pw-reqs-optional">
          <li data-key="upper" class="">una MAIUSCOLA</li>
          <li data-key="special" class="">un simbolo</li>
        </ul>
      </div>`;
    pass.closest('.row')?.insertAdjacentElement('afterend', meter) || pass.parentElement.appendChild(meter);
    return meter;
  } catch { return null; }
}

function updatePwMeter(info) {
  const meter = ensurePwMeter();
  if (!meter || !info) return;
  const reqs = {
    min: !info.failures?.minLength,
    letter: !info.failures?.letter,
    number: !info.failures?.number,
  };
  Object.entries(reqs).forEach(([k, ok]) => {
    const el = meter.querySelector(`li[data-key="${k}"]`);
    if (!el) return;
    el.classList.remove('ok','bad');
    el.classList.add(ok ? 'ok' : 'bad');
  });
  const meta = info.meta || {};
  const optional = {
    upper: !!meta.hasUpper,
    special: !!meta.hasSpecial,
  };
  Object.entries(optional).forEach(([k, ok]) => {
    const el = meter.querySelector(`li[data-key="${k}"]`);
    if (!el) return;
    el.classList.remove('ok','bad');
    if (ok) el.classList.add('ok');
  });
}

// wire live meter updates (single init)
try {
  const _emailEl = document.getElementById('auth-email');
  const _passEl = document.getElementById('auth-pass');
  const _update = () => {
    const email = (_emailEl?.value || '').trim();
    const pw = _passEl?.value || '';
    const info = analyzePasswordClient(pw, email);
    updatePwMeter(info);
  };
  ensurePwMeter();
  _emailEl?.addEventListener('input', _update);
  _passEl?.addEventListener('input', _update);
  _update();
} catch {}

function clearMessages(){
  if (errorEl) errorEl.textContent='';
  if (successEl) successEl.textContent='';
  if (authErr) authErr.textContent='';
  if (authOk) authOk.textContent='';
}

function showApp() {
  appSection.style.display='';
  authGate.style.display='none';
  toggleLogout(true);
  clearMessages();
}

function showGate(msg) {
  authGate.style.display='';
  appSection.style.display='none';
  toggleLogout(false);
  clearMessages();
  if (msg) authErr.textContent = msg;
}

function toggleLogout(show) { logoutBtn.style.display = show ? 'inline-block' : 'none'; }

logoutBtn?.addEventListener('click', async () => {
  // clear UI and cached fields
  clearMessages();
  inputTrigger.value=''; inputReplacement.value='';
  listEl.innerHTML=''; countEl.textContent='0';
  await chrome.runtime.sendMessage({ type: 'AUTH_LOGOUT' });
  showGate('disconnesso.');
});

btnLogin?.addEventListener('click', async () => {
  clearMessages();
  const email = sanitizeInput((authEmail?.value || '').trim()); 
  const password = authPass?.value || ''; // Don't sanitize password, just validate
  
  // Basic validation
  if (!email || !password) { 
    authErr.textContent = 'inserisci email e password'; 
    return; 
  }
  
  // Email validation
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    authErr.textContent = 'formato email non valido';
    return;
  }
  
  if (password.length < 8) {
    authErr.textContent = 'password troppo corta (minimo 8 caratteri)';
    return;
  }
  
  try {
    const resp = await chrome.runtime.sendMessage({ 
      type: 'AUTH_LOGIN', 
      payload: { email, password } 
    });
    
    if (resp?.errorCode === 'email_not_verified') {
      showResend(true);
      authErr.textContent = 'devi verificare l\'email prima di accedere.';
      return;
    }
    
    if (resp && resp.ok) {
      authOk.textContent = 'login effettuato ✓';
      setTimeout(async () => { await render(); showApp(); }, 900);
    } else {
      authErr.textContent = resp?.error || 'login fallito';
    }
  } catch (error) {
    console.error('Login error:', error);
    authErr.textContent = 'Errore durante il login';
  }
});

btnRegister?.addEventListener('click', async () => {
  clearMessages();
  const email = sanitizeInput((authEmail?.value || '').trim()); 
  const password = authPass?.value || '';
  
  // Basic validation
  if (!email || !password) { 
    authErr.textContent = 'inserisci email e password'; 
    return; 
  }
  
  // Email validation
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    authErr.textContent = 'formato email non valido';
    return;
  }

  // Client-side password analysis for immediate feedback
  const pwInfo = analyzePasswordClient(password, email);
  if (!pwInfo.ok) { 
    authErr.textContent = formatPasswordErrors(pwInfo); 
    return; 
  }

  try {
    const resp = await chrome.runtime.sendMessage({ 
      type: 'AUTH_REGISTER', 
      payload: { email, password } 
    });
    
    if (resp?.ok && resp.requiresVerification) {
      showResend(true);
      authOk.textContent = 'Registrazione ok. Ti abbiamo inviato un\'email di verifica. Controlla la casella e conferma per accedere.';
    } else {
      if (resp && resp.error === 'weak_password') {
        // Prefer server details; otherwise, fallback to local analysis
        if (resp.failures || resp.suggestions) {
          authErr.textContent = formatPasswordErrors(resp);
        } else if (resp.rules) {
          const local = analyzePasswordClient(password, email);
          authErr.textContent = !local.ok ? formatPasswordErrors(local) : ('password troppo debole: ' + resp.rules);
        } else {
          const local = analyzePasswordClient(password, email);
          authErr.textContent = formatPasswordErrors(local);
        }
      } else {
        authErr.textContent = resp?.error || 'registrazione fallita';
      }
    }
  } catch (error) {
    console.error('Registration error:', error);
    authErr.textContent = 'Errore durante la registrazione';
  }
});

btnResend?.addEventListener('click', async (e) => {
  e.preventDefault();
  clearMessages();
  const email = (authEmail?.value || '').trim();
  if (!email) { authErr.textContent='inserisci la tua email'; return; }
  const resp = await chrome.runtime.sendMessage({ type: 'AUTH_RESEND_VERIFY', payload: { email } });
  if (resp?.ok) { authOk.textContent = 'email di verifica inviata di nuovo.'; showResend(true); }
  else authErr.textContent = resp?.error || 'impossibile inviare email';
});

function setError(msg){ if (errorEl) errorEl.textContent = msg || ''; }
function setSuccess(msg){ if (successEl) successEl.textContent = msg || ''; }

function renderItems(items) {
  listEl.innerHTML = '';
  const arr = Array.isArray(items) ? items : [];
  countEl.textContent = String(arr.length);
  for (const it of arr) {
    const li = document.createElement('li'); li.className='item';
    const badge = document.createElement('span'); badge.className='badge'; badge.textContent = it.trigger;
    const text = document.createElement('span'); text.className='text'; text.textContent = it.replacement || '';
    const actions = document.createElement('div'); actions.className='actions';
    const btnDel = document.createElement('button'); btnDel.textContent='elimina';
    btnDel.addEventListener('click', async () => { const r = await chrome.runtime.sendMessage({ type:'API_DELETE_TRIGGER', payload:{ id: it.id }}); if (r?.unauthorized) return showGate('sessione scaduta — effettua di nuovo il login'); await render(); });
    actions.appendChild(btnDel); li.appendChild(badge); li.appendChild(text); li.appendChild(actions); listEl.appendChild(li);
  }
}

async function apiGetTriggers() {
  return new Promise(resolve => {
    chrome.runtime.sendMessage({ type: 'API_GET_TRIGGERS' }, (resp) => {
      if (resp?.unauthorized) { showGate('sessione scaduta — effettua di nuovo il login'); resolve([]); return; }
      resolve(resp?.items || []);
    });
  });
}
const validateLocalDuplicate = (trigger, items) => (items||[]).some(t => t.trigger === (trigger||'').trim());

saveBtn?.addEventListener('click', async () => {
  clearMessages();
  const trigger = sanitizeInput((inputTrigger.value || '').trim());
  const replacement = sanitizeInput((inputReplacement.value || '').trim());
  
  // Enhanced validation
  if (!trigger) { 
    setError('inserisci un trigger'); 
    return; 
  }
  
  if (!isValidTriggerString(trigger)) {
    setError('trigger non valido: evita caratteri speciali e script');
    return;
  }
  
  if (!isValidReplacementString(replacement)) {
    setError('testo sostitutivo non valido: evita script e contenuti pericolosi');
    return;
  }
  
  const items = await apiGetTriggers();
  if (validateLocalDuplicate(trigger, items)) { 
    setError('trigger già esistente'); 
    return; 
  }
  
  try {
    const resp = await chrome.runtime.sendMessage({ 
      type: 'API_CREATE_TRIGGER', 
      payload: { trigger, replacement } 
    });
    
    if (resp?.unauthorized) { 
      showGate('sessione scaduta — effettua di nuovo il login'); 
      return; 
    }
    if (resp?.conflict) { 
      setError('trigger già esistente'); 
      return; 
    }
    if (resp?.error) { 
      setError(resp.error); 
      return; 
    }
    
    inputTrigger.value=''; 
    inputReplacement.value=''; 
    setSuccess('salvato ✓'); 
    await render();
  } catch (error) {
    console.error('Error creating trigger:', error);
    setError('Errore nel salvataggio del trigger');
  }
});

async function ensureAuth(){ const st = await chrome.runtime.sendMessage({ type:'AUTH_STATUS' }); return !!st?.loggedIn; }

async function render(){ const ok = await ensureAuth(); if (!ok) { showGate(); return; } const items = await apiGetTriggers(); renderItems(items); showApp(); }

render();

// ——— Import/Export utilities ———
async function getAllTriggersSafe() {
  try {
    if (typeof ensureAuth === 'function') {
      const ok = await ensureAuth();
      if (ok && typeof apiGetTriggers === 'function') {
        return await apiGetTriggers();
      }
    }
  } catch (e) {}
  try {
    const resp = await chrome.runtime.sendMessage({ type: 'CACHE_GET' });
    return Array.isArray(resp?.items) ? resp.items : [];
  } catch (e) {
    return [];
  }
}

async function createTriggerSafe(trigger, replacement) {
  try {
    const resp = await chrome.runtime.sendMessage({
      type: 'API_CREATE_TRIGGER',
      payload: { trigger, replacement }
    });
    if (resp?.unauthorized) return { unauthorized: true };
    if (resp?.conflict)   return { conflict: true };
    if (resp?.error)      return { error: String(resp.error) };
    return { ok: true };
  } catch (e) {
    return { error: String(e) };
  }
}

function downloadJSON(filename, dataObj) {
  const blob = new Blob([JSON.stringify(dataObj, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

function normalizeImported(input) {
  const pick = (o, keys) => keys.find(k => typeof o[k] === 'string' && o[k].trim().length > 0);
  const tKey = pick(input, ['trigger', 'key', 'from']);
  const rKey = pick(input, ['replacement', 'value', 'to', 'text']);
  if (!tKey || !rKey) return null;
  return {
    trigger: input[tKey].trim(),
    replacement: input[rKey].trim()
  };
}

function isValidTriggerString(s) {
  if (typeof s !== 'string') return false;
  const trimmed = s.trim();
  if (trimmed.length === 0 || trimmed.length > 50) return false;
  
  // Block dangerous characters and patterns
  const dangerousPatterns = [
    /<script/i, /<iframe/i, /javascript:/i, /data:/i, /vbscript:/i,
    /on\w+\s*=/i, /[<>\"'&]/
  ];
  
  if (dangerousPatterns.some(pattern => pattern.test(trimmed))) return false;
  
  // Block common XSS patterns
  const xssPatterns = [
    /alert\s*\(/i, /confirm\s*\(/i, /prompt\s*\(/i, /eval\s*\(/i,
    /document\./i, /window\./i, /location\./i
  ];
  
  return !xssPatterns.some(pattern => pattern.test(trimmed));
}

function isValidReplacementString(s) {
  if (typeof s !== 'string') return false;
  if (s.length > 500) return false; // Reasonable limit
  
  // Block script tags and dangerous patterns
  const dangerousPatterns = [
    /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi,
    /<iframe\b[^<]*(?:(?!<\/iframe>)<[^<]*)*<\/iframe>/gi,
    /javascript:/gi, /data:/gi, /vbscript:/gi,
    /on\w+\s*=/gi
  ];
  
  return !dangerousPatterns.some(pattern => pattern.test(s));
}

function sanitizeInput(input) {
  if (typeof input !== 'string') return '';
  
  return input
    .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '')
    .replace(/<iframe\b[^<]*(?:(?!<\/iframe>)<[^<]*)*<\/iframe>/gi, '')
    .replace(/javascript:/gi, '')
    .replace(/data:/gi, '')
    .replace(/vbscript:/gi, '')
    .replace(/on\w+\s*=/gi, '');
}

// ——— EXPORT ———
if (typeof btnExport !== 'undefined' && btnExport) {
  btnExport.addEventListener('click', async () => {
    try {
      const items = await getAllTriggersSafe();
      const payload = items.map(x => ({ trigger: x.trigger, replacement: x.replacement }));
      const now = new Date();
      const y = now.getFullYear();
      const m = String(now.getMonth()+1).padStart(2,'0');
      const d = String(now.getDate()).padStart(2,'0');
      downloadJSON(`toppery_text_triggers_${y}-${m}-${d}.json`, payload);
      if (typeof setSuccess === 'function') setSuccess('esportazione completata ✓');
    } catch (e) {
      if (typeof setError === 'function') setError('errore esportazione: ' + String(e));
    }
  });
}

// ——— IMPORT ———
if (typeof btnImport !== 'undefined' && btnImport) {
  btnImport.addEventListener('click', () => {
    if (fileInput) {
      try { fileInput.value = ''; } catch(e){}
      fileInput.click();
    }
  });
}

if (typeof fileInput !== 'undefined' && fileInput) {
  fileInput.addEventListener('change', async (ev) => {
    const file = ev.target?.files?.[0];
    if (!file) return;
    if (file.type && file.type !== 'application/json') {
      if (typeof setError === 'function') setError('seleziona un file .json valido');
      return;
    }
    try {
      const text = await file.text();
      const raw = JSON.parse(text);
      if (!Array.isArray(raw)) {
        if (typeof setError === 'function') setError('formato non valido: atteso un array di oggetti {trigger, replacement}');
        return;
      }
      const current = await getAllTriggersSafe();
      const existingSet = new Set(current.map(x => (x.trigger || '').trim().toLowerCase()));
      const normalized = raw
        .map(normalizeImported)
        .filter(Boolean)
        .filter(x => isValidTriggerString(x.trigger) && isValidReplacementString(x.replacement))
        .map(x => ({
          trigger: sanitizeInput(x.trigger),
          replacement: sanitizeInput(x.replacement)
        }));
      const toCreate = [];
      for (const item of normalized) {
        const key = item.trigger.trim().toLowerCase();
        if (!existingSet.has(key)) {
          toCreate.push(item);
          existingSet.add(key);
        }
      }
      if (toCreate.length === 0) {
        if (typeof setSuccess === 'function') setSuccess('nessun nuovo trigger da importare (tutti già presenti)');
        return;
      }
      let created = 0, conflicts = 0, unauthorized = false, failed = 0;
      for (const { trigger, replacement } of toCreate) {
        const res = await createTriggerSafe(trigger, replacement);
        if (res?.unauthorized) { unauthorized = true; break; }
        if (res?.conflict) { conflicts++; continue; }
        if (res?.error) { failed++; continue; }
        if (res?.ok) created++;
      }
      if (unauthorized) {
        if (typeof showGate === 'function') showGate('sessione scaduta — effettua di nuovo il login');
        return;
      }
      try { if (typeof render === 'function') await render(); } catch(e){}
      const msg = `importazione completata — nuovi: ${created}` +
                  (conflicts ? `, duplicati: ${conflicts}` : '') +
                  (failed ? `, falliti: ${failed}` : '');
      if (typeof setSuccess === 'function') setSuccess(msg);
    } catch (e) {
      if (typeof setError === 'function') setError('errore importazione: file non valido o corrotto');
    }
  });
}
