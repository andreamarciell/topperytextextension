
import cfg from './apiConfig.js';

const AUTH_KEY = 'userAuth';
const CACHE_KEY = 'cachedTriggers';

async function getAuth() {
  const { [AUTH_KEY]: auth } = await chrome.storage.local.get(AUTH_KEY);
  return auth || null;
}
async function setAuth(auth) { await chrome.storage.local.set({ [AUTH_KEY]: auth }); }
async function clearAuth() { await chrome.storage.local.remove(AUTH_KEY); }
async function getCachedTriggers() { const { [CACHE_KEY]: items } = await chrome.storage.local.get(CACHE_KEY); return items || []; }
async function setCachedTriggers(items) { await chrome.storage.local.set({ [CACHE_KEY]: items || [] }); chrome.runtime.sendMessage({ type:'CACHE_UPDATED', payload:{ items: items || [] } }).catch(()=>{}); }
async function clearCache(){ await chrome.storage.local.remove(CACHE_KEY); chrome.runtime.sendMessage({ type:'CACHE_UPDATED', payload:{ items: [] } }).catch(()=>{}); }

function isExpired(auth) { if (!auth || !auth.expiresAt) return true; const skew=30; return (Date.now()/1000) > (auth.expiresAt - skew); }

async function refreshIfNeeded() {
  let auth = await getAuth();
  if (!auth) throw Object.assign(new Error('not logged in'), { status: 401 });
  if (!isExpired(auth)) return auth;
  const r = await fetch(cfg.API_BASE + '/auth/refresh', { method:'POST', headers:{ 'Content-Type':'application/json' }, body: JSON.stringify({ refreshToken: auth.refreshToken }) });
  if (!r.ok) { await clearAuth(); throw Object.assign(new Error('refresh failed'), { status: r.status }); }
  const data = await r.json();
  auth = { accessToken: data.accessToken, refreshToken: data.refreshToken || auth.refreshToken, expiresAt: Math.floor(Date.now()/1000) + (data.expiresIn || 3600) };
  await setAuth(auth); return auth;
}

async function api(path, init={}) {
  let auth; try { auth = await refreshIfNeeded(); } catch { throw Object.assign(new Error('unauthorized'), { status: 401 }); }
  const headers = new Headers(init.headers || {}); headers.set('Authorization','Bearer '+auth.accessToken); headers.set('Content-Type','application/json');
  const r = await fetch(cfg.API_BASE + path, { ...init, headers });
  if (r.status === 401) { await refreshIfNeeded(); const r2 = await fetch(cfg.API_BASE + path, { ...init, headers }); if (!r2.ok) throw Object.assign(new Error('api error '+r2.status), { status:r2.status }); return r2; }
  if (!r.ok) throw Object.assign(new Error('api error '+r.status), { status:r.status });
  return r;
}

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  (async () => {
    try {
      if (msg.type === 'AUTH_STATUS') { const auth = await getAuth(); sendResponse({ loggedIn: !!auth }); return; }

      if (msg.type === 'AUTH_LOGIN') {
        const r = await fetch(cfg.API_BASE + '/auth/login', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ email: msg.payload.email, password: msg.payload.password }) });
        const data = await r.json().catch(()=>({}));
        if (r.status === 403 && data?.error === 'email_not_verified') { sendResponse({ errorCode:'email_not_verified', error: 'email non verificata' }); return; }
        if (!r.ok) { sendResponse({ error: data.error || ('login failed '+r.status) }); return; }
        const auth = { accessToken: data.accessToken, refreshToken: data.refreshToken, expiresAt: Math.floor(Date.now()/1000) + (data.expiresIn || 3600) };
        await setAuth(auth);
        await setCachedTriggers([]); // reset triggers for new session
        sendResponse({ ok:true });
        return;
      }

      if (msg.type === 'AUTH_REGISTER') {
        const r = await fetch(cfg.API_BASE + '/auth/register', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ email: msg.payload.email, password: msg.payload.password }) });
        const data = await r.json().catch(()=>({}));
        if (!r.ok) { sendResponse(data); return; }
        // do NOT log the user in; require email verification
        await clearAuth(); await clearCache();
        sendResponse({ ok:true, requiresVerification: data.requiresVerification });
        return;
      }

      if (msg.type === 'AUTH_RESEND_VERIFY') {
        const r = await fetch(cfg.API_BASE + '/auth/resend', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ email: msg.payload.email }) });
        const data = await r.json().catch(()=>({}));
        if (!r.ok) { sendResponse({ error: data.error || 'resend failed' }); return; }
        sendResponse({ ok:true });
        return;
      }

      if (msg.type === 'AUTH_LOGOUT') { 
        try { 
          const auth = await getAuth(); 
          if (auth?.refreshToken) { 
            try { await fetch(cfg.API_BASE + '/auth/logout', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ refreshToken: auth.refreshToken }) }); } catch(e) {}
          }
        } catch(e) {}
        await clearAuth(); await clearCache(); sendResponse({ ok:true }); return; 
      }

      if (msg.type === 'API_GET_TRIGGERS') {
        try { const r = await api('/triggers', { method:'GET' }); const data = await r.json(); await setCachedTriggers(data.items || []); sendResponse({ items: data.items || [] }); }
        catch (e) { if (e.status === 401) sendResponse({ unauthorized:true }); else sendResponse({ error:String(e) }); }
        return;
      }

      if (msg.type === 'API_CREATE_TRIGGER') {
        try { const r = await api('/triggers', { method:'POST', body: JSON.stringify({ trigger: msg.payload.trigger, replacement: msg.payload.replacement }) }); const data = await r.json(); const cur = await getCachedTriggers(); await setCachedTriggers([data.item, ...cur]); sendResponse({ item: data.item }); }
        catch (e) { if (e.status === 409) sendResponse({ conflict:true }); else if (e.status === 401) sendResponse({ unauthorized:true }); else sendResponse({ error:String(e) }); }
        return;
      }

      if (msg.type === 'API_DELETE_TRIGGER') {
        try { const id = msg.payload.id; await api('/triggers?'+new URLSearchParams({id}).toString(), { method:'DELETE' }); const cur = await getCachedTriggers(); await setCachedTriggers(cur.filter(x=>x.id!==id)); sendResponse({ ok:true }); }
        catch (e) { if (e.status === 401) sendResponse({ unauthorized:true }); else sendResponse({ error:String(e) }); }
        return;
      }

      if (msg.type === 'CACHE_GET') { const items = await getCachedTriggers(); sendResponse({ items }); return; }
    } catch (err) { sendResponse({ error:String(err) }); }
  })();
  return true;
});
