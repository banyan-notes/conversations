// Versatiles background helper (v33). Unlocks the site's encrypted photos,
// images, video and music for a logged-in visitor. Files are AES-GCM
// ciphertext (12-byte IV + ciphertext). The key is held ONLY in memory for the
// current session: nothing is written to storage, and the key is re-confirmed
// with an open, logged-in page every 60s. Reload/new tab = password again.
const VERSION = 'v33';
let key = null, keyAt = 0;
const FRESH = 60 * 1000;
const RX = /\/(photos|img|audio|vid)\/[^/?#]+$/;
const TYPES = { jpg: 'image/jpeg', jpeg: 'image/jpeg', png: 'image/png', gif: 'image/gif', webp: 'image/webp', mp3: 'audio/mpeg', mp4: 'video/mp4' };
// Small LRU of decrypted files (max 20 items / 15 MB). Video is never kept.
const MAXN = 20, MAXB = 15 * 1024 * 1024;
const lru = new Map(); let bytes = 0;
function put(u, buf) {
  if (/\.mp4$/i.test(u) || buf.byteLength > MAXB / 3) return;
  if (lru.has(u)) { bytes -= lru.get(u).byteLength; lru.delete(u); }
  lru.set(u, buf); bytes += buf.byteLength;
  while (lru.size > MAXN || bytes > MAXB) { const [k, v] = lru.entries().next().value; lru.delete(k); bytes -= v.byteLength; }
}
function get(u) { const v = lru.get(u); if (v) { lru.delete(u); lru.set(u, v); } return v; }
function wipe() { key = null; keyAt = 0; lru.clear(); bytes = 0; }

self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', e => e.waitUntil((async () => {
  // remove the old 12h key store from earlier versions
  try { indexedDB.deleteDatabase('vst'); } catch (x) {}
  await self.clients.claim();
})()));

self.addEventListener('message', e => {
  const m = e.data || {};
  if (m.t === 'key' && m.k) { key = m.k; keyAt = Date.now(); lru.clear(); bytes = 0; }
  if (m.t === 'logout') wipe();
});

async function askKey() {
  const wins = await self.clients.matchAll({ type: 'window' });
  for (const c of wins) {
    const k = await new Promise(res => {
      const ch = new MessageChannel();
      const t = setTimeout(() => res(null), 1500);
      ch.port1.onmessage = ev => { clearTimeout(t); res(ev.data); };
      c.postMessage({ t: 'key?' }, [ch.port2]);
    });
    if (k) return k;
  }
  return null;
}
async function freshKey() {
  if (key && Date.now() - keyAt < FRESH) return key;
  const k = await askKey();
  if (!k) { wipe(); return null; }
  key = k; keyAt = Date.now(); return key;
}
const pending = new Map();
function load(url) {
  const hit = get(url); if (hit) return Promise.resolve(hit);
  if (pending.has(url)) return pending.get(url);
  const p = (async () => {
    const k = key;
    const r = await fetch(url, { cache: 'no-cache' });
    if (!r.ok) throw new Error('missing');
    const b = new Uint8Array(await r.arrayBuffer());
    const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: b.subarray(0, 12) }, k, b.subarray(12));
    if (key === k) put(url, pt);
    return pt;
  })();
  pending.set(url, p); p.finally(() => pending.delete(url)).catch(() => {});
  return p;
}

self.addEventListener('fetch', e => {
  const u = new URL(e.request.url);
  if (u.origin !== location.origin || e.request.method !== 'GET' || !RX.test(u.pathname)) return;
  if (/\/vid\/[^/]+\.mp4$/.test(u.pathname)) return; // videos are decrypted in the page (iOS needs real range support)
  if (u.searchParams.has('raw')) return; // page-side decrypt fallback fetches ciphertext directly
  e.respondWith((async () => {
    try {
      if (!(await freshKey())) throw new Error('locked');
      const buf = await load(u.origin + u.pathname);
      const type = TYPES[u.pathname.split('.').pop().toLowerCase()] || 'application/octet-stream';
      const headers = { 'Content-Type': type, 'Cache-Control': 'no-store', 'Accept-Ranges': 'bytes' };
      const range = e.request.headers.get('range');
      const m = range && /bytes=(\d*)-(\d*)/.exec(range);
      if (m) {
        const n = buf.byteLength;
        let s = m[1] ? +m[1] : n - +m[2];
        let end = m[1] && m[2] ? Math.min(+m[2], n - 1) : n - 1;
        s = Math.max(0, s);
        if (s >= n || s > end) return new Response('', { status: 416, headers: { 'Content-Range': 'bytes */' + n } });
        return new Response(buf.slice(s, end + 1), { status: 206, headers: { ...headers, 'Content-Range': `bytes ${s}-${end}/${n}`, 'Content-Length': String(end - s + 1) } });
      }
      return new Response(buf, { headers: { ...headers, 'Content-Length': String(buf.byteLength) } });
    } catch (x) {
      return new Response('', { status: 403, headers: { 'Cache-Control': 'no-store' } });
    }
  })());
});
