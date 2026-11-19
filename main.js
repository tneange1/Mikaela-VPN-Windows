const { app, BrowserWindow, Menu, Tray, nativeImage, ipcMain, safeStorage, shell, session: ses, net: enet, clipboard, dialog } = require('electron');
const path = require('path'), fs = require('fs'), net = require('net'), os = require('os'), crypto = require('crypto'), dns = require('dns');
const { spawn, execFileSync, execFile } = require('child_process');

const BASE = process.env.MIKAELA_API || 'https://cabinet.mikaelavpn.xyz';
const CABINET = 'https://cabinet.mikaelavpn.xyz/';
const UA = 'MikaelaVPN/1.0 (Windows)';     // свой User-Agent: на него настраивается Response Rule в панели
const PRE_PORT = 10880, PROXY_PORT = 10860;  // PRE_PORT+i: отдельные Xray для предварительной маршрутизации; PROXY_PORT: системный прокси
const XRAY_PORT = 10870;                    // локальный socks Xray (не пересекается с Happ: 10808/10809)
const REG = 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings';
const BAD = ['0.0.0.0', '127.0.0.1', 'localhost', '::', '::1'];

let win = null, tgCancel = false, session = null, prefix = null;
let pre = [], proxyActive = false;
let xray = null, sb = null, stopping = false, restarting = false, lastFail = '', lastLevel = 'warning', curTag = '';
let lastWarn = '';
let entries = null, entriesAt = 0, disk = null, stale = false, bgBusy = false; // disk: кэш подписки {url, at, arr}
const sleep = ms => new Promise(r => setTimeout(r, ms));
let opChain = Promise.resolve(), opBusy = '';
const serial = fn => (...a) => { const p = opChain.then(() => fn(...a)); opChain = p.catch(() => {}); return p; };
let curSub = '';                                   // выбранная подписка (мультитариф)
const sq = () => curSub ? '?subscription_id=' + encodeURIComponent(curSub) : '';
const sFile = () => path.join(app.getPath('userData'), 'session.bin');
const binDir = () => app.isPackaged ? path.join(process.resourcesPath, 'bin') : path.join(__dirname, 'bin');
const logDir = () => path.join(app.getPath('userData'), 'logs');

// ---------- логи ----------
const logBuf = { x: [], c: [] }, pend = { x: [], c: [] };
const LOGF = { x: 'xray.log', c: 'cabinet.log' };
const mask = s => String(s).replace(/\x1b\[[0-9;]*m/g, '').replace(/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi, m => m.slice(0, 8) + '…');
// журналы отключены: хранится только короткий буфер в памяти (для внутренних нужд), на диск ничего не пишется
function log(tag, msg) {
  const k = /^(sub|auth|api|renew|dev|bal|update|discord)$/.test(tag) ? 'c' : 'x';
  logBuf[k].push(mask(msg)); if (logBuf[k].length > 200) logBuf[k].splice(0, logBuf[k].length - 200);
}
try { fs.rmSync(path.join(app.getPath('userData'), 'logs'), { recursive: true, force: true }); } catch {}
const rl = new Map(); // key -> {n, t0, supp, tag}
function logRL(tag, msg) { // выводы xray/sing-box: убираем шум и схлопываем повторы
  if (/found process path|connection (upload|download) (finished|closed)/i.test(msg)) return;
  if (/FATAL|ERROR|panic|failed to start|WARN/i.test(msg)) return log(tag, msg);
  const key = tag + msg.replace(/\d{4}\/\d\d\/\d\d \d\d:\d\d:\d\d(\.\d+)?/g, '').replace(/\[\d+( [\d.]+m?s)?\]/g, '[]').replace(/\d+\.\d+\.\d+\.\d+/g, 'IP').replace(/\b\d{4,5}\b/g, 'P').replace(/[\d.]+m?s\b/g, '');
  const now = Date.now(); let e = rl.get(key);
  if (!e || now - e.t0 > 5000) { if (e && e.supp) log(tag, `  … ещё ×${e.supp} таких же строк`); e = { n: 0, t0: now, supp: 0, tag }; rl.set(key, e); }
  if (++e.n <= 3) log(tag, msg); else e.supp++;
  if (rl.size > 3000) rl.clear();
}
setInterval(() => { const now = Date.now(); for (const [k, e] of rl) if (now - e.t0 > 5000) { if (e.supp) log(e.tag, `  … ещё ×${e.supp} таких же строк`); rl.delete(k); } }, 5000);
const safeUrl = u => { try { const x = new URL(u); return x.host + x.pathname.split('/').map(s => /^(?=.*\d)[A-Za-z0-9_-]{8,}$/.test(s) ? s.slice(0, 4) + '…' : s).join('/'); } catch { return String(u); } };

function save() {
  try {
    if (!session) return fs.rmSync(sFile(), { force: true });
    const j = JSON.stringify(session);
    fs.writeFileSync(sFile(), safeStorage.isEncryptionAvailable() ? safeStorage.encryptString(j) : Buffer.from(j));
  } catch {}
}
function load() {
  try {
    const b = fs.readFileSync(sFile());
    session = JSON.parse(safeStorage.isEncryptionAvailable() ? safeStorage.decryptString(b) : b.toString());
  } catch { session = null; }
}

// ---------- HWID ----------
let _hwid = null;
function hwid() {
  if (_hwid) return _hwid;
  const f = path.join(app.getPath('userData'), 'hwid.txt');
  try { _hwid = fs.readFileSync(f, 'utf8').trim(); } catch {}
  if (!_hwid) {
    let g = '';
    try { const m = execFileSync('reg', ['query', 'HKLM\\SOFTWARE\\Microsoft\\Cryptography', '/v', 'MachineGuid'], { windowsHide: true }).toString().match(/MachineGuid\s+REG_SZ\s+(\S+)/i); g = m ? m[1] : ''; } catch {}
    _hwid = crypto.createHash('sha256').update((g || crypto.randomUUID()) + 'mikaela-vpn').digest('hex').slice(0, 32);
    try { fs.writeFileSync(f, _hwid); } catch {}
  }
  return _hwid;
}
const subHeaders = () => ({ 'User-Agent': UA, 'x-hwid': hwid(), 'x-device-os': 'Windows', 'x-ver-os': os.release(), 'x-device-model': os.hostname() });

// ---------- сеть ----------
const why = e => (e && e.cause && (e.cause.code || e.cause.message)) || (e && e.name === 'TimeoutError' ? 'таймаут' : e && e.message) || 'ошибка';
async function nf(url, o = {}, label = 'Нет связи с сервером') {
  const { timeout = 10000, tries = 2, ...fo } = o;
  const m = fo.method || 'GET', get = m === 'GET', t0 = Date.now();
  let err;
  for (let i = 0; i < tries; i++) {
    try {
      const r = await enet.fetch(url, { ...fo, signal: AbortSignal.timeout(timeout) });
      log('net', `${m} ${safeUrl(url)} → ${r.status} (${Date.now() - t0} мс)`);
      return r;
    } catch (e) {
      err = e;
      log('net', `${m} ${safeUrl(url)} ✗ ${why(e)} (попытка ${i + 1}/${tries})`);
      if (!get && !/CONNECT|ERR_CONNECTION|ERR_NAME|ERR_INTERNET|ENOTFOUND/i.test(why(e) + ' ' + (e && e.message))) break;
      if (i < tries - 1) await sleep(600);
    }
  }
  throw new Error(`${label} (${why(err)})`);
}
async function raw(p, o = {}) { // пробуем BASE и BASE/api
  if (prefix !== null) return nf(BASE + prefix + p, o);
  let last;
  for (const pf of ['', '/api']) {
    try {
      const r = await nf(BASE + pf + p, o);
      if ((r.headers.get('content-type') || '').includes('json')) { prefix = pf; log('net', `API prefix: "${pf}"`); return r; }
      last = r;
    } catch (e) { last = e; }
  }
  if (last instanceof Error) throw last;
  throw new Error('API не найден по адресу ' + BASE + ' (задай MIKAELA_API)');
}
const J = { 'Content-Type': 'application/json' };

async function refresh() {
  try {
    const r = await raw('/cabinet/auth/refresh', { method: 'POST', headers: J, body: JSON.stringify({ refresh_token: session.refresh }) });
    if (!r.ok) { log('auth', 'refresh отклонён: ' + r.status); session = null; save(); return false; }
    const d = await r.json();
    session.access = d.access_token;
    if (d.refresh_token) session.refresh = d.refresh_token;
    save(); log('auth', 'токен обновлён'); return true;
  } catch (e) { log('auth', 'refresh ошибка: ' + e.message); return false; }
}
async function authed(p, o = {}) {
  for (let i = 0; i < 2; i++) {
    if (!session) throw new Error('AUTH');
    const r = await raw(p, { ...o, headers: { ...(o.headers || {}), Authorization: 'Bearer ' + session.access } });
    if (r.status !== 401) return r;
    if (!(await refresh())) throw new Error('AUTH');
  }
  throw new Error('AUTH');
}
const errText = (d, def) => {
  const x = d && d.detail;
  if (typeof x === 'string') return x;
  if (Array.isArray(x)) return x.map(i => i.msg).join('; ');
  if (x && typeof x === 'object') return x.message || x.error || def;
  return (d && d.message) || def;
};
async function jcall(p, method = 'GET', body) {
  const r = await authed(p, { method, headers: body ? J : undefined, body: body ? JSON.stringify(body) : undefined });
  const d = await r.json().catch(() => ({}));
  if (!r.ok) { log('api', `${method} ${p} → ${r.status}: ${errText(d, '')}`); throw new Error(errText(d, 'Ошибка ' + r.status)); }
  log('api', `${method} ${p} → ${r.status}`);
  return d;
}

// ---------- аккаунт ----------
function setAuth(d) { session = { access: d.access_token, refresh: d.refresh_token, user: d.user }; save(); log('auth', 'вход выполнен'); return d.user; }
async function login(email, password) {
  const r = await raw('/cabinet/auth/email/login', { method: 'POST', headers: J, body: JSON.stringify({ email, password }) });
  const d = await r.json().catch(() => ({}));
  if (!r.ok) { log('auth', 'вход по email: отказ ' + r.status); throw new Error(errText(d, 'Неверная почта или пароль. Если вход был через Telegram/Google — пароль не задан: нажми «Забыли пароль?»')); }
  return setAuth(d);
}
async function register(email, password, name) {
  const r = await raw('/cabinet/auth/email/register/standalone', { method: 'POST', headers: J, body: JSON.stringify({ email, password, first_name: name || undefined, language: 'ru' }) });
  const d = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(errText(d, 'Не удалось зарегистрироваться'));
  return d.message || 'Письмо отправлено. Подтвердите почту и войдите.';
}
async function forgot(email) {
  const r = await raw('/cabinet/auth/password/forgot', { method: 'POST', headers: J, body: JSON.stringify({ email }) });
  const d = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(errText(d, 'Не удалось отправить письмо'));
  return 'Если такой аккаунт есть, письмо со ссылкой для пароля отправлено.';
}
async function tgLogin() {
  tgCancel = false;
  const r = await raw('/cabinet/auth/deeplink/request', { method: 'POST' });
  const d = await r.json().catch(() => ({}));
  if (!r.ok || !d.token) throw new Error('Вход через Telegram недоступен');
  shell.openExternal(`https://t.me/${d.bot_username}?start=webauth_${d.token}`);
  const until = Date.now() + (d.expires_in || 300) * 1000;
  while (Date.now() < until && !tgCancel) {
    await sleep(2000);
    const p = await raw('/cabinet/auth/deeplink/poll', { method: 'POST', headers: J, body: JSON.stringify({ token: d.token }) });
    if (p.status === 200) return setAuth(await p.json());
    if (p.status === 410) break;
  }
  throw new Error(tgCancel ? 'Отменено' : 'Время ожидания истекло, попробуйте ещё раз');
}
const SCAN = `(()=>{let a,r;const w=o=>{if(!o||typeof o!=='object')return;for(const k in o){const v=o[k];if(typeof v==='string'){if(/access.?token/i.test(k)&&v.startsWith('eyJ'))a=v;if(/refresh.?token/i.test(k)&&v)r=v}else w(v)}};
for(const st of [localStorage,sessionStorage])for(let i=0;i<st.length;i++){const k=st.key(i),v=st.getItem(k);if(/access.?token/i.test(k)&&v&&v.startsWith('eyJ'))a=v;if(/refresh.?token/i.test(k)&&v)r=v;try{w(JSON.parse(v))}catch{}}
return a&&r?{a,r}:null})()`;
function webLogin() {
  return new Promise(async (resolve, reject) => {
    const part = 'persist:cabinet-login';
    await ses.fromPartition(part).clearStorageData();
    const w = new BrowserWindow({ icon: path.join(__dirname,'icon.png'), width: 520, height: 780, parent: win, modal: true, autoHideMenuBar: true, title: 'Вход через кабинет', webPreferences: { partition: part } });
    w.webContents.setUserAgent(w.webContents.getUserAgent().replace(/\s(Electron|mikaela-vpn)\/\S+/gi, ''));
    let done = false;
    const t = setInterval(async () => {
      if (done || w.isDestroyed()) return;
      try {
        const r = await w.webContents.executeJavaScript(SCAN);
        if (!r) return;
        done = true; clearInterval(t);
        session = { access: r.a, refresh: r.r, user: null }; save();
        w.close();
        resolve(await me());
      } catch (e) { if (done) reject(e); }
    }, 1500);
    w.on('closed', () => { clearInterval(t); if (!done) reject(new Error('Окно входа закрыто')); });
    w.loadURL(CABINET);
  });
}
async function me() {
  for (const p of ['/cabinet/auth/me', '/cabinet/balance']) {
    try {
      const r = await authed(p);
      if (r.ok) { const d = await r.json(); session.user = { ...(session.user || {}), ...d }; save(); return session.user; }
    } catch (e) { if (e.message === 'AUTH') throw e; }
  }
  return session.user;
}
const getSub = async () => {
  const d = await jcall('/cabinet/subscription' + sq());
  const u = d.subscription && d.subscription.subscription_url;
  if (u && (!disk || disk.url !== u)) { disk = { url: u, at: disk ? disk.at : 0, arr: disk ? disk.arr : null }; saveDisk(); log('sub', 'адрес подписки обновлён из кабинета'); }
  return d;
};

// ---------- устройства, баланс, продление ----------
async function devices() {
  const d = await jcall('/cabinet/subscription/devices' + sq());
  const arr = Array.isArray(d) ? d : (d.devices || d.items || d.data || []);
  const mine = hwid();
  const list = arr.map(x => ({
    hwid: String(x.hwid || x.hwid_id || x.id || ''), platform: x.platform || x.device_os || '',
    model: x.device_model || x.model || x.name || '', created: x.created_at || x.createdAt || '',
  })).filter(x => x.hwid).map(x => ({ ...x, self: x.hwid.toLowerCase() === mine }));
  const n = typeof d.total === 'number' ? d.total : typeof d.connected === 'number' ? d.connected : list.length;
  return { list, count: n, limit: d.device_limit != null ? d.device_limit : (d.limit != null ? d.limit : null) };
}
const resetDevices = () => jcall('/cabinet/subscription/devices' + sq(), 'DELETE');
const delDevice = h => jcall('/cabinet/subscription/devices/' + encodeURIComponent(h) + sq(), 'DELETE');
const sq2 = () => curSub ? '&subscription_id=' + encodeURIComponent(curSub) : '';
const devicePrice = async n => { const d = await jcall('/cabinet/subscription/devices/price?devices=' + (+n || 1) + sq2()); log('dev', 'цена устройств: ' + String(JSON.stringify(d)).slice(0, 500)); return d; };
const deviceBuy = async n => { const d = await jcall('/cabinet/subscription/devices/purchase' + sq(), 'POST', { devices: +n || 1 }); log('dev', 'докупка устройств: ' + String(JSON.stringify(d)).slice(0, 300)); return d; };
const methods = () => jcall('/cabinet/balance/payment-methods');
async function topup(o) {
  const d = await jcall('/cabinet/balance/topup', 'POST', { amount_kopeks: o.amount_kopeks, payment_method: o.payment_method, payment_option: o.payment_option || undefined });
  if (d.payment_url && /^https:\/\//.test(d.payment_url)) shell.openExternal(d.payment_url);
  return d;
}
const renewOptions = async () => { const d = await jcall('/cabinet/subscription/renewal-options' + sq()); log('renew', 'варианты продления: ' + String(JSON.stringify(d)).slice(0, 700)); return d; };
const renew = days => jcall('/cabinet/subscription/renew' + sq(), 'POST', { period_days: days });

const normSub = x => ({ id: String(x.id != null ? x.id : (x.subscription_id != null ? x.subscription_id : '')), name: x.tariff_name || x.name || (x.tariff && x.tariff.name) || 'Подписка', days: x.days_left != null ? x.days_left : null, status: x.status || '', trial: !!x.is_trial });
async function listSubs() { // список подписок пользователя; эндпоинт в документации не описан — пробуем варианты
  for (const p of ['/cabinet/subscriptions', '/cabinet/subscription/list']) {
    try {
      const r = await authed(p); if (!r.ok) { log('sub', `${p} → ${r.status}`); continue; }
      const d = await r.json(), a = Array.isArray(d) ? d : (d.subscriptions || d.items || d.data || []);
      const list = (Array.isArray(a) ? a : []).map(normSub).filter(x => x.id);
      if (list.length) { log('sub', `подписки (${p}): ` + list.map(x => `${x.id}:${x.name}`).join(', ')); return list; }
    } catch (e) { if (e.message === 'AUTH') throw e; }
  }
  return [];
}
function setSub(id) {
  id = String(id || '');
  if (id === curSub) return true;
  curSub = id; entries = null; entriesAt = 0;
  disk = { url: null, at: 0, arr: null, ips: (disk && disk.ips) || {} }; saveDisk();
  log('sub', 'выбрана подписка: ' + (id || 'по умолчанию'));
  return true;
}
// ---------- подписка: Xray JSON (как в Happ) ----------
const isProxy = o => o && o.protocol && !['freedom', 'blackhole', 'dns', 'loopback'].includes(o.protocol);
const hostOf = o => { const s = o.settings || {}, v = (s.vnext && s.vnext[0]) || (s.servers && s.servers[0]) || s; return v && v.address ? { host: String(v.address), port: +v.port || 443 } : null; };
function parseDesc(cfg) {
  const m = cfg && cfg.meta, v = (m && typeof m === 'object' && (m.serverDescription || m.server_description || m.description)) || cfg.serverDescription || '';
  if (typeof v !== 'string' || !v) return '';
  if (/^[A-Za-z0-9+/]{8,}={0,2}$/.test(v) && v.length % 4 === 0) {
    try { const d = Buffer.from(v, 'base64').toString('utf8'); if (d && !d.includes('\ufffd') && /^[\p{L}\p{N}\p{P}\p{S}\s]+$/u.test(d)) return d.slice(0, 80); } catch {}
  }
  return v.slice(0, 80);
}
let ph = 0;
function buildEntries(arr) {
  const seen = new Set(), out = []; ph = 0;
  for (const cfg of arr) {
    const outs = (cfg.outbounds || []).filter(isProxy);
    if (!outs.length) continue;
    const bal = cfg.routing && cfg.routing.balancers && cfg.routing.balancers[0];
    let subj = outs;                                     // узлы балансировщика: теги с префиксом из selector
    if (bal && Array.isArray(bal.selector)) { const m = outs.filter(o => bal.selector.some(p => String(o.tag || '').startsWith(p))); if (m.length) subj = m; }
    const hosts = subj.map(hostOf).filter(Boolean);
    if (!hosts.length || hosts.every(h => BAD.includes(h.host))) { ph++; continue; }
    const name = cfg.remarks || cfg.ps || 'server';
    let t = name, i = 2; while (seen.has(t)) t = `${name} ${i++}`; seen.add(t);
    const ss = subj[0].streamSettings || {};
    out.push({ tag: t, cfg, desc: parseDesc(cfg), udp: /hysteria/i.test(String(subj[0].protocol) + ' ' + String(ss.network)), auto: !!bal && subj.length > 1, count: subj.length, hosts: hosts.filter(h => !BAD.includes(h.host)),
      proto: String(subj[0].protocol || '').toUpperCase(), net: String(ss.network || 'tcp').toUpperCase(), sec: ss.security && ss.security !== 'none' ? String(ss.security).toUpperCase() : '' });
  }
  return out;
}
const cacheFile = () => path.join(app.getPath('userData'), 'sub-cache.bin');
function loadDisk() { try { const b = fs.readFileSync(cacheFile()); disk = JSON.parse(safeStorage.isEncryptionAvailable() ? safeStorage.decryptString(b) : b.toString()); } catch { disk = null; } }
function saveDisk() { try { const j = JSON.stringify(disk); fs.writeFileSync(cacheFile(), safeStorage.isEncryptionAvailable() ? safeStorage.encryptString(j) : Buffer.from(j)); } catch {} }

async function pullArr(url, fast) { // скачать Xray JSON с панели (кабинет не нужен)
  const base = new URL(url).pathname.replace(/\/+$/, '');
  const withPath = sfx => { const x = new URL(url); x.pathname = base + sfx; return x.toString(); };
  let lastE = '';
  for (const [u, label] of [[url, 'базовая ссылка'], [withPath('/json'), 'ссылка /json']]) {
    try {
      const r = await nf(u, { headers: subHeaders(), timeout: fast ? 8000 : 15000, tries: fast ? 1 : 2 }, 'Панель недоступна');
      const text = await r.text();
      log('sub', `${label}: HTTP ${r.status}, ${text.length} байт, тип ${r.headers.get('content-type')}`);
      let j; try { j = JSON.parse(text); } catch {
        lastE = `ответ не JSON (HTTP ${r.status})${text ? ': ' + text.slice(0, 80).replace(/\s+/g, ' ') : ''}`;
        if (r.status === 403 || r.status === 404) lastE += ' — панель не отдаёт подписку для User-Agent ' + UA.split('/')[0] + ': добавьте Response Rule';
        log('sub', lastE); continue;
      }
      const arr = Array.isArray(j) ? j : (j && Array.isArray(j.outbounds) ? [j] : null);
      if (!arr || !arr.length) { lastE = 'JSON без конфигов'; log('sub', lastE); continue; }
      const ents = buildEntries(arr);
      if (ents.length) { log('sub', `серверов: ${ents.length}: ` + ents.map(e => e.tag + (e.auto ? ` [авто, ${e.count} узлов]` : '') + (e.udp ? ' [UDP]' : '')).join('; ')); log('sub', 'описания: ' + (ents.filter(e => e.desc).map(e => e.tag + ' → ' + e.desc).join('; ') || 'нет') + ' | meta: ' + String(JSON.stringify(arr[0] && arr[0].meta)).slice(0, 160)); return arr; }
      lastE = ph ? 'панель вернула заглушку — вероятно, достигнут лимит устройств (удалите лишнее на вкладке «Устройства»)' : 'в ответе нет подходящих серверов';
      log('sub', lastE);
    } catch (e) { lastE = e.message; log('sub', 'ошибка: ' + e.message); }
  }
  throw new Error(lastE);
}
async function pullEntries(url, fast) { const arr = await pullArr(url, fast); disk = { url, at: Date.now(), arr }; saveDisk(); stale = false; return buildEntries(arr); }
async function fetchEntries(fast) {
  const cached = disk && disk.url; let prevErr = '';
  if (cached) { // сначала напрямую в панель по сохранённому адресу — кабинет не нужен
    log('sub', `подписка: ${safeUrl(cached)} (адрес из кэша)`);
    try { return await pullEntries(cached, fast); } catch (e) { prevErr = e.message; log('sub', 'по сохранённому адресу не вышло: ' + prevErr); }
  }
  const s = await getSub(); // кабинет
  const url = s.subscription && s.subscription.subscription_url;
  if (!url) throw new Error('Нет активной подписки. Оформи её в боте или кабинете.');
  if (url === cached) throw new Error('Не удалось получить подписку: ' + prevErr);
  log('sub', `подписка: ${safeUrl(url)} (адрес от кабинета)`);
  try { return await pullEntries(url, fast); } catch (e) { throw new Error('Не удалось получить подписку: ' + e.message); }
}
async function loadEntries(force, fast) {
  if (!force && entries && Date.now() - entriesAt < 3600000) return entries;
  try { entries = await fetchEntries(fast); entriesAt = Date.now(); stale = false; return entries; }
  catch (e) {
    if (disk && disk.arr) {
      const ents = buildEntries(disk.arr);
      if (ents.length) { log('sub', `⚠ используем сохранённую подписку от ${new Date(disk.at).toLocaleString('ru')} (${e.message})`); entries = ents; entriesAt = Date.now() - 3000000; stale = true; return entries; }
    }
    throw e;
  }
}
const view = () => ({ list: entries.map(e => ({ tag: e.tag, desc: e.desc, auto: e.auto, count: e.count, proto: e.proto, net: e.net, sec: e.sec, udp: e.udp })), at: entriesAt, stale, sig: crypto.createHash('md5').update(entries.map(e => e.tag + '|' + e.hosts.map(h => h.host).join(',')).join(';')).digest('hex').slice(0, 10) });
function refreshBg() { if (bgBusy) return; bgBusy = true; loadEntries(true).catch(() => {}).finally(() => { bgBusy = false; }); }
async function servers(o) {
  if (!(o && o.force)) {
    if (!entries && disk && disk.arr) { entries = buildEntries(disk.arr); entriesAt = disk.at || 0; stale = true; log('sub', 'список серверов из кэша'); }
    if (entries && entries.length) { if (Date.now() - entriesAt > 3600000) refreshBg(); return view(); }
  }
  await loadEntries(true); return view();
}
const tcpPing = async h => { // сначала определяем IP (системный DNS -> DoH), потом TCP; запоминаем причину сбоя
  const ip = await resolveHost(h.host);
  if (!ip) return { ms: -1, why: 'DNS не резолвит' };
  return new Promise(res => {
    const t = Date.now(), s = net.connect({ host: ip, port: h.port, timeout: 3000 }, () => { const d = Date.now() - t; s.destroy(); res({ ms: d }); });
    s.on('error', e => res({ ms: -1, why: 'TCP ' + (e.code || 'ошибка') }));
    s.on('timeout', () => { s.destroy(); res({ ms: -1, why: `TCP ${ip}:${h.port} не отвечает` }); });
  });
};
let pingChain = Promise.resolve();
const proxyPing = e => { const p = pingChain.then(() => doProxyPing(e)); pingChain = p.catch(() => {}); return p; };
async function doProxyPing(entry) { // временный Xray на порту 10871: реальная задержка через сервер (для UDP/Hysteria)
  const port = XRAY_PORT + 1, f = path.join(app.getPath('userData'), 'xray-ping.json');
  let p;
  try {
    const ips = await resolveAll(hostsOf(entry), true);
    fs.writeFileSync(f, JSON.stringify(xrayConfig(entry, 'none', ips, port)));
    p = spawn(path.join(binDir(), 'xray.exe'), ['run', '-c', f], { windowsHide: true, cwd: binDir(), env: { ...process.env, XRAY_LOCATION_ASSET: binDir() } });
    let up = false;
    for (let i = 0; i < 25 && !up; i++) { await sleep(150); up = await portOpen(port, 250); }
    if (!up) return { ms: -1, why: 'xray не стартовал' };
    const r = await socksProbe(7000, port); return { ms: r.ms };
  } catch (e) { return { ms: -1, why: 'UDP: ' + e.message }; }
  finally { try { if (p) p.kill(); } catch {} }
}
async function pingOne(e) {
  if (e.udp) return proxyPing(e);
  const rs = await Promise.all(e.hosts.map(tcpPing)), ok = rs.filter(r => r.ms >= 0);
  return ok.length ? { ms: Math.min(...ok.map(r => r.ms)) } : { ms: -1, why: [...new Set(rs.map(r => r.why))].join(' / ') };
}
async function pingMany(tags) {
  const res = {}, whys = {};
  await Promise.all(tags.map(async t => { const e = (entries || []).find(x => x.tag === t), r = e ? await pingOne(e) : { ms: -1 }; res[t] = r.ms; if (r.why) whys[t] = r.why; }));
  log('ping', Object.entries(res).map(([t, v]) => `${t.replace(/[\u{1F1E6}-\u{1F1FF}]{2}\s*/gu, '')}: ${v === -2 ? 'UDP' : v < 0 ? '— (' + (whys[t] || '?') + ')' : v + ' мс'}`).join('; '));
  return res;
}
function logAdapters(tag) { // виден ли TUN-адаптер
  execFile('netsh', ['interface', 'ipv4', 'show', 'interfaces'], { windowsHide: true, encoding: 'buffer' }, (err, out) => {
    if (err) return log(tag, 'netsh: ' + err.message);
    out.toString('latin1').split(/\r?\n/).map(x => x.trim()).filter(Boolean).slice(0, 18).forEach(l => log(tag, 'iface: ' + l));
  });
}

// ---------- процессы: Xray (ядро) + sing-box (TUN) ----------
const proxyOffSync = () => { try { execFileSync('reg', ['add', REG, '/v', 'ProxyEnable', '/t', 'REG_DWORD', '/d', '0', '/f'], { windowsHide: true }); } catch {} };
const INET_REFRESH = "$s='[DllImport(\"wininet.dll\")]public static extern bool InternetSetOption(IntPtr h,int o,IntPtr b,int l);';$t=Add-Type -MemberDefinition $s -Name W -Namespace N -PassThru;$t::InternetSetOption([IntPtr]::Zero,39,[IntPtr]::Zero,0)|Out-Null;$t::InternetSetOption([IntPtr]::Zero,37,[IntPtr]::Zero,0)|Out-Null";
const inetRefresh = () => { try { execFile('powershell', ['-NoProfile', '-NonInteractive', '-Command', INET_REFRESH], { windowsHide: true, timeout: 15000 }, () => {}); } catch {} };
function proxyOn() {
  const add = (n, t, v) => execFileSync('reg', ['add', REG, '/v', n, '/t', t, '/d', v, '/f'], { windowsHide: true });
  add('ProxyServer', 'REG_SZ', '127.0.0.1:' + PROXY_PORT); add('ProxyOverride', 'REG_SZ', '<local>;localhost;127.*;10.*;192.168.*;172.16.*;172.17.*;172.18.*;172.19.*;172.2*;172.30.*;172.31.*'); add('ProxyEnable', 'REG_DWORD', '1');
  proxyActive = true; inetRefresh(); log('app', 'системный прокси включён: 127.0.0.1:' + PROXY_PORT);
}
function proxyOff() { if (!proxyActive) return; proxyOffSync(); proxyActive = false; inetRefresh(); log('app', 'системный прокси выключен'); }
const pidFile = () => path.join(app.getPath('userData'), 'pids.json');
const savePids = () => { try { fs.writeFileSync(pidFile(), JSON.stringify([xray && xray.pid, sb && sb.pid, ...pre.map(p => p.pid)].filter(Boolean))); } catch {} };
function killOrphans() { // процессы прошлого запуска, если приложение упало
  try {
    for (const pid of JSON.parse(fs.readFileSync(pidFile(), 'utf8'))) {
      try {
        const out = execFileSync('tasklist', ['/FI', `PID eq ${pid}`, '/FO', 'CSV', '/NH'], { windowsHide: true }).toString();
        if (/xray\.exe|sing-box\.exe/i.test(out)) { execFileSync('taskkill', ['/PID', String(pid), '/F'], { windowsHide: true }); log('app', `остановлен старый процесс ${pid}`); }
      } catch {}
    }
    fs.rmSync(pidFile(), { force: true });
  } catch {}
}
const portOpen = (port, ms) => new Promise(res => {
  const s = net.connect({ host: '127.0.0.1', port, timeout: ms }, () => { s.destroy(); res(true); });
  s.on('error', () => res(false)); s.on('timeout', () => { s.destroy(); res(false); });
});
function checkBins() {
  const miss = [];
  for (const f of ['xray.exe', 'sing-box.exe', 'wintun.dll', 'geoip.dat', 'geosite.dat']) {
    try { log('bin', `${f}: ${Math.round(fs.statSync(path.join(binDir(), f)).size / 1024)} КБ`); } catch { miss.push(f); log('bin', `${f}: ОТСУТСТВУЕТ в ${binDir()}`); }
  }
  if (miss.length) throw new Error('В приложении нет файлов: ' + miss.join(', ') + '. Пересоберите приложение (workflow их скачивает).');
}
function run(name, exe, args, env) {
  const p = spawn(path.join(binDir(), exe), args, { windowsHide: true, cwd: binDir(), env: { ...process.env, ...env } });
  log(name, `запуск: ${exe} ${args.map(a => path.basename(a)).join(' ')} (pid ${p.pid})`);
  let tail = '';
  const feed = d => String(d).split(/\r?\n/).filter(Boolean).forEach(l => { logRL(name, l); tail = (tail + '\n' + l).slice(-1500); });
  p.stdout.on('data', feed); p.stderr.on('data', feed);
  p.on('error', e => { p.failed = e.message; log(name, 'не запустился: ' + e.message); });
  p.tail = () => tail.trim();
  return p;
}
function pinAddress(o, ips) { // подставить IP сервера, SNI/host остаются прежними
  const st = o.settings || {}, v = (st.vnext && st.vnext[0]) || (st.servers && st.servers[0]) || st, h = v && v.address;
  if (!h || !ips[h] || ips[h] === h) return;
  const ss = o.streamSettings = o.streamSettings || {};
  if (ss.security === 'tls') { const t = ss.tlsSettings = ss.tlsSettings || {}; if (!t.serverName) t.serverName = h; }
  else if (ss.security === 'reality') { const r = ss.realitySettings = ss.realitySettings || {}; if (!r.serverName) r.serverName = h; }
  if (ss.xhttpSettings && !ss.xhttpSettings.host) ss.xhttpSettings.host = h;
  if (ss.wsSettings && !ss.wsSettings.host && !(ss.wsSettings.headers && ss.wsSettings.headers.Host)) ss.wsSettings.host = h;
  v.address = ips[h];
}
function xrayConfig(entry, level, ips, port = XRAY_PORT) {
  const c = JSON.parse(JSON.stringify(entry.cfg));
  delete c.meta; delete c.remarks; delete c.remnawave;
  for (const o of (c.outbounds || [])) if (isProxy(o)) pinAddress(o, ips);
  c.inbounds = [{ tag: 'socks', listen: '127.0.0.1', port, protocol: 'socks', settings: { auth: 'noauth', udp: true, ip: '127.0.0.1' },
    sniffing: { enabled: true, destOverride: ['http', 'tls', 'quic'], routeOnly: true } }]; // routeOnly: адрес назначения не подменяется доменом
  c.log = { loglevel: level };
  return c;
}
async function resolveHost(h) {
  if (net.isIP(h)) return h;
  try { const r = await Promise.race([dns.promises.lookup(h, { family: 4 }), sleep(4000).then(() => { throw new Error('таймаут'); })]); return r.address; }
  catch (e) { log('dns', `${h}: системный DNS не ответил (${e.code || e.message})`); }
  for (const u of [`https://1.1.1.1/dns-query?name=${h}&type=A`, `https://8.8.8.8/resolve?name=${h}&type=A`]) {
    try {
      const r = await enet.fetch(u, { headers: { accept: 'application/dns-json' }, signal: AbortSignal.timeout(5000) });
      const a = ((await r.json()).Answer || []).find(x => x.type === 1);
      if (a) { log('dns', `${h}: получен через DoH`); return a.data; }
    } catch {}
  }
  const old = disk && disk.ips && disk.ips[h];
  if (old) log('dns', `${h}: используем прошлый IP из кэша`);
  return old || null;
}
async function resolveAll(hosts, cached) {
  const map = {}, t0 = Date.now();
  await Promise.all(hosts.map(async h => { const ip = (cached && disk && disk.ips && disk.ips[h]) || await resolveHost(h); if (ip) { map[h] = ip; if (!net.isIP(h) && disk) { disk.ips = disk.ips || {}; disk.ips[h] = ip; } } else log('dns', `${h}: IP определить не удалось`); }));
  if (disk) saveDisk();
  log('dns', 'адреса серверов: ' + (Object.entries(map).filter(([h]) => !net.isIP(h)).map(([h, ip]) => `${h}→${ip}`).join(', ') || '—') + ` (${Date.now() - t0} мс)`);
  return map;
}
const hostsOf = entry => [...new Set((entry.cfg.outbounds || []).filter(isProxy).map(o => { const h = hostOf(o); return h && h.host; }).filter(Boolean))];
const freePort = async port => { for (let i = 0; i < 12; i++) { if (!(await portOpen(port, 300))) return true; await sleep(300); } return false; };
async function startXray(entry, level, pre) {
  const hosts = [...new Set((entry.cfg.outbounds || []).filter(isProxy).map(o => { const h = hostOf(o); return h && h.host; }).filter(Boolean))];
  const ips = pre || await resolveAll(hosts);
  if (!(await freePort(XRAY_PORT))) throw new Error('Порт ' + XRAY_PORT + ' занят другим процессом. Закройте лишние копии Xray/клиентов.');
  const f = path.join(app.getPath('userData'), 'xray-config.json');
  fs.writeFileSync(f, JSON.stringify(xrayConfig(entry, level, ips), null, 2));
  log('xray', `сервер «${entry.tag}»${entry.auto ? ` (автовыбор, ${entry.count} узлов)` : ''}`);
  const p = run('xray', 'xray.exe', ['run', '-c', f], { XRAY_LOCATION_ASSET: binDir() });
  xray = p; savePids();
  p.on('exit', (code, sig) => {
    log('xray', `завершился code=${code} signal=${sig}`);
    if (xray === p) { xray = null; if (!stopping && !restarting) { lastFail = 'Xray неожиданно остановился: ' + p.tail(); stopAll('xray упал'); } }
  });
  for (let i = 0; i < 40; i++) {
    await sleep(300);
    if (xray !== p) throw new Error('Xray остановился: ' + (p.failed || p.tail() || 'нет вывода'));
    if (await portOpen(XRAY_PORT, 400)) { log('xray', `socks-порт ${XRAY_PORT} готов (${(i + 1) * 300} мс)`); return; }
  }
  throw new Error('Xray не открыл порт ' + XRAY_PORT + ': ' + p.tail());
}
function socksProbe(ms, port = XRAY_PORT) { // HTTP-запрос к 1.1.1.1:80 через локальный socks Xray (до включения TUN)
  return new Promise((resolve, reject) => {
    const t0 = Date.now(); let step = 0, buf = Buffer.alloc(0), done = false;
    const s = net.connect({ host: '127.0.0.1', port });
    const fin = (err, val) => { if (done) return; done = true; clearTimeout(tm); s.destroy(); err ? reject(err) : resolve(val); };
    const tm = setTimeout(() => fin(new Error(`нет ответа за ${ms / 1000} с`)), ms);
    s.on('error', e => fin(e));
    s.on('connect', () => s.write(Buffer.from([5, 1, 0])));
    s.on('data', d => {
      buf = Buffer.concat([buf, d]);
      if (step === 0) { if (buf.length < 2) return; if (buf[0] !== 5 || buf[1] !== 0) return fin(new Error('socks: отказ')); buf = buf.slice(2); step = 1; s.write(Buffer.from([5, 1, 0, 1, 1, 1, 1, 1, 0, 80])); }
      if (step === 1) {
        if (buf.length < 10) return;
        if (buf[1] !== 0) return fin(new Error('socks: ошибка ' + buf[1] + ' (сервер не принял соединение)'));
        const len = buf[3] === 1 ? 10 : buf[3] === 4 ? 22 : 7 + buf[4]; if (buf.length < len) return;
        buf = buf.slice(len); step = 2; s.write('GET / HTTP/1.1\r\nHost: 1.1.1.1\r\nConnection: close\r\n\r\n');
      }
      if (step === 2) { const m = /^HTTP\/1\.[01] (\d{3})/.exec(buf.toString('latin1')); if (m) fin(null, { status: +m[1], ms: Date.now() - t0 }); }
    });
  });
}
async function verifyTunnel(entry) { // убеждаемся, что через сервер реально идёт трафик — до изменения сети Windows
  const tries = entry.auto ? 3 : 2; let last;
  for (let i = 0; i < tries; i++) {
    try { const r = await socksProbe(7000); log('xray', `проверка канала через «${entry.tag}»: HTTP ${r.status}, ${r.ms} мс ✓`); return; }
    catch (e) { last = e; log('xray', `проверка канала #${i + 1}: ${e.message}`); }
    await sleep(1200);
  }
  throw new Error(`Через сервер «${entry.tag}» трафик не идёт (${last.message}). Сервер недоступен или заблокирован — выберите другой (вкладка «Серверы» → «Тест пинга»).`);
}
function happAdapter() {
  try {
    const out = execFileSync('netsh', ['interface', 'show', 'interface'], { windowsHide: true }).toString('latin1');
    const m = out.split(/\r?\n/).find(l => /happ|nekoray|clash|v2ray/i.test(l));
    return m ? m.trim().split(/\s{2,}/).pop() : '';
  } catch { return ''; }
}
function preNorm(o) {
  const out = [], seen = new Set();
  for (const r of (o && o.rules) || []) {
    const kind = r.kind === 'app' ? 'app' : 'domain', server = String(r.server || '').trim();
    let value = kind === 'app' ? path.basename(String(r.value || '')).trim() : normDomain(r.value);
    if (!server) continue;
    if (kind === 'app' ? !/^[^\\/:*?"<>|]+\.exe$/i.test(value) : !(/^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$/.test(value) && value.includes('.'))) continue;
    const key = kind + '|' + value.toLowerCase(); if (seen.has(key)) continue; seen.add(key);
    out.push({ kind, value, server, ...(kind === 'app' && r.path ? { path: String(r.path).slice(0, 260) } : {}) });
  }
  return { rules: out };
}
const preFile = () => path.join(app.getPath('userData'), 'prerouting.json');
const preLoad = () => { try { return preNorm(JSON.parse(fs.readFileSync(preFile(), 'utf8'))); } catch { return { rules: [] }; } };
function preSave(o) { const r = preNorm(o); fs.writeFileSync(preFile(), JSON.stringify(r, null, 2)); log('app', `предварительная маршрутизация: правил ${r.rules.length}`); return r; }
function prePlan() { // правила группируются по серверу: каждому — свой Xray на своём порту и свой socks-выход sing-box
  const groups = new Map();
  for (const r of preLoad().rules) { if (!groups.has(r.server)) groups.set(r.server, []); groups.get(r.server).push(r); }
  const targets = [], outbounds = [], rules = [];
  [...groups.entries()].forEach(([server, rs], i) => {
    const port = PRE_PORT + i, tag = 'pre-' + i;
    targets.push({ server, port, tag }); outbounds.push({ type: 'socks', tag, server: '127.0.0.1', server_port: port, version: '5' });
    const apps = [...new Set(rs.filter(r => r.kind === 'app').flatMap(r => [r.value, r.value.toLowerCase()]))], doms = rs.filter(r => r.kind === 'domain').map(r => r.value);
    if (apps.length) rules.push({ process_name: apps, outbound: tag });
    if (doms.length) rules.push({ domain_suffix: doms, outbound: tag });
  });
  return { targets, outbounds, rules };
}
async function startPre(plan, level) { // если сервер правила не отвечает, порт остаётся закрытым — трафик правила блокируется (как Kill Switch)
  const bad = [];
  await Promise.all(plan.targets.map(async t => {
    const e = (entries || []).find(x => x.tag === t.server);
    if (!e) { log('pre', `сервер «${t.server}» не найден в подписке — трафик его правил блокируется`); bad.push(t.server); return; }
    try {
      const ips = await resolveAll(hostsOf(e), true);
      const f = path.join(app.getPath('userData'), `xray-pre-${t.port - PRE_PORT}.json`);
      fs.writeFileSync(f, JSON.stringify(xrayConfig(e, level, ips, t.port), null, 2));
      if (!(await freePort(t.port))) throw new Error('порт ' + t.port + ' занят');
      const p = run('xray-pre', 'xray.exe', ['run', '-c', f], { XRAY_LOCATION_ASSET: binDir() });
      pre.push(p); savePids();
      p.on('exit', (code) => { log('pre', `Xray для «${t.server}» завершился code=${code}`); pre = pre.filter(x => x !== p); });
      let up = false;
      for (let i = 0; i < 40 && !up; i++) { await sleep(250); if (p.exitCode !== null) throw new Error(p.failed || p.tail() || 'Xray остановился'); up = await portOpen(t.port, 300); }
      if (!up) throw new Error('Xray не открыл порт');
      const r = await socksProbe(7000, t.port); log('pre', `«${t.server}»: канал работает, ${r.ms} мс ✓`);
    } catch (err) { log('pre', `«${t.server}»: ${err.message} — трафик его правил блокируется`); bad.push(t.server); }
  }));
  return bad;
}
async function startSingbox(level, mode) {
  const RT = routeRules(), PP = prePlan();
  // адреса серверов исключаем из TUN: пинг из приложения идёт напрямую и показывает реальную задержку, а не локальный ответ TUN
  const ipm = await resolveAll([...new Set((entries || []).flatMap(hostsOf))], true).catch(() => ({}));
  const excl = [...new Set(Object.values(ipm || {}).filter(v => net.isIPv4(v)).map(v => v + '/32'))];
  const cfg = {
    log: { level: level === 'debug' ? 'debug' : level === 'info' ? 'info' : 'warn', timestamp: false },
    dns: { servers: [{ type: 'tcp', tag: 'dns-remote', server: '1.1.1.1', detour: 'xray' }], final: 'dns-remote', strategy: 'ipv4_only' },
    inbounds: mode === 'proxy' ? [{ type: 'mixed', tag: 'mixed-in', listen: '127.0.0.1', listen_port: PROXY_PORT }]
      : [{ type: 'tun', tag: 'tun-in', address: ['172.19.0.1/30'], auto_route: true, strict_route: true, stack: 'mixed', ...(excl.length ? { route_exclude_address: excl } : {}) }],
    outbounds: [{ type: 'socks', tag: 'xray', server: '127.0.0.1', server_port: XRAY_PORT, version: '5' }, { type: 'direct', tag: 'direct' }, ...PP.outbounds],
    route: {
      rules: [
        { action: 'sniff' },
        { process_name: ['xray.exe'], outbound: 'direct' },   // трафик самого Xray к серверам — мимо TUN
        { protocol: 'dns', action: 'hijack-dns' },
        { ip_is_private: true, outbound: 'direct' },
        ...PP.rules,          // предварительная маршрутизация — выше обычной, работает всегда
        ...RT.rules,
      ],
      final: RT.final, auto_detect_interface: true, find_process: true,
    },
  };
  const f = path.join(app.getPath('userData'), 'singbox-config.json');
  fs.writeFileSync(f, JSON.stringify(cfg, null, 2));
  const p = run('sing-box', 'sing-box.exe', ['run', '-c', f, '-D', binDir()]);
  sb = p; savePids();
  p.on('exit', (code, sig) => {
    log('sing-box', `завершился code=${code} signal=${sig}`);
    if (sb === p) { sb = null; if (!stopping) { lastFail = 'sing-box (TUN) остановился: ' + p.tail(); stopAll('sing-box упал'); } }
  });
  for (let i = 0; i < 8; i++) {
    await sleep(400);
    if (sb !== p) throw new Error('sing-box остановился: ' + (p.failed || p.tail() || 'нет вывода'));
  }
  log('sing-box', mode === 'proxy' ? 'прокси-вход запущен' : 'TUN запущен'); if (mode !== 'proxy') logAdapters('tun');
}
async function stopAll(reason) {
  if (/упал/.test(reason || '')) ksOn(); else if (reason !== 'ошибка' && reason !== 'ошибка переключения') ksOff();
  stopping = true;
  proxyOff();
  for (const p of [sb, xray, ...pre]) { if (p) { try { p.removeAllListeners('exit'); p.kill(); } catch {} } }
  const had = !!(sb || xray);
  sb = null; xray = null; pre = []; savePids();
  if (had) log('app', 'остановлено' + (reason ? ': ' + reason : ''));
  await sleep(150); stopping = false; rpcSince = 0; rpcUpdate();
}
const probe = async (url, ms = 10000) => { const t = Date.now(); const r = await enet.fetch(url, { signal: AbortSignal.timeout(ms) }); return { r, ms: Date.now() - t }; };
async function afterConnectTest() {
  await sleep(1500);
  for (const [name, url] of [['gstatic 204', 'http://www.gstatic.com/generate_204'], ['внешний IP', 'https://api.ipify.org']]) {
    try { const { r, ms } = await probe(url); log('test', `${name}: HTTP ${r.status}, ${ms} мс${name === 'внешний IP' ? ' → ' + (await r.text()).slice(0, 40) : ''}`); }
    catch (e) { log('test', `${name}: ОШИБКА ${why(e)} — канал Xray проверен, значит проблема в TUN/DNS (смотрите [sing-box] и [tun])`); }
  }
}
async function connect(o = {}) {
  await stopAll('перед подключением'); lastFail = '';
  lastLevel = ['info', 'debug'].includes(o.logLevel) ? o.logLevel : 'warning';
  log('app', `=== подключение: сервер «${o.server || '—'}», логи: ${lastLevel} ===`);
  try {
    checkBins();
    const hp = happAdapter();
    if (hp) { lastWarn = `Найден активный сетевой адаптер «${hp}» (Happ или другой VPN). Закройте его полностью (выход из трея) — два TUN конфликтуют.`; log('app', '⚠ ' + lastWarn); }
    const ents = await loadEntries(true, true);
    const entry = ents.find(e => e.tag === o.server) || ents[0];
    curTag = entry.tag;
    await startXray(entry, lastLevel);
    await verifyTunnel(entry);
    const mode = setLoad().mode === 'proxy' ? 'proxy' : 'tun', plan = prePlan();
    if (plan.targets.length) { const bad = await startPre(plan, lastLevel); if (bad.length) lastWarn = 'Предварительная маршрутизация: сервер недоступен (' + bad.map(b => b.replace(/[\u{1F1E6}-\u{1F1FF}]{2}\s*/gu, '')).join(', ') + ') — трафик этих правил заблокирован.'; }
    await startSingbox(lastLevel, mode);
    if (mode === 'proxy') proxyOn();
    log('app', 'подключено (' + (mode === 'proxy' ? 'системный прокси' : 'TUN') + ')'); rpcSince = Math.floor(Date.now() / 1000); rpcUpdate(); afterConnectTest().catch(() => {}); setTimeout(refreshBg, 6000);
    return true;
  } catch (e) { log('app', 'ОШИБКА подключения: ' + e.message); await stopAll('ошибка'); throw e; }
}
async function pick(tag) {
  curTag = tag;
  if (!(xray && sb)) return true;
  const e = (entries || []).find(x => x.tag === tag);
  if (!e) return false;
  opBusy = 'switch'; log('app', `переключение на «${tag}»`);
  try {
    const ips = await resolveAll(hostsOf(e), true);        // пока старый Xray ещё работает — DNS идёт через него
    restarting = true;
    if (xray) { xray.removeAllListeners('exit'); xray.kill(); xray = null; }
    await sleep(350);
    await startXray(e, lastLevel, ips); await verifyTunnel(e);
  } catch (err) { await stopAll('ошибка переключения'); throw err; }
  finally { restarting = false; opBusy = ''; }
  return true;
}
async function diag() {
  log('diag', `=== диагностика: ${app.getName()} ${app.getVersion()}, Windows ${os.release()}, HWID ${hwid().slice(0, 8)}… ===`);
  try { checkBins(); } catch (e) { log('diag', e.message); }
  log('diag', `socks-порт ${XRAY_PORT}: ${(await portOpen(XRAY_PORT, 500)) ? 'открыт' : 'закрыт'}; xray ${xray ? 'работает' : 'нет'}, sing-box ${sb ? 'работает' : 'нет'}`);
  for (const [n, u] of [['кабинет', BASE], ['gstatic 204', 'http://www.gstatic.com/generate_204'], ['внешний IP', 'https://api.ipify.org']]) {
    try { const { r, ms } = await probe(u, 8000); log('diag', `${n}: HTTP ${r.status}, ${ms} мс${n === 'внешний IP' ? ' → ' + (await r.text()).slice(0, 40) : ''}`); }
    catch (e) { log('diag', `${n}: ОШИБКА ${why(e)}`); }
  }
  for (const h of ['1.1.1.1', ...((entries || []).flatMap(e => e.hosts.slice(0, 1).map(x => x.host)).slice(0, 6))]) { const r = await tcpPing({ host: h, port: 443 }); log('diag', `TCP ${h}:443 → ${r.ms >= 0 ? r.ms + ' мс' : 'нет (' + r.why + ')'}`); }
  logAdapters('diag'); await sleep(800);
  log('diag', '=== конец ===');
  return true;
}

// ===== Discord Rich Presence: реклама проекта =====
const RPC = {
  clientId: process.env.MIKAELA_DISCORD_ID || '1571463306009514046',      // <-- вставьте Application ID из discord.com/developers
  largeImage: 'logo',                                   // ключ картинки в Rich Presence → Art Assets
  largeText: 'Mikaela VPN',
  details: 'Быстрый и стабильный VPN',
  stateOn: 'Защита включена', stateOff: 'Ожидает подключения',
  buttons: [{ label: 'Telegram-бот', url: 'https://t.me/vpnmikaelabot' }, { label: 'Личный кабинет', url: 'https://cabinet.mikaelavpn.xyz' }],
};
let rpcOn = false, rpcSock = null, rpcReady = false, rpcTimer = null, rpcSince = 0;
const rpcFrame = (op, obj) => { const b = Buffer.from(JSON.stringify(obj)), h = Buffer.alloc(8); h.writeInt32LE(op, 0); h.writeInt32LE(b.length, 4); return Buffer.concat([h, b]); };
function rpcConnect(i = 0) {
  if (!rpcOn || !RPC.clientId || rpcSock) return;
  if (i > 9) { rpcTimer = setTimeout(() => rpcConnect(0), 30000); return; }
  const s = net.connect('\\\\?\\pipe\\discord-ipc-' + i);
  let buf = Buffer.alloc(0), opened = false;
  s.on('connect', () => { opened = true; rpcSock = s; s.write(rpcFrame(0, { v: 1, client_id: RPC.clientId })); });
  s.on('data', d => {
    buf = Buffer.concat([buf, d]);
    while (buf.length >= 8) {
      const op = buf.readInt32LE(0), len = buf.readInt32LE(4);
      if (buf.length < 8 + len) break;
      let msg = {}; try { msg = JSON.parse(buf.slice(8, 8 + len).toString() || '{}'); } catch {}
      buf = buf.slice(8 + len);
      if (op === 3) s.write(rpcFrame(4, msg));
      if (op === 2) { log('discord', 'Discord закрыл соединение: ' + (msg.message || msg.code || '')); s.destroy(); }
      if (msg.evt === 'READY') { rpcReady = true; log('discord', 'подключено'); rpcUpdate(); }
      if (msg.evt === 'ERROR') log('discord', 'ошибка: ' + JSON.stringify(msg.data));
    }
  });
  s.on('error', () => { if (!opened) rpcConnect(i + 1); });
  s.on('close', () => { if (rpcSock === s) { rpcSock = null; rpcReady = false; } if (opened && rpcOn) rpcTimer = setTimeout(() => rpcConnect(0), 15000); });
}
function rpcUpdate() {
  if (!rpcSock || !rpcReady) return;
  const on = !!(xray && sb);
  const activity = { details: RPC.details, state: on ? RPC.stateOn : RPC.stateOff, assets: { large_image: RPC.largeImage, large_text: RPC.largeText }, buttons: RPC.buttons.slice(0, 2) };
  if (on) activity.timestamps = { start: rpcSince || Math.floor(Date.now() / 1000) };
  rpcSock.write(rpcFrame(1, { cmd: 'SET_ACTIVITY', args: { pid: process.pid, activity }, nonce: crypto.randomUUID() }));
}
function setRpc(en) {
  rpcOn = en; clearTimeout(rpcTimer);
  if (!RPC.clientId) { if (en) log('discord', 'не задан Application ID (RPC.clientId в main.js)'); return; }
  if (en) { if (!rpcSock) rpcConnect(0); else rpcUpdate(); }
  else if (rpcSock) { try { rpcSock.write(rpcFrame(1, { cmd: 'SET_ACTIVITY', args: { pid: process.pid, activity: null }, nonce: crypto.randomUUID() })); } catch {} const s = rpcSock; setTimeout(() => s.destroy(), 200); }
}

const h = (c, f) => ipcMain.handle(c, async (_, ...a) => {
  try { return { ok: true, data: await f(...a) }; }
  catch (e) { return { ok: false, error: e.message }; }
});
h('session', () => session ? session.user : null);
h('login', login);
h('logout', async () => { await stopAll('выход'); try { await authed('/cabinet/auth/logout', { method: 'POST', headers: J, body: JSON.stringify({ refresh_token: session.refresh }) }); } catch {} session = null; entries = null; save(); });
h('sub', getSub);
h('connect', serial(async o => { opBusy = 'connect'; try { return await connect(o); } finally { opBusy = ''; } }));
h('disconnect', serial(() => stopAll('по кнопке')));
h('status', async () => { const e = lastFail, w = lastWarn; lastFail = ''; lastWarn = ''; return { running: !!(xray && sb) || opBusy === 'switch', op: opBusy, error: e, warn: w, ea: entriesAt, stale }; });
h('servers', servers);
h('pingmany', pingMany);
h('pick', serial(pick));
h('devices', devices);
h('deviceprice', devicePrice);
h('devicebuy', deviceBuy);
h('deldevice', delDevice);
h('resetdevices', resetDevices);
h('hwid', async () => hwid());
h('methods', methods);
h('topup', topup);
h('renewoptions', renewOptions);
h('renew', renew);
h('register', register);
h('forgot', forgot);
h('tg', tgLogin);
h('tgcancel', async () => { tgCancel = true; });
h('weblogin', webLogin);
h('me', me);
h('cabinet', () => shell.openExternal(CABINET));
h('subs', listSubs);
h('setsub', setSub);
h('setrpc', async en => { setRpc(!!en); return true; });
h('rpcinfo', async () => ({ configured: !!RPC.clientId, connected: rpcReady }));

if (!app.requestSingleInstanceLock()) app.quit();
app.on('second-instance', () => showWin());

// ---- Kill Switch: при неожиданном обрыве VPN блокируем исходящий трафик (брандмауэр Windows) ----
const setFile = () => path.join(app.getPath('userData'), 'settings.json');
const setLoad = () => { try { return JSON.parse(fs.readFileSync(setFile(), 'utf8')); } catch { return {}; } };
const setSave = o => { try { fs.writeFileSync(setFile(), JSON.stringify(o)); } catch {} };
const ksMark = () => path.join(app.getPath('userData'), 'ks-active');
let ksActive = false;
const psq = s => "'" + String(s).replace(/'/g, "''") + "'";
function psRun(script) { execFileSync('powershell', ['-NoProfile', '-NonInteractive', '-Command', script], { windowsHide: true, stdio: 'pipe', timeout: 20000 }); }
function ksOn() {
  if (ksActive || !setLoad().ks) return;
  try {
    const apps = [process.execPath, path.join(binDir(), 'xray.exe'), path.join(binDir(), 'sing-box.exe')];
    const g = "'MikaelaVPN-KS'";
    let s = "$ErrorActionPreference='Stop';Get-NetFirewallRule -Group " + g + " -ErrorAction SilentlyContinue | Remove-NetFirewallRule;";
    apps.forEach((p, i) => { s += `New-NetFirewallRule -DisplayName 'Mikaela KS app ${i}' -Group ${g} -Direction Outbound -Action Allow -Program ${psq(p)} -Profile Any | Out-Null;`; });
    s += `New-NetFirewallRule -DisplayName 'Mikaela KS dns udp' -Group ${g} -Direction Outbound -Action Allow -Service Dnscache -Protocol UDP -RemotePort 53 -Profile Any | Out-Null;`;
    s += `New-NetFirewallRule -DisplayName 'Mikaela KS dns tcp' -Group ${g} -Direction Outbound -Action Allow -Service Dnscache -Protocol TCP -RemotePort 53 -Profile Any | Out-Null;`;
    s += `New-NetFirewallRule -DisplayName 'Mikaela KS dhcp' -Group ${g} -Direction Outbound -Action Allow -Service Dhcp -Protocol UDP -RemotePort 67 -Profile Any | Out-Null;`;
    s += "Set-NetFirewallProfile -All -DefaultOutboundAction Block";
    psRun(s); ksActive = true; try { fs.writeFileSync(ksMark(), '1'); } catch {}
    log('app', 'Kill Switch: интернет заблокирован до повторного подключения');
  } catch (e) { log('app', 'Kill Switch не включился: ' + String(e.stderr || e.message).slice(0, 200)); }
}
function ksOff(force) {
  if (!ksActive && !force) return;
  try { psRun("Set-NetFirewallProfile -All -DefaultOutboundAction Allow;Get-NetFirewallRule -Group 'MikaelaVPN-KS' -ErrorAction SilentlyContinue | Remove-NetFirewallRule"); }
  catch (e) { log('app', 'Kill Switch: не удалось снять блокировку: ' + String(e.stderr || e.message).slice(0, 200)); return; }
  ksActive = false; try { fs.unlinkSync(ksMark()); } catch {}
  log('app', 'Kill Switch: блокировка снята');
}
h('preget', async () => preLoad());
h('preset', async o => preSave(o || {}));
h('modeget', async () => ({ mode: setLoad().mode === 'proxy' ? 'proxy' : 'tun' }));
h('modeset', async m => { const s = setLoad(); s.mode = m === 'proxy' ? 'proxy' : 'tun'; setSave(s); log('app', 'режим работы: ' + s.mode); return { mode: s.mode }; });
h('ksget', async () => ({ on: !!setLoad().ks, active: ksActive }));
h('ksset', async v => { const s = setLoad(); s.ks = !!v; setSave(s); if (!v) ksOff(); return { on: !!v }; });

// ---- способы входа (подтягиваются из кабинета) ----
async function authOpts() {
  const o = { email: true, reg: true, telegram: false, oauth: [] };
  const get = async p => { try { const r = await raw(p); if (!r.ok) return null; return await r.json(); } catch { return null; } };
  const [pr, tw, em] = await Promise.all([get('/cabinet/auth/oauth/providers'), get('/cabinet/branding/telegram-widget'), get('/cabinet/branding/email-auth')]);
  log('auth', `способы входа: oauth=${JSON.stringify(pr)} telegram=${JSON.stringify(tw)} email=${JSON.stringify(em)}`.slice(0, 600));
  if (pr && Array.isArray(pr.providers)) o.oauth = pr.providers.filter(x => x && x.name).map(x => ({ name: String(x.name), title: String(x.display_name || x.name) }));
  if (tw && tw.enabled !== false && (tw.bot_username || tw.bot_name || tw.oidc_enabled || tw.oidc_client_id || tw.enabled === true)) o.telegram = true;
  if (em) { const v = em.enabled ?? em.email_auth_enabled ?? em.email_enabled; if (typeof v === 'boolean') { o.email = v; o.reg = v; } }
  return o;
}
h('authopts', authOpts);

// ---- маршрутизация: приложения и домены ----
const routeFile = () => path.join(app.getPath('userData'), 'routing.json');
const ROUTE_DEF = { mode: 'bypass', apps: [], domains: [] };
function routeLoad() {
  try { const j = JSON.parse(fs.readFileSync(routeFile(), 'utf8')); return { mode: j.mode === 'only' ? 'only' : 'bypass', apps: Array.isArray(j.apps) ? j.apps : [], domains: Array.isArray(j.domains) ? j.domains : [] }; }
  catch { return { ...ROUTE_DEF, apps: [], domains: [] }; }
}
const normDomain = s => String(s || '').trim().toLowerCase().replace(/^[a-z]+:\/\//, '').replace(/^\*?\./, '').split(/[\/:?#]/)[0];
function routeSave(o) {
  const apps = [], seen = new Set();
  for (const a of (o.apps || [])) { const name = path.basename(String(a.name || a.path || '')).trim(); if (!/^[^\\/:*?"<>|]+\.exe$/i.test(name) || seen.has(name.toLowerCase())) continue; seen.add(name.toLowerCase()); apps.push({ name, path: a.path ? String(a.path) : '' }); }
  const domains = [...new Set((o.domains || []).map(normDomain).filter(x => /^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$/.test(x) && x.includes('.')))];
  const r = { mode: o.mode === 'only' ? 'only' : 'bypass', apps, domains };
  fs.writeFileSync(routeFile(), JSON.stringify(r, null, 2)); log('app', `маршрутизация: режим ${r.mode}, приложений ${apps.length}, доменов ${domains.length}`);
  return r;
}
function routeRules() {
  const r = routeLoad(), rules = [];
  const target = r.mode === 'only' ? 'xray' : 'direct';
  const names = [...new Set(r.apps.flatMap(a => [a.name, a.name.toLowerCase()]))];
  if (names.length) rules.push({ process_name: names, outbound: target });
  if (r.domains.length) rules.push({ domain_suffix: r.domains, outbound: target });
  const only = r.mode === 'only' && rules.length > 0;
  if (r.mode === 'only' && !rules.length) log('app', 'режим «только список» пуст — используется обычная маршрутизация');
  return { rules, final: only ? 'direct' : 'xray' };
}
h('routeget', async () => routeLoad());
h('routeset', async o => routeSave(o || {}));
h('pickexe', async () => {
  const r = await dialog.showOpenDialog(win, { title: 'Выберите программу', properties: ['openFile'], filters: [{ name: 'Программы', extensions: ['exe'] }] });
  if (r.canceled || !r.filePaths[0]) return null;
  return { name: path.basename(r.filePaths[0]), path: r.filePaths[0] };
});
h('procs', () => new Promise(res => {
  const ps = "[Console]::OutputEncoding=[Text.Encoding]::UTF8; Get-Process | Where-Object {$_.MainWindowTitle} | Select-Object @{n='name';e={$_.ProcessName+'.exe'}},@{n='path';e={$_.Path}},@{n='title';e={$_.MainWindowTitle}} | ConvertTo-Json -Compress";
  execFile('powershell', ['-NoProfile', '-NonInteractive', '-Command', ps], { windowsHide: true, timeout: 10000, maxBuffer: 4e6 }, (err, out) => {
    if (err) return res([]);
    try { let a = JSON.parse(String(out).trim() || '[]'); if (!Array.isArray(a)) a = [a]; const seen = new Set();
      res(a.filter(x => x && x.name && !/^(xray|sing-box|mikaela vpn|mikaela-vpn)\.exe$/i.test(x.name) && !seen.has(x.name.toLowerCase()) && seen.add(x.name.toLowerCase())).map(x => ({ name: x.name, path: x.path || '', title: String(x.title || '').slice(0, 60) })).sort((p, q) => p.name.localeCompare(q.name))); }
    catch { res([]); }
  });
}));

// ---- автозапуск (планировщик задач: запуск с правами администратора без UAC) ----
const TASK = 'MikaelaVPN';
const taskXml = (exe, hidden) => `<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Triggers><LogonTrigger><Enabled>true</Enabled><Delay>PT10S</Delay></LogonTrigger></Triggers>
  <Principals><Principal id="A"><LogonType>InteractiveToken</LogonType><RunLevel>HighestAvailable</RunLevel></Principal></Principals>
  <Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy><DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries><StopIfGoingOnBatteries>false</StopIfGoingOnBatteries><ExecutionTimeLimit>PT0S</ExecutionTimeLimit><Enabled>true</Enabled></Settings>
  <Actions Context="A"><Exec><Command>${exe.replace(/&/g, '&amp;').replace(/</g, '&lt;')}</Command>${hidden ? '<Arguments>--hidden</Arguments>' : ''}</Exec></Actions>
</Task>`;
function autoGet() {
  try { const x = execFileSync('schtasks', ['/Query', '/TN', TASK, '/XML'], { windowsHide: true, stdio: ['ignore', 'pipe', 'ignore'] }).toString('utf8'); return { on: true, min: /--hidden/.test(x) }; }
  catch { return { on: false, min: false }; }
}
function autoSet(on, min) {
  if (!app.isPackaged) throw new Error('Автозапуск доступен только в установленной версии');
  if (!on) { try { execFileSync('schtasks', ['/Delete', '/TN', TASK, '/F'], { windowsHide: true, stdio: 'ignore' }); } catch {} log('app', 'автозапуск выключен'); return autoGet(); }
  const f = path.join(app.getPath('temp'), 'mikaela-task.xml');
  fs.writeFileSync(f, Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from(taskXml(process.execPath, !!min), 'utf16le')]));
  try { execFileSync('schtasks', ['/Create', '/TN', TASK, '/XML', f, '/F'], { windowsHide: true, stdio: 'pipe' }); }
  catch (e) { throw new Error('Не удалось создать задачу: ' + String((e.stderr || e.message)).slice(0, 160)); }
  finally { try { fs.unlinkSync(f); } catch {} }
  log('app', `автозапуск включён${min ? ' (свёрнутым)' : ''}`); return autoGet();
}
h('autoget', async () => ({ ...autoGet(), packaged: app.isPackaged }));
h('autoset', async (on, min) => autoSet(on, min));
const START_HIDDEN = process.argv.includes('--hidden');

// ---- трей: приложение живёт в фоне, закрытие окна только прячет его ----
let tray = null, quitting = false;
function showWin() { if (!win) return; if (win.isMinimized()) win.restore(); win.show(); win.focus(); }
function trayMenu() {
  const on = !!sb;
  tray.setToolTip('Mikaela VPN — ' + (on ? 'подключено' : 'отключено'));
  tray.setContextMenu(Menu.buildFromTemplate([
    { label: 'Открыть Mikaela VPN', click: showWin },
    { label: on ? 'Статус: подключено' : 'Статус: отключено', enabled: false },
    ...(on ? [{ label: 'Отключить', click: () => { serial(() => stopAll('по кнопке'))(); } }] : []),
    { type: 'separator' },
    { label: 'Выход', click: () => { quitting = true; app.quit(); } },
  ]));
}
function initTray() {
  try {
    tray = new Tray(nativeImage.createFromPath(path.join(__dirname, 'icon.png')).resize({ width: 16, height: 16 }));
    tray.on('click', showWin);
    trayMenu(); setInterval(trayMenu, 3000);
  } catch (e) { log('app', 'трей не создан: ' + e.message); }
}

// ---- автообновление клиента (electron-updater, GitHub Releases) ----
let updater = null, upd = { state: 'idle', version: '', percent: 0, error: '' };
function initUpdater() {
  if (!app.isPackaged || process.env.PORTABLE_EXECUTABLE_DIR) { upd.state = 'off'; return; }
  try {
    updater = require('electron-updater').autoUpdater;
    updater.autoDownload = true; updater.autoInstallOnAppQuit = true;
    updater.logger = { info: m => log('update', String(m)), warn: m => log('update', String(m)), error: m => log('update', String(m)), debug() {} };
    updater.on('checking-for-update', () => { upd.state = 'checking'; });
    updater.on('update-available', i => { upd = { state: 'downloading', version: i.version, percent: 0, error: '' }; });
    updater.on('update-not-available', () => { upd.state = 'latest'; });
    updater.on('download-progress', p => { upd.state = 'downloading'; upd.percent = Math.round(p.percent); });
    updater.on('update-downloaded', i => { upd = { state: 'ready', version: i.version, percent: 100, error: '' }; });
    updater.on('error', e => { upd.state = 'error'; upd.error = String(e && e.message || e).slice(0, 200); });
    const chk = () => updater.checkForUpdates().catch(() => {});
    setTimeout(chk, 8000); setInterval(chk, 180000);
  } catch (e) { upd.state = 'off'; log('update', 'не запущено: ' + e.message); }
}
h('updinfo', async () => ({ ...upd, current: app.getVersion(), enabled: !!updater }));
h('updcheck', async () => { if (updater) { try { await updater.checkForUpdates(); } catch {} } return { ...upd, current: app.getVersion(), enabled: !!updater }; });
h('updinstall', async () => { quitting = true; if (updater && upd.state === 'ready') { try { proxyOff(); for (const p of [sb, xray, ...pre]) if (p) p.kill(); } catch {} updater.quitAndInstall(true, true); } return {}; });

app.whenReady().then(() => {
  load(); loadDisk(); proxyOffSync(); killOrphans();
  if (fs.existsSync(ksMark())) { try { ksOff(true); } catch {} }
  log('app', `запуск ${app.getName()} ${app.getVersion()}, Windows ${os.release()}, bin: ${binDir()}`);
  win = new BrowserWindow({
    width: 440, height: 820, show: !START_HIDDEN, resizable: false, autoHideMenuBar: true, backgroundColor: '#111111',
    icon: path.join(__dirname,'icon.png'), title: 'Mikaela VPN', webPreferences: { preload: path.join(__dirname, 'preload.js'), contextIsolation: true },
  });
  win.loadFile('index.html');
  win.on('close', e => { if (!quitting) { e.preventDefault(); win.hide(); } });
  initTray();
  initUpdater();
});
app.on('before-quit', () => { quitting = true; try { proxyOff(); } catch {} try { ksOff(); } catch {} try { if (rpcSock) rpcSock.destroy(); } catch {} for (const p of [sb, xray, ...pre]) { try { if (p) p.kill(); } catch {} } });
app.on('window-all-closed', () => {});
