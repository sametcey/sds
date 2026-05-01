/* eslint-env node */
const crypto = require('crypto');
const fs = require('fs');
const http = require('http');
const path = require('path');
const nodemailer = require('nodemailer');

const PORT = Number(process.env.AUTH_PORT || process.env.PORT || 4000);
const PUBLIC_BASE_URL = process.env.AUTH_PUBLIC_BASE_URL || `http://localhost:${PORT}`;
const JWT_SECRET = process.env.AUTH_JWT_SECRET || crypto.randomBytes(32).toString('hex');
const DATA_DIR = process.env.AUTH_DATA_DIR || path.join(__dirname, 'data');
const DB_FILE = path.join(DATA_DIR, 'users.json');
const HEADERS = {
  'Content-Type': 'application/json; charset=utf-8',
  'Access-Control-Allow-Origin': process.env.AUTH_ALLOWED_ORIGIN || '*',
  'Access-Control-Allow-Methods': 'GET,POST,PATCH,PUT,DELETE,OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
  'X-Content-Type-Options': 'nosniff'
};

const ensureDb = () => {
  fs.mkdirSync(DATA_DIR, {recursive: true});
  if (!fs.existsSync(DB_FILE)) {
    fs.writeFileSync(DB_FILE, JSON.stringify({users: [], profiles: [], friendRequests: [], friends: [], chats: [], messages: []}, null, 2));
  }
};
const readDb = () => {
  ensureDb();
  const db = JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
  for (const key of ['users', 'profiles', 'friendRequests', 'friends', 'chats', 'messages']) db[key] = db[key] || [];
  return db;
};
const writeDb = db => { ensureDb(); fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2)); };
const json = (res, status, body) => { res.writeHead(status, HEADERS); res.end(JSON.stringify(body)); };
const body = req => new Promise((resolve, reject) => {
  let raw = '';
  req.on('data', chunk => { raw += chunk; if (raw.length > 1024 * 1024) reject(new Error('Istek cok buyuk.')); });
  req.on('end', () => { try { resolve(raw ? JSON.parse(raw) : {}); } catch { reject(new Error('Gecersiz JSON.')); } });
});
const normalizeEmail = email => String(email || '').trim().toLowerCase();
const validEmail = email => /\S+@\S+\.\S+/.test(email);
const validPassword = password => typeof password === 'string' && password.length >= 8 && /[A-Za-z]/.test(password) && /[0-9]/.test(password);
const hashPassword = password => new Promise((resolve, reject) => {
  const salt = crypto.randomBytes(16).toString('hex');
  crypto.scrypt(password, salt, 64, (err, key) => err ? reject(err) : resolve(`${salt}:${key.toString('hex')}`));
});
const verifyPassword = (password, hash) => new Promise((resolve, reject) => {
  const [salt, stored] = String(hash || '').split(':');
  if (!salt || !stored) return resolve(false);
  crypto.scrypt(password, salt, 64, (err, key) => {
    if (err) return reject(err);
    const expected = Buffer.from(stored, 'hex');
    resolve(expected.length === key.length && crypto.timingSafeEqual(expected, key));
  });
});
const b64 = input => Buffer.from(input).toString('base64url');
const sign = user => {
  const header = b64(JSON.stringify({alg: 'HS256', typ: 'JWT'}));
  const payload = b64(JSON.stringify({sub: user.id, email: user.email, emailVerified: user.emailVerified, exp: Math.floor(Date.now() / 1000) + 60 * 60 * 24 * 30}));
  const sig = crypto.createHmac('sha256', JWT_SECRET).update(`${header}.${payload}`).digest('base64url');
  return `${header}.${payload}.${sig}`;
};
const verify = token => {
  const [h, p, s] = String(token || '').split('.');
  if (!h || !p || !s) return null;
  const expected = crypto.createHmac('sha256', JWT_SECRET).update(`${h}.${p}`).digest('base64url');
  if (Buffer.byteLength(s) !== Buffer.byteLength(expected) || !crypto.timingSafeEqual(Buffer.from(s), Buffer.from(expected))) return null;
  const parsed = JSON.parse(Buffer.from(p, 'base64url').toString('utf8'));
  return parsed.exp > Math.floor(Date.now() / 1000) ? parsed : null;
};
const publicUser = user => ({id: user.id, email: user.email, emailVerified: Boolean(user.emailVerified)});
const normalizeUsername = username => String(username || '').trim().toLowerCase().replace(/^@/, '');
const uniqueUsername = (db, email, uid) => {
  const base = normalizeUsername(String(email).split('@')[0]).replace(/[^a-z0-9_]/g, '_').slice(0, 16) || `user_${uid.slice(0, 6)}`;
  let name = base, i = 1;
  while (db.profiles.some(p => p.uid !== uid && p.usernameLower === name)) name = `${base}_${i++}`.slice(0, 20);
  return name;
};
const ensureProfile = (db, user) => {
  let p = db.profiles.find(x => x.uid === user.id);
  if (p) return p;
  const now = new Date().toISOString();
  const username = uniqueUsername(db, user.email, user.id);
  p = {uid: user.id, username, usernameLower: username, displayName: username, email: user.email, photoURL: '', bio: '', streakIcon: '🔥', streakCount: 0, longestStreak: 0, totalVerifiedStudyMinutes: 0, createdAt: now, updatedAt: now, termsAccepted: Boolean(user.termsAccepted), termsAcceptedAt: user.termsAcceptedAt || '', privacyAccepted: Boolean(user.privacyAccepted), privacyAcceptedAt: user.privacyAcceptedAt || ''};
  db.profiles.push(p);
  return p;
};
const auth = req => {
  const token = (req.headers.authorization || '').replace(/^Bearer /, '');
  const payload = verify(token);
  if (!payload) return {error: 'Oturum gecersiz veya suresi dolmus.'};
  const db = readDb();
  const user = db.users.find(u => u.id === payload.sub);
  return user ? {db, user, token} : {error: 'Hesap bulunamadi.'};
};
const verificationLink = user => {
  user.verificationToken = crypto.randomBytes(32).toString('hex');
  user.verificationExpiresAt = new Date(Date.now() + 86400000).toISOString();
  return `${PUBLIC_BASE_URL}/auth/verify?token=${user.verificationToken}`;
};
const mailer = () => {
  for (const k of ['SMTP_HOST', 'SMTP_PORT', 'SMTP_USER', 'SMTP_PASS', 'SMTP_FROM']) if (!process.env[k]) throw new Error(`SMTP ayari eksik: ${k}`);
  return nodemailer.createTransport({host: process.env.SMTP_HOST, port: Number(process.env.SMTP_PORT), secure: process.env.SMTP_SECURE === 'true', auth: {user: process.env.SMTP_USER, pass: process.env.SMTP_PASS}});
};
const sendVerification = async (email, link) => mailer().sendMail({from: process.env.SMTP_FROM, to: email, subject: 'Streakify e-posta dogrulama', text: `Hesabini dogrulamak icin tikla: ${link}`, html: `<p>Streakify hesabini aktifleştirmek icin baglantiya tikla.</p><p><a href="${link}">E-postami dogrula</a></p>`});
const html = (res, title, text) => { res.writeHead(200, {'Content-Type': 'text/html; charset=utf-8'}); res.end(`<!doctype html><html lang="tr"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${title}</title><body style="font-family:Arial;background:#fff8ec;color:#1e293b;padding:32px;line-height:1.6"><main style="max-width:820px;margin:auto;background:white;border-radius:18px;padding:24px"><h1 style="color:#e8590c">${title}</h1><p>${text}</p><p>Bu metin genel bilgilendirme taslagidir; yasal danismanlik degildir.</p></main></body></html>`); };

const handlers = {
  async register(req, res) {
    const b = await body(req); const email = normalizeEmail(b.email); const password = String(b.password || '');
    if (!validEmail(email)) return json(res, 400, {message: 'Gecerli bir e-posta adresi yaz.'});
    if (!validPassword(password)) return json(res, 400, {message: 'Sifre en az 8 karakter olmali, harf ve rakam icermeli.'});
    const db = readDb(); let user = db.users.find(u => u.email === email);
    if (user?.emailVerified) return json(res, 409, {message: 'Bu e-posta ile kayitli dogrulanmis bir hesap var.'});
    user = user || {id: crypto.randomUUID(), email, createdAt: new Date().toISOString(), emailVerified: false};
    user.passwordHash = await hashPassword(password); user.termsAccepted = Boolean(b.termsAccepted); user.termsAcceptedAt = b.termsAcceptedAt || null; user.privacyAccepted = Boolean(b.privacyAccepted); user.privacyAcceptedAt = b.privacyAcceptedAt || null; user.updatedAt = new Date().toISOString();
    const link = verificationLink(user); if (!db.users.some(u => u.id === user.id)) db.users.push(user); writeDb(db); await sendVerification(email, link);
    json(res, 201, {message: 'Dogrulama maili gonderildi. Giris yapmadan once e-postani dogrula.', user: publicUser(user)});
  },
  async login(req, res) {
    const b = await body(req); const db = readDb(); const user = db.users.find(u => u.email === normalizeEmail(b.email));
    if (!user || !(await verifyPassword(String(b.password || ''), user.passwordHash))) return json(res, 401, {message: 'E-posta veya sifre hatali.'});
    if (!user.emailVerified) return json(res, 403, {message: 'E-postan dogrulanmadi. Lutfen dogrulama mailindeki baglantiya tikla.'});
    json(res, 200, {message: 'Giris basarili.', session: {token: sign(user), user: publicUser(user)}});
  },
  verify(req, res) {
    const token = new URL(req.url, PUBLIC_BASE_URL).searchParams.get('token'); const db = readDb(); const user = db.users.find(u => u.verificationToken === token);
    if (!user || new Date(user.verificationExpiresAt).getTime() < Date.now()) { res.writeHead(400, {'Content-Type': 'text/html; charset=utf-8'}); return res.end('<h1>Dogrulama baglantisi gecersiz veya suresi dolmus.</h1>'); }
    user.emailVerified = true; user.verificationToken = null; user.verificationExpiresAt = null; user.updatedAt = new Date().toISOString(); writeDb(db);
    res.writeHead(200, {'Content-Type': 'text/html; charset=utf-8'}); res.end('<h1>E-posta dogrulandi.</h1><p>Artik Streakify uygulamasina giris yapabilirsin.</p>');
  },
  async resend(req, res) {
    const b = await body(req); const db = readDb(); const user = db.users.find(u => u.email === normalizeEmail(b.email));
    if (!user) return json(res, 404, {message: 'Bu e-posta ile kayitli hesap bulunamadi.'});
    if (user.emailVerified) return json(res, 200, {message: 'Bu hesap zaten dogrulanmis.'});
    const link = verificationLink(user); writeDb(db); await sendVerification(user.email, link); json(res, 200, {message: 'Yeni dogrulama maili gonderildi.'});
  },
  me(req, res) { const a = auth(req); if (a.error) return json(res, 401, {message: a.error}); json(res, 200, {token: a.token, user: publicUser(a.user)}); },
  profiles(req, res) { const a = auth(req); if (a.error) return json(res, 401, {message: a.error}); ensureProfile(a.db, a.user); writeDb(a.db); json(res, 200, a.db.profiles); },
  async myProfile(req, res) { const a = auth(req); if (a.error) return json(res, 401, {message: a.error}); const p = ensureProfile(a.db, a.user); if (req.method === 'GET') { writeDb(a.db); return json(res, 200, p); } const b = await body(req); Object.assign(p, {displayName: String(b.displayName || p.displayName).slice(0,60), bio: String(b.bio || '').slice(0,240), photoURL: String(b.photoURL || ''), streakIcon: String(b.streakIcon || p.streakIcon || '🔥').slice(0,4), updatedAt: new Date().toISOString()}); if (b.username) { const u = normalizeUsername(b.username); if (!/^[a-z0-9_]{3,20}$/.test(u)) return json(res, 400, {message: 'Kullanici adi 3-20 karakter olmali; harf, rakam ve alt cizgi kullan.'}); if (a.db.profiles.some(x => x.uid !== p.uid && x.usernameLower === u)) return json(res, 409, {message: 'Bu kullanici adi zaten kullaniliyor.'}); p.username = u; p.usernameLower = u; } writeDb(a.db); json(res, 200, p); }
};

const server = http.createServer(async (req, res) => {
  try {
    if (req.method === 'OPTIONS') { res.writeHead(204, HEADERS); return res.end(); }
    if (req.method === 'GET' && req.url === '/health') return json(res, 200, {status: 'ok', service: 'streakify-auth'});
    if (req.method === 'GET' && req.url === '/terms') return html(res, 'Kullanici Sozlesmesi', 'Streakify calisma plani, motivasyon, streak, profil, arkadas ve mesajlasma ozellikleri sunar. Kullanici hesabi ve uygulama kullanimindan sorumludur.');
    if (req.method === 'GET' && req.url === '/privacy') return html(res, 'Gizlilik Politikasi', 'Streakify e-posta, profil, calisma plani, streak, arkadaslik ve mesaj verilerini uygulama ozelliklerini calistirmak icin isleyebilir. Sifreler duz metin saklanmaz.');
    if (req.method === 'POST' && req.url === '/auth/register') return handlers.register(req, res);
    if (req.method === 'GET' && req.url.startsWith('/auth/verify')) return handlers.verify(req, res);
    if (req.method === 'POST' && req.url === '/auth/login') return handlers.login(req, res);
    if (req.method === 'POST' && req.url === '/auth/resend-verification') return handlers.resend(req, res);
    if (req.method === 'GET' && req.url === '/auth/me') return handlers.me(req, res);
    if (req.method === 'GET' && req.url === '/profiles') return handlers.profiles(req, res);
    if ((req.method === 'GET' || req.method === 'PUT') && req.url === '/profiles/me') return handlers.myProfile(req, res);
    json(res, 404, {message: 'Endpoint bulunamadi.'});
  } catch (err) { json(res, 500, {message: err instanceof Error ? err.message : 'Sunucu hatasi.'}); }
});
server.listen(PORT, () => console.log(`Auth server listening on ${PUBLIC_BASE_URL}`));
