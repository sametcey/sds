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

process.on('uncaughtException', error => console.error('uncaughtException', error));
process.on('unhandledRejection', error => console.error('unhandledRejection', error));

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
const json = (res, status, value) => { res.writeHead(status, HEADERS); res.end(JSON.stringify(value)); };
const readBody = req => new Promise((resolve, reject) => {
  let raw = '';
  req.on('data', chunk => { raw += chunk; if (raw.length > 1024 * 1024) reject(new Error('Istek cok buyuk.')); });
  req.on('end', () => { try { resolve(raw ? JSON.parse(raw) : {}); } catch { reject(new Error('Gecersiz JSON.')); } });
});

const normalizeEmail = email => String(email || '').trim().toLowerCase();
const validEmail = email => /\S+@\S+\.\S+/.test(email);
const validPassword = password => typeof password === 'string' && password.length >= 8 && /[A-Za-z]/.test(password) && /[0-9]/.test(password);
const hashPassword = password => new Promise((resolve, reject) => {
  const salt = crypto.randomBytes(16).toString('hex');
  crypto.scrypt(password, salt, 64, (error, key) => error ? reject(error) : resolve(`${salt}:${key.toString('hex')}`));
});
const verifyPassword = (password, hash) => new Promise((resolve, reject) => {
  const [salt, stored] = String(hash || '').split(':');
  if (!salt || !stored) return resolve(false);
  crypto.scrypt(password, salt, 64, (error, key) => {
    if (error) return reject(error);
    const expected = Buffer.from(stored, 'hex');
    resolve(expected.length === key.length && crypto.timingSafeEqual(expected, key));
  });
});
const b64 = input => Buffer.from(input).toString('base64url');
const signSession = user => {
  const header = b64(JSON.stringify({alg: 'HS256', typ: 'JWT'}));
  const payload = b64(JSON.stringify({sub: user.id, email: user.email, emailVerified: user.emailVerified, exp: Math.floor(Date.now() / 1000) + 60 * 60 * 24 * 30}));
  const sig = crypto.createHmac('sha256', JWT_SECRET).update(`${header}.${payload}`).digest('base64url');
  return `${header}.${payload}.${sig}`;
};
const verifySession = token => {
  const [header, payload, sig] = String(token || '').split('.');
  if (!header || !payload || !sig) return null;
  const expected = crypto.createHmac('sha256', JWT_SECRET).update(`${header}.${payload}`).digest('base64url');
  if (Buffer.byteLength(sig) !== Buffer.byteLength(expected) || !crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) return null;
  const parsed = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
  return parsed.exp > Math.floor(Date.now() / 1000) ? parsed : null;
};
const publicUser = user => ({id: user.id, email: user.email, emailVerified: Boolean(user.emailVerified)});
const normalizeUsername = username => String(username || '').trim().toLowerCase().replace(/^@/, '');
const uniqueUsername = (db, email, uid) => {
  const base = normalizeUsername(String(email).split('@')[0]).replace(/[^a-z0-9_]/g, '_').slice(0, 16) || `user_${uid.slice(0, 6)}`;
  let username = base;
  let index = 1;
  while (db.profiles.some(profile => profile.uid !== uid && profile.usernameLower === username)) username = `${base}_${index++}`.slice(0, 20);
  return username;
};
const ensureProfile = (db, user) => {
  let profile = db.profiles.find(item => item.uid === user.id);
  if (profile) return profile;
  const now = new Date().toISOString();
  const username = uniqueUsername(db, user.email, user.id);
  profile = {uid: user.id, username, usernameLower: username, displayName: username, email: user.email, photoURL: '', bio: '', streakIcon: '🔥', streakCount: 0, longestStreak: 0, totalVerifiedStudyMinutes: 0, createdAt: now, updatedAt: now, termsAccepted: Boolean(user.termsAccepted), termsAcceptedAt: user.termsAcceptedAt || '', privacyAccepted: Boolean(user.privacyAccepted), privacyAcceptedAt: user.privacyAcceptedAt || ''};
  db.profiles.push(profile);
  return profile;
};
const getAuth = req => {
  const token = (req.headers.authorization || '').replace(/^Bearer /, '');
  const payload = verifySession(token);
  if (!payload) return {error: 'Oturum gecersiz veya suresi dolmus.'};
  const db = readDb();
  const user = db.users.find(item => item.id === payload.sub);
  return user ? {db, user, token} : {error: 'Hesap bulunamadi.'};
};
const createVerificationLink = user => {
  user.verificationToken = crypto.randomBytes(32).toString('hex');
  user.verificationExpiresAt = new Date(Date.now() + 86400000).toISOString();
  return `${PUBLIC_BASE_URL}/auth/verify?token=${user.verificationToken}`;
};
const createTransport = () => {
  const missing = ['SMTP_HOST', 'SMTP_PORT', 'SMTP_USER', 'SMTP_PASS', 'SMTP_FROM'].filter(key => !process.env[key]);
  if (missing.length) throw new Error(`SMTP ayari eksik: ${missing.join(', ')}`);
  return nodemailer.createTransport({host: process.env.SMTP_HOST, port: Number(process.env.SMTP_PORT), secure: process.env.SMTP_SECURE === 'true', auth: {user: process.env.SMTP_USER, pass: process.env.SMTP_PASS}});
};
const sendVerification = async (email, link) => {
  await createTransport().sendMail({from: process.env.SMTP_FROM, to: email, subject: 'Streakify e-posta dogrulama', text: `Hesabini dogrulamak icin tikla: ${link}`, html: `<p>Streakify hesabini aktifleştirmek icin baglantiya tikla.</p><p><a href="${link}">E-postami dogrula</a></p>`});
};
const html = (res, title, text) => { res.writeHead(200, {'Content-Type': 'text/html; charset=utf-8'}); res.end(`<!doctype html><html lang="tr"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${title}</title><body style="font-family:Arial;background:#fff8ec;color:#1e293b;padding:32px;line-height:1.6"><main style="max-width:820px;margin:auto;background:white;border-radius:18px;padding:24px"><h1 style="color:#e8590c">${title}</h1><p>${text}</p><p>Bu metin genel bilgilendirme taslagidir; yasal danismanlik degildir.</p></main></body></html>`); };

async function register(req, res) {
  const input = await readBody(req);
  const email = normalizeEmail(input.email);
  const password = String(input.password || '');
  if (!validEmail(email)) return json(res, 400, {message: 'Gecerli bir e-posta adresi yaz.'});
  if (!validPassword(password)) return json(res, 400, {message: 'Sifre en az 8 karakter olmali, harf ve rakam icermeli.'});
  const db = readDb();
  let user = db.users.find(item => item.email === email);
  if (user?.emailVerified) return json(res, 409, {message: 'Bu e-posta ile kayitli dogrulanmis bir hesap var.'});
  user = user || {id: crypto.randomUUID(), email, createdAt: new Date().toISOString(), emailVerified: false};
  user.passwordHash = await hashPassword(password);
  user.termsAccepted = Boolean(input.termsAccepted);
  user.termsAcceptedAt = input.termsAcceptedAt || null;
  user.privacyAccepted = Boolean(input.privacyAccepted);
  user.privacyAcceptedAt = input.privacyAcceptedAt || null;
  user.updatedAt = new Date().toISOString();
  const link = createVerificationLink(user);
  if (!db.users.some(item => item.id === user.id)) db.users.push(user);
  writeDb(db);
  await sendVerification(email, link);
  return json(res, 201, {message: 'Dogrulama maili gonderildi. Giris yapmadan once e-postani dogrula.', user: publicUser(user)});
}
async function login(req, res) {
  const input = await readBody(req);
  const db = readDb();
  const user = db.users.find(item => item.email === normalizeEmail(input.email));
  if (!user || !(await verifyPassword(String(input.password || ''), user.passwordHash))) return json(res, 401, {message: 'E-posta veya sifre hatali.'});
  if (!user.emailVerified) return json(res, 403, {message: 'E-postan dogrulanmadi. Lutfen dogrulama mailindeki baglantiya tikla.'});
  return json(res, 200, {message: 'Giris basarili.', session: {token: signSession(user), user: publicUser(user)}});
}
async function resend(req, res) {
  const input = await readBody(req);
  const db = readDb();
  const user = db.users.find(item => item.email === normalizeEmail(input.email));
  if (!user) return json(res, 404, {message: 'Bu e-posta ile kayitli hesap bulunamadi.'});
  if (user.emailVerified) return json(res, 200, {message: 'Bu hesap zaten dogrulanmis.'});
  const link = createVerificationLink(user);
  writeDb(db);
  await sendVerification(user.email, link);
  return json(res, 200, {message: 'Yeni dogrulama maili gonderildi.'});
}
function verifyEmail(req, res) {
  const token = new URL(req.url, PUBLIC_BASE_URL).searchParams.get('token');
  const db = readDb();
  const user = db.users.find(item => item.verificationToken === token);
  if (!user || new Date(user.verificationExpiresAt).getTime() < Date.now()) { res.writeHead(400, {'Content-Type': 'text/html; charset=utf-8'}); return res.end('<h1>Dogrulama baglantisi gecersiz veya suresi dolmus.</h1>'); }
  user.emailVerified = true;
  user.verificationToken = null;
  user.verificationExpiresAt = null;
  user.updatedAt = new Date().toISOString();
  writeDb(db);
  res.writeHead(200, {'Content-Type': 'text/html; charset=utf-8'});
  return res.end('<h1>E-posta dogrulandi.</h1><p>Artik Streakify uygulamasina giris yapabilirsin.</p>');
}
function me(req, res) { const auth = getAuth(req); if (auth.error) return json(res, 401, {message: auth.error}); return json(res, 200, {token: auth.token, user: publicUser(auth.user)}); }
function profiles(req, res) { const auth = getAuth(req); if (auth.error) return json(res, 401, {message: auth.error}); ensureProfile(auth.db, auth.user); writeDb(auth.db); return json(res, 200, auth.db.profiles); }
async function myProfile(req, res) {
  const auth = getAuth(req); if (auth.error) return json(res, 401, {message: auth.error});
  const profile = ensureProfile(auth.db, auth.user);
  if (req.method === 'GET') { writeDb(auth.db); return json(res, 200, profile); }
  const input = await readBody(req);
  if (input.username) {
    const username = normalizeUsername(input.username);
    if (!/^[a-z0-9_]{3,20}$/.test(username)) return json(res, 400, {message: 'Kullanici adi 3-20 karakter olmali; harf, rakam ve alt cizgi kullan.'});
    if (auth.db.profiles.some(item => item.uid !== profile.uid && item.usernameLower === username)) return json(res, 409, {message: 'Bu kullanici adi zaten kullaniliyor.'});
    profile.username = username; profile.usernameLower = username;
  }
  profile.displayName = String(input.displayName || profile.displayName).slice(0, 60);
  profile.bio = String(input.bio || '').slice(0, 240);
  profile.photoURL = String(input.photoURL || '');
  profile.streakIcon = String(input.streakIcon || profile.streakIcon || '🔥').slice(0, 4);
  profile.updatedAt = new Date().toISOString();
  writeDb(auth.db);
  return json(res, 200, profile);
}

const server = http.createServer(async (req, res) => {
  try {
    if (req.method === 'OPTIONS') { res.writeHead(204, HEADERS); return res.end(); }
    if (req.method === 'GET' && req.url === '/health') return json(res, 200, {status: 'ok', service: 'streakify-auth'});
    if (req.method === 'GET' && req.url === '/terms') return html(res, 'Kullanici Sozlesmesi', 'Streakify calisma plani, motivasyon, streak, profil, arkadas ve mesajlasma ozellikleri sunar. Kullanici hesabi ve uygulama kullanimindan sorumludur.');
    if (req.method === 'GET' && req.url === '/privacy') return html(res, 'Gizlilik Politikasi', 'Streakify e-posta, profil, calisma plani, streak, arkadaslik ve mesaj verilerini uygulama ozelliklerini calistirmak icin isleyebilir. Sifreler duz metin saklanmaz.');
    if (req.method === 'POST' && req.url === '/auth/register') return await register(req, res);
    if (req.method === 'POST' && req.url === '/auth/login') return await login(req, res);
    if (req.method === 'POST' && req.url === '/auth/resend-verification') return await resend(req, res);
    if (req.method === 'GET' && req.url.startsWith('/auth/verify')) return verifyEmail(req, res);
    if (req.method === 'GET' && req.url === '/auth/me') return me(req, res);
    if (req.method === 'GET' && req.url === '/profiles') return profiles(req, res);
    if ((req.method === 'GET' || req.method === 'PUT') && req.url === '/profiles/me') return await myProfile(req, res);
    return json(res, 404, {message: 'Endpoint bulunamadi.'});
  } catch (error) {
    console.error('request error', error);
    return json(res, 500, {message: error instanceof Error ? error.message : 'Sunucu hatasi.'});
  }
});
server.listen(PORT, () => console.log(`Auth server listening on ${PUBLIC_BASE_URL}`));
