// 认证与安全辅助模块
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');
const db = require('./db');

const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(48).toString('hex');
const TOKEN_TTL = '7d';

if (!process.env.JWT_SECRET) {
  console.warn('[安全警告] 未设置 JWT_SECRET 环境变量，重启后所有登录状态将失效。生产环境请在 .env / systemd 中设置。');
}

function signToken(user) {
  return jwt.sign({ uid: user.id, role: user.role }, JWT_SECRET, { expiresIn: TOKEN_TTL });
}

function hashPassword(pw) {
  return bcrypt.hashSync(pw, 10);
}

function verifyPassword(pw, hash) {
  return bcrypt.compareSync(pw, hash);
}

// JWT 中间件：可选登录（游客可浏览）
function optionalAuth(req, _res, next) {
  const token = req.cookies ? req.cookies.token : null;
  if (token) {
    try {
      const payload = jwt.verify(token, JWT_SECRET);
      // 已封禁用户即使持有有效 token 也视为未登录（封禁立即生效）
      const row = db.prepare('SELECT banned, banned_until, role FROM users WHERE id = ?').get(payload.uid);
      if (row) {
        // 封禁已过期则自动解封（best-effort，避免永久卡死）
        if (row.banned && row.banned_until != null && row.banned_until <= Date.now()) {
          try { db.prepare('UPDATE users SET banned = 0, banned_from = NULL, banned_until = NULL WHERE id = ?').run(payload.uid); } catch (_) {}
          row.banned = 0;
        }
        // 仅当处于有效封禁期内才视为未登录
        const activeBan = row.banned && (row.banned_until == null || row.banned_until > Date.now());
        if (!activeBan) req.user = { id: payload.uid, role: row.role };
      }
    } catch (_) { /* 无效 token 视为未登录 */ }
  }
  next();
}

// 必须登录
function requireAuth(req, res, next) {
  if (!req.user) return res.status(401).json({ error: '请先登录' });
  next();
}

// 必须管理员
function requireAdmin(req, res, next) {
  if (!req.user) return res.status(401).json({ error: '请先登录' });
  if (req.user.role !== 'admin' && req.user.role !== 'owner') return res.status(403).json({ error: '需要管理员权限' });
  next();
}

// 必须站长（owner）；其余角色一律拒绝
function requireOwner(req, res, next) {
  if (!req.user) return res.status(401).json({ error: '请先登录' });
  if (req.user.role !== 'owner') return res.status(403).json({ error: '需要站长权限' });
  next();
}

function isOwner(u) { return !!u && u.role === 'owner'; }
function isCollaborator(u) { return !!u && u.role === 'collaborator'; }

// CSRF 防护：校验自定义头（SameSite Cookie + 自定义头双重校验）
function csrfGuard(req, res, next) {
  const safe = ['GET', 'HEAD', 'OPTIONS'];
  if (safe.includes(req.method)) return next();
  if (req.headers['x-requested-with'] !== 'WebOwn') {
    return res.status(403).json({ error: '请求来源校验失败' });
  }
  next();
}

// 登录失败锁定（内存级，轻量）
const MAX_FAILS = 5;
const LOCK_MS = 15 * 60 * 1000;

function isLocked(ip) {
  const row = db.prepare('SELECT fails, locked_until FROM login_attempts WHERE ip = ?').get(ip);
  if (!row) return false;
  if (row.locked_until && row.locked_until > Date.now()) return true;
  return false;
}

function recordFail(ip) {
  const row = db.prepare('SELECT fails FROM login_attempts WHERE ip = ?').get(ip);
  const fails = (row ? row.fails : 0) + 1;
  const locked = fails >= MAX_FAILS ? Date.now() + LOCK_MS : null;
  db.prepare(
    `INSERT INTO login_attempts (ip, fails, locked_until) VALUES (?, ?, ?)
     ON CONFLICT(ip) DO UPDATE SET fails = excluded.fails, locked_until = excluded.locked_until`
  ).run(ip, fails, locked);
}

function clearFails(ip) {
  db.prepare('DELETE FROM login_attempts WHERE ip = ?').run(ip);
}

// ---------- IP 封禁 ----------
// 统一 IP 写法：::ffff:1.2.3.4（IPv4 映射地址）与 1.2.3.4 视为同一个来源，
// 否则封禁了其中一种写法、请求却以另一种进来，封禁会形同虚设。
function normalizeIp(ip) {
  const s = String(ip == null ? '' : ip).trim();
  return s.startsWith('::ffff:') ? s.slice(7) : s;
}

// 取当前生效的 IP 封禁记录；已到期的顺手清理（避免管理员后台看到过期条目）
function getIpBan(ip) {
  const key = normalizeIp(ip);
  if (!key) return null;
  let row = null;
  try { row = db.prepare('SELECT ip, reason, until FROM ip_bans WHERE ip = ?').get(key); } catch (_) { return null; }
  if (!row) return null;
  if (row.until && row.until <= Date.now()) {
    try { db.prepare('DELETE FROM ip_bans WHERE ip = ?').run(key); } catch (_) {}
    return null;
  }
  return row;
}

// 记录条款同意
function recordConsent(userId, type, req) {
  db.prepare('INSERT INTO consents (user_id, type, ip, user_agent, created_at) VALUES (?, ?, ?, ?, ?)')
    .run(userId || null, type, req.ip || '', (req.headers['user-agent'] || '').slice(0, 300), Date.now());
}

// 简单输入校验
function cleanStr(s, maxLen) {
  if (typeof s !== 'string') return '';
  return s.trim().slice(0, maxLen || 500);
}

// 密码强度：≥8 位，且同时包含大写字母、小写字母、数字（三类）
const PW_RE = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{8,72}$/;
function isStrongPassword(pw) {
  return typeof pw === 'string' && PW_RE.test(pw);
}
function passwordHint() {
  return '密码需 8-72 位，且包含大写字母、小写字母、数字三类';
}

// ---------- 邮箱验证码（内存存储，轻量） ----------
const codes = new Map(); // email(小写) -> { code, expires, lastSent, fails }
const CODE_TTL = 10 * 60 * 1000;       // 10 分钟有效
const RESEND_GAP = 60 * 1000;          // 60 秒后才能重发
const MAX_CODE_FAILS = 5;              // 校验失败上限

function setCode(email, code) {
  codes.set(email.toLowerCase(), { code, expires: Date.now() + CODE_TTL, lastSent: Date.now(), fails: 0 });
}
function canResend(email) {
  const r = codes.get(email.toLowerCase());
  if (!r) return { ok: true };
  if (Date.now() - r.lastSent < RESEND_GAP) return { ok: false, wait: Math.ceil((RESEND_GAP - (Date.now() - r.lastSent)) / 1000) };
  return { ok: true };
}
function verifyCode(email, code) {
  const r = codes.get(email.toLowerCase());
  if (!r) return { ok: false, reason: '请先获取验证码' };
  if (r.fails >= MAX_CODE_FAILS) { codes.delete(email.toLowerCase()); return { ok: false, reason: '验证码错误次数过多，请重新获取' }; }
  if (Date.now() > r.expires) { codes.delete(email.toLowerCase()); return { ok: false, reason: '验证码已过期，请重新获取' }; }
  if (cleanStr(code, 10) !== r.code) { r.fails += 1; return { ok: false, reason: '验证码不正确' }; }
  codes.delete(email.toLowerCase());
  return { ok: true };
}
function cleanupCodes() {
  const now = Date.now();
  for (const [k, v] of codes) if (now > v.expires) codes.delete(k);
}
setInterval(cleanupCodes, 5 * 60 * 1000);

module.exports = {
  signToken, hashPassword, verifyPassword,
  optionalAuth, requireAuth, requireAdmin, requireOwner,
  isOwner, isCollaborator,
  csrfGuard, isLocked, recordFail, clearFails,
  getIpBan, normalizeIp,
  recordConsent, cleanStr, JWT_SECRET,
  isStrongPassword, passwordHint, setCode, canResend, verifyCode,
  audit, safeUrl, maskIp, makeLimiter,
};

// ---------- 审计日志（只追加，读取脱敏） ----------
// 记录操作人/时间/对象/动作/结果/脱敏 IP·UA，禁止编辑删除。
// ip 默认做末段脱敏（隐私合规）；ua 截断至 300。
function maskIp(ip) {
  const s = normalizeIp(ip || '');
  if (!s) return '';
  // IPv4：末段置 0；IPv6 映射地址同样处理；其余保留前缀
  return s.replace(/(\d+)\.(\d+)\.(\d+)\.\d+$/, '$1.$2.$3.*')
          .replace(/([0-9a-f]+):([0-9a-f]+):([0-9a-f]+):[0-9a-f]+$/i, '$1:$2:$3:*');
}

function audit(actorId, role, action, objectType, objectId, detail, ip, ua) {
  try {
    db.prepare(
      `INSERT INTO audit_log (actor_id, role, action, object_type, object_id, detail, ip, ua, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
    ).run(
      actorId || 0, role || '', String(action || ''), objectType ? String(objectType) : null,
      objectId != null ? String(objectId) : null, detail ? JSON.stringify(detail) : null,
      maskIp(ip || ''), (ua || '').slice(0, 300), Date.now()
    );
  } catch (e) {
    console.error('[audit] 写入失败（不影响主流程）：', e.message);
  }
}

// 便捷审计（从 req 提取操作人/IP/UA）
function auditFromReq(req, action, objectType, objectId, detail) {
  const u = req.user || null;
  audit(u ? u.id : 0, u ? u.role : 'guest', action, objectType, objectId, detail, req.ip, req.headers['user-agent'] || '');
}

// ---------- 链接安全 ----------
// 仅允许 http(s) 外链；其余返回空（防 javascript:/data:/钓鱼与开放重定向）。
function safeUrl(u) {
  const s = cleanStr(String(u || ''), 500);
  if (!/^https?:\/\/[a-z0-9.-]+\.[a-z]{2,}(:\d+)?(\/[^\s]*)?$/i.test(s)) return '';
  return s;
}

// 社交链接字段白名单校验：只允许 http(s)，返回安全值或空
function sanitizeSocial(u) { return safeUrl(u); }

// ---------- 限速构造器（按用途复用 express-rate-limit） ----------
// 统一窗口与错误文案；用于签到/兑换/评论/上传/搜索等敏感接口重点限流。
function makeLimiter({ windowMs, max, msg }) {
  return rateLimit({
    windowMs: windowMs || 60 * 1000,
    max: max || 30,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: msg || '操作过于频繁，请稍后再试' },
  });
}
