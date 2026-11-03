// 业务路由：认证、内容、互动
const express = require('express');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');
const db = require('../lib/db');
const {
  signToken, hashPassword, verifyPassword,
  requireAuth, requireAdmin, isLocked, recordFail, clearFails,
  recordConsent, cleanStr, getIpBan, normalizeIp,
  isStrongPassword, passwordHint, setCode, canResend, verifyCode,
  makeLimiter, audit,
} = require('../lib/auth');
const { sendVerifyCode, mailEnabled } = require('../lib/mailer');
const community = require('../lib/community');
const { stripImageMetadata } = require('../lib/image-sanitize');

const router = express.Router();

const TARGET_TYPES = ['article', 'image', 'project'];

// ---------- 工具 ----------
function slugify(title) {
  const base = cleanStr(title, 80)
    .replace(/[^\p{L}\p{N}\s-]/gu, '')
    .replace(/\s+/g, '-')
    .toLowerCase() || 'post';
  return `${base}-${Date.now().toString(36)}`;
}

// 用户信息（含头像）
function publicUser(u) {
  return u ? { id: u.id, username: u.username, email: u.email, role: u.role, created_at: u.created_at, avatar: u.avatar || null } : null;
}

function getUserById(id) {
  return db.prepare('SELECT id, username, email, role, created_at, avatar FROM users WHERE id = ?').get(id);
}

// ---------- 图形验证码（防机器人） ----------
const CAPTCHA_TTL = 5 * 60 * 1000; // 5 分钟有效
const captchaLib = require('../lib/captcha');

// 取一张新验证码：返回 id + svg（id 与答案在服务端关联，答案绝不下发）
router.get('/captcha', (_req, res) => {
  // 顺带清理过期记录，避免表无限增长
  try { db.prepare('DELETE FROM captchas WHERE created_at < ?').run(Date.now() - CAPTCHA_TTL); } catch (_) {}
  const { code, svg } = captchaLib.create();
  const id = crypto.randomBytes(16).toString('hex');
  db.prepare('INSERT INTO captchas (id, code, created_at) VALUES (?, ?, ?)').run(id, code.toUpperCase(), Date.now());
  // 多层防御：禁止浏览器、CDN、Nginx 反代(proxy_cache)缓存该响应。
  // 哪怕前端漏带缓存破坏器，这里也能保证每次都返回全新验证码。
  res.set('Cache-Control', 'no-store, no-cache, must-revalidate, max-age=0, private');
  res.set('Pragma', 'no-cache');
  res.set('Expires', '0');
  res.set('Vary', '*');
  res.json({ id, svg });
});

// 校验并消费验证码（一次性：无论成功失败都删除，防止重放/爆破）
function checkCaptcha(captchaId, captchaText) {
  const id = cleanStr(String(captchaId || ''), 64);
  const input = cleanStr(String(captchaText || ''), 16).toUpperCase();
  if (!id || !input) return { ok: false, error: '请填写图形验证码' };
  const row = db.prepare('SELECT code, created_at FROM captchas WHERE id = ?').get(id);
  if (!row) return { ok: false, error: '图形验证码已失效，请点击图片刷新' };
  // 一次性消费
  db.prepare('DELETE FROM captchas WHERE id = ?').run(id);
  if (Date.now() - row.created_at > CAPTCHA_TTL) return { ok: false, error: '图形验证码已过期，请点击图片刷新' };
  if (row.code !== input) return { ok: false, error: '图形验证码不正确' };
  return { ok: true };
}

// 查询「我」所在 IP 是否被封禁（该接口被 server.js 的 IP 封禁中间件放行，
// 让被封禁的访客能看到封禁原因与解封时间，而不是满屏请求失败）
router.get('/ipban-status', (req, res) => {
  const ban = getIpBan(req.ip);
  res.json({
    banned: !!ban,
    ip: normalizeIp(req.ip),
    until: ban ? (ban.until || null) : null,
    reason: ban ? (ban.reason || '') : '',
  });
});

// ---------- 认证 ----------
// 发送邮箱验证码（注册 / 找回密码共用）
router.post('/auth/send-code', async (req, res) => {
  const mail = cleanStr(req.body && req.body.email, 120).toLowerCase();
  const purpose = cleanStr(req.body && req.body.purpose, 10) === 'reset' ? 'reset' : 'register';
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(mail)) return res.status(400).json({ error: '邮箱格式不正确' });
  // 图形验证码：防止机器人刷邮件（邮箱轰炸）与批量消耗邮件额度
  const cap = checkCaptcha(req.body && req.body.captchaId, req.body && req.body.captcha);
  if (!cap.ok) return res.status(400).json({ error: cap.error });

  const exists = db.prepare('SELECT id FROM users WHERE email = ?').get(mail);
  if (purpose === 'reset' && !exists) return res.status(404).json({ error: '该邮箱尚未注册，请先注册账号' });
  if (purpose === 'register' && exists) return res.status(409).json({ error: '该邮箱已被注册，请直接登录' });

  const gap = canResend(mail);
  if (!gap.ok) return res.status(429).json({ error: `发送过于频繁，请 ${gap.wait} 秒后再试` });
  // 用密码学安全的随机数生成 6 位验证码（避免 Math.random 可预测带来的暴力风险）
  const code = String(crypto.randomInt(100000, 1000000));
  setCode(mail, code);
  try {
    const r = await sendVerifyCode(mail, code, purpose);
    res.json({ ok: true, dev: r.dev, devCode: r.dev ? code : undefined, message: r.dev ? '开发模式：验证码已输出到服务器控制台' : '验证码已发送至邮箱' });
  } catch (e) {
    console.error('[邮件发送失败]', e.message);
    res.status(502).json({ error: '验证码邮件发送失败，请稍后再试或联系站长' });
  }
});

// 找回密码：邮箱验证码 + 新密码
router.post('/auth/reset-password', (req, res) => {
  const { email, code, password } = req.body || {};
  const mail = cleanStr(email, 120).toLowerCase();
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(mail)) return res.status(400).json({ error: '邮箱格式不正确' });
  if (!isStrongPassword(password)) return res.status(400).json({ error: passwordHint() });

  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(mail);
  if (!user) return res.status(404).json({ error: '该邮箱尚未注册' });

  const v = verifyCode(mail, code);
  if (!v.ok) return res.status(400).json({ error: v.reason });

  db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(hashPassword(password), user.id);
  console.log(`[安全] 用户 ${user.username}(${mail}) 通过邮箱验证码重置了密码`);
  res.json({ ok: true, message: '密码已重置，请用新密码登录' });
});

router.post('/auth/register', (req, res) => {
  const { username, email, password, agree } = req.body || {};
  if (!agree) return res.status(400).json({ error: '必须同意服务条款与隐私政策' });
  // 先过图形验证码，挡下批量注册的机器人
  const cap = checkCaptcha(req.body && req.body.captchaId, req.body && req.body.captcha);
  if (!cap.ok) return res.status(400).json({ error: cap.error });
  const name = cleanStr(username, 32);
  const mail = cleanStr(email, 120).toLowerCase();
  if (!/^[a-zA-Z0-9_\u4e00-\u9fa5]{2,32}$/.test(name)) return res.status(400).json({ error: '用户名需为 2-32 位字母/数字/下划线/中文' });
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(mail)) return res.status(400).json({ error: '邮箱格式不正确' });
  if (!isStrongPassword(password)) return res.status(400).json({ error: passwordHint() });
  const v = verifyCode(mail, req.body.code);
  if (!v.ok) return res.status(400).json({ error: v.reason });

  const exists = db.prepare('SELECT id FROM users WHERE username_lower = ? OR email = ? COLLATE NOCASE').get(name.toLowerCase(), mail);
  if (exists) return res.status(409).json({ error: '用户名或邮箱已被注册' });

  // 首个注册的用户自动成为管理员
  const userCount = db.prepare('SELECT COUNT(*) c FROM users').get().c;
  const role = userCount === 0 ? 'admin' : 'user';

  const info = db.prepare('INSERT INTO users (username, username_lower, email, password_hash, role, created_at, last_ip) VALUES (?, ?, ?, ?, ?, ?, ?)')
    .run(name, name.toLowerCase(), mail, hashPassword(password), role, Date.now(), normalizeIp(req.ip));
  recordConsent(info.lastInsertRowid, 'register', req);
  const user = getUserById(info.lastInsertRowid);
  res.cookie('token', signToken(user), cookieOpts(req)).status(201).json({ user: publicUser(user) });
});

router.post('/auth/login', (req, res) => {
  const ip = req.ip || 'unknown';
  if (isLocked(ip)) return res.status(429).json({ error: '失败次数过多，请 15 分钟后再试' });
  const { username, password, remember } = req.body || {};
  // 先过图形验证码：机器人在这步就被挡下，不消耗密码校验与失败计数
  const cap = checkCaptcha(req.body && req.body.captchaId, req.body && req.body.captcha);
  if (!cap.ok) return res.status(400).json({ error: cap.error });
  const key = cleanStr(username, 120);
  const user = db.prepare('SELECT * FROM users WHERE username_lower = ? OR email = ? COLLATE NOCASE').get(key.toLowerCase(), key.toLowerCase());
  if (!user || !verifyPassword(String(password || ''), user.password_hash)) {
    recordFail(ip);
    return res.status(401).json({ error: '用户名或密码错误' });
  }
  if (user.banned) return res.status(403).json({ error: '该账号已被封禁，如有疑问请联系站长' });
  clearFails(ip);
  // 记录本次登录 IP；把旧的 last_login_at 挪到 prev_login_at，供「久未登录」回归用户判断
  db.prepare('UPDATE users SET last_login_at = ?, prev_login_at = ?, last_ip = ? WHERE id = ?')
    .run(Date.now(), user.last_login_at || null, normalizeIp(ip), user.id);
  recordConsent(user.id, 'login', req);
  res.cookie('token', signToken(user), cookieOpts(req, !!remember)).json({ user: publicUser(user) });
});

router.post('/auth/logout', (req, res) => {
  // 同时清退「Secure 版」与「非 Secure 版」两种 token Cookie：
  // 登录时 Cookie 的 secure 属性取决于当时请求协议/代理，若只清退一种，另一种可能删不掉，
  // 导致"前端显示已登出、Cookie 仍在、刷新又被认回"的幽灵态半登出。两条都清最稳妥。
  const opts = { httpOnly: true, sameSite: 'lax', path: '/' };
  res.clearCookie('token', { ...opts, secure: true });
  res.clearCookie('token', { ...opts, secure: false });
  res.json({ ok: true });
});

router.get('/auth/me', (req, res) => {
  if (!req.user) return res.json({ user: null });
  res.json({ user: publicUser(getUserById(req.user.id)) });
});

function cookieOpts(req, remember) {
  // secure 跟随真实请求协议：反代 http 时不标 Secure（否则 http 下登录 Cookie 不发送导致登录失效）；反代 https 时自动 Secure。
  // 同时兼容 SSL=1 的部署（即便代理未正确传递 X-Forwarded-Proto，也强制 Secure 以配合 HSTS）。
  // remember=true（勾选"自动登录"）时延长登录态至 30 天，否则默认 7 天
  return {
    httpOnly: true,
    sameSite: 'lax',
    secure: !!((req && req.secure) || process.env.SSL === '1'),
    maxAge: (remember ? 30 : 7) * 24 * 3600 * 1000,
    path: '/',
  };
}

// ---------- 社交媒体动态（公开读取） ----------
router.get('/social', (_req, res) => {
  const rows = db.prepare(
    "SELECT id, platform, title, url, cover, description, created_at FROM social_posts WHERE status = 'published' ORDER BY created_at DESC LIMIT 60"
  ).all();
  res.json({ items: rows });
});

// 站点设置（公开读取，键白名单）
const PUBLIC_SETTINGS = ['site_name', 'site_slogan', 'footer_text', 'icp', 'sponsor_qr'];
router.get('/settings', (_req, res) => {
  const rows = db.prepare('SELECT key, value FROM settings').all();
  const out = {};
  for (const k of PUBLIC_SETTINGS) out[k] = '';
  for (const r of rows) if (PUBLIC_SETTINGS.includes(r.key)) out[r.key] = r.value || '';
  res.json(out);
});

// ---------- 站点私有资源受控访问（按 kind，禁止按文件名枚举） ----------
// 赞助二维码等站点级私有资源存放于 data/private/，不暴露真实文件名、不被静态托管。
// 只接受白名单内的 kind，且为单一已知资源 → 无可枚举面。公开可读（赞助墙需展示）。
const PRIVATE_DIR = path.join(__dirname, '..', 'data', 'private');
const ASSET_CT = { '.png': 'image/png', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.gif': 'image/gif', '.webp': 'image/webp', '.avif': 'image/avif' };
const PUBLIC_ASSET_KINDS = ['sponsor-qr'];
router.get('/asset/:kind', (req, res) => {
  const kind = cleanStr(req.params.kind, 40);
  if (!PUBLIC_ASSET_KINDS.includes(kind)) return res.status(404).json({ error: '资源不存在' });
  const row = db.prepare('SELECT filename FROM site_assets WHERE kind = ?').get(kind);
  if (!row || !row.filename) return res.status(404).json({ error: '资源未配置' });
  const fp = path.join(PRIVATE_DIR, row.filename);
  // 防路径遍历：解析后必须仍在 PRIVATE_DIR 内
  if (!fp.startsWith(PRIVATE_DIR + path.sep) && fp !== PRIVATE_DIR) return res.status(400).json({ error: '非法路径' });
  if (!fs.existsSync(fp)) return res.status(404).json({ error: '资源文件缺失' });
  const ext = path.extname(fp).toLowerCase();
  res.set('Content-Type', ASSET_CT[ext] || 'application/octet-stream');
  res.set('Cache-Control', 'no-store');
  res.sendFile(fp);
});

// 条款同意上报（游客首次访问）
router.post('/consent', (req, res) => {
  recordConsent(req.user ? req.user.id : null, 'visit', req);
  res.json({ ok: true });
});

// ---------- 内容读取（公开） ----------
router.get('/articles', (req, res) => {
  const page = Math.max(1, parseInt(req.query.page) || 1);
  const size = Math.min(50, Math.max(1, parseInt(req.query.size) || 10));
  // 管理员可传 status=all 查看全部（含草稿），其余一律只看已发布
  const all = req.query.status === 'all' && req.user && req.user.role === 'admin';
  const where = all ? '' : "WHERE status = 'published'";
  const total = db.prepare(`SELECT COUNT(*) c FROM articles ${where}`).get().c;
  const rows = db.prepare(
    `SELECT id, title, slug, summary, cover, tags, views, status, created_at, updated_at
     FROM articles ${where} ORDER BY created_at DESC LIMIT ? OFFSET ?`
  ).all(size, (page - 1) * size);
  res.json({ total, page, size, items: rows });
});

router.get('/articles/:slug', (req, res) => {
  const art = db.prepare("SELECT * FROM articles WHERE slug = ? AND status = 'published'").get(req.params.slug);
  if (!art) return res.status(404).json({ error: '文章不存在' });
  db.prepare('UPDATE articles SET views = views + 1 WHERE id = ?').run(art.id);
  if (req.user) community.recordBrowse(req.user.id, 'article', art.id);
  const counts = countsFor('article', art.id);
  res.json({ article: art, ...counts });
});

router.get('/images', (req, res) => {
  const page = Math.max(1, parseInt(req.query.page) || 1);
  const size = Math.min(36, Math.max(1, parseInt(req.query.size) || 12));
  // 站长后台（status=all）可看到被隐藏的图；前台一律只展示未隐藏的图。
  // 同时排除与「站点私有资源」（赞助二维码等）同名的记录，杜绝用途性图片流入图库。
  const isAdminAll = req.query.status === 'all' && req.user && (req.user.role === 'admin' || req.user.role === 'owner');
  const where = isAdminAll
    ? ''
    : "WHERE hidden = 0 AND filename NOT IN (SELECT filename FROM site_assets)";
  const total = db.prepare(`SELECT COUNT(*) c FROM images ${where}`).get().c;
  const rows = db.prepare(`SELECT id, filename, original_name, title, description, views, created_at, hidden FROM images ${where} ORDER BY created_at DESC LIMIT ? OFFSET ?`)
    .all(size, (page - 1) * size);
  res.json({ total, page, size, items: rows });
});

// 图片详情：自增浏览数 + 互动统计（点赞/收藏/评论/分享走通用互动表）
router.get('/images/:id', (req, res) => {
  const id = parseInt(req.params.id) || 0;
  const im = db.prepare('SELECT * FROM images WHERE id = ?').get(id);
  if (!im) return res.status(404).json({ error: '图片不存在' });
  db.prepare('UPDATE images SET views = views + 1 WHERE id = ?').run(id);
  if (req.user) community.recordBrowse(req.user.id, 'image', id);
  im.views = (im.views || 0) + 1;
  const counts = countsFor('image', id);
  res.json({ image: im, ...counts });
});

router.get('/projects', (_req, res) => {
  // 列表直接返回全部列（含 views / icon / readme 缓存），供前台卡片展示图标与浏览数
  res.json({ items: db.prepare('SELECT * FROM projects ORDER BY created_at DESC').all() });
});

// 项目详情：自增浏览数 + 互动统计；README 走独立接口异步加载（避免阻塞首屏）
router.get('/projects/:id', (req, res) => {
  const id = parseInt(req.params.id) || 0;
  const p = db.prepare('SELECT * FROM projects WHERE id = ?').get(id);
  if (!p) return res.status(404).json({ error: '项目不存在' });
  db.prepare('UPDATE projects SET views = views + 1 WHERE id = ?').run(id);
  if (req.user) community.recordBrowse(req.user.id, 'project', id);
  p.views = (p.views || 0) + 1;
  const counts = countsFor('project', id);
  res.json({ project: p, readme: p.readme || '', ...counts });
});

// 单独拉取 GitHub README（带服务端缓存）：前端详情页渲染后再异步填充，避免阻塞首屏
router.get('/projects/:id/readme', async (req, res) => {
  const id = parseInt(req.params.id) || 0;
  const p = db.prepare('SELECT * FROM projects WHERE id = ?').get(id);
  if (!p) return res.status(404).json({ error: '项目不存在' });
  const readme = await fetchReadme(p);
  res.json({ readme: readme || '' });
});

// GitHub 仓库元数据（Star/Fork/语言/贡献者/Release/文件列表等）：同样异步加载，不阻塞首屏
router.get('/projects/:id/github', async (req, res) => {
  const id = parseInt(req.params.id) || 0;
  const p = db.prepare('SELECT * FROM projects WHERE id = ?').get(id);
  if (!p) return res.status(404).json({ error: '项目不存在' });
  const meta = await fetchGithubMeta(p);
  res.json({ meta: meta || null });
});

router.get('/sponsors', (_req, res) => {
  res.json({ items: db.prepare('SELECT id, name, amount, message, created_at FROM sponsors ORDER BY created_at DESC LIMIT 50').all() });
});

// ---------- 站内搜索（跨文章 / 图片 / 项目 / 动态 / 公告） ----------
// 分类 type：all | article | image | project | social | announcement；关键词做子串匹配。
// 全部走参数化 LIKE，并转义 % 与 _，避免把用户输入当成通配符；ESCAPE 统一用反斜杠。
function likeEsc(s) {
  return String(s || '').replace(/[\\%_]/g, (c) => '\\' + c);
}
// 把 Markdown 粗浅转成纯文本（公告正文做搜索摘要用，避免卡片里冒出 #/* 等符号）
function mdPlain(s) {
  return String(s || '')
    .replace(/```[\s\S]*?```/g, ' ')
    .replace(/`([^`]*)`/g, '$1')
    .replace(/!\[[^\]]*\]\([^)]*\)/g, ' ')
    .replace(/\[([^\]]*)\]\([^)]*\)/g, '$1')
    .replace(/^#{1,6}\s*/gm, '')
    .replace(/[*_~]{1,3}/g, '')
    .replace(/^\s*[-*+]\s+/gm, '')
    .replace(/\s+/g, ' ')
    .trim();
}
router.get('/search', (req, res) => {
  const q = cleanStr(req.query.q, 80);
  const type = ['article', 'image', 'project', 'social', 'announcement', 'user'].includes(req.query.type) ? req.query.type : 'all';
  if (!q) return res.json({ q: '', type, total: 0, items: [] });

  const kw = `%${likeEsc(q)}%`;
  const LIMIT = 60;
  const items = [];
  const push = (type, id, o) => items.push({ type, id, ...o });

  if (type === 'all' || type === 'article') {
    db.prepare(
      `SELECT id, title, slug, summary, cover, tags, views, created_at
       FROM articles WHERE status = 'published'
       AND (title LIKE ? ESCAPE '\\' OR summary LIKE ? ESCAPE '\\' OR tags LIKE ? ESCAPE '\\' OR content LIKE ? ESCAPE '\\')
       ORDER BY created_at DESC LIMIT ?`
    ).all(kw, kw, kw, kw, LIMIT).forEach((r) => push('article', r.id, {
      title: r.title, summary: r.summary, cover: r.cover, tags: r.tags, views: r.views, href: `#/article/${r.slug}`,
    }));
  }
  if (type === 'all' || type === 'image') {
    db.prepare(
      `SELECT id, title, description, filename, views, created_at FROM images
       WHERE hidden = 0 AND (title LIKE ? ESCAPE '\\' OR description LIKE ? ESCAPE '\\')
       ORDER BY created_at DESC LIMIT ?`
    ).all(kw, kw, LIMIT).forEach((r) => push('image', r.id, {
      title: r.title || '', summary: r.description || '', cover: `/uploads/${r.filename}`, views: r.views, href: `#/image/${r.id}`,
    }));
  }
  if (type === 'all' || type === 'project') {
    db.prepare(
      `SELECT id, title, description, repo_url, icon, tags, views, created_at FROM projects
       WHERE title LIKE ? ESCAPE '\\' OR description LIKE ? ESCAPE '\\' OR tags LIKE ? ESCAPE '\\'
       ORDER BY created_at DESC LIMIT ?`
    ).all(kw, kw, kw, LIMIT).forEach((r) => push('project', r.id, {
      title: r.title, summary: r.description || '', icon: r.icon, tags: r.tags, views: r.views, href: `#/project/${r.id}`,
    }));
  }
  if (type === 'all' || type === 'social') {
    db.prepare(
      `SELECT id, title, description, cover, url, created_at FROM social_posts
       WHERE status = 'published' AND (title LIKE ? ESCAPE '\\' OR description LIKE ? ESCAPE '\\')
       ORDER BY created_at DESC LIMIT ?`
    ).all(kw, kw, LIMIT).forEach((r) => push('social', r.id, {
      title: r.title, summary: r.description || '', cover: r.cover, href: r.url,
    }));
  }
  if (type === 'all' || type === 'announcement') {
    db.prepare(
      `SELECT id, title, content, tag, pinned, created_at FROM announcements
       WHERE title LIKE ? ESCAPE '\\' OR content LIKE ? ESCAPE '\\'
       ORDER BY pinned DESC, created_at DESC LIMIT ?`
    ).all(kw, kw, LIMIT).forEach((r) => push('announcement', r.id, {
      title: r.title, summary: mdPlain(r.content), href: `#/announcements`,
    }));
  }
  if (type === 'all' || type === 'user') {
    // 用户搜索：仅收录「主页已公开」且未封禁的用户（最小可见：默认不公开，避免枚举隐私）
    db.prepare(
      `SELECT id, username, avatar, level, xp FROM users
       WHERE banned = 0 AND username_lower LIKE ? ESCAPE '\\'
       ORDER BY xp DESC, created_at DESC LIMIT ?`
    ).all(kw, LIMIT).forEach((u) => {
      const p = community.getPrivacy(u.id);
      if (!p.profile) return;
      const td = p.title ? community.titleDisplay(u.id, null) : { name: null, icon: '', color: null };
      const lv = community.levelForXp(u.xp || 0); // 等级与主页同源推导，避免脏 level 导致排序/配色失真
      push('user', u.id, {
        title: u.username, summary: '',
        cover: u.avatar ? `/uploads/${u.avatar}` : '',
        level: p.level ? lv : null,
        level_color: p.level ? community.getLevelColor(lv) : null,
        title: td.name, title_icon: td.icon, title_color: td.color,
        href: `#/user/${u.id}`,
      });
    });
  }

  res.json({ q, type, total: items.length, items });
});

router.get('/terms', (_req, res) => {
  const row = db.prepare("SELECT value FROM settings WHERE key = 'terms'").get();
  res.json({ content: row ? row.value : '' });
});

// ---------- 公告（公开读取 + 登录弹窗提醒） ----------
// 标签白名单（与前端 ANNOUNCE_TAGS 对齐）
const ANNOUNCE_TAGS = ['update', 'maintenance', 'action', 'important', 'event', 'other'];
function publicAnnouncement(a) {
  return { id: a.id, title: a.title, content: a.content, tag: a.tag, pinned: !!a.pinned, created_at: a.created_at, updated_at: a.updated_at };
}

// 公告列表（公开）：置顶优先，其次按发布时间倒序
router.get('/announcements', (_req, res) => {
  const rows = db.prepare('SELECT * FROM announcements ORDER BY pinned DESC, created_at DESC').all();
  res.json({ items: rows.map(publicAnnouncement) });
});

// 登录后弹窗提醒：返回"需要展示给当前用户"的置顶公告。
// 规则：新用户（注册 ≤7 天）或久未登录（上次登录距今 >30 天）→ 全部置顶公告都弹；
//       其他用户 → 只弹自己还没读过的置顶公告。
router.get('/announcements/popup', requireAuth, (req, res) => {
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);
  if (!user) return res.json({ items: [], isNew: false, isReturning: false });
  const now = Date.now();
  const DAY = 24 * 3600 * 1000;
  const isNew = !!(user.created_at && (now - user.created_at) <= 7 * DAY);
  // 首次登录或很久没来：prev_login_at 为空(首次) 或距今超 30 天
  const isReturning = !user.prev_login_at || (now - user.prev_login_at) > 30 * DAY;

  const pinned = db.prepare('SELECT * FROM announcements WHERE pinned = 1 ORDER BY created_at DESC').all();
  let items;
  if (isNew || isReturning) {
    items = pinned;
  } else {
    const readAt = user.ann_read_at || 0;
    items = pinned.filter((a) => a.created_at > readAt);
  }
  res.json({ items: items.map(publicAnnouncement), isNew, isReturning });
});

// 标记已读（点弹窗「知道了」后调用）：把已读时间推进到当前
router.post('/announcements/read', requireAuth, (req, res) => {
  db.prepare('UPDATE users SET ann_read_at = ? WHERE id = ?').run(Date.now(), req.user.id);
  res.json({ ok: true });
});

// 互动统计（给详情页复用）
function countsFor(type, id) {
  const likes = db.prepare('SELECT COUNT(*) c FROM likes WHERE target_type = ? AND target_id = ?').get(type, id).c;
  const comments = db.prepare("SELECT COUNT(*) c FROM comments WHERE target_type = ? AND target_id = ? AND status = 'visible'").get(type, id).c;
  const favorites = db.prepare('SELECT COUNT(*) c FROM favorites WHERE target_type = ? AND target_id = ?').get(type, id).c;
  const shares = db.prepare('SELECT COUNT(*) c FROM shares WHERE target_type = ? AND target_id = ?').get(type, id).c;
  return { likes, comments, favorites, shares };
}

// 从 GitHub 仓库地址解析 owner / repo（POST/PUT 已校验过形如 https://github.com/user/repo）
// 注意：协议部分必须显式写出 `https?://`——早期版本用 `[^\s:]+` 匹配协议，
// 而 [^\s:] 不包含冒号，永远跨不过 "https:" 里的冒号，导致所有地址都解析失败、
// README/元数据静默降级。这里用锚定的 https?://。
function parseGithubRepo(url) {
  const m = /^https?:\/\/(?:www\.)?github\.com\/([\w.-]+)\/([\w.-]+?)(?:\.git)?\/?$/i.exec(url || '');
  if (!m) return null;
  return { owner: m[1], repo: m[2] };
}

// 服务端拉取 GitHub README 并缓存（避免浏览器跨域 + 复用，降低 GitHub API 速率限制压力）
// 失败/限流时优雅兜底：返回已缓存的 readme 或项目自身 description，绝不抛错中断详情页。
async function fetchReadme(p) {
  // 24h 内已成功拉取且有内容则直接复用缓存
  const CACHE_TTL = 24 * 3600 * 1000;
  if (p.readme_fetched_at && Date.now() - p.readme_fetched_at < CACHE_TTL && p.readme) {
    return p.readme || '';
  }
  const repo = parseGithubRepo(p.repo_url);
  if (!repo) return p.readme || p.description || '';
  let md = p.readme || '';
  try {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), 8000);
    const resp = await fetch(`https://api.github.com/repos/${encodeURIComponent(repo.owner)}/${encodeURIComponent(repo.repo)}/readme`, {
      headers: { 'User-Agent': 'WebOwn', Accept: 'application/vnd.github+json' },
      signal: ctrl.signal,
    });
    clearTimeout(timer);
    if (resp.ok) {
      const data = await resp.json();
      if (data && data.content && data.encoding === 'base64') {
        md = Buffer.from(data.content, 'base64').toString('utf8');
      } else if (data && data.download_url) {
        const r2 = await fetch(data.download_url, { signal: ctrl.signal });
        if (r2.ok) md = await r2.text();
      }
    }
  } catch (_) {
    // 网络/限流/超时：保留已有缓存或降级到 description
  }
  // 截断超长 README，避免一次性渲染卡顿（数据库仍存全量，只是接口返回做长度保护）
  const safe = (md || '').slice(0, 80000);
  try {
    db.prepare('UPDATE projects SET readme = ?, readme_fetched_at = ? WHERE id = ?').run(safe, Date.now(), p.id);
  } catch (_) {}
  return safe || p.description || '';
}

// 统一走 GitHub API 的 JSON 请求：带超时、可选 token 提额（未配置也能用，只是速率限制低），失败一律返回 null
async function githubJson(path) {
  const token = process.env.GITHUB_TOKEN || '';
  const headers = {
    'User-Agent': 'WebOwn',
    Accept: 'application/vnd.github+json',
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
  };
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), 8000);
  try {
    const r = await fetch(`https://api.github.com${path}`, { headers, signal: ctrl.signal });
    clearTimeout(timer);
    if (!r.ok) return null;
    return await r.json();
  } catch (_) {
    clearTimeout(timer);
    return null;
  }
}

// 聚合 GitHub 仓库元数据：并行拉取后整段 JSON 缓存（默认 6 小时，避开 60 次/小时 的匿名限额）
// 任何单项失败都不影响整体，缺失字段前端会自动隐藏对应区块，绝不抛错。
async function fetchGithubMeta(p) {
  const CACHE_TTL = 6 * 3600 * 1000;
  const SCHEMA = 2; // 与下方 meta.schema 保持一致：老结构缓存视为过期
  const cached = (() => {
    if (p.gh_meta_fetched_at && Date.now() - p.gh_meta_fetched_at < CACHE_TTL && p.gh_meta) {
      try {
        const m = JSON.parse(p.gh_meta);
        // 结构版本不匹配（例如旧缓存没有发行版资产）→ 视为过期，重新拉取
        return (m && m.schema >= SCHEMA) ? m : null;
      } catch (_) { return null; }
    }
    return null;
  })();
  if (cached) return cached;

  const repo = parseGithubRepo(p.repo_url);
  if (!repo) return null;
  const base = `/repos/${encodeURIComponent(repo.owner)}/${encodeURIComponent(repo.repo)}`;
  const [info, langs, contribs, release, rawReleases, rawFiles, commits] = await Promise.all([
    githubJson(base),
    githubJson(base + '/languages'),
    githubJson(base + '/contributors?per_page=12'),
    githubJson(base + '/releases/latest'),
    githubJson(base + '/releases?per_page=20'),   // 最近 20 个版本：GitHub 风格发行版页逐条展示 + 资产下载
    githubJson(base + '/contents'),
    githubJson(base + '/commits?per_page=1'),
  ]);

  // 主信息都拿不到（限流/网络不通）：回退到旧缓存，实在没有就返回 null 让前端降级
  if (!info || !info.full_name) {
    if (p.gh_meta) { try { return JSON.parse(p.gh_meta); } catch (_) { return null; } }
    return null;
  }

  const languages = langs && typeof langs === 'object' && !Array.isArray(langs) ? langs : null;
  const contributors = Array.isArray(contribs)
    ? contribs.filter((c) => c && c.login).map((c) => ({
        login: c.login, avatar_url: c.avatar_url || '', html_url: c.html_url || '', contributions: c.contributions || 0,
      }))
    : [];
  const files = Array.isArray(rawFiles)
    ? rawFiles.map((f) => ({ name: f.name || '', type: f.type || 'file', size: f.size || 0, path: f.path || '', html_url: f.html_url || '' }))
        .sort((a, b) => (a.type === b.type ? a.name.localeCompare(b.name) : (a.type === 'dir' ? -1 : 1)))
    : [];
  const c0 = Array.isArray(commits) && commits[0] ? commits[0] : null;
  const lastCommit = c0 ? {
    message: (c0.commit && c0.commit.message ? String(c0.commit.message).split('\n')[0] : ''),
    author: (c0.commit && c0.commit.author && c0.commit.author.name) || (c0.author && c0.author.login) || '',
    date: (c0.commit && c0.commit.author && c0.commit.author.date) || null,
    url: c0.html_url || '',
  } : null;

  const meta = {
    // 缓存结构版本：升级字段（如发行版资产 assets）后 bump 此值，
    // 让旧缓存自动失效重新拉取，否则老缓存里没有 assets，发行版页就只有源码包没有 .jar。
    schema: 2,
    full_name: info.full_name || `${repo.owner}/${repo.repo}`,
    owner: repo.owner, name: repo.repo,
    description: info.description || '',
    homepage: info.homepage || '',
    topics: Array.isArray(info.topics) ? info.topics.slice(0, 20) : [],
    stargazers: info.stargazers_count || 0,
    forks: info.forks_count || 0,
    watchers: info.subscribers_count || 0,
    open_issues: info.open_issues_count || 0,
    language: info.language || '',
    languages,
    license: info.license
      ? { name: info.license.name || info.license.spdx_id || '', spdx: info.license.spdx_id || '' }
      : null,
    default_branch: info.default_branch || 'main',
    size: info.size || 0,
    created_at: info.created_at || null,
    pushed_at: info.pushed_at || null,
    contributors,
    // 最近 20 个发布版本：GitHub 风格发行版页据此展示——每个版本的标题、
    // 发布说明(markdown)、作者、时间、以及可逐个站内下载的资产(.jar/.zip 等)与源码包。
    // 下载一律走本站代理接口，绝不把访客送到 github.com。
    releases: Array.isArray(rawReleases)
      ? rawReleases.filter((x) => x && x.tag_name).slice(0, 20).map((x) => ({
          tag: x.tag_name,
          name: x.name || x.tag_name,
          body: typeof x.body === 'string' ? x.body : '',
          draft: !!x.draft,
          prerelease: !!x.prerelease,
          published_at: x.published_at || null,
          html_url: x.html_url || '',
          zipball_url: x.zipball_url || '',
          tarball_url: x.tarball_url || '',
          author: x.author && x.author.login
            ? { login: x.author.login, avatar_url: x.author.avatar_url || '', html_url: x.author.html_url || '' }
            : null,
          assets: Array.isArray(x.assets)
            ? x.assets.filter((a) => a && a.name).map((a) => ({
                id: a.id,
                name: a.name,
                size: a.size || 0,
                download_count: a.download_count || 0,
                content_type: a.content_type || '',
                browser_download_url: a.browser_download_url || '',
              }))
            : [],
        }))
      : [],
    release: release && release.tag_name
      ? { tag: release.tag_name, name: release.name || release.tag_name, published_at: release.published_at || null, url: release.html_url || '' }
      : null,
    files,
    last_commit: lastCommit,
    html_url: info.html_url || p.repo_url,
  };
  try {
    db.prepare('UPDATE projects SET gh_meta = ?, gh_meta_fetched_at = ? WHERE id = ?').run(JSON.stringify(meta), Date.now(), p.id);
  } catch (_) {}
  return meta;
}

// ================= 站内下载 / 浏览仓库源码 =================
// 目标：项目页的「下载 ZIP」「查看文件」「下载单个文件」全部走本站接口，
// 不再把访客送到 github.com（唯一保留的外链是"前往原仓库"按钮）。
// 由服务端代理 GitHub：规避浏览器跨域、不暴露 token，同时能统一做体积与超时限制。
const { Readable } = require('stream');

const CODELOAD_HOST = 'https://codeload.github.com';
const RAW_HOST = 'https://raw.githubusercontent.com';
const MAX_ZIP = 80 * 1024 * 1024;   // 源码包上限 80MB，超了直接拒绝，避免吃满服务器带宽/内存
const MAX_TEXT = 512 * 1024;        // 单文件文本预览上限 512KB

// 允许作为文本预览的扩展名（其余一律按二进制处理，只提供站内下载）
const TEXT_EXT = new Set(['md', 'markdown', 'txt', 'json', 'json5', 'yml', 'yaml', 'toml', 'ini', 'cfg', 'conf',
  'js', 'jsx', 'mjs', 'cjs', 'ts', 'tsx', 'css', 'scss', 'less', 'sass', 'html', 'htm', 'vue', 'svelte',
  'xml', 'svg', 'sh', 'bash', 'zsh', 'fish', 'bat', 'cmd', 'ps1', 'py', 'rb', 'pl', 'pm', 'php', 'java',
  'kt', 'kts', 'go', 'rs', 'c', 'h', 'cpp', 'hpp', 'cc', 'cs', 'swift', 'm', 'mm', 'scala', 'dart',
  'lua', 'r', 'sql', 'gradle', 'properties', 'env', 'gitignore', 'gitattributes', 'dockerfile', 'makefile',
  'cmake', 'proto', 'graphql', 'tf', 'hcl', 'zig', 'nim', 'ex', 'exs', 'erl', 'hs', 'asm', 'vb', 'groovy']);

function extOf(p) {
  const n = String(p || '').toLowerCase();
  const i = n.lastIndexOf('.');
  return i < 0 ? n : n.slice(i + 1);
}

// 路径合法性：禁止 ../ 穿越与绝对路径，避免把任意路径拼进 GitHub API
function safeRelPath(v) {
  const rel = String(v || '').replace(/^\/+|\/+$/g, '');
  if (!rel) return { ok: true, rel: '' };
  if (rel.includes('..') || rel.includes('\\') || rel.includes('\0')) return { ok: false };
  // 只允许常见字符：字母数字与 . _ - / 空格
  if (!/^[\w.\- /]+$/.test(rel)) return { ok: false };
  return { ok: true, rel };
}

// 取出默认分支：优先用已缓存的 GitHub 元数据，抓不到时退回 main
function defaultBranch(p) {
  if (p.gh_meta) {
    try {
      const m = JSON.parse(p.gh_meta);
      if (m && m.default_branch) return m.default_branch;
    } catch (_) { /* 缓存损坏则忽略 */ }
  }
  return 'main';
}

// 解析 ref（分支/标签/commit）：只允许安全字符集，非法则用默认分支
function pickRef(p, q) {
  const v = String(q || '').trim();
  if (v && /^[\w.\-/]{1,120}$/.test(v) && !v.includes('..')) return v;
  return defaultBranch(p);
}

// 代理请求 GitHub（带超时），失败返回 null
async function proxyFetch(url, { timeout = 20000, headers = {} } = {}) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeout);
  try {
    const r = await fetch(url, {
      headers: {
        'User-Agent': 'WebOwn',
        ...(process.env.GITHUB_TOKEN ? { Authorization: `Bearer ${process.env.GITHUB_TOKEN}` } : {}),
        ...headers,
      },
      signal: ctrl.signal,
      redirect: 'follow',
    });
    clearTimeout(timer);
    return r;
  } catch (_) {
    clearTimeout(timer);
    return null;
  }
}

// 站内下载整包源码（ZIP / TAR.GZ）：服务端从 codeload 拉取后以附件形式流式返回，浏览器不会离开本站
router.get('/projects/:id/download', async (req, res) => {
  const id = parseInt(req.params.id) || 0;
  const p = db.prepare('SELECT * FROM projects WHERE id = ?').get(id);
  if (!p) return res.status(404).json({ error: '项目不存在' });
  const repo = parseGithubRepo(p.repo_url);
  if (!repo) return res.status(400).json({ error: '仓库地址无效' });
  const ref = pickRef(p, req.query.ref);
  // 两种打包格式：zip（默认，Windows 友好）/ tar.gz（Linux/mac 常用）
  const tar = String(req.query.format || '').toLowerCase() === 'tar';
  const kind = tar ? 'tar' : 'zip';                       // codeload 路径段：/zip/ 或 /tar/
  const ext = tar ? 'tar.gz' : 'zip';
  const mime = tar ? 'application/gzip' : 'application/zip';

  // 默认分支可能是 main 也可能是 master；第一个 404 时换个名字再试一次
  const tries = [ref];
  const alt = ref === 'main' ? 'master' : 'main';
  if (!tries.includes(alt)) tries.push(alt);

  for (const r of tries) {
    const url = `${CODELOAD_HOST}/${encodeURIComponent(repo.owner)}/${encodeURIComponent(repo.repo)}/${kind}/${encodeURIComponent(r)}`;
    const upstream = await proxyFetch(url, { timeout: 25000, headers: { Accept: mime } });
    if (!upstream || !upstream.ok) continue;
    const len = Number(upstream.headers.get('content-length') || 0);
    if (len && len > MAX_ZIP) {
      try { upstream.body.cancel(); } catch (_) {}
      return res.status(413).json({ error: '源码包过大（>80MB），请前往原仓库下载' });
    }
    const fname = `${repo.repo}-${r}.${ext}`.replace(/[^\w.\-]/g, '_');
    res.setHeader('Content-Type', mime);
    // 中文/特殊字符文件名：同时给 ASCII 兜底名与 RFC5987 编码名
    res.setHeader('Content-Disposition', `attachment; filename="${fname}"; filename*=UTF-8''${encodeURIComponent(fname)}`);
    res.setHeader('Cache-Control', 'no-store');
    if (len) res.setHeader('Content-Length', String(len));
    // WHATWG ReadableStream → Node 流，pipe 给响应即可边下边传，不整包驻留内存
    try {
      Readable.fromWeb(upstream.body).pipe(res);
      return;
    } catch (_) {
      return res.status(502).json({ error: '下载失败，请稍后再试' });
    }
  }
  res.status(502).json({ error: '无法从 GitHub 获取源码包，请稍后再试或前往原仓库下载' });
});

// 站内下载单个文件：代理 raw.githubusercontent.com，同样以附件返回
router.get('/projects/:id/file/download', async (req, res) => {
  const id = parseInt(req.params.id) || 0;
  const p = db.prepare('SELECT * FROM projects WHERE id = ?').get(id);
  if (!p) return res.status(404).json({ error: '项目不存在' });
  const repo = parseGithubRepo(p.repo_url);
  if (!repo) return res.status(400).json({ error: '仓库地址无效' });
  const sp = safeRelPath(req.query.path);
  if (!sp.ok || !sp.rel) return res.status(400).json({ error: '文件路径不合法' });
  const ref = pickRef(p, req.query.ref);

  const url = `${RAW_HOST}/${encodeURIComponent(repo.owner)}/${encodeURIComponent(repo.repo)}/${encodeURIComponent(ref)}/${sp.rel.split('/').map(encodeURIComponent).join('/')}`;
  const upstream = await proxyFetch(url, { timeout: 20000 });
  if (!upstream || !upstream.ok) return res.status(502).json({ error: '无法获取该文件，请稍后再试' });
  const len = Number(upstream.headers.get('content-length') || 0);
  if (len && len > MAX_ZIP) return res.status(413).json({ error: '文件过大，请前往原仓库下载' });

  const base = sp.rel.split('/').pop() || 'file';
  res.setHeader('Content-Type', upstream.headers.get('content-type') || 'application/octet-stream');
  res.setHeader('Content-Disposition', `attachment; filename="${base.replace(/[^\w.\-]/g, '_')}"; filename*=UTF-8''${encodeURIComponent(base)}`);
  res.setHeader('Cache-Control', 'no-store');
  if (len) res.setHeader('Content-Length', String(len));
  try {
    Readable.fromWeb(upstream.body).pipe(res);
  } catch (_) {
    res.status(502).json({ error: '下载失败' });
  }
});

// 站内下载发行版资产（.jar/.zip 等发布时上传的文件）：优先用缓存的公开下载地址
// browser_download_url（https://github.com/.../releases/download/...，匿名可下，无需 token），
// 缺失时再回退到 API 端点。文件流代理回来，访客始终停留在本站、不跳 github.com。
router.get('/projects/:id/releases/download', async (req, res) => {
  const id = parseInt(req.params.id) || 0;
  const p = db.prepare('SELECT * FROM projects WHERE id = ?').get(id);
  if (!p) return res.status(404).json({ error: '项目不存在' });
  const repo = parseGithubRepo(p.repo_url);
  const assetId = parseInt(req.query.asset_id) || 0;
  if (!assetId) return res.status(400).json({ error: '缺少资产编号 asset_id' });

  // 从缓存的 gh_meta 里按 asset_id 反查：拿公开下载 URL 与友好文件名
  let assetName = cleanStr(req.query.name, 200);
  let dlUrl = '';
  if (p.gh_meta) {
    try {
      const m = JSON.parse(p.gh_meta);
      for (const r of (m.releases || [])) {
        const a = (r.assets || []).find((x) => String(x.id) === String(assetId));
        if (a) {
          if (!assetName) assetName = a.name;
          dlUrl = a.browser_download_url || '';
          break;
        }
      }
    } catch (_) { /* 缓存损坏则用兜底 */ }
  }
  if (!assetName) assetName = 'release-asset';

  // 缓存里没有公开地址（罕见：缓存过期且资产是刚发布的）→ 退回 API 端点
  const isApi = !dlUrl;
  if (!dlUrl) {
    if (!repo) return res.status(400).json({ error: '仓库地址无效' });
    dlUrl = `https://api.github.com/repos/${encodeURIComponent(repo.owner)}/${encodeURIComponent(repo.repo)}/releases/assets/${assetId}`;
  }

  const upstream = await proxyFetch(dlUrl, { timeout: 60000, headers: isApi ? { Accept: 'application/octet-stream' } : {} });
  if (!upstream || !upstream.ok) return res.status(502).json({ error: '无法获取该发行版文件，请稍后再试或前往原仓库下载' });
  const len = Number(upstream.headers.get('content-length') || 0);
  if (len && len > MAX_ZIP) return res.status(413).json({ error: '文件过大（>80MB），请前往原仓库下载' });

  const safe = assetName.replace(/[^\w.\-]/g, '_');
  res.setHeader('Content-Type', upstream.headers.get('content-type') || 'application/octet-stream');
  res.setHeader('Content-Disposition', `attachment; filename="${safe}"; filename*=UTF-8''${encodeURIComponent(assetName)}`);
  res.setHeader('Cache-Control', 'no-store');
  if (len) res.setHeader('Content-Length', String(len));
  try { Readable.fromWeb(upstream.body).pipe(res); }
  catch (_) { res.status(502).json({ error: '下载失败' }); }
});

// 站内浏览仓库：目录返回条目列表；文本文件返回源码正文；二进制文件返回元信息 + 站内下载链接
// 结果做 5 分钟内存缓存，避免连续点目录把 GitHub API 额度打满
const FILE_CACHE = new Map();
const FILE_CACHE_TTL = 5 * 60 * 1000;

router.get('/projects/:id/files', async (req, res) => {
  const id = parseInt(req.params.id) || 0;
  const p = db.prepare('SELECT * FROM projects WHERE id = ?').get(id);
  if (!p) return res.status(404).json({ error: '项目不存在' });
  const repo = parseGithubRepo(p.repo_url);
  if (!repo) return res.status(400).json({ error: '仓库地址无效' });
  const sp = safeRelPath(req.query.path);
  if (!sp.ok) return res.status(400).json({ error: '路径不合法' });
  const ref = pickRef(p, req.query.ref);
  const rel = sp.rel;

  const key = `${id}|${ref}|${rel}`;
  const hit = FILE_CACHE.get(key);
  if (hit && Date.now() - hit.at < FILE_CACHE_TTL) return res.json(hit.data);
  // 顺手清理过期项，防止 Map 无限增长（仓库浏览是低频操作，量很小）
  if (FILE_CACHE.size > 200) {
    for (const [k, v] of FILE_CACHE) if (Date.now() - v.at >= FILE_CACHE_TTL) FILE_CACHE.delete(k);
  }

  const api = `/repos/${encodeURIComponent(repo.owner)}/${encodeURIComponent(repo.repo)}/contents/${rel.split('/').filter(Boolean).map(encodeURIComponent).join('/')}?ref=${encodeURIComponent(ref)}`;
  const data = await githubJson(api);
  if (!data) return res.status(502).json({ error: '无法读取仓库内容（GitHub 限流或网络不通），请稍后再试' });

  const mkOut = (o) => { FILE_CACHE.set(key, { at: Date.now(), data: o }); return res.json(o); };
  const parent = rel.includes('/') ? rel.slice(0, rel.lastIndexOf('/')) : '';

  // 目录
  if (Array.isArray(data)) {
    const entries = data
      .filter((f) => f && f.name)
      .map((f) => ({ name: String(f.name), path: String(f.path || f.name), type: f.type === 'dir' ? 'dir' : 'file', size: Number(f.size || 0) }))
      .sort((a, b) => (a.type === b.type ? a.name.localeCompare(b.name) : (a.type === 'dir' ? -1 : 1)));
    return mkOut({ type: 'dir', path: rel, parent, ref, entries });
  }

  // 单文件
  if (data.type === 'file') {
    const ext = extOf(data.name);
    const isText = TEXT_EXT.has(ext);
    const out = {
      type: 'file', path: rel, parent, ref,
      name: String(data.name || rel.split('/').pop() || ''),
      size: Number(data.size || 0), ext, binary: !isText,
      download: `/api/projects/${id}/file/download?path=${encodeURIComponent(rel)}&ref=${encodeURIComponent(ref)}`,
    };
    if (isText && out.size <= MAX_TEXT && data.download_url) {
      const r = await proxyFetch(data.download_url, { timeout: 15000 });
      if (r && r.ok) out.text = (await r.text()).slice(0, MAX_TEXT);
      else out.text = null;
    } else {
      out.text = null;
    }
    return mkOut(out);
  }
  res.status(404).json({ error: '该路径不是文件或目录' });
});

// ---------- 互动（需登录） ----------
function interaction(req, res) {
  const { type, id } = req.params;
  if (!TARGET_TYPES.includes(type)) return res.status(400).json({ error: '无效类型' });
  const targetId = parseInt(id) || 0;
  return { type, targetId };
}

router.get('/mystate/:type/:id', requireAuth, (req, res) => {
  const { type, targetId } = interaction(req, res);
  const liked = !!db.prepare('SELECT 1 FROM likes WHERE target_type = ? AND target_id = ? AND user_id = ?').get(type, targetId, req.user.id);
  const favorited = !!db.prepare('SELECT 1 FROM favorites WHERE target_type = ? AND target_id = ? AND user_id = ?').get(type, targetId, req.user.id);
  res.json({ liked, favorited });
});

router.post('/likes/:type/:id', requireAuth, (req, res) => {
  const { type, targetId } = interaction(req, res);
  const exists = db.prepare('SELECT 1 FROM likes WHERE target_type = ? AND target_id = ? AND user_id = ?').get(type, targetId, req.user.id);
  if (exists) {
    db.prepare('DELETE FROM likes WHERE target_type = ? AND target_id = ? AND user_id = ?').run(type, targetId, req.user.id);
  } else {
    db.prepare('INSERT INTO likes (target_type, target_id, user_id, created_at) VALUES (?, ?, ?, ?)').run(type, targetId, req.user.id, Date.now());
    try { community.completeTask(req.user.id, 'daily_like', 'like:' + type + ':' + targetId); community.evaluateAutoAchievements(req.user.id); } catch (_) {}
  }
  res.json({ liked: !exists, ...countsFor(type, targetId) });
});

router.post('/favorites/:type/:id', requireAuth, (req, res) => {
  const { type, targetId } = interaction(req, res);
  const exists = db.prepare('SELECT 1 FROM favorites WHERE target_type = ? AND target_id = ? AND user_id = ?').get(type, targetId, req.user.id);
  if (exists) {
    db.prepare('DELETE FROM favorites WHERE target_type = ? AND target_id = ? AND user_id = ?').run(type, targetId, req.user.id);
  } else {
    db.prepare('INSERT INTO favorites (target_type, target_id, user_id, created_at) VALUES (?, ?, ?, ?)').run(type, targetId, req.user.id, Date.now());
    try { community.completeTask(req.user.id, 'daily_favorite', 'favorite:' + type + ':' + targetId); community.evaluateAutoAchievements(req.user.id); } catch (_) {}
  }
  res.json({ favorited: !exists, ...countsFor(type, targetId) });
});

// ---------- 我的收藏（跨 article / image / project 三类） ----------
// 只返回当前用户自己的收藏（WHERE user_id = ?），不存在越权读取
router.get('/favorites/mine', requireAuth, (req, res) => {
  const favs = db.prepare(
    'SELECT target_type, target_id, created_at FROM favorites WHERE user_id = ? ORDER BY created_at DESC'
  ).all(req.user.id);
  if (!favs.length) return res.json({ items: [], total: 0 });

  // 按类型分组后批量取内容；id 收敛为整数，占位符按数量生成（值仍走参数绑定）
  const byType = { article: [], image: [], project: [] };
  for (const f of favs) {
    const id = parseInt(f.target_id) || 0;
    if (byType[f.target_type] && id) byType[f.target_type].push(id);
  }
  const ph = (n) => Array(n).fill('?').join(',');

  const meta = {};
  // 文章：普通用户只看已发布，站长可见草稿（草稿只有自己能收藏到）
  const artWhere = req.user.role === 'admin' ? '' : "AND status = 'published'";
  if (byType.article.length) {
    db.prepare(
      `SELECT id, title, slug, summary, cover, tags, views, status
       FROM articles WHERE id IN (${ph(byType.article.length)}) ${artWhere}`
    ).all(...byType.article).forEach((r) => {
      meta[`article:${r.id}`] = {
        title: r.title, summary: r.summary, cover: r.cover,
        href: `#/article/${r.slug}`, draft: r.status === 'draft',
      };
    });
  }
  if (byType.image.length) {
    db.prepare(
      `SELECT id, title, description, filename, views FROM images WHERE id IN (${ph(byType.image.length)})`
    ).all(...byType.image).forEach((r) => {
      meta[`image:${r.id}`] = {
        title: r.title || '', summary: r.description || '', views: r.views || 0,
        cover: `/uploads/${r.filename}`, href: `#/image/${r.id}`,
      };
    });
  }
  if (byType.project.length) {
    db.prepare(
      `SELECT id, title, description, repo_url, cover, icon, views FROM projects WHERE id IN (${ph(byType.project.length)})`
    ).all(...byType.project).forEach((r) => {
      meta[`project:${r.id}`] = {
        title: r.title, summary: r.description || '', views: r.views || 0,
        icon: r.icon || '', cover: r.cover || '', href: `#/project/${r.id}`,
      };
    });
  }

  // 以收藏表为准输出；内容已被删除的记录自动不返回
  const items = favs.map((f) => {
    const id = parseInt(f.target_id) || 0;
    const m = meta[`${f.target_type}:${id}`];
    if (!m) return null;
    return {
      type: f.target_type, id, favorited_at: f.created_at,
      title: m.title, summary: m.summary, cover: m.cover, href: m.href, draft: !!m.draft,
    };
  }).filter(Boolean);
  res.json({ items, total: items.length });
});

router.post('/shares/:type/:id', (req, res) => {
  const { type, targetId } = interaction(req, res);
  db.prepare('INSERT INTO shares (target_type, target_id, created_at) VALUES (?, ?, ?)').run(type, targetId, Date.now());
  res.json({ ok: true });
});

router.post('/comments/:type/:id', requireAuth, (req, res) => {
  const { type, targetId } = interaction(req, res);
  const content = cleanStr(req.body && req.body.content, 1000);
  if (!content) return res.status(400).json({ error: '评论内容不能为空' });
  const info = db.prepare('INSERT INTO comments (target_type, target_id, user_id, content, created_at) VALUES (?, ?, ?, ?, ?)')
    .run(type, targetId, req.user.id, content, Date.now());
  // 任务/成就：评论事件触发每日任务与自动成就判定（幂等，失败不影响主流程）
  try { community.completeTask(req.user.id, 'daily_comment', 'comment:' + info.lastInsertRowid); community.evaluateAutoAchievements(req.user.id); } catch (_) {}
  const a = community.commentAuthor(req.user.id) || { username: req.user.username, avatar: null, level: null, level_color: null, title: null, title_icon: '', title_color: null, badges: [] };
  res.status(201).json({ id: info.lastInsertRowid, content, created_at: Date.now(), username: a.username, avatar: a.avatar, level: a.level, level_color: a.level_color, title: a.title, title_icon: a.title_icon, title_color: a.title_color, badges: a.badges });
});

// 删除自己的评论（软删除：置为 hidden；站长可删任意评论）
router.delete('/comments/:id', requireAuth, (req, res) => {
  const id = parseInt(req.params.id) || 0;
  const c = db.prepare('SELECT id, user_id FROM comments WHERE id = ?').get(id);
  if (!c) return res.status(404).json({ error: '评论不存在' });
  const isAdmin = req.user.role === 'admin' || req.user.role === 'owner';
  if (c.user_id !== req.user.id && !isAdmin) return res.status(403).json({ error: '无权删除他人评论' });
  db.prepare("UPDATE comments SET status = 'hidden' WHERE id = ?").run(id);
  audit(req.user.id, '', 'delete_comment', 'comment', String(id), { owner_id: c.user_id, by_admin: isAdmin });
  res.json({ ok: true });
});

// ---------- 用户中心 ----------
const multer = require('multer');

const UPLOAD_DIR = path.join(__dirname, '..', 'data', 'uploads');
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });

const AVATAR_EXT = ['.jpg', '.jpeg', '.png', '.gif', '.webp'];
const AVATAR_MAGIC = [
  [0xff, 0xd8, 0xff], [0x89, 0x50, 0x4e, 0x47], [0x47, 0x49, 0x46, 0x38], [0x52, 0x49, 0x46, 0x46],
];

const avatarUpload = multer({
  storage: multer.diskStorage({
    destination: (_r, _f, cb) => cb(null, UPLOAD_DIR),
    filename: (_r, file, cb) => cb(null, 'av-' + crypto.randomBytes(12).toString('hex') + path.extname(file.originalname).toLowerCase()),
  }),
  limits: { fileSize: 2 * 1024 * 1024, files: 1 },
  fileFilter: (_r, file, cb) => {
    if (!AVATAR_EXT.includes(path.extname(file.originalname).toLowerCase())) return cb(new Error('仅支持 jpg/png/gif/webp 头像'));
    cb(null, true);
  },
});

router.post('/user/avatar', requireAuth, (req, res) => {
  avatarUpload.single('file')(req, res, (err) => {
    if (err) return res.status(400).json({ error: err.message || '上传失败' });
    if (!req.file) return res.status(400).json({ error: '未收到文件' });
    try {
      const fd = fs.openSync(req.file.path, 'r');
      const buf = Buffer.alloc(4);
      fs.readSync(fd, buf, 0, 4, 0);
      fs.closeSync(fd);
      const ok = AVATAR_MAGIC.some((m) => m.every((b, i) => buf[i] === b));
      if (!ok) { fs.unlinkSync(req.file.path); return res.status(400).json({ error: '文件内容与图片格式不符' }); }
    } catch (_) { return res.status(500).json({ error: '头像保存失败' }); }
    // 隐私：剥离 EXIF/GPS/注释等元数据（失败不影响上传）
    try { stripImageMetadata(req.file.path, path.extname(req.file.filename).toLowerCase()); } catch (_) {}
    db.prepare('UPDATE users SET avatar = ? WHERE id = ?').run(req.file.filename, req.user.id);
    // 返回纯文件名：前端统一通过 /uploads/ 前缀拼接，避免双重前缀
    res.json({ ok: true, avatar: req.file.filename });
  });
});

// 修改昵称（用户名）：限流 + 唯一性 + 审计；账号邮箱不可在此修改
// 说明：昵称会同步 username_lower（登录/搜索/查重都依赖它），改名不影响登录。
const NICK_RE = /^[\p{L}\p{N}_.\-· ]{2,32}$/u;
const nickLimiter = makeLimiter({ windowMs: 24 * 60 * 60 * 1000, max: 5, msg: '昵称修改过于频繁，请稍后再试' });
router.put('/user/username', requireAuth, nickLimiter, (req, res) => {
  const me = db.prepare('SELECT username, banned FROM users WHERE id = ?').get(req.user.id);
  if (!me) return res.status(404).json({ error: '用户不存在' });
  if (me.banned) return res.status(403).json({ error: '账号已被封禁，无法修改昵称' });
  const name = cleanStr(req.body && req.body.username, 32).trim().replace(/\s+/g, ' ');
  if (!NICK_RE.test(name)) return res.status(400).json({ error: '昵称为 2-32 位，仅支持中英文、数字、空格与 _ . - ·' });
  if (name === me.username) return res.json({ ok: true, username: name, unchanged: true });
  const dup = db.prepare('SELECT id FROM users WHERE username_lower = ? AND id <> ?').get(name.toLowerCase(), req.user.id);
  if (dup) return res.status(400).json({ error: '该昵称已被占用' });
  db.prepare('UPDATE users SET username = ?, username_lower = ? WHERE id = ?').run(name, name.toLowerCase(), req.user.id);
  audit(req.user.id, '', 'change_username', 'user', String(req.user.id), { from: me.username, to: name });
  res.json({ ok: true, username: name });
});

// 账号绑定邮箱：只读，仅可切换「是否公开」（邮箱本身不支持在此修改，避免换绑劫持账号）
router.put('/user/email-visibility', requireAuth, (req, res) => {
  const pub = req.body && req.body.public !== undefined ? (req.body.public ? 1 : 0) : null;
  if (pub === null) return res.status(400).json({ error: '缺少参数' });
  community.ensureProfile(req.user.id);
  db.prepare('UPDATE user_profiles SET email_public = ? WHERE user_id = ?').run(pub, req.user.id);
  audit(req.user.id, '', 'set_email_public', 'user', String(req.user.id), { public: pub });
  res.json({ ok: true, email_public: !!pub });
});

router.put('/user/password', requireAuth, (req, res) => {
  const { oldPassword, newPassword } = req.body || {};
  const u = db.prepare('SELECT password_hash FROM users WHERE id = ?').get(req.user.id);
  if (!u || !verifyPassword(String(oldPassword || ''), u.password_hash)) return res.status(400).json({ error: '原密码不正确' });
  if (!isStrongPassword(newPassword)) return res.status(400).json({ error: passwordHint() });
  db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(hashPassword(newPassword), req.user.id);
  res.json({ ok: true });
});

// ================= 个人设置 / 隐私 / 个人主页 =================
// 读取自己的完整设置（含隐私），供设置页编辑
router.get('/user/profile', requireAuth, (req, res) => {
  const p = community.ensureProfile(req.user.id);
  let privacy;
  try { privacy = JSON.parse(p.privacy || '{}'); } catch (_) { privacy = {}; }
  res.json({
    profile: {
      birthday: p.birthday || '', birthday_visibility: p.birthday_visibility,
      gender: p.gender, signature: p.signature || '',
      social_bilibili: p.social_bilibili || '', social_github: p.social_github || '',
      social_qq: p.social_qq || '', social_email: p.social_email || '',
      email_public: !!p.email_public, email_verified: !!p.email_verified,
    },
    privacy: Object.assign(community.defaultPrivacy(), privacy),
  });
});

// 更新个人设置 + 隐私（服务端校验/白名单/脱敏）
router.put('/user/profile', requireAuth, (req, res) => {
  const b = req.body || {};
  const p = community.ensureProfile(req.user.id);
  const sets = [];
  const vals = [];

  // 生日：仅接受合理 ISO 日期；空串清空
  if (b.birthday !== undefined) {
    const v = cleanStr(b.birthday, 20);
    if (v && !/^\d{4}-\d{2}-\d{2}$/.test(v)) return res.status(400).json({ error: '生日格式应为 YYYY-MM-DD' });
    if (v) {
      const y = parseInt(v.slice(0, 4));
      if (y < 1900 || y > new Date().getFullYear()) return res.status(400).json({ error: '生日年份不合法' });
    }
    sets.push('birthday = ?'); vals.push(v);
  }
  if (b.birthday_visibility !== undefined) {
    sets.push('birthday_visibility = ?'); vals.push(['hidden', 'age_range', 'is_birthday'].includes(b.birthday_visibility) ? b.birthday_visibility : 'hidden');
  }
  if (b.gender !== undefined) {
    sets.push('gender = ?'); vals.push(['male', 'female', 'secret'].includes(b.gender) ? b.gender : 'secret');
  }
  if (b.signature !== undefined) {
    sets.push('signature = ?'); vals.push(cleanStr(b.signature, 200));
  }
  // 社交链接：白名单校验（仅 http(s)，否则清空），防 XSS/钓鱼/开放重定向
  for (const key of ['social_bilibili', 'social_github']) {
    if (b[key] !== undefined) { sets.push(`${key} = ?`); vals.push(community.safeSocial(b[key])); }
  }
  if (b.social_qq !== undefined) {
    const qq = cleanStr(b.social_qq, 20);
    sets.push('social_qq = ?'); vals.push(/^\d{4,15}$/.test(qq) ? qq : '');
  }
  if (b.social_email !== undefined) {
    const em = cleanStr(b.social_email, 120).toLowerCase();
    sets.push('social_email = ?'); vals.push(/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(em) ? em : '');
    // 改了邮箱则视为未验证（避免冒充）；email_public 跟随
    sets.push('email_verified = ?'); vals.push(0);
  }
  if (b.email_public !== undefined) {
    sets.push('email_public = ?'); vals.push(b.email_public ? 1 : 0);
  }
  // 隐私设置：仅接受已知键
  if (b.privacy !== undefined) {
    const merged = Object.assign(community.getPrivacy(req.user.id), community.sanitizePrivacy(b.privacy));
    sets.push('privacy = ?'); vals.push(JSON.stringify(merged));
  }

  if (!sets.length) return res.status(400).json({ error: '没有需要更新的字段' });
  vals.push(req.user.id);
  db.prepare(`UPDATE user_profiles SET ${sets.join(', ')} WHERE user_id = ?`).run(...vals);
  res.json({ ok: true });
});

// 他人公开信息（评论区/搜索用）：按隐私+展示开关过滤，未公开字段不返回
router.get('/user/:id/public', (req, res) => {
  const id = parseInt(req.params.id) || 0;
  const a = community.commentAuthor(id);
  if (!a) return res.status(404).json({ error: '用户不存在' });
  res.json({ user: a });
});

// 个人主页：遵守被访问用户隐私设置；未公开字段后端不返回
router.get('/user/:id/home', (req, res) => {
  const id = parseInt(req.params.id) || 0;
  const viewerId = req.user ? req.user.id : null;
  const home = community.getHome(id, viewerId);
  if (!home) return res.status(404).json({ error: '用户不存在' });
  res.json({ home });
});

// 站内通知：已读/未读
router.get('/notifications', requireAuth, (req, res) => {
  const items = db.prepare(
    'SELECT id, type, title, body, ref, read, created_at FROM notifications WHERE user_id = ? ORDER BY created_at DESC LIMIT 100'
  ).all(req.user.id);
  // 未读数按全量统计（不受上面 100 条截断影响），保证红点数字准确
  const unread = db.prepare('SELECT COUNT(*) c FROM notifications WHERE user_id = ? AND read = 0').get(req.user.id).c;
  res.json({ items, unread });
});

// 轻量未读计数：供头像红点轮询使用（只返回一个数字，开销极小）
router.get('/notifications/unread', requireAuth, (req, res) => {
  const unread = db.prepare('SELECT COUNT(*) c FROM notifications WHERE user_id = ? AND read = 0').get(req.user.id).c;
  res.json({ unread });
});

router.post('/notifications/read', requireAuth, (req, res) => {
  const { id, all } = req.body || {};
  if (all) {
    db.prepare('UPDATE notifications SET read = 1 WHERE user_id = ?').run(req.user.id);
  } else if (id) {
    db.prepare('UPDATE notifications SET read = 1 WHERE id = ? AND user_id = ?').run(parseInt(id) || 0, req.user.id);
  }
  res.json({ ok: true });
});

// ================= 签到 / 任务 / 成就 / 兑换码 =================
// 签到：每日一次（UNIQUE(user_id,date) 防重复）；连续奖励；基础经验不参与倍率（保底独立）
const checkinLimiter = makeLimiter({ windowMs: 60 * 1000, max: 10, msg: '签到操作过于频繁' });
router.post('/checkin', requireAuth, checkinLimiter, (req, res) => {
  try {
    const r = community.doCheckin(req.user.id);
    community.evaluateAutoAchievements(req.user.id);
    res.json(r);
  } catch (e) { res.status(500).json({ error: '签到失败：' + e.message }); }
});
router.get('/checkin', requireAuth, (req, res) => {
  res.json(community.getCheckinStatus(req.user.id));
});

// 任务：返回任务列表 + 本人今日进度/领取状态
router.get('/tasks', requireAuth, (req, res) => {
  res.json({ tasks: community.getMyTasks(req.user.id) });
});
// 任务完成（客户端触发型任务/兜底）：受每日上限 + 幂等约束
router.post('/tasks/:key/complete', requireAuth, (req, res) => {
  const r = community.completeTask(req.user.id, req.params.key, req.body && req.body.idempotency_id);
  if (r.error) return res.status(400).json(r);
  community.evaluateAutoAchievements(req.user.id);
  res.json(r);
});

// 成就墙（公开）：定义列表
router.get('/achievements', (req, res) => {
  res.json({ achievements: community.getAchievements() });
});
// 我的成就（登录）：含已获得/进度
router.get('/achievements/mine', requireAuth, (req, res) => {
  res.json({ achievements: community.getMyAchievements(req.user.id) });
});

// 兑换码兑换：一次性/绑定用户/过期/限次；限流防爆破
const redeemLimiter = makeLimiter({ windowMs: 60 * 1000, max: 20, msg: '兑换操作过于频繁' });
router.post('/redeem', requireAuth, redeemLimiter, (req, res) => {
  const code = req.body && req.body.code;
  if (!code) return res.status(400).json({ error: '请输入兑换码' });
  const r = community.redeemCode(req.user.id, code);
  if (r.error) return res.status(400).json(r);
  community.evaluateAutoAchievements(req.user.id);
  res.json(r);
});

// ================= 个人名片（Lv5+，图片隔离存储 + 审核发布） =================
// 图片写入 data/private/（不被 /uploads 静态托管），通过受控端点按「审核状态」放行，
// 杜绝直链枚举与未审核内容外泄。
const cardUpload = multer({
  storage: multer.diskStorage({
    destination: (_r, _f, cb) => cb(null, PRIVATE_DIR),
    filename: (_r, file, cb) => {
      const ext = path.extname(file.originalname).toLowerCase();
      const safeExt = AVATAR_EXT.includes(ext) ? ext : '.bin';
      cb(null, 'card-' + crypto.randomBytes(16).toString('hex') + safeExt);
    },
  }),
  limits: { fileSize: 4 * 1024 * 1024, files: 1 },
  fileFilter: (_r, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    if (!AVATAR_EXT.includes(ext)) return cb(new Error('仅支持 jpg/png/gif/webp 图片'));
    cb(null, true);
  },
});
function verifyCardMagic(filePath) {
  try {
    const fd = fs.openSync(filePath, 'r');
    const buf = Buffer.alloc(4);
    fs.readSync(fd, buf, 0, 4, 0);
    fs.closeSync(fd);
    return AVATAR_MAGIC.some((m) => m.every((b, i) => buf[i] === b));
  } catch (_) { return false; }
}

// 我的名片（编辑面板：含等级/是否解锁/当前状态）
router.get('/card', requireAuth, (req, res) => {
  res.json(community.getMyCard(req.user.id));
});

// 提交/更新名片（Lv5+ 才可；等级门槛在落盘前先校验，避免产生孤儿文件）
const cardLimiter = makeLimiter({ windowMs: 60 * 1000, max: 6, msg: '名片提交过于频繁' });
router.post('/card', requireAuth, cardLimiter, (req, res) => {
  const level = community.getUserLevel(req.user.id);
  const staff = community.isStaff(req.user.id); // 站长免等级门槛
  if (level < community.CARD_MIN_LEVEL && !staff) return res.status(403).json({ error: 'level_low', min_level: community.CARD_MIN_LEVEL });
  cardUpload.single('file')(req, res, (err) => {
    if (err) return res.status(400).json({ error: err.message || '上传失败' });
    const body = req.body || {};
    const existing = db.prepare('SELECT image_path FROM business_cards WHERE user_id = ?').get(req.user.id);
    let imagePath = existing ? existing.image_path : null;
    if (req.file) {
      if (!verifyCardMagic(req.file.path)) {
        try { fs.unlinkSync(req.file.path); } catch (_) {}
        return res.status(400).json({ error: '文件内容与图片格式不符' });
      }
      // 隐私：剥离 EXIF/GPS/注释等元数据（失败不影响提交）
      try { stripImageMetadata(req.file.path, path.extname(req.file.filename).toLowerCase()); } catch (_) {}
      // 覆盖式：删除旧图，避免私有目录堆积
      if (imagePath && imagePath !== req.file.filename) { try { fs.unlinkSync(path.join(PRIVATE_DIR, imagePath)); } catch (_) {} }
      imagePath = req.file.filename;
    }
    let style = null;
    if (body.style) { try { style = JSON.parse(body.style); } catch (_) { style = null; } }
    const r = community.submitCard(req.user.id, {
      title: cleanStr(body.title, 40), intro: cleanStr(body.intro, 300), style, imagePath,
    }, req.user.id);
    if (r.error) return res.status(r.error === 'level_low' ? 403 : 400).json(r);
    res.json({ ok: true, auto_approved: !!r.auto_approved, card: r.card });
  });
});

// 名片图片受控访问：仅「审核通过」对外可见；本人/管理员可预览待审图
router.get('/card/:userId/image', (req, res) => {
  const uid = parseInt(req.params.userId) || 0;
  const row = db.prepare(
    'SELECT b.image_path, b.status, u.level, u.xp, u.role, u.banned FROM business_cards b JOIN users u ON u.id = b.user_id WHERE b.user_id = ?'
  ).get(uid);
  if (!row || !row.image_path) return res.status(404).json({ error: '名片图片不存在' });
  const isOwner = req.user && req.user.id === uid;
  const isAdmin = req.user && (req.user.role === 'admin' || req.user.role === 'owner');
  // 对外可见须同时满足：已通过 + 具备资格（当前达 Lv5 或站长）+ 未封禁（降级/封禁后即时失效）；
  // 本人/管理员可预览
  const qualified = community.levelForXp(row.xp || 0) >= community.CARD_MIN_LEVEL || (row.role === 'admin' || row.role === 'owner');
  const publicOk = row.status === 'approved' && qualified && !row.banned;
  if (!publicOk && !isOwner && !isAdmin) return res.status(403).json({ error: '名片未审核通过' });
  const fp = path.join(PRIVATE_DIR, row.image_path);
  if (!fp.startsWith(PRIVATE_DIR + path.sep) && fp !== PRIVATE_DIR) return res.status(400).json({ error: '非法路径' });
  if (!fs.existsSync(fp)) return res.status(404).json({ error: '图片文件缺失' });
  const ext = path.extname(fp).toLowerCase();
  res.set('Content-Type', ASSET_CT[ext] || 'application/octet-stream');
  res.set('Cache-Control', 'no-store');
  res.sendFile(fp);
});

// 评论区增强：返回作者头像/等级/称号/成就（按隐私），且不暴露未公开字段
router.get('/comments/:type/:id', (req, res) => {
  const { type, id } = req.params;
  if (!TARGET_TYPES.includes(type)) return res.status(400).json({ error: '无效类型' });
  const rows = db.prepare(
    `SELECT c.id, c.content, c.created_at, c.user_id
     FROM comments c WHERE c.target_type = ? AND c.target_id = ? AND c.status = 'visible'
     ORDER BY c.created_at DESC LIMIT 100`
  ).all(type, parseInt(id) || 0);
  const items = rows.map((r) => {
    const a = community.commentAuthor(r.user_id) || { username: '已注销用户', avatar: null, level: null, level_color: null, title: null, title_icon: '', title_color: null, badges: [] };
    return { id: r.id, content: r.content, created_at: r.created_at, username: a.username, avatar: a.avatar, level: a.level, level_color: a.level_color, title: a.title, title_icon: a.title_icon, title_color: a.title_color, badges: a.badges };
  });
  res.json({ items });
});

module.exports = router;
