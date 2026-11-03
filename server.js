// WebOwn — 个人小站服务端
// 设计目标：单进程、低内存（<100MB），适配 2核/3.5GB 且与 NoneBot+NapCat 共存的服务器
// 启动建议：node --max-old-space-size=256 server.js（限制堆内存上限，见部署文档）
const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const path = require('path');
const fs = require('fs');

// 极简 .env 加载（不引入 dotenv 依赖）
try {
  for (const line of fs.readFileSync(path.join(__dirname, '.env'), 'utf8').split('\n')) {
    const m = line.match(/^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)\s*$/);
    if (m && process.env[m[1]] === undefined) process.env[m[1]] = m[2].replace(/^['"]|['"]$/g, '');
  }
} catch (_) { /* 无 .env 文件则跳过 */ }

const { optionalAuth, csrfGuard, getIpBan } = require('./lib/auth');
const apiRoutes = require('./routes/api');
const adminRoutes = require('./routes/admin');

const app = express();
app.disable('x-powered-by');
// trust proxy 不要用裸 true：会让 express-rate-limit 报 ERR_ERL_PERMISSIVE_TRUST_PROXY，
// 且允许伪造 X-Forwarded-For 绕过基于 IP 的限速。反代场景下用 'loopback'（仅信任本机 Nginx），
// 既能让 req.ip / req.secure 正确解析真实客户端信息，又不会被外部伪造头绕过。
app.set('trust proxy', process.env.TRUST_PROXY === '1' ? 'loopback' : false);

// ---------- 安全头 ----------
const isProd = process.env.NODE_ENV === 'production';
// SSL=1 表示部署在 HTTPS 下（同时开启 HSTS 与 upgrade-insecure-requests）。
// 免 SSL（纯 http）部署时务必留空，否则 HSTS 会强制浏览器跳 HTTPS、upgrade 会让资源加载失败导致白屏。
const useSSL = process.env.SSL === '1';
app.use(helmet({
  contentSecurityPolicy: {
    useDefaults: true,
    directives: {
      'default-src': ["'self'"],
      'base-uri': ["'self'"],
      'form-action': ["'self'"],
      'object-src': ["'none'"],      // 禁止 <object>/<embed> 等插件，杜绝插件类注入
      'script-src': ["'self'"],
      'style-src': ["'self'", "'unsafe-inline'"], // 主题切换需要内联样式
      'img-src': ["'self'", 'data:', 'blob:', 'https:'],   // blob: 供头像裁剪器等本地预览使用
      'connect-src': ["'self'"],
      'frame-ancestors': ["'none'"],
      'upgrade-insecure-requests': useSSL ? [] : null,
    },
  },
  crossOriginEmbedderPolicy: false,
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
}));
// 仅在明确部署 HTTPS 时启用 HSTS；免 SSL 部署关闭
if (useSSL) {
  app.use(helmet.hsts({ maxAge: 15552000, includeSubDomains: true }));
}

// ---------- 限速 ----------
app.use('/api', rateLimit({ windowMs: 60 * 1000, max: 120, standardHeaders: true, legacyHeaders: false }));
app.use('/api/auth/login', rateLimit({ windowMs: 15 * 60 * 1000, max: 20, standardHeaders: true, legacyHeaders: false }));
app.use('/api/auth/register', rateLimit({ windowMs: 60 * 60 * 1000, max: 10, standardHeaders: true, legacyHeaders: false }));

// ---------- 解析与 Cookie ----------
app.use(express.json({ limit: '256kb' }));
// API 响应一律禁止缓存（防止 /auth/me 被浏览器缓存导致切换账号后头像/用户名串号，
// 也防止删除/发布后列表接口被 Nginx 反代回吐旧数据）。
// 除了 Cache-Control，再补 Pragma/Expires/Surrogate-Control：部分反代与老代理只认这几个头。
app.use('/api', (_req, res, next) => {
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, max-age=0');
  res.setHeader('Surrogate-Control', 'no-store');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');
  next();
});
app.use((req, _res, next) => {
  // 轻量 cookie 解析（不引入 cookie-parser 依赖）
  req.cookies = {};
  const raw = req.headers.cookie;
  if (raw) {
    for (const pair of raw.split(';')) {
      const idx = pair.indexOf('=');
      if (idx > 0) req.cookies[pair.slice(0, idx).trim()] = decodeURIComponent(pair.slice(idx + 1).trim());
    }
  }
  next();
});
app.use(optionalAuth);
app.use('/api', csrfGuard);

// ---------- IP 封禁 ----------
// 封禁某个 IP 后，该 IP 下的所有账号（含已登录会话、登录/注册请求）一律无法进入。
// 仅放行 /api/ipban-status，让前端能拿到封禁信息并展示提示页而不是满屏报错。
app.use('/api', (req, res, next) => {
  if (req.path === '/ipban-status') return next();
  const ban = getIpBan(req.ip);
  if (!ban) return next();
  res.status(403).json({ error: 'IP_BANNED', banned: true, until: ban.until || null, reason: ban.reason || '' });
});

// ---------- 静态资源 ----------
const PUBLIC_DIR = path.join(__dirname, 'public');
const staticOpts = {
  maxAge: isProd ? '7d' : 0,
  extensions: ['html'],
  // HTML 入口永不缓存（no-store 连协商缓存都不要），改版后刷新立即生效；其余静态资源长缓存
  setHeaders: (res, filePath) => {
    if (filePath.endsWith('.html')) res.setHeader('Cache-Control', 'no-store');
  },
};
app.use(express.static(PUBLIC_DIR, staticOpts));
app.use('/uploads', express.static(path.join(__dirname, 'data', 'uploads'), { maxAge: '30d', immutable: true }));

// ---------- 路由 ----------
app.use('/api', apiRoutes);
app.use('/api/admin', adminRoutes);

// SPA 回退（非 API、非文件的 GET 请求 → index.html）
app.get(/^\/(?!api|uploads).*/, (_req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  res.sendFile(path.join(PUBLIC_DIR, 'index.html'));
});

// ---------- 错误处理 ----------
// eslint-disable-next-line no-unused-vars
app.use((err, _req, res, _next) => {
  console.error('[error]', err.message);
  res.status(500).json({ error: '服务器内部错误' });
});

// ---------- 启动 ----------
const PORT = parseInt(process.env.PORT) || 3000;
app.listen(PORT, () => {
  console.log(`月之海 已启动: http://localhost:${PORT} (pid ${process.pid})`);
});
