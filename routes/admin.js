// 管理端路由（全部需要管理员权限）
const express = require('express');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const multer = require('multer');
const db = require('../lib/db');
const { requireAdmin, cleanStr, normalizeIp, audit } = require('../lib/auth');
const { sanitizeHtml, fixFilename } = require('../lib/sanitize');
const community = require('../lib/community');

const router = express.Router();
router.use(requireAdmin);

// 条款文件路径：保存条款时同步回写，使「服务器 terms.md 文件」与「数据库 settings.terms」始终保持一致
const TERMS_PATH = path.join(__dirname, '..', 'terms.md');
function writeTermsFile(content) {
  try {
    fs.writeFileSync(TERMS_PATH, content, 'utf8');
  } catch (e) {
    // 文件回写失败不应影响数据库已保存的内容（如只读挂载），仅告警
    console.error('[terms] 回写 terms.md 失败（不影响数据库已保存内容）：', e.message);
  }
}

// 项目主页：只接受 http(s) 链接。
// 关键点：允许省略协议（demo.example.com → https://demo.example.com）。
// 早期版本对"没写 https://"的值一律存成空串，用户填了、保存也成功了、链接却不见了——
// 报"内容保存后消失"的典型来源。这里补全协议，实在不像网址的才判为非法。
function normalizeHomepage(v) {
  const s = cleanStr(v, 300);
  if (!s) return '';
  let u = s;
  if (!/^https?:\/\//i.test(u)) u = 'https://' + u;
  return /^https?:\/\/[a-z0-9-]+(\.[a-z0-9-]+)+([:/?#][^\s]*)?$/i.test(u) ? u : '';
}

// 解析主页字段：返回 { value, invalid }——invalid 时调用方应报 400 提示用户，
// 而不是静默写成空串（静默清空 == 用户看到"内容没了"）
function readHomepage(raw) {
  const s = cleanStr(raw, 300);
  if (!s) return { value: '', invalid: false };
  const value = normalizeHomepage(s);
  return { value, invalid: !value };
}

// 删除内容时顺带清掉挂在它上面的评论/点赞/收藏/分享：
// 这些表用 target_type + target_id 关联，没有外键约束，主记录删掉后会留下孤儿行，
// 既污染统计数字，也会让「我的收藏」里出现打不开的条目。
const INTERACTION_TABLES = ['comments', 'likes', 'favorites', 'shares'];
function purgeTarget(type, id) {
  for (const tb of INTERACTION_TABLES) {
    try { db.prepare(`DELETE FROM ${tb} WHERE target_type = ? AND target_id = ?`).run(type, id); } catch (_) { /* 表结构差异不阻断删除 */ }
  }
}

// ---------- 图片上传 ----------
const UPLOAD_DIR = path.join(__dirname, '..', 'data', 'uploads');
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });

const ALLOWED_EXT = ['.jpg', '.jpeg', '.png', '.gif', '.webp', '.avif'];
const MAGIC = [
  { bytes: [0xff, 0xd8, 0xff], ext: '.jpg' },
  { bytes: [0x89, 0x50, 0x4e, 0x47], ext: '.png' },
  { bytes: [0x47, 0x49, 0x46, 0x38], ext: '.gif' },
  { bytes: [0x52, 0x49, 0x46, 0x46], ext: '.webp' }, // RIFF（webp/avif 需再校验扩展名白名单）
];

const storage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, UPLOAD_DIR),
  filename: (_req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    const safeExt = ALLOWED_EXT.includes(ext) ? ext : '.bin';
    cb(null, crypto.randomBytes(16).toString('hex') + safeExt);
  },
});

const upload = multer({
  storage,
  limits: { fileSize: 8 * 1024 * 1024, files: 1 },
  fileFilter: (_req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    if (!ALLOWED_EXT.includes(ext)) return cb(new Error('仅支持 jpg/png/gif/webp/avif 图片'));
    cb(null, true);
  },
});

// 文件魔数校验（防止伪装扩展名）
function verifyMagic(filePath, ext) {
  try {
    const fd = fs.openSync(filePath, 'r');
    const buf = Buffer.alloc(4);
    fs.readSync(fd, buf, 0, 4, 0);
    fs.closeSync(fd);
    if (ext === '.avif') return true; // avif 魔数与 webp 同容器，依赖扩展名白名单
    return MAGIC.some((m) => m.bytes.every((b, i) => buf[i] === b));
  } catch (_) {
    return false;
  }
}

router.post('/upload', (req, res) => {
  upload.single('file')(req, res, (err) => {
    if (err) return res.status(400).json({ error: err.message || '上传失败' });
    if (!req.file) return res.status(400).json({ error: '未收到文件' });
    const ext = path.extname(req.file.filename).toLowerCase();
    if (!verifyMagic(req.file.path, ext)) {
      fs.unlinkSync(req.file.path);
      return res.status(400).json({ error: '文件内容与图片格式不符' });
    }
    const origName = fixFilename(req.file.originalname || '');
    const info = db.prepare('INSERT INTO images (filename, original_name, title, description, created_at) VALUES (?, ?, ?, ?, ?)')
      .run(req.file.filename, cleanStr(origName, 200), cleanStr(req.body.title || origName, 120), cleanStr(req.body.description, 500), Date.now());
    res.status(201).json({ id: info.lastInsertRowid, filename: req.file.filename, url: `/uploads/${req.file.filename}` });
  });
});

// ---------- 文章管理 ----------
router.post('/articles', (req, res) => {
  const { title, content } = req.body || {};
  const t = cleanStr(title, 120);
  const fmt = req.body.format === 'html' ? 'html' : 'md';
  const c = typeof content === 'string'
    ? (fmt === 'html' ? sanitizeHtml(content) : content).slice(0, 100000)
    : '';
  if (!t || !c) return res.status(400).json({ error: '标题与内容不能为空' });
  const now = Date.now();
  const slug = slugify(t);
  const info = db.prepare(
    'INSERT INTO articles (title, slug, summary, content, cover, tags, status, format, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)'
  ).run(t, slug, cleanStr(req.body.summary, 300), c, cleanStr(req.body.cover, 300), cleanStr(req.body.tags, 200),
        req.body.status === 'draft' ? 'draft' : 'published', fmt, now, now);
  res.status(201).json({ id: info.lastInsertRowid, slug });
});

// ---------- 文档导入（.md / .docx） ----------
let mammoth = null;
try { mammoth = require('mammoth'); } catch (_) { /* 未安装则不支持 docx */ }

const docUpload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 8 * 1024 * 1024, files: 1 },
});

router.post('/articles/import', (req, res) => {
  docUpload.single('file')(req, res, async (err) => {
    if (err) return res.status(400).json({ error: err.message || '文件读取失败' });
    if (!req.file) return res.status(400).json({ error: '未收到文件' });
    const name = fixFilename(req.file.originalname || '').toLowerCase();
    const baseTitle = fixFilename(req.file.originalname || '导入文档').replace(/\.(md|markdown|docx?|txt)$/i, '').slice(0, 120);
    try {
      if (/\.(md|markdown|txt)$/.test(name)) {
        const text = req.file.buffer.toString('utf8');
        if (!text.trim()) return res.status(400).json({ error: '文件内容为空' });
        return res.json({ title: baseTitle, content: text.slice(0, 100000), format: 'md' });
      }
      if (/\.docx$/.test(name)) {
        if (!mammoth) return res.status(500).json({ error: '服务端未安装 docx 解析依赖' });
        const r = await mammoth.convertToHtml({ buffer: req.file.buffer });
        const html = sanitizeHtml(r.value || '');
        if (!html.trim()) return res.status(400).json({ error: '未能从该 docx 中解析出内容' });
        return res.json({ title: baseTitle, content: html.slice(0, 100000), format: 'html' });
      }
      if (/\.doc$/.test(name)) {
        return res.status(400).json({ error: '旧版 .doc 格式不支持，请用 Word 另存为 .docx 后再导入' });
      }
      return res.status(400).json({ error: '仅支持 .md / .markdown / .txt / .docx 文件' });
    } catch (e) {
      console.error('[文档导入失败]', e.message);
      return res.status(500).json({ error: '文档解析失败：' + e.message });
    }
  });
});

// 按 id 读取文章（含草稿），供后台编辑使用
router.get('/articles/:id', (req, res) => {
  const art = db.prepare('SELECT * FROM articles WHERE id = ?').get(parseInt(req.params.id) || 0);
  if (!art) return res.status(404).json({ error: '文章不存在' });
  res.json({ article: art });
});

router.put('/articles/:id', (req, res) => {
  const art = db.prepare('SELECT id FROM articles WHERE id = ?').get(parseInt(req.params.id) || 0);
  if (!art) return res.status(404).json({ error: '文章不存在' });
  const fields = [];
  const vals = [];
  const map = { title: 120, summary: 300, cover: 300, tags: 200 };
  for (const [k, max] of Object.entries(map)) {
    if (req.body[k] !== undefined) { fields.push(`${k} = ?`); vals.push(cleanStr(req.body[k], max)); }
  }
  if (req.body.content !== undefined) {
    const fmt = req.body.format === 'html' ? 'html' : 'md';
    const raw = String(req.body.content);
    fields.push('content = ?');
    vals.push((fmt === 'html' ? sanitizeHtml(raw) : raw).slice(0, 100000));
    fields.push('format = ?');
    vals.push(fmt);
  }
  if (req.body.status === 'draft' || req.body.status === 'published') { fields.push('status = ?'); vals.push(req.body.status); }
  if (!fields.length) return res.status(400).json({ error: '没有需要更新的字段' });
  fields.push('updated_at = ?'); vals.push(Date.now()); vals.push(art.id);
  db.prepare(`UPDATE articles SET ${fields.join(', ')} WHERE id = ?`).run(...vals);
  res.json({ ok: true });
});

router.delete('/articles/:id', (req, res) => {
  const id = parseInt(req.params.id) || 0;
  // 返回受影响行数：前端据此判断"真的删掉了"还是"记录本就不存在"，
  // 避免出现点了删除却毫无变化、又查不出原因的情况。
  const info = db.prepare('DELETE FROM articles WHERE id = ?').run(id);
  if (info.changes) purgeTarget('article', id);
  res.json({ ok: true, deleted: info.changes });
});

router.post('/projects', (req, res) => {
  const t = cleanStr(req.body && req.body.title, 120);
  const url = cleanStr(req.body && req.body.repo_url, 300);
  if (!t || !/^https:\/\/github\.com\/[\w.-]+\/[\w.-]+$/.test(url)) {
    return res.status(400).json({ error: '标题与 GitHub 仓库地址（https://github.com/user/repo）不能为空' });
  }
  const home = readHomepage(req.body && req.body.homepage);
  if (home.invalid) return res.status(400).json({ error: '项目主页需形如 https://example.com（可省略 https://）' });
  const info = db.prepare('INSERT INTO projects (title, repo_url, description, tags, icon, homepage, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)')
    .run(t, url, cleanStr(req.body.description, 1000), cleanStr(req.body.tags, 200), cleanStr(req.body.icon || '', 16), home.value, Date.now());
  res.status(201).json({ id: info.lastInsertRowid });
});

router.put('/projects/:id', (req, res) => {
  const id = parseInt(req.params.id) || 0;
  // 先取现有记录：只有"确实传了"的字段才覆盖，缺失字段一律保留原值。
  // 这是「编辑保存后 About 链接 / 描述 / 话题 / 图标消失」的根因防线——
  // 只要请求体里少了某个键（前端表单重构、旧缓存脚本、接口直调），
  // 早期版本会把它写成空串，前端看起来就是内容凭空消失。
  const cur = db.prepare('SELECT * FROM projects WHERE id = ?').get(id);
  if (!cur) return res.status(404).json({ error: '项目不存在' });
  const b = req.body || {};
  const t = b.title === undefined ? (cur.title || '') : cleanStr(b.title, 120);
  const url = b.repo_url === undefined ? (cur.repo_url || '') : cleanStr(b.repo_url, 300);
  if (!t) return res.status(400).json({ error: '项目名称不能为空' });
  if (!/^https:\/\/github\.com\/[\w.-]+\/[\w.-]+$/.test(url)) {
    return res.status(400).json({ error: '仓库地址需形如 https://github.com/user/repo' });
  }
  const description = b.description === undefined ? (cur.description || '') : cleanStr(b.description, 1000);
  const tags = b.tags === undefined ? (cur.tags || '') : cleanStr(b.tags, 200);
  const icon = b.icon === undefined ? (cur.icon || '') : cleanStr(b.icon || '', 16);
  // 主页：空表示不填（清空），非空但格式不对则明确报错，绝不静默丢弃
  let homepage = cur.homepage || '';
  if (b.homepage !== undefined) {
    const home = readHomepage(b.homepage);
    if (home.invalid) return res.status(400).json({ error: '项目主页需形如 https://example.com（可省略 https://）' });
    homepage = home.value;
  }
  db.prepare('UPDATE projects SET title = ?, repo_url = ?, description = ?, tags = ?, icon = ?, homepage = ? WHERE id = ?')
    .run(t, url, description, tags, icon, homepage, id);

  // 换了仓库地址就必须丢掉旧的 README / GitHub 元数据缓存：
  // 这两个缓存只按时间失效，不认仓库，换仓后仍返回旧仓库的数据，
  // 前台就会显示"上一个仓库的内容"（或旧仓库没数据 → 看起来像内容凭空消失）。
  if (url !== (cur.repo_url || '')) {
    try {
      db.prepare('UPDATE projects SET readme = NULL, readme_fetched_at = NULL, gh_meta = NULL, gh_meta_fetched_at = NULL WHERE id = ?').run(id);
    } catch (_) { /* 老库可能没有这些列，忽略即可 */ }
  }

  res.json({ ok: true, project: db.prepare('SELECT * FROM projects WHERE id = ?').get(id) });
});

// 编辑时取全量记录：前端「编辑」按钮不再依赖列表接口的字段，
// 保证表单里填的一定是库里的真实值（列表接口为省流量可能裁剪字段）
router.get('/projects/:id', (req, res) => {
  const p = db.prepare('SELECT * FROM projects WHERE id = ?').get(parseInt(req.params.id) || 0);
  if (!p) return res.status(404).json({ error: '项目不存在' });
  res.json({ project: p });
});

router.delete('/projects/:id', (req, res) => {
  const id = parseInt(req.params.id) || 0;
  const info = db.prepare('DELETE FROM projects WHERE id = ?').run(id);
  if (info.changes) purgeTarget('project', id);
  res.json({ ok: true, deleted: info.changes });
});

// ---------- 赞助删除 ----------
router.delete('/sponsors/:id', (req, res) => {
  const info = db.prepare('DELETE FROM sponsors WHERE id = ?').run(parseInt(req.params.id) || 0);
  res.json({ ok: true, deleted: info.changes });
});

// ---------- 图库 ----------
// 编辑时取全量记录：前端「编辑」按钮用它回填表单，避免依赖列表接口
router.get('/images/:id', (req, res) => {
  const img = db.prepare('SELECT * FROM images WHERE id = ?').get(parseInt(req.params.id) || 0);
  if (!img) return res.status(404).json({ error: '图片不存在' });
  res.json({ image: img });
});

router.delete('/images/:id', (req, res) => {
  const id = parseInt(req.params.id) || 0;
  const img = db.prepare('SELECT id, filename FROM images WHERE id = ?').get(id);
  if (img && img.filename) {
    // 磁盘文件可能早就被手工清理/迁移走（例如之前发现的孤儿记录）。
    // 这里的 unlink 必须吞掉异常：一旦抛出就会 500，前端拿不到 ok，
    // 连数据库记录都删不掉——正是"点了删除没反应"的元凶之一。
    try { fs.unlinkSync(path.join(UPLOAD_DIR, img.filename)); } catch (_) { /* 文件不存在也算删除成功 */ }
  }
  const info = db.prepare('DELETE FROM images WHERE id = ?').run(id);
  if (info.changes) purgeTarget('image', id);
  res.json({ ok: true, deleted: info.changes });
});

// 编辑已发布图片：更新标题/描述；若上传了新文件则替换并删除旧文件（filename 同步更新）
router.put('/images/:id', (req, res) => {
  upload.single('file')(req, res, (err) => {
    if (err) return res.status(400).json({ error: err.message || '上传失败' });
    const id = parseInt(req.params.id, 10) || 0;
    const img = db.prepare('SELECT * FROM images WHERE id = ?').get(id);
    if (!img) return res.status(404).json({ error: '图片不存在' });

    // 若上传了新图片，先校验魔数、删除旧文件，再使用新文件名
    let filename = img.filename;
    if (req.file) {
      const ext = path.extname(req.file.filename).toLowerCase();
      if (!verifyMagic(req.file.path, ext)) {
        fs.unlinkSync(req.file.path);
        return res.status(400).json({ error: '文件内容与图片格式不符' });
      }
      const oldPath = path.join(UPLOAD_DIR, img.filename);
      if (fs.existsSync(oldPath)) { try { fs.unlinkSync(oldPath); } catch (_) {} }
      filename = req.file.filename;
    }

    const title = cleanStr(req.body.title !== undefined ? (req.body.title || '') : (img.title || ''), 120);
    const description = cleanStr(req.body.description !== undefined ? (req.body.description || '') : (img.description || ''), 500);
    // hidden：隐藏后不进前台图库与搜索（赞助二维码等用途性图片），后台仍可见
    const hidden = req.body.hidden !== undefined ? (req.body.hidden ? 1 : 0) : ((img.hidden || 0) ? 1 : 0);
    db.prepare('UPDATE images SET title = ?, description = ?, filename = ?, hidden = ? WHERE id = ?')
      .run(title, description, filename, hidden, id);
    res.json({ ok: true, filename, hidden });
  });
});

// ---------- 评论管理 ----------
router.get('/comments', (_req, res) => {
  const rows = db.prepare(
    `SELECT c.id, c.target_type, c.target_id, c.content, c.status, c.created_at, u.username
     FROM comments c JOIN users u ON u.id = c.user_id ORDER BY c.created_at DESC LIMIT 200`
  ).all();
  res.json({ items: rows });
});

router.put('/comments/:id', (req, res) => {
  if (req.body.status !== 'visible' && req.body.status !== 'hidden') return res.status(400).json({ error: '无效状态' });
  db.prepare('UPDATE comments SET status = ? WHERE id = ?').run(req.body.status, parseInt(req.params.id) || 0);
  res.json({ ok: true });
});

router.delete('/comments/:id', (req, res) => {
  const info = db.prepare('DELETE FROM comments WHERE id = ?').run(parseInt(req.params.id) || 0);
  res.json({ ok: true, deleted: info.changes });
});

// ---------- 赞助记录 ----------
router.post('/sponsors', (req, res) => {
  const name = cleanStr(req.body && req.body.name, 60);
  if (!name) return res.status(400).json({ error: '赞助者名称不能为空' });
  const amount = Number(req.body.amount);
  db.prepare('INSERT INTO sponsors (name, amount, message, created_at) VALUES (?, ?, ?, ?)')
    .run(name, Number.isFinite(amount) && amount > 0 ? amount : null, cleanStr(req.body.message, 300), Date.now());
  res.status(201).json({ ok: true });
});

// ---------- 条款编辑 ----------
router.put('/terms', (req, res) => {
  // 内容必须是字符串：若前端误传 null/undefined，这里宁可报错也不要把已有条款清成空
  if (typeof req.body.content !== 'string') return res.status(400).json({ error: '条款内容不能为空' });
  const content = req.body.content.slice(0, 50000);
  db.prepare("INSERT INTO settings (key, value) VALUES ('terms', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value").run(content);
  writeTermsFile(content);
  res.json({ ok: true });
});

// 从服务器项目根目录的 terms.md 导入到数据库（等价于 node seed-terms.js，但可在后台一键操作）
router.post('/terms/import', (req, res) => {
  const termsPath = path.join(__dirname, '..', 'terms.md');
  if (!fs.existsSync(termsPath)) {
    return res.status(404).json({ error: '服务器项目根目录未找到 terms.md，请先用「选择本地文件导入」，或用宝塔/FTP 把它放到项目根目录' });
  }
  const content = fs.readFileSync(termsPath, 'utf8');
  db.prepare("INSERT INTO settings (key, value) VALUES ('terms', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value").run(content);
  res.json({ ok: true, length: content.length });
});

// 直接以文本导入（前端读取本地 .md 文件后提交，避免依赖服务器上是否存在该文件）
router.post('/terms/import-text', (req, res) => {
  const content = typeof req.body.content === 'string' ? req.body.content.slice(0, 50000) : '';
  if (!content) return res.status(400).json({ error: '内容为空' });
  db.prepare("INSERT INTO settings (key, value) VALUES ('terms', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value").run(content);
  writeTermsFile(content);
  res.json({ ok: true, length: content.length });
});

// ---------- 数据统计 ----------
router.get('/stats', (_req, res) => {
  const count = (sql) => db.prepare(sql).get().c;
  res.json({
    users: count('SELECT COUNT(*) c FROM users'),
    articles: count("SELECT COUNT(*) c FROM articles WHERE status = 'published'"),
    images: count('SELECT COUNT(*) c FROM images'),
    projects: count('SELECT COUNT(*) c FROM projects'),
    comments: count("SELECT COUNT(*) c FROM comments WHERE status = 'visible'"),
    likes: count('SELECT COUNT(*) c FROM likes'),
    totalViews: count('SELECT (SELECT COALESCE(SUM(views),0) FROM articles) + (SELECT COALESCE(SUM(views),0) FROM images) + (SELECT COALESCE(SUM(views),0) FROM projects) c'),
  });
});

// ---------- 公告管理（站长发布） ----------
const ANNOUNCE_TAGS = ['update', 'maintenance', 'action', 'important', 'event', 'other'];
function cleanTag(v) { return ANNOUNCE_TAGS.includes(v) ? v : 'other'; }

router.get('/announcements', (_req, res) => {
  const rows = db.prepare('SELECT * FROM announcements ORDER BY pinned DESC, created_at DESC').all();
  res.json({ items: rows });
});

router.post('/announcements', (req, res) => {
  const title = cleanStr(req.body && req.body.title, 120);
  if (!title) return res.status(400).json({ error: '公告标题不能为空' });
  const now = Date.now();
  const info = db.prepare('INSERT INTO announcements (title, content, tag, pinned, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)')
    .run(title, cleanStr(req.body.content, 20000), cleanTag(req.body.tag), req.body.pinned ? 1 : 0, now, now);
  res.status(201).json({ id: info.lastInsertRowid });
});

// 编辑：只更新传入的字段，避免局部提交把内容清空
router.put('/announcements/:id', (req, res) => {
  const id = parseInt(req.params.id) || 0;
  const cur = db.prepare('SELECT * FROM announcements WHERE id = ?').get(id);
  if (!cur) return res.status(404).json({ error: '公告不存在' });
  const b = req.body || {};
  const title = b.title === undefined ? (cur.title || '') : cleanStr(b.title, 120);
  if (!title) return res.status(400).json({ error: '公告标题不能为空' });
  const content = b.content === undefined ? (cur.content || '') : cleanStr(b.content, 20000);
  const tag = b.tag === undefined ? (cur.tag || 'other') : cleanTag(b.tag);
  const pinned = b.pinned === undefined ? !!cur.pinned : !!b.pinned;
  db.prepare('UPDATE announcements SET title = ?, content = ?, tag = ?, pinned = ?, updated_at = ? WHERE id = ?')
    .run(title, content, tag, pinned ? 1 : 0, Date.now(), id);
  res.json({ ok: true });
});

router.delete('/announcements/:id', (req, res) => {
  const info = db.prepare('DELETE FROM announcements WHERE id = ?').run(parseInt(req.params.id) || 0);
  res.json({ ok: true, deleted: info.changes });
});

// ---------- 社交媒体动态 ----------
router.get('/social', (_req, res) => {
  const rows = db.prepare('SELECT * FROM social_posts ORDER BY created_at DESC LIMIT 100').all();
  res.json({ items: rows });
});

// 编辑时取全量记录（与文章一致）：表单回填不依赖列表接口的字段裁剪
router.get('/social/:id', (req, res) => {
  const s = db.prepare('SELECT * FROM social_posts WHERE id = ?').get(parseInt(req.params.id) || 0);
  if (!s) return res.status(404).json({ error: '动态不存在' });
  res.json({ social: s });
});

router.post('/social', (req, res) => {
  const title = cleanStr(req.body && req.body.title, 120);
  const url = cleanStr(req.body && req.body.url, 300);
  if (!title || !url) return res.status(400).json({ error: '标题与链接不能为空' });
  if (!/^https?:\/\/.+/i.test(url)) return res.status(400).json({ error: '链接需以 http(s):// 开头' });
  const platform = ['bilibili', 'youtube', 'weibo', 'x', 'github', 'other'].includes(req.body.platform) ? req.body.platform : 'bilibili';
  const info = db.prepare(
    'INSERT INTO social_posts (platform, title, url, cover, description, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)'
  ).run(platform, title, url, cleanStr(req.body.cover, 300), cleanStr(req.body.description, 500),
        req.body.status === 'draft' ? 'draft' : 'published', Date.now());
  res.status(201).json({ id: info.lastInsertRowid });
});

router.put('/social/:id', (req, res) => {
  const id = parseInt(req.params.id) || 0;
  if (!db.prepare('SELECT id FROM social_posts WHERE id = ?').get(id)) return res.status(404).json({ error: '动态不存在' });
  const fields = [];
  const vals = [];
  const map = { title: 120, url: 300, cover: 300, description: 500 };
  for (const [k, max] of Object.entries(map)) {
    if (req.body[k] !== undefined) { fields.push(`${k} = ?`); vals.push(cleanStr(req.body[k], max)); }
  }
  if (['bilibili', 'youtube', 'weibo', 'x', 'github', 'other'].includes(req.body.platform)) { fields.push('platform = ?'); vals.push(req.body.platform); }
  if (req.body.status === 'draft' || req.body.status === 'published') { fields.push('status = ?'); vals.push(req.body.status); }
  if (!fields.length) return res.status(400).json({ error: '没有需要更新的字段' });
  vals.push(id);
  db.prepare(`UPDATE social_posts SET ${fields.join(', ')} WHERE id = ?`).run(...vals);
  res.json({ ok: true });
});

router.delete('/social/:id', (req, res) => {
  const info = db.prepare('DELETE FROM social_posts WHERE id = ?').run(parseInt(req.params.id) || 0);
  res.json({ ok: true, deleted: info.changes });
});

// ---------- 用户管理 ----------
router.get('/users', (_req, res) => {
  const rows = db.prepare(
    `SELECT id, username, email, role, avatar, banned, banned_from, banned_until, created_at, last_login_at, last_ip
     FROM users ORDER BY id ASC`
  ).all();
  res.json({ items: rows });
});

router.put('/users/:id', (req, res) => {
  const id = parseInt(req.params.id) || 0;
  if (id === req.user.id) return res.status(400).json({ error: '不能修改自己的角色或封禁状态' });
  const u = db.prepare('SELECT id, username FROM users WHERE id = ?').get(id);
  if (!u) return res.status(404).json({ error: '用户不存在' });
  const fields = [];
  const vals = [];
  if (req.body.role === 'admin' || req.body.role === 'user') { fields.push('role = ?'); vals.push(req.body.role); }
  if (typeof req.body.banned === 'boolean') {
    fields.push('banned = ?'); vals.push(req.body.banned ? 1 : 0);
    // 封禁起/终：前端传毫秒时间戳或 null（解封时一并清空）
    const from = Number.isFinite(req.body.banned_from) ? req.body.banned_from : null;
    const until = Number.isFinite(req.body.banned_until) ? req.body.banned_until : null;
    fields.push('banned_from = ?'); vals.push(from);
    fields.push('banned_until = ?'); vals.push(until);
  }
  if (!fields.length) return res.status(400).json({ error: '没有需要更新的字段' });
  vals.push(id);
  db.prepare(`UPDATE users SET ${fields.join(', ')} WHERE id = ?`).run(...vals);
  console.log(`[安全] 管理员调整用户 ${u.username}: ${fields.join(', ')}`);
  res.json({ ok: true });
});

router.delete('/users/:id', (req, res) => {
  const id = parseInt(req.params.id) || 0;
  if (id === req.user.id) return res.status(400).json({ error: '不能删除自己' });
  const u = db.prepare('SELECT id, username FROM users WHERE id = ?').get(id);
  if (!u) return res.status(404).json({ error: '用户不存在' });
  const tx = db.transaction(() => {
    db.prepare('DELETE FROM comments WHERE user_id = ?').run(id);
    db.prepare('DELETE FROM likes WHERE user_id = ?').run(id);
    db.prepare('DELETE FROM favorites WHERE user_id = ?').run(id);
    db.prepare('DELETE FROM shares WHERE user_id = ?').run(id);
    db.prepare('DELETE FROM users WHERE id = ?').run(id);
  });
  tx();
  console.log(`[安全] 管理员删除用户 ${u.username}`);
  res.json({ ok: true, deleted: 1 });
});

// ---------- IP 封禁 ----------
// 封禁一个 IP = 切断该 IP 下所有账号的进入通道（由 server.js 的中间件统一拦截）
function normIp(v) {
  return cleanStr(normalizeIp(v), 64);
}

router.get('/ipbans', (_req, res) => {
  const rows = db.prepare('SELECT ip, reason, until, created_at, created_by FROM ip_bans ORDER BY created_at DESC').all();
  const countStmt = db.prepare('SELECT COUNT(*) c FROM users WHERE last_ip = ?');
  const items = rows.map((r) => ({ ...r, accounts: countStmt.get(r.ip).c }));
  res.json({ items });
});

// 某个 IP 下的所有账号（封禁前先看看会波及谁）
router.get('/ipbans/accounts', (req, res) => {
  const ip = normIp(req.query.ip);
  if (!ip) return res.json({ items: [] });
  const items = db.prepare(
    'SELECT id, username, email, role, banned, last_login_at FROM users WHERE last_ip = ? ORDER BY id ASC'
  ).all(ip);
  res.json({ items });
});

router.post('/ipbans', (req, res) => {
  const ip = normIp(req.body && req.body.ip);
  if (!ip) return res.status(400).json({ error: '请填写要封禁的 IP' });
  // 自锁保护：管理员不能封禁自己当前所在的 IP，否则会把自己关在门外
  if (ip === normalizeIp(req.ip)) return res.status(400).json({ error: '不能封禁你自己当前所在的 IP' });
  const reason = cleanStr((req.body && req.body.reason) || '', 200);
  const until = Number.isFinite(req.body && req.body.until) && req.body.until > 0 ? Math.trunc(req.body.until) : null;
  db.prepare(
    `INSERT INTO ip_bans (ip, reason, until, created_at, created_by) VALUES (?, ?, ?, ?, ?)
     ON CONFLICT(ip) DO UPDATE SET reason = excluded.reason, until = excluded.until,
                                   created_at = excluded.created_at, created_by = excluded.created_by`
  ).run(ip, reason, until, Date.now(), req.user.id);
  console.log(`[安全] 管理员封禁 IP ${ip}${until ? '，至 ' + new Date(until).toISOString() : '（永久）'}；原因：${reason || '未填写'}`);
  res.json({ ok: true });
});

router.delete('/ipbans/:ip', (req, res) => {
  const ip = normIp(decodeURIComponent(req.params.ip || ''));
  if (!ip) return res.status(400).json({ error: 'IP 不能为空' });
  db.prepare('DELETE FROM ip_bans WHERE ip = ?').run(ip);
  console.log(`[安全] 管理员解除 IP 封禁 ${ip}`);
  res.json({ ok: true });
});

// ---------- 站点私有资源上传（赞助二维码等，隔离于公共图库） ----------
// 关键：写入 data/private/ 独立目录（不被 /uploads 静态托管，杜绝直链枚举），
// 且【不】写入 images 表 → 不进图库列表、不进搜索、不进公共画廊。
const PRIVATE_DIR = path.join(__dirname, '..', 'data', 'private');
if (!fs.existsSync(PRIVATE_DIR)) fs.mkdirSync(PRIVATE_DIR, { recursive: true });

const privateUpload = multer({
  storage: multer.diskStorage({
    destination: (_r, _f, cb) => cb(null, PRIVATE_DIR),
    filename: (_r, file, cb) => {
      const ext = path.extname(file.originalname).toLowerCase();
      const safeExt = ALLOWED_EXT.includes(ext) ? ext : '.bin';
      cb(null, crypto.randomBytes(16).toString('hex') + safeExt);
    },
  }),
  limits: { fileSize: 4 * 1024 * 1024, files: 1 },
  fileFilter: (_r, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    if (!ALLOWED_EXT.includes(ext)) return cb(new Error('仅支持 jpg/png/gif/webp/avif 图片'));
    cb(null, true);
  },
});

// 校验 + 覆盖式保存：同一 kind 只保留最新一份（赞助二维码场景）
router.post('/site-asset/:kind', (req, res) => {
  const kind = cleanStr(req.params.kind, 40);
  if (!/^[a-z0-9_-]+$/.test(kind)) return res.status(400).json({ error: '非法的资源类型' });
  privateUpload.single('file')(req, res, (err) => {
    if (err) return res.status(400).json({ error: err.message || '上传失败' });
    if (!req.file) return res.status(400).json({ error: '未收到文件' });
    const ext = path.extname(req.file.filename).toLowerCase();
    if (!verifyMagic(req.file.path, ext)) {
      try { fs.unlinkSync(req.file.path); } catch (_) {}
      return res.status(400).json({ error: '文件内容与图片格式不符' });
    }
    // 删除同 kind 旧文件（覆盖式）
    try {
      const old = db.prepare('SELECT filename FROM site_assets WHERE kind = ?').get(kind);
      if (old && old.filename) { try { fs.unlinkSync(path.join(PRIVATE_DIR, old.filename)); } catch (_) {} }
    } catch (_) {}
    db.prepare('INSERT INTO site_assets (kind, filename, created_at) VALUES (?, ?, ?) ON CONFLICT(kind) DO UPDATE SET filename = excluded.filename, created_at = excluded.created_at')
      .run(kind, req.file.filename, Date.now());
    console.log(`[安全] 管理员上传站点私有资源 ${kind}（不入公共图库）`);
    // 返回受控端点 URL：固定单资源、无枚举
    res.status(201).json({ ok: true, url: `/api/asset/${kind}` });
  });
});

// ---------- 站点设置 ----------
const SETTING_KEYS = ['site_name', 'site_slogan', 'footer_text', 'icp', 'sponsor_qr'];
// 赞助二维码设置值改为受控端点路径（而非 /uploads 直链），避免出现在图库/被枚举
const CONTROLLED_ASSET_KINDS = ['sponsor_qr'];

router.get('/settings', (_req, res) => {
  const rows = db.prepare('SELECT key, value FROM settings').all();
  const out = {};
  for (const k of SETTING_KEYS) out[k] = '';
  for (const r of rows) out[r.key] = r.value || '';
  res.json(out);
});

router.put('/settings', (req, res) => {
  const stmt = db.prepare("INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value");
  const tx = db.transaction(() => {
    for (const k of SETTING_KEYS) {
      if (req.body[k] === undefined) continue;
      let v = typeof req.body[k] === 'string' ? req.body[k].slice(0, 500) : '';
      // 赞助二维码只能存受控端点路径（/api/asset/...）或空，禁止写入 /uploads 直链，
      // 否则会被公共图库/搜索索引、且可被直链枚举。
      if (k === 'sponsor_qr' && v && !/^\/api\/asset\/[a-z0-9_-]+$/.test(v)) {
        v = '';
      }
      stmt.run(k, v);
    }
  });
  tx();
  res.json({ ok: true });
});

function slugify(title) {
  const base = cleanStr(title, 80).replace(/[^\p{L}\p{N}\s-]/gu, '').replace(/\s+/g, '-').toLowerCase() || 'post';
  return `${base}-${Date.now().toString(36)}`;
}

// ================= 社区化配置（仅站长 owner 可配置成就/倍率/称号/兑换码） =================
// ---------- 称号 ----------
router.get('/titles', requireAdmin, (_req, res) => {
  res.json({ titles: community.listTitles() });
});
router.post('/titles', requireAdmin, (req, res) => {
  const b = req.body || {};
  const r = community.createTitle({ key: b.key, name: b.name, desc: b.desc, icon: b.icon, color: b.color, grantType: b.grantType, autoRule: b.autoRule }, req.user.id);
  if (r.error) return res.status(400).json(r);
  res.json(r);
});
router.put('/titles/:id', requireAdmin, (req, res) => {
  const b = req.body || {};
  const r = community.updateTitle(parseInt(req.params.id) || 0, { name: b.name, desc: b.desc, icon: b.icon, color: b.color }, req.user.id);
  if (r.error) return res.status(400).json(r);
  res.json(r);
});
router.delete('/titles/:id', requireAdmin, (req, res) => {
  const r = community.deleteTitle(parseInt(req.params.id) || 0, req.user.id);
  if (r.error) return res.status(400).json(r);
  res.json(r);
});
router.post('/titles/grant', requireAdmin, (req, res) => {
  const b = req.body || {};
  const uid = parseInt(b.userId || b.user_id) || 0;
  const r = b.titleKey ? community.grantTitleByKey(uid, b.titleKey, b.expireAt || null, req.user.id)
                        : community.grantTitle(uid, parseInt(b.titleId) || 0, b.expireAt || null, req.user.id);
  if (r.error) return res.status(400).json(r);
  res.json(r);
});
router.post('/titles/revoke', requireAdmin, (req, res) => {
  const b = req.body || {};
  const r = community.revokeTitle(parseInt(b.userId || b.user_id) || 0, parseInt(b.titleId) || 0, req.user.id);
  if (r.error) return res.status(400).json(r);
  res.json(r);
});

// ---------- 成就（定义 + 手动发放/撤销） ----------
router.get('/achievements', requireAdmin, (_req, res) => {
  res.json({ achievements: community.getAchievements() });
});
router.post('/achievements', requireAdmin, (req, res) => {
  const b = req.body || {};
  const cond = JSON.stringify(b.condition || {});
  const mult = b.multiplier ? JSON.stringify(b.multiplier) : null;
  const xp = parseInt(b.reward_xp) || 0;
  if (b.id) {
    db.prepare("UPDATE achievements SET name=?,desc=?,icon=?,condition=?,reward_xp=?,multiplier=?,updated_at=? WHERE id=?")
      .run(b.name, b.desc || '', b.icon || '', cond, xp, mult, Date.now(), parseInt(b.id));
    res.json({ ok: true, id: parseInt(b.id) });
  } else {
    const key = String(b.key || '').trim();
    if (!key) return res.status(400).json({ error: '缺少 key' });
    if (db.prepare('SELECT id FROM achievements WHERE key = ?').get(key)) return res.status(400).json({ error: 'key 已存在' });
    const info = db.prepare("INSERT INTO achievements (key,name,desc,icon,condition,reward_xp,multiplier,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?)")
      .run(key, b.name || key, b.desc || '', b.icon || '', cond, xp, mult, Date.now(), Date.now());
    res.json({ ok: true, id: info.lastInsertRowid });
  }
});
router.post('/achievements/:id/grant', requireAdmin, (req, res) => {
  const b = req.body || {};
  const r = community.grantAchievement(parseInt(b.userId || b.user_id) || 0, parseInt(req.params.id) || 0, b.idempotency_key || null, req.user.id);
  if (r.error) return res.status(400).json(r);
  res.json(r);
});
router.post('/achievements/:id/revoke', requireAdmin, (req, res) => {
  const b = req.body || {};
  const r = community.revokeAchievement(parseInt(b.userId || b.user_id) || 0, parseInt(req.params.id) || 0, req.user.id);
  if (r.error) return res.status(400).json(r);
  res.json(r);
});
router.delete('/achievements/:id', requireAdmin, (req, res) => {
  const id = parseInt(req.params.id) || 0;
  const a = db.prepare('SELECT key FROM achievements WHERE id = ?').get(id);
  if (!a) return res.status(404).json({ error: '成就不存在' });
  db.prepare('DELETE FROM user_achievements WHERE achievement_id = ?').run(id);
  db.prepare('DELETE FROM achievement_progress WHERE achievement_id = ?').run(id);
  db.prepare("DELETE FROM multipliers WHERE source='achievement' AND ref_id=?").run(id);
  db.prepare('DELETE FROM achievements WHERE id = ?').run(id);
  audit(req.user.id, 'owner', 'delete_achievement', 'achievement', a.key, {});
  res.json({ ok: true });
});

// ---------- 倍率规则（owner 配置；签到基础经验默认不参与） ----------
router.get('/multipliers', requireAdmin, (_req, res) => {
  res.json({ multipliers: db.prepare('SELECT * FROM multipliers ORDER BY id').all() });
});
router.post('/multipliers', requireAdmin, (req, res) => {
  const b = req.body || {};
  const info = db.prepare("INSERT INTO multipliers (name,value,scope,starts_at,ends_at,stackable,global_cap,enabled,source,ref_id,created_at) VALUES (?,?,?,?,?,?,?,1,'manual',NULL,?)")
    .run(b.name || '倍率', Number(b.value) || 0, b.scope || 'nonsignin', b.starts_at || null, b.ends_at || null, b.stackable ? 1 : 0, typeof b.global_cap === 'number' ? b.global_cap : 2.0, Date.now());
  community.invalidateAllMultipliers();
  res.json({ ok: true, id: info.lastInsertRowid });
});
router.put('/multipliers/:id', requireAdmin, (req, res) => {
  const b = req.body || {};
  db.prepare("UPDATE multipliers SET name=?,value=?,scope=?,starts_at=?,ends_at=?,stackable=?,global_cap=?,enabled=? WHERE id=?")
    .run(b.name || '倍率', Number(b.value) || 0, b.scope || 'nonsignin', b.starts_at || null, b.ends_at || null, b.stackable ? 1 : 0, typeof b.global_cap === 'number' ? b.global_cap : 2.0, b.enabled ? 1 : 0, parseInt(req.params.id));
  community.invalidateAllMultipliers();
  res.json({ ok: true });
});
router.delete('/multipliers/:id', requireAdmin, (req, res) => {
  db.prepare('DELETE FROM multipliers WHERE id = ?').run(parseInt(req.params.id));
  community.invalidateAllMultipliers();
  res.json({ ok: true });
});

// ---------- 兑换码（生成 / 列表） ----------
router.get('/redeem-codes', requireAdmin, (_req, res) => {
  const rows = db.prepare('SELECT id, code, title, reward, max_uses, used_count, per_user_once, expires_at, created_at FROM redeem_codes ORDER BY id DESC').all();
  res.json({ codes: rows });
});
router.post('/redeem-codes', requireAdmin, (req, res) => {
  const b = req.body || {};
  const code = community.generateRedeemCode({
    title: b.title, titleId: parseInt(b.titleId) || null,
    type: b.type || null, value: b.value, reward: b.reward || null,
    maxUses: parseInt(b.maxUses) || 1, perUserOnce: b.perUserOnce !== false ? 1 : 0, expiresAt: b.expiresAt || null,
    code: b.code || null,
  }, req.user.id);
  res.json({ ok: true, code });
});
// 批量随机生成兑换码（type：xp / achievement / title，值在对应类别内随机抽取）
router.post('/redeem-codes/random', requireAdmin, (req, res) => {
  const b = req.body || {};
  const type = ['xp', 'achievement', 'title'].includes(b.type) ? b.type : 'xp';
  const codes = community.generateRedeemCodesRandom({
    type, count: parseInt(b.count) || 1, title: b.title,
    maxUses: parseInt(b.maxUses) || 1, perUserOnce: b.perUserOnce !== false ? 1 : 0, expiresAt: b.expiresAt || null,
  }, req.user.id);
  res.json({ ok: true, codes });
});

// ---------- 等级标识颜色（站长自定义每个 Lv 的徽章颜色） ----------
router.get('/level-colors', requireAdmin, (_req, res) => {
  res.json({ colors: community.getLevelColors() });
});
router.put('/level-colors', requireAdmin, (req, res) => {
  const colors = community.setLevelColors((req.body && req.body.colors) || {});
  audit(req.user.id, 'owner', 'set_level_colors', 'settings', 'level_colors', { colors });
  res.json({ ok: true, colors });
});

// ---------- 任务（站长自定义；类型用于任务系统判定/展示） ----------
router.get('/tasks', requireAdmin, (_req, res) => {
  res.json({ tasks: db.prepare('SELECT * FROM tasks ORDER BY id').all() });
});
router.post('/tasks', requireAdmin, (req, res) => {
  const b = req.body || {};
  const key = cleanStr(b.key, 64);
  if (!key) return res.status(400).json({ error: '缺少任务标识 key' });
  if (!/^[a-zA-Z0-9_]+$/.test(key)) return res.status(400).json({ error: 'key 仅支持字母数字下划线' });
  if (db.prepare('SELECT id FROM tasks WHERE key = ?').get(key)) return res.status(400).json({ error: 'key 已存在' });
  const type = ['comment', 'like', 'favorite', 'download', 'online', 'custom'].includes(b.type) ? b.type : 'custom';
  const info = db.prepare('INSERT INTO tasks (key,name,desc,type,target_count,reward_xp,daily_cap,enabled) VALUES (?,?,?,?,?,?,?,1)')
    .run(key, cleanStr(b.name, 64) || key, cleanStr(b.desc, 200), type, Math.max(1, parseInt(b.target_count) || 1), Math.max(0, parseInt(b.reward_xp) || 0), Math.max(1, parseInt(b.daily_cap) || 1));
  audit(req.user.id, 'owner', 'create_task', 'task', key, { name: b.name });
  res.json({ ok: true, id: info.lastInsertRowid });
});
router.put('/tasks/:id', requireAdmin, (req, res) => {
  const id = parseInt(req.params.id) || 0;
  const t = db.prepare('SELECT * FROM tasks WHERE id = ?').get(id);
  if (!t) return res.status(404).json({ error: '任务不存在' });
  const b = req.body || {};
  const type = ['comment', 'like', 'favorite', 'download', 'online', 'custom'].includes(b.type) ? b.type : t.type;
  db.prepare('UPDATE tasks SET name=?, desc=?, type=?, target_count=?, reward_xp=?, daily_cap=?, enabled=? WHERE id=?')
    .run(cleanStr(b.name, 64) || t.name, cleanStr(b.desc, 200), type,
      Math.max(1, parseInt(b.target_count) || t.target_count), Math.max(0, parseInt(b.reward_xp) || t.reward_xp),
      Math.max(1, parseInt(b.daily_cap) || t.daily_cap), b.enabled !== undefined ? (b.enabled ? 1 : 0) : t.enabled, id);
  audit(req.user.id, 'owner', 'update_task', 'task', t.key, {});
  res.json({ ok: true });
});
router.delete('/tasks/:id', requireAdmin, (req, res) => {
  const id = parseInt(req.params.id) || 0;
  const t = db.prepare('SELECT * FROM tasks WHERE id = ?').get(id);
  if (!t) return res.status(404).json({ error: '任务不存在' });
  db.prepare('DELETE FROM tasks WHERE id = ?').run(id);
  audit(req.user.id, 'owner', 'delete_task', 'task', t.key, {});
  res.json({ ok: true });
});

// ---------- 站长定向发消息（审计 / 防冒充） ----------
router.post('/notify', requireAdmin, (req, res) => {
  const b = req.body || {};
  const title = cleanStr(b.title, 100) || '站内通知';
  const body = cleanStr(b.body || '', 1000);
  if (!body) return res.status(400).json({ error: '消息内容不能为空' });
  const uid = parseInt(b.userId || b.user_id) || 0;
  if (uid) {
    community.addNotification(uid, 'OWNER_MSG', title, body, JSON.stringify({ by: req.user.id }));
  } else {
    const users = db.prepare('SELECT id FROM users').all();
    const ins = db.prepare('INSERT INTO notifications (user_id, type, title, body, ref, created_at) VALUES (?, ?, ?, ?, ?, ?)');
    db.transaction(() => { for (const u of users) ins.run(u.id, 'OWNER_MSG', title, body, JSON.stringify({ by: req.user.id }), Date.now()); })();
  }
  audit(req.user.id, 'owner', 'owner_notify', 'notification', uid ? String(uid) : 'all', { title });
  res.json({ ok: true, count: uid ? 1 : db.prepare('SELECT COUNT(*) c FROM users').get().c });
});

// ---------- 个人名片审核（approve / reject / takedown） ----------
router.get('/cards', requireAdmin, (req, res) => {
  const status = cleanStr(req.query.status, 20) || 'pending';
  res.json({ cards: community.listCards(status) });
});
router.post('/cards/:userId/review', requireAdmin, (req, res) => {
  const uid = parseInt(req.params.userId) || 0;
  const b = req.body || {};
  const action = cleanStr(b.action, 20);
  const r = community.reviewCard(uid, action, cleanStr(b.reason, 200), req.user.id);
  if (r.error) return res.status(400).json(r);
  res.json(r);
});

// ---------- 隐私默认值（站长可配，影响新用户首次建档的默认可见性） ----------
router.get('/privacy-defaults', requireAdmin, (_req, res) => {
  res.json({ privacy: community.getDefaultPrivacy() });
});
router.put('/privacy-defaults', requireAdmin, (req, res) => {
  const p = community.setDefaultPrivacy((req.body && req.body.privacy) || {});
  audit(req.user.id, 'owner', 'set_privacy_defaults', 'settings', 'privacy_defaults', { privacy: p });
  res.json({ ok: true, privacy: p });
});

module.exports = router;
