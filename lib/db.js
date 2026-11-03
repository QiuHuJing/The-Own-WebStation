// 数据库层：better-sqlite3（同步、零依赖、单文件存储，内存占用极低）
const Database = require('better-sqlite3');
const path = require('path');
const fs = require('fs');

// 数据目录：默认项目根目录下的 data/；可用环境变量 WO_DATA_DIR 覆盖（便于隔离测试 / 迁移数据盘）
const DATA_DIR = process.env.WO_DATA_DIR ? path.resolve(process.env.WO_DATA_DIR) : path.join(__dirname, '..', 'data');
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

const db = new Database(path.join(DATA_DIR, 'webown.db'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL UNIQUE,
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'user',          -- user | admin
  created_at INTEGER NOT NULL,
  last_login_at INTEGER
);

CREATE TABLE IF NOT EXISTS consents (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER,                             -- 可为空（游客首次访问）
  type TEXT NOT NULL,                          -- visit | register | login
  ip TEXT,
  user_agent TEXT,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS articles (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  title TEXT NOT NULL,
  slug TEXT NOT NULL UNIQUE,
  summary TEXT DEFAULT '',
  content TEXT NOT NULL,                       -- Markdown
  cover TEXT,
  tags TEXT DEFAULT '',
  status TEXT NOT NULL DEFAULT 'published',    -- draft | published
  views INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS images (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  filename TEXT NOT NULL,
  original_name TEXT,
  title TEXT DEFAULT '',
  description TEXT DEFAULT '',
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS projects (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  title TEXT NOT NULL,
  repo_url TEXT NOT NULL,
  description TEXT DEFAULT '',
  tags TEXT DEFAULT '',
  cover TEXT,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS comments (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  target_type TEXT NOT NULL,                   -- article | image | project
  target_id INTEGER NOT NULL,
  user_id INTEGER NOT NULL,
  content TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'visible',      -- visible | hidden
  created_at INTEGER NOT NULL,
  FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS likes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  target_type TEXT NOT NULL,
  target_id INTEGER NOT NULL,
  user_id INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  UNIQUE(target_type, target_id, user_id)
);

CREATE TABLE IF NOT EXISTS favorites (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  target_type TEXT NOT NULL,
  target_id INTEGER NOT NULL,
  user_id INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  UNIQUE(target_type, target_id, user_id)
);

CREATE TABLE IF NOT EXISTS shares (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  target_type TEXT NOT NULL,
  target_id INTEGER NOT NULL,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS sponsors (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  amount REAL,
  message TEXT DEFAULT '',
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS social_posts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  platform TEXT NOT NULL DEFAULT 'bilibili',
  title TEXT NOT NULL,
  url TEXT NOT NULL,
  cover TEXT DEFAULT '',
  description TEXT DEFAULT '',
  status TEXT NOT NULL DEFAULT 'published',
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS login_attempts (
  ip TEXT PRIMARY KEY,
  fails INTEGER NOT NULL DEFAULT 0,
  locked_until INTEGER
);

-- 图形验证码：id 随机串，code 大写文本，一次性使用并有有效期（见 lib/captcha + routes/api）
CREATE TABLE IF NOT EXISTS captchas (
  id TEXT PRIMARY KEY,
  code TEXT NOT NULL,
  created_at INTEGER NOT NULL
);

-- IP 封禁：封禁一个 IP 即切断该 IP 下所有账号的进入通道
-- until 为 NULL 表示永久；到期后由 lib/auth.getIpBan 读取时自动清理
CREATE TABLE IF NOT EXISTS ip_bans (
  ip TEXT PRIMARY KEY,
  reason TEXT,
  until INTEGER,
  created_at INTEGER NOT NULL,
  created_by INTEGER
);

CREATE TABLE IF NOT EXISTS settings (
  key TEXT PRIMARY KEY,
  value TEXT
);

-- 公告：站长发布，前台公告板块展示；置顶公告对新用户/久未登录用户弹窗提醒
CREATE TABLE IF NOT EXISTS announcements (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  title TEXT NOT NULL,
  content TEXT NOT NULL DEFAULT '',          -- Markdown
  tag TEXT NOT NULL DEFAULT 'other',          -- update | maintenance | action | important | event | other
  pinned INTEGER NOT NULL DEFAULT 0,          -- 1=置顶
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
`);

// 轻量迁移：老库补列
const userCols = db.pragma('table_info(users)').map((c) => c.name);
if (!userCols.includes('avatar')) db.exec('ALTER TABLE users ADD COLUMN avatar TEXT');
if (!userCols.includes('banned')) db.exec('ALTER TABLE users ADD COLUMN banned INTEGER NOT NULL DEFAULT 0');
// 封禁时间区间：banned_from=起始(ms)、banned_until=结束(ms，NULL/0 表示永久)
if (!userCols.includes('banned_from')) db.exec('ALTER TABLE users ADD COLUMN banned_from INTEGER');
if (!userCols.includes('banned_until')) db.exec('ALTER TABLE users ADD COLUMN banned_until INTEGER');
// 最近一次登录的 IP：供后台「按 IP 封禁」定位该 IP 下的所有账号
if (!userCols.includes('last_ip')) db.exec('ALTER TABLE users ADD COLUMN last_ip TEXT');
// 上一次登录时间（登录时把旧的 last_login_at 挪到这里）：用于判断"久未登录"的回归用户
if (!userCols.includes('prev_login_at')) db.exec('ALTER TABLE users ADD COLUMN prev_login_at INTEGER');
// 最后已读公告时间：据此决定置顶公告是否再次弹窗
if (!userCols.includes('ann_read_at')) db.exec('ALTER TABLE users ADD COLUMN ann_read_at INTEGER');

// 归一化用户名列：解决 SQLite 默认 UNIQUE 为二进制排序的问题
// （username 的 UNIQUE 区分大小写，"Admin" 与 "admin" 会被视为不同、可重复入库，
//  但登录/注册用 COLLATE NOCASE 又会混为一谈）。统一用小写列 + 唯一索引，从 DB 层杜绝大小写重名。
if (!userCols.includes('username_lower')) {
  db.exec('ALTER TABLE users ADD COLUMN username_lower TEXT');
  db.exec("UPDATE users SET username_lower = lower(username) WHERE username_lower IS NULL");
  // 防御：若历史数据已存在大小写重复，保留每组最早一条，其余置空（UNIQUE 索引允许多个 NULL），避免建索引失败
  const dups = db.prepare('SELECT username_lower, COUNT(*) c FROM users GROUP BY username_lower HAVING COUNT(*) > 1').all();
  for (const d of dups) {
    const rows = db.prepare('SELECT id FROM users WHERE username_lower = ? ORDER BY created_at ASC').all(d.username_lower);
    for (let i = 1; i < rows.length; i++) db.prepare('UPDATE users SET username_lower = NULL WHERE id = ?').run(rows[i].id);
  }
  db.exec('CREATE UNIQUE INDEX IF NOT EXISTS uniq_username_lower ON users(username_lower)');
}

// 文章：format（md 源码 / html 富文本）
const artCols = db.pragma('table_info(articles)').map((c) => c.name);
if (!artCols.includes('format')) db.exec("ALTER TABLE articles ADD COLUMN format TEXT NOT NULL DEFAULT 'md'");

// 图片：浏览数（点赞/收藏/评论/分享已走通用互动表，此处仅补浏览数）
const imgCols = db.pragma('table_info(images)').map((c) => c.name);
if (!imgCols.includes('views')) db.exec('ALTER TABLE images ADD COLUMN views INTEGER NOT NULL DEFAULT 0');
// 隐藏：不进前台图库/搜索（用于赞助二维码等用途性图片，仍在后台可管理）
if (!imgCols.includes('hidden')) db.exec('ALTER TABLE images ADD COLUMN hidden INTEGER NOT NULL DEFAULT 0');

// 项目：浏览数 + 自定义展示图标 + GitHub README 缓存（服务端拉取后落库，减少重复请求）
const projCols = db.pragma('table_info(projects)').map((c) => c.name);
if (!projCols.includes('views')) db.exec('ALTER TABLE projects ADD COLUMN views INTEGER NOT NULL DEFAULT 0');
if (!projCols.includes('icon')) db.exec('ALTER TABLE projects ADD COLUMN icon TEXT');
if (!projCols.includes('readme')) db.exec('ALTER TABLE projects ADD COLUMN readme TEXT');
if (!projCols.includes('readme_fetched_at')) db.exec('ALTER TABLE projects ADD COLUMN readme_fetched_at INTEGER');
// GitHub 仓库元数据缓存（repo 信息/语言/贡献者/Release/文件列表/最新提交，整段 JSON 缓存）
if (!projCols.includes('gh_meta')) db.exec('ALTER TABLE projects ADD COLUMN gh_meta TEXT');
if (!projCols.includes('gh_meta_fetched_at')) db.exec('ALTER TABLE projects ADD COLUMN gh_meta_fetched_at INTEGER');
// 项目主页地址（GitHub 风格 About 侧栏展示的 homepage，可为空则回落到仓库主页）
if (!projCols.includes('homepage')) db.exec('ALTER TABLE projects ADD COLUMN homepage TEXT');

// ---------- 社区化 / 个人中心 / 等级成就 扩展表 ----------
// 设计原则：沿用既有"CREATE TABLE IF NOT EXISTS + 老库补列"迁移风格；
// 所有时间字段为毫秒整数；敏感/隐私相关放在独立表，便于按隐私设置过滤对外返回。
db.exec(`
CREATE TABLE IF NOT EXISTS site_assets (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  kind TEXT NOT NULL UNIQUE,            -- sponsor_qr 等站点级私有资源（不进 images/搜索/图库）
  filename TEXT NOT NULL,              -- 仅存文件名，物理位于 data/private/ 下，禁止静态直链枚举
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS user_profiles (
  user_id INTEGER PRIMARY KEY,          -- 1:1 关联 users.id
  birthday TEXT,                        -- ISO 日期；对外按隐私脱敏，不直出精确值
  birthday_visibility TEXT NOT NULL DEFAULT 'hidden', -- hidden | age_range | is_birthday
  gender TEXT NOT NULL DEFAULT 'secret',-- male | female | secret
  signature TEXT DEFAULT '',
  social_bilibili TEXT DEFAULT '',
  social_github TEXT DEFAULT '',
  social_qq TEXT DEFAULT '',
  social_email TEXT DEFAULT '',
  email_public INTEGER NOT NULL DEFAULT 0,
  email_verified INTEGER NOT NULL DEFAULT 0,
  privacy TEXT NOT NULL DEFAULT '{}'    -- JSON：各字段公开范围（最小可见默认）
);

CREATE TABLE IF NOT EXISTS titles (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  key TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL,
  desc TEXT DEFAULT '',
  icon TEXT DEFAULT '',
  color TEXT DEFAULT '',                    -- 称号底色（十六进制，可空→默认金色）
  grant_type TEXT NOT NULL DEFAULT 'owner', -- owner | redeem | auto
  auto_rule TEXT,                         -- JSON，自动发放条件（可空）
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS user_titles (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  title_id INTEGER NOT NULL,
  granted_by INTEGER,
  granted_at INTEGER NOT NULL,
  expire_at INTEGER,                      -- NULL=永久
  revoked INTEGER NOT NULL DEFAULT 0,
  UNIQUE(user_id, title_id)
);

CREATE TABLE IF NOT EXISTS achievements (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  key TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL,
  desc TEXT DEFAULT '',
  icon TEXT DEFAULT '',
  condition TEXT NOT NULL DEFAULT '{}',    -- JSON 触发规则
  reward_xp INTEGER NOT NULL DEFAULT 0,
  multiplier TEXT,                        -- JSON：{value,scope,starts_at,ends_at,stackable,global_cap}
  show_rule TEXT,                         -- JSON 展示规则
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS user_achievements (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  achievement_id INTEGER NOT NULL,
  granted_at INTEGER NOT NULL,
  revoked INTEGER NOT NULL DEFAULT 0,
  idempotency_key TEXT UNIQUE              -- 防重复发放/重放
);

CREATE TABLE IF NOT EXISTS achievement_progress (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  achievement_id INTEGER NOT NULL,
  progress INTEGER NOT NULL DEFAULT 0,
  updated_at INTEGER NOT NULL,
  UNIQUE(user_id, achievement_id)
);

CREATE TABLE IF NOT EXISTS multipliers (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  value REAL NOT NULL DEFAULT 0,           -- 倍率增量（如 0.1 = +10%）
  scope TEXT NOT NULL DEFAULT 'nonsignin', -- nonsignin | all（签到基础经验默认不参与）
  starts_at INTEGER,
  ends_at INTEGER,
  stackable INTEGER NOT NULL DEFAULT 1,
  global_cap REAL NOT NULL DEFAULT 2.0,    -- 有效倍率全局上限（如 2.0 = 最多 +200%）
  enabled INTEGER NOT NULL DEFAULT 1,
  source TEXT DEFAULT 'achievement',       -- achievement | manual
  ref_id INTEGER,                          -- 关联成就/手动规则
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS user_effective_multiplier (
  user_id INTEGER PRIMARY KEY,
  value REAL NOT NULL DEFAULT 0,
  computed_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS tasks (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  key TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL,
  desc TEXT DEFAULT '',
  type TEXT NOT NULL DEFAULT 'custom',     -- comment | like | favorite | download | online | custom
  target_count INTEGER NOT NULL DEFAULT 1,
  reward_xp INTEGER NOT NULL DEFAULT 0,
  daily_cap INTEGER NOT NULL DEFAULT 1,
  enabled INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS user_task_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  task_key TEXT NOT NULL,
  date TEXT NOT NULL,                      -- YYYY-MM-DD
  count INTEGER NOT NULL DEFAULT 0,
  idempotency_id TEXT UNIQUE,              -- 幂等：防止重复领取/重放
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS checkins (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  date TEXT NOT NULL,                      -- YYYY-MM-DD
  streak INTEGER NOT NULL DEFAULT 1,
  base_xp INTEGER NOT NULL DEFAULT 10,     -- 基础签到经验（不参与倍率）
  bonus_xp INTEGER NOT NULL DEFAULT 0,     -- 连续签到奖励
  created_at INTEGER NOT NULL,
  UNIQUE(user_id, date)
);

CREATE TABLE IF NOT EXISTS notifications (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  type TEXT NOT NULL,
  title TEXT NOT NULL,
  body TEXT DEFAULT '',
  ref TEXT,                                -- JSON 附带信息
  read INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS business_cards (
  user_id INTEGER PRIMARY KEY,             -- 1:1，Lv5+ 才可设置
  title TEXT DEFAULT '',
  intro TEXT DEFAULT '',
  image_path TEXT,                         -- 仅文件名，位于 data/private/（禁止静态直链）
  style TEXT,                              -- JSON 展示样式
  status TEXT NOT NULL DEFAULT 'pending',   -- pending | approved | rejected | taken_down
  submitted_at INTEGER,
  reviewed_at INTEGER,
  reviewer_id INTEGER,
  reject_reason TEXT DEFAULT '',
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS redeem_codes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  code TEXT NOT NULL UNIQUE,
  title TEXT DEFAULT '',
  title_id INTEGER,                        -- 关联授予称号（可为空）
  reward TEXT,                             -- JSON 其他奖励（经验/倍率等）
  max_uses INTEGER NOT NULL DEFAULT 1,     -- 总使用次数上限（防爆破）
  used_count INTEGER NOT NULL DEFAULT 0,
  per_user_once INTEGER NOT NULL DEFAULT 1,
  expires_at INTEGER,
  created_by INTEGER,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS redeem_code_uses (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  code_id INTEGER NOT NULL,
  user_id INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  UNIQUE(code_id, user_id)
);

CREATE TABLE IF NOT EXISTS browse_history (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  target_type TEXT NOT NULL,
  target_id INTEGER NOT NULL,
  last_viewed_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  actor_id INTEGER NOT NULL DEFAULT 0,     -- 0=系统
  role TEXT DEFAULT '',
  action TEXT NOT NULL,
  object_type TEXT,
  object_id TEXT,
  detail TEXT,                             -- JSON
  ip TEXT DEFAULT '',                      -- 脱敏
  ua TEXT DEFAULT '',                      -- 脱敏
  created_at INTEGER NOT NULL
);
`);

// 经验流水（审计/风控用，独立表避免污染 users）
db.exec(`
CREATE TABLE IF NOT EXISTS xp_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  delta INTEGER NOT NULL,
  source TEXT NOT NULL,                    -- signin | comment | like | favorite | download | online | task | achievement | multiplier
  ref_id INTEGER,
  created_at INTEGER NOT NULL
);
`);

// users 扩展列（等级/经验/展示偏好/角色细化）
const uCols2 = db.pragma('table_info(users)').map((c) => c.name);
if (!uCols2.includes('level')) db.exec('ALTER TABLE users ADD COLUMN level INTEGER NOT NULL DEFAULT 0');
if (!uCols2.includes('xp')) db.exec('ALTER TABLE users ADD COLUMN xp INTEGER NOT NULL DEFAULT 0');
if (!uCols2.includes('title_pref')) db.exec('ALTER TABLE users ADD COLUMN title_pref TEXT');
if (!uCols2.includes('show_level')) db.exec('ALTER TABLE users ADD COLUMN show_level INTEGER NOT NULL DEFAULT 1');
if (!uCols2.includes('show_title')) db.exec('ALTER TABLE users ADD COLUMN show_title INTEGER NOT NULL DEFAULT 1');
if (!uCols2.includes('show_achievement')) db.exec('ALTER TABLE users ADD COLUMN show_achievement INTEGER NOT NULL DEFAULT 1');

// 称号底色（站长自定义，类似等级颜色；老库补列）
const tCols = db.pragma('table_info(titles)').map((c) => c.name);
if (!tCols.includes('color')) db.exec("ALTER TABLE titles ADD COLUMN color TEXT DEFAULT ''");

module.exports = db;
