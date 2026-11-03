// 社区化 / 个人中心 / 等级成就 核心逻辑
// 所有对外返回均按 privacy 设置过滤；敏感字段未公开时后端不返回（绝不仅靠前端隐藏）。
const db = require('./db');
const { safeUrl, audit } = require('./auth');

// 隐私默认：最小可见原则（0=不公开，1=公开）。
//   - profile（个人主页）：默认公开，否则互相搜不到、主页打不开；
//   - card（个人名片）：默认公开，名片本身就是用于展示的内容，且已受「等级门槛 + 内容审核」两道闸。
// 其余敏感项（收藏 / 点赞 / 浏览记录 / 邮箱 / 倍率）一律默认不公开，用户可在「个人设置」自行收紧。
function defaultPrivacy() {
  return {
    profile: 1, favorites: 0, likes: 0, comments: 1, browse_history: 0,
    level: 1, title: 1, tags: 0, card: 1, badges: 1, multiplier: 0, email: 0,
  };
}

// 确保用户有 profile 行（首次访问时自动建；采用站长可配置的默认隐私）
function ensureProfile(uid) {
  const ex = db.prepare('SELECT user_id FROM user_profiles WHERE user_id = ?').get(uid);
  if (!ex) {
    db.prepare('INSERT INTO user_profiles (user_id, privacy) VALUES (?, ?)').run(uid, JSON.stringify(getDefaultPrivacy()));
  }
  return db.prepare('SELECT * FROM user_profiles WHERE user_id = ?').get(uid);
}

function getPrivacy(uid) {
  const p = db.prepare('SELECT privacy FROM user_profiles WHERE user_id = ?').get(uid);
  if (!p || !p.privacy) return getDefaultPrivacy();
  try {
    const j = JSON.parse(p.privacy);
    return Object.assign(getDefaultPrivacy(), j);
  } catch (_) { return getDefaultPrivacy(); }
}

// ---------- 隐私默认值（站长在后台可配置；未配置时回落到硬编码最小可见默认） ----------
function getSettingJson(key) {
  try {
    const r = db.prepare('SELECT value FROM settings WHERE key = ?').get(key);
    if (!r || !r.value) return null;
    return JSON.parse(r.value);
  } catch (_) { return null; }
}
let _defaultPrivacyCache = null; // 进程内缓存，避免每次隐私读取都查 settings
function getDefaultPrivacy() {
  if (!_defaultPrivacyCache) {
    const base = defaultPrivacy();
    const custom = getSettingJson('privacy_defaults');
    if (custom && typeof custom === 'object') {
      for (const k of PRIV_KEYS) if (custom[k] !== undefined) base[k] = custom[k] ? 1 : 0;
    }
    _defaultPrivacyCache = base;
  }
  return Object.assign({}, _defaultPrivacyCache);
}
function setDefaultPrivacy(obj) {
  const merged = Object.assign(defaultPrivacy(), sanitizePrivacy(obj));
  db.prepare("INSERT INTO settings (key, value) VALUES ('privacy_defaults', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value")
    .run(JSON.stringify(merged));
  _defaultPrivacyCache = merged;
  return Object.assign({}, merged);
}

// 一次性迁移：早期版本把「个人主页 / 个人名片」默认设为不公开，导致站内搜索不到任何用户、
// 互访主页直接提示私密、做好的名片对外不展示。现改为默认公开，把历史用户一并放通（仅一次）。
// 若站长已在后台自定义过隐私默认值，则尊重其配置、不做改动。
function migrateProfileVisibilityOnce() {
  try {
    if (getSettingJson('privacy_defaults')) return; // 站长已自定义，跳过
    if (db.prepare("SELECT value FROM settings WHERE key = 'privacy_migrated_profile_v1'").get()) return;
    const rows = db.prepare('SELECT user_id, privacy FROM user_profiles').all();
    const up = db.prepare('UPDATE user_profiles SET privacy = ? WHERE user_id = ?');
    let n = 0;
    for (const r of rows) {
      let j = null;
      try { j = JSON.parse(r.privacy || '{}') || {}; } catch (_) { j = {}; }
      if (j && typeof j === 'object' && (j.profile !== 1 || j.card !== 1)) {
        j.profile = 1; j.card = 1; up.run(JSON.stringify(j), r.user_id); n++;
      }
    }
    db.prepare("INSERT INTO settings (key, value) VALUES ('privacy_migrated_profile_v1', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value")
      .run(String(Date.now()));
    if (n) console.log('[迁移] 已放通 ' + n + ' 位历史用户的「个人主页 / 个人名片」默认可见性');
  } catch (_) { /* 迁移失败不影响启动 */ }
}

// 合并用户传入的隐私对象（仅接受已知键，值为布尔/0/1）
const PRIV_KEYS = ['profile', 'favorites', 'likes', 'comments', 'browse_history', 'level', 'title', 'tags', 'card', 'badges', 'multiplier', 'email'];
function sanitizePrivacy(obj) {
  const out = {};
  if (obj && typeof obj === 'object') {
    for (const k of PRIV_KEYS) {
      if (obj[k] !== undefined) out[k] = (obj[k] ? 1 : 0);
    }
  }
  return out;
}

// ---------- 等级经验曲线（累计 XP 到达该等级） ----------
// 到达 Lv10 需要 18000 XP；纯签到（每日 base_xp=10）5 年(1825天) = 18250 ≥ 18000，保底成立。
const LEVEL_XP = [0, 100, 300, 700, 1400, 2600, 4600, 7600, 11600, 14600, 18000];
const MAX_LEVEL = 10;

// ---------- 等级标识颜色（站长可在后台自定义每个 Lv 的颜色） ----------
// 默认设计一套从「低阶冷色 → 高阶暖金」的渐变，10 级满级用金色。
const LEVEL_COLORS_DEFAULT = {
  1: '#9aa0a6', 2: '#4ade80', 3: '#22d3ee', 4: '#60a5fa', 5: '#818cf8',
  6: '#a78bfa', 7: '#e879f9', 8: '#f472b6', 9: '#fb923c', 10: '#f59e0b',
};
const COLOR_HEX = /^#[0-9a-fA-F]{6}$/;
let _levelColorsCache = null;
function getLevelColors() {
  if (!_levelColorsCache) {
    const base = Object.assign({}, LEVEL_COLORS_DEFAULT);
    const custom = getSettingJson('level_colors');
    if (custom && typeof custom === 'object') {
      for (let i = 1; i <= MAX_LEVEL; i++) {
        const v = custom[String(i)];
        if (typeof v === 'string' && COLOR_HEX.test(v)) base[i] = v;
      }
    }
    _levelColorsCache = base;
  }
  return Object.assign({}, _levelColorsCache);
}
function getLevelColor(level) {
  // Lv0（尚未获得经验）也按 Lv1 的自定义色展示，否则站长的调色在这批用户身上永远看不到效果
  const lv = parseInt(level) || 0;
  const idx = Math.min(Math.max(lv, 1), MAX_LEVEL);
  return getLevelColors()[idx];
}
function setLevelColors(obj) {
  const merged = Object.assign({}, LEVEL_COLORS_DEFAULT);
  if (obj && typeof obj === 'object') {
    for (let i = 1; i <= MAX_LEVEL; i++) {
      const v = obj[String(i)];
      if (typeof v === 'string' && COLOR_HEX.test(v)) merged[i] = v;
    }
  }
  db.prepare("INSERT INTO settings (key, value) VALUES ('level_colors', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value")
    .run(JSON.stringify(merged));
  _levelColorsCache = merged;
  return Object.assign({}, merged);
}

function levelForXp(xp) {
  let lv = 0;
  for (let i = 1; i <= MAX_LEVEL; i++) {
    if (xp >= LEVEL_XP[i]) lv = i; else break;
  }
  return lv;
}

// 有效倍率：汇总生效中的 multipliers（scope 匹配、时间窗内、enabled），按 global_cap 封顶
function computeEffectiveMultiplier(uid) {
  const cached = db.prepare('SELECT value, computed_at FROM user_effective_multiplier WHERE user_id = ?').get(uid);
  const now = Date.now();
  if (cached && now - cached.computed_at < 60 * 1000) return cached.value; // 1 分钟缓存
  const rows = db.prepare('SELECT value, scope, global_cap, starts_at, ends_at FROM multipliers WHERE enabled = 1').all();
  let sum = 0;
  let cap = 2.0;
  for (const r of rows) {
    if (r.starts_at && now < r.starts_at) continue;
    if (r.ends_at && now > r.ends_at) continue;
    if (typeof r.global_cap === 'number' && r.global_cap < cap) cap = r.global_cap;
    sum += Number(r.value) || 0;
  }
  const eff = Math.max(0, Math.min(sum, cap));
  db.prepare('INSERT INTO user_effective_multiplier (user_id, value, computed_at) VALUES (?, ?, ?) ON CONFLICT(user_id) DO UPDATE SET value = excluded.value, computed_at = excluded.computed_at')
    .run(uid, eff, now);
  return eff;
}

function invalidateMultiplier(uid) {
  try { db.prepare('DELETE FROM user_effective_multiplier WHERE user_id = ?').run(uid); } catch (_) {}
}

// 发放经验：base 为基础经验；若 source 非签到(signin)则乘 (1+有效倍率)。
// 返回 { xp, leveledUp, newLevel }。签到基础经验不参与倍率（保证 5 年保底独立）。
function awardXp(uid, source, base, idempotencyId, refId) {
  base = Math.max(0, Math.floor(Number(base) || 0));
  if (base <= 0) return { xp: 0, leveledUp: false, newLevel: levelForXp(getXp(uid)) };
  let gained = base;
  if (source !== 'signin') {
    const mult = computeEffectiveMultiplier(uid);
    gained = Math.round(base * (1 + mult));
  }
  const before = getXp(uid);
  const after = before + gained;
  const newLv = levelForXp(after);
  const tx = db.transaction(() => {
    // 等级必须与 XP 同步落库：否则 users.level 永远停在 0，等级徽章/经验条/等级门槛全部失真
    db.prepare('UPDATE users SET xp = ?, level = ? WHERE id = ?').run(after, newLv, uid);
    db.prepare('INSERT INTO xp_log (user_id, delta, source, ref_id, created_at) VALUES (?, ?, ?, ?, ?)')
      .run(uid, gained, source, refId || null, Date.now());
  });
  tx();
  const oldLv = levelForXp(before);
  let leveledUp = false;
  if (newLv > oldLv) {
    leveledUp = true;
    addNotification(uid, 'LEVEL_UP', '等级提升', `恭喜，你的等级提升至 Lv${newLv}`, JSON.stringify({ level: newLv }));
  }
  return { xp: gained, leveledUp, newLevel: newLv };
}

function getXp(uid) {
  const r = db.prepare('SELECT xp FROM users WHERE id = ?').get(uid);
  return r ? r.xp : 0;
}

// ---------- 站内通知 ----------
function addNotification(uid, type, title, body, ref, dedupKey) {
  try {
    if (dedupKey) {
      // 关键通知去重：同 dedupKey 近期(24h)已发则不重复
      const ex = db.prepare("SELECT id FROM notifications WHERE user_id = ? AND ref = ? AND created_at > ?")
        .get(uid, dedupKey, Date.now() - 24 * 3600 * 1000);
      if (ex) return;
    }
    db.prepare('INSERT INTO notifications (user_id, type, title, body, ref, created_at) VALUES (?, ?, ?, ?, ?, ?)')
      .run(uid, type, String(title || ''), String(body || ''), ref ? JSON.stringify(ref) : null, Date.now());
  } catch (e) { console.error('[notify] 写入失败:', e.message); }
}

// ---------- 用户称号解析（未撤销且未过期） ----------
function activeTitles(uid) {
  const now = Date.now();
  return db.prepare(
    `SELECT t.id, t.key, t.name, t.icon, t.color FROM user_titles ut JOIN titles t ON t.id = ut.title_id
     WHERE ut.user_id = ? AND ut.revoked = 0 AND (ut.expire_at IS NULL OR ut.expire_at > ?)`
  ).all(uid, now);
}

// 取当前生效称号对象（用户可在设置中选择 title_pref）
function pickActiveTitle(uid, prefKey) {
  const list = activeTitles(uid);
  if (!list.length) return null;
  const hit = prefKey ? list.find((t) => t.key === prefKey) : list[0];
  return hit || list[0];
}

// 取用于展示的称号名（用户可在设置中选择 title_pref）
function displayTitle(uid, prefKey) {
  const t = pickActiveTitle(uid, prefKey);
  return t ? t.name : null;
}

// 取称号底色（无自定义时回退默认金色，供前端 title-tag 上色）
function titleColorOf(uid, prefKey) {
  const t = pickActiveTitle(uid, prefKey);
  return (t && t.color) ? t.color : '#d9920a';
}

// 取称号图标（自定义 emoji；未配置时由前端回退默认徽章）
function titleIconOf(uid, prefKey) {
  const t = pickActiveTitle(uid, prefKey);
  return (t && t.icon) ? t.icon : '';
}

// 一次性取全「称号展示三件套」：名称 + 图标 + 底色（内部只查一次库）
function titleDisplay(uid, prefKey) {
  const t = pickActiveTitle(uid, prefKey);
  if (!t) return { name: null, icon: '', color: null };
  return { name: t.name || null, icon: t.icon || '', color: t.color || '#d9920a' };
}

// 用户成就徽章（已获得、未撤销）
function userBadges(uid, limit) {
  return db.prepare(
    `SELECT a.id, a.key, a.name, a.icon FROM user_achievements ua JOIN achievements a ON a.id = ua.achievement_id
     WHERE ua.user_id = ? AND ua.revoked = 0 ORDER BY ua.granted_at DESC LIMIT ?`
  ).all(uid, limit || 6);
}

// 评论作者公开信息（头像/等级/称号/徽章），按用户展示开关+隐私
function commentAuthor(uid) {
  const u = db.prepare('SELECT id, username, avatar, level, xp, show_level, show_title, show_achievement, title_pref FROM users WHERE id = ?').get(uid);
  if (!u) return null;
  const priv = getPrivacy(uid);
  const lv = levelForXp(u.xp || 0);     // 等级由 XP 推导，与主页保持完全一致
  const td = (u.show_title && priv.title) ? titleDisplay(uid, u.title_pref) : { name: null, icon: '', color: null };
  const badges = (u.show_achievement && priv.badges) ? userBadges(uid, 3).map((b) => ({ name: b.name, icon: b.icon })) : [];
  return {
    id: u.id, username: u.username, avatar: u.avatar || null,
    level: (u.show_level && priv.level) ? lv : null,
    level_color: (u.show_level && priv.level) ? getLevelColor(lv) : null,
    title: td.name, title_icon: td.name ? td.icon : '', title_color: td.color, badges,
  };
}

// 个人主页（遵守隐私）
function getHome(uid, viewerId) {
  const u = db.prepare('SELECT id, username, avatar, email, level, xp, banned, show_level, show_title, show_achievement, title_pref, created_at FROM users WHERE id = ?').get(uid);
  if (!u) return null;
  const priv = getPrivacy(uid);
  const isSelf = viewerId === uid;
  const profile = ensureProfile(uid);
  const out = {
    id: u.id, username: u.username, avatar: u.avatar || null, created_at: u.created_at,
    is_self: isSelf,
  };
  // 经验进度：当前累计 XP / 下一级所需 XP（满级则不再显示下一级）
  const xpNow = u.xp || 0;
  // 等级一律由 XP 推导：历史版本只加 xp 不写 level，直接用 u.level 会拿到脏值
  // （表现为永远 Lv0、经验条卡在 100%、名片等级门槛失效、等级颜色改了没反应）。
  const lvNow = levelForXp(xpNow);
  if (lvNow !== (u.level || 0)) {
    try { db.prepare('UPDATE users SET level = ? WHERE id = ?').run(lvNow, uid); } catch (_) {}
  }
  const xpFloor = LEVEL_XP[lvNow] || 0;
  const xpNext = lvNow >= MAX_LEVEL ? null : LEVEL_XP[lvNow + 1];
  out.xp = {
    current: xpNow,
    level_start: xpFloor,
    next: xpNext,
    need: xpNext ? Math.max(0, xpNext - xpNow) : 0,
    percent: xpNext ? Math.min(100, Math.max(0, Math.round(((xpNow - xpFloor) / Math.max(1, xpNext - xpFloor)) * 100))) : 100,
    maxed: lvNow >= MAX_LEVEL,
  };
  // 主页是否对他人可见
  if (!isSelf && !priv.profile) {
    out.profile_private = true;
    // 即便主页不公开，仍可按各自展示开关展示等级/称号/徽章（评论区同源逻辑）
    const td = (u.show_title && priv.title) ? titleDisplay(uid, u.title_pref) : { name: null, icon: '', color: null };
    out.level = (u.show_level && priv.level) ? lvNow : null;
    out.level_color = (u.show_level && priv.level) ? getLevelColor(lvNow) : null;
    out.title = td.name;
    out.title_icon = td.name ? td.icon : '';
    out.title_color = td.color;
    out.badges = (u.show_achievement && priv.badges) ? userBadges(uid, 6) : [];
    if (out.level == null) out.xp = null; // 等级不对外展示时，经验进度同样不返回
    return out;
  }
  // 公开/自己可见字段
  const td = (isSelf || (u.show_title && priv.title)) ? titleDisplay(uid, u.title_pref) : { name: null, icon: '', color: null };
  out.level = (isSelf || (u.show_level && priv.level)) ? lvNow : null;
  out.level_color = (isSelf || (u.show_level && priv.level)) ? getLevelColor(lvNow) : null;
  out.title = td.name;
  out.title_icon = td.name ? td.icon : '';
  out.title_color = td.color;
  out.badges = (isSelf || (u.show_achievement && priv.badges)) ? userBadges(uid, 12) : [];
  if (isSelf || priv.profile) {
    out.signature = profile.signature || '';
    out.gender = profile.gender;
    // 生日按可见性脱敏
    if (profile.birthday) {
      if (isSelf) out.birthday = profile.birthday;
      else if (profile.birthday_visibility === 'age_range') out.birthday_age_range = ageRange(profile.birthday);
      else if (profile.birthday_visibility === 'is_birthday') out.is_birthday = isBirthdayToday(profile.birthday);
      // hidden → 不返回
    }
    // 社交链接（仅主页可见时给；email 需 email_public）
    if (priv.profile || isSelf) {
      out.social = {
        bilibili: profile.social_bilibili || '',
        github: profile.social_github || '',
        qq: profile.social_qq || '',
      };
      // 邮箱：统一展示「账号绑定的邮箱」（注册邮箱，不可在设置页修改），仅由「是否公开」开关控制
      // 仅由账号设置里的「公开邮箱」开关控制（隐私分组里不再重复给一个开关）
      if (isSelf || profile.email_public) {
        out.email = maskEmail(u.email || '');
      }
    }
  }
  // 收藏/点赞/浏览（受隐私 + 仅自己或授权）；评论可单独开关（默认公开）
  if (isSelf || priv.favorites) out.favorites = favList(uid); else out.favorites = [];
  if (isSelf || priv.likes) out.likes = likeList(uid); else out.likes = [];
  if (isSelf || priv.browse_history) out.browse_history = browseList(uid); else out.browse_history = [];
  out.comments = (isSelf || priv.comments) ? commentList(uid) : [];
  // 名片（受隐私 + 审核通过 + 实时资格）：自见全字段以预览；
  // 他人仅见「已通过 + 当前达 Lv5 + 未封禁」的名片（降级/封禁后即时隐藏）。
  if (isSelf || priv.card) {
    const card = db.prepare('SELECT status, title, intro, style, image_path FROM business_cards WHERE user_id = ?').get(uid);
    const cardPublicOk = card && card.status === 'approved' && (lvNow >= CARD_MIN_LEVEL || isStaff(uid)) && !u.banned;
    if (card && (isSelf || cardPublicOk)) {
      out.card = {
        status: card.status, title: card.title, intro: card.intro,
        style: parseStyle(card.style), has_image: !!card.image_path,
      };
    }
  }
  return out;
}

// ---------- 个人名片（Lv5+ 解锁，图片隔离存储 + 审核发布） ----------
const CARD_MIN_LEVEL = 5;
const CARD_STYLE_KEYS = ['bg', 'fg', 'accent'];
const CARD_HEX = /^#[0-9a-fA-F]{3,8}$/;

function parseStyle(s) {
  if (!s) return null;
  try { const j = JSON.parse(s); return j && typeof j === 'object' ? j : null; } catch (_) { return null; }
}
// 样式白名单：仅允许三个颜色键且必须为合法十六进制色值，杜绝注入任意 HTML/CSS
function sanitizeCardStyle(obj) {
  const out = {};
  if (obj && typeof obj === 'object') {
    for (const k of CARD_STYLE_KEYS) {
      const v = obj[k];
      if (typeof v === 'string' && CARD_HEX.test(v.trim())) out[k] = v.trim();
    }
  }
  return out;
}

// 读取等级：以 XP 为准自愈（历史版本只写 xp 不写 level，会导致等级永远停在 Lv0）
function getUserLevel(uid) {
  const u = db.prepare('SELECT level, xp FROM users WHERE id = ?').get(uid);
  if (!u) return 0;
  const calc = levelForXp(u.xp || 0);
  if (calc !== (u.level || 0)) {
    try { db.prepare('UPDATE users SET level = ? WHERE id = ?').run(calc, uid); } catch (_) {}
  }
  return calc;
}

// 启动自愈：把全库 users.level 按当前 XP 重算一次（幂等，仅在不一致时写入）
function syncAllLevelsOnce() {
  try {
    const rows = db.prepare('SELECT id, xp, level FROM users').all();
    const up = db.prepare('UPDATE users SET level = ? WHERE id = ?');
    let n = 0;
    db.transaction(() => {
      for (const r of rows) {
        const calc = levelForXp(r.xp || 0);
        if (calc !== (r.level || 0)) { up.run(calc, r.id); n++; }
      }
    })();
    if (n) console.log('[迁移] 已按 XP 重算 %d 位用户的等级', n);
    return n;
  } catch (_) { return 0; }
}

// 站长/管理员：本系统最高角色为 admin（首个注册账号），owner 仅为兼容旧数据。
// 站长不受名片等级门槛限制，且自己的名片免审核直接发布（已有最高权限，无需再走审批）。
function isStaff(uid) {
  if (!uid) return false;
  const u = db.prepare('SELECT role FROM users WHERE id = ?').get(uid);
  return !!u && (u.role === 'admin' || u.role === 'owner');
}

function getMyCard(uid) {
  const level = getUserLevel(uid);
  const staff = isStaff(uid);
  const row = db.prepare('SELECT * FROM business_cards WHERE user_id = ?').get(uid) || null;
  return {
    level,
    min_level: CARD_MIN_LEVEL,
    eligible: level >= CARD_MIN_LEVEL || staff,
    staff,
    card: row ? {
      status: row.status,
      title: row.title || '',
      intro: row.intro || '',
      style: parseStyle(row.style),
      has_image: !!row.image_path,
      reject_reason: row.reject_reason || '',
      submitted_at: row.submitted_at || null,
      reviewed_at: row.reviewed_at || null,
    } : null,
  };
}

// 提交/更新名片：等级门槛 + 一律回到 pending 待审；imagePath 由调用方负责落盘/清理旧文件
function submitCard(uid, { title, intro, style, imagePath }, actorId) {
  const level = getUserLevel(uid);
  const staff = isStaff(uid); // 站长免等级门槛 + 免审核
  if (level < CARD_MIN_LEVEL && !staff) return { error: 'level_low' };
  const t = String(title || '').slice(0, 40);
  const i = String(intro || '').slice(0, 300);
  const st = JSON.stringify(sanitizeCardStyle(style));
  const now = Date.now();
  const status = staff ? 'approved' : 'pending';
  const ex = db.prepare('SELECT user_id FROM business_cards WHERE user_id = ?').get(uid);
  if (ex) {
    db.prepare(`UPDATE business_cards SET title=?, intro=?, style=?, image_path=?, status=?, submitted_at=?,
                reviewed_at=?, reviewer_id=?, reject_reason='' WHERE user_id=?`)
      .run(t, i, st, imagePath || null, status, now, staff ? now : null, staff ? uid : null, uid);
  } else {
    db.prepare(`INSERT INTO business_cards (user_id,title,intro,image_path,style,status,submitted_at,reviewed_at,reviewer_id,created_at)
                VALUES (?,?,?,?,?,?,?,?,?,?)`)
      .run(uid, t, i, imagePath || null, st, status, now, staff ? now : null, staff ? uid : null, now);
  }
  audit(actorId || uid, '', staff ? 'publish_card_staff' : 'submit_card', 'business_card', String(uid), { has_image: !!imagePath, auto_approved: staff });
  return { ok: true, auto_approved: staff, card: getMyCard(uid).card };
}

// 审核：approve | reject | takedown；变更状态、记录审核人、通知本人
function reviewCard(uid, action, reason, reviewerId) {
  const row = db.prepare('SELECT user_id FROM business_cards WHERE user_id = ?').get(uid);
  if (!row) return { error: 'no_card' };
  const map = { approve: 'approved', reject: 'rejected', takedown: 'taken_down' };
  const status = map[action];
  if (!status) return { error: 'bad_action' };
  db.prepare('UPDATE business_cards SET status=?, reviewed_at=?, reviewer_id=?, reject_reason=? WHERE user_id=?')
    .run(status, Date.now(), reviewerId || 0, status === 'approved' ? '' : String(reason || '').slice(0, 200), uid);
  const titleMap = { approved: '名片审核通过', rejected: '名片被驳回', taken_down: '名片已下架' };
  addNotification(uid, 'CARD_REVIEW', titleMap[status], status === 'approved' ? '你的个人名片已通过审核并展示。' : ('原因：' + String(reason || '不符合规范')));
  audit(reviewerId || 0, '', 'review_card_' + status, 'business_card', String(uid), { reason: reason || '' });
  return { ok: true, status };
}

// 管理端：按状态列出名片（含用户名/等级）
function listCards(status) {
  const st = ['pending', 'approved', 'rejected', 'taken_down', 'all'].includes(status) ? status : 'pending';
  const where = st === 'all' ? '' : 'WHERE b.status = ?';
  const args = st === 'all' ? [] : [st];
  const rows = db.prepare(
    `SELECT b.user_id, b.title, b.intro, b.status, b.reject_reason, b.submitted_at, b.reviewed_at, b.reviewer_id,
            (b.image_path IS NOT NULL AND b.image_path <> '') AS has_image,
            u.username, u.level, u.xp
       FROM business_cards b JOIN users u ON u.id = b.user_id ${where}
      ORDER BY b.submitted_at DESC LIMIT 200`
  ).all(...args);
  return rows.map((r) => {
    const lv = levelForXp(r.xp || 0);   // 与主页/评论区同一套推导，避免后台列表显示脏等级
    return Object.assign({}, r, { level: lv, level_color: getLevelColor(lv) });
  });
}

function ageRange(birthday) {
  const y = parseInt(String(birthday).slice(0, 4));
  if (!y) return '';
  const age = new Date().getFullYear() - y;
  if (age < 18) return '<18';
  if (age <= 25) return '18-25';
  if (age <= 35) return '26-35';
  return '36+';
}
function isBirthdayToday(birthday) {
  const d = String(birthday);
  try { return d.slice(5) === new Date().toISOString().slice(5, 10); } catch (_) { return false; }
}
function maskEmail(email) {
  if (!email || !/^[^@]+@[^@]+$/.test(email)) return '';
  const [a, b] = email.split('@');
  const head = a.slice(0, 2);
  return `${head}***@${b}`;
}

// 收藏/点赞/浏览/评论列表（精简，复用既有 favorites/likes 表）
// 每条都解析出可跳转的 href 与标题，前端据此定位到具体内容页（文章按 slug、项目/图片按 id、动态跳外链）。
function targetHref(type, id) {
  if (!id) return null;
  switch (type) {
    case 'article': {
      const a = db.prepare("SELECT slug, title FROM articles WHERE id = ?").get(id);
      return a ? { href: '#/article/' + a.slug, title: a.title || '', external: false } : null;
    }
    case 'project': {
      const p = db.prepare('SELECT id, title FROM projects WHERE id = ?').get(id);
      return p ? { href: '#/project/' + p.id, title: p.title || '', external: false } : null;
    }
    case 'image': {
      const im = db.prepare('SELECT id, title FROM images WHERE id = ?').get(id);
      return im ? { href: '#/image/' + im.id, title: im.title || im.original_name || '', external: false } : null;
    }
    case 'social': {
      const s = db.prepare('SELECT url, title FROM social_posts WHERE id = ?').get(id);
      return s ? { href: s.url || ('#/social'), title: s.title || '', external: true } : null;
    }
    default: return null;
  }
}
function withTarget(rows, timeField) {
  return rows.map((f) => {
    const t = targetHref(f.target_type, f.target_id);
    return { type: f.target_type, id: f.target_id, at: f[timeField], title: t ? t.title : '', href: t ? t.href : '', external: t ? t.external : false, missing: !t };
  }).filter((x) => !x.missing);
}
function favList(uid) {
  const favs = db.prepare('SELECT target_type, target_id, created_at FROM favorites WHERE user_id = ? ORDER BY created_at DESC LIMIT 50').all(uid);
  return withTarget(favs, 'created_at');
}
function likeList(uid) {
  const rows = db.prepare('SELECT target_type, target_id, created_at FROM likes WHERE user_id = ? ORDER BY created_at DESC LIMIT 50').all(uid);
  return withTarget(rows, 'created_at');
}
function browseList(uid) {
  const rows = db.prepare('SELECT target_type, target_id, last_viewed_at FROM browse_history WHERE user_id = ? ORDER BY last_viewed_at DESC LIMIT 50').all(uid);
  return withTarget(rows, 'last_viewed_at');
}
function commentList(uid) {
  const rows = db.prepare(
    `SELECT c.id, c.target_type, c.target_id, c.content, c.created_at FROM comments c
     WHERE c.user_id = ? AND c.status = 'visible' ORDER BY c.created_at DESC LIMIT 50`
  ).all(uid);
  return rows.map((c) => {
    const t = targetHref(c.target_type, c.target_id);
    return { id: c.id, type: c.target_type, target_id: c.target_id, content: c.content, at: c.created_at, title: t ? t.title : '', href: t ? t.href : '', external: t ? t.external : false };
  });
}

// 记录浏览历史（登录用户）；同目标 24h 内只更新时间，避免刷量
function recordBrowse(uid, type, id) {
  if (!uid || !type || !id) return;
  const day = Date.now();
  const ex = db.prepare('SELECT id, last_viewed_at FROM browse_history WHERE user_id = ? AND target_type = ? AND target_id = ?').get(uid, type, id);
  if (ex) {
    if (day - ex.last_viewed_at < 24 * 3600 * 1000) {
      db.prepare('UPDATE browse_history SET last_viewed_at = ? WHERE id = ?').run(day, ex.id);
    } else {
      db.prepare('UPDATE browse_history SET last_viewed_at = ? WHERE id = ?').run(day, ex.id);
    }
  } else {
    db.prepare('INSERT INTO browse_history (user_id, target_type, target_id, last_viewed_at) VALUES (?, ?, ?, ?)').run(uid, type, id, day);
  }
}

// 浏览记录 TTL 定时清理（默认 90 天），避免无限增长。
// 可用环境变量覆盖：BROWSE_TTL_MS（保留时长）、BROWSE_CLEAN_INTERVAL_MS（清理频率）。
const BROWSE_TTL = parseInt(process.env.BROWSE_TTL_MS, 10) || 90 * 24 * 3600 * 1000;
const BROWSE_CLEAN_INTERVAL = parseInt(process.env.BROWSE_CLEAN_INTERVAL_MS, 10) || 6 * 3600 * 1000;
function cleanupBrowseHistory() {
  try {
    const n = db.prepare('DELETE FROM browse_history WHERE last_viewed_at < ?').run(Date.now() - BROWSE_TTL).changes;
    if (n) console.log(`[清理] 自动清除 ${n} 条过期浏览记录`);
    return n;
  } catch (_) { return 0; }
}
const browseTimer = setInterval(cleanupBrowseHistory, BROWSE_CLEAN_INTERVAL);
if (browseTimer.unref) browseTimer.unref(); // 不阻止进程/测试退出
try { cleanupBrowseHistory(); } catch (_) {}

// 链接安全导出（社交字段入库前校验）
function safeSocial(u) { return safeUrl(u); }

// ================= 签到 =================
// 本地日期 YYYY-MM-DD（单一服务器部署，按服务器时区计日）
function todayStr(ts) {
  const d = new Date(ts || Date.now());
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`;
}
function yestStr(ts) { return todayStr((ts || Date.now()) - 24 * 3600 * 1000); }

// 签到状态：今日是否已签、当前连续天数（未签则显示昨日连续，供"继续"提示）、累计天数
function getCheckinStatus(uid) {
  const t = todayStr();
  const today = db.prepare('SELECT * FROM checkins WHERE user_id = ? AND date = ?').get(uid, t);
  const total = db.prepare('SELECT COUNT(*) c FROM checkins WHERE user_id = ?').get(uid).c;
  let streak = 0;
  if (today) streak = today.streak;
  else {
    const y = db.prepare('SELECT streak FROM checkins WHERE user_id = ? AND date = ?').get(uid, yestStr());
    if (y) streak = y.streak;
  }
  return { checkedToday: !!today, streak, totalDays: total, today: t };
}

// 执行签到：基础 10 XP（不参与倍率，保底独立）；连续奖励第 2–6 天 +2/天、第 7 天 +10，循环，单日 bonus 封顶 +20。
function doCheckin(uid) {
  const t = todayStr();
  const ex = db.prepare('SELECT * FROM checkins WHERE user_id = ? AND date = ?').get(uid, t);
  if (ex) return { already: true, xp: 0, streak: ex.streak, bonus: ex.bonus_xp, leveledUp: false, newLevel: levelForXp(getXp(uid)) };
  const y = db.prepare('SELECT streak FROM checkins WHERE user_id = ? AND date = ?').get(uid, yestStr());
  const streak = (y ? y.streak : 0) + 1;
  const base = 10;
  const wp = ((streak - 1) % 7) + 1; // 周期内位置 1..7
  let bonus = 0;
  if (wp >= 2 && wp <= 6) bonus = 2;
  else if (wp === 7) bonus = 10;
  bonus = Math.min(bonus, 20);
  const award = base + bonus;
  const r = awardXp(uid, 'signin', award); // 签到基础经验不乘倍率
  db.prepare('INSERT INTO checkins (user_id, date, streak, base_xp, bonus_xp, created_at) VALUES (?, ?, ?, ?, ?, ?)')
    .run(uid, t, streak, base, bonus, Date.now());
  addNotification(uid, 'CHECKIN', '每日签到', `签到成功，获得 ${award} 经验（连续 ${streak} 天）`, JSON.stringify({ streak, xp: award }));
  return { already: false, xp: award, streak, bonus, leveledUp: r.leveledUp, newLevel: r.newLevel };
}

// ================= 任务 / 签到经验 =================
const DEFAULT_TASKS = [
  { key: 'daily_comment', name: '每日评论', desc: '发表 1 条评论', type: 'comment', target_count: 1, reward_xp: 5, daily_cap: 1 },
  { key: 'daily_like', name: '每日点赞', desc: '点赞 1 次', type: 'like', target_count: 1, reward_xp: 2, daily_cap: 1 },
  { key: 'daily_favorite', name: '每日收藏', desc: '收藏 1 次', type: 'favorite', target_count: 1, reward_xp: 2, daily_cap: 1 },
];
function seedTasks() {
  const n = db.prepare('SELECT COUNT(*) c FROM tasks').get().c;
  if (n === 0) db.transaction(() => {
    const ins = db.prepare('INSERT INTO tasks (key,name,desc,type,target_count,reward_xp,daily_cap,enabled) VALUES (@key,@name,@desc,@type,@target_count,@reward_xp,@daily_cap,1)');
    DEFAULT_TASKS.forEach((t) => ins.run(t));
  })();
}
function getTasks() { return db.prepare('SELECT * FROM tasks WHERE enabled = 1 ORDER BY id').all(); }
function getMyTasks(uid) {
  const t = todayStr();
  const logs = db.prepare('SELECT task_key, COALESCE(SUM(count),0) c FROM user_task_log WHERE user_id = ? AND date = ? GROUP BY task_key').all(uid, t);
  const map = {}; logs.forEach((l) => map[l.task_key] = l.c);
  return getTasks().map((tk) => {
    const c = map[tk.key] || 0;
    return Object.assign({}, tk, { today_count: c, claimed: c >= tk.daily_cap });
  });
}
// 完成任务：受每日上限 + 幂等（idempotencyId）约束；可参与倍率的非签到经验。
function completeTask(uid, key, idempotencyId) {
  const task = db.prepare('SELECT * FROM tasks WHERE key = ? AND enabled = 1').get(key);
  if (!task) return { error: 'unknown_task' };
  const t = todayStr();
  if (idempotencyId) {
    const hit = db.prepare('SELECT id FROM user_task_log WHERE idempotency_id = ?').get(idempotencyId);
    if (hit) return { claimed: true, already: true, xp: 0 };
  }
  const cur = db.prepare('SELECT COALESCE(SUM(count),0) c FROM user_task_log WHERE user_id = ? AND task_key = ? AND date = ?').get(uid, key, t).c;
  if (cur >= task.daily_cap) return { claimed: true, already: true, xp: 0 };
  if (idempotencyId) {
    db.prepare('INSERT INTO user_task_log (user_id, task_key, date, count, idempotency_id, created_at) VALUES (?, ?, ?, 1, ?, ?)')
      .run(uid, key, t, idempotencyId, Date.now());
  } else {
    const log = db.prepare('SELECT * FROM user_task_log WHERE user_id = ? AND task_key = ? AND date = ?').get(uid, key, t);
    if (log) db.prepare('UPDATE user_task_log SET count = count + 1 WHERE id = ?').run(log.id);
    else db.prepare('INSERT INTO user_task_log (user_id, task_key, date, count, created_at) VALUES (?, ?, ?, 1, ?)').run(uid, key, t, Date.now());
  }
  const r = awardXp(uid, 'task', task.reward_xp);
  return { claimed: true, xp: task.reward_xp, leveledUp: r.leveledUp, newLevel: r.newLevel };
}

// ================= 倍率缓存失效（全局） =================
function invalidateAllMultipliers() { try { db.prepare('DELETE FROM user_effective_multiplier').run(); } catch (_) {} }

// ================= 成就 =================
// 成就关联倍率：成就定义可带 multiplier JSON，发放时落地为 multipliers 行（source=achievement），撤销时移除。
function applyAchievementMultiplier(a) {
  if (!a.multiplier) return;
  let m; try { m = JSON.parse(a.multiplier); } catch (_) { return; }
  if (!m || typeof m.value !== 'number') return;
  const row = {
    name: (a.name || '成就') + ' 倍率',
    value: m.value,
    scope: m.scope || 'nonsignin',
    starts_at: m.starts_at || null,
    ends_at: m.ends_at || null,
    stackable: m.stackable ? 1 : 0,
    global_cap: typeof m.global_cap === 'number' ? m.global_cap : 2.0,
    enabled: 1,
  };
  const ex = db.prepare("SELECT id FROM multipliers WHERE source='achievement' AND ref_id=?").get(a.id);
  if (ex) db.prepare('UPDATE multipliers SET name=@name,value=@value,scope=@scope,starts_at=@starts_at,ends_at=@ends_at,stackable=@stackable,global_cap=@global_cap,enabled=1 WHERE id=@id')
    .run(Object.assign({}, row, { id: ex.id }));
  else db.prepare("INSERT INTO multipliers (name,value,scope,starts_at,ends_at,stackable,global_cap,enabled,source,ref_id,created_at) VALUES (@name,@value,@scope,@starts_at,@ends_at,@stackable,@global_cap,@enabled,'achievement',@ref_id,@created_at)")
    .run(Object.assign({}, row, { ref_id: a.id, created_at: Date.now() }));
  invalidateAllMultipliers();
}
// 幂等发放成就：idempotency_key 唯一约束；重复触发直接忽略；发放奖励经验（可参与倍率）并落地关联倍率。
function grantAchievement(uid, achievementId, idempotencyKey, actorId) {
  const a = db.prepare('SELECT * FROM achievements WHERE id = ?').get(achievementId);
  if (!a) return { error: 'unknown_achievement' };
  const idek = idempotencyKey || ('auto:' + a.key + ':' + uid);
  const had = db.prepare('SELECT id FROM user_achievements WHERE user_id = ? AND achievement_id = ? AND revoked = 0').get(uid, achievementId);
  if (had) return { already: true };
  try {
    db.prepare('INSERT INTO user_achievements (user_id, achievement_id, granted_at, revoked, idempotency_key) VALUES (?, ?, ?, 0, ?)')
      .run(uid, achievementId, Date.now(), idek);
  } catch (e) { return { already: true }; } // UNIQUE(idempotency_key) 冲突 → 幂等
  let r = { xp: 0, leveledUp: false, newLevel: levelForXp(getXp(uid)) };
  if (a.reward_xp > 0) r = awardXp(uid, 'achievement', a.reward_xp);
  applyAchievementMultiplier(a);
  addNotification(uid, 'ACHIEVEMENT', '获得成就', `恭喜获得成就「${a.name}」`, JSON.stringify({ achievement: a.key }));
  audit(actorId || 0, '', 'grant_achievement', 'achievement', a.id, { user_id: uid });
  return { ok: true, achievement: a.key, xp: r.xp, leveledUp: r.leveledUp, newLevel: r.newLevel };
}
function revokeAchievement(uid, achievementId, actorId) {
  const a = db.prepare('SELECT * FROM achievements WHERE id = ?').get(achievementId);
  if (!a) return { error: 'unknown_achievement' };
  db.prepare('UPDATE user_achievements SET revoked = 1 WHERE user_id = ? AND achievement_id = ?').run(uid, achievementId);
  db.prepare("DELETE FROM multipliers WHERE source='achievement' AND ref_id=?").run(achievementId);
  invalidateAllMultipliers();
  audit(actorId || 0, '', 'revoke_achievement', 'achievement', a.id, { user_id: uid });
  return { ok: true };
}
// 自动成就判定（条件式）：metric 支持 level/xp/checkins/comments/favorites/likes；op 默认 >=。
function evaluateAutoAchievements(uid) {
  const list = db.prepare("SELECT * FROM achievements WHERE condition IS NOT NULL AND condition != '{}' AND condition != ''").all();
  for (const a of list) {
    let cond; try { cond = JSON.parse(a.condition); } catch (_) { continue; }
    if (!cond || !cond.metric) continue;
    let val = 0;
    if (cond.metric === 'level') { val = levelForXp(getXp(uid)); }
    else if (cond.metric === 'xp') val = getXp(uid);
    else if (cond.metric === 'checkins') val = db.prepare('SELECT COUNT(*) c FROM checkins WHERE user_id=?').get(uid).c;
    else if (cond.metric === 'comments') val = db.prepare("SELECT COUNT(*) c FROM comments WHERE user_id=? AND status='visible'").get(uid).c;
    else if (cond.metric === 'favorites') val = db.prepare('SELECT COUNT(*) c FROM favorites WHERE user_id=?').get(uid).c;
    else if (cond.metric === 'likes') val = db.prepare('SELECT COUNT(*) c FROM likes WHERE user_id=?').get(uid).c;
    else continue;
    const thr = Number(cond.value) || 0;
    const op = cond.op || '>=';
    const met = op === '>=' ? val >= thr : op === '>' ? val > thr : op === '<=' ? val <= thr : val < thr;
    if (met) grantAchievement(uid, a.id, 'auto:' + a.key + ':' + uid, 0);
  }
}
function getAchievements() { return db.prepare('SELECT * FROM achievements ORDER BY id').all(); }
function getMyAchievements(uid) {
  const all = getAchievements();
  const got = db.prepare('SELECT achievement_id, granted_at, revoked FROM user_achievements WHERE user_id = ?').all(uid);
  const map = {}; got.forEach((g) => map[g.achievement_id] = g);
  return all.map((a) => Object.assign({}, a, {
    granted: !!(map[a.id] && !map[a.id].revoked),
    granted_at: map[a.id] ? map[a.id].granted_at : null,
    revoked: map[a.id] ? map[a.id].revoked : 0,
  }));
}

// ================= 兑换码 =================
function randCode(n) {
  const alpha = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // 去除易混淆字符
  let s = '';
  for (let i = 0; i < n; i++) s += alpha[Math.floor(Math.random() * alpha.length)];
  return s;
}
function generateRedeemCode({ title, titleId, type, value, reward, maxUses, perUserOnce, expiresAt, code }, actorId) {
  // 归一化奖励：优先 type+value（经验/成就/称号），兼容旧 titleId / reward JSON
  let rewardJson = null;
  if (type === 'xp') rewardJson = { type: 'xp', xp: Math.max(0, Math.floor(Number(value) || 0)) };
  else if (type === 'achievement') { const k = String(value || '').trim(); if (k) rewardJson = { type: 'achievement', key: k }; }
  else if (type === 'title') { const k = String(value || '').trim(); if (k) rewardJson = { type: 'title', key: k }; }
  else if (reward) rewardJson = reward; // 旧式 JSON 直传
  const codeStr = String(code || '').trim().toUpperCase() || randCode(12);
  db.prepare('INSERT INTO redeem_codes (code, title, title_id, reward, max_uses, used_count, per_user_once, expires_at, created_by, created_at) VALUES (?,?,?,?,?,0,?,?,?,?)')
    .run(codeStr, title || '', titleId || null, rewardJson ? JSON.stringify(rewardJson) : null, maxUses || 1, perUserOnce ? 1 : 0, expiresAt || null, actorId || 0, Date.now());
  audit(actorId || 0, '', 'create_redeem_code', 'redeem_code', codeStr, { title, reward: rewardJson });
  return codeStr;
}

// 批量随机生成兑换码：type 指定奖励类别，value 未给定时在对应类别内随机抽取。
// 返回 { codes: [...] }；单个码仍可被前台手动兑换，重复随机抽取不影响已发放内容。
function generateRedeemCodesRandom({ type, count, title, maxUses, perUserOnce, expiresAt }, actorId) {
  const n = Math.min(100, Math.max(1, Math.floor(Number(count) || 1)));
  const codes = [];
  for (let i = 0; i < n; i++) {
    let value = null;
    if (type === 'xp') value = 20 + Math.floor(Math.random() * 481); // 20~500
    else if (type === 'achievement') {
      const a = db.prepare('SELECT key FROM achievements ORDER BY RANDOM() LIMIT 1').get();
      value = a ? a.key : null;
    } else if (type === 'title') {
      const t = db.prepare('SELECT key FROM titles ORDER BY RANDOM() LIMIT 1').get();
      value = t ? t.key : null;
    }
    codes.push(generateRedeemCode({ title: title || '随机奖励', type, value, maxUses: maxUses || 1, perUserOnce, expiresAt }, actorId));
  }
  return codes;
}

function redeemCode(uid, code) {
  const c = db.prepare('SELECT * FROM redeem_codes WHERE code = ?').get(String(code || '').trim().toUpperCase());
  if (!c) return { error: 'invalid_code' };
  if (c.expires_at && Date.now() > c.expires_at) return { error: 'expired' };
  if (c.used_count >= c.max_uses) return { error: 'used_up' };
  if (c.per_user_once) {
    const used = db.prepare('SELECT id FROM redeem_code_uses WHERE code_id = ? AND user_id = ?').get(c.id, uid);
    if (used) return { error: 'already_used' };
  }
  // 称号（旧字段 title_id）
  if (c.title_id) grantTitle(uid, c.title_id, null, 0);
  // 奖励：经验 / 成就 / 称号（新 type 结构），兼容旧 {xp} 结构
  let xp = 0, leveledUp = false, newLevel = levelForXp(getXp(uid)), granted = '';
  let r = null; try { r = JSON.parse(c.reward); } catch (_) { r = null; }
  if (r) {
    if (r.type === 'xp' || typeof r.xp === 'number') {
      const v = Math.max(0, Math.floor(Number(r.xp) || 0));
      if (v > 0) { const a = awardXp(uid, 'achievement', v); xp = a.xp; leveledUp = a.leveledUp; newLevel = a.newLevel; granted = '+' + xp + ' XP'; }
    } else if (r.type === 'achievement' && r.key) {
      const a = db.prepare('SELECT id, name FROM achievements WHERE key = ?').get(r.key);
      if (a) { const g = grantAchievement(uid, a.id, 'redeem:' + c.id + ':' + uid, 0); if (g.ok) granted = '成就「' + a.name + '」'; }
    } else if (r.type === 'title' && r.key) {
      const t = db.prepare('SELECT id, name FROM titles WHERE key = ?').get(r.key);
      if (t) { const g = grantTitle(uid, t.id, null, 0); if (g.ok) granted = '称号「' + t.name + '」'; }
    }
  }
  db.prepare('UPDATE redeem_codes SET used_count = used_count + 1 WHERE id = ?').run(c.id);
  db.prepare('INSERT INTO redeem_code_uses (code_id, user_id, created_at) VALUES (?, ?, ?)').run(c.id, uid, Date.now());
  audit(0, '', 'redeem_code', 'redeem_code', c.code, { user_id: uid });
  addNotification(uid, 'REDEEM', '兑换成功', '成功兑换' + (granted ? '：' + granted : (c.title ? '「' + c.title + '」' : '')), JSON.stringify({ code: c.code }));
  return { ok: true, title: c.title, granted, xp, leveledUp, newLevel };
}

// ================= 称号 =================
function listTitles() { return db.prepare('SELECT * FROM titles ORDER BY id').all(); }
function seedDefaultTitles() {
  const n = db.prepare('SELECT COUNT(*) c FROM titles').get().c;
  if (n === 0) {
    db.prepare("INSERT INTO titles (key,name,desc,icon,grant_type,created_at) VALUES (?,?,?,?,?,?)")
      .run('sponsor', '赞助者', '感谢您对本站的支持', '💎', 'owner', Date.now());
  }
}
function createTitle({ key, name, desc, icon, color, grantType, autoRule }, actorId) {
  const k = String(key || '').trim();
  if (!k) return { error: 'key_required' };
  if (db.prepare('SELECT id FROM titles WHERE key = ?').get(k)) return { error: 'key_exists' };
  db.prepare('INSERT INTO titles (key,name,desc,icon,color,grant_type,auto_rule,created_at) VALUES (?,?,?,?,?,?,?,?)')
    .run(k, name || k, desc || '', icon || '', sanitizeTitleColor(color), grantType || 'owner', autoRule ? JSON.stringify(autoRule) : null, Date.now());
  audit(actorId || 0, '', 'create_title', 'title', k, {});
  return { ok: true, key: k };
}
function sanitizeTitleColor(c) {
  return (typeof c === 'string' && COLOR_HEX.test(c)) ? c : '';
}
// 编辑称号（名称/描述/图标/底色）；key 不可改（作为稳定标识）
function updateTitle(id, { name, desc, icon, color }, actorId) {
  const t = db.prepare('SELECT * FROM titles WHERE id = ?').get(id);
  if (!t) return { error: 'unknown_title' };
  db.prepare('UPDATE titles SET name=?, desc=?, icon=?, color=? WHERE id=?')
    .run(name || t.name, desc !== undefined ? desc : t.desc, icon !== undefined ? icon : t.icon, color !== undefined ? sanitizeTitleColor(color) : t.color, id);
  audit(actorId || 0, '', 'update_title', 'title', t.key, {});
  return { ok: true };
}
function deleteTitle(id, actorId) {
  const t = db.prepare('SELECT * FROM titles WHERE id = ?').get(id);
  if (!t) return { error: 'unknown_title' };
  db.prepare('DELETE FROM user_titles WHERE title_id = ?').run(id);
  db.prepare('DELETE FROM titles WHERE id = ?').run(id);
  audit(actorId || 0, '', 'delete_title', 'title', t.key, {});
  return { ok: true };
}
function grantTitle(uid, titleId, expireAt, actorId) {
  const t = db.prepare('SELECT * FROM titles WHERE id = ?').get(titleId);
  if (!t) return { error: 'unknown_title' };
  const ex = db.prepare('SELECT * FROM user_titles WHERE user_id = ? AND title_id = ?').get(uid, titleId);
  if (ex) {
    if (ex.revoked) db.prepare('UPDATE user_titles SET revoked = 0, expire_at = ?, granted_at = ? WHERE id = ?').run(expireAt || null, Date.now(), ex.id);
  } else {
    db.prepare('INSERT INTO user_titles (user_id, title_id, granted_by, granted_at, expire_at, revoked) VALUES (?, ?, ?, ?, ?, 0)')
      .run(uid, titleId, actorId || 0, Date.now(), expireAt || null);
  }
  addNotification(uid, 'TITLE', '获得称号', `你获得了称号「${t.name}」`, JSON.stringify({ title: t.key }));
  audit(actorId || 0, '', 'grant_title', 'title', t.key, { user_id: uid });
  return { ok: true, title: t.key };
}
function grantTitleByKey(uid, key, expireAt, actorId) {
  const t = db.prepare('SELECT id FROM titles WHERE key = ?').get(key);
  if (!t) return { error: 'unknown_title' };
  return grantTitle(uid, t.id, expireAt, actorId);
}
function revokeTitle(uid, titleId, actorId) {
  const t = db.prepare('SELECT * FROM titles WHERE id = ?').get(titleId);
  if (!t) return { error: 'unknown_title' };
  db.prepare('UPDATE user_titles SET revoked = 1 WHERE user_id = ? AND title_id = ?').run(uid, titleId);
  audit(actorId || 0, '', 'revoke_title', 'title', t.key, { user_id: uid });
  return { ok: true };
}

// 历史赞助二维码自动下架：早期赞助码曾作为普通图片上传（settings.sponsor_qr 指向 /uploads/xxx），
// 会出现在公共图库里。启动时识别这种遗留格式并把对应 images 记录标记为 hidden，
// 使其退出前台图库与搜索；后台仍可管理。幂等，可重复执行。
function hideLegacySponsorQr() {
  try {
    const row = db.prepare("SELECT value FROM settings WHERE key = 'sponsor_qr'").get();
    if (!row || !row.value) return 0;
    const m = /^\/uploads\/(.+)$/.exec(String(row.value).trim());
    if (!m) return 0; // 已是受控端点 /api/asset/... 或空，无需处理
    const n = db.prepare('UPDATE images SET hidden = 1 WHERE filename = ?').run(m[1]).changes;
    if (n) console.log('[迁移] 历史赞助二维码已从公共图库下架（标记为隐藏）');
    return n;
  } catch (_) { return 0; }
}

// 启动种子（默认任务 + 默认称号 + 历史赞助码下架 + 主页可见性迁移），幂等
try { seedTasks(); seedDefaultTitles(); hideLegacySponsorQr(); migrateProfileVisibilityOnce(); syncAllLevelsOnce(); } catch (_) {}

module.exports = {
  defaultPrivacy, ensureProfile, getPrivacy, sanitizePrivacy,
  getDefaultPrivacy, setDefaultPrivacy, migrateProfileVisibilityOnce, cleanupBrowseHistory, BROWSE_TTL, hideLegacySponsorQr,
  LEVEL_XP, MAX_LEVEL, levelForXp, getLevelColor, getLevelColors, setLevelColors,
  computeEffectiveMultiplier, invalidateMultiplier, awardXp, getXp, syncAllLevelsOnce,
  addNotification, activeTitles, displayTitle, userBadges, commentAuthor,
  getHome, recordBrowse, ageRange, isBirthdayToday, maskEmail, safeSocial,
  todayStr, getCheckinStatus, doCheckin,
  seedTasks, getTasks, getMyTasks, completeTask,
  invalidateAllMultipliers, applyAchievementMultiplier, grantAchievement, revokeAchievement,
  evaluateAutoAchievements, getAchievements, getMyAchievements,
  randCode, generateRedeemCode, generateRedeemCodesRandom, redeemCode,
  listTitles, seedDefaultTitles, createTitle, updateTitle, deleteTitle, grantTitle, grantTitleByKey, revokeTitle, titleColorOf, titleIconOf, titleDisplay,
  CARD_MIN_LEVEL, getUserLevel, isStaff, getMyCard, submitCard, reviewCard, listCards, sanitizeCardStyle,
};
