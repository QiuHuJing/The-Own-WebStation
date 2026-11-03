// 临时测试：个人设置/隐私/主页/通知/评论增强 + 等级公式保底
process.env.WO_DATA_DIR = require('path').join(__dirname, '.wotest_comm');
process.env.JWT_SECRET = 'testsecret_comm';
process.env.NODE_ENV = 'test';
process.env.PORT = '3998';
const path = require('path');
const jwt = require('jsonwebtoken');
const db = require('./lib/db');
const community = require('./lib/community');

let fails = 0;
function assert(c, m) { if (!c) { console.error('FAIL:', m); fails++; } else console.log('PASS:', m); }

(async () => {
  const owner = db.prepare("INSERT INTO users (username,username_lower,email,password_hash,role,created_at,level) VALUES (?,?,?,?,?,?,?)")
    .run('owntest', 'owntest', 'o@t.com', 'x', 'owner', Date.now(), 0).lastInsertRowid;
  const other = db.prepare("INSERT INTO users (username,username_lower,email,password_hash,role,created_at,level) VALUES (?,?,?,?,?,?,?)")
    .run('othertest', 'othertest', 'p@t.com', 'x', 'user', Date.now(), 0).lastInsertRowid;
  const tok = (id, role) => jwt.sign({ uid: id, role }, 'testsecret_comm', { expiresIn: '7d' });
  const cookie = (id, role) => `token=${tok(id, role)}`;
  const base = 'http://localhost:3998';

  require('./server');
  await new Promise(r => setTimeout(r, 400));

  // 等级公式保底：仅签到 5 年(1825天) 达 Lv10
  assert(community.levelForXp(18000) === 10, 'formula: 18000 XP => Lv10');
  assert(community.levelForXp(17999) === 9, 'formula: 17999 XP => Lv9');
  assert(10 * 1825 >= 18000, 'formula: 10*1825>=18000 保底成立');

  // 个人资料默认值
  let r = await fetch(base + '/api/user/profile', { headers: { Cookie: cookie(owner, 'owner') } });
  let d = await r.json();
  assert(r.status === 200 && d.privacy && d.privacy.profile === 1 && d.privacy.favorites === 0 && d.privacy.email === 0,
    'profile: 默认隐私（主页/名片公开，收藏/邮箱等最小可见）');

  // 更新资料 + 隐私
  r = await fetch(base + '/api/user/profile', { method: 'PUT', headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'WebOwn', Cookie: cookie(owner, 'owner') }, body: JSON.stringify({
    gender: 'male', signature: 'hi<x>', social_github: 'https://github.com/x', social_qq: '12345',
    social_email: 'a@b.com', email_public: 1, birthday: '2000-01-01', birthday_visibility: 'age_range',
    privacy: { profile: 1, favorites: 0, browse_history: 0 },
  }) });
  assert(r.status === 200, 'profile: 更新成功 ' + JSON.stringify(d));

  // 非法社交链接被清空（XSS/钓鱼）
  await fetch(base + '/api/user/profile', { method: 'PUT', headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'WebOwn', Cookie: cookie(owner, 'owner') }, body: JSON.stringify({ social_github: 'javascript:alert(1)' }) });
  d = await (await fetch(base + '/api/user/profile', { headers: { Cookie: cookie(owner, 'owner') } })).json();
  assert(d.profile.social_github === '', 'profile: 危险链接被清空');

  // 创建文章并浏览，触发 browse_history
  r = await fetch(base + '/api/admin/articles', { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'WebOwn', Cookie: cookie(owner, 'owner') }, body: JSON.stringify({ title: 't', content: 'c' }) });
  const slug = (await r.json()).slug;
  await fetch(base + '/api/articles/' + slug, { headers: { Cookie: cookie(owner, 'owner') } });

  // 主页（自己）：应包含 signature / 社交 / 浏览历史；favorites 因隐私=0 仍返回（自己可见）
  r = await fetch(base + '/api/user/' + owner + '/home', { headers: { Cookie: cookie(owner, 'owner') } });
  d = await r.json();
  assert(r.status === 200 && d.home.signature === 'hi<x>' && d.home.browse_history.length >= 1, 'home: 自己可见签名+浏览历史');

  // 主页（他人）：profile=1 可见；favorites=0 对他人隐藏 → 返回 favorites=[]
  r = await fetch(base + '/api/user/' + owner + '/home', { headers: { Cookie: cookie(other, 'user') } });
  d = await r.json();
  assert(r.status === 200 && d.home.favorites && d.home.favorites.length === 0, 'home: 他人按隐私隐藏收藏');

  // 他人访问 profile=0 的用户主页应标记 profile_private
  db.prepare("UPDATE user_profiles SET privacy = ? WHERE user_id = ?").run(JSON.stringify({ profile: 0 }), owner);
  r = await fetch(base + '/api/user/' + owner + '/home', { headers: { Cookie: cookie(other, 'user') } });
  d = await r.json();
  assert(d.home.profile_private === true, 'home: profile=0 对他人标记私有');

  // 公开信息接口（评论用）：不暴露未公开字段；level 为 0（新用户）
  r = await fetch(base + '/api/user/' + owner + '/public', { headers: { Cookie: cookie(other, 'user') } });
  d = await r.json();
  assert(r.status === 200 && d.user && d.user.username === 'owntest', 'public: 返回基础公开信息');

  // 评论增强：发布评论后，列表含 avatar/level/title/badges
  await fetch(base + '/api/comments/article/' + (await (await fetch(base + '/api/articles/' + slug)).json()).article.id, { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'WebOwn', Cookie: cookie(owner, 'owner') }, body: JSON.stringify({ content: 'nice' }) });
  r = await fetch(base + '/api/comments/article/' + (await (await fetch(base + '/api/articles/' + slug)).json()).article.id);
  d = await r.json();
  assert(r.status === 200 && d.items[0] && 'level' in d.items[0] && 'badges' in d.items[0], 'comments: 含等级/徽章字段 ' + JSON.stringify(d).slice(0,200));

  // 通知：升级通知（直接调用 awardXp 触发）
  const before = db.prepare('SELECT COUNT(*) c FROM notifications WHERE user_id=? AND type=?').get(other, 'LEVEL_UP').c;
  community.awardXp(other, 'signin', 18000, null, null); // 直接拉满到 Lv10
  const after = db.prepare('SELECT COUNT(*) c FROM notifications WHERE user_id=? AND type=?').get(other, 'LEVEL_UP').c;
  assert(after > before, 'notify: 升级触发 LEVEL_UP 通知');

  // 清理
  try { require('fs').rmSync(path.join(__dirname, '.wotest_comm'), { recursive: true, force: true }); } catch (_) {}
  console.log(fails === 0 ? 'ALL PASS' : ('FAILS=' + fails));
  process.exit(fails ? 1 : 0);
})().catch(e => { console.error('ERR', e); process.exit(2); });
