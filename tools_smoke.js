// 回归 / 验收冒烟测试（隔离数据目录）
// 覆盖：既有功能不回归（文章/图库/项目/评论/通知/条款/公告/SPA 静态）
//       + #50 新增社区端点（签到/任务/成就/兑换/后台社区配置）
//       + 安全约束（鉴权门控 401/403、CSRF 自定义头、helmet 安全响应头）
// 运行：node tools_smoke.js   （会自动清理 .wotest_smoke）
process.env.WO_DATA_DIR = require('path').join(__dirname, '.wotest_smoke');
process.env.JWT_SECRET = 'testsecret_smoke';
process.env.NODE_ENV = 'test';
process.env.PORT = '3998';
const path = require('path');
const fs = require('fs');
const jwt = require('jsonwebtoken');

// 每次运行前清空隔离目录，避免上次残留导致 UNIQUE 冲突（幂等可复跑）
function wipe() {
  try { fs.rmSync(path.join(__dirname, '.wotest_smoke'), { recursive: true, force: true }); } catch (_) {}
}
wipe();

const db = require('./lib/db');
const community = require('./lib/community');

let fails = 0;
function assert(c, m) { if (!c) { console.error('FAIL:', m); fails++; } else console.log('PASS:', m); }

const seedUser = (name, role) => db.prepare(
  "INSERT INTO users (username,username_lower,email,password_hash,role,created_at,level,xp) VALUES (?,?,?,?,?,?,?,?)"
).run(name, name, name + '@t.com', 'x', role, Date.now(), 0, 0).lastInsertRowid;

(async () => {
  const owner = seedUser('sm_owner', 'owner');
  const admin = seedUser('sm_admin', 'admin');
  const user = seedUser('sm_user', 'user');
  const user2 = seedUser('sm_user2', 'user');

  const tok = (id, role) => jwt.sign({ uid: id, role }, 'testsecret_smoke', { expiresIn: '7d' });
  const cookie = (id, role) => `token=${tok(id, role)}`;
  const base = 'http://localhost:3998';
  const H = (id, role) => ({ 'Content-Type': 'application/json', 'X-Requested-With': 'WebOwn', Cookie: cookie(id, role) });
  const HnoCsrf = (id, role) => ({ 'Content-Type': 'application/json', Cookie: cookie(id, role) });

  require('./server');
  await new Promise((r) => setTimeout(r, 450));

  const GET = (p, opts) => fetch(base + p, opts);
  const POST = (p, hdr, body) => fetch(base + p, { method: 'POST', headers: hdr, body: body ? JSON.stringify(body) : undefined });

  // ---------- A. 既有公开端点不回归（应 200 且不 500） ----------
  for (const p of ['/api/articles', '/api/images', '/api/projects', '/api/terms', '/api/announcements', '/api/comments/article/1']) {
    const r = await GET(p);
    assert(r.status === 200, `legacy GET ${p} => 200 (got ${r.status})`);
  }
  // SPA 入口 + 静态资源（缓存戳版本）
  let r = await GET('/');
  assert(r.status === 200 && (r.headers.get('content-type') || '').includes('text/html'), 'SPA / => 200 text/html');
  r = await GET('/js/app.js?v=20261102e');
  assert(r.status === 200, 'static /js/app.js?v=20261102e => 200');

  // ---------- B. 安全响应头（helmet）仍在 ----------
  r = await GET('/api/articles');
  assert(r.headers.get('x-content-type-options') === 'nosniff', 'helmet: X-Content-Type-Options nosniff');
  assert((r.headers.get('content-security-policy') || '').includes("default-src 'self'"), 'helmet: CSP default-src self');

  // ---------- C. 鉴权门控（默认拒绝 / 最小权限） ----------
  r = await GET('/api/checkin');
  assert(r.status === 401, 'authz: 未登录 GET /api/checkin => 401');
  r = await GET('/api/admin/titles', { headers: H(user, 'user') });
  assert(r.status === 403, 'authz: 普通用户 GET /api/admin/titles => 403');
  r = await GET('/api/achievements/mine');
  assert(r.status === 401, 'authz: 未登录 GET /api/achievements/mine => 401');

  // ---------- D. CSRF（POST 必须带 X-Requested-With，否则拒绝） ----------
  r = await POST('/api/checkin', HnoCsrf(user, 'user'));
  assert(r.status === 403, 'csrf: 缺少自定义头 POST /api/checkin => 403');
  // 用 owner 做正例，避免消耗 user 的首次签到（section F 需要干净的签到状态）
  r = await POST('/api/checkin', H(owner, 'owner'));
  assert(r.status === 200, 'csrf: 带头 POST /api/checkin => 200');

  // ---------- E. 既有登录态端点不回归 ----------
  r = await GET('/api/auth/me', { headers: H(user, 'user') });
  let d = await r.json();
  assert(r.status === 200 && d.user && d.user.id === user, 'legacy: GET /api/auth/me 返回本人');
  r = await POST('/api/comments/article/1', H(user, 'user'), { content: 'hello' });
  d = await r.json();
  assert(r.status === 201 && d.level !== undefined && Array.isArray(d.badges), 'legacy: 发评论 201 且含等级/徽章增强字段');
  r = await GET('/api/notifications', { headers: H(user, 'user') });
  d = await r.json();
  assert(r.status === 200 && Array.isArray(d.items) && typeof d.unread === 'number', 'legacy: GET /api/notifications 结构正常');
  r = await POST('/api/notifications/read', H(user, 'user'), { all: true });
  assert(r.status === 200, 'legacy: 标记通知已读 200');

  // ---------- F. 新社区端点（前端页面依赖的接口） ----------
  r = await GET('/api/checkin', { headers: H(user, 'user') });
  d = await r.json();
  assert(r.status === 200 && typeof d.checkedToday === 'boolean' && typeof d.streak === 'number', 'community: GET /checkin 结构正常 ' + JSON.stringify(d));

  r = await POST('/api/checkin', H(user, 'user'));
  d = await r.json();
  assert(r.status === 200 && d.already === false && d.xp === 10, 'community: 首签 +10 ' + JSON.stringify(d));
  r = await POST('/api/checkin', H(user, 'user'));
  d = await r.json();
  assert(d.already === true, 'community: 同日重复签到 already=true');

  r = await GET('/api/tasks', { headers: H(user, 'user') });
  d = await r.json();
  assert(r.status === 200 && Array.isArray(d.tasks) && d.tasks.length > 0, 'community: GET /tasks 返回任务列表');
  const dc = d.tasks.find((x) => x.key === 'daily_comment');
  assert(dc && dc.claimed === true, 'community: 评论已自动完成 daily_comment 任务');

  r = await GET('/api/achievements');
  d = await r.json();
  assert(r.status === 200 && Array.isArray(d.achievements), 'community: 公开成就墙 GET /achievements');
  r = await GET('/api/achievements/mine', { headers: H(user, 'user') });
  d = await r.json();
  assert(r.status === 200 && Array.isArray(d.achievements), 'community: 我的成就 GET /achievements/mine');

  r = await POST('/api/redeem', H(user, 'user'), { code: 'NOSUCHCODE1' });
  assert(r.status === 400, 'community: 无效兑换码 => 400（非 500）');

  // ---------- G. 后台社区配置（admin/owner 可读可写；结构匹配前端渲染） ----------
  r = await GET('/api/admin/titles', { headers: H(admin, 'admin') });
  d = await r.json();
  assert(r.status === 200 && Array.isArray(d.titles), 'admin: GET /admin/titles => {titles}');
  r = await POST('/api/admin/titles', H(admin, 'admin'), { key: 'sm_t1', name: '冒烟称号' });
  assert(r.status === 200, 'admin: POST /admin/titles 新建称号');

  r = await GET('/api/admin/achievements', { headers: H(admin, 'admin') });
  d = await r.json();
  assert(r.status === 200 && Array.isArray(d.achievements), 'admin: GET /admin/achievements => {achievements}');
  r = await POST('/api/admin/achievements', H(admin, 'admin'), { key: 'sm_a1', name: '冒烟成就', condition: { metric: 'xp', op: '>=', value: 0 }, reward_xp: 5 });
  assert(r.status === 200, 'admin: POST /admin/achievements 新建成就');

  r = await GET('/api/admin/multipliers', { headers: H(admin, 'admin') });
  d = await r.json();
  assert(r.status === 200 && Array.isArray(d.multipliers), 'admin: GET /admin/multipliers => {multipliers}');
  r = await POST('/api/admin/multipliers', H(admin, 'admin'), { name: '冒烟倍率', value: 0.1, scope: 'nonsignin', global_cap: 2.0 });
  assert(r.status === 200, 'admin: POST /admin/multipliers 新建倍率');

  r = await GET('/api/admin/redeem-codes', { headers: H(admin, 'admin') });
  d = await r.json();
  assert(r.status === 200 && Array.isArray(d.codes), 'admin: GET /admin/redeem-codes => {codes}');
  r = await POST('/api/admin/redeem-codes', H(admin, 'admin'), { title: '冒烟码', maxUses: 2, perUserOnce: true });
  d = await r.json();
  assert(r.status === 200 && d.ok && typeof d.code === 'string' && d.code.length === 12, 'admin: POST /admin/redeem-codes 生成 12 位码');

  r = await POST('/api/admin/notify', H(admin, 'admin'), { userId: user2, title: 'hi', body: 'hello' });
  d = await r.json();
  assert(r.status === 200 && d.ok && d.count >= 1, 'admin: POST /admin/notify 定向群发 ' + JSON.stringify(d));

  // owner 同样具备站长权限（本系统最高角色 admin=站长，兼容 owner）
  r = await GET('/api/admin/titles', { headers: H(owner, 'owner') });
  assert(r.status === 200, 'admin: owner 亦可访问后台社区配置');

  // ---------- H. 收尾回归：跑完一圈后既有列表仍健康（无状态污染） ----------
  r = await GET('/api/articles');
  assert(r.status === 200, 'regression: 全流程后 GET /api/articles 仍 200');

  console.log(fails === 0 ? 'ALL PASS' : ('FAILS=' + fails));
  wipe();
  process.exit(fails ? 1 : 0);
})().catch((e) => { console.error('ERR', e); wipe(); process.exit(2); });
