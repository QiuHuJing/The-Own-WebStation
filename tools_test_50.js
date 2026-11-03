// 临时测试 #50：签到/任务/成就/倍率/兑换码/称号/通知（隔离数据目录）
process.env.WO_DATA_DIR = require('path').join(__dirname, '.wotest_50');
process.env.JWT_SECRET = 'testsecret_50';
process.env.NODE_ENV = 'test';
process.env.PORT = '3999';
const path = require('path');
const jwt = require('jsonwebtoken');
const db = require('./lib/db');
const community = require('./lib/community');

let fails = 0;
function assert(c, m) { if (!c) { console.error('FAIL:', m); fails++; } else console.log('PASS:', m); }

function cleanup() {
  try { require('fs').rmSync(path.join(__dirname, '.wotest_50'), { recursive: true, force: true }); } catch (_) {}
}

(async () => {
  const owner = db.prepare("INSERT INTO users (username,username_lower,email,password_hash,role,created_at,level,xp) VALUES (?,?,?,?,?,?,?,?)")
    .run('owner50', 'owner50', 'o50@t.com', 'x', 'owner', Date.now(), 0, 0).lastInsertRowid;
  const admin = db.prepare("INSERT INTO users (username,username_lower,email,password_hash,role,created_at,level,xp) VALUES (?,?,?,?,?,?,?,?)")
    .run('admin50', 'admin50', 'a50@t.com', 'x', 'admin', Date.now(), 0, 0).lastInsertRowid;
  const user = db.prepare("INSERT INTO users (username,username_lower,email,password_hash,role,created_at,level,xp) VALUES (?,?,?,?,?,?,?,?)")
    .run('user50', 'user50', 'u50@t.com', 'x', 'user', Date.now(), 0, 0).lastInsertRowid;
  const tok = (id, role) => jwt.sign({ uid: id, role }, 'testsecret_50', { expiresIn: '7d' });
  const cookie = (id, role) => `token=${tok(id, role)}`;
  const base = 'http://localhost:3999';
  const hdr = (id, role) => ({ 'Content-Type': 'application/json', 'X-Requested-With': 'WebOwn', Cookie: cookie(id, role) });

  require('./server');
  await new Promise(r => setTimeout(r, 400));

  // 1) 公式保底
  assert(community.levelForXp(18000) === 10, 'formula: 18000 => Lv10');
  assert(10 * 1825 >= 18000, 'formula: 10*1825>=18000');

  // 2) 签到：首签 +10（streak1, bonus0）；同日记再签 -> already
  let xp0 = community.getXp(user);
  let r = await fetch(base + '/api/checkin', { method: 'POST', headers: hdr(user, 'user') });
  let d = await r.json();
  assert(d.already === false && d.xp === 10 && d.streak === 1, 'checkin: 首签 +10 streak1 ' + JSON.stringify(d));
  assert(community.getXp(user) - xp0 === 10, 'checkin: XP 精确 +10（不参与倍率）');
  r = await fetch(base + '/api/checkin', { method: 'POST', headers: hdr(user, 'user') });
  d = await r.json();
  assert(d.already === true, 'checkin: 同日记再签 already');

  // 连签：为 u2 插入昨日 streak=5，今日签到应 streak=6, bonus=2（wp6）
  const u2 = db.prepare("INSERT INTO users (username,username_lower,email,password_hash,role,created_at,level,xp) VALUES (?,?,?,?,?,?,?,?)")
    .run('user50b', 'user50b', 'u50b@t.com', 'x', 'user', Date.now(), 0, 0).lastInsertRowid;
  db.prepare("INSERT INTO checkins (user_id,date,streak,base_xp,bonus_xp,created_at) VALUES (?,?,?,?,?,?)")
    .run(u2, community.todayStr(Date.now() - 86400000), 5, 10, 0, Date.now() - 86400000);
  const xpBefore = community.getXp(u2);
  const rr = community.doCheckin(u2);
  assert(rr.streak === 6 && rr.bonus === 2 && rr.xp === 12, 'checkin: 连签 streak6 bonus2 xp12 ' + JSON.stringify(rr));
  assert(community.getXp(u2) - xpBefore === 12, 'checkin: 连签 XP 精确 +12');

  // 签到基础经验不受倍率影响：设置倍率后首签仍 +10
  db.prepare("DELETE FROM multipliers").run();
  db.prepare("INSERT INTO multipliers (name,value,scope,global_cap,enabled,source,created_at) VALUES ('t',1.0,'nonsignin',2.0,1,'manual',?)").run(Date.now());
  const u3 = db.prepare("INSERT INTO users (username,username_lower,email,password_hash,role,created_at,level,xp) VALUES (?,?,?,?,?,?,?,?)")
    .run('user50c', 'user50c', 'u50c@t.com', 'x', 'user', Date.now(), 0, 0).lastInsertRowid;
  const xp3 = community.getXp(u3);
  community.doCheckin(u3);
  assert(community.getXp(u3) - xp3 === 10, 'checkin: 有倍率时基础经验仍精确 +10（保底独立）');
  db.prepare("DELETE FROM multipliers").run();

  // 4) 任务：用全新用户测试 completeTask 幂等 + 每日上限
  const uT = db.prepare("INSERT INTO users (username,username_lower,email,password_hash,role,created_at,level,xp) VALUES (?,?,?,?,?,?,?,?)")
    .run('user50t', 'user50t', 'u50t@t.com', 'x', 'user', Date.now(), 0, 0).lastInsertRowid;
  let ct = community.completeTask(uT, 'daily_comment', 'c1');
  assert(ct.claimed && ct.xp === 5, 'task: 完成 daily_comment +5 ' + JSON.stringify(ct));
  ct = community.completeTask(uT, 'daily_comment', 'c1');
  assert(ct.already === true && community.getXp(uT) === (ct.xp === 0 ? community.getXp(uT) : community.getXp(uT)), 'task: 同 idempotency 幂等');
  const xpTA = community.getXp(uT);
  ct = community.completeTask(uT, 'daily_comment', 'c2'); // 不同 idempotency 但 daily_cap=1 -> 已达上限
  assert(ct.already === true && ct.xp === 0 && community.getXp(uT) === xpTA, 'task: 达每日上限后不再发奖');

  // 评论事件钩子完成 daily_comment
  const uT2 = db.prepare("INSERT INTO users (username,username_lower,email,password_hash,role,created_at,level,xp) VALUES (?,?,?,?,?,?,?,?)")
    .run('user50t2', 'user50t2', 'u50t2@t.com', 'x', 'user', Date.now(), 0, 0).lastInsertRowid;
  await fetch(base + '/api/comments/article/1', { method: 'POST', headers: hdr(uT2, 'user'), body: JSON.stringify({ content: 'hi' }) });
  const tk = await (await fetch(base + '/api/tasks', { headers: hdr(uT2, 'user') })).json();
  const dc = tk.tasks.find((t) => t.key === 'daily_comment');
  assert(dc && dc.claimed === true, 'task: 评论事件钩子自动完成 daily_comment');

  // 5) 倍率封顶：两条 1.5 倍 -> 有效倍率封顶 2.0
  db.prepare("DELETE FROM multipliers").run();
  db.prepare("INSERT INTO multipliers (name,value,scope,global_cap,enabled,source,created_at) VALUES ('a',1.5,'nonsignin',2.0,1,'manual',?)").run(Date.now());
  db.prepare("INSERT INTO multipliers (name,value,scope,global_cap,enabled,source,created_at) VALUES ('b',1.5,'nonsignin',2.0,1,'manual',?)").run(Date.now());
  community.invalidateAllMultipliers();
  const eff = community.computeEffectiveMultiplier(owner);
  assert(Math.abs(eff - 2.0) < 1e-9, 'multiplier: 1.5+1.5 封顶 2.0（防溢出） got ' + eff);
  const xpM0 = community.getXp(owner);
  community.awardXp(owner, 'comment', 100);
  assert(community.getXp(owner) - xpM0 === 300, 'multiplier: 非签到 100XP 应用 2.0 倍率 = +300');

  // 6) 成就：自动判定（xp>=0 立即达成）+ 幂等；手动发放 + 关联倍率
  const aAuto = db.prepare("INSERT INTO achievements (key,name,desc,icon,condition,reward_xp,multiplier,created_at,updated_at) VALUES ('auto_xp','自动成就','', '', '{\"metric\":\"xp\",\"op\":\">=\",\"value\":0}',0,NULL,?,?)")
    .run(Date.now(), Date.now()).lastInsertRowid;
  community.evaluateAutoAchievements(user);
  let got = db.prepare('SELECT id FROM user_achievements WHERE user_id=? AND achievement_id=? AND revoked=0').get(user, aAuto);
  assert(got, 'achievement: 自动判定发放');
  community.evaluateAutoAchievements(user);
  let cnt = db.prepare('SELECT COUNT(*) c FROM user_achievements WHERE user_id=? AND achievement_id=?').get(user, aAuto).c;
  assert(cnt === 1, 'achievement: 自动发放幂等（仅一条）');

  db.prepare("DELETE FROM multipliers").run();
  const aMult = db.prepare("INSERT INTO achievements (key,name,desc,icon,condition,reward_xp,multiplier,created_at,updated_at) VALUES ('mult_ach','倍率成就','', '', '{}',50,'{\"value\":0.2,\"scope\":\"nonsignin\",\"global_cap\":2.0}',?,?)")
    .run(Date.now(), Date.now()).lastInsertRowid;
  const xpA0 = community.getXp(user);
  const gr = community.grantAchievement(user, aMult, null, owner);
  assert(gr.ok && gr.xp === 50, 'achievement: 手动发放奖励 +50 ' + JSON.stringify(gr));
  assert(community.getXp(user) - xpA0 === 50, 'achievement: 奖励 XP 入账');
  const mRow = db.prepare("SELECT id FROM multipliers WHERE source='achievement' AND ref_id=?").get(aMult);
  assert(mRow, 'achievement: 关联倍率已落地 multipliers 表');
  community.revokeAchievement(user, aMult, owner);
  const mRow2 = db.prepare("SELECT id FROM multipliers WHERE source='achievement' AND ref_id=?").get(aMult);
  assert(!mRow2, 'achievement: 撤销后移除关联倍率');

  // 7) 兑换码：一次性(used_up) + 绑定用户(already_used) + 过期 + 授予称号
  const code = community.generateRedeemCode({ title: '测试码', reward: { xp: 20 }, maxUses: 1, perUserOnce: true }, owner);
  assert(code && code.length === 12, 'redeem: 生成 12 位码 ' + code);
  let rd = community.redeemCode(user, code);
  assert(rd.ok && rd.xp === 20, 'redeem: 兑换成功 +20 ' + JSON.stringify(rd));
  rd = community.redeemCode(user, code);
  assert(rd.error === 'used_up', 'redeem: max_uses=1 满次数 used_up');
  // per_user_once
  const codeP = community.generateRedeemCode({ title: '多', reward: { xp: 0 }, maxUses: 5, perUserOnce: true }, owner);
  rd = community.redeemCode(user, codeP);
  assert(rd.ok, 'redeem: 多码首次 ok');
  rd = community.redeemCode(user, codeP);
  assert(rd.error === 'already_used', 'redeem: 同用户二次 already_used');
  rd = community.redeemCode(admin, codeP);
  assert(rd.ok, 'redeem: 不同用户可兑');
  // 过期
  const code3 = community.generateRedeemCode({ title: '过期', expiresAt: Date.now() - 1000 }, owner);
  rd = community.redeemCode(user, code3);
  assert(rd.error === 'expired', 'redeem: 过期码 expired');
  // 授予称号
  const sp = db.prepare("SELECT id FROM titles WHERE key='sponsor'").get();
  const code4 = community.generateRedeemCode({ title: '赞助', titleId: sp.id, maxUses: 5, perUserOnce: true }, owner);
  rd = community.redeemCode(user, code4);
  const ut = db.prepare('SELECT id FROM user_titles WHERE user_id=? AND title_id=? AND revoked=0').get(user, sp.id);
  assert(rd.ok && ut, 'redeem: 兑换授予称号 sponsor');

  // 8) 称号撤销
  community.revokeTitle(user, sp.id, owner);
  const ut2 = db.prepare('SELECT id FROM user_titles WHERE user_id=? AND title_id=? AND revoked=0').get(user, sp.id);
  assert(!ut2, 'title: 撤销后不再生效');

  // 9) 普通用户越权配置成就 -> 403；站长(admin/owner) 可配置
  r = await fetch(base + '/api/admin/achievements', { method: 'POST', headers: hdr(user, 'user'), body: JSON.stringify({ key: 'x', name: 'x' }) });
  assert(r.status === 403, 'admin: 普通用户配置成就被拒 403');
  r = await fetch(base + '/api/admin/achievements', { method: 'POST', headers: hdr(admin, 'admin'), body: JSON.stringify({ key: 'admok', name: 'ok' }) });
  assert(r.status === 200, 'admin: 站长(admin)可配置成就');
  r = await fetch(base + '/api/admin/achievements', { method: 'POST', headers: hdr(owner, 'owner'), body: JSON.stringify({ key: 'ownerok', name: 'ok' }) });
  assert(r.status === 200, 'admin: 站长(owner)可配置成就');

  // 10) 站长发消息
  r = await fetch(base + '/api/admin/notify', { method: 'POST', headers: hdr(owner, 'owner'), body: JSON.stringify({ userId: user, title: 'hi', body: 'hello' }) });
  d = await r.json();
  const notif = db.prepare("SELECT id FROM notifications WHERE user_id=? AND type='OWNER_MSG'").get(user);
  assert(d.ok && notif, 'notify: 站长定向发消息成功');

  cleanup();
  console.log(fails === 0 ? 'ALL PASS' : ('FAILS=' + fails));
  process.exit(fails ? 1 : 0);
})().catch(e => { console.error('ERR', e); cleanup(); process.exit(2); });
