// 临时测试 #51：个人名片（Lv5+ 门槛 / 图片隔离 / 审核发布 / 隐私）
process.env.WO_DATA_DIR = require('path').join(__dirname, '.wotest_card');
process.env.JWT_SECRET = 'testsecret_card';
process.env.NODE_ENV = 'test';
process.env.PORT = '3997';
const path = require('path');
const fs = require('fs');
const jwt = require('jsonwebtoken');

function wipe() { try { fs.rmSync(path.join(__dirname, '.wotest_card'), { recursive: true, force: true }); } catch (_) {} }
wipe();
const db = require('./lib/db');

let fails = 0;
function assert(c, m) { if (!c) { console.error('FAIL:', m); fails++; } else console.log('PASS:', m); }

// 1x1 透明 PNG（合法魔数 89 50 4E 47）
const PNG = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==', 'base64');

(async () => {
  // 等级由 XP 推导（levelForXp）：造数据时必须写 xp，否则等级恒为 0
  const XP = { 4: 1400, 5: 2600, 10: 18000 };
  const mkUser = (name, xp) => db.prepare(
    "INSERT INTO users (username,username_lower,email,password_hash,role,created_at,level,xp) VALUES (?,?,?,?,?,?,?,?)"
  ).run(name, name, name + '@t.com', 'x', 'user', Date.now(), 0, xp).lastInsertRowid;
  const owner = db.prepare("INSERT INTO users (username,username_lower,email,password_hash,role,created_at,level,xp) VALUES (?,?,?,?,?,?,?,?)")
    .run('card_owner', 'card_owner', 'cowner@t.com', 'x', 'admin', Date.now(), 0, XP[10]).lastInsertRowid;
  const lv4 = mkUser('card_lv4', XP[4]);
  const lv5 = mkUser('card_lv5', XP[5]);

  const tok = (id, role) => jwt.sign({ uid: id, role }, 'testsecret_card', { expiresIn: '7d' });
  const cookie = (id, role) => `token=${tok(id, role)}`;
  const base = 'http://localhost:3997';
  const J = (id, role) => ({ 'Content-Type': 'application/json', 'X-Requested-With': 'WebOwn', Cookie: cookie(id, role) });
  const MULTI = (id, role) => ({ 'X-Requested-With': 'WebOwn', Cookie: cookie(id, role) }); // 不设 Content-Type，交给 fetch 定 boundary

  require('./server');
  await new Promise((r) => setTimeout(r, 450));

  const submit = async (uid, role, fields, png) => {
    const fd = new FormData();
    for (const [k, v] of Object.entries(fields)) fd.append(k, v);
    if (png) fd.append('file', new Blob([png], { type: 'image/png' }), 'card.png');
    return fetch(base + '/api/card', { method: 'POST', headers: MULTI(uid, role), body: fd });
  };

  // 1) Lv4 未解锁 -> 403 level_low
  let r = await submit(lv4, 'user', { title: 'x' });
  let d = await r.json();
  assert(r.status === 403 && d.error === 'level_low', 'card: Lv4 提交被拒 403 level_low');
  const my4 = await (await fetch(base + '/api/card', { headers: J(lv4, 'user') })).json();
  assert(my4.eligible === false && my4.card === null, 'card: Lv4 getMyCard eligible=false');

  // 2) Lv5 提交（含样式清洗：非法色值/未知键被丢弃）
  r = await submit(lv5, 'user', {
    title: '我的名片', intro: '简介',
    style: JSON.stringify({ bg: '#ffffff', fg: 'red', accent: '#123456', evil: '<script>' }),
  }, PNG);
  d = await r.json();
  assert(r.status === 200 && d.ok && d.card.status === 'pending', 'card: Lv5 提交成功，状态 pending ' + JSON.stringify(d.card && d.card.status));
  let my5 = await (await fetch(base + '/api/card', { headers: J(lv5, 'user') })).json();
  assert(my5.eligible === true && my5.card.has_image === true, 'card: Lv5 getMyCard eligible + has_image');
  assert(my5.card.style && my5.card.style.bg === '#ffffff' && my5.card.style.accent === '#123456'
    && my5.card.style.fg === undefined && my5.card.style.evil === undefined, 'card: 样式白名单清洗（只留合法十六进制色） ' + JSON.stringify(my5.card.style));

  // 3) 图片隔离：待审状态下匿名 403，本人/管理员可预览
  const imgUrl = base + '/api/card/' + lv5 + '/image';
  r = await fetch(imgUrl);
  assert(r.status === 403, 'card: 待审图片匿名访问 403（未审核不外泄）');
  r = await fetch(imgUrl, { headers: J(lv5, 'user') });
  assert(r.status === 200 && (r.headers.get('content-type') || '').includes('image/png'), 'card: 本人可预览待审图 200 image/png');
  r = await fetch(imgUrl, { headers: J(owner, 'admin') });
  assert(r.status === 200, 'card: 管理员可预览待审图 200');

  // 4) 隐私：默认 card=0 他人不可见；开启 card=1 后仍须 approved 才可见
  db.prepare("INSERT INTO user_profiles (user_id, privacy) VALUES (?,?) ON CONFLICT(user_id) DO UPDATE SET privacy=excluded.privacy")
    .run(lv5, JSON.stringify({ profile: 1, card: 1, comments: 1, level: 1, title: 1, badges: 1 }));
  let home = await (await fetch(base + '/api/user/' + lv5 + '/home')).json();
  assert(!home.home.card, 'card: 待审状态即使 card=1，他人主页也不显示（仅 approved 可见）');

  // 5) 审核通过 -> 匿名可看图 + 主页可见
  r = await fetch(base + '/api/admin/cards/' + lv5 + '/review', { method: 'POST', headers: J(owner, 'admin'), body: JSON.stringify({ action: 'approve' }) });
  d = await r.json();
  assert(r.status === 200 && d.status === 'approved', 'card: 管理员审核通过');
  r = await fetch(imgUrl);
  assert(r.status === 200, 'card: 审核通过后匿名可看图 200');
  home = await (await fetch(base + '/api/user/' + lv5 + '/home')).json();
  assert(home.home.card && home.home.card.has_image === true && home.home.card.title === '我的名片', 'card: 通过后他人主页可见名片（含图）');

  // 5b) 降级即时失效（安全：降级权限失效）
  db.prepare('UPDATE users SET xp = ? WHERE id = ?').run(XP[4], lv5);
  home = await (await fetch(base + '/api/user/' + lv5 + '/home')).json();
  assert(!home.home.card, 'card: 降级到 Lv4 后已通过名片即时隐藏');
  r = await fetch(imgUrl);
  assert(r.status === 403, 'card: 降级后图片匿名访问 403');
  // 5c) 封禁即时失效
  db.prepare('UPDATE users SET xp = ?, banned = 1 WHERE id = ?').run(XP[5], lv5);
  home = await (await fetch(base + '/api/user/' + lv5 + '/home')).json();
  assert(!home.home.card, 'card: 封禁后名片即时隐藏');
  db.prepare('UPDATE users SET banned = 0 WHERE id = ?').run(lv5);
  home = await (await fetch(base + '/api/user/' + lv5 + '/home')).json();
  assert(home.home.card, 'card: 恢复 Lv5 且解封后名片重新可见');

  // 6) 驳回 -> 带原因 + 通知；主页再次不可见
  await submit(lv5, 'user', { title: '改名', intro: 'x' }); // 重新提交回到 pending
  r = await fetch(base + '/api/admin/cards/' + lv5 + '/review', { method: 'POST', headers: J(owner, 'admin'), body: JSON.stringify({ action: 'reject', reason: '含违规内容' }) });
  d = await r.json();
  assert(r.status === 200 && d.status === 'rejected', 'card: 驳回 rejected');
  const cardRow = db.prepare('SELECT status, reject_reason FROM business_cards WHERE user_id=?').get(lv5);
  assert(cardRow.status === 'rejected' && cardRow.reject_reason === '含违规内容', 'card: 驳回原因落库');
  const notif = db.prepare("SELECT id FROM notifications WHERE user_id=? AND type='CARD_REVIEW'").get(lv5);
  assert(notif, 'card: 审核结果通知本人');
  home = await (await fetch(base + '/api/user/' + lv5 + '/home')).json();
  assert(!home.home.card, 'card: 驳回后他人主页不再可见');

  // 7) 伪装扩展名（垃圾字节）被魔数校验拦截，且不改动已存图片路径
  const beforeImg = db.prepare('SELECT image_path FROM business_cards WHERE user_id=?').get(lv5).image_path;
  r = await submit(lv5, 'user', { title: '坏图' }, Buffer.from('NOTANIMAGE'));
  d = await r.json();
  assert(r.status === 400, 'card: 非图片字节被拒 400');
  const afterImg = db.prepare('SELECT image_path FROM business_cards WHERE user_id=?').get(lv5).image_path;
  assert(beforeImg === afterImg, 'card: 非法上传不改动已存图片路径');

  // 8) 下架 -> 他人主页不可见
  await fetch(base + '/api/admin/cards/' + lv5 + '/review', { method: 'POST', headers: J(owner, 'admin'), body: JSON.stringify({ action: 'approve' }) });
  r = await fetch(base + '/api/admin/cards/' + lv5 + '/review', { method: 'POST', headers: J(owner, 'admin'), body: JSON.stringify({ action: 'takedown', reason: '下架' }) });
  d = await r.json();
  assert(r.status === 200 && d.status === 'taken_down', 'card: 下架 taken_down');
  home = await (await fetch(base + '/api/user/' + lv5 + '/home')).json();
  assert(!home.home.card, 'card: 下架后他人主页不可见');

  // 9) 管理端列表 + 鉴权：普通用户不可见待审列表
  r = await fetch(base + '/api/admin/cards?status=all', { headers: J(lv5, 'user') });
  assert(r.status === 403, 'card: 普通用户访问审核列表 403');
  r = await fetch(base + '/api/admin/cards?status=all', { headers: J(owner, 'admin') });
  d = await r.json();
  assert(r.status === 200 && Array.isArray(d.cards) && d.cards.length >= 1, 'card: 管理员可见审核列表');

  // 10) 审计留痕
  const audits = db.prepare("SELECT action FROM audit_log WHERE object_type='business_card'").all().map((x) => x.action);
  assert(audits.includes('submit_card') && audits.some((a) => a.startsWith('review_card_')), 'card: 提交/审核均有审计留痕 ' + JSON.stringify(audits));

  // 11) 路径遍历防护：不存在的用户 -> 404
  r = await fetch(base + '/api/card/999999/image');
  assert(r.status === 404, 'card: 不存在用户图片 404');

  console.log(fails === 0 ? 'ALL PASS' : ('FAILS=' + fails));
  wipe();
  process.exit(fails ? 1 : 0);
})().catch((e) => { console.error('ERR', e); wipe(); process.exit(2); });
