// 临时测试：模糊项优化（图片元数据剥离 / 浏览记录 TTL / 用户搜索 / 隐私默认值）
process.env.WO_DATA_DIR = require('path').join(__dirname, '.wotest_opt');
process.env.JWT_SECRET = 'testsecret_opt';
process.env.NODE_ENV = 'test';
process.env.PORT = '3996';
process.env.BROWSE_TTL_MS = '1000'; // 便于验证清理时序
const path = require('path');
const fs = require('fs');
const jwt = require('jsonwebtoken');

function wipe() { try { fs.rmSync(path.join(__dirname, '.wotest_opt'), { recursive: true, force: true }); } catch (_) {} }
wipe();
const db = require('./lib/db');
const community = require('./lib/community');
const { stripJpeg, stripPng, stripWebp } = require('./lib/image-sanitize');

let fails = 0;
function assert(c, m) { if (!c) { console.error('FAIL:', m); fails++; } else console.log('PASS:', m); }

// ---------- 二进制夹具 ----------
function jpegWithApp1() {
  const payload = Buffer.concat([Buffer.from('Exif\0\0', 'latin1'), Buffer.from('GPS-SECRET-DATA', 'latin1')]);
  const app1 = Buffer.alloc(4 + payload.length);
  app1[0] = 0xFF; app1[1] = 0xE1; app1.writeUInt16BE(payload.length + 2, 2); payload.copy(app1, 4);
  return Buffer.concat([Buffer.from([0xFF, 0xD8]), app1, Buffer.from([0xFF, 0xD9])]);
}
function jpegPlain() {
  // SOI + APP0(JFIF) + EOI（无 EXIF）
  const app0 = Buffer.from([0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46, 0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00]);
  return Buffer.concat([Buffer.from([0xFF, 0xD8]), app0, Buffer.from([0xFF, 0xD9])]);
}
function pngChunk(type, data) {
  const b = Buffer.alloc(12 + data.length);
  b.writeUInt32BE(data.length, 0); b.write(type, 4, 'latin1'); data.copy(b, 8); b.writeUInt32BE(0, 8 + data.length);
  return b;
}
function pngWithText() {
  const SIG = Buffer.from([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]);
  return Buffer.concat([
    SIG,
    pngChunk('IHDR', Buffer.alloc(13)),
    pngChunk('tEXt', Buffer.from('Author\0secret', 'latin1')),
    pngChunk('IDAT', Buffer.alloc(4)),
    pngChunk('IEND', Buffer.alloc(0)),
  ]);
}
function pngTypes(buf) {
  const t = []; let i = 8;
  while (i + 12 <= buf.length) { const len = buf.readUInt32BE(i); t.push(buf.slice(i + 4, i + 8).toString('latin1')); i += 12 + len; if (t[t.length - 1] === 'IEND') break; }
  return t;
}
function webpChunk(id, data) {
  const pad = data.length & 1; const b = Buffer.alloc(8 + data.length + pad);
  b.write(id, 0, 'latin1'); b.writeUInt32LE(data.length, 4); data.copy(b, 8); return b;
}
function webpWithExif() {
  const body = Buffer.concat([webpChunk('VP8 ', Buffer.alloc(6)), webpChunk('EXIF', Buffer.from('GPS-SECRET', 'latin1'))]);
  const header = Buffer.alloc(12);
  header.write('RIFF', 0, 'latin1'); header.writeUInt32LE(body.length + 4, 4); header.write('WEBP', 8, 'latin1');
  return Buffer.concat([header, body]);
}
function webpIds(buf) {
  const t = []; let i = 12;
  while (i + 8 <= buf.length) { const id = buf.slice(i, i + 4).toString('latin1'); const size = buf.readUInt32LE(i + 4); t.push(id); i += 8 + size + (size & 1); }
  return t;
}

(async () => {
  // ---------- A. 图片元数据剥离 ----------
  {
    const src = jpegWithApp1();
    const r = stripJpeg(src);
    const expect = Buffer.concat([Buffer.from([0xFF, 0xD8]), Buffer.from([0xFF, 0xD9])]);
    assert(r.changed === true && r.buf.equals(expect), 'exif: JPEG 剥离 APP1/EXIF，仅保留 SOI+EOI');
    const plain = jpegPlain();
    const r2 = stripJpeg(plain);
    assert(r2.changed === false && r2.buf.equals(plain), 'exif: 无 EXIF 的 JPEG 保持原样');
    const png = pngWithText();
    const rp = stripPng(png);
    const types = pngTypes(rp.buf);
    assert(rp.changed === true && !types.includes('tEXt') && types.includes('IHDR') && types.includes('IEND'), 'exif: PNG 剥离 tEXt，保留 IHDR/IDAT/IEND');
    const webp = webpWithExif();
    const rw = stripWebp(webp);
    const ids = webpIds(rw.buf);
    const riffSize = rw.buf.readUInt32LE(4);
    assert(rw.changed === true && !ids.includes('EXIF') && ids.includes('VP8 ') && riffSize === rw.buf.length - 8, 'exif: WebP 剥离 EXIF 且 RIFF 长度正确');
  }

  // ---------- 建用户 ----------
  // 等级由 XP 推导（LEVEL_XP）：造数据时写 xp，level 列交给服务端自愈
  const LV_XP = { 3: 700, 10: 18000 };
  const mk = (name, role, level) => db.prepare(
    "INSERT INTO users (username,username_lower,email,password_hash,role,created_at,level,xp) VALUES (?,?,?,?,?,?,?,?)"
  ).run(name, name, name + '@t.com', 'x', role, Date.now(), level || 0, LV_XP[level] || 0).lastInsertRowid;
  const admin = mk('opt_admin', 'admin', 10);
  const pub = mk('opt_pub_user', 'user', 3);
  const priv = mk('opt_priv_user', 'user', 3);
  const ttlUser = mk('opt_ttl_user', 'user', 0);

  // ---------- B. 浏览记录 TTL 清理 ----------
  db.prepare('INSERT INTO browse_history (user_id,target_type,target_id,last_viewed_at) VALUES (?,?,?,?)').run(ttlUser, 'article', 1, Date.now() - 5000);
  db.prepare('INSERT INTO browse_history (user_id,target_type,target_id,last_viewed_at) VALUES (?,?,?,?)').run(ttlUser, 'article', 2, Date.now());
  const n = community.cleanupBrowseHistory();
  const remain = db.prepare('SELECT target_id FROM browse_history WHERE user_id=? ORDER BY target_id').all(ttlUser).map((x) => x.target_id);
  assert(n === 1 && remain.length === 1 && remain[0] === 2, 'browse: TTL 到期记录被清理，未到期保留 ' + JSON.stringify({ n, remain }));

  // ---------- 公开主页用户（供搜索） ----------
  db.prepare("INSERT INTO user_profiles (user_id, privacy) VALUES (?, ?) ON CONFLICT(user_id) DO UPDATE SET privacy=excluded.privacy")
    .run(pub, JSON.stringify({ profile: 1, level: 1, title: 1, comments: 1, badges: 1 }));
  // 主动关闭主页可见性的用户（防枚举用例）
  db.prepare("INSERT INTO user_profiles (user_id, privacy) VALUES (?, ?) ON CONFLICT(user_id) DO UPDATE SET privacy=excluded.privacy")
    .run(priv, JSON.stringify({ profile: 0, level: 1, title: 1, comments: 1, badges: 1 }));

  const tok = (id, role) => jwt.sign({ uid: id, role }, 'testsecret_opt', { expiresIn: '7d' });
  const J = (id, role) => ({ 'Content-Type': 'application/json', 'X-Requested-With': 'WebOwn', Cookie: `token=${tok(id, role)}` });
  const base = 'http://localhost:3996';
  require('./server');
  await new Promise((r) => setTimeout(r, 450));

  // ---------- C. 用户搜索（仅公开主页 + 未封禁） ----------
  let r = await fetch(base + '/api/search?q=opt_pub_user&type=user');
  let d = await r.json();
  assert(r.status === 200 && d.items.some((x) => x.type === 'user' && x.id === pub), 'search: 公开主页用户可被搜索到');
  r = await fetch(base + '/api/search?q=opt_priv_user&type=user');
  d = await r.json();
  assert(r.status === 200 && !d.items.some((x) => x.id === priv), 'search: 未公开主页用户不出现（防枚举隐私）');
  // 封禁后不可搜
  db.prepare('UPDATE users SET banned=1 WHERE id=?').run(pub);
  r = await fetch(base + '/api/search?q=opt_pub_user&type=user');
  d = await r.json();
  assert(!d.items.some((x) => x.id === pub), 'search: 封禁用户不出现在用户搜索');
  db.prepare('UPDATE users SET banned=0 WHERE id=?').run(pub);

  // ---------- D. 隐私默认值（站长可配） ----------
  r = await fetch(base + '/api/admin/privacy-defaults', { headers: J(admin, 'admin') });
  d = await r.json();
  assert(r.status === 200 && d.privacy && d.privacy.profile === 1, 'privacyDefaults: 默认 profile=1（个人主页默认公开，用户可自行关闭）');
  // 默认公开 → 新用户无需任何设置即可被搜索到、主页可访问（修复「搜不到用户」）
  {
    const r2 = await fetch(base + '/api/search?q=opt_priv_user&type=user');
    const d2 = await r2.json();
    assert(r2.status === 200 && !d2.items.some((x) => x.id === priv), 'privacyDefaults: 用户主动关闭主页后仍搜不到（开关真实生效）');
  }
  r = await fetch(base + '/api/admin/privacy-defaults', { headers: J(pub, 'user') });
  assert(r.status === 403, 'privacyDefaults: 普通用户 403');
  r = await fetch(base + '/api/admin/privacy-defaults', { method: 'PUT', headers: J(admin, 'admin'), body: JSON.stringify({ privacy: { profile: 1, level: 1 } }) });
  d = await r.json();
  assert(r.status === 200 && d.ok && d.privacy.profile === 1, 'privacyDefaults: 站长修改 profile=1 生效');
  // 新建用户按新默认建档
  const newU = mk('opt_new_user', 'user', 0);
  const prof = community.ensureProfile(newU);
  const parsed = JSON.parse(prof.privacy);
  assert(parsed.profile === 1, 'privacyDefaults: 新用户首次建档采用新默认 profile=1');

  // ---------- E. 图库：隐藏赞助二维码等用途性图片 ----------
  const imgTitle = 'opt_sponsor_qr';
  const imgId = db.prepare('INSERT INTO images (filename, original_name, title, description, views, created_at, hidden) VALUES (?,?,?,?,?,?,0)')
    .run('opt-qr.png', 'opt-qr.png', imgTitle, 'sponsor qr', 0, Date.now()).lastInsertRowid;
  r = await fetch(base + '/api/images?size=36');
  d = await r.json();
  assert(d.items.some((x) => x.id === imgId), 'images: 默认出现在前台图库');
  const fdHide = new FormData(); fdHide.append('hidden', '1');
  r = await fetch(base + '/api/admin/images/' + imgId, { method: 'PUT', headers: { 'X-Requested-With': 'WebOwn', Cookie: `token=${tok(admin, 'admin')}` }, body: fdHide });
  assert(r.status === 200, 'images: 站长可切换隐藏');
  r = await fetch(base + '/api/images?size=36');
  d = await r.json();
  assert(!d.items.some((x) => x.id === imgId), 'images: 隐藏后不出现在前台图库');
  r = await fetch(base + '/api/search?q=' + encodeURIComponent(imgTitle) + '&type=image');
  d = await r.json();
  assert(!d.items.some((x) => x.id === imgId), 'images: 隐藏后不出现在搜索');
  r = await fetch(base + '/api/images?size=36&status=all', { headers: J(admin, 'admin') });
  d = await r.json();
  assert(d.items.some((x) => x.id === imgId), 'images: 后台(status=all)仍可见已隐藏图');
  r = await fetch(base + '/api/images?size=36&status=all', { headers: J(pub, 'user') });
  d = await r.json();
  assert(!d.items.some((x) => x.id === imgId), 'images: 普通用户传 status=all 也看不到隐藏图（权限校验）');

  // 历史赞助二维码：站点设置仍指向 /uploads/ 时，自动从公共图库下架
  db.prepare("INSERT INTO settings (key, value) VALUES ('sponsor_qr', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value")
    .run('/uploads/opt-qr.png');
  const legacyN = community.hideLegacySponsorQr();
  const legacyHidden = db.prepare('SELECT hidden FROM images WHERE id = ?').get(imgId);
  assert(legacyN === 1 && legacyHidden.hidden === 1, 'images: 历史赞助二维码(/uploads/)被自动下架 hidden=1');
  r = await fetch(base + '/api/images?size=36');
  d = await r.json();
  assert(!d.items.some((x) => x.id === imgId), 'images: 自动下架后不出现在前台图库');

  // ---------- F. 个人主页经验进度 ----------
  db.prepare('UPDATE users SET xp=?, level=? WHERE id=?').run(500, 2, pub); // Lv2 起 300 → Lv3 需 700
  r = await fetch(base + '/api/user/' + pub + '/home');
  d = await r.json();
  const xp = d.home && d.home.xp;
  assert(!!xp && xp.current === 500 && xp.next === 700 && xp.need === 200 && xp.percent === 50,
    'home: 经验进度返回 current/next/need/percent ' + JSON.stringify(xp));
  db.prepare('UPDATE users SET xp=?, level=? WHERE id=?').run(18000, 10, pub);
  r = await fetch(base + '/api/user/' + pub + '/home');
  d = await r.json();
  assert(d.home.xp.maxed === true && d.home.xp.percent === 100 && d.home.xp.next === null, 'home: 满级时 next=null、percent=100');

  // ---------- G. 站长名片：免等级门槛 + 免审核 ----------
  const staff = mk('opt_staff', 'admin', 1); // Lv1，低于名片门槛 Lv5
  r = await fetch(base + '/api/card', { headers: J(staff, 'admin') });
  d = await r.json();
  assert(r.status === 200 && d.eligible === true && d.staff === true, 'card: 站长不受 Lv5 门槛限制 eligible=true');
  const fdCard = new FormData();
  fdCard.append('title', '站长名片'); fdCard.append('intro', '站点管理员');
  fdCard.append('style', JSON.stringify({ bg: '#101024', fg: '#e8e8f0', accent: '#8b5cf6' }));
  r = await fetch(base + '/api/card', { method: 'POST', headers: { 'X-Requested-With': 'WebOwn', Cookie: `token=${tok(staff, 'admin')}` }, body: fdCard });
  d = await r.json();
  assert(r.status === 200 && d.auto_approved === true && d.card.status === 'approved', 'card: 站长名片提交后免审核直接发布 ' + JSON.stringify(d));
  r = await fetch(base + '/api/user/' + staff + '/home');
  d = await r.json();
  assert(!!(d.home && d.home.card && d.home.card.status === 'approved'), 'card: 站长主页直接展示已发布名片');
  // 普通用户（Lv1）仍受门槛限制
  const lowU = mk('opt_low_user', 'user', 1);
  r = await fetch(base + '/api/card', { headers: J(lowU, 'user') });
  d = await r.json();
  assert(r.status === 200 && d.eligible === false && d.staff === false, 'card: 普通 Lv1 用户仍受 Lv5 门槛限制');

  // ---------- H. 昵称修改 / 邮箱公开 ----------
  {
    const u1 = mk('opt_nick_user', 'user', 1);
    // 正常改名
    r = await fetch(base + '/api/user/username', { method: 'PUT', headers: J(u1, 'user'), body: JSON.stringify({ username: 'nick_new' }) });
    d = await r.json();
    assert(r.status === 200 && d.ok && d.username === 'nick_new', 'nick: 改名成功 ' + JSON.stringify(d));
    const row = db.prepare('SELECT username, username_lower FROM users WHERE id = ?').get(u1);
    assert(row.username === 'nick_new' && row.username_lower === 'nick_new', 'nick: username_lower 同步更新');
    // 改名后按新昵称可被搜索（旧昵称搜不到）
    r = await fetch(base + '/api/search?q=nick_new&type=user');
    d = await r.json();
    assert(d.items.some((x) => x.id === u1), 'nick: 改名后可用新昵称搜到');
    r = await fetch(base + '/api/search?q=opt_nick_user&type=user');
    d = await r.json();
    assert(!d.items.some((x) => x.id === u1), 'nick: 旧昵称不再出现在搜索');
    // 重名 400
    r = await fetch(base + '/api/user/username', { method: 'PUT', headers: J(u1, 'user'), body: JSON.stringify({ username: 'opt_pub_user' }) });
    assert(r.status === 400, 'nick: 昵称被占用返回 400');
    // 过短 400
    r = await fetch(base + '/api/user/username', { method: 'PUT', headers: J(u1, 'user'), body: JSON.stringify({ username: 'a' }) });
    assert(r.status === 400, 'nick: 昵称长度不合法返回 400');
    // 未登录 401
    r = await fetch(base + '/api/user/username', { method: 'PUT', headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'WebOwn' }, body: JSON.stringify({ username: 'hacker' }) });
    assert(r.status === 401, 'nick: 未登录 401');
    // 审计留痕
    const aud = db.prepare("SELECT COUNT(*) c FROM audit_log WHERE action = 'change_username' AND object_type = 'user'").get();
    assert(aud.c >= 1, 'nick: 改名有审计留痕');
  }
  {
    // 邮箱：账号绑定邮箱只读，仅可切换公开
    const u2 = mk('opt_mail_user', 'user', 1);
    r = await fetch(base + '/api/user/email-visibility', { method: 'PUT', headers: J(u2, 'user'), body: JSON.stringify({ public: 1 }) });
    d = await r.json();
    assert(r.status === 200 && d.ok && d.email_public === true, 'email: 切换公开成功');
    r = await fetch(base + '/api/user/' + u2 + '/home');
    d = await r.json();
    assert(d.home.email && d.home.email.startsWith('op***@'), 'email: 公开后主页展示脱敏账号邮箱 ' + JSON.stringify(d.home.email));
    r = await fetch(base + '/api/user/email-visibility', { method: 'PUT', headers: J(u2, 'user'), body: JSON.stringify({ public: 0 }) });
    await r.json();
    r = await fetch(base + '/api/user/' + u2 + '/home');
    d = await r.json();
    assert(!d.home.email, 'email: 关闭公开后主页不再返回邮箱');
    // 设置页不提供改邮箱入口：PUT /user/profile 不接受 email
    const before = db.prepare('SELECT email FROM users WHERE id = ?').get(u2).email;
    await fetch(base + '/api/user/profile', { method: 'PUT', headers: J(u2, 'user'), body: JSON.stringify({ email: 'pwn@t.com', social_email: 'pwn@t.com' }) });
    const after = db.prepare('SELECT email FROM users WHERE id = ?').get(u2).email;
    assert(before === after, 'email: 通过资料接口改邮箱无效（账号邮箱只读）');
  }

  // ---------- I. 内容定位 / 评论删除 / 评论隐私 / 等级颜色 / 兑换类型 / 任务 CRUD ----------
  {
    const u = mk('opt_href_user', 'user', 1);
    const aid = db.prepare("INSERT INTO articles (title,slug,summary,content,status,created_at,updated_at) VALUES ('opt文章','opt-article-1','','正文','published',?,?)").run(Date.now(), Date.now()).lastInsertRowid;
    const pid = db.prepare("INSERT INTO projects (title,repo_url,description,created_at) VALUES ('opt项目','https://github.com/a/b','',?)").run(Date.now()).lastInsertRowid;
    const iid = db.prepare("INSERT INTO images (filename,title,created_at,views,hidden) VALUES ('opt-i.png','opt图片',?,0,0)").run(Date.now()).lastInsertRowid;
    const sid = db.prepare("INSERT INTO social_posts (platform,title,url,status,created_at) VALUES ('bilibili','opt动态','https://www.bilibili.com/video/1','published',?)").run(Date.now()).lastInsertRowid;
    db.prepare("INSERT INTO favorites (target_type,target_id,user_id,created_at) VALUES ('article',?,?,?)").run(aid, u, Date.now());
    db.prepare("INSERT INTO likes (target_type,target_id,user_id,created_at) VALUES ('project',?,?,?)").run(pid, u, Date.now());
    db.prepare("INSERT INTO browse_history (user_id,target_type,target_id,last_viewed_at) VALUES (?,?,?,?)").run(u, 'image', iid, Date.now());
    db.prepare("INSERT INTO browse_history (user_id,target_type,target_id,last_viewed_at) VALUES (?,?,?,?)").run(u, 'social', sid, Date.now());
    r = await fetch(base + '/api/user/' + u + '/home', { headers: J(u, 'user') }); d = await r.json();
    const hh = d.home;
    assert(hh.favorites.some((x) => x.href === '#/article/opt-article-1' && x.title === 'opt文章'), 'href: 收藏文章按 slug 定位 ' + JSON.stringify(hh.favorites));
    assert(hh.likes.some((x) => x.href === '#/project/' + pid), 'href: 点赞项目按 id 定位');
    assert(hh.browse_history.some((x) => x.href === '#/image/' + iid), 'href: 浏览图片按 id 定位');
    assert(hh.browse_history.some((x) => x.external === true && String(x.href).startsWith('https://www.bilibili.com')), 'href: 浏览动态跳外链');
    db.prepare('DELETE FROM articles WHERE id = ?').run(aid);
    r = await fetch(base + '/api/user/' + u + '/home', { headers: J(u, 'user') }); d = await r.json();
    assert(!d.home.favorites.some((x) => x.id === aid), 'href: 目标被删后从列表剔除');
  }
  {
    // 评论删除（软删除 + 权限）
    const u = mk('opt_cmt_owner', 'user', 1);
    const u2 = mk('opt_cmt_other', 'user', 1);
    const aid = db.prepare("INSERT INTO articles (title,slug,summary,content,status,created_at,updated_at) VALUES ('c','opt-c-1','','x','published',?,?)").run(Date.now(), Date.now()).lastInsertRowid;
    const cid = db.prepare("INSERT INTO comments (target_type,target_id,user_id,content,created_at) VALUES ('article',?,?,?,?)").run(aid, u, '我的评论', Date.now()).lastInsertRowid;
    r = await fetch(base + '/api/comments/' + cid, { method: 'DELETE', headers: J(u2, 'user') });
    assert(r.status === 403, 'cmt: 他人删除 403');
    r = await fetch(base + '/api/comments/' + cid, { method: 'DELETE', headers: J(u, 'user') }); d = await r.json();
    assert(r.status === 200 && d.ok, 'cmt: 本人删除成功');
    assert(db.prepare('SELECT status FROM comments WHERE id=?').get(cid).status === 'hidden', 'cmt: 软删除为 hidden');
    r = await fetch(base + '/api/user/' + u + '/home'); d = await r.json();
    assert(!(d.home.comments || []).some((x) => x.id === cid), 'cmt: 删除后主页不再展示');
  }
  {
    // 评论隐私开关
    const u = mk('opt_cmt_priv', 'user', 1);
    const aid = db.prepare("INSERT INTO articles (title,slug,summary,content,status,created_at,updated_at) VALUES ('d','opt-d-1','','x','published',?,?)").run(Date.now(), Date.now()).lastInsertRowid;
    db.prepare("INSERT INTO comments (target_type,target_id,user_id,content,created_at) VALUES ('article',?,?,?,?)").run(aid, u, '可见评论', Date.now());
    db.prepare("INSERT INTO user_profiles (user_id, privacy) VALUES (?, ?) ON CONFLICT(user_id) DO UPDATE SET privacy=excluded.privacy").run(u, JSON.stringify({ comments: 0 }));
    r = await fetch(base + '/api/user/' + u + '/home'); d = await r.json();
    assert(Array.isArray(d.home.comments) && d.home.comments.length === 0, 'privacy: comments=0 对他人不返回评论');
    r = await fetch(base + '/api/user/' + u + '/home', { headers: J(u, 'user') }); d = await r.json();
    assert((d.home.comments || []).some((x) => x.content === '可见评论'), 'privacy: 本人仍可见自己的评论');
  }
  {
    // 等级颜色
    r = await fetch(base + '/api/admin/level-colors', { headers: J(admin, 'admin') }); d = await r.json();
    assert(d.colors && d.colors['1'] && d.colors['10'], 'levelColors: 默认返回 Lv1-10 颜色');
    const def2 = d.colors['2'];
    r = await fetch(base + '/api/admin/level-colors', { method: 'PUT', headers: J(admin, 'admin'), body: JSON.stringify({ colors: { '1': '#111111', '10': '#abcdef' } }) }); d = await r.json();
    assert(d.ok && d.colors['1'] === '#111111' && d.colors['10'] === '#abcdef' && d.colors['2'] === def2, 'levelColors: 自定义生效且未改项保留默认');
    r = await fetch(base + '/api/search?q=opt_pub_user&type=user'); d = await r.json();
    const hit = d.items.find((x) => x.type === 'user');
    assert(hit && hit.level_color && /^#[0-9a-f]{6}$/.test(hit.level_color), 'levelColors: 搜索用户带 level_color');
    r = await fetch(base + '/api/admin/level-colors', { headers: J(pub, 'user') });
    assert(r.status === 403, 'levelColors: 普通用户 403');
  }
  {
    // 兑换类型（经验/成就/称号）+ 随机批量
    r = await fetch(base + '/api/admin/redeem-codes', { method: 'POST', headers: J(admin, 'admin'), body: JSON.stringify({ type: 'xp', value: 50, title: 'xp码' }) }); d = await r.json();
    r = await fetch(base + '/api/redeem', { method: 'POST', headers: J(pub, 'user'), body: JSON.stringify({ code: d.code }) }); d = await r.json();
    assert(d.ok && d.xp === 50, 'redeem: 经验码 +50 XP ' + JSON.stringify(d));
    db.prepare("INSERT INTO titles (key,name,desc,icon,grant_type,created_at) VALUES ('opt_t','opt称号','','\u{1f3c5}','owner',?)").run(Date.now());
    r = await fetch(base + '/api/admin/redeem-codes', { method: 'POST', headers: J(admin, 'admin'), body: JSON.stringify({ type: 'title', value: 'opt_t', title: '称号码' }) }); d = await r.json();
    r = await fetch(base + '/api/redeem', { method: 'POST', headers: J(pub, 'user'), body: JSON.stringify({ code: d.code }) }); d = await r.json();
    assert(d.ok && String(d.granted || '').includes('opt称号'), 'redeem: 称号码授予称号 ' + JSON.stringify(d));
    db.prepare("INSERT INTO achievements (key,name,desc,icon,condition,reward_xp,created_at,updated_at) VALUES ('opt_a','opt成就','','','{}',0,?,?)").run(Date.now(), Date.now());
    r = await fetch(base + '/api/admin/redeem-codes', { method: 'POST', headers: J(admin, 'admin'), body: JSON.stringify({ type: 'achievement', value: 'opt_a', title: '成就码' }) }); d = await r.json();
    r = await fetch(base + '/api/redeem', { method: 'POST', headers: J(pub, 'user'), body: JSON.stringify({ code: d.code }) }); d = await r.json();
    assert(d.ok && String(d.granted || '').includes('opt成就'), 'redeem: 成就码授予成就 ' + JSON.stringify(d));
    r = await fetch(base + '/api/admin/redeem-codes/random', { method: 'POST', headers: J(admin, 'admin'), body: JSON.stringify({ type: 'xp', count: 5 }) }); d = await r.json();
    assert(d.ok && d.codes.length === 5, 'redeem: 随机批量生成 5 个');
  }
  {
    // 任务 CRUD
    r = await fetch(base + '/api/admin/tasks', { method: 'POST', headers: J(admin, 'admin'), body: JSON.stringify({ key: 'opt_task', name: 'opt任务', desc: '', type: 'custom', target_count: 3, reward_xp: 20, daily_cap: 2 }) }); d = await r.json();
    assert(d.ok && d.id, 'tasks: 创建成功');
    const tid = d.id;
    r = await fetch(base + '/api/admin/tasks', { method: 'POST', headers: J(admin, 'admin'), body: JSON.stringify({ key: 'opt_task', name: 'x' }) });
    assert(r.status === 400, 'tasks: 重复 key 400');
    r = await fetch(base + '/api/tasks', { headers: J(pub, 'user') }); d = await r.json();
    assert(d.tasks.some((x) => x.key === 'opt_task'), 'tasks: 前台可见新任务');
    r = await fetch(base + '/api/admin/tasks/' + tid, { method: 'PUT', headers: J(admin, 'admin'), body: JSON.stringify({ enabled: 0, reward_xp: 30 }) });
    assert(r.status === 200, 'tasks: 更新成功');
    r = await fetch(base + '/api/tasks', { headers: J(pub, 'user') }); d = await r.json();
    assert(!d.tasks.some((x) => x.key === 'opt_task'), 'tasks: 停用后前台不可见');
    r = await fetch(base + '/api/admin/tasks/' + tid, { method: 'DELETE', headers: J(admin, 'admin') });
    assert(r.status === 200, 'tasks: 删除成功');
    r = await fetch(base + '/api/admin/tasks', { headers: J(admin, 'admin') }); d = await r.json();
    assert(!d.tasks.some((x) => x.id === tid), 'tasks: 删除后不在列表');
    r = await fetch(base + '/api/admin/tasks', { method: 'POST', headers: J(pub, 'user'), body: JSON.stringify({ key: 'x', name: 'x' }) });
    assert(r.status === 403, 'tasks: 普通用户 403');
  }

  // ---------- J. 编辑功能 + 称号底色 + 颜色一致性 ----------
  {
    // 称号：创建（带底色）→ 编辑 → 列表含色 → 删除
    r = await fetch(base + '/api/admin/titles', { method: 'POST', headers: J(admin, 'admin'), body: JSON.stringify({ key: 'opt_edit_t', name: '编辑称号', icon: '🏷️', color: '#123456' }) }); d = await r.json();
    assert(d.ok, 'title: 创建成功');
    const tid = db.prepare("SELECT id FROM titles WHERE key='opt_edit_t'").get().id;
    r = await fetch(base + '/api/admin/titles', { headers: J(admin, 'admin') }); d = await r.json();
    assert(d.titles.some((x) => x.id === tid && x.color === '#123456'), 'title: 列表返回 color');
    r = await fetch(base + '/api/admin/titles/' + tid, { method: 'PUT', headers: J(admin, 'admin'), body: JSON.stringify({ name: '改名', color: '#abcdef' }) }); d = await r.json();
    assert(d.ok, 'title: 编辑成功');
    r = await fetch(base + '/api/admin/titles', { headers: J(admin, 'admin') }); d = await r.json();
    const t1 = d.titles.find((x) => x.id === tid);
    assert(t1.name === '改名' && t1.color === '#abcdef', 'title: 编辑后名称/底色生效');
    // 授予用户 → 主页返回 title_color（用新用户，避免与其它测试授予的称号冲突）
    const tuser = mk('opt_title_user', 'user', 1);
    community.grantTitleByKey(tuser, 'opt_edit_t', null, admin);
    r = await fetch(base + '/api/user/' + tuser + '/home'); d = await r.json();
    assert(d.home.title === '改名' && d.home.title_color === '#abcdef', 'title: 主页返回 title_color ' + JSON.stringify({ t: d.home.title, c: d.home.title_color }));
    // 评论作者也返回 title_color
    r = await fetch(base + '/api/user/' + tuser + '/public'); d = await r.json();
    assert(d.user.title_color === '#abcdef', 'title: 评论作者(public)返回 title_color');
    r = await fetch(base + '/api/admin/titles/' + tid, { method: 'DELETE', headers: J(admin, 'admin') });
    assert(r.status === 200, 'title: 删除成功');
    r = await fetch(base + '/api/admin/titles', { headers: J(admin, 'admin') }); d = await r.json();
    assert(!d.titles.some((x) => x.id === tid), 'title: 删除后不在列表');
  }
  {
    // 等级颜色一致性：设置 Lv3 颜色后，主页 / public / 后台名片列表取到的 level_color 一致
    await fetch(base + '/api/admin/level-colors', { method: 'PUT', headers: J(admin, 'admin'), body: JSON.stringify({ colors: { '3': '#336699' } }) });
    const u3 = mk('opt_lv3_user', 'user', 3);
    r = await fetch(base + '/api/user/' + u3 + '/home'); d = await r.json();
    const cHome = d.home.level_color;
    r = await fetch(base + '/api/user/' + u3 + '/public'); d = await r.json();
    const cPub = d.user.level_color;
    assert(cHome === '#336699' && cPub === '#336699', 'levelColors: 主页与 public 的 level_color 一致 ' + JSON.stringify({ cHome, cPub }));
    // 后台名片列表（listCards）也用同一颜色
    db.prepare("INSERT INTO business_cards (user_id,title,intro,status,submitted_at,created_at) VALUES (?,?,?,?,?,?)").run(u3, '卡', '', 'pending', Date.now(), Date.now());
    r = await fetch(base + '/api/admin/cards?status=all', { headers: J(admin, 'admin') }); d = await r.json();
    const cardRow = d.cards.find((x) => x.user_id === u3);
    assert(cardRow.level_color === '#336699', 'levelColors: 后台名片列表 level_color 一致');
  }
  {
    // 成就：编辑（POST id）与删除
    r = await fetch(base + '/api/admin/achievements', { method: 'POST', headers: J(admin, 'admin'), body: JSON.stringify({ key: 'opt_edit_a', name: '编辑成就', reward_xp: 10 }) }); d = await r.json();
    const aid = d.id;
    r = await fetch(base + '/api/admin/achievements', { method: 'POST', headers: J(admin, 'admin'), body: JSON.stringify({ id: aid, name: '成就改名', reward_xp: 99 }) }); d = await r.json();
    assert(d.ok, 'ach: 编辑成功');
    const a1 = db.prepare('SELECT name, reward_xp FROM achievements WHERE id=?').get(aid);
    assert(a1.name === '成就改名' && a1.reward_xp === 99, 'ach: 编辑后名称/经验生效');
    r = await fetch(base + '/api/admin/achievements/' + aid, { method: 'DELETE', headers: J(admin, 'admin') });
    assert(r.status === 200, 'ach: 删除成功');
    assert(!db.prepare('SELECT id FROM achievements WHERE id=?').get(aid), 'ach: 删除后不存在');
  }

  {
    // ---------- 等级随 XP 提升并落库（历史 BUG：只加 xp 不写 level，等级永远 Lv0） ----------
    const nu = mk('opt_lvup_user', 'user', 0);
    db.prepare("INSERT INTO user_profiles (user_id, privacy) VALUES (?, ?) ON CONFLICT(user_id) DO UPDATE SET privacy=excluded.privacy")
      .run(nu, JSON.stringify({ profile: 1, level: 1, title: 1, comments: 1, badges: 1 }));
    r = await fetch(base + '/api/admin/level-colors', { method: 'PUT', headers: J(admin, 'admin'), body: JSON.stringify({ colors: { '1': '#00ff00' } }) }); d = await r.json();
    assert(d.colors && d.colors['1'] === '#00ff00', 'level: 自定义 Lv1 颜色已保存');
    // Lv0 也按 Lv1 的自定义色展示（否则站长调色在这批用户身上完全看不到）
    r = await fetch(base + '/api/user/' + nu + '/home'); d = await r.json();
    assert(d.home.level === 0 && d.home.level_color === '#00ff00', 'level: Lv0 使用自定义 Lv1 色 ' + JSON.stringify({ lv: d.home.level, c: d.home.level_color }));
    // 兑换 150 XP -> 应升到 Lv1，且 users.level 落库同步
    r = await fetch(base + '/api/admin/redeem-codes', { method: 'POST', headers: J(admin, 'admin'), body: JSON.stringify({ type: 'xp', value: 150, title: 'lv码' }) }); d = await r.json();
    r = await fetch(base + '/api/redeem', { method: 'POST', headers: J(nu, 'user'), body: JSON.stringify({ code: d.code }) });
    r = await fetch(base + '/api/user/' + nu + '/home'); d = await r.json();
    const dbLv = db.prepare('SELECT level, xp FROM users WHERE id = ?').get(nu);
    assert(d.home.level === 1 && dbLv.level === 1 && dbLv.xp === 150, 'level: XP 增长后等级提升并写回 users ' + JSON.stringify({ home: d.home.level, db: dbLv }));
    assert(d.home.level_color === '#00ff00', 'level: 升级后颜色仍是自定义 Lv1 色');
    assert(d.home.xp && d.home.xp.current === 150 && d.home.xp.next === 300, 'level: 经验进度按当前等级计算 ' + JSON.stringify(d.home.xp));
  }
  {
    // ---------- 称号图标生效（主页 + 评论区） ----------
    const tu = mk('opt_icon_user', 'user', 0);
    db.prepare("INSERT INTO user_profiles (user_id, privacy) VALUES (?, ?) ON CONFLICT(user_id) DO UPDATE SET privacy=excluded.privacy")
      .run(tu, JSON.stringify({ profile: 1, level: 1, title: 1, comments: 1, badges: 1 }));
    r = await fetch(base + '/api/admin/titles', { method: 'POST', headers: J(admin, 'admin'), body: JSON.stringify({ key: 'opt_icon_t', name: '图标称号', icon: '\u{1f451}', color: '#123456' }) }); d = await r.json();
    r = await fetch(base + '/api/admin/titles/grant', { method: 'POST', headers: J(admin, 'admin'), body: JSON.stringify({ titleKey: 'opt_icon_t', userId: tu }) });
    r = await fetch(base + '/api/user/' + tu + '/home'); d = await r.json();
    assert(d.home.title === '图标称号' && d.home.title_icon === '\u{1f451}' && d.home.title_color === '#123456',
      'titleIcon: 主页返回称号名+图标+底色 ' + JSON.stringify({ t: d.home.title, i: d.home.title_icon, c: d.home.title_color }));
    r = await fetch(base + '/api/user/' + tu + '/public'); d = await r.json();
    assert(d.user.title_icon === '\u{1f451}', 'titleIcon: 评论作者(public)返回 title_icon ' + JSON.stringify(d.user));
  }
  {
    // ---------- 未读消息红点 ----------
    const mu = mk('opt_notif_user', 'user', 0);
    r = await fetch(base + '/api/notifications/unread', { headers: J(mu, 'user') }); d = await r.json();
    assert(d.unread === 0, 'notif: 初始未读为 0');
    r = await fetch(base + '/api/admin/notify', { method: 'POST', headers: J(admin, 'admin'), body: JSON.stringify({ userId: mu, title: '测试', body: '红点提醒' }) });
    assert(r.status === 200, 'notif: 站长定向发消息成功');
    r = await fetch(base + '/api/notifications/unread', { headers: J(mu, 'user') }); d = await r.json();
    assert(d.unread === 1, 'notif: 收到消息后未读=1 ' + JSON.stringify(d));
    r = await fetch(base + '/api/notifications', { headers: J(mu, 'user') }); d = await r.json();
    assert(d.unread === 1 && d.items.length === 1, 'notif: 列表接口 unread 与条目一致');
    r = await fetch(base + '/api/notifications/read', { method: 'POST', headers: J(mu, 'user'), body: JSON.stringify({ all: true }) });
    r = await fetch(base + '/api/notifications/unread', { headers: J(mu, 'user') }); d = await r.json();
    assert(d.unread === 0, 'notif: 全部已读后未读归零（红点消失）');
    // 未读数按全量统计，不受列表 100 条截断影响
    const ins = db.prepare('INSERT INTO notifications (user_id, type, title, body, ref, created_at) VALUES (?,?,?,?,?,?)');
    db.transaction(() => { for (let i = 0; i < 105; i++) ins.run(mu, 'OWNER_MSG', '批量', 'b' + i, null, Date.now()); })();
    r = await fetch(base + '/api/notifications/unread', { headers: J(mu, 'user') }); d = await r.json();
    assert(d.unread === 105, 'notif: 超过 100 条仍精确计数 ' + JSON.stringify(d));
    r = await fetch(base + '/api/notifications/unread');
    assert(r.status === 401, 'notif: 未登录访问未读接口 401');
  }

  console.log(fails === 0 ? 'ALL PASS' : ('FAILS=' + fails));
  wipe();
  process.exit(fails ? 1 : 0);
})().catch((e) => { console.error('ERR', e); wipe(); process.exit(2); });
