/* ============ WebOwn 前端 SPA ============ */
'use strict';

// ---------- 工具 ----------
const $ = (sel, el = document) => el.querySelector(sel);
const $$ = (sel, el = document) => [...el.querySelectorAll(sel)];

function esc(s) {
  return String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

function fmtTime(ts) {
  if (!ts) return '';
  const d = new Date(ts);
  const pad = (n) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

// 封禁时间区间文案（供用户管理表格展示）
function banRangeText(u) {
  if (!u || !u.banned) return '';
  const from = u.banned_from ? fmtTime(u.banned_from) : t('ban.immediate');
  if (u.banned_until) return `<div class="ban-range">${esc(from)} ~ ${esc(fmtTime(u.banned_until))}</div>`;
  return `<div class="ban-range">${esc(from)}${t('ban.permanentSuffix')}</div>`;
}

function toast(msg) {
  const t = $('#toast');
  t.textContent = msg;
  t.classList.remove('hidden');
  clearTimeout(t._timer);
  t._timer = setTimeout(() => t.classList.add('hidden'), 2600);
}

// 项目可选择的展示图标（emoji 调色板，管理员可在后台点选，也支持手动输入任意 emoji）
const PROJECT_ICONS = ['🐙', '🚀', '💡', '🛠️', '🎮', '📦', '⭐', '🔧', '🌟', '💻', '🌐', '📱', '🤖', '🧩', '⚙️', '🧪', '📚', '🎨', '🌈', '🔥', '🌙', '🪐'];

// ---------- API ----------
async function api(path, opts = {}) {
  const method = opts.method || 'GET';
  // GET 一律追加一次性时间戳：仅靠 cache:'no-store' 时，Nginx/宝塔反代或 CDN 仍可能
  // 回吐旧响应（删除后列表"没变化"的典型成因）。换 URL 才能真正强制回源。
  const sep = path.includes('?') ? '&' : '?';
  const url = `/api${path}${method === 'GET' ? sep + '_=' + Date.now() : ''}`;
  const res = await fetch(url, {
    method,
    headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'WebOwn', ...(opts.headers || {}) },
    body: opts.body ? JSON.stringify(opts.body) : undefined,
    credentials: 'same-origin',
    // 始终向服务端取最新数据，避免反向代理/浏览器把 GET 响应（尤其是验证码）缓存住
    cache: 'no-store',
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    // IP 被封禁时后端返回结构化信息，这里换成可读文案（真实原因/时间见封禁提示页）
    if (data.banned) throw new Error(t('ipban.blockedToast'));
    throw new Error(data.error || t('msg.reqFailed', { status: res.status }));
  }
  return data;
}

// ---------- 极简 Markdown 渲染（先转义再解析，天然防 XSS） ----------
// 校验经 esc() 转义后的 URL 是否可安全放入属性：
// esc() 已把 & 转成 &amp;、引号转成 &quot; 等。先还原实体再做原始校验，
// 拒绝含空白/引号/尖括号（属性逃逸）或 javascript:/vbscript:/非图片 data: 协议的内容；
// 校验通过后返回「仍保持转义」的安全值（浏览器会把 &amp; 正确还原为 &，从而兼容带查询参数的正常链接）。
function safeUrl(u) {
  const raw = u.replace(/&amp;/g, '&').replace(/&quot;/g, '"').replace(/&#39;/g, "'")
              .replace(/&lt;/g, '<').replace(/&gt;/g, '>');
  if (/[\s"'<>]/.test(raw)) return '';
  if (/^(javascript|vbscript):/i.test(raw)) return '';
  if (/^data:/i.test(raw) && !/^data:image\//i.test(raw)) return '';
  return u;
}

// ==================== Markdown 渲染 ====================
// 整体思路：先把整段原文 esc() 转义（天然防 XSS），再按「块」逐行解析，块内再做行内语法替换。
// 相比旧版一串全局正则，这里补上了以前会漏掉的一大类语法：
//   · [文字](#锚点) / [徽章](LICENSE) 这类非 http 链接      · 1. 2. 3. 有序列表
//   · | a | b | 表格    · --- 水平线    · 缩进嵌套列表    · ~~删除线~~
//   · README 里极常见的 <p align="center"> / <img> / <br> 排版 HTML（白名单还原，绝不执行脚本）
const MD_TAGS_OK = new Set(['p', 'div', 'span', 'center', 'img', 'br', 'hr', 'a', 'b', 'i', 'u', 's',
  'strong', 'em', 'del', 'code', 'pre', 'kbd', 'sub', 'sup', 'ul', 'ol', 'li',
  'table', 'thead', 'tbody', 'tr', 'td', 'th', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
  'blockquote', 'details', 'summary', 'figure', 'figcaption']);
const MD_ATTR_OK = {
  img: ['src', 'alt', 'width', 'height', 'title', 'align'],
  a: ['href', 'title'],
  p: ['align'], div: ['align'], center: [], ol: ['start'],
  td: ['align', 'colspan', 'rowspan'], th: ['align', 'colspan', 'rowspan'],
};

// 把 esc() 转义过的白名单标签还原成真标签；属性只放行白名单键，
// src/href 走 safeUrl，尺寸类只放行数字/px/%，其余标签保持转义（当纯文本显示，不会被浏览器执行）
function mdRestoreHtml(text) {
  return text.replace(/&lt;(\/?)([a-zA-Z][a-zA-Z0-9-]*)((?:[^&]|&(?:quot|amp|#39);)*)&gt;/g, (m, close, tag, attrs) => {
    const t = tag.toLowerCase();
    if (!MD_TAGS_OK.has(t)) return m;
    if (close) return `</${t}>`;
    if (t === 'br' || t === 'hr') return `<${t}>`;
    const allow = MD_ATTR_OK[t] || [];
    const built = [];
    const re = /([a-zA-Z-]+)\s*=\s*&quot;((?:[^&]|&(?!quot;))*?)&quot;/g;
    let a;
    while ((a = re.exec(attrs))) {
      const key = a[1].toLowerCase();
      if (!allow.includes(key)) continue;
      const val = a[2];
      if (key === 'src' || key === 'href') {
        const safe = safeUrl(val);
        if (!safe) continue;
        built.push(` ${key}="${safe}"`);
      } else if (/^(width|height|colspan|rowspan|start)$/.test(key)) {
        if (!/^\d+(px|%)?$/.test(val)) continue;
        built.push(` ${key}="${val}"`);
      } else {
        // 普通属性（alt/title/align）：值里不许出现尖括号或事件属性，防属性逃逸
        if (/(&lt;|&gt;|javascript:|on[a-z]+\s*=)/i.test(val)) continue;
        built.push(` ${key}="${val}"`);
      }
    }
    if (t === 'a' && built.some((x) => /^ href="https?:/.test(x))) built.push(' target="_blank" rel="noopener noreferrer"');
    return `<${t}${built.join('')}>`;
  });
}

// 行内语法：行内代码 → 图片 → 链接 → 强调。
// 行内代码先抽成占位符，避免其中的 * _ 等被后续的强调规则误伤。
function mdInline(text) {
  const codes = [];
  let s = String(text).replace(/`([^`]+)`/g, (_m, c) => {
    codes.push(c);
    return `\u0001${codes.length - 1}\u0001`;
  });
  // 图片：![alt](url "title")，url 支持 http(s) / 相对路径 / data:image
  s = s.replace(/!\[([^\]]*)\]\(\s*([^)\s]+)(?:\s+&quot;[^&]*&quot;)?\s*\)/g, (m, alt, url) => {
    const u = safeUrl(url);
    return u ? `<img src="${u}" alt="${alt}" loading="lazy">` : m;
  });
  // 链接：[文字](url)。url 允许 #锚点（含中文）/ 相对路径 / mailto: / http(s)
  s = s.replace(/\[([^\]]*)\]\(\s*([^)\s]+)(?:\s+&quot;[^&]*&quot;)?\s*\)/g, (m, txt, url) => {
    const u = safeUrl(url);
    if (!u) return m;
    const external = /^https?:/i.test(url.replace(/&amp;/g, '&'));
    return `<a href="${u}"${external ? ' target="_blank" rel="noopener noreferrer"' : ''}>${txt || u}</a>`;
  });
  s = s.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>')
       .replace(/__([^_]+)__/g, '<strong>$1</strong>')
       .replace(/(^|[^*\w])\*([^*\n]+)\*/g, '$1<em>$2</em>')
       .replace(/~~([^~]+)~~/g, '<del>$1</del>');
  return s.replace(/\u0001(\d+)\u0001/g, (_m, i) => `<code>${codes[Number(i)]}</code>`);
}

// 列表项按缩进层级生成嵌套 ul/ol（支持 - * + 与 1. 1) ）
function mdBuildList(rows) {
  let html = '';
  const stack = [];
  const open = (indent, tag) => {
    let took = false;
    if (html.endsWith('</li>')) { html = html.slice(0, -5); took = true; }
    html += `<${tag}>`;
    stack.push({ indent, tag, took });
  };
  const close = () => {
    const s = stack.pop();
    html += `</${s.tag}>`;
    if (s.took) html += '</li>';
  };
  for (const r of rows) {
    if (!stack.length) open(r.indent, r.tag);
    else if (r.indent > stack[stack.length - 1].indent) open(r.indent, r.tag);
    else {
      while (stack.length && r.indent < stack[stack.length - 1].indent) close();
      const top = stack[stack.length - 1];
      if (!top) open(r.indent, r.tag);
      else if (top.tag !== r.tag) { close(); open(r.indent, r.tag); }
    }
    html += `<li>${mdInline(r.text)}</li>`;
  }
  while (stack.length) close();
  return html;
}

// 表格：| a | b | + | --- | --- | 分隔行（支持 :--- / ---: / :---: 对齐）
function mdBuildTable(rows) {
  const cells = (line) => line.replace(/^\s*\|/, '').replace(/\|\s*$/, '').split('|').map((c) => c.trim());
  const head = cells(rows[0]);
  const align = cells(rows[1]).map((c) => (/^:.*:$/.test(c) ? 'center' : (/:$/.test(c) ? 'right' : (/^:/.test(c) ? 'left' : ''))));
  const st = (i) => (align[i] ? ` style="text-align:${align[i]}"` : '');
  const th = head.map((c, i) => `<th${st(i)}>${mdInline(c)}</th>`).join('');
  const tb = rows.slice(2).map((r) => `<tr>${cells(r).map((c, i) => `<td${st(i)}>${mdInline(c)}</td>`).join('')}</tr>`).join('');
  return `<div class="md-table-wrap"><table><thead><tr>${th}</tr></thead><tbody>${tb}</tbody></table></div>`;
}

// 块级解析：入参是「已 esc 过」的文本（safeUrl / mdRestoreHtml 都基于转义态工作）
function mdBlocks(text) {
  const lines = String(text || '').replace(/\r\n?/g, '\n').split('\n');
  const out = [];
  let para = [];
  const flush = () => {
    if (!para.length) return;
    const body = mdInline(para.join('\n')).replace(/\n/g, '<br>').trim();
    para = [];
    if (!body) return;
    // 段落里若已被还原成块级标签（如 <img>、<div>），就不再套一层 <p>
    out.push(/^<(p|div|span|center|img|table|details|figure|h\d|ul|ol|li|blockquote|pre|hr)\b/i.test(body) ? body : `<p>${body}</p>`);
  };

  let i = 0;
  while (i < lines.length) {
    const raw = lines[i];
    const line = mdRestoreHtml(raw);
    const trim = line.trim();

    // 围栏代码块：内部保持转义原样输出，不做任何 Markdown 解析
    const fence = /^\s{0,3}(```|~~~)\s*([\w+#.-]*)\s*$/.exec(raw);
    if (fence) {
      flush();
      const endRe = new RegExp('^\\s{0,3}' + (fence[1] === '```' ? '`{3,}' : '~{3,}') + '\\s*$');
      const buf = [];
      i++;
      while (i < lines.length && !endRe.test(lines[i])) { buf.push(lines[i]); i++; }
      i++; // 跳过收尾围栏
      out.push(`<div class="md-code"${fence[2] ? ` data-lang="${esc(fence[2])}"` : ''}><pre><code>${buf.join('\n')}</code></pre></div>`);
      continue;
    }

    if (!trim) { flush(); i++; continue; }

    // 水平线：--- / *** / ___
    if (/^(-{3,}|\*{3,}|_{3,})$/.test(trim)) { flush(); out.push('<hr>'); i++; continue; }

    // 标题（# ~ ######）
    const h = /^(#{1,6})\s+(.*)$/.exec(trim);
    if (h) { flush(); const lv = h[1].length; out.push(`<h${lv}>${mdInline(h[2].trim())}</h${lv}>`); i++; continue; }

    // 引用块（连续 > 行合并，内部递归解析）
    if (/^&gt;\s?/.test(trim)) {
      flush();
      const buf = [];
      while (i < lines.length && /^\s*&gt;\s?/.test(lines[i])) { buf.push(lines[i].replace(/^\s*&gt;\s?/, '')); i++; }
      out.push(`<blockquote>${mdBlocks(buf.join('\n'))}</blockquote>`);
      continue;
    }

    // 表格：当前行含 | 且下一行是 |---| 分隔行
    if (trim.indexOf('|') >= 0 && i + 1 < lines.length && /^\s*\|?\s*:?-{2,}:?\s*(\|\s*:?-{2,}:?\s*)*\|?\s*$/.test(lines[i + 1])) {
      flush();
      const rows = [trim, lines[i + 1].trim()];
      i += 2;
      while (i < lines.length && lines[i].trim() && lines[i].trim().indexOf('|') >= 0) { rows.push(lines[i].trim()); i++; }
      out.push(mdBuildTable(rows));
      continue;
    }

    // 列表（无序 - * + / 有序 1. 1)），并吞掉缩进续行
    if (/^(\s*)([-*+]|\d+[.)])\s+(.*)$/.test(line)) {
      flush();
      const rows = [];
      while (i < lines.length) {
        const cur = mdRestoreHtml(lines[i]);
        const m2 = /^(\s*)([-*+]|\d+[.)])\s+(.*)$/.exec(cur);
        if (m2) {
          rows.push({ indent: m2[1].length, tag: /[-*+]/.test(m2[2]) ? 'ul' : 'ol', text: m2[3] });
          i++;
          continue;
        }
        // 缩进续行：挂到上一个列表项（代码块起始行除外，避免把 ``` 吞进列表）
        if (rows.length && /^\s{2,}\S/.test(cur) && !/^\s{0,3}(```|~~~)/.test(cur)) {
          rows[rows.length - 1].text += '\n' + cur.trim();
          i++;
          continue;
        }
        break;
      }
      out.push(mdBuildList(rows));
      continue;
    }

    // 原生 HTML 块（白名单标签已还原）：整段原样输出，不再包 <p>
    if (/^<(p|div|center|img|table|details|figure|h\d|ul|ol|blockquote|pre|hr)\b/i.test(trim)) {
      flush();
      const buf = [];
      while (i < lines.length && lines[i].trim()) { buf.push(mdRestoreHtml(lines[i])); i++; }
      out.push(buf.join('\n'));
      continue;
    }

    para.push(trim);
    i++;
  }
  flush();
  return out.join('\n');
}

function renderMD(src) {
  return mdBlocks(esc(src));
}

// 解析 GitHub 仓库地址 → { owner, repo }（用于把 README 中的相对图片补全为 raw 地址）
function parseRepo(url) {
  const m = /github\.com\/([\w.-]+)\/([\w.-]+?)(?:\.git)?\/?$/i.exec(url || '');
  if (!m) return null;
  return { owner: m[1], repo: m[2] };
}

// README 渲染：在基础 Markdown 之上，把相对图片地址补全为 GitHub raw 地址（best-effort）
// README 里的图片有两种写法，都要补全，否则站点内必然裂图：
//   1) Markdown 写法 ![alt](img/banner.png)
//   2) HTML 写法 <img src="img/banner.png">（常见于 <p align="center"> 包着的横幅）
// branch 用仓库真实默认分支（元数据到位后传入），拿不到时退回 main。
function renderReadme(md, repoUrl, branch) {
  let out = md || '';
  const r = parseRepo(repoUrl);
  const br = branch || 'main';
  const abs = (u) => (/^https?:\/\//i.test(u) || u.startsWith('/') || u.startsWith('data:')) ? null
    : `https://raw.githubusercontent.com/${r.owner}/${r.repo}/${br}/${u.replace(/^\.\//, '').replace(/^\.\.\//, '')}`;
  if (r) {
    out = out.replace(/!\[([^\]]*)\]\(\s*([^)\s]+)(?:\s+"[^"]*")?\s*\)/gi, (m, alt, url) => {
      const full = abs(url);
      return full ? `![${alt}](${full})` : m;
    });
    out = out.replace(/<img\b[^>]*\bsrc\s*=\s*["']([^"']+)["'][^>]*>/gi, (m, url) => {
      const full = abs(url);
      return full ? m.replace(url, full) : m;
    });
  }
  return renderMD(out);
}

// 详情页通用互动：点赞 / 收藏 / 分享 按钮 + 评论框。
// 前置 HTML：.action-bar 含 #btn-like/#btn-fav/#btn-share（各含 <span> 计数）；#cmt-list 需带 data-count；
// 登录态另含 #cmt-input + #cmt-send，以及 #cmt-heading（标题内嵌评论数，发布后 +1）。

// 单条评论渲染：头像 + 昵称 + 等级/称号/成就徽章（按用户隐私与展示开关，后端已过滤未公开字段）
function commentItemHtml(c) {
  const av = c.avatar
    ? `<img class="c-avatar" src="/uploads/${esc(c.avatar)}" alt="">`
    : `<div class="c-avatar c-avatar-empty">${esc((c.username || '?').slice(0, 1))}</div>`;
  const lv = (c.level != null) ? `<span class="c-badge c-lv" style="background:${esc(c.level_color || '#8b5cf6')}">Lv${esc(c.level)}</span>` : '';
  const ti = c.title ? `<span class="c-badge c-title" style="color:#fff;background:${esc(c.title_color || '#d9920a')};border:none">${c.title_icon ? esc(c.title_icon) + ' ' : ''}${esc(c.title)}</span>` : '';
  const bg = (c.badges && c.badges.length)
    ? c.badges.map((b) => `<span class="c-badge c-ach" title="${esc(b.name || '')}">${b.icon ? esc(b.icon) : '🏅'}</span>`).join('')
    : '';
  const time = c.created_at ? fmtTime(c.created_at) : t('comment.justNow');
  return `<div class="comment-item">
    <div class="c-avatar-wrap">${av}</div>
    <div class="c-body">
      <div class="c-head"><span class="c-name">${esc(c.username)}</span>${lv}${ti}${bg}<span class="c-time">${time}</span></div>
      <p>${esc(c.content)}</p>
    </div>
  </div>`;
}

function commentListHtml(cmts) {
  if (!cmts || !cmts.length) return `<p class="empty" style="padding:16px 0">${t('comment.empty')}</p>`;
  return cmts.map(commentItemHtml).join('');
}

async function bindInteractions(el, type, id) {
  // 取按钮里的计数 <span>：优先用显式标记的 .btn-count（页头 Star/Watch 按钮里还有标签 span，
  // 单纯取第一个 span 会误伤标签文字），老页面没有该标记时回退到第一个 span。
  const cntOf = (btn) => $('.btn-count', btn) || $('span', btn);
  let myState = { liked: false, favorited: false };
  try { const st = await api(`/mystate/${type}/${id}`); myState = st; } catch (_) {}
  const likeBtn = $('#btn-like', el), favBtn = $('#btn-fav', el), shareBtn = $('#btn-share', el);
  if (likeBtn) {
    likeBtn.classList.toggle('active', !!myState.liked);
    likeBtn.addEventListener('click', async () => {
      if (!Auth.user) { toast(t('auth.needLogin')); location.hash = '#/login'; return; }
      try {
        const r = await api(`/likes/${type}/${id}`, { method: 'POST' });
        const n = cntOf(likeBtn); if (n) n.textContent = r.likes;
        likeBtn.classList.toggle('active', !!r.liked);
        likeBtn.classList.remove('beat'); void likeBtn.offsetWidth; likeBtn.classList.add('beat');
      } catch (e) { toast(e.message); }
    });
  }
  if (favBtn) {
    favBtn.classList.toggle('active', !!myState.favorited);
    favBtn.addEventListener('click', async () => {
      if (!Auth.user) { toast(t('auth.needLogin')); location.hash = '#/login'; return; }
      try {
        const r = await api(`/favorites/${type}/${id}`, { method: 'POST' });
        const n = cntOf(favBtn); if (n) n.textContent = r.favorites;
        favBtn.classList.toggle('active', !!r.favorited);
        favBtn.classList.remove('beat'); void favBtn.offsetWidth; favBtn.classList.add('beat');
      } catch (e) { toast(e.message); }
    });
  }
  if (shareBtn) {
    shareBtn.addEventListener('click', async () => {
      try { await navigator.clipboard.writeText(location.href); } catch (_) {}
      try { await api(`/shares/${type}/${id}`, { method: 'POST' }); } catch (_) {}
      toast(t('share.copied'));
    });
  }
  const listEl = $('#cmt-list', el);
  let nCmt = parseInt((listEl && listEl.dataset.count)) || 0;
  if (listEl && Auth.user) {
    const send = $('#cmt-send', el);
    if (send) send.addEventListener('click', async () => {
      const input = $('#cmt-input', el);
      if (!input.value.trim()) return toast(t('comment.needContent'));
      try {
        const c = await api(`/comments/${type}/${id}`, { method: 'POST', body: { content: input.value } });
        listEl.insertAdjacentHTML('afterbegin', commentItemHtml(c));
        input.value = '';
        nCmt += 1;
        const head = $('#cmt-heading', el);
        if (head) head.textContent = `${t('title.comments')} (${nCmt})`;
        toast(t('comment.posted'));
      } catch (e) { toast(e.message); }
    });
  }
}

// 让底部互动栏按钮与页头 Star/Watch 按钮共享同一套状态：
// 页头按钮由 bindInteractions 接管，这里把点击转发过去，并用 MutationObserver 同步激活态与计数。
function mirrorAction(el, srcId, dstId, labOn, labOff) {
  const src = $('#' + srcId, el);
  const dst = $('#' + dstId, el);
  if (!src || !dst) return;
  const sync = () => {
    const on = src.classList.contains('active');
    // 关键：所有写操作都要先比对再赋值。
    // 下面写的是 src 内部的 .gh-lab，而 src 正是被观察的节点——若无条件赋值会
    // 再次触发 MutationObserver → sync → 再赋值……页面主线程被死循环卡死。
    if (dst.classList.contains('active') !== on) dst.classList.toggle('active', on);
    const a = $('.btn-count', src) || $('span', src);
    const b = $('.btn-count', dst) || $('span', dst);
    if (a && b && b.textContent !== a.textContent) b.textContent = a.textContent;
    const lab = $('.gh-lab', src);
    if (lab && labOn) {
      const want = on ? labOn : labOff;
      if (lab.textContent !== want) lab.textContent = want;
    }
  };
  sync();
  dst.addEventListener('click', () => src.click());
  if (window.MutationObserver) new MutationObserver(sync).observe(src, { attributes: true, childList: true, subtree: true });
}

// 站内下载源码包：先做一次只读取响应头的预检（服务端代理 GitHub 需要几秒），
// 失败直接 toast 报错而不让浏览器跳到 JSON 错误页；预检通过再交给浏览器原生下载，
// 这样大文件也不会整包驻留内存。全程同域，访客不会离开本站。
async function startDownload(el, p, ref) {
  const url = `/api/projects/${p.id}/download?ref=${encodeURIComponent(ref || window.__ghRef || 'main')}`;
  toast(t('gh.downloading'));
  try {
    const res = await fetch(url, { credentials: 'same-origin', headers: { 'X-Requested-With': 'WebOwn' } });
    const ct = res.headers.get('content-type') || '';
    if (!res.ok || ct.includes('application/json')) {
      const d = await res.json().catch(() => ({}));
      toast(d.error || t('gh.dlFail'));
      return;
    }
    if (res.body && res.body.cancel) { try { res.body.cancel(); } catch (_) { /* 已拿到头信息，丢弃响应体 */ } }
  } catch (_) {
    // 预检本身失败（网络抖动等）：仍交给浏览器尝试一次原生下载
  }
  const a = document.createElement('a');
  a.href = url;
  a.download = '';
  document.body.appendChild(a);
  a.click();
  a.remove();
}

// 详情页内容缺失时的友好兜底（记录已被删除 / 后端接口还没生效返回 404）：
// 直接抛「请求失败 (404)」会让访客困惑，这里给出可读文案 + 返回列表的入口。
function renderDetailMissing(el, backHash, backLabel) {
  el.innerHTML = `
    <div class="view">
      <div class="empty"><span class="big">🌫️</span>${esc(t('detail.notFound'))}
        <div style="margin-top:14px"><a class="btn btn-ghost btn-sm" href="${esc(backHash)}">${esc(backLabel)}</a></div>
      </div>
    </div>`;
}

// 语言配色（与 GitHub 官方语言色一致；未知语言按名称哈希取一个稳定色）
const LANG_COLORS = {
  JavaScript: '#f1e05a', TypeScript: '#3178c6', Python: '#3572A5', Java: '#b07219', Go: '#00ADD8',
  Rust: '#dea584', C: '#555555', 'C++': '#f34b7d', 'C#': '#178600', PHP: '#4F5D95', Ruby: '#701516',
  Swift: '#F05138', Kotlin: '#A97BFF', HTML: '#e34c26', CSS: '#563d7c', Vue: '#41b883', Shell: '#89e051',
  Lua: '#000080', Dart: '#00B4AB', Solidity: '#AA6746', Jupyter: '#DA5B0B', 'Jupyter Notebook': '#DA5B0B',
  'Objective-C': '#438eff', Scala: '#c22d40', Perl: '#0298c3', R: '#198CE7', MATLAB: '#e16737',
  Crystal: '#000100', Elixir: '#6e4a7e', Haskell: '#5e5086', Nim: '#ffc200', Zig: '#ec915c',
};
function langColor(name) {
  if (LANG_COLORS[name]) return LANG_COLORS[name];
  let h = 0;
  for (const ch of String(name || '')) h = (h * 31 + ch.charCodeAt(0)) % 360;
  return `hsl(${h}, 62%, 58%)`;
}

// 公告标签（key 与后端白名单对齐；颜色由 CSS 的 .ann-tag-<key> 控制）
const ANNOUNCE_TAGS = ['update', 'maintenance', 'action', 'important', 'event', 'other'];
function annTagLabel(tag) { return t('ann.tag.' + (ANNOUNCE_TAGS.includes(tag) ? tag : 'other')); }

// GitHub 风格相对时间（"3天前" / "3 days ago"）
function relTime(ts) {
  if (!ts) return '';
  const diff = Date.now() - new Date(ts).getTime();
  if (diff < 0) return '';
  const s = Math.floor(diff / 1000);
  const en = Lang.get() === 'en';
  const units = [
    [31536000, '年', 'year'], [2592000, '个月', 'month'], [604800, '周', 'week'],
    [86400, '天', 'day'], [3600, '小时', 'hour'], [60, '分钟', 'minute'],
  ];
  for (const [sec, zh, enName] of units) {
    if (s >= sec) {
      const n = Math.floor(s / sec);
      return en ? `${n} ${enName}${n > 1 ? 's' : ''} ago` : `${n}${zh}前`;
    }
  }
  return en ? 'just now' : '刚刚';
}

// 文件体积（GitHub 文件列表用 KB/MB 显示）
function fmtBytes(n) {
  const b = Number(n) || 0;
  if (b < 1024) return `${b} B`;
  if (b < 1024 * 1024) return `${(b / 1024).toFixed(1)} KB`;
  return `${(b / 1024 / 1024).toFixed(1)} MB`;
}

// 千分位计数（Star/Fork 数）
function fmtCount(n) {
  const v = Number(n) || 0;
  if (v < 1000) return String(v);
  if (v < 1000000) return `${(v / 1000).toFixed(v < 10000 ? 1 : 0)}k`;
  return `${(v / 1000000).toFixed(1)}m`;
}

// ---------- 图形验证码 ----------
// 生成一组「验证码输入框 + 图片」的 HTML（图片点击即刷新，失败可重试）
function captchaFieldHtml() {
  return `
    <div class="field captcha-field" data-loading="">
      <label>${esc(t('captcha.label'))}</label>
      <div class="captcha-row">
        <input name="captcha" class="captcha-input" maxlength="6" autocomplete="off"
               placeholder="${esc(t('captcha.ph'))}" aria-label="${esc(t('captcha.label'))}">
        <img class="captcha-img" tabindex="0" role="button"
             alt="${esc(t('captcha.alt'))}" title="${esc(t('captcha.refresh'))}">
        <button type="button" class="btn btn-ghost btn-sm captcha-reload" title="${esc(t('captcha.refresh'))}"
                aria-label="${esc(t('captcha.refresh'))}">↻</button>
      </div>
      <input type="hidden" name="captchaId">
    </div>`;
}

// 刷新单个验证码字段（幂等：同一字段可反复调用；加载中自动忽略连点）
async function refreshCaptcha(field) {
  if (!field) return;
  const img = $('.captcha-img', field);
  const idInput = $('input[name="captchaId"]', field);
  if (!img || !idInput) return;
  if (field.dataset.loading === '1') return;
  field.dataset.loading = '1';
  img.classList.add('loading');
  try {
    // 带时间戳缓存破坏器：即使反代(Nginx proxy_cache)/CDN/浏览器按 URL 缓存，
    // 每次 URL 都不同，无法命中旧响应，杜绝「刷新后仍是原验证码」
    const r = await api('/captcha?_=' + Date.now());
    idInput.value = r.id;
    // 先摘掉旧图再换新图，确保无论浏览器如何处理 data URI 都必定重绘
    img.removeAttribute('src');
    img.src = 'data:image/svg+xml;charset=utf-8,' + encodeURIComponent(r.svg);
  } catch (_e) {
    img.removeAttribute('src');
    toast(t('captcha.loadFail'));
  } finally {
    img.classList.remove('loading');
    field.dataset.loading = '';
  }
}

// 页面级事件委托：验证码字段哪怕被重渲染（切页、提交失败重绘）也照样能刷新，
// 且不会因反复调用 loadCaptcha 而重复绑定，避免一次点击发出多次请求。
function initCaptchaDelegation() {
  document.addEventListener('click', (e) => {
    const hit = e.target.closest && e.target.closest('.captcha-img, .captcha-reload');
    if (!hit) return;
    e.preventDefault();
    refreshCaptcha(hit.closest('.captcha-field'));
  });
  document.addEventListener('keydown', (e) => {
    if (e.key !== 'Enter' && e.key !== ' ') return;
    const el = document.activeElement;
    if (!el || !el.classList) return;
    if (!el.classList.contains('captcha-img') && !el.classList.contains('captcha-reload')) return;
    e.preventDefault();
    refreshCaptcha(el.closest('.captcha-field'));
  });
}

// 首次渲染表单时拉一张验证码（el 为包含 .captcha-field 的容器）
async function loadCaptcha(el) {
  await refreshCaptcha($('.captcha-field', el));
}

// ---------- 主题 ----------
const Theme = {
  get() { return localStorage.getItem('wo-theme') || (matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'); },
  apply(t) {
    document.documentElement.dataset.theme = t;
    localStorage.setItem('wo-theme', t);
    const btn = $('#theme-toggle');
    if (btn) btn.textContent = t === 'dark' ? '☀️' : '🌙';
  },
  toggle() { this.apply(this.get() === 'dark' ? 'light' : 'dark'); },
};

// ---------- 国际化（zh / en） ----------
// 用法：t('key')；支持插值 t('key', { n: 5 })。缺失键自动回退中文，再回退键名。
const I18N = {
  zh: {
    'nav.home': '文章', 'nav.gallery': '图库', 'nav.projects': '项目', 'nav.social': '动态', 'nav.sponsor': '赞助',
    'nav.admin': '👑 管理后台',
    'nav.search': '搜索', 'search.title': '站内搜索',
    'nav.announcements': '公告', 'ann.title': '公告', 'ann.empty': '暂无公告', 'ann.pinned': '置顶',
    'ann.tag.update': '更新公告', 'ann.tag.maintenance': '维护公告', 'ann.tag.action': '处置公告',
    'ann.tag.important': '重要公告', 'ann.tag.event': '活动公告', 'ann.tag.other': '其他公告',
    'ann.popup.title': '📢 站内公告', 'ann.popup.gotIt': '知道了',
    'ann.adminTitle': '发布 / 管理公告', 'ann.newTitle': '发布公告', 'ann.editTitle': '编辑公告',
    'ann.fieldTitle': '标题', 'ann.fieldContent': '内容（Markdown）', 'ann.fieldTag': '标签',
    'ann.fieldPinned': '置顶（新用户与久未登录用户会弹窗提醒）',
    'ann.addBtn': '发布公告', 'ann.cancelEdit': '取消编辑',
    'ann.tblTitle': '标题', 'ann.tblTag': '标签', 'ann.tblPinned': '置顶', 'ann.tblTime': '时间', 'ann.noAnnouncements': '暂无公告',
    'ann.delMsg': '确定删除这条公告吗？',
    'search.ph': '搜索文章、图片、项目、动态…', 'search.btn': '搜索',
    'search.empty': '未找到相关内容，换个关键词试试～', 'search.count': '共 {n} 条结果',
    'search.all': '全部', 'search.article': '文章', 'search.image': '图片', 'search.project': '项目', 'search.social': '动态', 'search.announcement': '公告', 'search.user': '用户',
    'title.articles': '文章', 'title.gallery': '图库', 'title.projects': 'GitHub 项目',
    'title.social': '社交动态 📱', 'title.sponsor': '赞助', 'title.login': '登录 / 注册',
    'title.settings': '账号设置', 'title.comments': '评论',
    'admin.dashboard': '📊 概览', 'admin.articles': '📝 文章', 'admin.images': '🖼️ 图库',
    'admin.projects': '🐙 项目', 'admin.comments': '💬 评论', 'admin.sponsors': '💝 赞助',
    'admin.social': '📱 动态', 'admin.users': '👥 用户', 'admin.terms': '📜 条款', 'admin.settings': '⚙️ 设置',
    'admin.announcements': '📢 公告',
    'admin.enter': '进入后台', 'admin.needPermission': '需要管理员权限', 'admin.usersTitle': '用户管理',
    'admin.settingsTitle': '站点设置', 'admin.termsTitle': '服务条款', 'admin.community': '🎀 社区/等级',
    'comm.titles': '称号管理', 'comm.achievements': '成就管理', 'comm.multipliers': '经验倍率', 'comm.redeem': '兑换码', 'comm.notify': '站内群发', 'comm.name': '名称', 'comm.key': '标识', 'comm.desc': '描述', 'comm.icon': '图标', 'comm.create': '创建', 'comm.grant': '授予', 'comm.revoke': '撤销', 'comm.rewardXp': '奖励经验', 'comm.condition': '达成条件(JSON)', 'comm.multiplier': '关联倍率(JSON)', 'comm.value': '倍率值', 'comm.scope': '作用域(nonsignin/all)', 'comm.cap': '全局上限', 'comm.enabled': '启用', 'comm.maxUses': '最大次数', 'comm.perUserOnce': '每用户限一次', 'comm.expiresAt': '过期时间', 'comm.genCode': '生成兑换码', 'comm.recipient': '接收用户ID(留空=全员)', 'comm.sendMsg': '发送', 'comm.userId': '用户ID', 'comm.noOwner': '仅站长可配置社区/等级', 'comm.generated': '已生成兑换码', 'comm.titleColor': '底色', 'comm.edit': '编辑', 'comm.delConfirm': '确定删除？此操作不可恢复', 'comm.tasks': '任务', 'comm.levelColors': '等级颜色', 'comm.levelColorTip': '为 Lv1-Lv10 分别设置徽章颜色，默认已设计一套从冷色到暖金的渐变。', 'comm.resetColors': '恢复默认', 'comm.resetDone': '已恢复默认配色', 'comm.levelColorSaveTip': '保存后立即对全站生效（个人主页、评论区、后台列表、搜索结果统一取同一套颜色）。', 'comm.taskType': '类型', 'comm.target': '目标次数', 'comm.dailyCap': '每日上限', 'comm.rewardType': '奖励类型', 'comm.rewardValue': '奖励值', 'comm.random': '随机', 'comm.randomGen': '随机生成 5 个', 'comm.count': '数量', 'comm.typeXp': '经验', 'comm.typeAchievement': '成就', 'comm.typeTitle': '称号', 'comm.useTitleKey': '或用称号标识', 'comm.cards': '名片审核', 'comm.approve': '通过', 'comm.reject': '驳回', 'comm.takedown': '下架', 'comm.reason': '原因', 'comm.preview': '查看', 'comm.user': '用户', 'comm.all': '全部', 'comm.emptyCards': '暂无名片', 'comm.privacy': '隐私默认值', 'comm.privacyTip': '新用户首次建档时采用的默认可见性（最小可见为默认，可在此放宽）。', 'comm.save': '保存', 'card.pending': '待审核', 'card.approved': '已通过', 'card.rejected': '已驳回', 'card.takenDown': '已下架', 'card.locked': '名片需达到 Lv{lv} 解锁', 'card.tip': '填写名片信息并上传图片，提交后由站长审核；通过后展示在你的主页。', 'card.titleField': '名片标题', 'card.introField': '名片简介', 'card.titlePh': '一句话介绍自己', 'card.introPh': '更详细的自我介绍（选填）', 'card.bg': '背景色', 'card.fg': '文字色', 'card.accent': '强调色', 'card.image': '名片图片', 'card.pickImage': '选择图片', 'card.noImage': '未选择图片', 'card.clearImage': '清除所选', 'card.submit': '提交审核', 'card.submitted': '已提交，等待审核', 'card.reason': '驳回原因',
    'col.uid': 'UID', 'col.user': '用户', 'col.email': '邮箱', 'col.role': '角色',
    'col.status': '状态', 'col.created': '注册', 'col.lastLogin': '最后登录', 'col.actions': '操作',
    'role.admin': '站长', 'role.user': '普通用户', 'status.banned': '已封禁', 'status.normal': '正常',
    'status.self': '当前账号不可操作', 'neverLogin': '从未登录', 'noUsers': '暂无用户',
    'user.setAdmin': '设为管理员', 'user.demote': '降为普通', 'user.ban': '封禁', 'user.unban': '解封',
    'user.delete': '删除', 'user.promoteTo': '站长', 'user.demoteTo': '普通用户',
    'common.save': '保存', 'common.cancel': '取消', 'common.delete': '删除', 'common.confirm': '确定',
    'common.edit': '编辑', 'common.publish': '发布', 'common.upload': '上传', 'common.add': '添加',
    'common.submit': '提交', 'common.loading': '加载中…', 'common.close': '关闭', 'common.all': '全部',
    'common.draft': '草稿', 'common.published': '已发布', 'common.title': '标题', 'common.desc': '说明',
    'common.cover': '封面', 'common.link': '链接', 'common.time': '时间', 'common.content': '内容',
    'common.allArticles': '全部文章（含草稿）', 'common.uploaded': '已上传', 'common.existProjects': '已有项目',
    'common.sponsorList': '赞助列表', 'common.existSocial': '已有动态',
    'empty.gallery': '图库还是空的', 'empty.articles': '还没有发布文章', 'empty.comments': '还没有评论',
    'empty.projects': '还没有展示项目', 'empty.social': '还没有发布动态', 'empty.sponsors': '还没有赞助记录',
    'empty.images': '暂无图片', 'empty.records': '暂无记录',
    'lightbox.close': '关闭', 'lightbox.prev': '上一张', 'lightbox.next': '下一张',
    'auth.email': '邮箱', 'auth.password': '密码', 'auth.code': '验证码', 'auth.sendCode': '发送验证码',
    'captcha.label': '图形验证码', 'captcha.ph': '请输入右侧 4 位字符',
    'captcha.refresh': '点击刷新验证码', 'captcha.alt': '图形验证码',
    'captcha.required': '请填写图形验证码', 'captcha.empty': '请填写图形验证码',
    'captcha.wrong': '图形验证码不正确', 'captcha.expired': '图形验证码已失效，请点击图片刷新',
    'captcha.loadFail': '验证码加载失败，请点击图片重试',
    'auth.login': '登录', 'auth.register': '注册', 'auth.logout': '退出登录', 'auth.uid': 'UID',
    'auth.remember': '记住我', 'auth.username': '用户名', 'auth.loginTab': '登录', 'auth.regTab': '注册',
    'logout.title': '退出登录', 'logout.msg': '确定要退出当前账号吗？', 'logout.ok': '退出登录', 'logout.cancel': '再想想',
    'pager.prev': '上一页', 'pager.next': '下一页',
    'action.like': '💗 点赞', 'action.fav': '⭐ 收藏', 'action.share': '🔗 分享',
    'comment.ph': '说点什么吧…（最多 1000 字）', 'comment.send': '发送评论',
    'comment.login': '登录', 'comment.loginSuffix': ' 后即可评论',
    'comment.empty': '还没有评论，来抢沙发～', 'comment.justNow': '刚刚',
    'comment.needContent': '评论内容不能为空', 'comment.posted': '评论已发布',
    'ctx.refresh': '刷新', 'ctx.copy': '复制',
    'share.copied': '链接已复制，感谢分享！', 'auth.needLogin': '请先登录',
    'title.settings': '个人设置', 'settings.basic': '基础资料', 'settings.social': '社交信息', 'settings.privacy': '隐私展示设置', 'settings.save': '保存资料', 'settings.saved': '设置已保存 ✨',
    'profile.birthday': '生日', 'profile.birthdayVis': '生日可见性', 'profile.birthdayHidden': '不展示', 'profile.birthdayAge': '仅年龄段', 'profile.birthdayIs': '仅是否生日当天',
    'profile.gender': '性别', 'profile.genderSecret': '保密', 'profile.genderMale': '男', 'profile.genderFemale': '女',
    'profile.signature': '个性签名', 'profile.signaturePh': '一句话介绍自己…',
    'profile.emailPublic': '公开邮箱', 'profile.emailVerified': '已验证', 'profile.emailUnverified': '修改后需重新验证',
    'profile.privacyTip': '默认最小可见：仅自己可见。开启后，对应内容才对其他用户展示。浏览记录默认仅自己可见。',
    'profile.field': '个人主页', 'profile.showFavorites': '收藏', 'profile.showLikes': '点赞', 'profile.showComments': '评论', 'profile.showBrowse': '最近浏览', 'profile.showLevel': '等级', 'profile.showTitle': '称号', 'profile.showCard': '个人名片', 'profile.showBadges': '成就徽章', 'profile.showMultiplier': '经验倍率', 'profile.showEmail': '邮箱',
    'profile.favorites': '收藏', 'profile.likes': '点赞', 'profile.browse': '最近浏览', 'profile.comments': '评论', 'profile.card': '个人名片', 'profile.cardStatus': '名片状态', 'profile.isBirthday': '今天是 TA 的生日', 'profile.ageRange': '年龄段', 'profile.privateHome': '该用户的主页未公开',
    'profile.xp': '经验', 'profile.xpMax': '已满级 ✨', 'profile.xpTip': '再获得 {need} 经验即可升级',
    'card.staff': '你是站长/管理员：名片不受等级限制，保存后免审核直接发布', 'card.autoApproved': '（已自动发布）',
    'menu.profile': '🏠 个人主页', 'menu.notifications': '🔔 消息',
    'notif.title': '站内消息', 'notif.readAll': '全部已读', 'notif.empty': '暂时没有消息',
    'notif.newMsg': '收到 {n} 条新消息', 'notif.unreadTip': '{n} 条未读消息',
    'menu.checkin': '📅 每日签到', 'menu.tasks': '✅ 任务', 'menu.achievements': '🏆 成就', 'menu.redeem': '🎟️ 兑换码', 'menu.community': '🎀 社区 · 成长', 'menu.groupMe': '个人', 'menu.groupCommunity': '社区',
    'checkin.title': '每日签到', 'checkin.do': '签到', 'checkin.done': '今日已签到', 'checkin.streak': '连续签到', 'checkin.days': '累计天数', 'checkin.tip': '每日签到获得经验，连续签到有额外奖励。纯签到 5 年保底可达 Lv10。', 'checkin.levelUp': '升级啦',
    'tasks.title': '每日任务', 'tasks.todo': '待完成', 'tasks.done': '已完成', 'tasks.reward': '奖励', 'tasks.xp': '经验', 'tasks.today': '今日进度',
    'ach.title': '成就墙', 'ach.get': '已获得', 'ach.locked': '未获得', 'ach.rewardXp': '奖励经验', 'ach.desc': '描述',
    'redeem.title': '兑换码', 'redeem.placeholder': '请输入兑换码', 'redeem.go': '兑换', 'redeem.ok': '兑换成功', 'redeem.tip': '兑换码可获取经验、称号等奖励，请妥善保管，切勿泄露。',
    'type.article': '文章', 'type.image': '图片', 'type.project': '项目', 'type.social': '动态',
    'login.welcome': '欢迎回来 🌙', 'login.userOrEmail': '用户名或邮箱', 'login.forgot': '忘记密码？',
    'login.agreePrefix': '我已阅读并同意 ', 'terms.link': '服务条款与隐私政策',
    'login.rememberPw': '记住密码', 'login.autoLogin': '自动登录',
    'login.loggingIn': '登录中…', 'login.noAccount': '还没有账号？', 'login.registerNow': '注册一个',
    'login.welcomeBack': '欢迎回来，{name} ✨', 'chip.loginRegister': '登录 / 注册',
    'profile.changePwd': '修改密码', 'profile.account': '账号', 'profile.avatar': '头像',
    'footer.default': '月之海 · 星娅小站 — 潮汐因月亮而有了方向，文字因被阅读而存在',
    'common.preview': '预览', 'common.format': '格式', 'common.views': '浏览', 'common.target': '目标',
    'common.platform': '平台', 'common.name': '名称', 'common.amount': '金额', 'common.repo': '仓库',
    'common.summary': '摘要', 'common.optional': '（可选）', 'common.me': '我', 'dlg.confirmTitle': '确认操作',
    'nav.menu': '展开菜单', 'theme.toggle': '切换主题',
    'entry.sub': '「 如霜的月色，落在你的小站 」',
    'msg.readFail': '文件读取失败', 'msg.importFailed': '导入失败',
    'md.imageAlt': '插图', 'md.imageLinkPh': '图片链接',
    'menu.settings': '⚙️ 个人设置', 'menu.logout': '🚪 退出登录', 'menu.adminBadge': ' · 站长',
    'menu.favorites': '⭐ 我的收藏',
    'fav.title': '我的收藏', 'fav.count': '共 {n} 项',
    'fav.empty': '还没有收藏任何内容', 'fav.emptyHint': '在文章、图片或项目上点「⭐ 收藏」，就会收进这里',
    'fav.remove': '取消收藏', 'fav.removed': '已取消收藏', 'fav.added': '已收藏', 'fav.removeMsg': '确定取消收藏这一项？',
    'fav.filterAll': '全部', 'fav.filterArticle': '文章', 'fav.filterImage': '图片', 'fav.filterProject': '项目',
    'type.article': '文章', 'type.image': '图片', 'type.project': '项目',
    'fav.savedAt': '收藏于', 'fav.view': '查看', 'fav.draft': '草稿',
    'fav.needLogin': '登录后才能查看收藏',
    'msg.loggedOut': '已退出登录', 'msg.reqFailed': '请求失败 ({status})',
    'msg.imgTooLarge': '图片不能超过 5MB', 'msg.uploadFailed': '上传失败', 'msg.saveFailed': '保存失败',
    'msg.avatarUpdated': '头像已更新 ✨', 'msg.avatarFail': '头像更新失败',
    'msg.pwdMismatch': '两次输入的新密码不一致', 'msg.pwdChanged': '密码已修改，下次登录请使用新密码',
    'msg.codeSent': '验证码已发送', 'msg.sending': '发送中…', 'msg.sendCode': '发送验证码',
    'msg.devCode': '开发模式：验证码 {code}（见服务器控制台）', 'msg.resendIn': '{n}s 后重发',
    'msg.needCorrectEmail': '请先填写正确的邮箱',
    'msg.pwdWeak': '密码需 8-72 位，且包含大写字母、小写字母、数字',
    'msg.pwdReset': '密码已重置，请用新密码登录 ✅',
    'msg.registering': '注册中…', 'msg.registerOk': '注册成功，欢迎加入！🎉',
    'msg.deleted': '已删除', 'msg.saved': '修改已保存', 'msg.updated': '已更新',
    'msg.delNoEffect': '服务端未找到该记录（可能已删除）',
    'msg.editing': '正在编辑：{title}', 'msg.banned': '已封禁', 'msg.unbanned': '已解封',
    'pwd.tooShort': '长度不足 8 位', 'pwd.needKinds': '需同时包含大写字母、小写字母和数字',
    'pwd.strong': '强 💪', 'pwd.ok': '合格 · 再长一点更安全',
    'settings.title': '个人设置 ⚙️', 'settings.changeAvatar': '更换头像',
    'settings.avatarHint': '支持 jpg/png/gif/webp，不超过 2MB',
    'settings.username': '用户名', 'settings.email': '邮箱（注册后不可修改）',
    'settings.uid': '账号 UID（唯一标识，用于区分重名账号）',
    'settings.usernameHint': '昵称 2-32 位，支持中英文/数字/空格与 _ . - ·；每 24 小时最多改 5 次',
    'settings.saveName': '保存昵称', 'settings.nameOk': '昵称已更新 ✨',
    'settings.emailFixed': '这是注册时绑定的账号邮箱，不支持修改；可选择是否在个人主页公开（公开时展示为脱敏格式）',
    'settings.emailSaved': '邮箱公开设置已保存 ✨',
    'settings.pwdMismatch': '两次输入的新密码不一致', 'settings.pwdTip': '修改成功后，其他设备上的登录状态会失效，需重新登录',
    'settings.oldPwd': '原密码', 'settings.newPwd': '新密码（8-72 位，需含大写字母、小写字母、数字）',
    'settings.confirmPwd': '确认新密码', 'settings.savePwd': '保存新密码',
    'reg.title': '加入小站 ✨', 'reg.username': '用户名（2-32 位字母/数字/下划线/中文）',
    'reg.emailPh': '用于接收验证码', 'reg.codePh': '6 位数字',
    'reg.pwd': '密码（8-72 位，需含大写字母、小写字母、数字）',
    'reg.confirmPwd': '确认密码', 'reg.confirmPwdPh': '再输入一次密码',
    'reg.submit': '注册', 'reg.hasAccount': '已有账号？', 'reg.loginNow': '直接登录',
    'forgot.title': '找回密码 🔑', 'forgot.tip': '输入注册时使用的邮箱，验证通过后即可设置新密码。',
    'forgot.email': '注册邮箱', 'forgot.code': '邮箱验证码（10 分钟内有效）',
    'forgot.newPwdPh': '再输入一次新密码', 'forgot.submit': '重置密码',
    'forgot.remembered': '想起来了？', 'forgot.backLogin': '返回登录',
    'loggedin.title': '你已经登录了', 'loggedin.identity': '当前身份：',
    'loggedin.home': '返回首页', 'loggedin.switch': '换个账号登录',
    'crop.title': '裁剪头像 ✂️', 'crop.zoom': '缩放', 'crop.alt': '裁剪预览',
    'crop.tip': '拖动图片调整位置，拖动滑块缩放；圆形区域内即为最终头像',
    'crop.use': '使用这张', 'crop.fail': '裁剪失败', 'crop.decodeFail': '该图片格式无法在浏览器中解码，请换 jpg/png/webp',
    'avatar.alt': '头像',
    'terms.welcome': '欢迎来到 {site} ✨', 'terms.decline': '不同意', 'terms.accept': '我已阅读并同意',
    'terms.gateMsg': '你需要同意条款才能使用本站。', 'terms.rethink': '重新考虑',
    'terms.thanks': '感谢同意，欢迎来到小站 ✨', 'terms.loading': '加载中…',
    'terms.empty': '本站暂未发布正式条款。使用本站即表示你同意遵守法律法规、尊重其他用户。',
    'sponsor.coffee': '☕ 请作者喝一杯',
    'sponsor.desc': '如果这个站点或我的项目对你有帮助，欢迎请我喝杯奶茶～<br>所有赞助将用于服务器与域名开销。',
    'sponsor.qrAlt': '收款码',
    'sponsor.noQr': '（站长还未上传收款码<br>可在后台「⚙️ 设置」中上传）',
    'sponsor.note': '赞助后可在下方留言墙留言（由站长登记）',
    'sponsor.wall': '💝 赞助留言墙', 'sponsor.empty': '还没有赞助记录，等你成为第一位～',
    'project.repo': '前往仓库 ↗',
    'social.intro': '我在各平台发布的内容，主要是 B 站视频，点卡片即可跳转观看。',
    'plat.bilibili': '哔哩哔哩', 'plat.weibo': '微博', 'plat.other': '其他',
    'article.noSummary': '（暂无摘要）',
    'notfound.title': '页面走丢了', 'notfound.home': '回到首页',
    'dash.title': '站点概览', 'dash.tip': '提示：第一个注册的账号自动成为站长。上传的收款码与站点设置可在各面板中维护。',
    'stat.articles': '文章', 'stat.images': '图片', 'stat.projects': '项目',
    'stat.users': '用户', 'stat.comments': '评论', 'stat.likes': '点赞', 'stat.views': '总阅读',
    'art.newTitle': '发布 / 管理文章', 'art.editTitle': '编辑文章',
    'art.mdMode': '📝 Markdown 模式', 'art.htmlMode': '📄 富文本 Doc 模式',
    'art.fieldTitle': '标题', 'art.fieldSummary': '摘要',
    'art.fieldCover': '封面图片 URL（可选）', 'art.fieldTags': '标签（英文逗号分隔）',
    'art.fieldStatus': '状态', 'art.statusPublish': '发布（前台可见）', 'art.statusDraft': '草稿（仅自己可见）',
    'art.contentMd': '正文（Markdown）', 'art.contentHtml': '正文（富文本 · 所见即所得）',
    'art.importMd': '📤 导入本地 .md', 'art.uploadImg': '🖼 上传图片并插入', 'art.importDoc': '📤 导入本地 .docx',
    'art.publishBtn': '发布文章', 'art.cancelEdit': '取消编辑',
    'art.tblTitle': '标题', 'art.tblStatus': '状态', 'art.tblFormat': '格式',
    'art.tblViews': '浏览', 'art.tblTime': '时间',
    'art.fmtRich': '富文本', 'art.noArticles': '暂无文章', 'art.publishedBadge': '已发布',
    'tb.bold': '加粗', 'tb.italic': '斜体', 'tb.underline': '下划线', 'tb.strike': '删除线',
    'tb.h2': '二级标题', 'tb.h3': '三级标题', 'tb.quote': '引用', 'tb.code': '代码块',
    'tb.ul': '无序列表', 'tb.ol': '有序列表', 'tb.link': '链接',
    'tb.image': '插入图片（先上传再填链接）', 'tb.clear': '清除格式',
    'tb.size': '字号', 'tb.xs': '特小', 'tb.sm': '小', 'tb.md': '正常', 'tb.lg': '大', 'tb.xl': '特大', 'tb.xxl': '超大',
    'tb.color': '文字颜色', 'tb.applyColor': '🎨 上色',
    'md.ph': '文字', 'md.codePh': '代码', 'md.linkPh': '链接文字', 'md.imagePh': '图片说明',
    'dlg.promptLink': '输入链接地址：', 'msg.imgInserted': '图片已插入', 'msg.linkInserted': '图片链接已插入',
    'msg.mdImported': '已导入 Markdown', 'msg.docImported': '已导入 docx，记得点保存',
    'msg.articlePublished': '文章已发布',
    'img.title': '上传 / 管理图片', 'img.pick': '选择图片（jpg/png/gif/webp/avif，≤8MB）',
    'img.fieldTitle': '标题', 'img.fieldDesc': '描述（会显示在图库卡片下方）',
    'img.uploadBtn': '上传', 'msg.uploadOk': '上传成功', 'msg.uploadedRemember': '已上传，记得点保存',
    'img.tblPreview': '预览',
    'img.hidden': '隐藏（不进前台图库）', 'img.hiddenTip': '适合赞助二维码等用途性图片：后台仍可管理与替换，但前台图库和搜索不再展示。', 'img.hiddenTag': '已隐藏', 'img.hide': '隐藏', 'img.show': '显示', 'img.hiddenOk': '已从前台图库隐藏', 'img.shownOk': '已恢复展示',
    'img.editTitle': '编辑图片', 'img.editing': '正在编辑：{title}', 'img.keepCurrent': '留空则保留当前图片',
    'prj.newTitle': '添加 / 管理项目', 'prj.editTitle': '编辑项目', 'prj.name': '项目名称',
    'prj.repo': 'GitHub 仓库地址（https://github.com/user/repo）', 'prj.desc': '描述',
    'prj.tags': '标签（逗号分隔）', 'prj.addBtn': '添加项目', 'prj.cancelEdit': '取消编辑',
    'prj.tblName': '名称', 'prj.noProjects': '暂无项目',
    'prj.icon': '展示图标', 'prj.iconPh': '选一个 emoji 作为项目图标',
    'prj.homepage': '项目主页（可选，展示在 About 侧栏）', 'prj.homepagePh': 'https://example.com',
    'prj.homepageTip': '可以省略 https://，例如直接填 example.com',
    'prj.secRepo': '仓库信息', 'prj.secAbout': '展示信息（About）', 'prj.topicsPh': '用逗号分隔，如：minecraft,plugin,folia',
    'prj.preview': '前台效果预览', 'prj.tip': '保存后前台项目页会自动同步 GitHub 的 README、语言、贡献者与发布版本；访客的下载与文件浏览都在站内完成，不会跳走。',
    'project.back': '返回项目列表', 'project.detail': '查看详情',
    'project.readmeTitle': '项目介绍', 'project.readmeEmpty': '暂时无法获取该项目的 GitHub README 介绍',
    'project.readmeLoading': '正在从 GitHub 加载项目介绍…',
    'detail.notFound': '内容不存在或已被删除',
    'gh.public': '公开', 'gh.code': '代码', 'gh.copy': '复制', 'gh.zip': '下载 ZIP',
    'gh.watch': '关注', 'gh.fork': '派生', 'gh.star': '星标',
    'gh.tabCode': '代码', 'gh.tabIssues': '议题', 'gh.tabPR': '拉取请求',
    'gh.tabActions': 'Actions', 'gh.tabWiki': 'Wiki', 'gh.tabSecurity': '安全', 'gh.tabInsights': '洞察',
    'gh.loading': '加载中…', 'gh.noCommit': '暂无提交信息', 'gh.noFiles': '暂无文件列表',
    'gh.metaUnavailable': 'GitHub 数据暂不可用',
    'gh.about': '关于', 'gh.stars': '星标', 'gh.forks': '派生', 'gh.watching': '关注',
    'gh.languages': '语言', 'gh.contributors': '贡献者', 'gh.releases': '发布版本',
    'gh.siteActions': '本站互动',
    // 三个大按钮全部改为站内动作：Star=收藏、Watch=点赞、Fork=下载源码副本
    'gh.starTip': '在本站收藏这个项目（Star）', 'gh.watchTip': '在本站点赞这个项目（Watch）', 'gh.forkTip': '在本站下载一份源码副本（Fork）',
    'gh.starOn': '已星标', 'gh.starOff': '星标', 'gh.watchOn': '已关注', 'gh.watchOff': '关注',
    'gh.ghStar': 'GitHub 星标', 'gh.ghFork': 'GitHub 派生', 'gh.ghWatch': 'GitHub 关注',
    'gh.openRepo': '前往原仓库', 'gh.downloading': '正在准备源码包…', 'gh.dlFail': '下载失败，请稍后再试',
    'gh.fileUp': '返回上级', 'gh.fileDown': '下载此文件', 'gh.fileBinary': '二进制文件无法在线预览，可下载后查看',
    'gh.fileEmpty': '该文件为空', 'gh.browseFail': '读取失败，请稍后再试', 'gh.fileRoot': '根目录',
    'gh.paneIssues': '本站讨论', 'gh.paneIssuesTip': '这里是你与访客在本站的留言区；如需向作者提交缺陷或功能请求，可前往原仓库的 Issues。',
    'gh.panePulls': '拉取请求', 'gh.panePullsTip': '本站不托管代码，无法直接发起 Pull Request。想贡献代码请前往原仓库；也可以先在「议题」里留言交流。',
    'gh.paneActions': '最近动态', 'gh.paneActionsTip': '以下信息由本站定时从 GitHub 同步（默认 6 小时刷新一次）。',
    'gh.paneWiki': '项目文档', 'gh.paneWikiTip': '以下为仓库 README 的完整内容（本站代理抓取并渲染）。',
    'gh.paneSecurity': '安全与许可', 'gh.paneSecurityTip': '本站不提供漏洞上报通道，安全相关问题请通过原仓库的 Security 页面或联系作者反馈。',
    'gh.paneInsights': '统计概览', 'gh.paneInsightsTip': '语言构成与贡献者均由本站定时同步。',
    'gh.releaseDl': '下载该版本源码', 'gh.noRelease': '暂无发布版本', 'gh.noLicense': '未声明开源许可',
    'gh.noData': '暂无数据', 'gh.lastCommit': '最近提交', 'gh.closeFile': '关闭',
    'gh.cloneLab': '克隆', 'gh.downloadLab': '下载源码', 'gh.tar': '下载 TAR.GZ', 'gh.preRelease': '预览版',
    'gh.relLatest': '最新', 'gh.relAssets': '资产', 'gh.relDownload': '下载',
    'gh.relTip': '以下为该 GitHub 仓库的发行版本，所有下载均在站内完成，不会跳转到 GitHub。',
    'gh.relSourceZip': '源码 (ZIP)', 'gh.relSourceTar': '源码 (TAR.GZ)', 'gh.relViewAll': '查看全部发行版',
    'image.back': '返回图库', 'image.untitled': '未命名图片', 'image.zoom': '🔍 放大查看',
    'image.detail': '详情 · 评论',
    'msg.prjUpdated': '项目已更新', 'msg.prjAdded': '项目已添加',
    'cmt.delete': '删除', 'cmt.deleted': '评论已删除', 'cmt.adminTitle': '评论管理', 'cmt.tblContent': '内容', 'cmt.tblTarget': '目标',
    'cmt.visible': '✅ 可见', 'cmt.hidden': '🚫 已隐藏',
    'cmt.hideBtn': '隐藏', 'cmt.restoreBtn': '恢复',
    'sp.adminTitle': '登记赞助', 'sp.sponsorName': '赞助者名称',
    'sp.amount': '金额（元，可空）', 'sp.message': '留言', 'sp.recordBtn': '登记',
    'sp.tblName': '名称', 'sp.tblAmount': '金额', 'sp.tblMessage': '留言',
    'msg.recorded': '已登记',
    'soc.newTitle': '发布社交动态', 'soc.editTitle': '编辑动态', 'soc.platform': '平台',
    'soc.fieldTitle': '标题', 'soc.titlePh': '视频/动态标题', 'soc.url': '链接（B站视频链接等）',
    'soc.desc': '简介', 'soc.cover': '封面图（可选，B站视频截图更好看）',
    'soc.coverPh': '留空则显示平台图标', 'soc.uploadBtn': '上传',
    'soc.status': '状态', 'soc.show': '展示（前台可见）', 'soc.hide': '隐藏',
    'soc.publishBtn': '发布动态', 'soc.cancelEdit': '取消编辑', 'soc.exist': '已有动态',
    'soc.tblPlatform': '平台', 'soc.badgeShow': '展示', 'soc.badgeHide': '隐藏', 'empty.socialShort': '暂无动态',
    'msg.coverUploaded': '封面已上传', 'msg.socPublished': '动态已发布',
    'user.banTip': '封禁后该用户的所有登录态立即失效，无法再登录；删除用户会一并清理其评论、点赞与收藏。封禁时间留空表示立即永久生效，可设置起止时间进行限时封禁。',
    'ban.title': '封禁用户', 'ban.titleEdit': '封禁 / 解封用户',
    'ban.msgBanned': '该用户当前处于封禁状态。可调整封禁时间，或点「解封」恢复其登录。',
    'ban.msgFree': '为该用户设置封禁时间，确认后其登录态立即失效。',
    'ban.from': '封禁起（可选，留空=立即生效）', 'ban.to': '封禁至（可选，留空=永久封禁）',
    'ban.unban': '解封', 'ban.saveChange': '保存修改', 'ban.confirmBan': '确认封禁',
    'ban.immediate': '立即', 'ban.permanentSuffix': ' 起 · 永久',
    'ban.permanent': '永久',
    'admin.ipban': '🚫 IP 封禁', 'admin.ipbanTitle': 'IP 封禁', 'col.ip': 'IP 地址',
    'user.banIp': '封禁此IP',
    'ipban.title': '你的 IP 已被封禁',
    'ipban.desc': '当前网络地址已被站长封禁，该地址下的所有账号都无法进入本站。',
    'ipban.yourIp': '你的 IP', 'ipban.until': '解封时间', 'ipban.reason': '封禁原因',
    'ipban.contact': '如认为这是误封，请联系站长处理。',
    'ipban.blockedToast': '你的 IP 已被封禁，无法进行此操作',
    'ipban.dialogTitle': '封禁 IP', 'ipban.dialogMsg': '封禁「{ip}」后，该 IP 下的所有账号都将无法进入本站。',
    'ipban.ip': 'IP 地址', 'ipban.duration': '封禁时长', 'ipban.reasonPh': '可选，如：恶意刷评论',
    'ipban.selfTip': '提示：不能封禁你自己当前所在的 IP，避免把自己关在门外。',
    'ipban.confirm': '确认封禁', 'ipban.banned': '已封禁该 IP', 'ipban.needIp': '请填写要封禁的 IP',
    'ipban.h1': '1 小时', 'ipban.h6': '6 小时', 'ipban.d1': '1 天', 'ipban.d7': '7 天', 'ipban.d30': '30 天',
    'ipban.accounts': '关联账号', 'ipban.viewAccounts': '{n} 个账号', 'ipban.accountsOf': '「{ip}」下的账号',
    'ipban.noAccount': '该 IP 下暂无记录到的账号',
    'ipban.unban': '解除封禁', 'ipban.unbanTitle': '解除 IP 封禁', 'ipban.unbanMsg': '确定解除对「{ip}」的封禁？',
    'ipban.unbanned': '已解除封禁', 'ipban.empty': '暂无被封禁的 IP', 'ipban.expired': '已过期',
    'ipban.tip': '说明：封禁 IP 会切断该地址下所有账号的进入通道（含已登录状态）。用户最近一次登录的 IP 见「用户」表格。',
    'site.name': '站名（显示在导航栏与浏览器标题）', 'site.namePh': '月之海',
    'site.slogan': '副标题', 'site.sloganPh': '星娅小站',
    'site.footer': '页脚文案', 'site.footerPh': '留空则使用默认文案',
    'site.icp': '备案号（留空则页脚不显示备案信息）', 'site.icpPh': '如：京ICP备XXXXXXXX号',
    'site.qr': '赞助收款码图片（上传后显示在赞助页）', 'site.qrPh': '留空则赞助页显示占位提示',
    'site.qrUpload': '⬆️ 上传收款码', 'site.qrAlt': '当前收款码',
    'site.qrCurrent': '当前收款码 · 重新上传后记得点保存',
    'site.noQr': '还没有收款码，点「上传收款码」选择图片（jpg/png/webp，≤8MB）',
    'site.save': '保存设置', 'msg.siteSaved': '设置已保存并生效',
    'termsAdmin.title': '编辑服务条款（支持 Markdown）',
    'termsAdmin.tip': '可直接编辑后点「保存条款」；也可用下方按钮从 <code>terms.md</code> 文件载入：',
    'termsAdmin.save': '保存条款', 'termsAdmin.importServer': '从服务器 terms.md 导入',
    'termsAdmin.importLocal': '选择本地文件导入', 'termsAdmin.importing': '导入中…',
    'msg.termsSaved': '条款已保存',
    'msg.importedServer': '已从服务器 terms.md 导入并生效（{n} 字符）',
    'msg.importedLocal': '已从「{name}」导入并生效（{n} 字符）',
    'dlg.publishArticle': '发布文章', 'dlg.publishArticleMsg': '确认将这篇新文章发布到前台？发布后访客即可看到。',
    'dlg.publishBtn': '发布', 'dlg.rethink': '再想想',
    'dlg.delArticle': '删除文章', 'dlg.delArticleMsg': '确定删除这篇文章？此操作不可恢复。',
    'dlg.uploadImg': '上传图片', 'dlg.uploadImgMsg': '确认将这张图片上传到图库？',
    'dlg.delImage': '删除图片', 'dlg.delImageMsg': '确定删除这张图片？',
    'dlg.addProject': '添加项目', 'dlg.addProjectMsg': '确认添加这个新项目到前台展示？',
    'dlg.delProject': '删除项目', 'dlg.delProjectMsg': '确定删除该项目？',
    'dlg.delComment': '删除评论', 'dlg.delCommentMsg': '确定删除该评论？',
    'dlg.recordSponsor': '登记赞助', 'dlg.recordSponsorMsg': '确认登记这条赞助记录？',
    'dlg.delSponsor': '删除赞助记录', 'dlg.delSponsorMsg': '确定删除这条赞助记录？',
    'dlg.publishMoment': '发布动态', 'dlg.publishMomentMsg': '确认发布这条新动态到前台？',
    'dlg.delMoment': '删除动态', 'dlg.delMomentMsg': '确定删除这条动态？',
    'dlg.roleMsg': '确定将所选用户调整为「{role}」？', 'dlg.roleTitle': '调整角色', 'dlg.delUserTitle': '删除用户',
    'dlg.delUserMsg': '确定删除该用户？其评论、点赞、收藏将一并清除，且不可恢复。',
  },
  en: {
    'nav.home': 'Articles', 'nav.gallery': 'Gallery', 'nav.projects': 'Projects', 'nav.social': 'Moments', 'nav.sponsor': 'Sponsor',
    'nav.admin': '👑 Admin',
    'nav.search': 'Search', 'search.title': 'Search',
    'nav.announcements': 'Announcements', 'ann.title': 'Announcements', 'ann.empty': 'No announcements yet', 'ann.pinned': 'Pinned',
    'ann.tag.update': 'Update', 'ann.tag.maintenance': 'Maintenance', 'ann.tag.action': 'Action',
    'ann.tag.important': 'Important', 'ann.tag.event': 'Event', 'ann.tag.other': 'Other',
    'ann.popup.title': '📢 Announcements', 'ann.popup.gotIt': 'Got it',
    'ann.adminTitle': 'Publish / Manage Announcements', 'ann.newTitle': 'New announcement', 'ann.editTitle': 'Edit announcement',
    'ann.fieldTitle': 'Title', 'ann.fieldContent': 'Content (Markdown)', 'ann.fieldTag': 'Tag',
    'ann.fieldPinned': 'Pinned (shown as a popup to new & returning users)',
    'ann.addBtn': 'Publish', 'ann.cancelEdit': 'Cancel edit',
    'ann.tblTitle': 'Title', 'ann.tblTag': 'Tag', 'ann.tblPinned': 'Pinned', 'ann.tblTime': 'Time', 'ann.noAnnouncements': 'No announcements',
    'ann.delMsg': 'Delete this announcement?',
    'search.ph': 'Search articles, images, projects, moments…', 'search.btn': 'Search',
    'search.empty': 'No results — try another keyword.', 'search.count': '{n} result(s)',
    'search.all': 'All', 'search.article': 'Articles', 'search.image': 'Images', 'search.project': 'Projects', 'search.social': 'Moments', 'search.announcement': 'Announcements', 'search.user': 'Users',
    'title.articles': 'Articles', 'title.gallery': 'Gallery', 'title.projects': 'GitHub Projects',
    'title.social': 'Moments 📱', 'title.sponsor': 'Sponsor', 'title.login': 'Sign in / Sign up',
    'title.settings': 'Account Settings', 'title.comments': 'Comments',
    'admin.dashboard': '📊 Dashboard', 'admin.articles': '📝 Articles', 'admin.images': '🖼️ Gallery',
    'admin.projects': '🐙 Projects', 'admin.comments': '💬 Comments', 'admin.sponsors': '💝 Sponsors',
    'admin.social': '📱 Moments', 'admin.users': '👥 Users', 'admin.terms': '📜 Terms', 'admin.settings': '⚙️ Settings',
    'admin.announcements': '📢 Announcements',
    'admin.enter': 'Admin Panel', 'admin.needPermission': 'Admin permission required', 'admin.usersTitle': 'Users',
    'admin.settingsTitle': 'Site Settings', 'admin.termsTitle': 'Terms of Service', 'admin.community': '🎀 Community',
    'comm.titles': 'Titles', 'comm.achievements': 'Achievements', 'comm.multipliers': 'XP Multipliers', 'comm.redeem': 'Redeem Codes', 'comm.notify': 'Broadcast', 'comm.name': 'Name', 'comm.key': 'Key', 'comm.desc': 'Desc', 'comm.icon': 'Icon', 'comm.create': 'Create', 'comm.grant': 'Grant', 'comm.revoke': 'Revoke', 'comm.rewardXp': 'XP reward', 'comm.condition': 'Condition(JSON)', 'comm.multiplier': 'Linked multiplier(JSON)', 'comm.value': 'Value', 'comm.scope': 'Scope(nonsignin/all)', 'comm.cap': 'Global cap', 'comm.enabled': 'Enabled', 'comm.maxUses': 'Max uses', 'comm.perUserOnce': 'Once per user', 'comm.expiresAt': 'Expires at', 'comm.genCode': 'Generate code', 'comm.recipient': 'Recipient user id (blank=all)', 'comm.sendMsg': 'Send', 'comm.userId': 'User ID', 'comm.noOwner': 'Only the owner can configure community', 'comm.generated': 'Code generated', 'comm.titleColor': 'Color', 'comm.edit': 'Edit', 'comm.delConfirm': 'Delete this item? This cannot be undone.', 'comm.tasks': 'Tasks', 'comm.levelColors': 'Level colors', 'comm.levelColorTip': 'Set a badge color for each level (Lv1-Lv10); a cool-to-warm gold gradient is designed by default.', 'comm.resetColors': 'Reset', 'comm.resetDone': 'Default palette restored', 'comm.levelColorSaveTip': 'Takes effect site-wide immediately (profile, comments, admin lists and search all share one palette).', 'comm.taskType': 'Type', 'comm.target': 'Target', 'comm.dailyCap': 'Daily cap', 'comm.rewardType': 'Reward type', 'comm.rewardValue': 'Reward value', 'comm.random': 'Random', 'comm.randomGen': 'Random 5', 'comm.count': 'Count', 'comm.typeXp': 'XP', 'comm.typeAchievement': 'Achievement', 'comm.typeTitle': 'Title', 'comm.useTitleKey': 'or title key', 'comm.cards': 'Card Review', 'comm.approve': 'Approve', 'comm.reject': 'Reject', 'comm.takedown': 'Take down', 'comm.reason': 'Reason', 'comm.preview': 'View', 'comm.user': 'User', 'comm.all': 'All', 'comm.emptyCards': 'No cards', 'comm.privacy': 'Privacy defaults', 'comm.privacyTip': 'Default visibility applied when a new user profile is first created (minimal by default).', 'comm.save': 'Save', 'card.pending': 'Pending', 'card.approved': 'Approved', 'card.rejected': 'Rejected', 'card.takenDown': 'Taken down', 'card.locked': 'Name card unlocks at Lv{lv}', 'card.tip': 'Fill in your card and upload an image. It will be reviewed by the owner, and shown on your profile once approved.', 'card.titleField': 'Card title', 'card.introField': 'Card intro', 'card.titlePh': 'One line about you', 'card.introPh': 'A longer self-introduction (optional)', 'card.bg': 'Background', 'card.fg': 'Text color', 'card.accent': 'Accent', 'card.image': 'Card image', 'card.pickImage': 'Choose image', 'card.noImage': 'No image selected', 'card.clearImage': 'Clear', 'card.submit': 'Submit for review', 'card.submitted': 'Submitted, awaiting review', 'card.reason': 'Reject reason',
    'col.uid': 'UID', 'col.user': 'User', 'col.email': 'Email', 'col.role': 'Role',
    'col.status': 'Status', 'col.created': 'Joined', 'col.lastLogin': 'Last login', 'col.actions': 'Actions',
    'role.admin': 'Admin', 'role.user': 'User', 'status.banned': 'Banned', 'status.normal': 'Active',
    'status.self': 'Cannot modify current account', 'neverLogin': 'Never', 'noUsers': 'No users',
    'user.setAdmin': 'Make admin', 'user.demote': 'Demote', 'user.ban': 'Ban', 'user.unban': 'Unban',
    'user.delete': 'Delete', 'user.promoteTo': 'Admin', 'user.demoteTo': 'User',
    'common.save': 'Save', 'common.cancel': 'Cancel', 'common.delete': 'Delete', 'common.confirm': 'Confirm',
    'common.edit': 'Edit', 'common.publish': 'Publish', 'common.upload': 'Upload', 'common.add': 'Add',
    'common.submit': 'Submit', 'common.loading': 'Loading…', 'common.close': 'Close', 'common.all': 'All',
    'common.draft': 'Draft', 'common.published': 'Published', 'common.title': 'Title', 'common.desc': 'Description',
    'common.cover': 'Cover', 'common.link': 'Link', 'common.time': 'Time', 'common.content': 'Content',
    'common.allArticles': 'All articles (incl. drafts)', 'common.uploaded': 'Uploaded', 'common.existProjects': 'Projects',
    'common.sponsorList': 'Sponsors', 'common.existSocial': 'Moments',
    'empty.gallery': 'Gallery is empty', 'empty.articles': 'No articles yet', 'empty.comments': 'No comments yet',
    'empty.projects': 'No projects yet', 'empty.social': 'No moments yet', 'empty.sponsors': 'No sponsor records',
    'empty.images': 'No images', 'empty.records': 'No records',
    'lightbox.close': 'Close', 'lightbox.prev': 'Previous', 'lightbox.next': 'Next',
    'auth.email': 'Email', 'auth.password': 'Password', 'auth.code': 'Code', 'auth.sendCode': 'Send code',
    'captcha.label': 'CAPTCHA', 'captcha.ph': 'Enter the 4 characters shown',
    'captcha.refresh': 'Click to refresh', 'captcha.alt': 'CAPTCHA image',
    'captcha.required': 'Please enter the CAPTCHA', 'captcha.empty': 'Please enter the CAPTCHA',
    'captcha.wrong': 'Incorrect CAPTCHA', 'captcha.expired': 'CAPTCHA expired, click the image to refresh',
    'captcha.loadFail': 'Failed to load CAPTCHA, click the image to retry',
    'auth.login': 'Sign in', 'auth.register': 'Sign up', 'auth.logout': 'Sign out', 'auth.uid': 'UID',
    'auth.remember': 'Remember me', 'auth.username': 'Username', 'auth.loginTab': 'Sign in', 'auth.regTab': 'Sign up',
    'logout.title': 'Sign out', 'logout.msg': 'Are you sure you want to sign out?', 'logout.ok': 'Sign out', 'logout.cancel': 'Not now',
    'pager.prev': 'Previous', 'pager.next': 'Next',
    'action.like': '💗 Like', 'action.fav': '⭐ Save', 'action.share': '🔗 Share',
    'comment.ph': 'Say something… (up to 1000 characters)', 'comment.send': 'Post comment',
    'comment.login': 'Sign in', 'comment.loginSuffix': ' to join the conversation',
    'comment.empty': 'No comments yet — be the first!', 'comment.justNow': 'Just now',
    'comment.needContent': 'Comment cannot be empty', 'comment.posted': 'Comment posted',
    'ctx.refresh': 'Refresh', 'ctx.copy': 'Copy',
    'share.copied': 'Link copied, thanks for sharing!', 'auth.needLogin': 'Please sign in first',
    'login.welcome': 'Welcome back 🌙', 'login.userOrEmail': 'Username or email', 'login.forgot': 'Forgot password?',
    'login.agreePrefix': 'I have read and agree to the ', 'terms.link': 'Terms & Privacy Policy',
    'login.rememberPw': 'Remember password', 'login.autoLogin': 'Auto sign in',
    'login.loggingIn': 'Signing in…', 'login.noAccount': 'No account yet?', 'login.registerNow': 'Sign up',
    'login.welcomeBack': 'Welcome back, {name} ✨', 'chip.loginRegister': 'Sign in / Sign up',
    'profile.changePwd': 'Change Password', 'profile.account': 'Account', 'profile.avatar': 'Avatar',
    'footer.default': 'Moonlit Sea · Xingya Station — The tide finds its direction by the moon, words exist by being read',
    'common.preview': 'Preview', 'common.format': 'Format', 'common.views': 'Views', 'common.target': 'Target',
    'common.platform': 'Platform', 'common.name': 'Name', 'common.amount': 'Amount', 'common.repo': 'Repo',
    'common.summary': 'Summary', 'common.optional': '(optional)', 'common.me': 'Me', 'dlg.confirmTitle': 'Confirm',
    'nav.menu': 'Open menu', 'theme.toggle': 'Toggle theme',
    'entry.sub': '「 Moonlight like frost, resting on your little station 」',
    'msg.readFail': 'Failed to read file', 'msg.importFailed': 'Import failed',
    'md.imageAlt': 'illustration', 'md.imageLinkPh': 'image URL',
    'menu.settings': '⚙️ Settings', 'menu.logout': '🚪 Sign out', 'menu.adminBadge': ' · Admin',
    'menu.favorites': '⭐ My Favorites',
    'fav.title': 'My Favorites', 'fav.count': '{n} items',
    'fav.empty': 'Nothing saved yet', 'fav.emptyHint': 'Tap ⭐ Save on an article, image or project to collect it here',
    'title.settings': 'Account Settings', 'settings.basic': 'Basic Profile', 'settings.social': 'Social Links', 'settings.privacy': 'Privacy Visibility', 'settings.save': 'Save Profile', 'settings.saved': 'Settings saved ✨',
    'profile.birthday': 'Birthday', 'profile.birthdayVis': 'Birthday visibility', 'profile.birthdayHidden': 'Hidden', 'profile.birthdayAge': 'Age range only', 'profile.birthdayIs': 'Is-birthday only',
    'profile.gender': 'Gender', 'profile.genderSecret': 'Private', 'profile.genderMale': 'Male', 'profile.genderFemale': 'Female',
    'profile.signature': 'Signature', 'profile.signaturePh': 'One line about you…',
    'profile.emailPublic': 'Public email', 'profile.emailVerified': 'Verified', 'profile.emailUnverified': 'Re-verify after change',
    'profile.privacyTip': 'Minimal visibility by default: visible to you only. Toggle on to share with others. Browse history is private by default.',
    'profile.field': 'Profile', 'profile.showFavorites': 'Favorites', 'profile.showLikes': 'Likes', 'profile.showComments': 'Comments', 'profile.showBrowse': 'Recent views', 'profile.showLevel': 'Level', 'profile.showTitle': 'Title', 'profile.showCard': 'Name card', 'profile.showBadges': 'Achievement badges', 'profile.showMultiplier': 'XP multiplier', 'profile.showEmail': 'Email',
    'profile.favorites': 'Favorites', 'profile.likes': 'Likes', 'profile.browse': 'Recent views', 'profile.comments': 'Comments', 'profile.card': 'Name card', 'profile.cardStatus': 'Card status', 'profile.isBirthday': "It's their birthday", 'profile.ageRange': 'Age range', 'profile.privateHome': "This user's profile is private",
    'profile.xp': 'XP', 'profile.xpMax': 'MAX ✨', 'profile.xpTip': '{need} more XP to level up',
    'card.staff': 'You are the site owner/admin: no level requirement, your card publishes without review', 'card.autoApproved': '(auto-published)',
    'menu.profile': '🏠 Profile', 'menu.notifications': '🔔 Notifications',
    'notif.title': 'Notifications', 'notif.readAll': 'Mark all read', 'notif.empty': 'No messages yet',
    'notif.newMsg': '{n} new message(s)', 'notif.unreadTip': '{n} unread',
    'menu.checkin': '📅 Daily Check-in', 'menu.tasks': '✅ Tasks', 'menu.achievements': '🏆 Achievements', 'menu.redeem': '🎟️ Redeem', 'menu.community': '🎀 Community', 'menu.groupMe': 'Me', 'menu.groupCommunity': 'Community',
    'checkin.title': 'Daily Check-in', 'checkin.do': 'Check in', 'checkin.done': 'Checked in today', 'checkin.streak': 'Streak', 'checkin.days': 'Total days', 'checkin.tip': 'Check in daily for XP; streaks give bonus. 5 years of check-ins guarantee Lv10.', 'checkin.levelUp': 'Level up',
    'tasks.title': 'Daily Tasks', 'tasks.todo': 'To do', 'tasks.done': 'Done', 'tasks.reward': 'Reward', 'tasks.xp': 'XP', 'tasks.today': 'Today',
    'ach.title': 'Achievements', 'ach.get': 'Earned', 'ach.locked': 'Locked', 'ach.rewardXp': 'XP reward', 'ach.desc': 'Desc',
    'redeem.title': 'Redeem Code', 'redeem.placeholder': 'Enter redeem code', 'redeem.go': 'Redeem', 'redeem.ok': 'Redeemed', 'redeem.tip': 'Codes grant XP, titles and more. Keep them safe.',
    'type.article': 'Article', 'type.image': 'Image', 'type.project': 'Project', 'type.social': 'Moment',
    'fav.remove': 'Remove', 'fav.removed': 'Removed from favorites', 'fav.added': 'Saved to favorites', 'fav.removeMsg': 'Remove this item from your favorites?',
    'fav.filterAll': 'All', 'fav.filterArticle': 'Articles', 'fav.filterImage': 'Images', 'fav.filterProject': 'Projects',
    'type.article': 'Article', 'type.image': 'Image', 'type.project': 'Project',
    'fav.savedAt': 'Saved', 'fav.view': 'View', 'fav.draft': 'Draft',
    'fav.needLogin': 'Please sign in to view your favorites',
    'msg.loggedOut': 'Signed out', 'msg.reqFailed': 'Request failed ({status})',
    'msg.imgTooLarge': 'Image must be under 5MB', 'msg.uploadFailed': 'Upload failed', 'msg.saveFailed': 'Save failed',
    'msg.avatarUpdated': 'Avatar updated ✨', 'msg.avatarFail': 'Failed to update avatar',
    'msg.pwdMismatch': 'The two new passwords do not match', 'msg.pwdChanged': 'Password changed. Use the new one next time',
    'msg.codeSent': 'Code sent', 'msg.sending': 'Sending…', 'msg.sendCode': 'Send code',
    'msg.devCode': 'Dev mode: code {code} (see server console)', 'msg.resendIn': 'Resend in {n}s',
    'msg.needCorrectEmail': 'Please enter a valid email',
    'msg.pwdWeak': 'Password must be 8-72 characters with upper, lower and digit',
    'msg.pwdReset': 'Password reset. Sign in with the new one ✅',
    'msg.registering': 'Signing up…', 'msg.registerOk': 'Welcome aboard! 🎉',
    'msg.deleted': 'Deleted', 'msg.saved': 'Changes saved', 'msg.updated': 'Updated',
    'msg.delNoEffect': 'Server found no matching record (already deleted?)',
    'msg.editing': 'Editing: {title}', 'msg.banned': 'Banned', 'msg.unbanned': 'Unbanned',
    'pwd.tooShort': 'At least 8 characters', 'pwd.needKinds': 'Must include upper, lower and digit',
    'pwd.strong': 'Strong 💪', 'pwd.ok': 'OK · longer is safer',
    'settings.title': 'Account Settings ⚙️', 'settings.changeAvatar': 'Change avatar',
    'settings.avatarHint': 'jpg/png/gif/webp, max 2MB',
    'settings.username': 'Username', 'settings.email': 'Email (cannot be changed afterwards)',
    'settings.uid': 'Account UID (unique ID, distinguishes same-name accounts)',
    'settings.usernameHint': '2-32 chars (letters/digits/space/_ . - ·), up to 5 changes per 24h',
    'settings.saveName': 'Save nickname', 'settings.nameOk': 'Nickname updated ✨',
    'settings.emailFixed': 'This is the email bound at registration and cannot be changed; you may toggle whether it shows on your profile (masked)',
    'settings.emailSaved': 'Email visibility saved ✨',
    'settings.pwdMismatch': 'The two new passwords do not match', 'settings.pwdTip': 'After changing, other devices will be signed out.',
    'settings.oldPwd': 'Current password', 'settings.newPwd': 'New password (8-72 chars, upper + lower + digit)',
    'settings.confirmPwd': 'Confirm new password', 'settings.savePwd': 'Save password',
    'reg.title': 'Join the station ✨', 'reg.username': 'Username (2-32 chars: letters/digits/_/Chinese)',
    'reg.emailPh': 'To receive the code', 'reg.codePh': '6 digits',
    'reg.pwd': 'Password (8-72 chars, upper + lower + digit)',
    'reg.confirmPwd': 'Confirm password', 'reg.confirmPwdPh': 'Re-enter password',
    'reg.submit': 'Sign up', 'reg.hasAccount': 'Already have an account?', 'reg.loginNow': 'Sign in',
    'forgot.title': 'Reset Password 🔑', 'forgot.tip': 'Enter the email you registered with; you can set a new password once verified.',
    'forgot.email': 'Registered email', 'forgot.code': 'Email code (valid for 10 minutes)',
    'forgot.newPwdPh': 'Re-enter new password', 'forgot.submit': 'Reset password',
    'forgot.remembered': 'Remembered it?', 'forgot.backLogin': 'Back to sign in',
    'loggedin.title': "You're already signed in", 'loggedin.identity': 'Signed in as:',
    'loggedin.home': 'Back home', 'loggedin.switch': 'Switch account',
    'crop.title': 'Crop Avatar ✂️', 'crop.zoom': 'Zoom', 'crop.alt': 'Crop preview',
    'crop.tip': 'Drag to reposition, use the slider to zoom; the circle is your final avatar',
    'crop.use': 'Use this', 'crop.fail': 'Crop failed', 'crop.decodeFail': 'This format cannot be decoded, use jpg/png/webp',
    'avatar.alt': 'Avatar',
    'terms.welcome': 'Welcome to {site} ✨', 'terms.decline': 'Decline', 'terms.accept': 'I have read and agree',
    'terms.gateMsg': 'You need to accept the terms to use this site.', 'terms.rethink': 'Let me reconsider',
    'terms.thanks': 'Thanks, welcome aboard ✨', 'terms.loading': 'Loading…',
    'terms.empty': 'No formal terms published yet. By using this site you agree to comply with the law and respect other users.',
    'sponsor.coffee': '☕ Buy me a coffee',
    'sponsor.desc': 'If this site or my projects helped you, feel free to treat me to a milk tea~<br>All support goes to server and domain costs.',
    'sponsor.qrAlt': 'QR code',
    'sponsor.noQr': '(No QR code uploaded yet<br>add one in Admin → ⚙️ Settings)',
    'sponsor.note': 'After supporting, you can leave a message on the wall below (recorded by the admin)',
    'sponsor.wall': '💝 Supporter Wall', 'sponsor.empty': 'No sponsors yet — be the first～',
    'project.repo': 'View repo ↗',
    'social.intro': 'My posts across platforms, mostly Bilibili videos. Click a card to watch.',
    'plat.bilibili': 'Bilibili', 'plat.weibo': 'Weibo', 'plat.other': 'Other',
    'article.noSummary': '(no summary)',
    'notfound.title': 'Page not found', 'notfound.home': 'Back home',
    'dash.title': 'Overview', 'dash.tip': 'Tip: the first registered account becomes the admin. The QR code and site settings are managed in their panels.',
    'stat.articles': 'Articles', 'stat.images': 'Images', 'stat.projects': 'Projects',
    'stat.users': 'Users', 'stat.comments': 'Comments', 'stat.likes': 'Likes', 'stat.views': 'Total views',
    'art.newTitle': 'Publish / Manage Articles', 'art.editTitle': 'Edit Article',
    'art.mdMode': '📝 Markdown mode', 'art.htmlMode': '📄 Rich-text Doc mode',
    'art.fieldTitle': 'Title', 'art.fieldSummary': 'Summary',
    'art.fieldCover': 'Cover image URL (optional)', 'art.fieldTags': 'Tags (comma separated)',
    'art.fieldStatus': 'Status', 'art.statusPublish': 'Published (visible to all)', 'art.statusDraft': 'Draft (only me)',
    'art.contentMd': 'Content (Markdown)', 'art.contentHtml': 'Content (rich text · WYSIWYG)',
    'art.importMd': '📤 Import local .md', 'art.uploadImg': '🖼 Upload & insert image', 'art.importDoc': '📤 Import local .docx',
    'art.publishBtn': 'Publish article', 'art.cancelEdit': 'Cancel edit',
    'art.tblTitle': 'Title', 'art.tblStatus': 'Status', 'art.tblFormat': 'Format',
    'art.tblViews': 'Views', 'art.tblTime': 'Time',
    'art.fmtRich': 'Rich text', 'art.noArticles': 'No articles', 'art.publishedBadge': 'Published',
    'tb.bold': 'Bold', 'tb.italic': 'Italic', 'tb.underline': 'Underline', 'tb.strike': 'Strikethrough',
    'tb.h2': 'Heading 2', 'tb.h3': 'Heading 3', 'tb.quote': 'Quote', 'tb.code': 'Code block',
    'tb.ul': 'Bullet list', 'tb.ol': 'Numbered list', 'tb.link': 'Link',
    'tb.image': 'Insert image (upload first, then paste link)', 'tb.clear': 'Clear formatting',
    'tb.size': 'Font size', 'tb.xs': 'XS', 'tb.sm': 'S', 'tb.md': 'Normal', 'tb.lg': 'L', 'tb.xl': 'XL', 'tb.xxl': 'XXL',
    'tb.color': 'Text color', 'tb.applyColor': '🎨 Apply',
    'md.ph': 'text', 'md.codePh': 'code', 'md.linkPh': 'link text', 'md.imagePh': 'alt text',
    'dlg.promptLink': 'Enter URL:', 'msg.imgInserted': 'Image inserted', 'msg.linkInserted': 'Image link inserted',
    'msg.mdImported': 'Markdown imported', 'msg.docImported': 'docx imported, remember to save',
    'msg.articlePublished': 'Article published',
    'img.title': 'Upload / Manage Images', 'img.pick': 'Choose image (jpg/png/gif/webp/avif, ≤8MB)',
    'img.fieldTitle': 'Title', 'img.fieldDesc': 'Description (shown under the gallery card)',
    'img.uploadBtn': 'Upload', 'msg.uploadOk': 'Uploaded', 'msg.uploadedRemember': 'Uploaded, remember to save',
    'img.tblPreview': 'Preview',
    'img.hidden': 'Hide (exclude from public gallery)', 'img.hiddenTip': 'For utility images like the sponsor QR: still manageable here, but hidden from the public gallery and search.', 'img.hiddenTag': 'Hidden', 'img.hide': 'Hide', 'img.show': 'Show', 'img.hiddenOk': 'Hidden from public gallery', 'img.shownOk': 'Visible again',
    'img.editTitle': 'Edit Image', 'img.editing': 'Editing: {title}', 'img.keepCurrent': 'Leave empty to keep current image',
    'prj.newTitle': 'Add / Manage Projects', 'prj.editTitle': 'Edit Project', 'prj.name': 'Project name',
    'prj.repo': 'GitHub repo URL (https://github.com/user/repo)', 'prj.desc': 'Description',
    'prj.tags': 'Tags (comma separated)', 'prj.addBtn': 'Add project', 'prj.cancelEdit': 'Cancel edit',
    'prj.tblName': 'Name', 'prj.noProjects': 'No projects',
    'prj.icon': 'Display icon', 'prj.iconPh': 'Pick an emoji as the project icon',
    'prj.homepage': 'Project homepage (optional, shown in About)', 'prj.homepagePh': 'https://example.com',
    'prj.homepageTip': 'You may omit https:// — e.g. just example.com',
    'prj.secRepo': 'Repository', 'prj.secAbout': 'About (display)', 'prj.topicsPh': 'Comma separated, e.g. minecraft,plugin,folia',
    'prj.preview': 'Front-end preview', 'prj.tip': 'After saving, the project page syncs the GitHub README, languages, contributors and releases automatically; downloads and file browsing stay on this site.',
    'project.back': 'Back to projects', 'project.detail': 'Details',
    'project.readmeTitle': 'About this project', 'project.readmeEmpty': "Couldn't fetch this project's GitHub README",
    'project.readmeLoading': 'Loading project intro from GitHub…',
    'detail.notFound': "This item doesn't exist or has been deleted",
    'gh.public': 'Public', 'gh.code': 'Code', 'gh.copy': 'Copy', 'gh.zip': 'Download ZIP',
    'gh.watch': 'Watch', 'gh.fork': 'Fork', 'gh.star': 'Star',
    'gh.tabCode': 'Code', 'gh.tabIssues': 'Issues', 'gh.tabPR': 'Pull requests',
    'gh.tabActions': 'Actions', 'gh.tabWiki': 'Wiki', 'gh.tabSecurity': 'Security', 'gh.tabInsights': 'Insights',
    'gh.loading': 'Loading…', 'gh.noCommit': 'No commit info', 'gh.noFiles': 'No files',
    'gh.metaUnavailable': 'GitHub data unavailable',
    'gh.about': 'About', 'gh.stars': 'stars', 'gh.forks': 'forks', 'gh.watching': 'watching',
    'gh.languages': 'Languages', 'gh.contributors': 'Contributors', 'gh.releases': 'Releases',
    'gh.siteActions': 'On this site',
    // The three big buttons now perform on-site actions: Star=favorite, Watch=like, Fork=download a copy
    'gh.starTip': 'Favorite this project on this site (Star)', 'gh.watchTip': 'Like this project on this site (Watch)', 'gh.forkTip': 'Download a source copy on this site (Fork)',
    'gh.starOn': 'Starred', 'gh.starOff': 'Star', 'gh.watchOn': 'Watching', 'gh.watchOff': 'Watch',
    'gh.ghStar': 'GitHub stars', 'gh.ghFork': 'GitHub forks', 'gh.ghWatch': 'GitHub watchers',
    'gh.openRepo': 'Visit repository', 'gh.downloading': 'Preparing archive…', 'gh.dlFail': 'Download failed, please retry later',
    'gh.fileUp': 'Parent directory', 'gh.fileDown': 'Download file', 'gh.fileBinary': 'Binary file — preview unavailable, download to view',
    'gh.fileEmpty': 'This file is empty', 'gh.browseFail': 'Failed to load, please retry later', 'gh.fileRoot': 'root',
    'gh.paneIssues': 'Discussions here', 'gh.paneIssuesTip': 'Comments left by you and other visitors on this site. To file a bug or feature request, use Issues on the original repository.',
    'gh.panePulls': 'Pull requests', 'gh.panePullsTip': 'This site does not host code, so pull requests cannot be opened here. Contribute on the original repository, or leave a comment under Issues first.',
    'gh.paneActions': 'Recent activity', 'gh.paneActionsTip': 'Synced from GitHub by this site periodically (refreshed every 6 hours).',
    'gh.paneWiki': 'Documentation', 'gh.paneWikiTip': 'Full README of the repository, fetched and rendered by this site.',
    'gh.paneSecurity': 'Security & license', 'gh.paneSecurityTip': 'This site has no vulnerability reporting channel. For security issues use the Security page of the original repository or contact the author.',
    'gh.paneInsights': 'Insights', 'gh.paneInsightsTip': 'Language breakdown and contributors are synced periodically.',
    'gh.releaseDl': 'Download this release', 'gh.noRelease': 'No releases yet', 'gh.noLicense': 'No license declared',
    'gh.noData': 'No data', 'gh.lastCommit': 'Latest commit', 'gh.closeFile': 'Close',
    'gh.cloneLab': 'Clone', 'gh.downloadLab': 'Download source', 'gh.tar': 'Download TAR.GZ', 'gh.preRelease': 'Pre-release',
    'gh.relLatest': 'Latest', 'gh.relAssets': 'Assets', 'gh.relDownload': 'Download',
    'gh.relTip': 'Releases from the GitHub repository — every download happens on this site, without leaving to GitHub.',
    'gh.relSourceZip': 'Source code (ZIP)', 'gh.relSourceTar': 'Source code (TAR.GZ)', 'gh.relViewAll': 'View all releases',
    'image.back': 'Back to gallery', 'image.untitled': 'Untitled image', 'image.zoom': '🔍 Zoom',
    'image.detail': 'Details & comments',
    'msg.prjUpdated': 'Project updated', 'msg.prjAdded': 'Project added',
    'cmt.delete': 'Delete', 'cmt.deleted': 'Comment deleted', 'cmt.adminTitle': 'Comments', 'cmt.tblContent': 'Content', 'cmt.tblTarget': 'Target',
    'cmt.visible': '✅ Visible', 'cmt.hidden': '🚫 Hidden',
    'cmt.hideBtn': 'Hide', 'cmt.restoreBtn': 'Restore',
    'sp.adminTitle': 'Record Sponsor', 'sp.sponsorName': 'Sponsor name',
    'sp.amount': 'Amount (CNY, optional)', 'sp.message': 'Message', 'sp.recordBtn': 'Record',
    'sp.tblName': 'Name', 'sp.tblAmount': 'Amount', 'sp.tblMessage': 'Message',
    'msg.recorded': 'Recorded',
    'soc.newTitle': 'Publish Moment', 'soc.editTitle': 'Edit Moment', 'soc.platform': 'Platform',
    'soc.fieldTitle': 'Title', 'soc.titlePh': 'Video / moment title', 'soc.url': 'URL (e.g. a Bilibili video)',
    'soc.desc': 'Description', 'soc.cover': 'Cover image (optional, a Bilibili screenshot looks better)',
    'soc.coverPh': 'Leave blank to show the platform icon', 'soc.uploadBtn': 'Upload',
    'soc.status': 'Status', 'soc.show': 'Visible (public)', 'soc.hide': 'Hidden',
    'soc.publishBtn': 'Publish moment', 'soc.cancelEdit': 'Cancel edit', 'soc.exist': 'Moments',
    'soc.tblPlatform': 'Platform', 'soc.badgeShow': 'Visible', 'soc.badgeHide': 'Hidden', 'empty.socialShort': 'No moments',
    'msg.coverUploaded': 'Cover uploaded', 'msg.socPublished': 'Moment published',
    'user.banTip': 'Once banned, all their sessions end immediately and they cannot sign in again. Deleting a user also removes their comments, likes and favorites. Leave the period blank for an immediate permanent ban, or set start/end for a timed ban.',
    'ban.title': 'Ban user', 'ban.titleEdit': 'Ban / Unban user',
    'ban.msgBanned': 'This user is currently banned. Adjust the period, or click Unban to restore access.',
    'ban.msgFree': 'Set a ban period for this user; their sessions will end immediately on confirm.',
    'ban.from': 'Start (optional, blank = immediately)', 'ban.to': 'End (optional, blank = permanent)',
    'ban.unban': 'Unban', 'ban.saveChange': 'Save', 'ban.confirmBan': 'Confirm ban',
    'ban.immediate': 'Immediately', 'ban.permanentSuffix': ' · permanent',
    'ban.permanent': 'Permanent',
    'admin.ipban': '🚫 IP Bans', 'admin.ipbanTitle': 'IP Bans', 'col.ip': 'IP Address',
    'user.banIp': 'Ban this IP',
    'ipban.title': 'Your IP has been banned',
    'ipban.desc': 'Your network address has been banned by the site owner. No account on this address can enter the site.',
    'ipban.yourIp': 'Your IP', 'ipban.until': 'Until', 'ipban.reason': 'Reason',
    'ipban.contact': 'If you believe this is a mistake, please contact the site owner.',
    'ipban.blockedToast': 'Your IP is banned, this action is not allowed',
    'ipban.dialogTitle': 'Ban IP', 'ipban.dialogMsg': 'After banning "{ip}", every account on this IP will be locked out.',
    'ipban.ip': 'IP Address', 'ipban.duration': 'Duration', 'ipban.reasonPh': 'Optional, e.g. comment spam',
    'ipban.selfTip': 'Note: you cannot ban the IP you are currently using, so you never lock yourself out.',
    'ipban.confirm': 'Ban this IP', 'ipban.banned': 'IP banned', 'ipban.needIp': 'Please enter an IP to ban',
    'ipban.h1': '1 hour', 'ipban.h6': '6 hours', 'ipban.d1': '1 day', 'ipban.d7': '7 days', 'ipban.d30': '30 days',
    'ipban.accounts': 'Accounts', 'ipban.viewAccounts': '{n} accounts', 'ipban.accountsOf': 'Accounts on "{ip}"',
    'ipban.noAccount': 'No account recorded on this IP yet',
    'ipban.unban': 'Unban', 'ipban.unbanTitle': 'Unban IP', 'ipban.unbanMsg': 'Unban "{ip}"?',
    'ipban.unbanned': 'IP unbanned', 'ipban.empty': 'No banned IP', 'ipban.expired': 'Expired',
    'ipban.tip': 'Banning an IP cuts off every account on that address (including logged-in sessions). Last login IP of each user is shown in the Users table.',
    'site.name': 'Site name (shown in the nav bar and browser title)', 'site.namePh': 'Moonlit Sea',
    'site.slogan': 'Subtitle', 'site.sloganPh': 'Xingya Station',
    'site.footer': 'Footer text', 'site.footerPh': 'Leave blank to use the default',
    'site.icp': 'ICP number (blank = no ICP info in footer)', 'site.icpPh': 'e.g. 京ICP备XXXXXXXX号',
    'site.qr': 'Sponsor QR image (shown on the Sponsor page)', 'site.qrPh': 'Leave blank to show a placeholder',
    'site.qrUpload': '⬆️ Upload QR', 'site.qrAlt': 'Current QR',
    'site.qrCurrent': 'Current QR · remember to save after re-uploading',
    'site.noQr': 'No QR yet — click "Upload QR" to pick an image (jpg/png/webp, ≤8MB)',
    'site.save': 'Save settings', 'msg.siteSaved': 'Settings saved and applied',
    'termsAdmin.title': 'Edit Terms of Service (Markdown supported)',
    'termsAdmin.tip': 'Edit directly then click "Save Terms", or load from the <code>terms.md</code> file below:',
    'termsAdmin.save': 'Save Terms', 'termsAdmin.importServer': 'Import from server terms.md',
    'termsAdmin.importLocal': 'Import a local file', 'termsAdmin.importing': 'Importing…',
    'msg.termsSaved': 'Terms saved',
    'msg.importedServer': 'Imported from server terms.md and applied ({n} chars)',
    'msg.importedLocal': 'Imported from "{name}" and applied ({n} chars)',
    'dlg.publishArticle': 'Publish Article', 'dlg.publishArticleMsg': 'Publish this new article? Visitors will see it right away.',
    'dlg.publishBtn': 'Publish', 'dlg.rethink': 'Not now',
    'dlg.delArticle': 'Delete Article', 'dlg.delArticleMsg': 'Delete this article? This cannot be undone.',
    'dlg.uploadImg': 'Upload Image', 'dlg.uploadImgMsg': 'Upload this image to the gallery?',
    'dlg.delImage': 'Delete Image', 'dlg.delImageMsg': 'Delete this image?',
    'dlg.addProject': 'Add Project', 'dlg.addProjectMsg': 'Add this new project to the public site?',
    'dlg.delProject': 'Delete Project', 'dlg.delProjectMsg': 'Delete this project?',
    'dlg.delComment': 'Delete Comment', 'dlg.delCommentMsg': 'Delete this comment?',
    'dlg.recordSponsor': 'Record Sponsor', 'dlg.recordSponsorMsg': 'Record this sponsor entry?',
    'dlg.delSponsor': 'Delete Sponsor', 'dlg.delSponsorMsg': 'Delete this sponsor entry?',
    'dlg.publishMoment': 'Publish Moment', 'dlg.publishMomentMsg': 'Publish this new moment publicly?',
    'dlg.delMoment': 'Delete Moment', 'dlg.delMomentMsg': 'Delete this moment?',
    'dlg.roleMsg': 'Change this user\'s role to "{role}"?', 'dlg.roleTitle': 'Change role', 'dlg.delUserTitle': 'Delete User',
    'dlg.delUserMsg': 'Delete this user? Their comments, likes and favorites will be removed and cannot be recovered.',
  },
};

const Lang = {
  get() {
    const l = localStorage.getItem('wo-lang');
    return I18N[l] ? l : 'zh';
  },
  apply(l) {
    if (!I18N[l]) l = 'zh';
    localStorage.setItem('wo-lang', l);
    document.documentElement.lang = l === 'en' ? 'en' : 'zh-CN';
    const btn = $('#lang-toggle');
    if (btn) {
      btn.textContent = l === 'en' ? '中' : 'EN';
      btn.title = l === 'en' ? '切换为中文 / Switch to Chinese' : '切换为英文 / Switch to English';
      btn.setAttribute('aria-label', btn.title);
    }
    applyStaticI18n();
  },
  // 切换语言：更新静态文案并重新渲染当前视图与用户菜单
  toggle() {
    this.apply(this.get() === 'en' ? 'zh' : 'en');
    if (typeof renderRoute === 'function') renderRoute();
    if (typeof Auth !== 'undefined' && Auth.renderChip) Auth.renderChip();
  },
};

function t(key, vars) {
  const cur = I18N[Lang.get()] || I18N.zh;
  let s = cur[key];
  if (s == null) s = I18N.zh[key];
  if (s == null) return key;
  if (vars) s = String(s).replace(/\{(\w+)\}/g, (_, k) => (vars[k] != null ? vars[k] : ''));
  return s;
}

// 把 data-i18n 系列属性应用到静态 DOM（导航、页脚等写在 index.html 里的文案）
function applyStaticI18n() {
  // 站点名为动态配置：支持 {site} 插值（如条款弹窗标题），取不到时用当前语言的默认站名
  let site = '';
  try { site = (Site && Site.data && Site.data.site_name) || ''; } catch (_) {}
  if (!site) site = Lang.get() === 'en' ? 'Moonlit Sea' : '月之海';
  const vars = { site };
  $$('[data-i18n]').forEach((n) => { n.textContent = t(n.dataset.i18n, vars); });
  $$('[data-i18n-title]').forEach((n) => { n.title = t(n.dataset.i18nTitle); });
  $$('[data-i18n-ph]').forEach((n) => { n.placeholder = t(n.dataset.i18nPh); });
  $$('[data-i18n-aria]').forEach((n) => { n.setAttribute('aria-label', t(n.dataset.i18nAria)); });
}

// 默认头像：按用户名生成渐变字母 SVG
function avatarSvg(name) {
  const n = String(name || '月');
  const letter = n.slice(0, 1).toUpperCase();
  let h = 0;
  for (const c of n) h = (h * 31 + c.charCodeAt(0)) % 360;
  const svg = `<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 64 64'>`
    + `<defs><linearGradient id='g' x1='0' y1='0' x2='1' y2='1'>`
    + `<stop offset='0' stop-color='hsl(${h},72%,64%)'/><stop offset='1' stop-color='hsl(${(h + 60) % 360},72%,56%)'/>`
    + `</linearGradient></defs>`
    + `<rect width='64' height='64' rx='32' fill='url(#g)'/>`
    + `<text x='32' y='43' font-size='28' text-anchor='middle' fill='#fff' font-family='sans-serif' font-weight='600'>${letter}</text></svg>`;
  return 'data:image/svg+xml,' + encodeURIComponent(svg);
}

// ---------- 登录态 ----------
const Auth = {
  user: null,
  unread: 0,          // 站内消息未读数（头像红点 / 菜单红点共用）
  _unreadInit: false, // 首次拉取仅设基线，不弹提示
  async refresh() {
    try { this.user = (await api('/auth/me')).user; } catch (_) { this.user = null; }
    this.renderChip();
    this.refreshUnread();
  },
  // 只拉一个数字，供轮询使用；数量变多时给一条轻提示
  async refreshUnread() {
    if (!this.user) { this.unread = 0; this._unreadInit = false; return this.renderUnread(); }
    try {
      const n = (await api('/notifications/unread')).unread || 0;
      if (this._unreadInit && n > this.unread) toast(t('notif.newMsg', { n: n - this.unread }));
      this.unread = n;
      this._unreadInit = true;
    } catch (_) { /* 静默：轮询失败不影响页面 */ }
    return this.renderUnread();
  },
  // 红点就地更新（不重绘整个菜单，避免把已展开的下拉菜单收起来）
  renderUnread() {
    const n = this.unread || 0;
    const dot = document.querySelector('#user-chip .av-dot');
    const badge = document.querySelector('#user-chip .um-badge');
    const label = n > 99 ? '99+' : String(n);
    [dot, badge].forEach((el) => {
      if (!el) return;
      el.textContent = label;
      el.hidden = n <= 0;
      if (el === dot) el.title = t('notif.unreadTip', { n });
    });
  },
  avatarUrl() {
    if (this.user && this.user.avatar) {
      const a = this.user.avatar;
      const url = a.startsWith('/uploads/') ? a : '/uploads/' + a;
      return url + (this._avT ? '?t=' + this._avT : '');
    }
    return avatarSvg(this.user && this.user.username);
  },
  renderChip() {
    const chip = $('#user-chip');
    if (this.user) {
      const u = this.user;
      const isAdmin = u.role === 'admin';
      chip.innerHTML = `
        <div class="user-wrap">
          <span class="av-wrap">
            <img class="avatar" src="${this.avatarUrl()}" alt="${t('avatar.alt')}">
            <span class="av-dot" hidden></span>
          </span>
          <span class="uname">${esc(u.username)}${isAdmin ? t('menu.adminBadge') : ''}</span>
          <div class="user-menu">
            <div class="um-head">
              <img class="avatar" src="${this.avatarUrl()}" alt="">
              <div><b>${esc(u.username)}</b><span>${isAdmin ? t('role.admin') : t('role.user')}</span></div>
            </div>
            <div class="um-group">${t('menu.groupMe')}</div>
            <a href="#/user/${u.id}">${t('menu.profile')}</a>
            <a href="#/settings">${t('menu.settings')}</a>
            <a href="#/favorites">${t('menu.favorites')}</a>
            <a href="#/notifications" class="um-notif">${t('menu.notifications')}<span class="um-badge" hidden></span></a>
            <div class="um-sep"></div>
            <div class="um-group">${t('menu.groupCommunity')}</div>
            <div class="um-sub" id="um-community">
              <button type="button" class="um-sub-toggle">${t('menu.community')} <span class="um-caret">▶</span></button>
              <div class="um-sub-list">
                <a href="#/checkin">${t('menu.checkin')}</a>
                <a href="#/tasks">${t('menu.tasks')}</a>
                <a href="#/achievements">${t('menu.achievements')}</a>
                <a href="#/redeem">${t('menu.redeem')}</a>
              </div>
            </div>
            <div class="um-sep"></div>
            ${isAdmin ? `<a href="#/admin" data-i18n="nav.admin">${t('nav.admin')}</a><div class="um-sep"></div>` : ''}
            <a href="#" id="logout-btn">${t('menu.logout')}</a>
          </div>
        </div>`;
      const wrap = chip.querySelector('.user-wrap');
      // 触屏无 hover：点按头像切换菜单显隐（桌面端 hover 仍可用，二者互补）
      wrap.addEventListener('click', (e) => {
        e.stopPropagation();
        wrap.classList.toggle('open');
      });
      // 点击菜单内任意项先收起菜单
      chip.querySelectorAll('.user-menu a').forEach(a => a.addEventListener('click', () => wrap.classList.remove('open')));
      // 分级子菜单：点按展开/收起（不依赖 hover，移动端同样可用）
      const umSub = chip.querySelector('#um-community');
      if (umSub) {
        umSub.querySelector('.um-sub-toggle').addEventListener('click', (e) => {
          e.preventDefault();
          e.stopPropagation();
          umSub.classList.toggle('open');
        });
      }
      $('#logout-btn').onclick = (e) => { e.preventDefault(); e.stopPropagation(); wrap.classList.remove('open'); confirmLogout(); };
      this.renderUnread();
    } else {
      chip.innerHTML = `<a href="#/login" class="btn btn-primary btn-sm">${t('chip.loginRegister')}</a>`;
    }
  },
};

// 统一登出：清退服务器端 Cookie（双清退 Secure/非Secure）、清本地存储、本地立即置空、跳登录页
async function doLogout() {
  try { await api('/auth/logout', { method: 'POST' }); } catch (_) { /* 接口异常也继续本地登出，不让用户卡住 */ }
  localStorage.removeItem('wo-login');
  localStorage.removeItem('wo-autologin');
  Auth.user = null;            // 立即在本地置为登出并刷新导航，不等网络往返
  Auth.renderChip();
  try { await Auth.refresh(); } catch (_) {}  // 与服务器最终态对齐（Cookie 已清则应返回 null）
  toast(t('msg.loggedOut'));
  location.hash = '#/login';
  renderRoute();
}

// ---------- 站点设置（后台可改，全站生效） ----------
const Site = {
  data: {},
  async load() {
    try { this.data = await api('/settings'); } catch (_) { this.data = {}; }
    this.apply();
    // 站点名是异步拿到的：拿到后刷新静态文案（条款弹窗标题含 {site} 插值）
    applyStaticI18n();
  },
  apply() {
    const d = this.data || {};
    if (d.site_name) {
      const el = $('#site-name');
      if (el) el.textContent = d.site_name;
      document.title = d.site_slogan ? `${d.site_name} · ${d.site_slogan}` : d.site_name;
    }
    if (d.footer_text) {
      const el = $('#footer-text');
      // 站长自定义了页脚文案：移除翻译标记，避免切换语言时被默认文案覆盖
      if (el) { el.removeAttribute('data-i18n'); el.textContent = d.footer_text; }
    }
    const icp = $('#footer-icp');
    if (icp) {
      if (d.icp) {
        icp.innerHTML = `<a href="https://beian.miit.gov.cn/" target="_blank" rel="noopener noreferrer">${esc(d.icp)}</a>`;
        icp.hidden = false;
      } else {
        icp.hidden = true;
        icp.innerHTML = '';
      }
    }
  },
};

// ---------- 条款弹窗（全站唯一入口，无独立条款页） ----------
// 认证相关路由（登录 / 注册 / 找回密码）
function onAuthRoute() {
  const first = (location.hash || '').replace(/^#\//, '').split('/')[0];
  return ['login', 'register', 'forgot'].includes(first);
}

// ---------- 服务条款（首次访问拦截 / 随时查看） ----------
const Terms = {
  agreed() { return localStorage.getItem('wo-terms-ok') === '1'; },
  // mode: 'gate' = 首次访问拦截（不同意则无法使用）；'view' = 注册/登录页随手查看
  async show(mode = 'view') {
    let content = '';
    try { content = (await api('/terms')).content; } catch (_) {}
    const bodyEl = $('#terms-modal-body');
    // 条款正文由接口填充：移除翻译标记，避免切换语言时被「加载中…」覆盖
    bodyEl.removeAttribute('data-i18n');
    bodyEl.innerHTML = content
      ? renderMD(content)
      : t('terms.empty');
    const actions = $('#terms-modal-actions');
    if (mode === 'gate') {
      actions.innerHTML = `
        <button id="terms-decline" class="btn btn-ghost">${t('terms.decline')}</button>
        <button id="terms-accept" class="btn btn-primary">${t('terms.accept')}</button>`;
      $('#terms-accept').onclick = () => Terms.accept();
      $('#terms-decline').onclick = () => {
        $('#terms-modal-body').innerHTML = t('terms.gateMsg');
        $('#terms-modal-actions').innerHTML = `<button id="terms-rethink" class="btn btn-primary">${t('terms.rethink')}</button>`;
        $('#terms-rethink').onclick = () => Terms.show('gate');
      };
    } else {
      actions.innerHTML = `<button id="terms-close" class="btn btn-primary">${t('common.close')}</button>`;
      $('#terms-close').onclick = () => $('#terms-modal').classList.add('hidden');
    }
    $('#terms-modal').classList.remove('hidden');
  },
  async maybeShow() {
    if (this.agreed()) return;
    // 认证页（登录/注册/找回）自带「同意条款」勾选项，且拦截层会整块盖住表单，
    // 连图形验证码的刷新都点不动——这些页面一律不弹拦截层，等进入其它页面再提示。
    if (onAuthRoute()) return;
    await this.show('gate');
  },
  async accept() {
    localStorage.setItem('wo-terms-ok', '1');
    $('#terms-modal').classList.add('hidden');
    try { await api('/consent', { method: 'POST' }); } catch (_) {}
    toast(t('terms.thanks'));
  },
};

// ---------- 通用自定义弹窗（风格与服务条款弹窗一致，移动端自适应） ----------
function openModal({ title, bodyHtml, actions = [], allowBackdrop = true }) {
  const mask = document.createElement('div');
  mask.className = 'modal-mask';
  mask.innerHTML = `
    <div class="modal card" role="dialog" aria-modal="true">
      <h2>${esc(title)}</h2>
      <div class="modal-body">${bodyHtml}</div>
      <div class="modal-actions"></div>
    </div>`;
  document.body.appendChild(mask);
  const actionsEl = mask.querySelector('.modal-actions');
  let closed = false;
  function close() {
    if (closed) return; closed = true;
    document.removeEventListener('keydown', onKey);
    mask.remove();
  }
  const onKey = (e) => { if (e.key === 'Escape') close(); };
  document.addEventListener('keydown', onKey);
  actions.forEach((a) => {
    const btn = document.createElement('button');
    btn.className = 'btn ' + (a.cls || 'btn-ghost') + ' btn-sm';
    btn.textContent = a.label;
    btn.onclick = () => a.onClick && a.onClick(close);
    actionsEl.appendChild(btn);
  });
  if (allowBackdrop) mask.addEventListener('click', (e) => { if (e.target === mask) close(); });
  return { mask, close };
}

// 确认弹窗：返回 Promise<boolean>
function confirmDialog({ title = t('dlg.confirmTitle'), message = '', confirmText = t('common.confirm'), cancelText = t('common.cancel'), danger = false } = {}) {
  return new Promise((resolve) => {
    openModal({
      title,
      bodyHtml: `<p>${message}</p>`,
      actions: [
        { label: cancelText, cls: 'btn-ghost', onClick: (close) => { close(); resolve(false); } },
        { label: confirmText, cls: danger ? 'btn-danger' : 'btn-primary', onClick: (close) => { close(); resolve(true); } },
      ],
    });
  });
}

// ---------- 公告弹窗（登录后：新用户 / 久未登录用户 / 有未读置顶公告时弹出） ----------
function showAnnouncementsPopup(items) {
  if (!Array.isArray(items) || !items.length) return;
  const body = items.map((a) => `
    <div class="ann-pop">
      <div class="ann-pop-head">
        <span class="ann-tag ann-tag-${esc(a.tag)}">${esc(annTagLabel(a.tag))}</span>
        <b class="ann-pop-title">${esc(a.title)}</b>
        <span class="gh-time">${esc(fmtTime(a.created_at))}</span>
      </div>
      ${a.content ? `<div class="md ann-pop-body">${renderMD(a.content)}</div>` : ''}
    </div>`).join('');
  openModal({
    title: t('ann.popup.title'),
    bodyHtml: body,
    actions: [
      { label: t('ann.popup.gotIt'), cls: 'btn-primary', onClick: async (close) => { close(); await api('/announcements/read', { method: 'POST' }).catch(() => {}); } },
    ],
  });
}

async function checkAnnouncements() {
  if (!Auth.user) return;
  try {
    const r = await api('/announcements/popup');
    if (r && r.items && r.items.length) showAnnouncementsPopup(r.items);
  } catch (_) { /* 接口不可用时静默跳过，不打断用户 */ }
}

// 后台统一删除流程：
// 确认 → 先把按钮所在行从 DOM 摘掉（给即时反馈，不必等重渲染）→ 调接口 → 重渲染。
// 之前只做 renderRoute()：若列表接口被反代缓存回吐旧数据，界面就会表现为"删了却还在"。
// onCleared：删除成功后要清掉的本地状态（如正在编辑的那条）。
async function adminDelete(btn, { url, title, message, onCleared } = {}) {
  if (!(await confirmDialog({ title, message, confirmText: t('common.delete'), cancelText: t('common.cancel'), danger: true }))) return;
  const row = btn.closest('tr') || btn.closest('li') || btn.closest('.card') || btn.closest('[data-del-item]');
  btn.disabled = true;
  if (row) row.style.opacity = '.4';
  try {
    const data = await api(url, { method: 'DELETE' });
    if (onCleared) onCleared();
    if (row) row.remove();
    toast(t('msg.deleted'));
    // 后端明确返回 0 行受影响：说明记录本就不存在（或接口没生效），提示而不是静默
    if (data && typeof data.deleted === 'number' && data.deleted === 0) toast(t('msg.delNoEffect'));
    renderRoute();
  } catch (err) {
    btn.disabled = false;
    if (row) row.style.opacity = '';
    toast(err.message);
    renderRoute();
  }
}

// 封禁用户弹窗：可设置起/终时间（留空“至”=永久），已封禁时额外提供「解封」
function banDialog(user) {
  return new Promise((resolve) => {
    const isBanned = !!user.banned;
    const toLocalInput = (ts) => {
      if (!ts) return '';
      const d = new Date(ts - new Date().getTimezoneOffset() * 60000);
      return d.toISOString().slice(0, 16);
    };
    const body = `
      <p>${isBanned ? t('ban.msgBanned') : t('ban.msgFree')}</p>
      <div class="field"><label>${t('ban.from')}</label><input type="datetime-local" id="ban-from" value="${toLocalInput(user.banned_from)}"></div>
      <div class="field"><label>${t('ban.to')}</label><input type="datetime-local" id="ban-to" value="${toLocalInput(user.banned_until)}"></div>`;
    const actions = [
      { label: t('common.cancel'), cls: 'btn-ghost', onClick: (close) => { close(); resolve(null); } },
    ];
    if (isBanned) actions.push({ label: t('ban.unban'), cls: 'btn-primary', onClick: (close) => { close(); resolve({ banned: false }); } });
    actions.push({
      label: isBanned ? t('ban.saveChange') : t('ban.confirmBan'), cls: 'btn-danger',
      onClick: (close) => {
        const fromV = m.mask.querySelector('#ban-from').value;
        const toV = m.mask.querySelector('#ban-to').value;
        close();
        resolve({
          banned: true,
          banned_from: fromV ? new Date(fromV).getTime() : null,
          banned_until: toV ? new Date(toV).getTime() : null,
        });
      },
    });
    const m = openModal({ title: isBanned ? t('ban.titleEdit') : t('ban.title'), bodyHtml: body, actions });
  });
}

// IP 封禁弹窗：选时长 + 填原因，封禁后该 IP 下所有账号都无法进入
function ipBanDialog(ip) {
  return new Promise((resolve) => {
    const opts = [
      { v: 1, label: t('ipban.h1') }, { v: 6, label: t('ipban.h6') },
      { v: 24, label: t('ipban.d1') }, { v: 168, label: t('ipban.d7') },
      { v: 720, label: t('ipban.d30') }, { v: 0, label: t('ban.permanent') },
    ];
    const body = `
      <p>${esc(t('ipban.dialogMsg', { ip: ip || '' }))}</p>
      <div class="field"><label>${t('ipban.ip')}</label><input id="ipb-ip" value="${esc(ip || '')}" placeholder="1.2.3.4" maxlength="64"></div>
      <div class="field"><label>${t('ipban.duration')}</label>
        <select id="ipb-dur">${opts.map((o) => `<option value="${o.v}">${esc(o.label)}</option>`).join('')}</select>
      </div>
      <div class="field"><label>${t('ipban.reason')}</label><input id="ipb-reason" maxlength="200" placeholder="${esc(t('ipban.reasonPh'))}"></div>
      <p class="form-tip">${esc(t('ipban.selfTip'))}</p>`;
    const m = openModal({
      title: t('ipban.dialogTitle'),
      bodyHtml: body,
      actions: [
        { label: t('common.cancel'), cls: 'btn-ghost', onClick: (close) => { close(); resolve(null); } },
        {
          label: t('ipban.confirm'), cls: 'btn-danger',
          onClick: (close) => {
            const val = m.mask.querySelector('#ipb-ip').value.trim();
            const hours = parseInt(m.mask.querySelector('#ipb-dur').value, 10) || 0;
            const reason = m.mask.querySelector('#ipb-reason').value.trim();
            close();
            resolve({ ip: val, hours, reason, until: hours > 0 ? Date.now() + hours * 3600 * 1000 : null });
          },
        },
      ],
    });
  });
}

// 退出登录确认（自定义弹窗，不再用浏览器默认 confirm）
function confirmLogout() {
  confirmDialog({ title: t('logout.title'), message: t('logout.msg'), confirmText: t('logout.ok'), cancelText: t('logout.cancel') })
    .then((ok) => { if (ok) doLogout(); });
}

// ---------- 图库灯箱（点击放大：带关闭按钮、左右切换、Esc / 点空白关闭） ----------
const Lightbox = {
  _items: [], _idx: 0, _el: null, _keyHandler: null,

  // 首次使用时创建 DOM（关闭后保留复用）
  _ensure() {
    if (this._el) return this._el;
    const el = document.createElement('div');
    el.className = 'lightbox';
    el.setAttribute('role', 'dialog');
    el.setAttribute('aria-modal', 'true');
    el.innerHTML = `
      <button class="lb-close" type="button">✕</button>
      <button class="lb-nav lb-prev" type="button">‹</button>
      <button class="lb-nav lb-next" type="button">›</button>
      <button class="lb-fav" type="button" hidden>⭐</button>
      <figure class="lb-figure">
        <img class="lb-img" alt="">
        <figcaption class="lb-cap"><b class="lb-title"></b><span class="lb-desc"></span></figcaption>
      </figure>
      <div class="lb-counter"></div>`;
    // 关闭：✕ 按钮；点击图片以外的空白区域也关闭
    $('.lb-close', el).addEventListener('click', () => this.close());
    el.addEventListener('click', (e) => { if (e.target === el) this.close(); });
    $('.lb-prev', el).addEventListener('click', (e) => { e.stopPropagation(); this.prev(); });
    $('.lb-next', el).addEventListener('click', (e) => { e.stopPropagation(); this.next(); });
    // 收藏当前图片（仅登录用户可见）
    $('.lb-fav', el).addEventListener('click', (e) => { e.stopPropagation(); this.toggleFav(); });
    this._el = el;
    return el;
  },

  open(items, idx = 0) {
    this._items = Array.isArray(items) ? items : [];
    if (!this._items.length) return;
    this._idx = Math.max(0, Math.min(idx, this._items.length - 1));
    const el = this._ensure();
    document.body.appendChild(el);
    document.body.classList.add('lb-open');
    this._keyHandler = (e) => {
      if (e.key === 'Escape') this.close();
      else if (e.key === 'ArrowLeft') this.prev();
      else if (e.key === 'ArrowRight') this.next();
    };
    document.addEventListener('keydown', this._keyHandler);
    this._render();
    requestAnimationFrame(() => el.classList.add('show'));
  },

  _render() {
    const el = this._el;
    if (!el) return;
    const im = this._items[this._idx];
    const img = $('.lb-img', el);
    img.src = `/uploads/${im.filename}`;
    img.alt = im.title || '';
    $('.lb-title', el).textContent = im.title || '';
    const desc = $('.lb-desc', el);
    desc.textContent = im.description || '';
    desc.hidden = !im.description;
    const multi = this._items.length > 1;
    $('.lb-prev', el).hidden = !multi;
    $('.lb-next', el).hidden = !multi;
    $('.lb-counter', el).textContent = multi ? `${this._idx + 1} / ${this._items.length}` : '';
    // 提示文案跟随当前语言
    const closeBtn = $('.lb-close', el);
    closeBtn.title = t('lightbox.close');
    closeBtn.setAttribute('aria-label', t('lightbox.close'));
    $('.lb-prev', el).title = t('lightbox.prev');
    $('.lb-next', el).title = t('lightbox.next');
    $('.lb-prev', el).setAttribute('aria-label', t('lightbox.prev'));
    $('.lb-next', el).setAttribute('aria-label', t('lightbox.next'));
    // 收藏按钮：仅登录用户展示，并同步当前图片的收藏状态
    const favBtn = $('.lb-fav', el);
    favBtn.hidden = !Auth.user;
    if (Auth.user) this._syncFav(favBtn);
  },

  // 查询当前图片是否已收藏（异步，结果回来时若已切图则忽略）
  async _syncFav(btn) {
    const im = this._items[this._idx];
    if (!im) return;
    const token = `${im.id}:${this._idx}`;
    btn.classList.remove('active');
    btn.title = t('action.fav');
    try {
      const st = await api(`/mystate/image/${im.id}`);
      if (token !== `${this._items[this._idx] && this._items[this._idx].id}:${this._idx}`) return;
      btn.classList.toggle('active', !!st.favorited);
      btn.title = st.favorited ? t('fav.remove') : t('action.fav');
    } catch (_) {}
  },

  // 切换当前图片的收藏状态
  async toggleFav() {
    if (!Auth.user) { toast(t('auth.needLogin')); return; }
    const im = this._items[this._idx];
    if (!im) return;
    const btn = $('.lb-fav', this._el);
    try {
      const r = await api(`/favorites/image/${im.id}`, { method: 'POST' });
      if (btn) {
        btn.classList.toggle('active', !!r.favorited);
        btn.title = r.favorited ? t('fav.remove') : t('action.fav');
      }
      toast(r.favorited ? t('fav.added') : t('fav.removed'));
    } catch (e) { toast(e.message); }
  },

  prev() {
    if (this._items.length < 2) return;
    this._idx = (this._idx - 1 + this._items.length) % this._items.length;
    this._render();
  },
  next() {
    if (this._items.length < 2) return;
    this._idx = (this._idx + 1) % this._items.length;
    this._render();
  },

  close() {
    const el = this._el;
    if (!el) return;
    el.classList.remove('show');
    if (this._keyHandler) { document.removeEventListener('keydown', this._keyHandler); this._keyHandler = null; }
    document.body.classList.remove('lb-open');
    setTimeout(() => { if (el.parentNode) el.remove(); }, 180);
  },
};

// 把 GitHub 元数据填充进已渲染的项目详情页骨架（渐进增强：拿不到数据也不影响其余区块）
function fillGithubMeta(el, m, p) {
  const url = m.html_url || p.repo_url;
  // 标题：owner/repo（保留外链，这是全页唯一允许跳 GitHub 的入口之一）
  const titleEl = $('#gh-title', el);
  if (titleEl) {
    // 标题保持纯文本：全页唯一允许跳 GitHub 的入口是「前往原仓库」按钮
    titleEl.innerHTML = `<span>${esc(m.owner)}</span>`
      + `<span class="gh-slash">/</span>`
      + `<b>${esc(m.name)}</b>`;
  }
  // 描述 / 话题（GitHub 的优先于后台手填的）
  const descEl = $('#gh-desc', el);
  if (descEl) descEl.textContent = m.description || p.description || '';
  const topicsEl = $('#gh-topics', el);
  const topics = (m.topics && m.topics.length) ? m.topics : (p.tags || '').split(',').filter(Boolean).map((s) => s.trim());
  if (topicsEl) topicsEl.innerHTML = topics.map((x) => `<span class="gh-topic">${esc(x)}</span>`).join('');

  // GitHub 真实计数只做「展示」：放在标题下与 About 侧栏，不再做成跳转链接
  const setCount = (key, val) => { $$(`[data-cnt="${key}"]`, el).forEach((n) => { n.textContent = fmtCount(val); }); };
  setCount('stargazers', m.stargazers); setCount('forks', m.forks);
  setCount('watchers', m.watchers); setCount('open_issues', m.open_issues);

  // 站内下载源码：走本站代理接口（同域、带 Content-Disposition），绝不把访客送到 github.com
  const br = m.default_branch || 'main';
  const setDl = (sel, extra) => { const n = $(sel, el); if (n) n.href = `/api/projects/${p.id}/download?ref=${encodeURIComponent(br)}${extra || ''}`; };
  setDl('#gh-zip', '');
  setDl('#gh-tar', '&format=tar');

  // 发行版本：把最近几个 tag 直接列在 Code 下拉里，逐个可站内下载
  const relList = $('#gh-rel-list', el);
  const relLab = $('#gh-rel-lab', el);
  if (relList && relLab) {
    const rows = ghReleaseList(m, p, 5);
    if (rows) {
      relList.innerHTML = rows + `<a class="gh-rel-viewall" href="#/project/${p.id}?tab=releases">${esc(t('gh.relViewAll'))} →</a>`;
      relList.hidden = false; relLab.hidden = false;
    }
    else { relList.hidden = true; relLab.hidden = true; }
  }

  const cloneInput = $('#gh-clone-url', el);
  if (cloneInput) cloneInput.value = `${url}.git`;
  const branchEl = $('#gh-branch', el);
  if (branchEl) branchEl.textContent = m.default_branch || 'main';

  // 最近提交
  const commitEl = $('#gh-commit', el);
  if (commitEl) {
    const c = m.last_commit;
    if (c && c.message) {
      commitEl.innerHTML = `<b>${esc(c.author || '')}</b> ${esc(c.message)}`
        + (c.date ? ` <span class="gh-time">· ${esc(relTime(c.date))}</span>` : '');
    } else commitEl.textContent = t('gh.noCommit');
  }

  // 文件列表：改成站内可点按钮（点击走 /api/projects/:id/files，在页面内浏览，不跳 GitHub）
  const filesEl = $('#gh-files', el);
  if (filesEl && window.__ghBrowse) window.__ghBrowse('');

  // 右侧 About 侧栏
  const side = $('#gh-side', el);
  if (side) side.innerHTML = buildGhSide(m, p);

  // 「最近动态 / 安全 / 统计概览」三个标签页的内容也在这里补齐
  const act = $('#pane-actions', el);
  if (act) act.innerHTML = buildGhActivity(m, p);
  const sec = $('#pane-security', el);
  if (sec) sec.innerHTML = buildGhSecurity(m);
  const ins = $('#pane-insights', el);
  if (ins) ins.innerHTML = (ghLangBlock(m) + ghContribBlock(m)) || `<div class="gh-empty">${esc(t('gh.noData'))}</div>`;

  // 「发行版」标签页：完整 GitHub 风格列表（资产逐个站内下载 + 源码包）
  const relPane = $('#pane-releases', el);
  if (relPane) relPane.innerHTML = buildReleasesPane(m, p);
  const relCount = $('#gh-rel-count', el);
  if (relCount) {
    const n = Array.isArray(m.releases) ? m.releases.length : 0;
    relCount.textContent = n;
    relCount.hidden = !n;
  }

  // 侧栏 / Code 下拉的「查看全部发行版」：切到 Releases 标签页（站内，不重新加载整页）
  $$('.gh-rel-viewall', el).forEach((b) => b.addEventListener('click', (e) => {
    e.preventDefault();
    const menu = $('#gh-code-menu', el);
    if (menu) menu.hidden = true;
    const t = $$('.gh-tab', el).find((x) => x.dataset.tab === 'releases');
    if (t) t.click();
  }));
}

// 语言构成块（About 侧栏与「统计概览」标签页共用）
function ghLangBlock(m) {
  const entries = m.languages ? Object.entries(m.languages) : [];
  if (!entries.length) return '';
  const total = entries.reduce((a, b) => a + b[1], 0);
  const sorted = entries.sort((a, b) => b[1] - a[1]);
  const bar = total
    ? `<div class="gh-lang-bar">${sorted.map(([n, v]) => `<span style="width:${(v / total * 100).toFixed(2)}%;background:${esc(langColor(n))}" title="${esc(n)} ${(v / total * 100).toFixed(1)}%"></span>`).join('')}</div>`
    : '';
  const list = sorted.slice(0, 8).map(([n, v]) => (
    `<li><span class="gh-dot" style="background:${esc(langColor(n))}"></span><b>${esc(n)}</b>`
    + `<span class="gh-lang-pct">${total ? (v / total * 100).toFixed(1) : '0'}%</span></li>`
  )).join('');
  return `<div class="gh-side-block"><h3>${esc(t('gh.languages'))}</h3>${bar}<ul class="gh-lang-list">${list}</ul></div>`;
}

// 贡献者块：头像不再链到 github.com 个人页（除"前往原仓库"外一律不跳 GitHub），改成纯展示
function ghContribBlock(m) {
  if (!m.contributors || !m.contributors.length) return '';
  return `<div class="gh-side-block"><h3>${esc(t('gh.contributors'))}</h3>
    <div class="gh-contribs">${m.contributors.slice(0, 12).map((c) => (
      `<span title="${esc(c.login)} · ${c.contributions}" class="gh-contrib">`
      + `<img src="${esc(c.avatar_url)}" alt="${esc(c.login)}" loading="lazy"></span>`
    )).join('')}</div></div>`;
}

// 发布版本块：下载按钮走站内代理（按 tag 拉归档），不再链到 GitHub Release 页
// 发行版本列表（最多 n 个）：每个版本都能在站内直接下载对应 tag 的源码包
function ghReleaseList(m, p, n) {
  const list = Array.isArray(m.releases) && m.releases.length
    ? m.releases
    : (m.release ? [m.release] : []);
  if (!list.length) return '';
  return list.slice(0, n || 5).map((r) => {
    const href = `/api/projects/${p.id}/download?ref=${encodeURIComponent(r.tag)}`;
    return `<div class="gh-release">
      <span class="gh-tag">🏷 ${esc(r.tag)}${r.prerelease ? ` <span class="gh-pre">${esc(t('gh.preRelease'))}</span>` : ''}</span>
      <span class="gh-time">${esc(relTime(r.published_at))}</span>
      <a class="btn btn-ghost btn-sm" href="${esc(href)}" download>⬇ ${esc(t('gh.releaseDl'))}</a>
    </div>`;
  }).join('');
}

function ghReleaseBlock(m, p) {
  const rows = ghReleaseList(m, p, 3);
  if (!rows) return '';
  return `<div class="gh-side-block"><h3>${esc(t('gh.releases'))}</h3>${rows}<a class="gh-side-link gh-rel-viewall" href="#/project/${p.id}?tab=releases">${esc(t('gh.relViewAll'))} →</a></div>`;
}

// GitHub 风格「发行版」完整页：每个版本展示 标题 / 作者 / 时间 / 发布说明(markdown) /
// 资产列表(.jar/.zip 等，逐个站内下载) / 源码包(ZIP/TAR)。下载全走本站代理，不跳 GitHub。
function buildReleasesPane(m, p) {
  const list = Array.isArray(m.releases) && m.releases.length
    ? m.releases
    : (m.release ? [{ ...m.release, body: '', author: null, assets: [] }] : []);
  if (!list.length) return `<div class="gh-pane-inner"><div class="gh-empty">${esc(t('gh.noRelease'))}</div></div>`;

  const zip = (r) => `/api/projects/${p.id}/download?ref=${encodeURIComponent(r.tag)}`;
  const tar = (r) => `/api/projects/${p.id}/download?ref=${encodeURIComponent(r.tag)}&format=tar`;
  const latestTag = (m.release && m.release.tag) || '';

  const assetsHtml = (r) => {
    const as = Array.isArray(r.assets) ? r.assets : [];
    if (!as.length) return '';
    return `<div class="gh-rel-assets">
      <div class="gh-rel-assets-h">📦 ${esc(t('gh.relAssets'))}</div>
      ${as.map((a) => `
        <div class="gh-rel-asset">
          <span class="gh-rel-asset-ico">📦</span>
          <span class="gh-rel-asset-name" title="${esc(a.name)}">${esc(a.name)}</span>
          <span class="gh-rel-asset-meta">${esc(fmtBytes(a.size))}${a.download_count ? ' · ⬇ ' + esc(fmtCount(a.download_count)) : ''}</span>
          <a class="btn btn-primary btn-sm" href="/api/projects/${p.id}/releases/download?asset_id=${a.id}&name=${encodeURIComponent(a.name)}" download>${esc(t('gh.relDownload'))}</a>
        </div>`).join('')}
    </div>`;
  };

  return `<div class="gh-pane-inner gh-releases">
    <div class="gh-rel-head">
      <div class="gh-rel-head-title">🏷 ${esc(t('gh.releases'))}</div>
      <div class="gh-rel-head-tip">${esc(t('gh.relTip'))}</div>
    </div>
    ${list.map((r) => `
      <div class="gh-rel-item">
        <div class="gh-rel-item-head">
          <div class="gh-rel-tag-wrap">
            ${r.tag === latestTag ? `<span class="gh-rel-latest">${esc(t('gh.relLatest'))}</span>` : ''}
            ${r.prerelease && r.tag !== latestTag ? `<span class="gh-rel-pre">${esc(t('gh.preRelease'))}</span>` : ''}
            <span class="gh-rel-name">${esc(r.name || r.tag)}</span>
          </div>
          <div class="gh-rel-author">
            ${r.author && r.author.avatar_url ? `<img class="gh-rel-avatar" src="${esc(r.author.avatar_url)}" alt="" loading="lazy">` : ''}
            ${r.author && r.author.login ? `<span class="gh-rel-login">${esc(r.author.login)}</span>` : ''}
            <span class="gh-time">${esc(relTime(r.published_at))}</span>
          </div>
        </div>
        <div class="gh-rel-tagline">${esc(r.tag)}</div>
        ${r.body ? `<div class="md gh-rel-body">${renderMD(r.body)}</div>` : ''}
        ${assetsHtml(r)}
        <div class="gh-rel-sources">
          <a class="btn btn-ghost btn-sm" href="${esc(zip(r))}" download>⬇ ${esc(t('gh.relSourceZip'))}</a>
          <a class="btn btn-ghost btn-sm" href="${esc(tar(r))}" download>⬇ ${esc(t('gh.relSourceTar'))}</a>
        </div>
      </div>`).join('')}
  </div>`;
}

// 「最近动态」标签页：最近提交 + 发布版本（数据来自本站缓存的 GitHub 元数据）
function buildGhActivity(m, p) {
  const c = m.last_commit;
  const commit = c && c.message
    ? `<div class="gh-commit">${esc(c.message)}<div class="gh-time">${esc(c.author || '')}${c.date ? ' · ' + esc(relTime(c.date)) : ''}</div></div>`
    : `<div class="gh-empty">${esc(t('gh.noCommit'))}</div>`;
  const relRows = ghReleaseList(m, p, 5);
  return `<div class="gh-pane-inner">
    <p class="gh-pane-tip">${esc(t('gh.paneActionsTip'))}</p>
    <h3 class="gh-pane-h">${esc(t('gh.lastCommit'))}</h3>
    ${commit}
    <h3 class="gh-pane-h" style="margin-top:14px">🏷 ${esc(t('gh.releases'))}</h3>
    ${relRows || `<div class="gh-empty">${esc(t('gh.noRelease'))}</div>`}
  </div>`;
}

// 「安全与许可」标签页：许可信息 + 上报渠道说明
function buildGhSecurity(m) {
  const lic = m.license && m.license.name ? m.license.name : t('gh.noLicense');
  return `<div class="gh-pane-inner">
    <p class="gh-pane-tip">${esc(t('gh.paneSecurityTip'))}</p>
    <h3 class="gh-pane-h">⚖️ ${esc(lic)}</h3>
  </div>`;
}

// 右侧 About 侧栏：描述 / 主页 / 话题 / GitHub 计数 / License / 语言条 / Release / 贡献者
// 注意：这里的 Star/Fork/Watch 只展示 GitHub 真实数字，交互统一走页头的站内按钮
function buildGhSide(m, p) {
  const counts = `
    <span class="gh-side-count"><b>${esc(fmtCount(m.stargazers))}</b> ${esc(t('gh.ghStar'))}</span>
    <span class="gh-side-count"><b>${esc(fmtCount(m.forks))}</b> ${esc(t('gh.ghFork'))}</span>
    <span class="gh-side-count"><b>${esc(fmtCount(m.watchers))}</b> ${esc(t('gh.ghWatch'))}</span>`;

  // 描述与话题：GitHub 仓库常常没写 description / 没打 topics，
  // 这时必须回落到后台手填的 description / tags，否则 About 区块看起来就是"内容没了"
  const desc = m.description || p.description || '';
  const topicList = (m.topics && m.topics.length)
    ? m.topics
    : (p.tags || '').split(',').map((s) => s.trim()).filter(Boolean);
  const topics = topicList.length
    ? `<div class="gh-topics gh-topics-side">${topicList.map((x) => `<span class="gh-topic">${esc(x)}</span>`).join('')}</div>`
    : '';

  return `
    <div class="gh-side-block">
      <h3>${esc(t('gh.about'))}</h3>
      ${desc ? `<p class="gh-side-desc">${esc(desc)}</p>` : ''}
      ${(p.homepage || m.homepage) ? `<a class="gh-homepage" href="${esc(p.homepage || m.homepage)}" target="_blank" rel="noopener noreferrer">🔗 ${esc(String(p.homepage || m.homepage).replace(/^https?:\/\//, ''))}</a>` : ''}
      ${topics}
      <div class="gh-side-counts">${counts}</div>
      ${m.license ? `<div class="gh-license">⚖️ ${esc(m.license.name)}</div>` : ''}
    </div>
    ${ghLangBlock(m)}
    ${ghReleaseBlock(m, p)}
    ${ghContribBlock(m)}`;
}

// GitHub 元数据不可用时（限流/网络不通/仓库不存在）：侧栏与文件区降级为仓库链接，其余区块照常
function degradeGithubMeta(el, p) {
  const commitEl = $('#gh-commit', el);
  if (commitEl) commitEl.textContent = t('gh.noCommit');
  const filesEl = $('#gh-files', el);
  if (filesEl) {
    filesEl.innerHTML = `<div class="gh-loading">${esc(t('gh.metaUnavailable'))} `
      + `<a href="${esc(p.repo_url)}" target="_blank" rel="noopener noreferrer">${esc(t('gh.openRepo'))}</a></div>`;
  }
  const side = $('#gh-side', el);
  if (side) {
    // 降级也只降"GitHub 那部分"：后台手填的描述 / 话题 / 主页一律保留，
    // 不能因为 GitHub 限流就把整个 About 区块清空
    const tags = (p.tags || '').split(',').map((s) => s.trim()).filter(Boolean);
    side.innerHTML = `
      <div class="gh-side-block">
        <h3>${esc(t('gh.about'))}</h3>
        ${p.description ? `<p class="gh-side-desc">${esc(p.description)}</p>` : ''}
        ${(p.homepage || m.homepage)
          ? `<a class="gh-homepage" href="${esc(p.homepage || m.homepage)}" target="_blank" rel="noopener noreferrer">🔗 ${esc(String(p.homepage || m.homepage).replace(/^https?:\/\//, ''))}</a>`
          : `<a class="gh-homepage" href="${esc(p.repo_url)}" target="_blank" rel="noopener noreferrer">🔗 ${esc(t('gh.openRepo'))}</a>`}
        ${tags.length ? `<div class="gh-topics gh-topics-side">${tags.map((x) => `<span class="gh-topic">${esc(x)}</span>`).join('')}</div>` : ''}
      </div>`;
  }
  $$('[data-cnt]', el).forEach((n) => { n.textContent = '·'; });
}

// ---------- 视图 ----------
const Views = {

  async home(el) {
    const page = parseInt(new URLSearchParams(location.hash.split('?')[1] || '').get('page')) || 1;
    const { total, items } = await api(`/articles?page=${page}&size=10`);
    const cards = items.map((a) => `
      <article class="card hoverable article-card" data-slug="${esc(a.slug)}">
        ${a.cover ? `<img class="cover" src="${esc(a.cover)}" alt="" loading="lazy">` : ''}
        <h3>${esc(a.title)}</h3>
        <p class="summary">${esc(a.summary) || t('article.noSummary')}</p>
        <div class="tag-row">${(a.tags || '').split(',').filter(Boolean).map((t) => `<span class="tag">${esc(t.trim())}</span>`).join('')}</div>
        <div class="meta-row"><span>📅 ${fmtTime(a.created_at)}</span><span>👀 ${a.views}</span></div>
      </article>`).join('');
    const pages = Math.max(1, Math.ceil(total / 10));
    el.innerHTML = `
      <div class="view">
        <h2 class="section-title">${t('title.articles')}</h2>
        ${items.length ? `<div class="article-grid">${cards}</div>` : `<div class="empty"><span class="big">🫧</span>${t('empty.articles')}</div>`}
        ${pages > 1 ? `<div class="pager">
          ${page > 1 ? `<a class="btn btn-ghost btn-sm" href="#/?page=${page - 1}">${t('pager.prev')}</a>` : ''}
          <span class="btn btn-ghost btn-sm">${page} / ${pages}</span>
          ${page < pages ? `<a class="btn btn-ghost btn-sm" href="#/?page=${page + 1}">${t('pager.next')}</a>` : ''}
        </div>` : ''}
      </div>`;
    $$('.article-card', el).forEach((c) => c.addEventListener('click', () => { location.hash = `#/article/${c.dataset.slug}`; }));
  },

  async article(el, slug) {
    const { article: a, likes, comments: nComments, favorites, shares } = await api(`/articles/${encodeURIComponent(slug)}`);
    const cmts = (await api(`/comments/article/${a.id}`)).items;
    let myState = { liked: false, favorited: false };
    if (Auth.user) {
      try {
        const st = await api(`/mystate/article/${a.id}`);
        myState = st;
      } catch (_) {}
    }
    el.innerHTML = `
      <div class="view card article-detail">
        <h1>${esc(a.title)}</h1>
        <div class="meta-row"><span>📅 ${fmtTime(a.created_at)}</span><span>👀 ${a.views + 1}</span>
          <span class="tag-row">${(a.tags || '').split(',').filter(Boolean).map((t) => `<span class="tag">${esc(t.trim())}</span>`).join('')}</span>
        </div>
        <div class="md">${a.format === 'html' ? a.content : renderMD(a.content)}</div>
        <div class="action-bar">
          <button class="action-btn ${myState.liked ? 'active' : ''}" id="btn-like">${t('action.like')} <span>${likes}</span></button>
          <button class="action-btn ${myState.favorited ? 'active' : ''}" id="btn-fav">${t('action.fav')} <span>${favorites}</span></button>
          <button class="action-btn" id="btn-share">${t('action.share')} <span>${shares}</span></button>
        </div>
        <div class="comment-box">
          <h3 class="section-title" style="margin-top:0">${t('title.comments')} (${nComments})</h3>
          ${Auth.user
            ? `<div class="field"><textarea id="cmt-input" rows="3" maxlength="1000" placeholder="${esc(t('comment.ph'))}"></textarea></div>
               <button class="btn btn-primary btn-sm" id="cmt-send">${t('comment.send')}</button>`
            : `<p class="empty" style="padding:16px 0"><a href="#/login">${t('comment.login')}</a>${t('comment.loginSuffix')}</p>`}
          <div id="cmt-list">${commentListHtml(cmts)}</div>
        </div>
      </div>`;

    const bindAction = (id, path, extra) => {
      const btn = $(id, el);
      btn.addEventListener('click', async () => {
        if (!Auth.user) { toast(t('auth.needLogin')); location.hash = '#/login'; return; }
        try {
          const r = await api(path, { method: 'POST' });
          $('span', btn).textContent = r[extra.count];
          btn.classList.toggle('active', !!r[extra.flag]);
          btn.classList.remove('beat'); void btn.offsetWidth; btn.classList.add('beat');
          if (path.startsWith('/shares')) toast(t('share.copied'));
        } catch (e) { toast(e.message); }
      });
    };
    $('#btn-share', el).addEventListener('click', async () => {
      try { await navigator.clipboard.writeText(location.href); } catch (_) {}
      try { await api(`/shares/article/${a.id}`, { method: 'POST' }); } catch (_) {}
      toast(t('share.copied'));
    });
    bindAction('#btn-like', `/likes/article/${a.id}`, { count: 'likes', flag: 'liked' });
    bindAction('#btn-fav', `/favorites/article/${a.id}`, { count: 'favorites', flag: 'favorited' });

    const send = $('#cmt-send', el);
    if (send) send.addEventListener('click', async () => {
      const input = $('#cmt-input', el);
      if (!input.value.trim()) return toast(t('comment.needContent'));
      try {
        const c = await api(`/comments/article/${a.id}`, { method: 'POST', body: { content: input.value } });
        const list = $('#cmt-list', el);
        list.insertAdjacentHTML('afterbegin', commentItemHtml(c));
        input.value = '';
        toast(t('comment.posted'));
      } catch (e) { toast(e.message); }
    });
  },

  // 我的收藏：跨文章 / 图片 / 项目，登录用户查看自己收藏的内容
  async favorites(el) {
    if (!Auth.user) { location.hash = '#/login'; return; }
    const { items } = await api('/favorites/mine');
    const filter = FavState.filter || 'all';
    const shown = filter === 'all' ? items : items.filter((x) => x.type === filter);
    const tabs = [['all', t('fav.filterAll')], ['article', t('fav.filterArticle')],
      ['image', t('fav.filterImage')], ['project', t('fav.filterProject')]];
    const icon = { article: '📝', image: '🖼️', project: '🐙' };

    el.innerHTML = `
      <div class="view">
        <h2 class="section-title">${t('fav.title')}</h2>
        <div class="fav-filter">
          ${tabs.map(([v, label]) => `<button class="btn btn-sm ${filter === v ? 'btn-primary' : 'btn-ghost'}" data-fav-filter="${v}">${esc(label)}</button>`).join('')}
        </div>
        ${shown.length ? `
          <p class="fav-count">${t('fav.count', { n: shown.length })}</p>
          <div class="fav-grid">
            ${shown.map((it) => `
              <div class="card fav-card">
                ${it.cover
                  ? `<img class="fav-cover" src="${esc(it.cover)}" alt="" loading="lazy">`
                  : `<div class="fav-cover fav-cover-empty">${icon[it.type] || '⭐'}</div>`}
                <div class="fav-body">
                  <span class="fav-badge">${esc(t('type.' + it.type))}${it.draft ? ' · ' + esc(t('fav.draft')) : ''}</span>
                  <h3>${esc(it.title || '')}</h3>
                  ${it.summary ? `<p class="fav-summary">${esc(it.summary)}</p>` : ''}
                  <div class="fav-meta">${esc(t('fav.savedAt'))} ${fmtTime(it.favorited_at)}</div>
                  <div class="fav-actions">
                    <a class="btn btn-ghost btn-sm" href="${esc(it.href)}"${it.href.startsWith('#') ? '' : ' target="_blank" rel="noopener noreferrer"'}>${esc(t('fav.view'))}</a>
                    <button class="btn btn-danger btn-sm" data-unfav="${esc(it.type + ':' + it.id)}">${esc(t('fav.remove'))}</button>
                  </div>
                </div>
              </div>`).join('')}
          </div>`
        : `<div class="empty"><span class="big">⭐</span>${esc(t('fav.empty'))}<div class="fav-hint">${esc(t('fav.emptyHint'))}</div></div>`}
      </div>`;

    $$('[data-fav-filter]', el).forEach((b) => b.addEventListener('click', () => {
      FavState.filter = b.dataset.favFilter;
      renderRoute();
    }));
    $$('[data-unfav]', el).forEach((b) => b.addEventListener('click', async () => {
      const [type, id] = b.dataset.unfav.split(':');
      const ok = await confirmDialog({
        title: t('fav.remove'), message: t('fav.removeMsg'),
        confirmText: t('fav.remove'), cancelText: t('common.cancel'), danger: true,
      });
      if (!ok) return;
      try {
        await api(`/favorites/${type}/${id}`, { method: 'POST' });
        toast(t('fav.removed'));
        renderRoute();
      } catch (err) { toast(err.message); }
    }));
  },

  async search(el) {
    const params = new URLSearchParams((location.hash.split('?')[1] || ''));
    const q0 = params.get('q') || '';
    const type0 = params.get('type') || 'all';
    const types = [['all', t('search.all')], ['article', t('search.article')], ['image', t('search.image')], ['project', t('search.project')], ['social', t('search.social')], ['announcement', t('search.announcement')], ['user', t('search.user')]];
    const icon = { article: '📝', image: '🖼️', project: '🐙', social: '📱', announcement: '📢', user: '👤' };

    const renderResults = (r) => {
      const box = $('#search-results', el);
      if (!box) return;
      if (!r || !r.items.length) {
        box.innerHTML = `<div class="empty"><span class="big">🔍</span>${esc(t('search.empty'))}</div>`;
        return;
      }
      box.innerHTML = `<p class="search-count">${esc(t('search.count', { n: r.total }))}</p>
        <div class="search-grid">
          ${r.items.map((it) => `
            <a class="card search-card" href="${esc(it.href)}"${it.type === 'social' ? ' target="_blank" rel="noopener noreferrer"' : ''}>
              ${it.cover ? `<img class="search-cover" src="${esc(it.cover)}" alt="" loading="lazy">` : ''}
              <div class="search-card-main">
                <span class="search-type">${icon[it.type] || '🔍'} ${esc(t('search.' + it.type))}</span>
                <h3>${esc(it.title || '')}${it.level != null ? ` <span class="lv-tag" style="background:${esc(it.level_color || '#8b5cf6')}">Lv${esc(it.level)}</span>` : ''}</h3>
                ${it.summary ? `<p class="search-summary">${esc(it.summary)}</p>` : ''}
              </div>
            </a>`).join('')}
        </div>`;
    };

    el.innerHTML = `
      <div class="view search-view">
        <h2 class="section-title">${esc(t('search.title'))}</h2>
        <form id="search-form" class="search-form">
          <input id="search-input" name="q" maxlength="80" placeholder="${esc(t('search.ph'))}" value="${esc(q0)}" autocomplete="off">
          <button class="btn btn-primary" type="submit">${esc(t('search.btn'))}</button>
        </form>
        <div class="search-filters">
          ${types.map(([v, label]) => `<button type="button" class="btn btn-sm ${type0 === v ? 'btn-primary' : 'btn-ghost'}" data-type="${v}">${esc(label)}</button>`).join('')}
        </div>
        <div id="search-results"></div>
      </div>`;

    const input = $('#search-input', el);
    if (input) input.focus();

    const doSearch = async (q, type) => {
      const box = $('#search-results', el);
      if (!box) return;
      box.innerHTML = `<div class="gh-loading">${esc(t('common.loading'))}</div>`;
      try {
        const r = await api(`/search?q=${encodeURIComponent(q)}&type=${type}`);
        renderResults(r);
      } catch (e) {
        box.innerHTML = `<div class="empty"><span class="big">⚠️</span>${esc(e.message)}</div>`;
      }
    };

    const goto = (q, type) => {
      const next = `#/search?q=${encodeURIComponent(q)}&type=${type}`;
      if (location.hash === next) doSearch(q, type);
      else location.hash = next;
    };

    $('#search-form', el).addEventListener('submit', (e) => {
      e.preventDefault();
      goto(input.value.trim(), type0);
    });

    $$('.search-filters [data-type]', el).forEach((b) => b.addEventListener('click', () => {
      goto(input.value.trim(), b.dataset.type);
    }));

    if (q0) doSearch(q0, type0);
    else $('#search-results', el).innerHTML = `<div class="empty"><span class="big">🔍</span>${esc(t('search.ph'))}</div>`;
  },

  async announcements(el) {
    const { items } = await api('/announcements');
    el.innerHTML = `
      <div class="view ann-view">
        <h2 class="section-title">📢 ${esc(t('ann.title'))}</h2>
        ${items.length ? items.map((a) => `
          <div class="card ann-card${a.pinned ? ' ann-pinned' : ''}">
            <div class="ann-card-head">
              ${a.pinned ? `<span class="ann-pin-badge">📌 ${esc(t('ann.pinned'))}</span>` : ''}
              <span class="ann-tag ann-tag-${esc(a.tag)}">${esc(annTagLabel(a.tag))}</span>
              <h3>${esc(a.title)}</h3>
              <span class="gh-time">${esc(fmtTime(a.created_at))}</span>
            </div>
            ${a.content ? `<div class="md ann-body">${renderMD(a.content)}</div>` : ''}
          </div>`).join('') : `<div class="empty"><span class="big">📢</span>${esc(t('ann.empty'))}</div>`}
      </div>`;
  },

  async gallery(el) {
    const { items } = await api('/images?size=36');
    el.innerHTML = `
      <div class="view">
        <h2 class="section-title">${t('title.gallery')}</h2>
        ${items.length ? `<div class="gallery-grid">
          ${items.map((im) => `
            <div class="card gallery-item" data-iid="${im.id}">
              <img src="/uploads/${esc(im.filename)}" alt="${esc(im.title)}" loading="lazy">
              <div class="g-cap">
                <b>${esc(im.title)}</b>
                ${im.description ? `<span>${esc(im.description)}</span>` : ''}
                <span class="g-meta">👀 ${im.views || 0} · <a class="g-detail" href="#/image/${im.id}">${t('image.detail')}</a></span>
              </div>
            </div>`).join('')}
        </div>` : `<div class="empty"><span class="big">🖼️</span>${t('empty.gallery')}</div>`}
      </div>`;
    // 点击图片：页内放大查看（灯箱），带关闭按钮与左右切换；点击「详情」链接则跳转到图片详情页
    $$('.gallery-item', el).forEach((g, i) => g.addEventListener('click', (e) => {
      if (e.target.closest('a')) return;
      Lightbox.open(items, i);
    }));
  },

  async projects(el) {
    const { items } = await api('/projects');
    el.innerHTML = `
      <div class="view">
        <h2 class="section-title">${t('title.projects')}</h2>
        ${items.length ? `<div class="project-list">
          ${items.map((p) => `
            <div class="card hoverable project-card" data-pid="${p.id}">
              <span class="gh-icon">${esc(p.icon || '🐙')}</span>
              <div class="project-main"><h3>${esc(p.title)}</h3><p>${esc(p.description)}</p>
                <div class="tag-row" style="margin-top:6px">${(p.tags || '').split(',').filter(Boolean).map((t) => `<span class="tag">${esc(t.trim())}</span>`).join('')}</div>
                <div class="meta-row"><span>👀 ${p.views || 0}</span></div>
              </div>
              <div class="project-actions">
                ${Auth.user ? `<button class="btn btn-ghost btn-sm fav-btn" data-fav-project="${p.id}" title="${esc(t('action.fav'))}">⭐</button>` : ''}
                <a class="repo-link btn btn-ghost btn-sm" href="${esc(p.repo_url)}" target="_blank" rel="noopener noreferrer">${t('project.repo')}</a>
                <a class="btn btn-ghost btn-sm" href="#/project/${p.id}">${t('project.detail')}</a>
              </div>
            </div>`).join('')}
        </div>` : `<div class="empty"><span class="big">🛠️</span>${t('empty.projects')}</div>`}
      </div>`;
    // 整张卡片点击进入详情页（链接/按钮自身处理，不触发跳转）
    $$('.project-card', el).forEach((c) => c.addEventListener('click', (e) => {
      if (e.target.closest('a, button')) return;
      location.hash = `#/project/${c.dataset.pid}`;
    }));
    // 项目收藏（登录用户）
    const favBtns = $$('[data-fav-project]', el);
    if (favBtns.length && Auth.user) {
      favBtns.forEach((b) => b.addEventListener('click', async (e) => {
        e.stopPropagation();
        const id = b.dataset.favProject;
        try {
          const r = await api(`/favorites/project/${id}`, { method: 'POST' });
          b.classList.toggle('active', !!r.favorited);
          b.title = r.favorited ? t('fav.remove') : t('action.fav');
          toast(r.favorited ? t('fav.added') : t('fav.removed'));
        } catch (err) { toast(err.message); }
      }));
      favBtns.forEach((b) => {
        api(`/mystate/project/${b.dataset.favProject}`).then((st) => {
          if (st && st.favorited) { b.classList.add('active'); b.title = t('fav.remove'); }
        }).catch(() => {});
      });
    }
  },

  // 项目详情：GitHub 仓库页风格（头部/标签页/文件列表/README/About 侧栏）+ 本站互动与评论
  // 关键约束：除「前往原仓库」外，所有交互都在站内完成——
  //   Star → 站内收藏、Watch → 站内点赞、Fork → 站内下载源码副本、
  //   Download ZIP / 单文件下载 → 本站代理接口、文件列表 → 站内文件浏览器、
  //   六个标签页 → 站内面板（议题=本站讨论，其余用已有数据拼出说明页）。
  async project(app, id) {
    const el = app;
    let data;
    try {
      data = await api(`/projects/${encodeURIComponent(id)}`);
    } catch (e) {
      // 项目已被删除，或后端还没重启导致详情接口不存在：给友好提示而不是「请求失败」
      renderDetailMissing(el, '#/projects', t('project.back'));
      return;
    }
    const p = data.project;
    const cmts = (await api(`/comments/project/${p.id}`)).items;
    const rp = parseRepo(p.repo_url) || { owner: '', repo: p.title };
    const icon = p.icon || '🐙';
    const tags = (p.tags || '').split(',').filter(Boolean);

    el.innerHTML = `
      <div class="view gh-repo">
        <a class="back-link" href="#/projects">← ${esc(t('project.back'))}</a>

        <div class="gh-head">
          <div class="gh-title-row">
            <span class="gh-repo-icon">${esc(icon)}</span>
            <h1 class="gh-title" id="gh-title">
              <span>${esc(rp.owner || 'GitHub')}</span>
              <span class="gh-slash">/</span>
              <b>${esc(rp.repo || p.title)}</b>
            </h1>
            <span class="gh-badge">${esc(t('gh.public'))}</span>
          </div>
          <div class="gh-head-actions">
            <div class="gh-code-wrap">
              <button type="button" class="gh-btn gh-code-btn" id="gh-code-toggle">${esc(t('gh.code'))} ▾</button>
              <div class="gh-code-menu" id="gh-code-menu" hidden>
                <div class="gh-code-lab">${esc(t('gh.cloneLab'))}</div>
                <div class="gh-code-url">
                  <input id="gh-clone-url" readonly value="https://github.com/${esc(rp.owner)}/${esc(rp.repo)}.git">
                  <button type="button" class="btn btn-primary btn-sm" id="gh-copy">${esc(t('gh.copy'))}</button>
                </div>
                <div class="gh-code-lab">${esc(t('gh.downloadLab'))}</div>
                <a class="gh-dl" id="gh-zip" href="/api/projects/${p.id}/download" download>⬇ ${esc(t('gh.zip'))}</a>
                <a class="gh-dl" id="gh-tar" href="/api/projects/${p.id}/download?format=tar" download>⬇ ${esc(t('gh.tar'))}</a>
                <div class="gh-code-lab" id="gh-rel-lab" hidden>🏷 ${esc(t('gh.releases'))}</div>
                <div class="gh-rel-list" id="gh-rel-list" hidden><span class="gh-loading">${esc(t('gh.loading'))}</span></div>
              </div>
            </div>
            <button type="button" class="gh-btn" id="btn-like" title="${esc(t('gh.watchTip'))}">👁 <span class="gh-lab">${esc(t('gh.watch'))}</span> <span class="gh-count btn-count">${data.likes}</span></button>
            <button type="button" class="gh-btn" id="gh-fork" title="${esc(t('gh.forkTip'))}">🍴 ${esc(t('gh.fork'))} <span class="gh-count" data-cnt="forks">·</span></button>
            <button type="button" class="gh-btn gh-star" id="btn-fav" title="${esc(t('gh.starTip'))}">⭐ <span class="gh-lab">${esc(t('gh.star'))}</span> <span class="gh-count btn-count">${data.favorites}</span></button>
          </div>
        </div>

        <p class="gh-desc" id="gh-desc">${esc(p.description || '')}</p>
        <div class="gh-topics" id="gh-topics">${tags.map((x) => `<span class="gh-topic">${esc(x.trim())}</span>`).join('')}</div>
        <div class="gh-gh-counts">
          <span>⭐ <b data-cnt="stargazers">·</b> ${esc(t('gh.ghStar'))}</span>
          <span>🍴 <b data-cnt="forks">·</b> ${esc(t('gh.ghFork'))}</span>
          <span>👁 <b data-cnt="watchers">·</b> ${esc(t('gh.ghWatch'))}</span>
        </div>

        <nav class="gh-tabs" id="gh-tabs">
          <button type="button" class="gh-tab active" data-tab="code">📄 ${esc(t('gh.tabCode'))}</button>
          <button type="button" class="gh-tab" data-tab="issues">🐛 ${esc(t('gh.tabIssues'))} <span class="gh-count" data-cnt="open_issues">·</span></button>
          <button type="button" class="gh-tab" data-tab="pulls">🔀 ${esc(t('gh.tabPR'))}</button>
          <button type="button" class="gh-tab" data-tab="actions">⚡ ${esc(t('gh.tabActions'))}</button>
          <button type="button" class="gh-tab" data-tab="wiki">📖 ${esc(t('gh.tabWiki'))}</button>
          <button type="button" class="gh-tab" data-tab="security">🛡 ${esc(t('gh.tabSecurity'))}</button>
          <button type="button" class="gh-tab" data-tab="insights">📊 ${esc(t('gh.tabInsights'))}</button>
          <button type="button" class="gh-tab" data-tab="releases">🏷 ${esc(t('gh.releases'))} <span class="gh-count" id="gh-rel-count" hidden></span></button>
        </nav>

        <div class="gh-body">
          <div class="gh-main">
            <section class="gh-pane" data-pane="code">
              <div class="gh-commit-bar">
                <span class="gh-branch">🌿 <b id="gh-branch">main</b></span>
                <span class="gh-commit" id="gh-commit">${esc(t('gh.loading'))}</span>
              </div>
              <div class="gh-files" id="gh-files"><div class="gh-loading">${esc(t('gh.loading'))}</div></div>
              <div class="gh-fileview" id="gh-fileview" hidden></div>
              <div class="card gh-readme">
                <div class="gh-readme-head">README</div>
                <div class="md readme" id="readme-box"><p class="empty">${esc(t('project.readmeLoading'))}</p></div>
              </div>
            </section>

            <section class="gh-pane" data-pane="issues" hidden>
              <div class="card comment-box">
                <h3 class="section-title" style="margin-top:0" id="cmt-heading">${t('title.comments')} (${data.comments})</h3>
                <p class="gh-pane-tip">${esc(t('gh.paneIssuesTip'))}</p>
                ${Auth.user
                  ? `<div class="field"><textarea id="cmt-input" rows="3" maxlength="1000" placeholder="${esc(t('comment.ph'))}"></textarea></div>
                     <button class="btn btn-primary btn-sm" id="cmt-send">${t('comment.send')}</button>`
                  : `<p class="empty" style="padding:16px 0"><a href="#/login">${t('comment.login')}</a>${t('comment.loginSuffix')}</p>`}
                <div id="cmt-list" data-count="${data.comments}">${commentListHtml(cmts)}</div>
              </div>
            </section>

            <section class="gh-pane" data-pane="pulls" hidden>
              <div class="card gh-pane-inner">
                <h3 class="gh-pane-h">🔀 ${esc(t('gh.panePulls'))}</h3>
                <p class="gh-pane-tip">${esc(t('gh.panePullsTip'))}</p>
                <a class="btn btn-ghost btn-sm" href="${esc(p.repo_url)}" target="_blank" rel="noopener noreferrer">${esc(t('gh.openRepo'))}</a>
              </div>
            </section>

            <section class="gh-pane" data-pane="actions" hidden>
              <div class="card" id="pane-actions"><div class="gh-pane-inner"><div class="gh-loading">${esc(t('gh.loading'))}</div></div></div>
            </section>

            <section class="gh-pane" data-pane="wiki" hidden>
              <div class="card gh-pane-inner">
                <h3 class="gh-pane-h">📖 ${esc(t('gh.paneWiki'))}</h3>
                <p class="gh-pane-tip">${esc(t('gh.paneWikiTip'))}</p>
                <button type="button" class="btn btn-ghost btn-sm" id="wiki-to-readme">📄 ${esc(t('gh.tabCode'))}</button>
              </div>
            </section>

            <section class="gh-pane" data-pane="security" hidden>
              <div class="card" id="pane-security"><div class="gh-pane-inner"><div class="gh-loading">${esc(t('gh.loading'))}</div></div></div>
            </section>

            <section class="gh-pane" data-pane="insights" hidden>
              <div class="card" id="pane-insights"><div class="gh-pane-inner"><div class="gh-loading">${esc(t('gh.loading'))}</div></div></div>
            </section>

            <section class="gh-pane" data-pane="releases" hidden>
              <div class="card" id="pane-releases"><div class="gh-pane-inner"><div class="gh-loading">${esc(t('gh.loading'))}</div></div></div>
            </section>

            <div class="card gh-interact">
              <div class="gh-interact-title">${esc(t('gh.siteActions'))}</div>
              <div class="meta-row"><span>👀 ${p.views + 1}</span><span>📅 ${fmtTime(p.created_at)}</span></div>
              <div class="action-bar">
                <button class="action-btn" id="btn-like2">${t('action.like')} <span>${data.likes}</span></button>
                <button class="action-btn" id="btn-fav2">${t('action.fav')} <span>${data.favorites}</span></button>
                <button class="action-btn" id="btn-share">${t('action.share')} <span>${data.shares}</span></button>
                <a class="action-btn repo-btn" href="${esc(p.repo_url)}" target="_blank" rel="noopener noreferrer">${esc(t('gh.openRepo'))}</a>
              </div>
            </div>
          </div>
          <aside class="gh-side" id="gh-side"><div class="gh-loading">${esc(t('gh.loading'))}</div></aside>
        </div>
      </div>`;

    bindInteractions(el, 'project', p.id);
    // 页头 Star/Watch 与底部互动栏是同一套动作：底部按钮镜像页头状态，两边始终一致
    mirrorAction(el, 'btn-like', 'btn-like2', t('gh.watchOn'), t('gh.watchOff'));
    mirrorAction(el, 'btn-fav', 'btn-fav2', t('gh.starOn'), t('gh.starOff'));

    // ---------- 绿色 Code 下拉：复制克隆地址 / 站内下载 ZIP ----------
    const codeToggle = $('#gh-code-toggle', el);
    const codeMenu = $('#gh-code-menu', el);
    if (codeToggle && codeMenu) {
      codeToggle.addEventListener('click', (e) => { e.stopPropagation(); codeMenu.hidden = !codeMenu.hidden; });
      document.addEventListener('click', () => { codeMenu.hidden = true; });
      const copyBtn = $('#gh-copy', el);
      if (copyBtn) copyBtn.addEventListener('click', async () => {
        const v = ($('#gh-clone-url', el) || {}).value || '';
        try { await navigator.clipboard.writeText(v); toast(t('share.copied')); }
        catch (_) { toast(v || t('share.copied')); }
      });
    }
    // ---------- Fork：站内下载一份源码副本（不跳 GitHub 的 fork 页） ----------
    const forkBtn = $('#gh-fork', el);
    if (forkBtn) forkBtn.addEventListener('click', () => startDownload(el, p));

    // ---------- 站内文件浏览器 ----------
    let curRef = 'main';
    const filesEl = $('#gh-files', el);
    const fileView = $('#gh-fileview', el);

    function renderDir(r) {
      const crumb = r.path || t('gh.fileRoot');
      const up = r.path ? `<button type="button" class="gh-file gh-up" id="gh-up">↩ ${esc(t('gh.fileUp'))}</button>` : '';
      const rows = r.entries.map((f) => `
        <button type="button" class="gh-file" data-p="${esc(f.path)}">
          <span class="gh-file-icon">${f.type === 'dir' ? '📁' : '📄'}</span>
          <span class="gh-file-name">${esc(f.name)}</span>
          <span class="gh-file-size">${f.type === 'dir' ? '' : esc(fmtBytes(f.size))}</span>
        </button>`).join('');
      filesEl.innerHTML = `<div class="gh-path">📂 ${esc(crumb)}</div>${up}${rows || `<div class="gh-loading">${esc(t('gh.noFiles'))}</div>`}`;
      $$('.gh-file[data-p]', filesEl).forEach((b) => b.addEventListener('click', () => browse(b.dataset.p)));
      const upBtn = $('#gh-up', filesEl);
      if (upBtn) upBtn.addEventListener('click', () => browse(r.parent || ''));
    }

    function renderFile(r) {
      const body = r.text == null
        ? `<div class="gh-loading">${esc(t('gh.fileBinary'))}</div>`
        : (String(r.text).trim() ? `<pre class="gh-code"><code>${esc(r.text)}</code></pre>` : `<div class="gh-loading">${esc(t('gh.fileEmpty'))}</div>`);
      fileView.innerHTML = `
        <div class="gh-file-head">
          <span class="gh-file-icon">📄</span><b>${esc(r.name)}</b>
          <span class="gh-time">${esc(fmtBytes(r.size))}</span>
          <span class="gh-file-actions">
            <a class="btn btn-ghost btn-sm" href="${esc(r.download)}" download>⬇ ${esc(t('gh.fileDown'))}</a>
            <button type="button" class="btn btn-ghost btn-sm" id="gh-file-close">${esc(t('gh.closeFile'))}</button>
          </span>
        </div>${body}`;
      fileView.hidden = false;
      const c = $('#gh-file-close', fileView);
      if (c) c.addEventListener('click', () => { fileView.hidden = true; fileView.innerHTML = ''; });
    }

    // 渲染某个目录（不触碰已打开的文件预览，便于"边看文件边换目录"）
    async function showDir(path) {
      try {
        const r = await api(`/projects/${p.id}/files?path=${encodeURIComponent(path || '')}&ref=${encodeURIComponent(curRef)}`);
        if (r && r.type === 'dir') renderDir(r);
        else filesEl.innerHTML = `<div class="gh-loading">${esc(t('gh.browseFail'))}</div>`;
      } catch (e) {
        filesEl.innerHTML = `<div class="gh-loading">${esc(e.message || t('gh.browseFail'))}</div>`;
      }
    }

    async function browse(path) {
      filesEl.innerHTML = `<div class="gh-loading">${esc(t('gh.loading'))}</div>`;
      fileView.hidden = true; fileView.innerHTML = '';
      try {
        const r = await api(`/projects/${p.id}/files?path=${encodeURIComponent(path || '')}&ref=${encodeURIComponent(curRef)}`);
        if (r.type === 'dir') renderDir(r);
        else {
          // 打开文件：预览显示在下方，同时把所在目录的列表补回来（否则"返回上级"会消失）
          renderFile(r);
          await showDir(r.parent || '');
        }
      } catch (e) {
        filesEl.innerHTML = `<div class="gh-loading">${esc(e.message || t('gh.browseFail'))}</div>`;
      }
    }
    // 元数据到位后 fillGithubMeta 会调用它带真实默认分支刷新一次
    window.__ghBrowse = async (path) => {
      if (window.__ghRef) curRef = window.__ghRef;
      browse(path || '');
    };

    // ---------- 标签页切换（全部站内面板） ----------
    const tabs = $$('.gh-tab', el);
    const activateTab = (name) => {
      const target = tabs.find((x) => x.dataset.tab === name) || tabs[0];
      tabs.forEach((x) => x.classList.toggle('active', x === target));
      $$('.gh-pane', el).forEach((sec) => { sec.hidden = sec.dataset.pane !== target.dataset.tab; });
    };
    tabs.forEach((b) => b.addEventListener('click', () => activateTab(b.dataset.tab)));
    // 支持 #/project/:id?tab=releases 直达某个标签页（如侧栏「查看全部发行版」）
    const initTab = (new URLSearchParams((location.hash.split('?')[1] || '')).get('tab')) || '';
    if (initTab && initTab !== 'code') activateTab(initTab);
    const wikiBtn = $('#wiki-to-readme', el);
    if (wikiBtn) wikiBtn.addEventListener('click', () => {
      tabs[0].click();
      const rm = $('#readme-box', el);
      if (rm) rm.scrollIntoView({ behavior: 'smooth', block: 'start' });
    });

    // README 异步加载（不阻塞首屏）：命中缓存秒回，未命中则服务端拉取 GitHub 并回填。
    // 相对图片要按真实默认分支补全，所以元数据到位后若分支不同会重画一次。
    const box = $('#readme-box', el);
    let readmeText = '';
    let readmeBranch = 'main';
    const paintReadme = () => {
      if (!box) return;
      if (readmeText.trim()) box.innerHTML = renderReadme(readmeText, p.repo_url, readmeBranch);
      else box.innerHTML = `<p class="empty">${esc(t('project.readmeEmpty'))} <a href="${esc(p.repo_url)}" target="_blank" rel="noopener noreferrer">${esc(t('gh.openRepo'))}</a></p>`;
    };
    api(`/projects/${p.id}/readme`).then((r) => {
      readmeText = (r && r.readme) || '';
      paintReadme();
    }).catch(paintReadme);

    // GitHub 元数据异步加载（Star/语言/贡献者/文件列表…）：拿不到就降级，不影响其余区块
    api(`/projects/${p.id}/github`).then((r) => {
      if (r.meta) {
        const br = r.meta.default_branch || 'main';
        window.__ghRef = br;
        // 默认分支可能与 README 首次渲染时假设的不一致（main/master）：分支变了就重画，
        // 否则相对图片会指向不存在的分支而裂图
        if (br !== readmeBranch) { readmeBranch = br; paintReadme(); }
        fillGithubMeta(el, r.meta, p);
      } else degradeGithubMeta(el, p);
    }).catch(() => degradeGithubMeta(el, p));
  },

  // 图片详情：大图 + 点赞/收藏/分享/评论 + 浏览数（灯箱仅作放大查看）
  async image(app, id) {
    const el = app;
    let data;
    try {
      data = await api(`/images/${encodeURIComponent(id)}`);
    } catch (e) {
      // 图片已被删除，或后端还没重启导致详情接口不存在：给友好提示而不是「请求失败」
      renderDetailMissing(el, '#/gallery', t('image.back'));
      return;
    }
    const im = data.image;
    const cmts = (await api(`/comments/image/${im.id}`)).items;
    el.innerHTML = `
      <div class="view card article-detail image-detail">
        <a class="back-link" href="#/gallery">← ${esc(t('image.back'))}</a>
        <h1>${esc(im.title || t('image.untitled'))}</h1>
        ${im.description ? `<p class="project-desc">${esc(im.description)}</p>` : ''}
        <div class="meta-row"><span>📅 ${fmtTime(im.created_at)}</span><span>👀 ${im.views + 1}</span></div>
        <div class="img-detail-wrap">
          <img class="img-detail" src="/uploads/${esc(im.filename)}" alt="${esc(im.title)}" loading="lazy">
          <button class="btn btn-ghost btn-sm zoom-btn" id="zoom-btn" type="button">${esc(t('image.zoom'))}</button>
        </div>
        <div class="action-bar">
          <button class="action-btn" id="btn-like">${t('action.like')} <span>${data.likes}</span></button>
          <button class="action-btn" id="btn-fav">${t('action.fav')} <span>${data.favorites}</span></button>
          <button class="action-btn" id="btn-share">${t('action.share')} <span>${data.shares}</span></button>
        </div>
        <div class="comment-box">
          <h3 class="section-title" style="margin-top:0" id="cmt-heading">${t('title.comments')} (${data.comments})</h3>
          ${Auth.user
            ? `<div class="field"><textarea id="cmt-input" rows="3" maxlength="1000" placeholder="${esc(t('comment.ph'))}"></textarea></div>
               <button class="btn btn-primary btn-sm" id="cmt-send">${t('comment.send')}</button>`
            : `<p class="empty" style="padding:16px 0"><a href="#/login">${t('comment.login')}</a>${t('comment.loginSuffix')}</p>`}
          <div id="cmt-list" data-count="${data.comments}">${commentListHtml(cmts)}</div>
        </div>
      </div>`;
    bindInteractions(el, 'image', im.id);
    const zoom = $('#zoom-btn', el);
    if (zoom) zoom.addEventListener('click', () => Lightbox.open([{ id: im.id, filename: im.filename, title: im.title, description: im.description }], 0));
  },

  async social(el) {
    const { items } = await api('/social');
    const meta = {
      bilibili: { icon: '📺', name: t('plat.bilibili') },
      youtube: { icon: '▶️', name: 'YouTube' },
      weibo: { icon: '💬', name: t('plat.weibo') },
      x: { icon: '𝕏', name: 'X' },
      github: { icon: '🐙', name: 'GitHub' },
      other: { icon: '🔗', name: t('plat.other') },
    };
    el.innerHTML = `
      <div class="view">
        <h2 class="section-title">${t('title.social')}</h2>
        <p style="color:var(--text-soft);font-size:13.5px;margin-bottom:16px">${t('social.intro')}</p>
        ${items.length ? `<div class="social-grid">${items.map((s) => {
          const m = meta[s.platform] || meta.other;
          return `
          <a class="card social-card" href="${esc(s.url)}" target="_blank" rel="noopener noreferrer">
            <div class="social-cover" style="${s.cover ? `background-image:url('${esc(s.cover)}')` : ''}">
              ${s.cover ? '' : `<span class="social-emoji">${m.icon}</span>`}
              <span class="social-platform">${m.icon} ${m.name}</span>
            </div>
            <div class="social-body">
              <h3>${esc(s.title)}</h3>
              ${s.description ? `<p>${esc(s.description)}</p>` : ''}
              <span class="social-time">${fmtTime(s.created_at)}</span>
            </div>
          </a>`;
        }).join('')}</div>` : `<div class="empty"><span class="big">📱</span>${t('empty.social')}</div>`}
      </div>`;
  },

  async sponsor(el) {
    const { items } = await api('/sponsors');
    el.innerHTML = `
      <div class="view">
        <h2 class="section-title">${t('title.sponsor')}</h2>
        <div class="sponsor-wrap">
          <div class="card sponsor-card">
            <h3>${t('sponsor.coffee')}</h3>
            <p style="color:var(--text-soft);font-size:13.5px;margin-top:8px">
              ${t('sponsor.desc')}
            </p>
            ${(Site.data && Site.data.sponsor_qr)
              ? `<img class="sponsor-qr" src="${esc(Site.data.sponsor_qr)}" alt="${t('sponsor.qrAlt')}">`
              : `<div class="qr-placeholder">${t('sponsor.noQr')}</div>`}
            <p style="font-size:12.5px;color:var(--text-soft)">${t('sponsor.note')}</p>
          </div>
          <div class="card sponsor-list">
            <h3>${t('sponsor.wall')}</h3>
            ${items.length ? items.map((s) => `
              <div class="sponsor-row">
                <span>🌸 <b>${esc(s.name)}</b></span>
                ${s.amount ? `<span class="amount">¥${esc(s.amount)}</span>` : ''}
                <span style="color:var(--text-soft);font-size:13px">${esc(s.message)}</span>
              </div>`).join('') : `<p class="empty" style="padding:20px 0">${t('sponsor.empty')}</p>`}
          </div>
        </div>
      </div>`;
  },

  async settings(el) {
    if (!Auth.user) { location.hash = '#/login'; return; }
    const u = Auth.user;
    el.innerHTML = `
      <div class="view">
        <div class="card form-card" style="max-width:520px">
          <h2>${t('settings.title')}</h2>
          <div class="settings-av">
            <img id="set-av" class="avatar-big" src="${Auth.avatarUrl()}" alt="${t('avatar.alt')}">
            <div class="settings-av-r">
              <input type="file" id="av-file" accept="image/*" hidden>
              <button type="button" class="btn btn-ghost btn-sm" id="av-pick">${t('settings.changeAvatar')}</button>
              <p class="pw-hint">${t('settings.avatarHint')}</p>
            </div>
          </div>
          <div class="field"><label>${t('settings.username')}</label><input value="${esc(u.username)}" disabled></div>
          <div class="field"><label>${t('settings.email')}</label><input value="${esc(u.email)}" disabled></div>
          <div class="field"><label>${t('settings.uid')}</label><input value="${esc(u.id)}" disabled></div>
          <h3 class="section-title">${t('profile.changePwd')}</h3>
          <form id="pw-form">
            <div class="field"><label>${t('settings.oldPwd')}</label><input name="old" type="password" required autocomplete="current-password"></div>
            <div class="field"><label>${t('settings.newPwd')}</label><input name="nw" type="password" required maxlength="72" autocomplete="new-password"></div>
            <div class="field"><label>${t('settings.confirmPwd')}</label><input name="nw2" type="password" required maxlength="72" autocomplete="new-password"></div>
            <button class="btn btn-primary btn-sm">${t('settings.savePwd')}</button>
          </form>
          <h3 class="section-title">${t('profile.account')}</h3>
          <button type="button" class="btn btn-ghost btn-sm" id="settings-logout">${t('menu.logout')}</button>
        </div>
      </div>`;

    $('#av-pick', el).addEventListener('click', async () => {
      const file = await pickFile('image/*');
      if (!file) return;
      if (file.size > 5 * 1024 * 1024) return toast(t('msg.imgTooLarge'));
      try {
        const blob = await Cropper.open(file);
        const fd = new FormData();
        fd.append('file', blob, 'avatar.jpg');
        const res = await fetch('/api/user/avatar', { method: 'POST', headers: { 'X-Requested-With': 'WebOwn' }, body: fd, credentials: 'same-origin' });
        const data = await res.json();
        if (!res.ok) throw new Error(data.error || t('msg.uploadFailed'));
        Auth.user.avatar = data.avatar;
        Auth._avT = Date.now();
        $('#set-av', el).src = Auth.avatarUrl();
        Auth.renderChip();
        toast(t('msg.avatarUpdated'));
      } catch (e) {
        if (e && e.message !== 'cancel') toast(e.message || t('msg.avatarFail'));
      }
    });

    $('#pw-form', el).addEventListener('submit', async (e) => {
      e.preventDefault();
      const f = e.target;
      if (f.nw.value !== f.nw2.value) return toast(t('msg.pwdMismatch'));
      try {
        await api('/user/password', { method: 'PUT', body: { oldPassword: f.old.value, newPassword: f.nw.value } });
        toast(t('msg.pwdChanged'));
        f.reset();
      } catch (err) { toast(err.message); }
    });

    const sLogout = $('#settings-logout', el);
    if (sLogout) sLogout.addEventListener('click', () => { confirmLogout(); });
  },

  async login(el) {
    if (Auth.user) return Views.loggedInNotice(el);
    el.innerHTML = `
      <div class="view">
        <form class="card form-card" id="login-form">
          <h2>${t('login.welcome')}</h2>
          <div class="field"><label>${t('login.userOrEmail')}</label><input name="username" required maxlength="120" autocomplete="username"></div>
          <div class="field pw-field">
            <label>${t('auth.password')}</label>
            <input name="password" type="password" required maxlength="72" autocomplete="current-password">
            <a href="#/forgot" class="forgot-link">${t('login.forgot')}</a>
          </div>
          <label class="agree-row"><input type="checkbox" id="login-agree"><span>${t('login.agreePrefix')}<a href="#/terms" class="terms-link" target="_blank">${t('terms.link')}</a></span></label>
          <div class="login-options" style="display:flex;gap:18px;margin:6px 0 2px">
            <label class="agree-row"><input type="checkbox" id="login-rememberpw"><span>${t('login.rememberPw')}</span></label>
            <label class="agree-row"><input type="checkbox" id="login-autologin"><span>${t('login.autoLogin')}</span></label>
          </div>
          ${captchaFieldHtml()}
          <button class="btn btn-primary" id="login-btn" style="width:100%">${t('auth.login')}</button>
          <p class="form-foot">${t('login.noAccount')}<a href="#/register">${t('login.registerNow')}</a></p>
        </form>
      </div>`;
    await loadCaptcha(el);
    const tl2 = $('.terms-link', el);
    if (tl2) tl2.addEventListener('click', (e) => {
      e.preventDefault(); e.stopPropagation();
      Terms.show('view');
    });
    const form = $('#login-form', el);
    // 记住密码：回填上次保存的账号
    try {
      const saved = JSON.parse(localStorage.getItem('wo-login') || 'null');
      if (saved && saved.username) {
        form.username.value = saved.username;
        if (saved.password) form.password.value = saved.password;
        $('#login-rememberpw', el).checked = true;
      }
      if (localStorage.getItem('wo-autologin') === '1') $('#login-autologin', el).checked = true;
    } catch (_) {}

    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      const f = e.target;
      const btn = $('#login-btn', el);
      const rememberPw = $('#login-rememberpw', el).checked;
      const autoLogin = $('#login-autologin', el).checked;
      btn.disabled = true; btn.textContent = t('login.loggingIn');
      try {
        const r = await api('/auth/login', { method: 'POST', body: {
          username: f.username.value, password: f.password.value, remember: autoLogin,
          captchaId: f.captchaId.value, captcha: f.captcha.value,
        } });
        if (rememberPw) localStorage.setItem('wo-login', JSON.stringify({ username: f.username.value, password: f.password.value }));
        else localStorage.removeItem('wo-login');
        localStorage.setItem('wo-autologin', autoLogin ? '1' : '0');
        Auth.user = r.user; Auth.renderChip();
        toast(t('login.welcomeBack', { name: r.user.username }));
        // 登录成功后检查置顶公告弹窗（新用户 / 久未登录 / 未读）
        checkAnnouncements();
        location.hash = '#/';
      } catch (err) {
        toast(err.message);
        btn.disabled = false; btn.textContent = t('auth.login');
        // 验证码一次性：无论何种失败都换新一张，并清空已填内容
        f.captcha.value = '';
        await loadCaptcha(el);
      }
    });
  },

  // 找回密码：邮箱验证码 → 设置新密码
  async forgot(el) {
    el.innerHTML = `
      <div class="view">
        <form class="card form-card" id="forgot-form">
          <h2>${t('forgot.title')}</h2>
          <p class="form-tip">${t('forgot.tip')}</p>
          <div class="field">
            <label>${t('forgot.email')}</label>
            <div class="code-row">
              <input name="email" type="email" required maxlength="120" autocomplete="email" placeholder="you@example.com">
              <button type="button" class="btn btn-ghost btn-sm" id="forgot-send">${t('msg.sendCode')}</button>
            </div>
          </div>
          <div class="field"><label>${t('forgot.code')}</label><input name="code" required maxlength="6" inputmode="numeric" pattern="\\d{6}" placeholder="${t('reg.codePh')}"></div>
          <div class="field">
            <label>${t('settings.newPwd')}</label>
            <input name="password" type="password" required minlength="8" maxlength="72" autocomplete="new-password" id="forgot-pw">
            <div class="pw-meter"><i id="forgot-pw-bar"></i></div>
            <div class="pw-hint" id="forgot-pw-hint"></div>
          </div>
          <div class="field"><label>${t('settings.confirmPwd')}</label><input name="password2" type="password" required maxlength="72" autocomplete="new-password" placeholder="${t('forgot.newPwdPh')}"></div>
          ${captchaFieldHtml()}
          <button class="btn btn-primary" style="width:100%">${t('forgot.submit')}</button>
          <p class="form-foot">${t('forgot.remembered')}<a href="#/login">${t('forgot.backLogin')}</a></p>
        </form>
      </div>`;

    // 密码强度条（与注册页一致）
    await loadCaptcha(el);
    const pw = $('#forgot-pw', el), bar = $('#forgot-pw-bar', el), hint = $('#forgot-pw-hint', el);
    pw.addEventListener('input', () => {
      const v = pw.value;
      const kinds = [/[a-z]/.test(v), /[A-Z]/.test(v), /\d/.test(v), /[^A-Za-z0-9]/.test(v)].filter(Boolean).length;
      const ok = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{8,72}$/.test(v);
      let text = '';
      if (!v) text = '';
      else if (!ok) text = v.length < 8 ? t('pwd.tooShort') : t('pwd.needKinds');
      else if (kinds >= 4 || v.length >= 14) text = t('pwd.strong');
      else text = t('pwd.ok');
      bar.style.width = ok ? (kinds >= 4 || v.length >= 14 ? '100%' : '66%') : (v.length >= 8 ? '33%' : '10%');
      bar.className = ok ? (kinds >= 4 || v.length >= 14 ? 's-strong' : 's-mid') : 's-weak';
      hint.textContent = text;
    });

    // 发送验证码 + 60 秒倒计时
    const sendBtn = $('#forgot-send', el);
    sendBtn.addEventListener('click', async () => {
      const email = $('input[name="email"]', el).value.trim();
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return toast(t('msg.needCorrectEmail'));
      sendBtn.disabled = true; sendBtn.textContent = t('msg.sending');
      try {
        const r = await api('/auth/send-code', { method: 'POST', body: {
          email, purpose: 'reset',
          captchaId: $('input[name="captchaId"]', el).value,
          captcha: $('input[name="captcha"]', el).value,
        } });
        toast(r.message || t('msg.codeSent'));
        if (r.dev) toast(t('msg.devCode', { code: r.devCode }));
        // 图形验证码已被消费，换新一张避免用户拿着失效的码提交
        $('input[name="captcha"]', el).value = '';
        await loadCaptcha(el);
      } catch (e) {
        toast(e.message);
        sendBtn.disabled = false; sendBtn.textContent = t('msg.sendCode');
        $('input[name="captcha"]', el).value = '';
        await loadCaptcha(el);
        return;
      }
      let wait = 60;
      const tick = setInterval(() => {
        sendBtn.textContent = t('msg.resendIn', { n: wait });
        if (--wait < 0) { clearInterval(tick); sendBtn.disabled = false; sendBtn.textContent = t('msg.sendCode'); }
      }, 1000);
    });

    $('#forgot-form', el).addEventListener('submit', async (e) => {
      e.preventDefault();
      const f = e.target;
      if (!/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{8,72}$/.test(f.password.value)) {
        return toast(t('msg.pwdWeak'));
      }
      if (f.password.value !== f.password2.value) return toast(t('msg.pwdMismatch'));
      try {
        await api('/auth/reset-password', { method: 'POST', body: {
          email: f.email.value, code: f.code.value, password: f.password.value,
        } });
        toast(t('msg.pwdReset'));
        location.hash = '#/login';
      } catch (err) { toast(err.message); }
    });
  },

  // 已登录后访问登录/注册页：显示提示卡而不是表单
  loggedInNotice(el) {
    const u = Auth.user;
    el.innerHTML = `
      <div class="view">
        <div class="card form-card" style="text-align:center">
          <div style="font-size:40px">✨</div>
          <h2>${t('loggedin.title')}</h2>
          <p style="color:var(--text-soft);font-size:14px;margin:10px 0 18px">
            ${t('loggedin.identity')}<b>${esc(u.username)}</b>${u.role === 'admin' ? t('menu.adminBadge') : ''}
          </p>
          <div style="display:flex;gap:10px;justify-content:center;flex-wrap:wrap">
            <a href="#/" class="btn btn-primary btn-sm">${t('loggedin.home')}</a>
            ${u.role === 'admin' ? `<a href="#/admin" class="btn btn-ghost btn-sm">${t('admin.enter')}</a>` : ''}
            <button class="btn btn-ghost btn-sm" id="switch-logout">${t('loggedin.switch')}</button>
          </div>
        </div>
      </div>`;
    $('#switch-logout', el).addEventListener('click', () => { confirmLogout(); });
  },

  async register(el) {
    if (Auth.user) return Views.loggedInNotice(el);
    el.innerHTML = `
      <div class="view">
        <form class="card form-card" id="reg-form">
          <h2>${t('reg.title')}</h2>
          <div class="field"><label>${t('reg.username')}</label><input name="username" required maxlength="32" autocomplete="username"></div>
          <div class="field">
            <label>${t('auth.email')}</label>
            <div class="code-row">
              <input name="email" type="email" required maxlength="120" autocomplete="email" placeholder="${t('reg.emailPh')}">
              <button type="button" class="btn btn-ghost btn-sm" id="send-code">${t('msg.sendCode')}</button>
            </div>
          </div>
          <div class="field"><label>${t('forgot.code')}</label><input name="code" required maxlength="6" inputmode="numeric" pattern="\\d{6}" placeholder="${t('reg.codePh')}"></div>
          <div class="field">
            <label>${t('reg.pwd')}</label>
            <input name="password" type="password" required minlength="8" maxlength="72" autocomplete="new-password" id="reg-pw">
            <div class="pw-meter"><i id="pw-bar"></i></div>
            <div class="pw-hint" id="pw-hint"></div>
          </div>
          <div class="field"><label>${t('reg.confirmPwd')}</label><input name="password2" type="password" required maxlength="72" autocomplete="new-password" placeholder="${t('reg.confirmPwdPh')}"></div>
          <label class="agree-row"><input type="checkbox" id="reg-agree" required><span>${t('login.agreePrefix')}<a href="#/terms" class="terms-link" target="_blank">${t('terms.link')}</a></span></label>
          ${captchaFieldHtml()}
          <button class="btn btn-primary" id="reg-btn" style="width:100%">${t('reg.submit')}</button>
          <p class="form-foot">${t('reg.hasAccount')}<a href="#/login">${t('reg.loginNow')}</a></p>
        </form>
      </div>`;
    await loadCaptcha(el);

    // 密码强度条（弱/中/强）
    const pw = $('#reg-pw', el), bar = $('#pw-bar', el), hint = $('#pw-hint', el);
    pw.addEventListener('input', () => {
      const v = pw.value;
      const kinds = [/[a-z]/.test(v), /[A-Z]/.test(v), /\d/.test(v), /[^A-Za-z0-9]/.test(v)].filter(Boolean).length;
      let score = 0, text = '';
      if (v.length >= 8) score = kinds; else score = v.length ? 1 : 0;
      const ok = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{8,72}$/.test(v);
      if (!v) { text = ''; }
      else if (!ok) { text = v.length < 8 ? t('pwd.tooShort') : t('pwd.needKinds'); }
      else if (kinds >= 4 || v.length >= 14) { text = t('pwd.strong'); }
      else { text = t('pwd.ok'); }
      bar.style.width = ok ? (kinds >= 4 || v.length >= 14 ? '100%' : '66%') : (v.length >= 8 ? '33%' : '10%');
      bar.className = ok ? (kinds >= 4 || v.length >= 14 ? 's-strong' : 's-mid') : 's-weak';
      hint.textContent = text;
    });

    // 条款链接：弹出条款弹窗，不跳页、不误触勾选框
    const tl = $('.terms-link', el);
    if (tl) tl.addEventListener('click', (e) => {
      e.preventDefault(); e.stopPropagation();
      Terms.show('view');
    });

    // 发送验证码 + 60 秒倒计时
    const sendBtn = $('#send-code', el);
    sendBtn.addEventListener('click', async () => {
      const email = $('input[name="email"]', el).value.trim();
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return toast(t('msg.needCorrectEmail'));
      sendBtn.disabled = true; sendBtn.textContent = t('msg.sending');
      try {
        const r = await api('/auth/send-code', { method: 'POST', body: {
          email,
          captchaId: $('input[name="captchaId"]', el).value,
          captcha: $('input[name="captcha"]', el).value,
        } });
        toast(r.message || t('msg.codeSent'));
        if (r.dev) toast(t('msg.devCode', { code: r.devCode }));
        // 图形验证码已被消费：提交注册时还要再验一次，这里直接换新一张并清空输入
        $('input[name="captcha"]', el).value = '';
        await loadCaptcha(el);
      } catch (e) {
        toast(e.message);
        sendBtn.disabled = false; sendBtn.textContent = t('msg.sendCode');
        $('input[name="captcha"]', el).value = '';
        await loadCaptcha(el);
        return;
      }
      let wait = 60;
      const tick = setInterval(() => {
        sendBtn.textContent = t('msg.resendIn', { n: wait });
        if (--wait < 0) { clearInterval(tick); sendBtn.disabled = false; sendBtn.textContent = t('msg.sendCode'); }
      }, 1000);
    });

    $('#reg-form', el).addEventListener('submit', async (e) => {
      e.preventDefault();
      const f = e.target;
      const btn = $('#reg-btn', el);
      if (!/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{8,72}$/.test(f.password.value)) {
        return toast(t('msg.pwdWeak'));
      }
      if (f.password.value !== f.password2.value) return toast(t('msg.pwdMismatch'));
      btn.disabled = true; btn.textContent = t('msg.registering');
      try {
        const r = await api('/auth/register', { method: 'POST', body: {
          username: f.username.value, email: f.email.value, password: f.password.value,
          code: f.code.value, agree: true,
          captchaId: f.captchaId.value, captcha: f.captcha.value,
        } });
        Auth.user = r.user; Auth.renderChip();
        // 注册时已勾选同意条款，标记为已同意，避免进入其它页面再被拦截层打断
        localStorage.setItem('wo-terms-ok', '1');
        toast(t('msg.registerOk'));
        // 注册成功即新用户：立即检查并弹出置顶公告
        checkAnnouncements();
        location.hash = '#/';
      } catch (err) {
        toast(err.message);
        btn.disabled = false; btn.textContent = t('reg.submit');
        f.captcha.value = '';
        await loadCaptcha(el);
      }
    });
  },

  async admin(el) {
    if (!Auth.user) { location.hash = '#/login'; return; }
    if (Auth.user.role !== 'admin' && Auth.user.role !== 'owner') { el.innerHTML = `<div class="view"><div class="empty"><span class="big">🚫</span>${t('admin.needPermission')}</div></div>`; return; }
    const section = location.hash.split('/')[2] || 'dashboard';
    el.innerHTML = `
      <div class="view admin-layout">
        <aside class="card admin-side">
          <a href="#/admin/dashboard" class="${section === 'dashboard' ? 'active' : ''}">${t('admin.dashboard')}</a>
          <a href="#/admin/articles" class="${section === 'articles' ? 'active' : ''}">${t('admin.articles')}</a>
          <a href="#/admin/images" class="${section === 'images' ? 'active' : ''}">${t('admin.images')}</a>
          <a href="#/admin/projects" class="${section === 'projects' ? 'active' : ''}">${t('admin.projects')}</a>
          <a href="#/admin/comments" class="${section === 'comments' ? 'active' : ''}">${t('admin.comments')}</a>
          <a href="#/admin/sponsors" class="${section === 'sponsors' ? 'active' : ''}">${t('admin.sponsors')}</a>
          <a href="#/admin/social" class="${section === 'social' ? 'active' : ''}">${t('admin.social')}</a>
          <a href="#/admin/users" class="${section === 'users' ? 'active' : ''}">${t('admin.users')}</a>
          <a href="#/admin/announcements" class="${section === 'announcements' ? 'active' : ''}">${t('admin.announcements')}</a>
          <a href="#/admin/ipban" class="${section === 'ipban' ? 'active' : ''}">${t('admin.ipban')}</a>
          <a href="#/admin/terms" class="${section === 'terms' ? 'active' : ''}">${t('admin.terms')}</a>
          <a href="#/admin/settings" class="${section === 'settings' ? 'active' : ''}">${t('admin.settings')}</a>
          <a href="#/admin/community" class="${section === 'community' ? 'active' : ''}">${t('admin.community')}</a>
        </aside>
        <div class="card admin-panel" id="admin-panel">${t('common.loading')}</div>
      </div>`;
    const view = AdminViews[section] || AdminViews.dashboard;
    await view($('#admin-panel', el));
  },
};

// ---------- 头像裁剪器（拖动选区 + 缩放，输出正方形 JPEG） ----------
const Cropper = {
  open(file) {
    // 用 DataURL 而非 blob URL（CSP img-src 对 blob: 曾拦截导致"图片读取失败"）
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => {
        const img = new Image();
        img.onload = () => this.build(img, resolve, reject);
        img.onerror = () => reject(new Error(t('crop.decodeFail')));
        img.src = reader.result;
      };
      reader.onerror = () => reject(new Error(t('msg.readFail')));
      reader.readAsDataURL(file);
    });
  },

  build(img, resolve, reject) {
    const SIZE = 300;                 // 舞台尺寸
    const BOX = 200;                  // 裁剪框（圆形选择区）直径
    const mask = document.createElement('div');
    mask.className = 'modal-mask';
    mask.innerHTML = `
      <div class="modal card">
        <h2>${t('crop.title')}</h2>
        <div class="crop-wrap">
          <div class="crop-stage" id="crop-stage">
            <img id="crop-img" alt="${t('crop.alt')}">
            <div class="crop-box" id="crop-box"></div>
          </div>
          <div class="crop-ctrl">
            <span style="font-size:12.5px;color:var(--text-soft)">${t('crop.zoom')}</span>
            <input type="range" id="crop-zoom" min="10" max="300" value="100">
            <span id="crop-zoom-val" style="font-size:12.5px;color:var(--text-soft)">100%</span>
          </div>
          <p class="form-tip" style="margin:0">${t('crop.tip')}</p>
        </div>
        <div class="modal-actions">
          <button class="btn btn-ghost" id="crop-cancel">${t('common.cancel')}</button>
          <button class="btn btn-primary" id="crop-ok">${t('crop.use')}</button>
        </div>
      </div>`;
    document.body.appendChild(mask);

    const stage = $('#crop-stage', mask);
    const el = $('#crop-img', mask);
    const box = $('#crop-box', mask);
    const zoom = $('#crop-zoom', mask);
    const zoomVal = $('#crop-zoom-val', mask);

    // 裁剪框居中
    box.style.width = BOX + 'px';
    box.style.height = BOX + 'px';
    box.style.left = ((SIZE - BOX) / 2) + 'px';
    box.style.top = ((SIZE - BOX) / 2) + 'px';

    el.src = img.src;
    const state = { scale: 1, x: 0, y: 0 };

    // 初始：让图片覆盖整个舞台（短边贴合）
    const fitScale = Math.max(SIZE / img.naturalWidth, SIZE / img.naturalHeight);
    state.scale = fitScale;
    state.x = (SIZE - img.naturalWidth * fitScale) / 2;
    state.y = (SIZE - img.naturalHeight * fitScale) / 2;
    zoom.value = Math.round(fitScale * 100);
    zoomVal.textContent = Math.round(fitScale * 100) + '%';

    const apply = () => {
      el.style.width = (img.naturalWidth * state.scale) + 'px';
      el.style.height = (img.naturalHeight * state.scale) + 'px';
      el.style.left = state.x + 'px';
      el.style.top = state.y + 'px';
    };
    apply();

    // 拖动
    let dragging = false, sx = 0, sy = 0, ox = 0, oy = 0;
    const down = (e) => {
      dragging = true;
      const p = e.touches ? e.touches[0] : e;
      sx = p.clientX; sy = p.clientY; ox = state.x; oy = state.y;
      e.preventDefault();
    };
    const move = (e) => {
      if (!dragging) return;
      const p = e.touches ? e.touches[0] : e;
      state.x = ox + (p.clientX - sx);
      state.y = oy + (p.clientY - sy);
      apply();
      e.preventDefault();
    };
    const up = () => { dragging = false; };
    stage.addEventListener('mousedown', down);
    window.addEventListener('mousemove', move);
    window.addEventListener('mouseup', up);
    stage.addEventListener('touchstart', down, { passive: false });
    window.addEventListener('touchmove', move, { passive: false });
    window.addEventListener('touchend', up);

    zoom.addEventListener('input', () => {
      const next = Number(zoom.value) / 100;
      // 以舞台中心为锚点缩放
      const cx = SIZE / 2, cy = SIZE / 2;
      state.x = cx - (cx - state.x) * (next / state.scale);
      state.y = cy - (cy - state.y) * (next / state.scale);
      state.scale = next;
      zoomVal.textContent = Math.round(next * 100) + '%';
      apply();
    });

    const cleanup = () => {
      window.removeEventListener('mousemove', move);
      window.removeEventListener('mouseup', up);
      window.removeEventListener('touchmove', move);
      window.removeEventListener('touchend', up);
      mask.remove();
    };

    $('#crop-cancel', mask).onclick = () => { cleanup(); reject(new Error('cancel')); };
    $('#crop-ok', mask).onclick = () => {
      // 换算：舞台坐标 → 原图坐标，按裁剪框区域绘制
      const ratio = img.naturalWidth / (img.naturalWidth * state.scale); // = 1/scale
      const sx0 = (((SIZE - BOX) / 2) - state.x) * ratio;
      const sy0 = (((SIZE - BOX) / 2) - state.y) * ratio;
      const side = BOX * ratio;
      const canvas = document.createElement('canvas');
      canvas.width = 512; canvas.height = 512;
      const ctx = canvas.getContext('2d');
      ctx.fillStyle = '#fff';
      ctx.fillRect(0, 0, 512, 512);
      ctx.drawImage(img, sx0, sy0, side, side, 0, 0, 512, 512);
      canvas.toBlob((blob) => {
        cleanup();
        if (blob) resolve(blob); else reject(new Error(t('crop.fail')));
      }, 'image/jpeg', 0.92);
    };
  },
};

// ---------- 文件选择 / 上传辅助（后台编辑器、头像裁剪共用） ----------
function pickFile(accept) {
  return new Promise((resolve) => {
    const inp = document.createElement('input');
    inp.type = 'file';
    inp.accept = accept || '';
    inp.style.display = 'none';
    document.body.appendChild(inp);
    inp.addEventListener('change', () => {
      const f = inp.files[0] || null;
      inp.remove();
      resolve(f);
    });
    inp.click();
  });
}

async function uploadAdminFile(file) {
  const fd = new FormData();
  fd.append('file', file);
  const res = await fetch('/api/admin/upload', {
    method: 'POST', headers: { 'X-Requested-With': 'WebOwn' }, body: fd, credentials: 'same-origin',
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || t('msg.uploadFailed'));
  return data.url;
}

async function uploadDoc(file, url) {
  const fd = new FormData();
  fd.append('file', file);
  const res = await fetch(url, {
    method: 'POST', headers: { 'X-Requested-With': 'WebOwn' }, body: fd, credentials: 'same-origin',
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || t('msg.importFailed'));
  return data;
}

// ---------- 管理面板 ----------
// 后台编辑态（跨渲染保持：文章 / 项目）
const AdminState = { article: null, project: null, social: null, image: null, draft: null, artMode: null, announcement: null };
// 我的收藏页：类型筛选状态（跨渲染保持）
const FavState = { filter: 'all' };

const AdminViews = {
  async dashboard(el) {
    const s = await api('/admin/stats');
    el.innerHTML = `
      <h2 style="margin-bottom:16px">${t('dash.title')}</h2>
      <div class="stat-grid">
        <div class="card stat-cell"><b>${s.articles}</b><span>${t('stat.articles')}</span></div>
        <div class="card stat-cell"><b>${s.images}</b><span>${t('stat.images')}</span></div>
        <div class="card stat-cell"><b>${s.projects}</b><span>${t('stat.projects')}</span></div>
        <div class="card stat-cell"><b>${s.users}</b><span>${t('stat.users')}</span></div>
        <div class="card stat-cell"><b>${s.comments}</b><span>${t('stat.comments')}</span></div>
        <div class="card stat-cell"><b>${s.likes}</b><span>${t('stat.likes')}</span></div>
        <div class="card stat-cell"><b>${s.totalViews}</b><span>${t('stat.views')}</span></div>
      </div>
      <p style="color:var(--text-soft);font-size:13px">${t('dash.tip')}</p>`;
  },

  async articles(el) {
    const { items } = await api('/articles?status=all&size=50');
    const ed = AdminState.article;
    const d = AdminState.draft || {};
    const mode = AdminState.artMode || (ed && ed.format === 'html' ? 'html' : 'md');
    const val = (k, fb = '') => (d[k] !== undefined ? d[k] : (ed && ed[k] !== undefined && ed[k] !== null ? ed[k] : fb));
    const body = val('content', '');
    const statusBadge = (s) => (s === 'draft'
      ? `<span class="badge badge-draft">${t('common.draft')}</span>`
      : `<span class="badge badge-live">${t('art.publishedBadge')}</span>`);

    el.innerHTML = `
      <h2 style="margin-bottom:12px">${ed ? t('art.editTitle') : t('art.newTitle')}</h2>
      <div class="mode-switch">
        <button class="btn btn-sm ${mode === 'md' ? 'btn-primary' : 'btn-ghost'}" data-mode="md">${t('art.mdMode')}</button>
        <button class="btn btn-sm ${mode === 'html' ? 'btn-primary' : 'btn-ghost'}" data-mode="html">${t('art.htmlMode')}</button>
      </div>
      <form id="art-form">
        <div class="field"><label>${t('art.fieldTitle')}</label><input name="title" required maxlength="120" value="${esc(val('title'))}"></div>
        <div class="field"><label>${t('art.fieldSummary')}</label><input name="summary" maxlength="300" value="${esc(val('summary'))}"></div>
        <div class="field"><label>${t('art.fieldCover')}</label><input name="cover" maxlength="300" value="${esc(val('cover'))}"></div>
        <div class="field"><label>${t('art.fieldTags')}</label><input name="tags" maxlength="200" value="${esc(val('tags'))}"></div>
        <div class="field">
          <label>${t('art.fieldStatus')}</label>
          <select name="status">
            <option value="published"${val('status', 'published') === 'draft' ? '' : ' selected'}>${t('art.statusPublish')}</option>
            <option value="draft"${val('status', 'published') === 'draft' ? ' selected' : ''}>${t('art.statusDraft')}</option>
          </select>
        </div>
        ${mode === 'md' ? `
        <div class="field">
          <label>${t('art.contentMd')}</label>
          <div class="editor-toolbar">
            <button type="button" class="tb" data-md="bold" title="${t('tb.bold')}"><b>B</b></button>
            <button type="button" class="tb" data-md="italic" title="${t('tb.italic')}"><i>I</i></button>
            <button type="button" class="tb" data-md="h2" title="${t('tb.h2')}">H2</button>
            <button type="button" class="tb" data-md="h3" title="${t('tb.h3')}">H3</button>
            <button type="button" class="tb" data-md="quote" title="${t('tb.quote')}">❝</button>
            <button type="button" class="tb" data-md="code" title="${t('tb.code')}">&lt;/&gt;</button>
            <button type="button" class="tb" data-md="list" title="${t('tb.ul')}">• ${t('tb.ul')}</button>
            <button type="button" class="tb" data-md="link" title="${t('tb.link')}">🔗</button>
            <button type="button" class="tb" data-md="image" title="${t('tb.image')}">🖼</button>
          </div>
          <textarea name="content" id="md-editor" rows="14" required>${esc(body)}</textarea>
          <div class="import-row">
            <button type="button" class="btn btn-ghost btn-sm" id="import-md">${t('art.importMd')}</button>
            <button type="button" class="btn btn-ghost btn-sm" id="md-image">${t('art.uploadImg')}</button>
            <input type="file" id="md-file" accept=".md,.markdown,.txt" hidden>
            <input type="file" id="md-img-file" accept="image/*" hidden>
          </div>
        </div>` : `
        <div class="field">
          <label>${t('art.contentHtml')}</label>
          <div class="editor-toolbar" id="rt-toolbar">
            <button type="button" class="tb" data-cmd="bold" title="${t('tb.bold')}"><b>B</b></button>
            <button type="button" class="tb" data-cmd="italic" title="${t('tb.italic')}"><i>I</i></button>
            <button type="button" class="tb" data-cmd="underline" title="${t('tb.underline')}"><u>U</u></button>
            <button type="button" class="tb" data-cmd="strikeThrough" title="${t('tb.strike')}"><s>S</s></button>
            <span class="tb-sep"></span>
            <button type="button" class="tb" data-cmd="formatBlock" data-val="h2" title="${t('tb.h2')}">H2</button>
            <button type="button" class="tb" data-cmd="formatBlock" data-val="h3" title="${t('tb.h3')}">H3</button>
            <button type="button" class="tb" data-cmd="formatBlock" data-val="blockquote" title="${t('tb.quote')}">❝ ${t('tb.quote')}</button>
            <button type="button" class="tb" data-cmd="insertUnorderedList" title="${t('tb.ul')}">• ${t('tb.ul')}</button>
            <button type="button" class="tb" data-cmd="insertOrderedList" title="${t('tb.ol')}">1. ${t('tb.ol')}</button>
            <span class="tb-sep"></span>
            <select id="tb-size" class="tb-select" title="${t('tb.size')}">
              <option value="">${t('tb.size')}</option>
              <option value="1">${t('tb.xs')}</option><option value="2">${t('tb.sm')}</option>
              <option value="3">${t('tb.md')}</option><option value="4">${t('tb.lg')}</option>
              <option value="5">${t('tb.xl')}</option><option value="6">${t('tb.xxl')}</option>
            </select>
            <input type="color" id="tb-color" class="tb-color" title="${t('tb.color')}" value="#b863d9">
            <button type="button" class="tb" data-cmd="foreColor" data-from="tb-color" title="${t('tb.color')}">${t('tb.applyColor')}</button>
            <span class="tb-sep"></span>
            <button type="button" class="tb" data-cmd="createLink" title="${t('tb.link')}">🔗</button>
            <button type="button" class="tb" id="rt-image" title="${t('tb.image')}">🖼</button>
            <button type="button" class="tb" data-cmd="removeFormat" title="${t('tb.clear')}">🧹</button>
          </div>
          <div id="rt-editor" class="rt-editor" contenteditable="true">${body}</div>
          <input type="hidden" name="content" id="rt-content" value="">
          <div class="import-row">
            <button type="button" class="btn btn-ghost btn-sm" id="import-doc">${t('art.importDoc')}</button>
            <input type="file" id="doc-file" accept=".docx" hidden>
          </div>
        </div>`}
        <button class="btn btn-primary btn-sm">${ed ? t('common.save') : t('art.publishBtn')}</button>
        ${ed ? `<button type="button" class="btn btn-ghost btn-sm" id="art-cancel">${t('art.cancelEdit')}</button>` : ''}
      </form>
      <h3 class="section-title">${t('common.allArticles')}</h3>
      <table class="admin-table"><thead><tr><th>${t('art.tblTitle')}</th><th>${t('art.tblStatus')}</th><th>${t('art.tblFormat')}</th><th>${t('art.tblViews')}</th><th>${t('art.tblTime')}</th><th>${t('col.actions')}</th></tr></thead>
      <tbody>${items.map((a) => `
        <tr><td><a href="#/article/${esc(a.slug)}">${esc(a.title)}</a></td>
        <td>${statusBadge(a.status)}</td><td>${a.format === 'html' ? t('art.fmtRich') : 'Markdown'}</td>
        <td>${a.views}</td><td>${fmtTime(a.created_at)}</td>
        <td>
          <button class="btn btn-ghost btn-sm" data-edit="${a.id}">${t('common.edit')}</button>
          <button class="btn btn-danger btn-sm" data-del="${a.id}">${t('common.delete')}</button>
        </td></tr>`).join('') || `<tr><td colspan="6">${t('art.noArticles')}</td></tr>`}</tbody></table>`;

    // ---------- 模式切换（先保存草稿再重渲染） ----------
    const collect = () => {
      const f = $('#art-form', el);
      const draft = {
        title: f.title.value, summary: f.summary.value, cover: f.cover.value,
        tags: f.tags.value, status: f.status.value,
      };
      if (mode === 'html') {
        draft.content = $('#rt-editor', el).innerHTML;
        draft.format = 'html';
      } else {
        draft.content = f.content.value;
        draft.format = 'md';
      }
      AdminState.draft = draft;
    };

    $$('[data-mode]', el).forEach((b) => b.addEventListener('click', () => {
      if (b.dataset.mode === mode) return;
      collect();
      AdminState.artMode = b.dataset.mode;
      if (AdminState.artMode === 'html' && AdminState.draft) AdminState.draft.format = 'html';
      renderRoute();
    }));

    // ---------- 富文本工具栏 ----------
    const rtEditor = $('#rt-editor', el);
    if (rtEditor) {
      rtEditor.innerHTML = body || '<p><br></p>';
      $$('#rt-toolbar [data-cmd]', el).forEach((b) => b.addEventListener('click', () => {
        rtEditor.focus();
        const cmd = b.dataset.cmd;
        let value = null;
        if (cmd === 'foreColor') value = $('#tb-color', el).value;
        else if (cmd === 'formatBlock') value = b.dataset.val;
        else if (cmd === 'createLink') {
          value = prompt(t('dlg.promptLink'), 'https://');
          if (!value) return;
        }
        document.execCommand(cmd, false, value);
      }));
      const sizeSel = $('#tb-size', el);
      if (sizeSel) sizeSel.addEventListener('change', () => {
        rtEditor.focus();
        document.execCommand('fontSize', false, sizeSel.value);
        sizeSel.value = '';
      });
      $('#rt-image', el).addEventListener('click', async () => {
        const file = await pickFile('image/*');
        if (!file) return;
        try {
          const url = await uploadAdminFile(file);
          rtEditor.focus();
          document.execCommand('insertHTML', false, `<img src="${url}" alt="${t('md.imageAlt')}" style="max-width:100%;border-radius:10px">`);
          toast(t('msg.imgInserted'));
        } catch (err) { toast(err.message); }
      });
      $('#import-doc', el).addEventListener('click', () => $('#doc-file', el).click());
      $('#doc-file', el).addEventListener('change', async (e) => {
        const file = e.target.files[0];
        if (!file) return;
        try {
          const r = await uploadDoc(file, '/api/admin/articles/import');
          AdminState.draft = { ...(AdminState.draft || {}), title: $('#art-form', el).title.value || r.title, content: r.content };
          AdminState.artMode = 'html';
          toast(t('msg.docImported'));
          renderRoute();
        } catch (err) { toast(err.message); }
      });
    }

    // ---------- Markdown 模式辅助 ----------
    const mdEditor = $('#md-editor', el);
    if (mdEditor) {
      const wrap = (before, after = before, placeholder = t('md.ph')) => {
        const s = mdEditor.selectionStart, e = mdEditor.selectionEnd;
        const sel = mdEditor.value.slice(s, e) || placeholder;
        mdEditor.value = mdEditor.value.slice(0, s) + before + sel + after + mdEditor.value.slice(e);
        mdEditor.focus();
        mdEditor.setSelectionRange(s + before.length, s + before.length + sel.length);
      };
      const linePrefix = (prefix) => {
        const s = mdEditor.selectionStart;
        const lineStart = mdEditor.value.lastIndexOf('\n', s - 1) + 1;
        mdEditor.value = mdEditor.value.slice(0, lineStart) + prefix + mdEditor.value.slice(lineStart);
        mdEditor.focus();
      };
      $$('[data-md]', el).forEach((b) => b.addEventListener('click', () => {
        switch (b.dataset.md) {
          case 'bold': wrap('**'); break;
          case 'italic': wrap('*'); break;
          case 'h2': linePrefix('## '); break;
          case 'h3': linePrefix('### '); break;
          case 'quote': linePrefix('> '); break;
          case 'code': wrap('\n```\n', '\n```\n', t('md.codePh')); break;
          case 'list': linePrefix('- '); break;
          case 'link': wrap('[', '](https://)', t('md.linkPh')); break;
          case 'image': wrap('![', '](' + t('md.imageLinkPh') + ')', t('md.imagePh')); break;
        }
      }));
      $('#import-md', el).addEventListener('click', () => $('#md-file', el).click());
      $('#md-file', el).addEventListener('change', async (e) => {
        const file = e.target.files[0];
        if (!file) return;
        try {
          const r = await uploadDoc(file, '/api/admin/articles/import');
          mdEditor.value = r.content;
          if (!$('#art-form', el).title.value) $('#art-form', el).title.value = r.title;
          toast(t('msg.mdImported'));
        } catch (err) { toast(err.message); }
      });
      $('#md-image', el).addEventListener('click', async () => {
        const file = await pickFile('image/*');
        if (!file) return;
        try {
          const url = await uploadAdminFile(file);
          const s = mdEditor.selectionStart;
          mdEditor.value = mdEditor.value.slice(0, s) + `![${t('md.imageAlt')}](${url})` + mdEditor.value.slice(s);
          toast(t('msg.linkInserted'));
        } catch (err) { toast(err.message); }
      });
    }

    $('#art-form', el).addEventListener('submit', async (e) => {
      e.preventDefault();
      const f = e.target;
      if (mode === 'html') $('#rt-content', el).value = $('#rt-editor', el).innerHTML;
      const payload = {
        title: f.title.value, summary: f.summary.value, cover: f.cover.value,
        tags: f.tags.value, content: f.content.value, status: f.status.value,
        format: mode === 'html' ? 'html' : 'md',
      };
      try {
        if (AdminState.article) {
          await api(`/admin/articles/${AdminState.article.id}`, { method: 'PUT', body: payload });
          AdminState.article = null;
          toast(t('msg.saved'));
        } else {
          if (!(await confirmDialog({ title: t('dlg.publishArticle'), message: t('dlg.publishArticleMsg'), confirmText: t('dlg.publishBtn'), cancelText: t('dlg.rethink') }))) return;
          await api('/admin/articles', { method: 'POST', body: payload });
          toast(t('msg.articlePublished'));
        }
        AdminState.draft = null;
        AdminState.artMode = null;
        renderRoute();
      } catch (err) { toast(err.message); }
    });

    const cancelBtn = $('#art-cancel', el);
    if (cancelBtn) cancelBtn.addEventListener('click', () => {
      AdminState.article = null; AdminState.draft = null; AdminState.artMode = null;
      renderRoute();
    });

    $$('[data-edit]', el).forEach((b) => b.addEventListener('click', async () => {
      try {
        const { article } = await api(`/admin/articles/${b.dataset.edit}`);
        AdminState.article = article;
        AdminState.draft = null;
        AdminState.artMode = article.format === 'html' ? 'html' : 'md';
        renderRoute();
        toast(t('msg.editing', { title: article.title }));
      } catch (err) { toast(err.message); }
    }));

    $$('[data-del]', el).forEach((b) => b.addEventListener('click', () => adminDelete(b, {
      url: `/admin/articles/${b.dataset.del}`,
      title: t('dlg.delArticle'), message: t('dlg.delArticleMsg'),
      // 删掉的正是当前正在编辑的那篇时必须清空编辑态，否则表单继续显示已删除文章的
      // 标题/正文，看起来就像"删除了却没刷新"。
      onCleared: () => {
        if (AdminState.article && String(AdminState.article.id) === String(b.dataset.del)) {
          AdminState.article = null; AdminState.draft = null; AdminState.artMode = null;
        }
      },
    })));
  },

  async images(el) {
    // status=all：站长后台需看到「已隐藏」的图（前台图库会自动过滤它们）
    const { items } = await api('/images?size=36&status=all');
    const ed = AdminState.image;
    el.innerHTML = `
      <h2 style="margin-bottom:16px">${ed ? t('img.editTitle') : t('img.title')}</h2>
      ${ed ? `<p class="form-tip">${t('img.editing', { title: esc(ed.title || ('#' + ed.id)) })}</p>` : ''}
      <form id="img-form">
        <div class="field"><label>${t('img.pick')}${ed ? `（${t('img.keepCurrent')}）` : ''}</label><input type="file" name="file" accept="image/*"${ed ? '' : ' required'}></div>
        <div class="field"><label>${t('img.fieldTitle')}</label><input name="title" maxlength="120" value="${esc(ed ? ed.title : '')}"></div>
        <div class="field"><label>${t('img.fieldDesc')}</label><textarea name="description" rows="2" maxlength="500">${esc(ed ? (ed.description || '') : '')}</textarea></div>
        ${ed ? `<label class="switch-row inline"><span>${t('img.hidden')}</span><input type="checkbox" name="hidden" ${ed.hidden ? 'checked' : ''}></label><p class="form-tip">${t('img.hiddenTip')}</p>` : ''}
        <div style="display:flex;gap:10px;align-items:center">
          <button class="btn btn-primary btn-sm">${ed ? t('common.save') : t('img.uploadBtn')}</button>
          ${ed ? `<button type="button" class="btn btn-ghost btn-sm" id="img-cancel">${t('common.cancel')}</button>` : ''}
        </div>
      </form>
      <h3 class="section-title">${t('common.uploaded')}</h3>
      <table class="admin-table"><thead><tr><th>${t('img.tblPreview')}</th><th>${t('img.fieldTitle')}</th><th>${t('common.desc')}</th><th>${t('common.time')}</th><th>${t('col.actions')}</th></tr></thead>
      <tbody>${items.map((im) => `
        <tr><td><img src="/uploads/${esc(im.filename)}" style="width:60px;height:40px;object-fit:cover" loading="lazy"></td>
        <td>${esc(im.title)}${im.hidden ? ` <span class="warn-tag">${t('img.hiddenTag')}</span>` : ''}</td><td style="max-width:220px;font-size:12.5px;color:var(--text-soft)">${esc(im.description || '')}</td><td>${fmtTime(im.created_at)}</td>
        <td>
          <button class="btn btn-ghost btn-sm" data-edit="${im.id}">${t('common.edit')}</button>
          <button class="btn btn-ghost btn-sm" data-hide="${im.id}" data-next="${im.hidden ? 0 : 1}">${im.hidden ? t('img.show') : t('img.hide')}</button>
          <button class="btn btn-danger btn-sm" data-del="${im.id}">${t('common.delete')}</button>
        </td></tr>`).join('') || `<tr><td colspan="5">${t('empty.images')}</td></tr>`}</tbody></table>`;

    $('#img-form', el).addEventListener('submit', async (e) => {
      e.preventDefault();
      const f = e.target;
      const fd = new FormData();
      // 编辑模式：未选新文件则保留原图
      if (f.file.files[0]) fd.append('file', f.file.files[0]);
      // 两个文本字段始终提交：后端按"传了就覆盖、没传就保留"处理，
      // 这样既能改，也能真正把标题/描述清空（旧写法只在非空时才提交，导致清不掉）
      fd.append('title', f.title.value);
      fd.append('description', f.description.value);
      // 隐藏开关：编辑态存在该字段时提交，让「历史赞助二维码」可从前台图库下架
      if (f.hidden) fd.append('hidden', f.hidden.checked ? '1' : '0');
      try {
        if (ed) {
          const res = await fetch('/api/admin/images/' + ed.id, { method: 'PUT', headers: { 'X-Requested-With': 'WebOwn' }, body: fd, credentials: 'same-origin' });
          const data = await res.json().catch(() => ({}));
          if (!res.ok) throw new Error(data.error || t('msg.saveFailed'));
          toast(t('msg.saved'));
        } else {
          if (!(await confirmDialog({ title: t('dlg.uploadImg'), message: t('dlg.uploadImgMsg'), confirmText: t('common.upload'), cancelText: t('common.cancel') }))) return;
          const res = await fetch('/api/admin/upload', { method: 'POST', headers: { 'X-Requested-With': 'WebOwn' }, body: fd, credentials: 'same-origin' });
          const data = await res.json();
          if (!res.ok) throw new Error(data.error || t('msg.uploadFailed'));
          toast(t('msg.uploadOk'));
        }
        AdminState.image = null;
        renderRoute();
      } catch (err) { toast(err.message); }
    });

    const cancel = $('#img-cancel', el);
    if (cancel) cancel.addEventListener('click', () => { AdminState.image = null; renderRoute(); });

    $$('[data-edit]', el).forEach((b) => b.addEventListener('click', async () => {
      try {
        const { image } = await api(`/admin/images/${b.dataset.edit}`);
        AdminState.image = image;
        renderRoute();
      } catch (err) { toast(err.message); }
    }));

    $$('[data-hide]', el).forEach((b) => b.addEventListener('click', async () => {
      const fd = new FormData();
      fd.append('hidden', b.dataset.next);
      try {
        const res = await fetch('/api/admin/images/' + b.dataset.hide, { method: 'PUT', headers: { 'X-Requested-With': 'WebOwn' }, body: fd, credentials: 'same-origin' });
        const data = await res.json().catch(() => ({}));
        if (!res.ok) throw new Error(data.error || t('msg.saveFailed'));
        toast(b.dataset.next === '1' ? t('img.hiddenOk') : t('img.shownOk'));
        renderRoute();
      } catch (err) { toast(err.message); }
    }));

    $$('[data-del]', el).forEach((b) => b.addEventListener('click', () => adminDelete(b, {
      url: `/admin/images/${b.dataset.del}`,
      title: t('dlg.delImage'), message: t('dlg.delImageMsg'),
      // 删掉的正是正在编辑的那张：清空编辑态，避免表单残留已删除图片
      onCleared: () => { if (AdminState.image && String(AdminState.image.id) === String(b.dataset.del)) AdminState.image = null; },
    })));
  },

  // 后台发布项目：做成 GitHub 仓库「New repository / Settings」风格的分区表单，
  // 与前台项目页一一对应（图标 + owner/repo + 描述 + 话题 + 主页），并带实时预览。
  async projects(el) {
    const { items } = await api('/projects');
    const ed = AdminState.project;
    el.innerHTML = `
      <h2 style="margin-bottom:6px">${ed ? t('prj.editTitle') : t('prj.newTitle')}</h2>
      <p class="form-tip">${esc(t('prj.tip'))}</p>
      <form id="prj-form">
        <fieldset class="gh-form-sec">
          <legend>${esc(t('prj.secRepo'))}</legend>
          <div class="field"><label>${t('prj.repo')}</label>
            <input name="repo_url" required maxlength="300" placeholder="https://github.com/user/repo" value="${ed ? esc(ed.repo_url) : ''}" id="prj-repo">
          </div>
          <div class="field"><label>${t('prj.name')}</label><input name="title" required maxlength="120" value="${ed ? esc(ed.title) : ''}" id="prj-title"></div>
        </fieldset>

        <fieldset class="gh-form-sec">
          <legend>${esc(t('prj.secAbout'))}</legend>
          <div class="field"><label>${t('prj.icon')}</label>
            <div class="icon-picker">
              <input name="icon" class="icon-input" maxlength="4" value="${ed ? esc(ed.icon || '🐙') : ''}" placeholder="${t('prj.iconPh')}" id="prj-icon">
              <div class="icon-palette">${PROJECT_ICONS.map((e) => `<button type="button" class="icon-opt${ed && ed.icon === e ? ' active' : ''}" data-icon="${e}">${e}</button>`).join('')}</div>
            </div>
          </div>
          <div class="field"><label>${t('prj.desc')}</label><textarea name="description" rows="3" maxlength="1000" id="prj-desc">${ed ? esc(ed.description || '') : ''}</textarea></div>
          <div class="field"><label>${t('prj.tags')}</label><input name="tags" maxlength="200" placeholder="${esc(t('prj.topicsPh'))}" value="${ed ? esc(ed.tags || '') : ''}" id="prj-tags"></div>
          <div class="field"><label>${t('prj.homepage')}</label><input name="homepage" maxlength="300" placeholder="${esc(t('prj.homepagePh'))}" value="${ed ? esc(ed.homepage || '') : ''}"><span class="form-tip">${esc(t('prj.homepageTip'))}</span></div>
        </fieldset>

        <div class="gh-form-sec gh-preview">
          <div class="gh-preview-title">${esc(t('prj.preview'))}</div>
          <div class="gh-preview-card" id="prj-preview"></div>
        </div>

        <div style="display:flex;gap:10px;align-items:center;margin-top:4px">
          <button class="btn btn-primary btn-sm">${ed ? t('common.save') : t('prj.addBtn')}</button>
          ${ed ? `<button type="button" class="btn btn-ghost btn-sm" id="prj-cancel">${t('prj.cancelEdit')}</button>` : ''}
        </div>
      </form>
      <h3 class="section-title">${t('common.existProjects')}</h3>
      <table class="admin-table"><thead><tr><th>${t('prj.tblName')}</th><th>${t('common.repo')}</th><th>${t('col.actions')}</th></tr></thead>
      <tbody>${items.map((p) => `
        <tr><td>${esc(p.icon ? p.icon + ' ' : '🐙 ')}${esc(p.title)}</td><td><a href="${esc(p.repo_url)}" target="_blank" rel="noopener noreferrer">${esc(p.repo_url)}</a></td>
        <td>
          <button class="btn btn-ghost btn-sm" data-edit="${p.id}">${t('common.edit')}</button>
          <button class="btn btn-danger btn-sm" data-del="${p.id}">${t('common.delete')}</button>
        </td></tr>`).join('') || `<tr><td colspan="3">${t('prj.noProjects')}</td></tr>`}</tbody></table>`;

    // 预览卡片：与前台项目页头部保持一致（图标 + owner/repo + Public + 描述 + 话题）
    const drawPreview = () => {
      const box = $('#prj-preview', el);
      if (!box) return;
      const rp = parseRepo($('#prj-repo', el).value.trim()) || { owner: 'owner', repo: 'repo' };
      const icon = ($('#prj-icon', el).value.trim() || '🐙');
      const title = $('#prj-title', el).value.trim() || rp.repo || 'repo';
      const desc = $('#prj-desc', el).value.trim();
      const topics = $('#prj-tags', el).value.split(',').map((s) => s.trim()).filter(Boolean);
      box.innerHTML = `
        <div class="gh-title-row">
          <span class="gh-repo-icon">${esc(icon)}</span>
          <h1 class="gh-title"><span>${esc(rp.owner)}</span><span class="gh-slash">/</span><b>${esc(title)}</b></h1>
          <span class="gh-badge">${esc(t('gh.public'))}</span>
        </div>
        <p class="gh-desc">${esc(desc || t('prj.desc'))}</p>
        <div class="gh-topics">${topics.map((x) => `<span class="gh-topic">${esc(x)}</span>`).join('')}</div>`;
    };
    ['prj-repo', 'prj-title', 'prj-icon', 'prj-desc', 'prj-tags'].forEach((id) => {
      const n = $('#' + id, el);
      if (n) n.addEventListener('input', drawPreview);
    });
    drawPreview();

    // 图标调色板：点选即填入输入框并同步预览（也可手动输入任意 emoji）
    const iconInput = $('input[name="icon"]', el);
    $$('.icon-opt', el).forEach((b) => b.addEventListener('click', () => {
      if (iconInput) iconInput.value = b.dataset.icon;
      $$('.icon-opt', el).forEach((x) => x.classList.remove('active'));
      b.classList.add('active');
      drawPreview();
    }));
    $('#prj-form', el).addEventListener('submit', async (e) => {
      e.preventDefault();
      const f = e.target;
      const payload = {
        title: f.title.value, repo_url: f.repo_url.value, description: f.description.value,
        tags: f.tags.value, icon: (f.icon.value || '🐙').trim(), homepage: f.homepage.value,
      };
      try {
        if (AdminState.project) {
          await api(`/admin/projects/${AdminState.project.id}`, { method: 'PUT', body: payload });
          AdminState.project = null;
          toast(t('msg.prjUpdated'));
        } else {
          if (!(await confirmDialog({ title: t('dlg.addProject'), message: t('dlg.addProjectMsg'), confirmText: t('common.add'), cancelText: t('dlg.rethink') }))) return;
          await api('/admin/projects', { method: 'POST', body: payload });
          toast(t('msg.prjAdded'));
        }
        renderRoute();
      } catch (err) { toast(err.message); }
    });

    const prjCancel = $('#prj-cancel', el);
    if (prjCancel) prjCancel.addEventListener('click', () => { AdminState.project = null; renderRoute(); });

    $$('[data-edit]', el).forEach((b) => b.addEventListener('click', async () => {
      // 与文章一致：编辑前回服务端取这条的完整记录再回填表单。
      // 列表接口为了省流量可能裁剪字段（例如文章列表不带正文），
      // 直接拿列表行回填会导致"打开编辑看着是空的 → 一保存就把内容清掉"。
      try {
        const { project } = await api(`/admin/projects/${b.dataset.edit}`);
        AdminState.project = project;
        renderRoute();
      } catch (err) { toast(err.message); }
    }));

    $$('[data-del]', el).forEach((b) => b.addEventListener('click', () => adminDelete(b, {
      url: `/admin/projects/${b.dataset.del}`,
      title: t('dlg.delProject'), message: t('dlg.delProjectMsg'),
      onCleared: () => { if (AdminState.project && String(AdminState.project.id) === String(b.dataset.del)) AdminState.project = null; },
    })));
  },

  async comments(el) {
    const { items } = await api('/admin/comments');
    el.innerHTML = `
      <h2 style="margin-bottom:16px">${t('cmt.adminTitle')}</h2>
      <table class="admin-table"><thead><tr><th>${t('col.user')}</th><th>${t('cmt.tblContent')}</th><th>${t('cmt.tblTarget')}</th><th>${t('col.status')}</th><th>${t('col.actions')}</th></tr></thead>
      <tbody>${items.map((c) => `
        <tr><td>${esc(c.username)}</td><td style="max-width:280px">${esc(c.content)}</td>
        <td>${esc(c.target_type)}#${c.target_id}</td><td>${c.status === 'visible' ? t('cmt.visible') : t('cmt.hidden')}</td>
        <td>
          <button class="btn btn-ghost btn-sm" data-toggle="${c.id}" data-next="${c.status === 'visible' ? 'hidden' : 'visible'}">${c.status === 'visible' ? t('cmt.hideBtn') : t('cmt.restoreBtn')}</button>
          <button class="btn btn-danger btn-sm" data-del="${c.id}">${t('common.delete')}</button>
        </td></tr>`).join('') || `<tr><td colspan="5">${t('empty.comments')}</td></tr>`}</tbody></table>`;
    $$('[data-toggle]', el).forEach((b) => b.addEventListener('click', async () => {
      try { await api(`/admin/comments/${b.dataset.toggle}`, { method: 'PUT', body: { status: b.dataset.next } }); renderRoute(); }
      catch (err) { toast(err.message); }
    }));
    $$('[data-del]', el).forEach((b) => b.addEventListener('click', () => adminDelete(b, {
      url: `/admin/comments/${b.dataset.del}`,
      title: t('dlg.delComment'), message: t('dlg.delCommentMsg'),
    })));
  },

  async sponsors(el) {
    const { items } = await api('/sponsors');
    el.innerHTML = `
      <h2 style="margin-bottom:16px">${t('sp.adminTitle')}</h2>
      <form id="sp-form">
        <div class="field"><label>${t('sp.sponsorName')}</label><input name="name" required maxlength="60"></div>
        <div class="field"><label>${t('sp.amount')}</label><input name="amount" type="number" min="0" step="0.01"></div>
        <div class="field"><label>${t('sp.message')}</label><input name="message" maxlength="300"></div>
        <button class="btn btn-primary btn-sm">${t('sp.recordBtn')}</button>
      </form>
      <h3 class="section-title">${t('common.sponsorList')}</h3>
      <table class="admin-table"><thead><tr><th>${t('sp.tblName')}</th><th>${t('sp.tblAmount')}</th><th>${t('sp.tblMessage')}</th><th>${t('common.time')}</th><th>${t('col.actions')}</th></tr></thead>
      <tbody>${items.map((s) => `
        <tr><td>${esc(s.name)}</td><td>${s.amount ? '¥' + esc(s.amount) : '-'}</td><td>${esc(s.message)}</td><td>${fmtTime(s.created_at)}</td>
        <td><button class="btn btn-danger btn-sm" data-del="${s.id}">${t('common.delete')}</button></td></tr>`).join('') || `<tr><td colspan="5">${t('empty.records')}</td></tr>`}</tbody></table>`;
    $('#sp-form', el).addEventListener('submit', async (e) => {
      e.preventDefault();
      const f = e.target;
      try {
        if (!(await confirmDialog({ title: t('dlg.recordSponsor'), message: t('dlg.recordSponsorMsg'), confirmText: t('sp.recordBtn'), cancelText: t('common.cancel') }))) return;
        await api('/admin/sponsors', { method: 'POST', body: { name: f.name.value, amount: f.amount.value ? Number(f.amount.value) : null, message: f.message.value } });
        toast(t('msg.recorded'));
        renderRoute();
      } catch (err) { toast(err.message); }
    });
    $$('[data-del]', el).forEach((b) => b.addEventListener('click', () => adminDelete(b, {
      url: `/admin/sponsors/${b.dataset.del}`,
      title: t('dlg.delSponsor'), message: t('dlg.delSponsorMsg'),
    })));
  },

  async social(el) {
    const { items } = await api('/admin/social');
    const ed = AdminState.social;
    const opts = [['bilibili', t('plat.bilibili')], ['youtube', 'YouTube'], ['weibo', t('plat.weibo')], ['x', 'X'], ['github', 'GitHub'], ['other', t('plat.other')]];
    el.innerHTML = `
      <h2 style="margin-bottom:16px">${ed ? t('soc.editTitle') : t('soc.newTitle')}</h2>
      <form id="soc-form">
        <div class="field">
          <label>${t('soc.platform')}</label>
          <select name="platform">${opts.map(([v, t]) => `<option value="${v}"${ed && ed.platform === v ? ' selected' : ''}>${t}</option>`).join('')}</select>
        </div>
        <div class="field"><label>${t('soc.fieldTitle')}</label><input name="title" required maxlength="120" value="${ed ? esc(ed.title) : ''}" placeholder="${t('soc.titlePh')}"></div>
        <div class="field"><label>${t('soc.url')}</label><input name="url" required maxlength="300" value="${ed ? esc(ed.url) : ''}" placeholder="https://www.bilibili.com/video/BV..."></div>
        <div class="field"><label>${t('soc.desc')}</label><input name="description" maxlength="500" value="${ed ? esc(ed.description || '') : ''}"></div>
        <div class="field">
          <label>${t('soc.cover')}</label>
          <div class="code-row">
            <input name="cover" maxlength="300" value="${ed ? esc(ed.cover || '') : ''}" placeholder="${t('soc.coverPh')}">
            <button type="button" class="btn btn-ghost btn-sm" id="soc-cover">${t('soc.uploadBtn')}</button>
          </div>
        </div>
        <div class="field">
          <label>${t('soc.status')}</label>
          <select name="status">
            <option value="published"${ed && ed.status === 'draft' ? '' : ' selected'}>${t('soc.show')}</option>
            <option value="draft"${ed && ed.status === 'draft' ? ' selected' : ''}>${t('soc.hide')}</option>
          </select>
        </div>
        <button class="btn btn-primary btn-sm">${ed ? t('common.save') : t('soc.publishBtn')}</button>
        ${ed ? `<button type="button" class="btn btn-ghost btn-sm" id="soc-cancel">${t('soc.cancelEdit')}</button>` : ''}
      </form>
      <h3 class="section-title">${t('soc.exist')}</h3>
      <table class="admin-table"><thead><tr><th>${t('soc.tblPlatform')}</th><th>${t('art.tblTitle')}</th><th>${t('col.status')}</th><th>${t('common.time')}</th><th>${t('col.actions')}</th></tr></thead>
      <tbody>${items.map((s) => `
        <tr><td>${esc(s.platform)}</td><td><a href="${esc(s.url)}" target="_blank" rel="noopener noreferrer">${esc(s.title)}</a></td>
        <td>${s.status === 'draft' ? `<span class="badge badge-draft">${t('soc.badgeHide')}</span>` : `<span class="badge badge-live">${t('soc.badgeShow')}</span>`}</td>
        <td>${fmtTime(s.created_at)}</td>
        <td>
          <button class="btn btn-ghost btn-sm" data-edit="${s.id}">${t('common.edit')}</button>
          <button class="btn btn-danger btn-sm" data-del="${s.id}">${t('common.delete')}</button>
        </td></tr>`).join('') || `<tr><td colspan="5">${t('empty.socialShort')}</td></tr>`}</tbody></table>`;

    $('#soc-cover', el).addEventListener('click', async () => {
      const file = await pickFile('image/*');
      if (!file) return;
      try {
        const url = await uploadAdminFile(file);
        $('#soc-form', el).cover.value = url;
        toast(t('msg.coverUploaded'));
      } catch (err) { toast(err.message); }
    });

    $('#soc-form', el).addEventListener('submit', async (e) => {
      e.preventDefault();
      const f = e.target;
      const payload = {
        platform: f.platform.value, title: f.title.value, url: f.url.value,
        description: f.description.value, cover: f.cover.value, status: f.status.value,
      };
      try {
        if (AdminState.social) {
          await api(`/admin/social/${AdminState.social.id}`, { method: 'PUT', body: payload });
          AdminState.social = null;
          toast(t('msg.saved'));
        } else {
          if (!(await confirmDialog({ title: t('dlg.publishMoment'), message: t('dlg.publishMomentMsg'), confirmText: t('dlg.publishBtn'), cancelText: t('dlg.rethink') }))) return;
          await api('/admin/social', { method: 'POST', body: payload });
          toast(t('msg.socPublished'));
        }
        renderRoute();
      } catch (err) { toast(err.message); }
    });

    const socCancel = $('#soc-cancel', el);
    if (socCancel) socCancel.addEventListener('click', () => { AdminState.social = null; renderRoute(); });

    $$('[data-edit]', el).forEach((b) => b.addEventListener('click', async () => {
      try {
        const { social } = await api(`/admin/social/${b.dataset.edit}`);
        AdminState.social = social;
        renderRoute();
      } catch (err) { toast(err.message); }
    }));
    $$('[data-del]', el).forEach((b) => b.addEventListener('click', () => adminDelete(b, {
      url: `/admin/social/${b.dataset.del}`,
      title: t('dlg.delMoment'), message: t('dlg.delMomentMsg'),
      onCleared: () => { if (AdminState.social && String(AdminState.social.id) === String(b.dataset.del)) AdminState.social = null; },
    })));
  },

  async users(el) {
    const { items } = await api('/admin/users');
    el.innerHTML = `
      <h2 style="margin-bottom:16px">${t('admin.usersTitle')}</h2>
      <table class="admin-table"><thead><tr><th>${t('col.uid')}</th><th>${t('col.user')}</th><th>${t('col.email')}</th><th>${t('col.ip')}</th><th>${t('col.role')}</th><th>${t('col.status')}</th><th>${t('col.created')}</th><th>${t('col.lastLogin')}</th><th>${t('col.actions')}</th></tr></thead>
      <tbody>${items.map((u) => `
        <tr>
          <td class="uid-cell">${esc(u.id)}</td>
          <td>${u.avatar ? `<img src="/uploads/${esc(u.avatar)}" style="width:24px;height:24px;border-radius:50%;vertical-align:middle;margin-right:6px">` : ''}${esc(u.username)}${u.id === Auth.user.id ? ' <span class="badge badge-live">' + t('common.me') + '</span>' : ''}</td>
          <td>${esc(u.email)}</td>
          <td class="uid-cell">${u.last_ip ? esc(u.last_ip) : '<span style="color:var(--text-soft)">-</span>'}</td>
          <td>${u.role === 'admin' ? t('role.admin') : t('role.user')}</td>
          <td>${u.banned ? `<span class="badge badge-draft">${t('status.banned')}</span>${banRangeText(u)}` : `<span class="badge badge-live">${t('status.normal')}</span>`}</td>
          <td>${fmtTime(u.created_at)}</td>
          <td>${u.last_login_at ? fmtTime(u.last_login_at) : t('neverLogin')}</td>
          <td>${u.id === Auth.user.id ? `<span style="color:var(--text-soft);font-size:12px">${t('status.self')}</span>` : `
            <button class="btn btn-ghost btn-sm" data-role="${u.id}" data-next="${u.role === 'admin' ? 'user' : 'admin'}">${u.role === 'admin' ? t('user.demote') : t('user.setAdmin')}</button>
            <button class="btn btn-ghost btn-sm" data-ban="${u.id}" data-next="${u.banned ? '0' : '1'}">${u.banned ? t('user.unban') : t('user.ban')}</button>
            <button class="btn btn-ghost btn-sm" data-banip="${esc(u.last_ip || '')}">${t('user.banIp')}</button>
            <button class="btn btn-danger btn-sm" data-del="${u.id}">${t('user.delete')}</button>`}</td>
        </tr>`).join('') || `<tr><td colspan="9">${t('noUsers')}</td></tr>`}</tbody></table>
      <p class="form-tip">${t('user.banTip')}</p>`;

    $$('[data-role]', el).forEach((b) => b.addEventListener('click', async () => {
      const next = b.dataset.next === 'admin' ? t('role.admin') : t('role.user');
      if (!(await confirmDialog({ title: t('dlg.roleTitle'), message: t('dlg.roleMsg', { role: next }), confirmText: t('common.confirm'), cancelText: t('common.cancel') }))) return;
      try { await api(`/admin/users/${b.dataset.role}`, { method: 'PUT', body: { role: b.dataset.next } }); toast(t('msg.updated')); renderRoute(); }
      catch (err) { toast(err.message); }
    }));
    $$('[data-ban]', el).forEach((b) => b.addEventListener('click', async () => {
      const user = items.find((x) => String(x.id) === b.dataset.ban);
      if (!user) return;
      const res = await banDialog(user);
      if (res === null) return; // 用户取消
      try { await api(`/admin/users/${b.dataset.ban}`, { method: 'PUT', body: res }); toast(res.banned ? t('msg.banned') : t('msg.unbanned')); renderRoute(); }
      catch (err) { toast(err.message); }
    }));
    $$('[data-banip]', el).forEach((b) => b.addEventListener('click', async () => {
      const res = await ipBanDialog(b.dataset.banip);
      if (res === null) return;
      if (!res.ip) return toast(t('ipban.needIp'));
      try {
        await api('/admin/ipbans', { method: 'POST', body: { ip: res.ip, until: res.until, reason: res.reason } });
        toast(t('ipban.banned'));
        renderRoute();
      } catch (err) { toast(err.message); }
    }));
    $$('[data-del]', el).forEach((b) => b.addEventListener('click', () => adminDelete(b, {
      url: `/admin/users/${b.dataset.del}`,
      title: t('dlg.delUserTitle'), message: t('dlg.delUserMsg'),
    })));
  },

  // IP 封禁管理：新增 / 列表 / 解封 / 查看同 IP 账号
  async ipban(el) {
    const { items } = await api('/admin/ipbans');
    const now = Date.now();
    el.innerHTML = `
      <h2 style="margin-bottom:16px">${t('admin.ipbanTitle')}</h2>
      <form class="ipban-form" id="ipban-add">
        <div class="field"><label>${t('ipban.ip')}</label><input name="ip" placeholder="1.2.3.4" maxlength="64"></div>
        <div class="field"><label>${t('ipban.duration')}</label>
          <select name="hours">
            <option value="1">${t('ipban.h1')}</option>
            <option value="6">${t('ipban.h6')}</option>
            <option value="24" selected>${t('ipban.d1')}</option>
            <option value="168">${t('ipban.d7')}</option>
            <option value="720">${t('ipban.d30')}</option>
            <option value="0">${t('ban.permanent')}</option>
          </select>
        </div>
        <div class="field ipban-form-reason"><label>${t('ipban.reason')}</label><input name="reason" maxlength="200" placeholder="${esc(t('ipban.reasonPh'))}"></div>
        <button class="btn btn-danger btn-sm" type="submit">${t('ipban.confirm')}</button>
      </form>
      <table class="admin-table"><thead><tr><th>${t('col.ip')}</th><th>${t('ipban.reason')}</th><th>${t('ipban.until')}</th><th>${t('ipban.accounts')}</th><th>${t('col.created')}</th><th>${t('col.actions')}</th></tr></thead>
      <tbody>${items.map((r) => `
        <tr>
          <td class="uid-cell">${esc(r.ip)}</td>
          <td>${r.reason ? esc(r.reason) : '<span style="color:var(--text-soft)">-</span>'}</td>
          <td>${r.until ? (r.until > now ? esc(fmtTime(r.until)) : `<span class="badge badge-draft">${t('ipban.expired')}</span>`) : `<span class="badge badge-draft">${t('ban.permanent')}</span>`}</td>
          <td><button class="btn btn-ghost btn-sm" data-acc="${esc(r.ip)}">${t('ipban.viewAccounts', { n: r.accounts })}</button></td>
          <td>${fmtTime(r.created_at)}</td>
          <td><button class="btn btn-primary btn-sm" data-unban="${esc(r.ip)}">${t('ipban.unban')}</button></td>
        </tr>`).join('') || `<tr><td colspan="6">${t('ipban.empty')}</td></tr>`}</tbody></table>
      <p class="form-tip">${t('ipban.tip')}</p>`;

    $('#ipban-add', el).addEventListener('submit', async (e) => {
      e.preventDefault();
      const f = e.target;
      const ip = f.ip.value.trim();
      if (!ip) return toast(t('ipban.needIp'));
      const hours = parseInt(f.hours.value, 10) || 0;
      try {
        await api('/admin/ipbans', { method: 'POST', body: { ip, until: hours > 0 ? Date.now() + hours * 3600 * 1000 : null, reason: f.reason.value.trim() } });
        toast(t('ipban.banned')); f.reset(); renderRoute();
      } catch (err) { toast(err.message); }
    });
    $$('[data-unban]', el).forEach((b) => b.addEventListener('click', async () => {
      const ip = b.dataset.unban;
      if (!(await confirmDialog({ title: t('ipban.unbanTitle'), message: t('ipban.unbanMsg', { ip }), confirmText: t('ipban.unban'), cancelText: t('common.cancel') }))) return;
      try { await api('/admin/ipbans/' + encodeURIComponent(ip), { method: 'DELETE' }); toast(t('ipban.unbanned')); renderRoute(); }
      catch (err) { toast(err.message); }
    }));
    $$('[data-acc]', el).forEach((b) => b.addEventListener('click', async () => {
      const ip = b.dataset.acc;
      try {
        const { items: accs } = await api('/admin/ipbans/accounts?ip=' + encodeURIComponent(ip));
        const list = accs.length
          ? accs.map((u) => `<div class="ipban-acc">${u.avatar ? `<img src="/uploads/${esc(u.avatar)}" alt="">` : ''}<b>${esc(u.username)}</b><span>${esc(u.email)}</span>${u.banned ? `<span class="badge badge-draft">${t('status.banned')}</span>` : ''}</div>`).join('')
          : `<p class="form-tip">${t('ipban.noAccount')}</p>`;
        openModal({ title: t('ipban.accountsOf', { ip }), bodyHtml: list, actions: [{ label: t('common.close'), cls: 'btn-primary', onClick: (close) => close() }] });
      } catch (err) { toast(err.message); }
    }));
  },

  async settings(el) {
    const s = await api('/admin/settings');
    el.innerHTML = `
      <h2 style="margin-bottom:16px">${t('admin.settingsTitle')}</h2>
      <form id="site-form">
        <div class="field"><label>${t('site.name')}</label><input name="site_name" maxlength="60" value="${esc(s.site_name)}" placeholder="${t('site.namePh')}"></div>
        <div class="field"><label>${t('site.slogan')}</label><input name="site_slogan" maxlength="80" value="${esc(s.site_slogan)}" placeholder="${t('site.sloganPh')}"></div>
        <div class="field"><label>${t('site.footer')}</label><input name="footer_text" maxlength="200" value="${esc(s.footer_text)}" placeholder="${t('site.footerPh')}"></div>
        <div class="field"><label>${t('site.icp')}</label><input name="icp" maxlength="100" value="${esc(s.icp)}" placeholder="${t('site.icpPh')}"></div>
        <div class="field qr-field">
          <label>${t('site.qr')}</label>
          <div class="code-row">
            <input name="sponsor_qr" maxlength="300" value="${esc(s.sponsor_qr)}" placeholder="${t('site.qrPh')}">
            <button type="button" class="btn btn-primary btn-sm" id="qr-upload">${t('site.qrUpload')}</button>
          </div>
          <input type="file" id="qr-file" accept="image/*" hidden>
          ${s.sponsor_qr
            ? `<div class="qr-preview"><img src="${esc(s.sponsor_qr)}" alt="${t('site.qrAlt')}"><span>${t('site.qrCurrent')}</span></div>`
            : `<p class="form-tip">${t('site.noQr')}</p>`}
        </div>
        <button class="btn btn-primary btn-sm">${t('site.save')}</button>
      </form>`;

    $('#qr-upload', el).addEventListener('click', () => $('#qr-file', el).click());
    $('#qr-file', el).addEventListener('change', async (e) => {
      const file = e.target.files[0];
      if (!file) return;
      const fd = new FormData();
      fd.append('file', file);
      try {
        // 专用隔离端点：写入 data/private/，不进 images 表/图库/搜索；返回受控 URL
        const res = await fetch('/api/admin/site-asset/sponsor-qr', { method: 'POST', headers: { 'X-Requested-With': 'WebOwn' }, body: fd, credentials: 'same-origin' });
        const data = await res.json();
        if (!res.ok) throw new Error(data.error || t('msg.uploadFailed'));
        $('#site-form', el).sponsor_qr.value = data.url;
        $('#site-form', el).querySelector('.qr-preview')?.remove();
        toast(t('msg.uploadedRemember'));
      } catch (err) { toast(err.message); }
    });

    $('#site-form', el).addEventListener('submit', async (e) => {
      e.preventDefault();
      const f = e.target;
      try {
        await api('/admin/settings', { method: 'PUT', body: {
          site_name: f.site_name.value, site_slogan: f.site_slogan.value,
          footer_text: f.footer_text.value, icp: f.icp.value, sponsor_qr: f.sponsor_qr.value,
        } });
        await Site.load();
        toast(t('msg.siteSaved'));
        renderRoute();
      } catch (err) { toast(err.message); }
    });
  },

  async terms(el) {
    let content = '';
    try { content = (await api('/terms')).content; } catch (_) {}
    el.innerHTML = `
      <h2 style="margin-bottom:16px">${t('termsAdmin.title')}</h2>
      <p class="form-tip">${t('termsAdmin.tip')}</p>
      <form id="terms-form">
        <div class="field"><textarea name="content" rows="14">${esc(content)}</textarea></div>
        <div style="display:flex;gap:10px;flex-wrap:wrap">
          <button class="btn btn-primary btn-sm">${t('termsAdmin.save')}</button>
          <button type="button" class="btn btn-ghost btn-sm" id="terms-import">${t('termsAdmin.importServer')}</button>
          <button type="button" class="btn btn-ghost btn-sm" id="terms-pick">${t('termsAdmin.importLocal')}</button>
          <input type="file" id="terms-file" accept=".md,.txt" hidden>
        </div>
      </form>`;
    $('#terms-form', el).addEventListener('submit', async (e) => {
      e.preventDefault();
      try {
        await api('/admin/terms', { method: 'PUT', body: { content: e.target.content.value } });
        toast(t('msg.termsSaved'));
      } catch (err) { toast(err.message); }
    });
    const ta = () => $('#terms-form textarea', el);
    const importBtn = $('#terms-import', el);
    if (importBtn) importBtn.addEventListener('click', async () => {
      importBtn.disabled = true; importBtn.textContent = t('termsAdmin.importing');
      try {
        const r = await api('/admin/terms/import', { method: 'POST' });
        ta().value = (await api('/terms')).content;
        toast(t('msg.importedServer', { n: r.length }));
      } catch (err) { toast(err.message); }
      finally { importBtn.disabled = false; importBtn.textContent = t('termsAdmin.importServer'); }
    });
    const pickBtn = $('#terms-pick', el);
    const fileInput = $('#terms-file', el);
    if (pickBtn && fileInput) {
      pickBtn.addEventListener('click', () => fileInput.click());
      fileInput.addEventListener('change', async () => {
        const file = fileInput.files && fileInput.files[0];
        if (!file) return;
        try {
          const text = await file.text();
          const r = await api('/admin/terms/import-text', { method: 'POST', body: { content: text } });
          ta().value = text;
          toast(t('msg.importedLocal', { name: file.name, n: r.length }));
        } catch (err) { toast(err.message); }
        fileInput.value = '';
      });
    }
  },

  async announcements(el) {
    const { items } = await api('/admin/announcements');
    const ed = AdminState.announcement;
    el.innerHTML = `
      <h2 style="margin-bottom:16px">${t('ann.adminTitle')}</h2>
      <form id="ann-form">
        <div class="field"><label>${t('ann.fieldTitle')}</label><input name="title" required maxlength="120" value="${ed ? esc(ed.title || '') : ''}"></div>
        <div class="field">
          <label>${t('ann.fieldTag')}</label>
          <select name="tag">${ANNOUNCE_TAGS.map((k) => `<option value="${k}"${ed && ed.tag === k ? ' selected' : ''}>${esc(annTagLabel(k))}</option>`).join('')}</select>
        </div>
        <div class="field"><label>${t('ann.fieldContent')}</label><textarea name="content" rows="8">${ed ? esc(ed.content || '') : ''}</textarea></div>
        <div class="field">
          <label class="ann-pin-label"><input type="checkbox" name="pinned"${ed && ed.pinned ? ' checked' : ''}> ${t('ann.fieldPinned')}</label>
        </div>
        <div style="display:flex;gap:10px;align-items:center">
          <button class="btn btn-primary btn-sm">${ed ? t('common.save') : t('ann.addBtn')}</button>
          ${ed ? `<button type="button" class="btn btn-ghost btn-sm" id="ann-cancel">${t('ann.cancelEdit')}</button>` : ''}
        </div>
      </form>
      <h3 class="section-title">${t('ann.title')}</h3>
      <table class="admin-table"><thead><tr><th>${t('ann.tblTitle')}</th><th>${t('ann.tblTag')}</th><th>${t('ann.tblPinned')}</th><th>${t('ann.tblTime')}</th><th>${t('col.actions')}</th></tr></thead>
      <tbody>${items.map((a) => `
        <tr>
          <td>${esc(a.title)}</td>
          <td><span class="ann-tag ann-tag-${esc(a.tag)}">${esc(annTagLabel(a.tag))}</span></td>
          <td>${a.pinned ? '📌 ' + t('ann.pinned') : ''}</td>
          <td>${fmtTime(a.created_at)}</td>
          <td>
            <button class="btn btn-ghost btn-sm" data-edit="${a.id}">${t('common.edit')}</button>
            <button class="btn btn-danger btn-sm" data-del="${a.id}">${t('common.delete')}</button>
          </td>
        </tr>`).join('') || `<tr><td colspan="5">${t('ann.noAnnouncements')}</td></tr>`}</tbody></table>`;

    $('#ann-form', el).addEventListener('submit', async (e) => {
      e.preventDefault();
      const f = e.target;
      const payload = { title: f.title.value, content: f.content.value, tag: f.tag.value, pinned: f.pinned.checked };
      try {
        if (AdminState.announcement) {
          await api(`/admin/announcements/${AdminState.announcement.id}`, { method: 'PUT', body: payload });
          AdminState.announcement = null;
        } else {
          await api('/admin/announcements', { method: 'POST', body: payload });
        }
        toast(t('msg.saved'));
        renderRoute();
      } catch (err) { toast(err.message); }
    });

    const cancelBtn = $('#ann-cancel', el);
    if (cancelBtn) cancelBtn.addEventListener('click', () => { AdminState.announcement = null; renderRoute(); });

    $$('[data-edit]', el).forEach((b) => b.addEventListener('click', () => {
      const a = items.find((x) => String(x.id) === b.dataset.edit);
      if (a) { AdminState.announcement = a; renderRoute(); }
    }));
    $$('[data-del]', el).forEach((b) => b.addEventListener('click', () => adminDelete(b, {
      url: `/admin/announcements/${b.dataset.del}`,
      title: t('common.delete'), message: t('ann.delMsg'),
      onCleared: () => { if (AdminState.announcement && String(AdminState.announcement.id) === String(b.dataset.del)) AdminState.announcement = null; },
    })));
  },

  community(el) { return adminCommunity(el); },
};

// ---------- 后台：社区 / 等级 配置（仅站长 admin/owner） ----------
async function adminCommunity(el) {
  if (Auth.user.role !== 'admin' && Auth.user.role !== 'owner') { el.innerHTML = `<div class="empty">${t('comm.noOwner')}</div>`; return; }
  const tabs = [
    ['titles', t('comm.titles')], ['achievements', t('comm.achievements')], ['cards', t('comm.cards')],
    ['multipliers', t('comm.multipliers')], ['redeem', t('comm.redeem')], ['tasks', t('comm.tasks')],
    ['levelColors', t('comm.levelColors')], ['privacy', t('comm.privacy')], ['notify', t('comm.notify')],
  ];
  let sub = 'achievements';
  function render() {
    const bar = tabs.map(([k, l]) => `<button class="btn btn-sm ${sub === k ? 'btn-primary' : 'btn-ghost'}" data-tab="${k}">${l}</button>`).join(' ');
    el.innerHTML = `<h2 style="margin-bottom:14px">${t('admin.community')}</h2><div class="tab-bar" style="margin-bottom:14px">${bar}</div><div id="comm-content"></div>`;
    el.querySelectorAll('[data-tab]').forEach((b) => b.addEventListener('click', () => { sub = b.dataset.tab; render(); }));
    const c = $('#comm-content', el);
    const run = async () => {
      try {
        if (sub === 'titles') await commTabTitles(c, render);
        else if (sub === 'achievements') await commTabAch(c, render);
        else if (sub === 'cards') await commTabCards(c, render);
        else if (sub === 'multipliers') await commTabMult(c, render);
        else if (sub === 'redeem') await commTabRedeem(c, render);
        else if (sub === 'tasks') await commTabTasks(c, render);
        else if (sub === 'levelColors') await commTabLevelColors(c);
        else if (sub === 'privacy') await commTabPrivacy(c);
        else if (sub === 'notify') await commTabNotify(c, render);
      } catch (e) { c.innerHTML = `<div class="empty">⚠️ ${esc(e.message)}</div>`; }
    };
    run();
  }
  render();
}
async function commTabPrivacy(c) {
  const p = (await api('/admin/privacy-defaults')).privacy || {};
  c.innerHTML = `
    <div class="card comm-card">
      <h3>${t('comm.privacy')}</h3>
      <p class="form-tip">${t('comm.privacyTip')}</p>
      <div class="switch-grid">${PRIV_GROUPS.map((g) => `<label class="switch-row"><span>${t(g.label)}</span><input type="checkbox" data-p="${g.key}" ${p[g.key] ? 'checked' : ''}></label>`).join('')}</div>
      <button class="btn btn-primary btn-sm" id="priv-save" style="margin-top:12px">${t('comm.save')}</button>
    </div>`;
  $('#priv-save', c).addEventListener('click', async () => {
    const privacy = {};
    c.querySelectorAll('[data-p]').forEach((el) => { privacy[el.dataset.p] = el.checked ? 1 : 0; });
    try { await api('/admin/privacy-defaults', { method: 'PUT', body: { privacy } }); toast(t('settings.saved')); } catch (e) { toast(e.message); }
  });
}
async function commTabTitles(c, refresh) {
  const titles = (await api('/admin/titles')).titles || [];
  c.innerHTML = `
    <div class="card comm-card">
      <h3>${t('comm.titles')}</h3>
      <form id="tf" class="comm-form">
        <input name="key" placeholder="${t('comm.key')}" required>
        <input name="name" placeholder="${t('comm.name')}" required>
        <input name="icon" placeholder="${t('comm.icon')}">
        <input name="color" type="color" value="#d9920a" title="${t('comm.titleColor')}">
        <input name="desc" placeholder="${t('comm.desc')}">
        <button class="btn btn-primary btn-sm" type="submit">${t('comm.create')}</button>
      </form>
      <form id="gf" class="comm-form">
        <input name="titleKey" placeholder="${t('comm.useTitleKey')}" required>
        <input name="userId" placeholder="${t('comm.userId')}" required>
        <button class="btn btn-primary btn-sm" type="submit">${t('comm.grant')}</button>
      </form>
      <table class="admin-table"><thead><tr><th>${t('comm.key')}</th><th>${t('comm.name')}</th><th>${t('comm.icon')}</th><th>${t('comm.titleColor')}</th><th>${t('col.actions')}</th></tr></thead>
        <tbody>${(titles || []).map((tl) => `<tr>
          <td><code>${esc(tl.key)}</code></td><td>${esc(tl.name)}</td><td>${esc(tl.icon || '')}</td>
          <td><span class="color-dot" style="background:${esc(tl.color || '#d9920a')}"></span></td>
          <td>
            <button class="btn btn-ghost btn-sm" data-edit="${tl.id}" data-key="${esc(tl.key)}" data-name="${esc(tl.name)}" data-icon="${esc(tl.icon || '')}" data-desc="${esc(tl.desc || '')}" data-color="${esc(tl.color || '#d9920a')}">${t('comm.edit')}</button>
            <button class="btn btn-ghost btn-sm" data-grant="${esc(tl.key)}">${t('comm.grant')}</button>
            <button class="btn btn-danger btn-sm" data-del="${tl.id}">✕</button>
          </td></tr>`).join('') || `<tr><td colspan="5">—</td></tr>`}</tbody>
      </table>
    </div>`;
  const ef = $('#tf', c);
  ef.addEventListener('submit', async (e) => { e.preventDefault(); const f = e.target;
    const body = { key: f.key.value.trim(), name: f.name.value.trim(), icon: f.icon.value.trim(), color: f.color.value, desc: f.desc.value.trim() };
    const editing = ef.dataset.id;
    try {
      if (editing) { await api('/admin/titles/' + editing, { method: 'PUT', body }); toast('OK'); }
      else { await api('/admin/titles', { method: 'POST', body }); toast('OK'); }
      refresh();
    } catch (e) { toast(e.message); }
  });
  $('#gf', c).addEventListener('submit', async (e) => { e.preventDefault(); const f = e.target;
    try { await api('/admin/titles/grant', { method: 'POST', body: { titleKey: f.titleKey.value.trim(), userId: parseInt(f.userId.value) } }); toast('OK'); refresh(); } catch (e) { toast(e.message); } });
  c.querySelectorAll('[data-grant]').forEach((b) => b.addEventListener('click', () => { $('#gf [name=titleKey]', c).value = b.dataset.grant; $('#gf [name=userId]', c).focus(); }));
  c.querySelectorAll('[data-edit]').forEach((b) => b.addEventListener('click', () => {
    ef.dataset.id = b.dataset.edit; ef.key.value = b.dataset.key; ef.name.value = b.dataset.name; ef.icon.value = b.dataset.icon; ef.desc.value = b.dataset.desc; ef.color.value = b.dataset.color;
    ef.key.disabled = true; // key 不可改
    ef.querySelector('button').textContent = t('comm.save');
  }));
  c.querySelectorAll('[data-del]').forEach((b) => b.addEventListener('click', async () => {
    if (!confirm(t('comm.delConfirm'))) return;
    try { await api('/admin/titles/' + b.dataset.del, { method: 'DELETE' }); toast('OK'); refresh(); } catch (e) { toast(e.message); }
  }));
}
async function commTabAch(c, refresh) {
  const ach = (await api('/admin/achievements')).achievements || [];
  c.innerHTML = `
    <div class="card comm-card">
      <h3>${t('comm.achievements')}</h3>
      <form id="af" class="comm-form">
        <input name="key" placeholder="${t('comm.key')}" required>
        <input name="name" placeholder="${t('comm.name')}" required>
        <input name="icon" placeholder="${t('comm.icon')}">
        <input name="reward_xp" placeholder="${t('comm.rewardXp')}" type="number">
        <input name="condition" placeholder="${t('comm.condition')}">
        <input name="multiplier" placeholder="${t('comm.multiplier')}">
        <textarea name="desc" placeholder="${t('comm.desc')}" rows="1"></textarea>
        <button class="btn btn-primary btn-sm" type="submit">${t('comm.create')}</button>
      </form>
      <table class="admin-table"><thead><tr><th>${t('comm.key')}</th><th>${t('comm.name')}</th><th>${t('comm.rewardXp')}</th><th>${t('col.actions')}</th></tr></thead>
        <tbody>${(ach || []).map((a) => `<tr><td>${esc(a.key)}</td><td>${esc(a.name)}</td><td>${a.reward_xp || 0}</td><td>
          <button class="btn btn-ghost btn-sm" data-edit="${a.id}" data-key="${esc(a.key)}" data-name="${esc(a.name)}" data-icon="${esc(a.icon || '')}" data-desc="${esc(a.desc || '')}" data-xp="${a.reward_xp || 0}" data-cond="${esc(a.condition || '')}" data-mult="${esc(a.multiplier || '')}">${t('comm.edit')}</button>
          <button class="btn btn-ghost btn-sm" data-grant="${a.id}">${t('comm.grant')}</button>
          <button class="btn btn-danger btn-sm" data-del="${a.id}">✕</button>
        </td></tr>`).join('')}</tbody>
      </table>
    </div>`;
  const af = $('#af', c);
  af.addEventListener('submit', async (e) => { e.preventDefault(); const f = e.target;
    const body = { key: f.key.value.trim(), name: f.name.value.trim(), icon: f.icon.value.trim(), desc: f.desc.value.trim(), reward_xp: parseInt(f.reward_xp.value) || 0 };
    if (f.condition.value.trim()) { try { body.condition = JSON.parse(f.condition.value); } catch (_) { return toast(t('comm.condition') + ' JSON 错误'); } }
    if (f.multiplier.value.trim()) { try { body.multiplier = JSON.parse(f.multiplier.value); } catch (_) { return toast(t('comm.multiplier') + ' JSON 错误'); } }
    if (af.dataset.id) body.id = parseInt(af.dataset.id);
    try { await api('/admin/achievements', { method: 'POST', body }); toast('OK'); refresh(); } catch (e) { toast(e.message); } });
  c.querySelectorAll('[data-grant]').forEach((b) => b.addEventListener('click', async () => { const uid = prompt(t('comm.userId')); if (uid) { try { await api('/admin/achievements/' + b.dataset.grant + '/grant', { method: 'POST', body: { userId: parseInt(uid) } }); toast('OK'); refresh(); } catch (e) { toast(e.message); } } }));
  c.querySelectorAll('[data-edit]').forEach((b) => b.addEventListener('click', () => {
    af.dataset.id = b.dataset.edit; af.key.value = b.dataset.key; af.name.value = b.dataset.name; af.icon.value = b.dataset.icon; af.desc.value = b.dataset.desc;
    af.reward_xp.value = b.dataset.xp; af.condition.value = b.dataset.cond; af.multiplier.value = b.dataset.mult;
    af.key.disabled = true; af.querySelector('button').textContent = t('comm.save');
  }));
  c.querySelectorAll('[data-del]').forEach((b) => b.addEventListener('click', async () => { if (!confirm(t('comm.delConfirm'))) return; try { await api('/admin/achievements/' + b.dataset.del, { method: 'DELETE' }); toast('OK'); refresh(); } catch (e) { toast(e.message); } }));
}
async function commTabCards(c) {
  let status = 'pending';
  async function draw() {
    const cards = (await api('/admin/cards?status=' + status)).cards || [];
    const filters = [['pending', t('card.pending')], ['approved', t('card.approved')], ['rejected', t('card.rejected')], ['taken_down', t('card.takenDown')], ['all', t('comm.all')]];
    const bar = filters.map(([k, l]) => `<button class="btn btn-sm ${status === k ? 'btn-primary' : 'btn-ghost'}" data-f="${k}">${l}</button>`).join(' ');
    c.innerHTML = `
      <div class="card comm-card">
        <h3>${t('comm.cards')}</h3>
        <div class="tab-bar" style="margin-bottom:12px">${bar}</div>
        <table class="admin-table"><thead><tr><th>${t('comm.user')}</th><th>${t('card.titleField')}</th><th>${t('card.image')}</th><th>${t('profile.cardStatus')}</th><th>${t('col.actions')}</th></tr></thead>
        <tbody>${cards.map((x) => `<tr>
          <td>${esc(x.username)} <span class="lv-tag" style="background:${esc(x.level_color || '#8b5cf6')}">Lv${esc(x.level != null ? x.level : '')}</span></td>
          <td>${esc(x.title || '')}</td>
          <td>${x.has_image ? `<a href="/api/card/${x.user_id}/image" target="_blank" rel="noopener">${t('comm.preview')}</a>` : '—'}</td>
          <td>${esc(x.status)}${x.status !== 'approved' && x.reject_reason ? `<div class="form-tip">${esc(x.reject_reason)}</div>` : ''}</td>
          <td>
            <button class="btn btn-ghost btn-sm" data-approve="${x.user_id}">${t('comm.approve')}</button>
            <button class="btn btn-danger btn-sm" data-reject="${x.user_id}">${t('comm.reject')}</button>
            <button class="btn btn-ghost btn-sm" data-takedown="${x.user_id}">${t('comm.takedown')}</button>
          </td></tr>`).join('') || `<tr><td colspan="5">${t('comm.emptyCards')}</td></tr>`}</tbody></table>
      </div>`;
    c.querySelectorAll('[data-f]').forEach((b) => b.addEventListener('click', () => { status = b.dataset.f; draw(); }));
    const review = async (uid, action, reason) => {
      try { await api('/admin/cards/' + uid + '/review', { method: 'POST', body: { action, reason } }); toast('OK'); draw(); } catch (e) { toast(e.message); }
    };
    c.querySelectorAll('[data-approve]').forEach((b) => b.addEventListener('click', () => review(b.dataset.approve, 'approve')));
    c.querySelectorAll('[data-reject]').forEach((b) => b.addEventListener('click', () => { const reason = prompt(t('comm.reason')); if (reason !== null) review(b.dataset.reject, 'reject', reason); }));
    c.querySelectorAll('[data-takedown]').forEach((b) => b.addEventListener('click', () => { const reason = prompt(t('comm.reason')); if (reason !== null) review(b.dataset.takedown, 'takedown', reason); }));
  }
  await draw();
}
async function commTabMult(c, refresh) {
  const ms = (await api('/admin/multipliers')).multipliers || [];
  c.innerHTML = `
    <div class="card comm-card">
      <h3>${t('comm.multipliers')}</h3>
      <form id="mf" class="comm-form">
        <input name="name" placeholder="${t('comm.name')}" required>
        <input name="value" placeholder="${t('comm.value')}" type="number" step="0.1" required>
        <input name="scope" placeholder="${t('comm.scope')}" value="nonsignin">
        <input name="global_cap" placeholder="${t('comm.cap')}" type="number" step="0.1" value="2.0">
        <button class="btn btn-primary btn-sm" type="submit">${t('comm.create')}</button>
      </form>
      <table class="admin-table"><thead><tr><th>${t('comm.name')}</th><th>${t('comm.value')}</th><th>${t('comm.scope')}</th><th>${t('comm.enabled')}</th><th>${t('col.actions')}</th></tr></thead>
        <tbody>${(ms || []).map((m) => `<tr><td>${esc(m.name)}</td><td>${m.value}</td><td>${esc(m.scope)}</td><td>${m.enabled ? '✅' : '⛔'}</td><td>
          <button class="btn btn-ghost btn-sm" data-edit="${m.id}" data-name="${esc(m.name)}" data-value="${m.value}" data-scope="${esc(m.scope)}" data-cap="${m.global_cap}" data-en="${m.enabled}">${t('comm.edit')}</button>
          <button class="btn btn-ghost btn-sm" data-del="${m.id}">✕</button></td></tr>`).join('')}</tbody>
      </table>
    </div>`;
  const mf = $('#mf', c);
  mf.addEventListener('submit', async (e) => { e.preventDefault(); const f = e.target;
    const body = { name: f.name.value.trim(), value: parseFloat(f.value.value) || 0, scope: f.scope.value.trim() || 'nonsignin', global_cap: parseFloat(f.global_cap.value) || 2.0 };
    const editing = mf.dataset.id;
    try {
      if (editing) { await api('/admin/multipliers/' + editing, { method: 'PUT', body }); toast('OK'); }
      else { await api('/admin/multipliers', { method: 'POST', body }); toast('OK'); }
      refresh();
    } catch (e) { toast(e.message); }
  });
  c.querySelectorAll('[data-edit]').forEach((b) => b.addEventListener('click', () => {
    mf.dataset.id = b.dataset.edit; mf.name.value = b.dataset.name; mf.value.value = b.dataset.value; mf.scope.value = b.dataset.scope; mf.global_cap.value = b.dataset.cap;
    mf.querySelector('button').textContent = t('comm.save');
  }));
  c.querySelectorAll('[data-del]').forEach((b) => b.addEventListener('click', async () => { if (!confirm(t('comm.delConfirm'))) return; try { await api('/admin/multipliers/' + b.dataset.del, { method: 'DELETE' }); toast('OK'); refresh(); } catch (e) { toast(e.message); } }));
}
async function commTabRedeem(c, refresh) {
  const codes = (await api('/admin/redeem-codes')).codes || [];
  const titles = (await api('/admin/titles')).titles || [];
  const ach = (await api('/admin/achievements')).achievements || [];
  const rewardLabel = (r) => {
    if (!r) return '—';
    try { const o = typeof r === 'string' ? JSON.parse(r) : r; return o.type === 'xp' ? ('+'+o.xp+' XP') : o.type === 'achievement' ? ('成就:'+o.key) : o.type === 'title' ? ('称号:'+o.key) : JSON.stringify(o); } catch (_) { return String(r); }
  };
  c.innerHTML = `
    <div class="card comm-card">
      <h3>${t('comm.redeem')}</h3>
      <form id="rf" class="comm-form">
        <input name="title" placeholder="${t('comm.name')}">
        <select name="type" id="redeem-type">
          <option value="xp">${t('comm.typeXp')}</option>
          <option value="achievement">${t('comm.typeAchievement')}</option>
          <option value="title">${t('comm.typeTitle')}</option>
        </select>
        <input name="value" id="redeem-value" placeholder="${t('comm.rewardValue')}">
        <button type="button" class="btn btn-ghost btn-sm" id="redeem-random">🎲 ${t('comm.random')}</button>
        <input name="maxUses" placeholder="${t('comm.maxUses')}" type="number" value="1">
        <input name="perUserOnce" placeholder="${t('comm.perUserOnce')} (1/0)" value="1">
        <input name="expiresAt" placeholder="${t('comm.expiresAt')} (ms)">
        <button class="btn btn-primary btn-sm" type="submit">${t('comm.genCode')}</button>
        <button type="button" class="btn btn-primary btn-sm" id="redeem-random5">${t('comm.randomGen')}</button>
      </form>
      <table class="admin-table"><thead><tr><th>CODE</th><th>${t('comm.name')}</th><th>${t('comm.rewardType')}</th><th>${t('comm.maxUses')}</th><th>used</th></tr></thead>
        <tbody>${(codes || []).map((x) => `<tr><td><code>${esc(x.code)}</code></td><td>${esc(x.title || '')}</td><td>${esc(rewardLabel(x.reward))}</td><td>${x.max_uses}</td><td>${x.used_count}</td></tr>`).join('')}</tbody>
      </table>
    </div>`;
  const typeSel = $('#redeem-type', c), valIn = $('#redeem-value', c);
  const pickRandom = () => {
    const ty = typeSel.value;
    if (ty === 'xp') valIn.value = 20 + Math.floor(Math.random() * 481);
    else if (ty === 'achievement' && ach.length) valIn.value = ach[Math.floor(Math.random() * ach.length)].key;
    else if (ty === 'title' && titles.length) valIn.value = titles[Math.floor(Math.random() * titles.length)].key;
    else valIn.value = '';
  };
  $('#redeem-random', c).addEventListener('click', pickRandom);
  $('#redeem-random5', c).addEventListener('click', async () => {
    const type = typeSel.value, count = 5;
    try { const r = await api('/admin/redeem-codes/random', { method: 'POST', body: { type, count, title: '随机奖励' } }); toast(t('comm.generated') + ' × ' + r.codes.length); refresh(); } catch (e) { toast(e.message); }
  });
  $('#rf', c).addEventListener('submit', async (e) => { e.preventDefault(); const f = e.target;
    const type = typeSel.value, value = valIn.value.trim();
    const body = { title: f.title.value.trim(), type, value, maxUses: parseInt(f.maxUses.value) || 1, perUserOnce: f.perUserOnce.value.trim() !== '0', expiresAt: f.expiresAt.value.trim() ? parseInt(f.expiresAt.value) : null };
    try { const r = await api('/admin/redeem-codes', { method: 'POST', body }); toast(t('comm.generated') + ': ' + r.code); refresh(); } catch (e) { toast(e.message); } });
}
async function commTabTasks(c, refresh) {
  const tasks = (await api('/admin/tasks')).tasks || [];
  const TYPES = ['comment', 'like', 'favorite', 'download', 'online', 'custom'];
  c.innerHTML = `
    <div class="card comm-card">
      <h3>${t('comm.tasks')}</h3>
      <form id="tf" class="comm-form">
        <input name="key" placeholder="${t('comm.key')}" required>
        <input name="name" placeholder="${t('comm.name')}" required>
        <input name="desc" placeholder="${t('comm.desc')}">
        <select name="type">${TYPES.map((x) => `<option value="${x}">${x}</option>`).join('')}</select>
        <input name="target_count" placeholder="${t('comm.target')}" type="number" value="1">
        <input name="reward_xp" placeholder="${t('comm.rewardXp')}" type="number" value="0">
        <input name="daily_cap" placeholder="${t('comm.dailyCap')}" type="number" value="1">
        <button class="btn btn-primary btn-sm" type="submit">${t('comm.create')}</button>
      </form>
      <table class="admin-table"><thead><tr><th>${t('comm.key')}</th><th>${t('comm.name')}</th><th>${t('comm.taskType')}</th><th>${t('comm.target')}</th><th>${t('comm.rewardXp')}</th><th>${t('comm.dailyCap')}</th><th>${t('comm.enabled')}</th><th>✕</th></tr></thead>
        <tbody>${(tasks || []).map((tk) => `<tr>
          <td><code>${esc(tk.key)}</code></td><td>${esc(tk.name)}</td><td>${esc(tk.type)}</td>
          <td>${tk.target_count}</td><td>${tk.reward_xp}</td><td>${tk.daily_cap}</td>
          <td>${tk.enabled ? `<button class="btn btn-ghost btn-sm" data-toggle="${tk.id}" data-en="0">✅</button>` : `<button class="btn btn-ghost btn-sm" data-toggle="${tk.id}" data-en="1">⛔</button>`}</td>
          <td>
            <button class="btn btn-ghost btn-sm" data-edit="${tk.id}" data-key="${esc(tk.key)}" data-name="${esc(tk.name)}" data-desc="${esc(tk.desc || '')}" data-type="${esc(tk.type)}" data-tc="${tk.target_count}" data-xp="${tk.reward_xp}" data-cap="${tk.daily_cap}">${t('comm.edit')}</button>
            <button class="btn btn-ghost btn-sm" data-del="${tk.id}">✕</button></td></tr>`).join('') || `<tr><td colspan="8">—</td></tr>`}</tbody>
      </table>
    </div>`;
  const tf = $('#tf', c);
  tf.addEventListener('submit', async (e) => { e.preventDefault(); const f = e.target;
    const body = { key: f.key.value.trim(), name: f.name.value.trim(), desc: f.desc.value.trim(), type: f.type.value, target_count: parseInt(f.target_count.value) || 1, reward_xp: parseInt(f.reward_xp.value) || 0, daily_cap: parseInt(f.daily_cap.value) || 1 };
    const editing = tf.dataset.id;
    try {
      if (editing) { await api('/admin/tasks/' + editing, { method: 'PUT', body }); toast('OK'); }
      else { await api('/admin/tasks', { method: 'POST', body }); toast('OK'); }
      refresh();
    } catch (e) { toast(e.message); }
  });
  c.querySelectorAll('[data-toggle]').forEach((b) => b.addEventListener('click', async () => { try { await api('/admin/tasks/' + b.dataset.toggle, { method: 'PUT', body: { enabled: b.dataset.en === '1' } }); refresh(); } catch (e) { toast(e.message); } }));
  c.querySelectorAll('[data-edit]').forEach((b) => b.addEventListener('click', () => {
    tf.dataset.id = b.dataset.edit; tf.key.value = b.dataset.key; tf.name.value = b.dataset.name; tf.desc.value = b.dataset.desc; tf.type.value = b.dataset.type;
    tf.target_count.value = b.dataset.tc; tf.reward_xp.value = b.dataset.xp; tf.daily_cap.value = b.dataset.cap;
    tf.key.disabled = true; tf.querySelector('button').textContent = t('comm.save');
  }));
  c.querySelectorAll('[data-del]').forEach((b) => b.addEventListener('click', async () => { if (!confirm(t('comm.delConfirm'))) return; try { await api('/admin/tasks/' + b.dataset.del, { method: 'DELETE' }); refresh(); } catch (e) { toast(e.message); } }));
}
async function commTabLevelColors(c) {
  const colors = (await api('/admin/level-colors')).colors || {};
  const rows = Array.from({ length: 10 }, (_, i) => i + 1).map((lv) => `
    <label class="level-color-row"><span class="lv-tag" style="background:${esc(colors[lv] || '#8b5cf6')}">Lv${lv}</span>
    <input type="color" data-lv="${lv}" value="${esc(colors[lv] || '#8b5cf6')}"></label>`).join('');
  c.innerHTML = `
    <div class="card comm-card">
      <h3>${t('comm.levelColors')}</h3>
      <p class="form-tip">${t('comm.levelColorTip')}</p>
      <div class="level-colors-grid">${rows}</div>
      <div class="lc-actions">
        <button class="btn btn-primary btn-sm" id="lc-save">${t('comm.save')}</button>
        <button class="btn btn-ghost btn-sm" id="lc-reset">${t('comm.resetColors')}</button>
      </div>
      <p class="form-tip">${t('comm.levelColorSaveTip')}</p>
    </div>`;
  const syncBadge = () => c.querySelectorAll('.level-color-row').forEach((r) => { const inp = r.querySelector('input'); const tag = r.querySelector('.lv-tag'); tag.style.background = inp.value; });
  c.querySelectorAll('[data-lv]').forEach((i) => i.addEventListener('input', syncBadge));
  const collect = () => { const o = {}; c.querySelectorAll('[data-lv]').forEach((i) => { o[i.dataset.lv] = i.value; }); return o; };
  const save = async (colors2, tip) => {
    try {
      // 以服务端回执为准重绘：保存后立刻能看到「服务端实际生效值」，避免误以为没改成功
      const r = await api('/admin/level-colors', { method: 'PUT', body: { colors: colors2 } });
      const back = r.colors || colors2;
      c.querySelectorAll('[data-lv]').forEach((i) => { const v = back[i.dataset.lv]; if (v) i.value = v; });
      syncBadge();
      toast(tip);
    } catch (e) { toast(e.message); }
  };
  $('#lc-save', c).addEventListener('click', () => save(collect(), t('settings.saved')));
  $('#lc-reset', c).addEventListener('click', () => save({}, t('comm.resetDone')));
}
async function commTabNotify(c) {
  c.innerHTML = `
    <div class="card comm-card">
      <h3>${t('comm.notify')}</h3>
      <form id="nf" class="comm-form">
        <input name="userId" placeholder="${t('comm.recipient')}">
        <input name="title" placeholder="${t('comm.name')}">
        <textarea name="body" placeholder="${t('comm.desc')}" rows="3" required></textarea>
        <button class="btn btn-primary btn-sm" type="submit">${t('comm.sendMsg')}</button>
      </form>
    </div>`;
  $('#nf', c).addEventListener('submit', async (e) => { e.preventDefault(); const f = e.target;
    try { const r = await api('/admin/notify', { method: 'POST', body: { userId: f.userId.value.trim() ? parseInt(f.userId.value) : 0, title: f.title.value.trim(), body: f.body.value.trim() } }); toast(t('comm.sendMsg') + ' (' + r.count + ')'); } catch (e) { toast(e.message); } });
}

// ---------- 个人设置 / 隐私 ----------
// 隐私开关：true=公开；默认最小可见（多数默认关闭）。下方按分组渲染。
const PRIV_GROUPS = [
  { key: 'profile', label: 'profile.field' },
  { key: 'favorites', label: 'profile.showFavorites' },
  { key: 'likes', label: 'profile.showLikes' },
  { key: 'comments', label: 'profile.showComments' },
  { key: 'browse_history', label: 'profile.showBrowse' },
  { key: 'level', label: 'profile.showLevel' },
  { key: 'title', label: 'profile.showTitle' },
  { key: 'card', label: 'profile.showCard' },
  { key: 'badges', label: 'profile.showBadges' },
  { key: 'multiplier', label: 'profile.showMultiplier' },
];

async function viewSettings(el) {
  if (!Auth.user) { el.innerHTML = `<div class="view"><div class="empty">${t('auth.needLogin')} <a href="#/login">${t('chip.loginRegister')}</a></div></div>`; return; }
  const p = await api('/user/profile');
  const cardInfo = await api('/card');
  const prof = p.profile, priv = p.privacy;
  const u = Auth.user;
  const privToggles = PRIV_GROUPS.map((g) => `
    <label class="switch-row">
      <span>${t(g.label)}</span>
      <input type="checkbox" name="priv_${g.key}" ${priv[g.key] ? 'checked' : ''}>
    </label>`).join('');
  const cCard = cardInfo.card;
  const cardStatusLabel = (s) => ({ pending: t('card.pending'), approved: t('card.approved'), rejected: t('card.rejected'), taken_down: t('card.takenDown') }[s] || s);
  const cardSection = !cardInfo.eligible
    ? `<div class="card form-card card-lock"><h3 class="sub-title">${t('profile.card')}</h3><p class="form-tip">🔒 ${t('card.locked', { lv: cardInfo.min_level })}</p></div>`
    : `<form id="card-form" class="card form-card">
        <h3 class="sub-title">${t('profile.card')}</h3>
        <p class="form-tip">${t('card.tip')}</p>
        ${cardInfo.staff ? `<p class="form-tip">👑 ${t('card.staff')}</p>` : ''}
        ${cCard ? `<div class="card-status-line"><span class="${cCard.status === 'approved' ? 'ok-tag' : 'warn-tag'}">${t('profile.cardStatus')}: ${esc(cardStatusLabel(cCard.status))}</span>${cCard.status === 'rejected' && cCard.reject_reason ? `<span class="form-tip">${t('card.reason')}: ${esc(cCard.reject_reason)}</span>` : ''}</div>` : ''}
        <div class="field"><label>${t('card.titleField')}</label><input name="title" maxlength="40" value="${esc(cCard ? cCard.title : '')}" placeholder="${t('card.titlePh')}"></div>
        <div class="field"><label>${t('card.introField')}</label><textarea name="intro" rows="2" maxlength="300" placeholder="${t('card.introPh')}">${esc(cCard ? cCard.intro : '')}</textarea></div>
        <div class="card-colors">
          <label>${t('card.bg')} <input type="color" name="bg" value="${esc((cCard && cCard.style && cCard.style.bg) || '#1a1a2e')}"></label>
          <label>${t('card.fg')} <input type="color" name="fg" value="${esc((cCard && cCard.style && cCard.style.fg) || '#e8e8f0')}"></label>
          <label>${t('card.accent')} <input type="color" name="accent" value="${esc((cCard && cCard.style && cCard.style.accent) || '#8b5cf6')}"></label>
        </div>
        <div class="field">
          <label>${t('card.image')}</label>
          <div class="file-pick">
            <input type="file" id="card-file" name="file" accept="image/png,image/jpeg,image/gif,image/webp" hidden>
            <button type="button" class="btn btn-ghost btn-sm" id="card-pick">${t('card.pickImage')}</button>
            <span class="file-name" id="card-fname">${t('card.noImage')}</span>
            <button type="button" class="btn btn-ghost btn-sm" id="card-clear" hidden>${t('card.clearImage')}</button>
          </div>
          <div class="card-preview" id="card-prev" hidden><img class="card-img" alt=""></div>
          <p class="form-tip">${t('settings.avatarHint')}</p>
        </div>
        ${cCard && cCard.has_image ? `<div class="card-preview"><img class="card-img" src="/api/card/${Auth.user.id}/image?v=${Date.now()}" alt=""></div>` : ''}
        <button class="btn btn-primary btn-sm" type="submit">${t('card.submit')}</button>
      </form>`;
  el.innerHTML = `
    <div class="view view-settings">
      <h2 class="view-title">${t('title.settings')}</h2>

      <div class="card form-card">
        <h3 class="sub-title">${t('profile.account')}</h3>
        <div class="settings-av">
          <img id="set-av" class="avatar-big" src="${Auth.avatarUrl()}" alt="${t('avatar.alt')}">
          <div class="settings-av-r">
            <button type="button" class="btn btn-ghost btn-sm" id="av-pick">${t('settings.changeAvatar')}</button>
            <p class="pw-hint">${t('settings.avatarHint')}</p>
          </div>
        </div>
        <form id="name-form">
          <div class="field"><label>${t('settings.username')}</label>
            <input name="username" maxlength="32" value="${esc(u.username)}" required autocomplete="nickname">
            <p class="pw-hint">${t('settings.usernameHint')}</p>
          </div>
          <button class="btn btn-primary btn-sm" type="submit">${t('settings.saveName')}</button>
        </form>
        <div class="field"><label>${t('settings.uid')}</label><input value="${esc(u.id)}" disabled></div>
        <div class="field"><label>${t('settings.email')}</label>
          <input value="${esc(u.email || '')}" disabled>
          <label class="switch-row inline"><span>${t('profile.emailPublic')}</span><input type="checkbox" id="email-public" ${prof.email_public ? 'checked' : ''}></label>
          <p class="pw-hint">${t('settings.emailFixed')}</p>
        </div>
      </div>

      <form id="profile-form" class="card form-card">
        <h3 class="sub-title">${t('settings.basic')}</h3>
        <div class="field"><label>${t('profile.birthday')}</label><input type="date" name="birthday" value="${esc(prof.birthday)}"></div>
        <div class="field"><label>${t('profile.birthdayVis')}</label>
          <select name="birthday_visibility">
            <option value="hidden" ${prof.birthday_visibility === 'hidden' ? 'selected' : ''}>${t('profile.birthdayHidden')}</option>
            <option value="age_range" ${prof.birthday_visibility === 'age_range' ? 'selected' : ''}>${t('profile.birthdayAge')}</option>
            <option value="is_birthday" ${prof.birthday_visibility === 'is_birthday' ? 'selected' : ''}>${t('profile.birthdayIs')}</option>
          </select>
        </div>
        <div class="field"><label>${t('profile.gender')}</label>
          <select name="gender">
            <option value="secret" ${prof.gender === 'secret' ? 'selected' : ''}>${t('profile.genderSecret')}</option>
            <option value="male" ${prof.gender === 'male' ? 'selected' : ''}>${t('profile.genderMale')}</option>
            <option value="female" ${prof.gender === 'female' ? 'selected' : ''}>${t('profile.genderFemale')}</option>
          </select>
        </div>
        <div class="field"><label>${t('profile.signature')}</label><textarea name="signature" rows="2" maxlength="200" placeholder="${t('profile.signaturePh')}">${esc(prof.signature)}</textarea></div>

        <h3 class="sub-title">${t('settings.social')}</h3>
        <div class="field"><label>Bilibili</label><input name="social_bilibili" maxlength="300" value="${esc(prof.social_bilibili)}" placeholder="https://space.bilibili.com/..."></div>
        <div class="field"><label>GitHub</label><input name="social_github" maxlength="300" value="${esc(prof.social_github)}" placeholder="https://github.com/..."></div>
        <div class="field"><label>QQ</label><input name="social_qq" maxlength="20" value="${esc(prof.social_qq)}" placeholder="12345678"></div>

        <h3 class="sub-title">${t('settings.privacy')}</h3>
        <p class="form-tip">${t('profile.privacyTip')}</p>
        <div class="switch-grid">${privToggles}</div>

        <button class="btn btn-primary btn-sm" type="submit">${t('settings.save')}</button>
      </form>

      <form id="pw-form" class="card form-card">
        <h3 class="sub-title">${t('profile.changePwd')}</h3>
        <div class="field"><label>${t('settings.oldPwd')}</label><input name="old" type="password" required autocomplete="current-password"></div>
        <div class="field"><label>${t('settings.newPwd')}</label><input name="nw" type="password" required maxlength="72" autocomplete="new-password"></div>
        <div class="field"><label>${t('settings.confirmPwd')}</label><input name="nw2" type="password" required maxlength="72" autocomplete="new-password"></div>
        <p class="pw-hint">${t('settings.pwdTip')}</p>
        <button class="btn btn-primary btn-sm" type="submit">${t('settings.savePwd')}</button>
      </form>
      ${cardSection}
    </div>`;
  const cardForm = $('#card-form', el);
  if (cardForm) cardForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const f = e.target;
    const fd = new FormData();
    fd.append('title', f.title.value);
    fd.append('intro', f.intro.value);
    fd.append('style', JSON.stringify({ bg: f.bg.value, fg: f.fg.value, accent: f.accent.value }));
    if (f.file.files[0]) fd.append('file', f.file.files[0]);
    try {
      // 多部分表单：与头像上传一致，直接 fetch + CSRF 自定义头（api() 仅处理 JSON）
      const res = await fetch('/api/card', { method: 'POST', headers: { 'X-Requested-With': 'WebOwn' }, body: fd, credentials: 'same-origin' });
      const j = await res.json();
      if (!res.ok) throw new Error(j.error === 'level_low' ? t('card.locked', { lv: j.min_level || 5 }) : (j.error || 'error'));
      toast(t('card.submitted') + (j.auto_approved ? ' ' + t('card.autoApproved') : '')); renderRoute();
    } catch (err) { toast(err.message); }
  });
  $('#profile-form', el).addEventListener('submit', async (e) => {
    e.preventDefault();
    const f = e.target;
    const privacy = {};
    PRIV_GROUPS.forEach((g) => { privacy[g.key] = f['priv_' + g.key].checked ? 1 : 0; });
    const body = {
      birthday: f.birthday.value, birthday_visibility: f.birthday_visibility.value,
      gender: f.gender.value, signature: f.signature.value,
      social_bilibili: f.social_bilibili.value, social_github: f.social_github.value,
      social_qq: f.social_qq.value, privacy,
    };
    try {
      await api('/user/profile', { method: 'PUT', body });
      toast(t('settings.saved'));
    } catch (err) { toast(err.message); }
  });

  // ---- 账号区：头像 / 昵称 / 邮箱公开 / 修改密码 ----
  const avPick = $('#av-pick', el);
  if (avPick) avPick.addEventListener('click', async () => {
    const file = await pickFile('image/*');
    if (!file) return;
    if (file.size > 2 * 1024 * 1024) return toast(t('settings.avatarHint'));
    try {
      const blob = await Cropper.open(file);
      const fd = new FormData();
      fd.append('file', blob, 'avatar.jpg');
      const res = await fetch('/api/user/avatar', { method: 'POST', headers: { 'X-Requested-With': 'WebOwn' }, body: fd, credentials: 'same-origin' });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || t('msg.uploadFailed'));
      Auth.user.avatar = data.avatar;
      Auth._avT = Date.now();
      $('#set-av', el).src = Auth.avatarUrl();
      Auth.renderChip();
      toast(t('msg.avatarUpdated'));
    } catch (e) {
      if (e && e.message !== 'cancel') toast(e.message || t('msg.avatarFail'));
    }
  });

  const nameForm = $('#name-form', el);
  if (nameForm) nameForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const val = e.target.username.value.trim();
    if (!val) return;
    try {
      const r = await api('/user/username', { method: 'PUT', body: { username: val } });
      Auth.user.username = r.username;
      Auth.renderChip();
      toast(t('settings.nameOk'));
      renderRoute();
    } catch (err) { toast(err.message); }
  });

  const emailPub = $('#email-public', el);
  if (emailPub) emailPub.addEventListener('change', async () => {
    try {
      await api('/user/email-visibility', { method: 'PUT', body: { public: emailPub.checked ? 1 : 0 } });
      toast(t('settings.emailSaved'));
    } catch (err) { toast(err.message); emailPub.checked = !emailPub.checked; }
  });

  const pwForm = $('#pw-form', el);
  if (pwForm) pwForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const f = e.target;
    if (f.nw.value !== f.nw2.value) return toast(t('settings.pwdMismatch'));
    try {
      await api('/user/password', { method: 'PUT', body: { oldPassword: f.old.value, newPassword: f.nw.value } });
      f.reset();
      toast(t('settings.saved'));
    } catch (err) { toast(err.message); }
  });

  // ---- 名片：自定义图片选择（按钮 + 文件名 + 本地预览 + 清除） ----
  const cardFile = $('#card-file', el);
  const cardPick = $('#card-pick', el);
  const cardClear = $('#card-clear', el);
  const cardPrev = $('#card-prev', el);
  const cardFname = $('#card-fname', el);
  let cardObjUrl = '';
  if (cardPick && cardFile) {
    const syncCardFile = () => {
      const fl = cardFile.files && cardFile.files[0];
      if (cardObjUrl) { URL.revokeObjectURL(cardObjUrl); cardObjUrl = ''; }
      if (!fl) {
        cardFname.textContent = t('card.noImage');
        cardClear.hidden = true; cardPrev.hidden = true;
        return;
      }
      cardFname.textContent = fl.name;
      cardClear.hidden = false;
      cardObjUrl = URL.createObjectURL(fl);
      cardPrev.hidden = false;
      cardPrev.querySelector('img').src = cardObjUrl;
    };
    cardPick.addEventListener('click', () => cardFile.click());
    cardFile.addEventListener('change', syncCardFile);
    cardClear.addEventListener('click', () => { cardFile.value = ''; syncCardFile(); });
  }
}

// ---------- 个人主页 ----------
async function viewUserHome(el, rawId) {
  const id = parseInt(rawId) || 0;
  let data;
  try { data = (await api('/user/' + id + '/home')).home; }
  catch (e) { el.innerHTML = `<div class="view"><div class="empty">⚠️ ${esc(e.message)}</div></div>`; return; }
  const isSelf = data.is_self;
  const av = data.avatar ? `<img class="avatar-big" src="/uploads/${esc(data.avatar)}" alt="">` : `<img class="avatar-big" src="${avatarSvg(data.username)}" alt="">`;
  const badgeHtml = (data.badges && data.badges.length) ? data.badges.map((b) => `<span class="badge-ach" title="${esc(b.name || '')}">${b.icon ? esc(b.icon) : '🏅'} ${esc(b.name || '')}</span>`).join(' ') : '';
  // 分区标题统一带 emoji 前缀，与下拉菜单/后台按钮的视觉语言保持一致
  const sec = (icon, title, items, render) => items && items.length
    ? `<div class="home-sec"><h3 class="sub-title">${icon} ${title} (${items.length})</h3>${items.map(render).join('')}</div>`
    : '';
  const lvTag = (lv, color) => lv != null ? `<span class="lv-tag" style="background:${esc(color || '#8b5cf6')}">Lv${esc(lv)}</span>` : '';
  // 定位链接：文章按 slug、项目/图片按 id、动态跳外链；标题缺失时回退为 #id
  const itemLink = (x) => x.href
    ? `<a class="home-item" href="${esc(x.href)}"${x.external ? ' target="_blank" rel="noopener noreferrer nofollow"' : ''}>${t('type.' + x.type)} · ${esc(x.title || ('#' + x.id))}</a>`
    : `<span class="home-item">${t('type.' + x.type)} #${esc(x.id)}</span>`;
  const favRender = itemLink;
  // 经验进度条：Lv 当前 → 下一级（满级则显示 MAX）
  const xpBar = !data.xp ? '' : `
    <div class="xp-wrap">
      <div class="xp-line">
        <span class="xp-label">${t('profile.xp')}</span>
        <b class="xp-num">${esc(data.xp.current)}${data.xp.next ? ' / ' + esc(data.xp.next) : ''}</b>
        ${data.xp.maxed ? `<span class="ok-tag">${t('profile.xpMax')}</span>`
    : `<span class="form-tip">${t('profile.xpTip', { need: esc(data.xp.need) })}</span>`}
      </div>
      <div class="xp-bar"><i style="width:${data.xp.percent}%"></i></div>
    </div>`;
  el.innerHTML = `
    <div class="view view-profile">
      <div class="profile-head card">
        ${av}
        <div class="ph-info">
          <h2>${esc(data.username)} ${lvTag(data.level, data.level_color)} ${data.title ? `<span class="title-tag" style="color:#fff;background:${esc(data.title_color || '#d9920a')};border-color:transparent">${data.title_icon ? esc(data.title_icon) + ' ' : ''}${esc(data.title)}</span>` : ''}</h2>
          ${data.signature ? `<p class="ph-sign">${esc(data.signature)}</p>` : ''}
          ${badgeHtml ? `<div class="ph-badges">${badgeHtml}</div>` : ''}
          ${data.is_birthday ? `<span class="badge-ach">🎂 ${t('profile.isBirthday')}</span>` : ''}
          ${data.birthday_age_range ? `<span class="badge-ach">${t('profile.ageRange')}: ${esc(data.birthday_age_range)}</span>` : ''}
          ${xpBar}
        </div>
      </div>
      ${data.profile_private ? `<div class="empty">${t('profile.privateHome')}</div>` : `
        ${sec('⭐', t('profile.favorites'), data.favorites, favRender)}
        ${sec('❤️', t('profile.likes'), data.likes, favRender)}
        ${sec('🕘', t('profile.browse'), data.browse_history, favRender)}
        ${sec('💬', t('profile.comments'), data.comments, (c) => `<div class="home-comment">${itemLink(c)} <span class="home-comment-txt">${esc(c.content)}</span> <span class="c-time">${fmtTime(c.at)}</span>${isSelf ? `<button class="btn btn-ghost btn-sm cmt-del" data-id="${c.id}">${t('cmt.delete')}</button>` : ''}</div>`)}
        ${data.card ? `<div class="home-sec"><h3 class="sub-title">🪪 ${t('profile.card')}</h3><div class="card-block" style="${data.card.style && data.card.style.bg ? `background:${esc(data.card.style.bg)};color:${esc(data.card.style.fg || '#e8e8f0')};` : ''}">${data.card.has_image ? `<img class="card-img" src="/api/card/${id}/image" alt="">` : ''}<b>${esc(data.card.title || '')}</b><p>${esc(data.card.intro || '')}</p>${data.card.status !== 'approved' ? `<span class="warn-tag">${t('profile.cardStatus')}: ${esc(data.card.status)}</span>` : ''}</div></div>` : ''}
        ${data.social && (data.social.bilibili || data.social.github || data.social.qq) ? `<div class="home-sec"><h3 class="sub-title">🔗 ${t('settings.social')}</h3><div class="ph-social">${data.social.bilibili ? `<a href="${esc(data.social.bilibili)}" target="_blank" rel="noopener noreferrer nofollow">Bilibili</a>` : ''}${data.social.github ? `<a href="${esc(data.social.github)}" target="_blank" rel="noopener noreferrer nofollow">GitHub</a>` : ''}${data.social.qq ? `<span>QQ: ${esc(data.social.qq)}</span>` : ''}</div></div>` : ''}
      `}
    </div>`;
  el.querySelectorAll('.cmt-del').forEach((b) => b.addEventListener('click', async () => {
    try { await api('/comments/' + b.dataset.id, { method: 'DELETE' }); toast(t('cmt.deleted')); renderRoute(); } catch (e) { toast(e.message); }
  }));
}

// ---------- 站内通知 ----------
async function viewNotifications(el) {
  if (!Auth.user) { el.innerHTML = `<div class="view"><div class="empty">${t('auth.needLogin')} <a href="#/login">${t('chip.loginRegister')}</a></div></div>`; return; }
  const res = await api('/notifications');
  const items = res.items || [];
  let unread = res.unread || 0;
  // 进入消息页即视为已读：清单已完整呈现，红点不应继续挂着
  if (unread > 0) {
    try { await api('/notifications/read', { method: 'POST', body: { all: true } }); } catch (_) {}
    Auth.unread = 0; Auth.renderUnread(); unread = 0;
  }
  el.innerHTML = `
    <div class="view view-notif">
      <div class="notif-head"><h2 class="view-title">${t('notif.title')}</h2>${unread ? `<button class="btn btn-sm" id="notif-readall">${t('notif.readAll')}</button>` : ''}</div>
      ${items.length ? `<div class="notif-list">${items.map((n) => `
        <div class="notif-item ${n.read ? '' : 'unread'}">
          <div class="notif-top"><b>${esc(n.title)}</b><span class="c-time">${fmtTime(n.created_at)}</span></div>
          <p>${esc(n.body)}</p>
        </div>`).join('')}</div>` : `<div class="empty">${t('notif.empty')}</div>`}
    </div>`;
  const ra = $('#notif-readall', el);
  if (ra) ra.addEventListener('click', async () => {
    try { await api('/notifications/read', { method: 'POST', body: { all: true } }); renderRoute(); } catch (e) { toast(e.message); }
  });
}

// ---------- 每日签到 ----------
async function viewCheckin(el) {
  if (!Auth.user) { el.innerHTML = `<div class="view"><div class="empty">${t('auth.needLogin')} <a href="#/login">${t('chip.loginRegister')}</a></div></div>`; return; }
  let st;
  try { st = await api('/checkin'); } catch (e) { el.innerHTML = `<div class="view"><div class="empty">⚠️ ${esc(e.message)}</div></div>`; return; }
  const can = !st.checkedToday;
  el.innerHTML = `
    <div class="view view-checkin">
      <h2 class="view-title">${t('checkin.title')}</h2>
      <p class="form-tip">${t('checkin.tip')}</p>
      <div class="card checkin-card">
        <div class="ci-stats">
          <div class="ci-stat"><span>${t('checkin.streak')}</span><b>${st.streak}</b></div>
          <div class="ci-stat"><span>${t('checkin.days')}</span><b>${st.totalDays}</b></div>
        </div>
        <button class="btn btn-primary" id="ci-btn" ${can ? '' : 'disabled'}>${can ? t('checkin.do') : t('checkin.done')}</button>
      </div>
    </div>`;
  const btn = $('#ci-btn', el);
  if (btn && can) btn.addEventListener('click', async () => {
    try {
      const r = await api('/checkin', { method: 'POST' });
      if (r.leveledUp) toast(`${t('checkin.levelUp')} Lv${r.newLevel}`);
      else toast(`+${r.xp} XP`);
      renderRoute();
    } catch (e) { toast(e.message); }
  });
}

// ---------- 每日任务 ----------
async function viewTasks(el) {
  if (!Auth.user) { el.innerHTML = `<div class="view"><div class="empty">${t('auth.needLogin')} <a href="#/login">${t('chip.loginRegister')}</a></div></div>`; return; }
  let data;
  try { data = await api('/tasks'); } catch (e) { el.innerHTML = `<div class="view"><div class="empty">⚠️ ${esc(e.message)}</div></div>`; return; }
  const items = (data.tasks || []).map((tk) => `
    <div class="card task-card ${tk.claimed ? 'done' : ''}">
      <div class="tc-main">
        <b>${esc(tk.name)}</b>
        <p>${esc(tk.desc || '')}</p>
        <span class="tc-reward">${t('tasks.reward')}: +${tk.reward_xp} ${t('tasks.xp')}</span>
      </div>
      <div class="tc-state">${tk.claimed ? '✅ ' + t('tasks.done') : '⭕ ' + t('tasks.todo')}</div>
    </div>`).join('');
  el.innerHTML = `<div class="view view-tasks"><h2 class="view-title">${t('tasks.title')}</h2><div class="task-list">${items || '<div class="empty">' + t('empty.projects') + '</div>'}</div></div>`;
}

// ---------- 成就墙 ----------
async function viewAchievements(el) {
  let data;
  try { data = await api('/achievements/mine'); } catch (e) { el.innerHTML = `<div class="view"><div class="empty">⚠️ ${esc(e.message)}</div></div>`; return; }
  const items = (data.achievements || []).map((a) => `
    <div class="card ach-card ${a.granted ? 'got' : 'locked'}">
      <div class="ach-icon">${a.icon || '🏅'}</div>
      <div class="ach-body">
        <b>${esc(a.name)}</b>
        ${a.desc ? `<p>${esc(a.desc)}</p>` : ''}
        ${a.reward_xp ? `<span class="tc-reward">${t('ach.rewardXp')}: +${a.reward_xp}</span>` : ''}
      </div>
      <div class="ach-state">${a.granted ? '✅ ' + t('ach.get') : '🔒 ' + t('ach.locked')}</div>
    </div>`).join('');
  el.innerHTML = `<div class="view view-ach"><h2 class="view-title">${t('ach.title')}</h2><div class="ach-grid">${items}</div></div>`;
}

// ---------- 兑换码 ----------
async function viewRedeem(el) {
  if (!Auth.user) { el.innerHTML = `<div class="view"><div class="empty">${t('auth.needLogin')} <a href="#/login">${t('chip.loginRegister')}</a></div></div>`; return; }
  el.innerHTML = `
    <div class="view view-redeem">
      <h2 class="view-title">${t('redeem.title')}</h2>
      <p class="form-tip">${t('redeem.tip')}</p>
      <div class="card form-card">
        <div class="field"><input id="rd-code" placeholder="${t('redeem.placeholder')}" maxlength="16" autocomplete="off"></div>
        <button class="btn btn-primary btn-sm" id="rd-btn">${t('redeem.go')}</button>
      </div>
    </div>`;
  $('#rd-btn', el).addEventListener('click', async () => {
    const code = $('#rd-code', el).value.trim().toUpperCase();
    if (!code) return toast(t('redeem.placeholder'));
    try {
      const r = await api('/redeem', { method: 'POST', body: { code } });
      let msg = t('redeem.ok');
      if (r.xp) msg += ` +${r.xp} XP`;
      if (r.title) msg += ` · ${r.title}`;
      toast(msg);
      $('#rd-code', el).value = '';
    } catch (e) { toast(e.message); }
  });
}

// ---------- 路由 ----------
async function renderRoute() {
  const hash = location.hash || '#/';
  // 剥离每段路径里可能带的 query（如 #/search?q=xx、#/project/1?tab=releases），
  // 否则 parts[0] 会变成 "search?q=xx"，导致 Views[parts[0]] 匹配不到而 404。
  // query 由各视图内部再按 location.hash 自行解析。
  const parts = hash.slice(2).split('/').map((s) => s.split('?')[0]);
  const app = $('#app');
  // 切换路由时若灯箱仍开着（如浏览器后退），先关闭，避免遮挡新页面
  if (typeof Lightbox !== 'undefined' && Lightbox) Lightbox.close();
  // 导航高亮
  const navKey = ['article', 'admin'].includes(parts[0]) ? (parts[0] === 'admin' ? 'admin' : 'home') : (parts[0] || 'home');
  $$('#nav-links a').forEach((a) => a.classList.toggle('active', a.dataset.nav === (navKey === 'admin' ? '' : navKey)));

  try {
    if (parts[0] === '') await Views.home(app);
    else if (parts[0] === 'article' && parts[1]) await Views.article(app, decodeURIComponent(parts[1]));
    else if (parts[0] === 'project' && parts[1]) await Views.project(app, parts[1]);
    else if (parts[0] === 'image' && parts[1]) await Views.image(app, parts[1]);
    else if (parts[0] === 'terms') { await Views.home(app); Terms.show('view'); return; } // 旧地址兼容：弹出条款
    else if (parts[0] === 'settings') await viewSettings(app);
    else if (parts[0] === 'notifications') await viewNotifications(app);
    else if (parts[0] === 'checkin') await viewCheckin(app);
    else if (parts[0] === 'tasks') await viewTasks(app);
    else if (parts[0] === 'achievements') await viewAchievements(app);
    else if (parts[0] === 'redeem') await viewRedeem(app);
    else if (parts[0] === 'user' && parts[1]) await viewUserHome(app, parts[1]);
    else if (Views[parts[0]]) await Views[parts[0]](app);
    else {
      app.innerHTML = `<div class="view"><div class="empty"><span class="big">🌫️</span>${t('notfound.title')} <a href="#/">${t('notfound.home')}</a></div></div>`;
    }
  } catch (e) {
    app.innerHTML = `<div class="view"><div class="empty"><span class="big">⚠️</span>${esc(e.message)}</div></div>`;
  }
  window.scrollTo({ top: 0 });
}

// ---------- 启动 ----------
// 说明：原「打开开发者工具 → 跳转原神官网」彩蛋已移除。
// 该彩蛋靠「窗口外框与视口尺寸差 > 160px」判断，在手机浏览器（地址栏/工具栏占位）、
// 页面缩放、分屏等场景下会误判并强制跳转，属于干扰正常访问的 BUG，故彻底删除。

// ---------- 小彩蛋 2：自定义右键菜单（本站风格，仅「刷新」「复制」） ----------
function initContextMenu() {
  const menu = document.createElement('div');
  menu.className = 'ctx-menu';
  menu.setAttribute('role', 'menu');
  menu.innerHTML = `
    <button type="button" class="ctx-item" data-act="refresh">🔄 ${esc(t('ctx.refresh'))}</button>
    <button type="button" class="ctx-item" data-act="copy">📋 ${esc(t('ctx.copy'))}</button>`;
  document.body.appendChild(menu);

  const hide = () => menu.classList.remove('show');
  document.addEventListener('contextmenu', (e) => {
    e.preventDefault();
    menu.classList.add('show');
    const w = menu.offsetWidth, h = menu.offsetHeight;
    menu.style.left = Math.max(8, Math.min(e.clientX, window.innerWidth - w - 8)) + 'px';
    menu.style.top = Math.max(8, Math.min(e.clientY, window.innerHeight - h - 8)) + 'px';
  });
  menu.addEventListener('click', async (e) => {
    const btn = e.target.closest('.ctx-item');
    if (!btn) return;
    hide();
    const act = btn.dataset.act;
    if (act === 'refresh') { location.reload(); return; }
    if (act === 'copy') {
      // 有选中文本就复制文本，否则复制当前页面链接
      const sel = window.getSelection().toString();
      const text = sel || location.href;
      try { await navigator.clipboard.writeText(text); toast(t('share.copied')); }
      catch (_) { toast(location.href || t('share.copied')); }
    }
  });
  // 其它交互一律收起菜单
  document.addEventListener('click', hide);
  window.addEventListener('scroll', hide, true);
  window.addEventListener('blur', hide);
  window.addEventListener('resize', hide);
  document.addEventListener('keydown', (e) => { if (e.key === 'Escape') hide(); });
}

// ---------- 小彩蛋：打开开发者工具跳转原神官网 ----------
// 旧实现用 outerWidth - innerWidth 差值判断「DevTools 是否打开」，手机地址栏收缩 / 浏览器缩放 /
// 分屏都会让差值超过阈值，导致「没开开发者工具也被跳转」——该误判渠道已彻底移除。
// 现改为四条互不依赖的通道，任一命中即跳转，且都不依赖窗口尺寸绝对值：
//   ① 快捷键：F12 / Ctrl+Shift+I,J,C / Cmd+Opt+I（最直接，按了必定跳）
//   ② 控制台探针：输出一个带 getter 的对象，只有控制台真的渲染这条日志时才求值
//   ③ 停靠检测：以页面加载时的「外框-视口」差为基线，只认**相对基线的突变**（右侧/底部停靠）
//   ④ 键盘口令：页面空白处依次键入 g e n s h i n
function initDevtoolsEgg() {
  const EGG_URL = 'https://ys.mihoyo.com/';
  let fired = false;
  const go = () => { if (fired) return; fired = true; location.href = EGG_URL; };

  // ① 快捷键（桌面端才启用，移动端没有这些键）
  window.addEventListener('keydown', (e) => {
    if (e.key === 'F12') { go(); return; }
    const meta = e.metaKey || e.ctrlKey;
    if (meta && e.shiftKey && ['I', 'J', 'C'].includes((e.key || '').toUpperCase())) go();
    else if (e.metaKey && e.altKey && ['I', 'J', 'C'].includes((e.key || '').toUpperCase())) go();
  }, true);

  // ② 控制台探针（plain object + getter：控制台渲染对象预览时必定读取属性）
  const probe = {};
  Object.defineProperty(probe, 'moon', { get() { go(); return '🌙'; }, enumerable: true, configurable: true });
  let armed = false, last = 0, shots = 0;
  const logProbe = () => {
    if (!armed || fired || shots >= 30) return;
    const now = Date.now();
    if (now - last < 8000) return;   // 节流：避免频繁切窗口刷屏
    last = now; shots++;
    console.log('%c🌙 月之海', 'color:#8b5cf6', probe);
  };
  setTimeout(() => { armed = true; logProbe(); }, 1200);
  window.addEventListener('focus', logProbe);
  document.addEventListener('visibilitychange', () => { if (!document.hidden) logProbe(); });

  // ③ 停靠检测：仅桌面端（无触摸、宽度 ≥ 900），且只看相对基线的变化量
  const isTouch = ('ontouchstart' in window) || (navigator.maxTouchPoints || 0) > 0;
  if (!isTouch) {
    const baseW = window.outerWidth - window.innerWidth;
    const baseH = window.outerHeight - window.innerHeight;
    const baseDpr = window.devicePixelRatio || 1;
    const checkDock = () => {
      if (fired) return;
      // 缩放会同时改变 dpr 与外框/视口差，直接跳过（避免把浏览器缩放误判成 DevTools）
      if (Math.abs((window.devicePixelRatio || 1) - baseDpr) > 0.01) return;
      const dw = (window.outerWidth - window.innerWidth) - baseW;
      const dh = (window.outerHeight - window.innerHeight) - baseH;
      // 侧边停靠：宽度突变；底部停靠：高度突变。阈值取 200/250，避开标签栏/书签栏的固有高度
      if (dw > 200 || dh > 250) go();
    };
    window.addEventListener('resize', checkDock);
    setTimeout(checkDock, 1500);
  }

  // ④ 键盘口令 genshin
  let buf = '';
  document.addEventListener('keydown', (e) => {
    if (e.metaKey || e.ctrlKey || e.altKey) return;
    const el = e.target;
    const tag = (el && el.tagName || '').toLowerCase();
    if (tag === 'input' || tag === 'textarea' || tag === 'select' || (el && el.isContentEditable)) return;
    buf = (buf + String(e.key || '').toLowerCase()).slice(-7);
    if (buf === 'genshin') go();
  });
}

function init() {
  Theme.apply(Theme.get());
  $('#theme-toggle').addEventListener('click', () => Theme.toggle());
  Lang.apply(Lang.get());
  $('#lang-toggle').addEventListener('click', () => Lang.toggle());
  // 图形验证码刷新走事件委托：只需在启动时绑定一次，表单重渲染也不会失效
  initCaptchaDelegation();
  // 小彩蛋：开发者工具跳转（控制台探针 + 键盘口令）+ 自定义右键菜单
  initDevtoolsEgg();
  initContextMenu();
  window.addEventListener('hashchange', () => { renderRoute(); Terms.maybeShow(); });
  // 站内消息红点：登录态下定时拉未读数（只返回一个数字，开销可忽略）；切回页面时补拉一次
  setInterval(() => { if (Auth.user) Auth.refreshUnread(); }, 45000);
  document.addEventListener('visibilitychange', () => { if (!document.hidden && Auth.user) Auth.refreshUnread(); });

  // 移动端汉堡菜单：点按开合，点击链接或外部区域自动收起
  const navToggle = $('#nav-toggle');
  const navLinks = $('#nav-links');
  if (navToggle && navLinks) {
    navToggle.addEventListener('click', (e) => {
      e.stopPropagation();
      const open = navLinks.classList.toggle('open');
      navToggle.setAttribute('aria-expanded', open ? 'true' : 'false');
    });
    navLinks.querySelectorAll('a').forEach(a => a.addEventListener('click', () => {
      navLinks.classList.remove('open');
      navToggle.setAttribute('aria-expanded', 'false');
    }));
  }
  // 点击页面其它区域：收起导航下拉与用户菜单（移动端触屏友好）
  document.addEventListener('click', (e) => {
    if (navLinks && navLinks.classList.contains('open') && !navLinks.contains(e.target) && !navToggle.contains(e.target)) {
      navLinks.classList.remove('open');
      navToggle.setAttribute('aria-expanded', 'false');
    }
    document.querySelectorAll('.user-wrap.open').forEach(w => {
      if (!w.contains(e.target)) w.classList.remove('open');
    });
  });

  // 入场动画退场：无论后续是否被 IP 封禁，这层遮罩都必须移除，否则会挡住整页点击
  const overlay = $('#entry-overlay');
  setTimeout(() => {
    overlay.classList.add('leave');
    setTimeout(() => overlay.remove(), 800);
  }, 900);

  // 启动收尾：先探 IP 封禁，被封禁时不再拉取任何业务数据
  afterBoot();
}

async function afterBoot() {
  try {
    const st = await api('/ipban-status');
    if (st && st.banned) return showIpBanNotice(st);
  } catch (_) { /* 接口不可用时按正常访客处理 */ }
  Site.load();
  // 先刷新登录态，再渲染一次（首屏月亮动画会遮住这 ~100ms）。
  // 注意：不要在此之外再同步调用 renderRoute()，否则 Auth.refresh 返回后会二次渲染，
  // 可能清空用户正在输入的登录/注册表单，或把登录页误换成"已登录"卡片。
  await Auth.refresh().catch(() => {});
  Terms.maybeShow();
  renderRoute();
  // 登录态确认后，检查是否有需要弹窗提醒的置顶公告（新用户/久未登录/未读）
  checkAnnouncements();
}

// 被 IP 封禁时展示的整页提示（该 IP 下所有账号都无法进入站点）
function showIpBanNotice(st) {
  const app = $('#app');
  const until = st.until ? new Date(st.until).toLocaleString() : t('ban.permanent');
  app.innerHTML = `
    <div class="view">
      <div class="card ipban-notice">
        <div class="ipban-icon">🚫</div>
        <h2>${esc(t('ipban.title'))}</h2>
        <p>${esc(t('ipban.desc'))}</p>
        <div class="ipban-meta">
          <div><span>${esc(t('ipban.yourIp'))}</span><b>${esc(st.ip || '-')}</b></div>
          <div><span>${esc(t('ipban.until'))}</span><b>${esc(until)}</b></div>
          ${st.reason ? `<div><span>${esc(t('ipban.reason'))}</span><b>${esc(st.reason)}</b></div>` : ''}
        </div>
        <p class="form-tip">${esc(t('ipban.contact'))}</p>
      </div>
    </div>`;
}

init();
