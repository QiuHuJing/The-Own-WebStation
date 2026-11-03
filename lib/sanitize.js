// 极简 HTML 净化：用于管理员导入/编辑的富文本内容（无外部依赖）
// 策略：标签白名单 + 属性白名单 + 去除事件属性与危险协议
const ALLOWED_TAGS = new Set([
  'p', 'br', 'div', 'span', 'strong', 'b', 'em', 'i', 'u', 's', 'del', 'ins',
  'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'ul', 'ol', 'li', 'blockquote', 'pre', 'code',
  'a', 'img', 'hr', 'table', 'thead', 'tbody', 'tr', 'th', 'td', 'figure', 'figcaption',
]);

const ALLOWED_ATTR = {
  a: new Set(['href', 'title', 'target', 'rel']),
  img: new Set(['src', 'alt', 'title', 'width', 'height', 'loading']),
};

// 通用属性（所有标签都允许）
const GLOBAL_ATTR = new Set(['class']);

// style 属性净化：保留正常排版（颜色/字号/加粗/对齐），剥离可用于攻击的片段
// - url() 可加载远程资源、expression()/@import/behavior: 为历史注入手段
// - <> 可嵌套标签、引号会提前闭合属性
// - position/z-index/inset/top/.../width/height/transform/opacity/pointer-events 等可被用来做全屏遮罩覆盖（篡改/点击劫持）
function sanitizeStyle(attr) {
  const m = attr.match(/=\s*("|')([\s\S]*?)\1|=(.*)$/);
  let v = m ? (m[2] !== undefined ? m[2] : (m[3] || '')) : '';
  v = v.replace(/url\s*\(/gi, '(')
        .replace(/expression\s*\(/gi, '(')
        .replace(/javascript:/gi, '')
        .replace(/@import/gi, '')
        .replace(/behavior\s*:/gi, '')
        .replace(/[<>]/g, '')
        .replace(/["']/g, ''); // 去除引号，防止属性被提前闭合
  // 剥离可用于全屏遮罩/点击劫持的样式声明（保留 color/font-size/font-weight/text-align 等正常排版）
  v = v.replace(/(?:^|;)\s*(position|z-index|inset|top|left|right|bottom|width|height|float|overflow|transform|transition|animation|filter|opacity|visibility|clip-path|pointer-events)\s*:\s*[^;]*/gi, '');
  v = v.replace(/;{2,}/g, ';').replace(/^\s*;|;\s*$/g, '').replace(/\s+/g, ' ').trim();
  return v.slice(0, 200);
}

function sanitizeHtml(html) {
  if (typeof html !== 'string') return '';
  let out = html;

  // 1) 去掉整块的危险内容
  out = out.replace(/<\s*(script|style|iframe|object|embed|form|input|button|link|meta)\b[\s\S]*?<\s*\/\s*\1\s*>/gi, '');
  out = out.replace(/<\s*(script|style|iframe|object|embed|form|input|button|link|meta)\b[\s\S]*?>/gi, '');

  // 2) 去掉事件属性与危险协议
  out = out.replace(/\son[a-z]+\s*=\s*(".*?"|'.*?'|[^\s>]+)/gi, '');
  out = out.replace(/(href|src)\s*=\s*(["'])\s*(javascript|vbscript):[^"']*\2/gi, '$1=""');
  // 阻断非图片类型的 data: 导航（如 data:text/html）；图片 data: 保留（已被 CSP img-src 允许）
  out = out.replace(/href\s*=\s*(["'])\s*data:(?!image\/)[^"']*\1/gi, 'href=""');

  // 3) 标签白名单：不在白名单的标签剥掉外壳、保留内容
  out = out.replace(/<\/?([a-zA-Z][a-zA-Z0-9-]*)\b([^>]*)>/g, (full, tag, attrs) => {
    const t = tag.toLowerCase();
    if (!ALLOWED_TAGS.has(t)) return '';
    if (!/\//.test(full.slice(0, 2))) {
      // 开标签：过滤属性
      const allow = ALLOWED_ATTR[t];
      const kept = attrs.replace(/([a-zA-Z-]+)\s*=\s*(".*?"|'.*?'|[^\s>]+)/g, (attr, name) => {
        const n = name.toLowerCase();
        if (n === 'style') return `style="${sanitizeStyle(attr)}"`;
        if (GLOBAL_ATTR.has(n)) return attr;
        if (allow && allow.has(n)) return attr;
        return '';
      });
      return `<${t}${kept}>`;
    }
    return `</${t}>`;
  });

  // 4) 外链统一加 rel=noopener
  out = out.replace(/<a\s([^>]*)>/g, (full, attrs) => {
    if (/rel\s*=/i.test(attrs)) return full;
    return `<a ${attrs} rel="noopener noreferrer">`;
  });

  return out;
}

// 修复 multer/busboy 对 multipart 文件名的 latin1 误解码（中文文件名乱码）
// 'è¢«è®°å½' 这类 mojibake 经 latin1→utf8 还原为原文；纯 ASCII 名转换无损
function fixFilename(name) {
  if (typeof name !== 'string' || !name) return '';
  try {
    const fixed = Buffer.from(name, 'latin1').toString('utf8');
    // 还原后若出现 U+FFFD 替换符，说明本来就不是 latin1 误码，保持原样
    return fixed.includes('\uFFFD') ? name : fixed;
  } catch (_) {
    return name;
  }
}

module.exports = { sanitizeHtml, fixFilename };
