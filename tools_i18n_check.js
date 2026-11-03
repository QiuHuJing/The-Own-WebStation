// i18n 回归校验：找出代码中 t('x.y') 用到、但 zh / en 语言包缺失的键。
// 用法：node tools_i18n_check.js   （期望输出：zh/en 缺失均为 0 条）
// 说明：动态拼接键（如 t('search.' + type)）会被过滤，不计入缺失。
const fs = require('fs');
const src = fs.readFileSync(require('path').join(__dirname, 'public/js/app.js'), 'utf8');

// 1) 提取 t('xxx') 用到的键
const used = new Set();
const re = /\bt\(\s*'([^']+)'/g;
let m;
while ((m = re.exec(src))) {
  // 只保留静态键（形如 a.b）；t('search.' + x) 这类动态拼接会被正则截断，过滤掉
  if (/^[A-Za-z0-9_]+(\.[A-Za-z0-9_]+)+$/.test(m[1])) used.add(m[1]);
}

// 2) 按行扫描 I18N 的 zh / en 段，收集已定义键
const defined = { zh: new Set(), en: new Set() };
let cur = null;
for (const line of src.split('\n')) {
  if (/^\s*zh:\s*\{\s*$/.test(line)) { cur = 'zh'; continue; }
  if (/^\s*en:\s*\{\s*$/.test(line)) { cur = 'en'; continue; }
  if (cur && /^\s*\},?\s*$/.test(line)) { cur = null; continue; }
  if (!cur) continue;
  // 一行内可能有多个 'key': 'value' 对，需全部提取
  const km = line.matchAll(/'([A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)*)':\s/g);
  for (const x of km) defined[cur].add(x[1]);
}

const missZh = [...used].filter((k) => !defined.zh.has(k)).sort();
const missEn = [...used].filter((k) => !defined.en.has(k)).sort();
console.log('zh 语言包键数:', defined.zh.size, '| en:', defined.en.size);
console.log('\n--- 中文包缺失（界面会显示键名/回退英文）', missZh.length, '条 ---');
missZh.forEach((k) => console.log('   ', k));
console.log('\n--- 英文包缺失', missEn.length, '条 ---');
missEn.forEach((k) => console.log('   ', k));
