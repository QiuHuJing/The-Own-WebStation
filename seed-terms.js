// 将 terms.md 写入数据库 settings.terms（幂等，可重复运行）
// 用法：把本文件和 terms.md 一起放到服务器项目根目录，执行 `node seed-terms.js`
const fs = require('fs');
const path = require('path');
const Database = require('better-sqlite3');

const root = __dirname;
const termsPath = path.join(root, 'terms.md');
const dbPath = path.join(root, 'data', 'webown.db');

if (!fs.existsSync(termsPath)) {
  console.error('找不到 terms.md，请确认它与本脚本在同一目录。');
  process.exit(1);
}
if (!fs.existsSync(dbPath)) {
  console.error('找不到 data/webown.db，请确认在服务器项目根目录执行本脚本。');
  process.exit(1);
}

const content = fs.readFileSync(termsPath, 'utf8');
const db = new Database(dbPath);
db.prepare(
  `INSERT INTO settings (key, value) VALUES ('terms', ?)
   ON CONFLICT(key) DO UPDATE SET value = excluded.value`
).run(content);
db.close();
console.log(`已写入服务条款（${content.length} 字符）到 settings.terms，后台「条款」页即可看到。`);
