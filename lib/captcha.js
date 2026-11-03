// 图形验证码：零第三方依赖，用 crypto 生成随机字符并绘制为 SVG
// 说明：返回 SVG 字符串，前端以 data:image/svg+xml 作为 <img> 展示（CSP img-src 已放行 data:）
const crypto = require('crypto');

// 字符池：去掉易混淆的 0/O、1/I/L，降低人工识别歧义
const CHARS = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789';
const LEN = 4;
const WIDTH = 128;
const HEIGHT = 48;

// 墨色（深色系）：配合浅色底，在浅色/深色主题下都能看清
const INK = ['#3b2b4a', '#46365f', '#2f4858', '#5a2f4a', '#31483a', '#4a3a22'];

const ri = (min, max) => crypto.randomInt(min, max + 1);
const pick = (arr) => arr[ri(0, arr.length - 1)];

function randomCode() {
  let s = '';
  for (let i = 0; i < LEN; i++) s += CHARS[ri(0, CHARS.length - 1)];
  return s;
}

function draw(code) {
  let svg = `<svg xmlns="http://www.w3.org/2000/svg" width="${WIDTH}" height="${HEIGHT}" viewBox="0 0 ${WIDTH} ${HEIGHT}">`;
  svg += `<rect width="${WIDTH}" height="${HEIGHT}" fill="#f6f2fa"/>`;
  // 干扰线
  for (let i = 0; i < 4; i++) {
    const x1 = ri(0, WIDTH);
    const y1 = ri(2, HEIGHT - 2);
    const x2 = ri(0, WIDTH);
    const y2 = ri(2, HEIGHT - 2);
    svg += `<line x1="${x1}" y1="${y1}" x2="${x2}" y2="${y2}" stroke="${pick(INK)}" stroke-width="1" stroke-opacity="0.35"/>`;
  }
  // 噪点
  for (let i = 0; i < 40; i++) {
    svg += `<circle cx="${ri(0, WIDTH)}" cy="${ri(0, HEIGHT)}" r="${ri(1, 2)}" fill="${pick(INK)}" fill-opacity="0.22"/>`;
  }
  // 字符：逐个随机旋转与轻微位移，增加机器识别难度
  for (let i = 0; i < code.length; i++) {
    const x = 18 + i * 28;
    const y = 34 + ri(-3, 4);
    const rot = ri(-16, 16);
    svg += `<text x="${x}" y="${y}" text-anchor="middle" font-family="Georgia,'Times New Roman',serif"`
      + ` font-size="28" font-weight="700" fill="${pick(INK)}"`
      + ` transform="rotate(${rot} ${x} ${y})">${code[i]}</text>`;
  }
  svg += '</svg>';
  return svg;
}

// 生成一对：code 存服务端校验，svg 下发前端展示
function create() {
  const code = randomCode();
  return { code, svg: draw(code) };
}

module.exports = { create, LEN };
