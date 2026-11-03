// 图片元数据剥离（隐私合规）：在不重编码（不损画质）的前提下，移除 EXIF/GPS/注释等
// 可能泄露隐私的元数据段。纯字节级处理，无第三方依赖。
// 覆盖：JPEG(APP1/APP13/COM)、PNG(eXIf/tEXt/iTXt/zTXt/tIME)、WebP(EXIF/XMP)。
// 任何解析异常一律「原样返回」，确保绝不会破坏可用的图片文件。
const fs = require('fs');

function stripJpeg(buf) {
  if (buf.length < 4 || buf[0] !== 0xFF || buf[1] !== 0xD8) return { buf, changed: false };
  const parts = [Buffer.from([0xFF, 0xD8])];
  let i = 2;
  let changed = false;
  while (i < buf.length - 1) {
    if (buf[i] !== 0xFF) { parts.push(buf.slice(i)); break; } // 异常：保留剩余
    const start = i; // 标记起点（含可能的 0xFF 填充）
    let j = i;
    while (j < buf.length && buf[j] === 0xFF) j++;
    if (j >= buf.length) { parts.push(buf.slice(start)); break; }
    const marker = buf[j];
    if (marker === 0xD8 || marker === 0xD9) { // SOI / EOI：无长度
      parts.push(buf.slice(start, j + 1));
      i = j + 1;
      if (marker === 0xD9) break;
      continue;
    }
    if (marker === 0xDA) { parts.push(buf.slice(start)); break; } // SOS：其后为熵编码数据，整段保留
    if (marker === 0x01 || (marker >= 0xD0 && marker <= 0xD7)) { // TEM / RSTn：无长度
      parts.push(buf.slice(start, j + 1)); i = j + 1; continue;
    }
    if (j + 3 > buf.length) { parts.push(buf.slice(start)); break; }
    const len = buf.readUInt16BE(j + 1);
    const segEnd = j + 1 + len;
    if (len < 2 || segEnd > buf.length) { parts.push(buf.slice(start)); break; }
    // 丢弃：APP1(0xE1, EXIF/XMP)、APP13(0xED, IPTC)、COM(0xFE)
    if (marker === 0xE1 || marker === 0xED || marker === 0xFE) changed = true;
    else parts.push(buf.slice(start, segEnd));
    i = segEnd;
  }
  return { buf: changed ? Buffer.concat(parts) : buf, changed };
}

function stripPng(buf) {
  const SIG = Buffer.from([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]);
  if (buf.length < 8 || !buf.slice(0, 8).equals(SIG)) return { buf, changed: false };
  const drop = new Set(['eXIf', 'tEXt', 'iTXt', 'zTXt', 'tIME']);
  const parts = [SIG];
  let i = 8;
  let changed = false;
  while (i + 12 <= buf.length) {
    const len = buf.readUInt32BE(i);
    const end = i + 12 + len; // 4(len) + 4(type) + len(data) + 4(crc)
    if (end > buf.length) { parts.push(buf.slice(i)); break; }
    const type = buf.slice(i + 4, i + 8).toString('latin1');
    // 整块拷贝（含原 CRC），不修改数据则 CRC 仍有效
    if (drop.has(type)) changed = true;
    else parts.push(buf.slice(i, end));
    i = end;
    if (type === 'IEND') break;
  }
  return { buf: changed ? Buffer.concat(parts) : buf, changed };
}

function stripWebp(buf) {
  if (buf.length < 12) return { buf, changed: false };
  if (buf.slice(0, 4).toString('latin1') !== 'RIFF' || buf.slice(8, 12).toString('latin1') !== 'WEBP') {
    return { buf, changed: false };
  }
  const drop = new Set(['EXIF', 'XMP ']);
  const chunks = [];
  let i = 12;
  let changed = false;
  while (i + 8 <= buf.length) {
    const id = buf.slice(i, i + 4).toString('latin1');
    const size = buf.readUInt32LE(i + 4);
    const padded = size + (size & 1); // 奇数长度需 1 字节填充
    const end = i + 8 + padded;
    if (end > buf.length) { chunks.push(buf.slice(i)); break; } // 异常：保留剩余
    if (drop.has(id)) changed = true;
    else chunks.push(buf.slice(i, end));
    i = end;
  }
  if (!changed) return { buf, changed: false };
  const body = Buffer.concat(chunks);
  const header = Buffer.alloc(12);
  header.write('RIFF', 0, 'latin1');
  header.writeUInt32LE(body.length + 4, 4); // 文件大小 - 8 = 'WEBP'(4) + body
  header.write('WEBP', 8, 'latin1');
  return { buf: Buffer.concat([header, body]), changed: true };
}

// 原地剥离：读文件 → 按格式处理 → 仅在确有变化且结果非空时写回
function stripImageMetadata(filePath, ext) {
  try {
    const e = String(ext || '').toLowerCase();
    if (!['.jpg', '.jpeg', '.png', '.webp'].includes(e)) return { ok: true, changed: false };
    const buf = fs.readFileSync(filePath);
    const r = e === '.png' ? stripPng(buf) : (e === '.webp' ? stripWebp(buf) : stripJpeg(buf));
    if (r.changed && r.buf && r.buf.length > 8) fs.writeFileSync(filePath, r.buf);
    return { ok: true, changed: !!r.changed };
  } catch (err) {
    return { ok: false, changed: false, error: err.message };
  }
}

module.exports = { stripImageMetadata, stripJpeg, stripPng, stripWebp };
