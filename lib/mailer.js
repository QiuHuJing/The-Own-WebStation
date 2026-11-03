// 邮件发送模块（可插拔，优先级：Resend HTTPS API > SMTP > 开发模式）
// - 配置了 RESEND_API_KEY → 走 Resend 官方 REST API（HTTPS/443），彻底绕过云服务器 SMTP 端口/IP 黑名单
// - 否则配置了 SMTP_*      → 走 SMTP（适合本地开发或自有邮件服务器）
// - 都没有                → 开发模式：验证码打印到服务器控制台（仅限本地/测试环境）
const nodemailer = require('nodemailer');

// ===== Resend（推荐，走 443，使用自有域名发信）=====
const RESEND_API_KEY = process.env.RESEND_API_KEY;
const RESEND_FROM = process.env.RESEND_FROM || 'noreply@yuezhihai.xyz';
const RESEND_FROM_NAME = process.env.RESEND_FROM_NAME || '月之海';
const RESEND_API_URL = 'https://api.resend.com/emails';

// ===== SMTP（回退）=====
const SMTP_HOST = process.env.SMTP_HOST;
const SMTP_PORT = parseInt(process.env.SMTP_PORT) || 465;
const SMTP_USER = process.env.SMTP_USER;
const SMTP_PASS = process.env.SMTP_PASS;
const SMTP_FROM = process.env.SMTP_FROM || SMTP_USER;

const useResend = !!RESEND_API_KEY;
const useSMTP = !useResend && !!(SMTP_HOST && SMTP_USER && SMTP_PASS);
const devMode = !useResend && !useSMTP;

let transporter = null;
if (useSMTP) {
  transporter = nodemailer.createTransport({
    host: SMTP_HOST,
    port: SMTP_PORT,
    secure: SMTP_PORT === 465,
    auth: { user: SMTP_USER, pass: SMTP_PASS },
  });
}

if (devMode) {
  console.warn('[邮件] 未配置 RESEND_API_KEY 或 SMTP_*，验证码将以开发模式输出到控制台。生产环境请在 .env 配置 RESEND_API_KEY（推荐）或 SMTP_*。');
}

async function sendVerifyCode(email, code, purpose) {
  const isReset = purpose === 'reset';
  const title = isReset ? '重置密码验证码' : '注册验证码';
  const tip = isReset
    ? '你正在重置账号密码。如果这不是你本人操作，请立即忽略本邮件并检查账号安全。'
    : '如果不是你本人操作，请忽略本邮件。';

  const html = `<div style="font-family:sans-serif;max-width:420px;margin:0 auto;padding:24px;border-radius:16px;background:#faf5fd;border:1px solid #eee">
      <h2 style="color:#b863d9;margin:0 0 12px">🌙 月之海 · 星娅小站</h2>
      <p style="color:#555;font-size:14px">你的${title}：</p>
      <p style="font-size:30px;font-weight:700;letter-spacing:8px;color:#b863d9;margin:8px 0 16px">${code}</p>
      <p style="color:#999;font-size:12px">10 分钟内有效。${tip}</p>
    </div>`;
  const text = `你的${title}是：${code}\n10 分钟内有效。${tip}`;

  if (useResend) {
    const res = await fetch(RESEND_API_URL, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${RESEND_API_KEY}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        from: `${RESEND_FROM_NAME} <${RESEND_FROM}>`,
        to: [email],
        subject: `月之海 · ${title}`,
        html,
        text,
      }),
    });
    if (!res.ok) {
      const body = await res.text();
      throw new Error(`Resend ${res.status}: ${body}`);
    }
    return { dev: false, provider: 'resend' };
  }

  if (useSMTP) {
    await transporter.sendMail({
      from: SMTP_FROM,
      to: email,
      subject: `月之海 · ${title}`,
      text,
      html,
    });
    return { dev: false, provider: 'smtp' };
  }

  // 开发模式
  console.log(`[开发模式] ${title} -> ${email}: ${code} (10 分钟内有效)`);
  return { dev: true };
}

module.exports = { sendVerifyCode, mailEnabled: !devMode };
