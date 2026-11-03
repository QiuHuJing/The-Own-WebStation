# 月之海 · 个人小站（项目代号 WebOwn）

二次元主题个人站点：文章 / 图库 / GitHub 项目 / 赞助 / 评论互动 / 管理后台。
后端 Node.js + Express + SQLite（单文件、单进程），前端原生 HTML/CSS/JS（无构建步骤），
专为 **低配服务器（2核 / 3.5GB，与 NoneBot + NapCat 共存）** 设计，常驻内存约 60~100MB。

## 功能

- 📝 文章发布（Markdown，管理后台发布）
- 🖼️ 图库（后台上传，魔数校验防伪装文件）
- 🐙 GitHub 项目展示
- 💗 点赞 / ⭐ 收藏 / 🔗 分享 / 💬 评论（登录用户）
- ☕ 赞助窗口 + 赞助留言墙
- 📜 备案号占位 + 服务条款（首次访问 / 登录 / 注册均需同意，服务端留存同意记录）
- 🌙 白天主题（粉紫） / 夜晚主题（黑灰），跟随系统 + 手动切换
- ✨ 进入动画、圆润 UI、丝滑切换动画
- 🔐 管理后台 `/#/admin`（概览 / 文章 / 图库 / 项目 / 评论 / 赞助 / 条款）

## 快速开始（本地）

```bash
npm install
npm start
# 打开 http://localhost:3000
```

**第一个注册的账号自动成为管理员（站长）。**

## 部署到服务器（Linux）

### 1. 上传代码

```bash
# 将整个 WebOwn 目录上传到服务器，例如 /opt/webown
scp -r WebOwn user@your-server:/opt/webown
```

### 2. 安装依赖（服务器需 Node ≥ 18）

```bash
cd /opt/webown
npm install --omit=dev
```

> 若 better-sqlite3 编译慢，先 `npm config set registry https://registry.npmmirror.com`

### 3. 配置环境变量

```bash
cp .env.example .env
vi .env
```

- `JWT_SECRET`：**必填**，随机长字符串（`openssl rand -hex 48` 生成）
- `NODE_ENV=production`
- `TRUST_PROXY=1`（使用 nginx 反代 + HTTPS 时开启，Cookie 将标记 Secure）
- `PORT=3000`

### 4. 限制内存（关键：与机器人共存不 OOM）

用 systemd 托管并限制内存，创建 `/etc/systemd/system/webown.service`：

```ini
[Unit]
Description=WebOwn personal site
After=network.target

[Service]
Type=simple
WorkingDirectory=/opt/webown
ExecStart=/usr/bin/node --max-old-space-size=256 server.js
Restart=always
RestartSec=5
MemoryMax=300M
Environment=NODE_ENV=production
User=www-data

[Install]
WantedBy=multi-user.target
```

```bash
systemctl daemon-reload
systemctl enable --now webown
```

`--max-old-space-size=256` + `MemoryMax=300M` 双重限制，最坏情况也只占 300MB，
不会影响 NoneBot / NapCat。

### 5. nginx 反向代理 + HTTPS（强烈建议）

```nginx
server {
    listen 80;
    server_name your-domain.com;
    return 301 https://$host$request_uri;
}
server {
    listen 443 ssl http2;
    server_name your-domain.com;
    ssl_certificate     /etc/letsencrypt/live/your-domain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/your-domain.com/privkey.pem;

    client_max_body_size 10m;
    gzip on;
    gzip_types text/css application/javascript application/json;

    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

证书用 certbot 免费申请：`certbot --nginx -d your-domain.com`

## 安全措施清单

| 层面 | 措施 |
|------|------|
| 传输 | HSTS、HTTPS（nginx）、`upgrade-insecure-requests` |
| 头部 | helmet 全套安全头 + 严格 CSP（禁止内联/外域脚本） |
| 注入 | SQLite 全量 prepared statement，参数化查询 |
| XSS | 前端先转义后渲染；CSP 兜底；评论纯文本存储 |
| CSRF | SameSite=Lax Cookie + 自定义头 `X-Requested-With` 双校验 |
| 暴力破解 | 登录接口 IP 限速 + 5 次失败锁定 15 分钟 |
| 滥用 | 全局 API 限速（120 次/分）、注册限速（10 次/时） |
| 上传 | 扩展名白名单 + 文件魔数校验 + 8MB 上限 + 随机文件名 |
| 密码 | bcrypt（10 轮）哈希，不明文 |
| 会话 | JWT httpOnly Cookie，7 天过期 |
| 权限 | 管理接口全部要求 admin 角色，前后端双重校验 |

## 待你补充的内容

1. **备案号**：编辑 `public/index.html` 页脚 `footer-icp` 处
2. **收款码**：把图片放到 `public/assets/` 并替换赞助页占位块
3. **站点名 / 角色文案**：可按喜好修改 `index.html` 的标题与页脚
4. **默认条款**：登录后台 → 条款面板，粘贴你的正式条款

## 目录结构

```
WebOwn/
├── server.js            # 服务入口（安全头/限速/静态/路由）
├── lib/db.js            # SQLite schema
├── lib/auth.js          # JWT/bcrypt/CSRF/防爆破/条款记录
├── routes/api.js        # 公开 API + 互动
├── routes/admin.js      # 管理端 API（含上传校验）
├── public/
│   ├── index.html       # SPA 壳（进入动画/导航/条款弹窗）
│   ├── css/style.css    # 双主题样式
│   └── js/app.js        # 路由/视图/Markdown 渲染
└── data/                # 运行时生成：数据库 + 上传图片（注意备份）
```
