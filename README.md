# Security Guard — 服务器安全加固模块

> Fail2Ban + IP/ASN 封禁 + Nginx 黑名单 + 内核优化 + 安全 TG Bot  

默认封禁动作为 `iptables-multiport[blocktype=DROP]`（不依赖 UFW，封禁使用 DROP）。
> 独立部署 · 自动解禁 · Telegram 管理

---

## 目录

- [功能概览](#功能概览)
- [快速部署](#快速部署)
- [安全加固](#安全加固)
- [Telegram Bot](#telegram-bot)
- [文件结构](#文件结构)

---

## 功能概览

| 组件 | 功能 | 影响 |
|------|------|------|
| **Fail2Ban** | SSH/Nginx 恶意扫描 + CC 攻击防护 | 极低 |
| **Nginx 黑名单** | IP 黑名单 + inotify 热重载 | 极低 |
| **ASN 封禁** | ipset + iptables 整段 IP 封禁 | 极低 |
| **内核加固** | SYN Flood / IP 欺骗 / 连接优化 | 正向优化 |
| **自动解禁 Cron** | 每天 03:00 清理过期封禁 | 极低 |
| **Security TG Bot** | Telegram 管理 + 每日摘要 + 告警 | 独立运行 |

---

## 架构与部署约定

- **源码目录**：`/root/code/fail2ban-nginx-security`
- **运行目录**：`/etc/security-guard`
- `scripts/deploy.sh` 会先在源码目录构建 `security-guard-bot:latest`，再把运行所需文件同步到 `/etc/security-guard`
- `/etc/security-guard` 只保留 `docker-compose.yml`、`.env`、`ban/`、`state/`、`scripts/`，不再保留 `tg-bot/` 源码目录
- 不要在源码目录直接执行 `docker compose up`

## 快速部署

### 开发仓库 vs 生产目录（重要）

如果你是在这台机器上直接维护本项目，请区分：

- **开发仓库**：`/root/code/fail2ban-nginx-security`
- **生产目录**：`/etc/security-guard`

也就是说，修改源码仓库后，必须通过部署脚本同步到 `/etc/security-guard`，再以生产目录中的实际状态为准。

### 推荐更新/验证流程

```bash
# 1) 修改源码
cd /root/code/fail2ban-nginx-security

# 2) 先做基本校验
bash -n scripts/deploy.sh
docker compose --env-file .env.example -f docker-compose.yml config

# 3) 提交代码
git add .
git commit -m "your change"

# 4) 执行部署脚本
sudo bash scripts/deploy.sh

# 5) 验证生产环境是否真的更新
docker compose --env-file /etc/security-guard/.env -f /etc/security-guard/docker-compose.yml ps
docker inspect security-bot
```

### 一键部署

```bash
# 1. 进入源码目录
cd /root/code/fail2ban-nginx-security

# 2. 一键部署
sudo bash scripts/deploy.sh
```

脚本将自动：
- ✅ 在源码目录构建 `security-guard-bot:latest`
- ✅ 安装 `security-harden` 到 `/usr/local/bin/`
- ✅ 安装 `sg` 管理工具到 `/usr/local/bin/`
- ✅ 创建 `/etc/security-guard/` 目录结构
- ✅ 补齐 `/etc/security-guard/.env` 缺失字段
- ✅ 运行安全加固 (Fail2Ban + 黑名单 + 内核优化)
- ✅ 安装自动解禁定时任务
- ✅ 启动安全 TG Bot (需配置 Token)

### `sg` — 管理工具

```bash
# 交互式菜单
sg

# 命令行模式
sg start          # 启动 Security Bot
sg stop           # 停止
sg restart        # 重启
sg status         # 安全状态 + 容器状态
sg logs           # Bot 日志
sg security       # 安全状态总览
sg banned         # 封禁列表
sg ban <IP>       # 封禁 IP
sg unban <IP>     # 解封 IP
sg ban-asn <ASN>  # 封禁 ASN
sg harden         # 运行安全加固
sg config         # 编辑配置
```

### 配置 Telegram Bot

```bash
# 编辑环境变量
nano /etc/security-guard/.env

# 填入:
SEC_TG_BOT_TOKEN=你的Bot_Token
SEC_TG_CHAT_ID=你的Chat_ID

# 重启 Bot
cd /etc/security-guard && docker compose restart
```

---

## 安全加固

### `security-harden` — 一键安全加固

```bash
# 安装/卸载
security-harden install        # 安装全部组件
security-harden uninstall      # 卸载

# IP 封禁 (手动=永久, 自动=30天后解禁)
security-harden ban 1.2.3.4        # 永久封禁
security-harden ban-auto 1.2.3.4   # 30天后自动解禁
security-harden unban 1.2.3.4      # 解封

# ASN 封禁
security-harden ban-asn 13335 "Cloudflare"   # 封禁整个 ASN
security-harden unban-asn 13335              # 解封 ASN
security-harden list-asn                     # 列出 ASN 封禁

# 查看状态
security-harden status             # 安全状态总览
security-harden banned             # 封禁列表
security-harden summary            # JSON 摘要 (供脚本使用)
security-harden logs               # 安全日志
```

### 自动解禁规则

- **自动封禁** (Fail2Ban 触发): 30 天后自动解禁
- **手动封禁** (`security-harden ban`): 永不自动解禁
- **ASN 封禁**: 永不自动解禁
- 定时任务: 每天 03:00 执行清理

### 运行策略与性能设计

为降低服务器性能消耗并避免 Fail2Ban 重启时的连锁开销，当前设计采用以下策略：

- **保留 `actionban`，移除 `actionunban`**
  - 新封禁时才调用 `security-harden ban-auto` 记录到 `auto-banned.json`
  - Fail2Ban 停止/重启时**不再**对每个已封禁 IP 逐条调用 `security-harden unban`
  - 这样可以显著减少 shell 进程、JSON 读写、黑名单刷新与重启耗时

- **自动解封不依赖 Fail2Ban stop/restart**
  - 自动封禁仍然写入 `expires_at`
  - 过期解封由 `security-harden auto-unban` 定时任务负责
  - 手动解封仍使用 `security-harden unban` / `/unban`

- **重复自动封禁不重写时间戳**
  - 同一 IP 若已存在于 `auto-banned.json`，重复封禁时保留原 `banned_at` / `expires_at`
  - 避免 Fail2Ban 重载或重复 ban 时，把历史封禁误记成“刚刚新增”

- **服务器自身公网 IP 防护**
  - 自动封禁逻辑会跳过本机公网 IP
  - 生成 `jail.local` 时，会自动把服务器公网 IP 写入 `ignoreip`

- **高频封禁告警抑制**
  - TG Bot 在 Fail2Ban 刚重启后的短时间内，会抑制“高频封禁警告”
  - 避免重启后的状态同步被误判为真实攻击峰值

这些设计的目标是：**以尽量少的文件读写和外部进程开销，保留真实攻击记录能力，同时降低重启抖动与误报。**

---

## Telegram Bot

### 命令列表

| 命令 | 功能 |
|------|------|
| `/status` | 系统安全状态 (磁盘/内存/封禁) |
| `/ban IP` | 手动封禁 IP |
| `/unban IP` | 解封 IP（若该 IP 当前未封禁，会返回无需解封提示） |
| `/ban_asn ASN` | 封禁 ASN |
| `/unban_asn ASN` | 解封 ASN |
| `/banned` | 封禁列表（显示 IP / 时间 / 封禁原因） |
| `/export_banned` | 导出封禁列表文件 |
| `/security` | 安全详情 |
| `/summary` | 每日综合摘要 |
| `/logs [服务]` | 查看日志 (fail2ban/nginx/ufw) |
| `/run` | 运行 Security Bot |
| `/stop` | 停止 Security Bot |
| `/restart` | 重启 Security Bot |

### 定时任务

| 任务 | 频率 | 说明 |
|------|------|------|
| **每日安全摘要** | 每天 08:00 | 封禁统计 + 系统资源 |
| **异常检测** | 每 5 分钟 | 高频封禁(1分钟≥60IP)/Fail2Ban/磁盘/内存 |

### 通知工具

```python
# 在任意 Python 脚本中:
from notify import send_tg
send_tg("🛡️ 安全告警: 检测到异常")
```

```bash
# 命令行:
python /root/code/fail2ban-nginx-security/tg-bot/notify.py "安全事件通知"
```

---

## 文件结构

```text
/root/code/fail2ban-nginx-security/
├── docker-compose.yml            ← Docker 编排
├── .env.example                  ← 运行时环境变量模板
├── scripts/
│   ├── security-harden.sh
│   ├── Fail2ban.sh
│   ├── nginx-ban.sh
│   └── deploy.sh
└── tg-bot/
    ├── Dockerfile
    ├── bot.py
    ├── notify.py
    └── requirements.txt

/etc/security-guard/
├── ban/
│   ├── auto-banned.json
│   ├── manual-banned.json
│   └── asn-banned.json
├── state/
├── docker-compose.yml
├── .env
└── scripts/
```

---

## 与 AI Proxy 的关系

此安全模块从 `ai-proxy` 项目中独立出来，两者完全解耦：

- **独立部署**: 各自有独立的 `docker-compose.yml` 和部署脚本
- **独立 TG Bot**: 使用不同的 Bot Token，互不干扰
- **数据隔离**: 安全数据存储在 `/etc/security-guard/`，AI 代理数据在 `/etc/ai-proxy/`
- **可复用**: 安全模块可独立部署到任何 VPS，不依赖 AI Proxy
