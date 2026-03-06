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

## 快速部署

```bash
# 1. 进入安全模块目录
cd security/

# 2. 一键部署
sudo bash scripts/deploy.sh
```

脚本将自动：
- ✅ 交互式配置 TG Bot Token / Chat ID
- ✅ 安装 `security-harden` 到 `/usr/local/bin/`
- ✅ 安装 `sg` 管理工具到 `/usr/local/bin/`
- ✅ 创建 `/etc/security-guard/` 目录结构
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
python /etc/security-guard/tg-bot/notify.py "安全事件通知"
```

---

## 文件结构

```
security/
├── docker-compose.yml            ← Docker 编排
├── .env                          ← 环境变量 (TG Bot Token)
├── .gitignore
├── README.md                     ← 本文档
├── scripts/
│   ├── security-harden.sh        ← 安全加固一键脚本
│   ├── Fail2ban.sh               ← Fail2Ban 独立配置
│   ├── nginx-ban.sh              ← Nginx 封禁脚本
│   └── deploy.sh                 ← 部署脚本
└── tg-bot/
    ├── Dockerfile
    ├── bot.py                    ← 安全 TG Bot
    ├── notify.py                 ← 通知工具
    └── requirements.txt

# 服务器部署目录
/etc/security-guard/
├── ban/
│   ├── auto-banned.json          ← 自动封禁记录
│   ├── manual-banned.json        ← 手动封禁记录 (永久)
│   └── asn-banned.json           ← ASN 封禁记录
├── docker-compose.yml
├── .env
├── scripts/
└── tg-bot/
```

---

## 与 AI Proxy 的关系

此安全模块从 `ai-proxy` 项目中独立出来，两者完全解耦：

- **独立部署**: 各自有独立的 `docker-compose.yml` 和部署脚本
- **独立 TG Bot**: 使用不同的 Bot Token，互不干扰
- **数据隔离**: 安全数据存储在 `/etc/security-guard/`，AI 代理数据在 `/etc/ai-proxy/`
- **可复用**: 安全模块可独立部署到任何 VPS，不依赖 AI Proxy
