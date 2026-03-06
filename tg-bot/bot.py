#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Security Guard TG Bot - 安全模块 Telegram 管理机器人

功能:
  - IP 封禁/解禁 (/ban /unban /ban_asn /unban_asn /banned)
  - 安全状态查看 (/security /status)
  - 每日封禁摘要
  - 异常告警 (DDoS检测/磁盘/内存)
  - 日志查看 (/logs)

注意: 容器通过 pid:host + nsenter 在宿主机命名空间执行安全命令。
"""

import asyncio
import json
import logging
import os
import subprocess
import sys
import time
import urllib.request
from collections import Counter
from datetime import datetime, timezone, timedelta, time as dt_time
from pathlib import Path
from zoneinfo import ZoneInfo

from telegram import Update, BotCommand
from telegram.ext import (
    Application,
    CommandHandler,
    ContextTypes,
)

# ── 配置 ──
TG_BOT_TOKEN = os.environ.get("TG_BOT_TOKEN", "")
TG_CHAT_ID = os.environ.get("TG_CHAT_ID", "")
TG_ADMIN_IDS = os.environ.get("TG_ADMIN_IDS", "")
TG_TOPIC_ID = os.environ.get("TG_TOPIC_ID", "")  # 群组话题 ID (发送到"安全"话题)

# 告警阈值
ALERT_BAN_THRESHOLD = int(os.environ.get("ALERT_BAN_THRESHOLD", "20"))
ALERT_BAN_PER_MINUTE = int(os.environ.get("ALERT_BAN_PER_MINUTE", "60"))

# 封禁记录目录 (容器内挂载路径)
BAN_DIR = "/etc/security-guard/ban"
STATE_DIR = "/etc/security-guard/state"
DAILY_STATE_FILE = Path(STATE_DIR) / "daily-summary.json"
SCHEDULE_TZ = ZoneInfo("Asia/Shanghai")

# 日志
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("SecurityBot")

# ── 工具函数 ──

def get_admin_ids():
    """获取管理员 ID 列表"""
    ids = set()
    if TG_CHAT_ID:
        ids.add(int(TG_CHAT_ID))
    if TG_ADMIN_IDS:
        for x in TG_ADMIN_IDS.split(","):
            x = x.strip()
            if x.isdigit():
                ids.add(int(x))
    return ids

ADMIN_IDS = get_admin_ids()

def is_admin(user_id: int) -> bool:
    return not ADMIN_IDS or user_id in ADMIN_IDS

def run_host_cmd(cmd: str) -> str:
    """通过 nsenter 在宿主机命名空间执行命令 (通过 stdin 传入避免引号问题)"""
    try:
        result = subprocess.run(
            ["nsenter", "-t", "1", "-m", "-u", "-i", "-n", "--", "bash"],
            input=cmd, capture_output=True, text=True, timeout=30
        )
        return result.stdout.strip() or result.stderr.strip() or "(无输出)"
    except subprocess.TimeoutExpired:
        return "(命令超时)"
    except Exception as e:
        return f"(错误: {e})"

def read_ban_json(filename: str) -> list:
    """直接读取封禁 JSON 文件"""
    filepath = os.path.join(BAN_DIR, filename)
    try:
        with open(filepath, "r") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return []


def format_short_dt(raw: str) -> str:
    """格式化时间: MM-DD HH:MM (24小时制)"""
    if not raw:
        return "?"
    try:
        dt = datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
        local_dt = dt.astimezone(SCHEDULE_TZ)
        return local_dt.strftime("%m-%d %H:%M")
    except Exception:
        text = str(raw)
        return text[:16] if len(text) >= 16 else text


def find_latest_ban_entry(ip: str):
    """在手动/自动封禁中查找某 IP 最新封禁记录"""
    records = []
    for b in read_ban_json("manual-banned.json"):
        if b.get("ip") == ip:
            b = dict(b)
            b["_type"] = "手动"
            records.append(b)
    for b in read_ban_json("auto-banned.json"):
        if b.get("ip") == ip:
            b = dict(b)
            b["_type"] = "自动"
            records.append(b)

    def _k(x):
        try:
            return datetime.fromisoformat(x.get("banned_at", "1970-01-01").replace("Z", "+00:00"))
        except Exception:
            return datetime.min.replace(tzinfo=timezone.utc)

    records.sort(key=_k, reverse=True)
    return records[0] if records else None


def get_recent_ban_count_24h() -> int:
    """优先用 fail2ban 日志统计 24h 新封禁，避免列表迁移导致重复计数。"""
    out = run_host_cmd("journalctl -u fail2ban --since '24 hours ago' --no-pager 2>/dev/null | grep -c ' Ban '")
    try:
        return max(0, int(str(out).strip().splitlines()[-1]))
    except Exception:
        # 回退: 用 JSON，排除迁移记录
        auto_bans = read_ban_json("auto-banned.json")
        now_ts = datetime.now(timezone.utc)
        yesterday = now_ts - timedelta(hours=24)
        cnt = 0
        for b in auto_bans:
            reason = str(b.get("reason", ""))
            if reason.startswith("migrated-"):
                continue
            try:
                ban_time = datetime.fromisoformat(b.get("banned_at", "").replace("Z", "+00:00"))
                if ban_time > yesterday:
                    cnt += 1
            except (ValueError, TypeError):
                pass
        return cnt

def load_last_daily_date() -> str:
    try:
        if DAILY_STATE_FILE.exists():
            data = json.loads(DAILY_STATE_FILE.read_text(encoding="utf-8"))
            return str(data.get("last_daily_date", ""))
    except Exception as e:
        log.warning(f"读取日报状态失败: {e}")
    return ""


def save_last_daily_date(date_text: str) -> None:
    try:
        Path(STATE_DIR).mkdir(parents=True, exist_ok=True)
        DAILY_STATE_FILE.write_text(
            json.dumps({"last_daily_date": date_text, "updated_at": datetime.now(timezone.utc).isoformat()}, ensure_ascii=False),
            encoding="utf-8",
        )
    except Exception as e:
        log.warning(f"保存日报状态失败: {e}")


def query_ip_info(ips: list) -> dict:
    """批量查询 IP 地理位置和 ASN 信息 (ip-api.com batch API)"""
    if not ips:
        return {}
    results = {}
    # ip-api.com 批量接口，最多 100 个
    batch = ips[:100]
    payload = json.dumps([{"query": ip, "fields": "query,country,city,isp,as"} for ip in batch])
    try:
        req = urllib.request.Request(
            "http://ip-api.com/batch",
            data=payload.encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            for item in data:
                ip = item.get("query", "")
                results[ip] = {
                    "country": item.get("country", "?"),
                    "city": item.get("city", ""),
                    "isp": item.get("isp", ""),
                    "asn": item.get("as", ""),
                }
    except Exception as e:
        log.warning(f"IP 查询失败: {e}")
    return results


# ════════════════════════════════════════════════════════════
# TG 命令处理
# ════════════════════════════════════════════════════════════


async def cmd_start(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    """开始命令"""
    if not is_admin(update.effective_user.id):
        await update.message.reply_text("⛔ 无权限")
        return

    await update.message.reply_text(
        "🛡️ <b>Security Guard Bot</b>\n\n"
        "📋 <b>命令列表:</b>\n"
        "/status — 封禁概览 + 最近 IP\n"
        "/ban <code>IP</code> — 手动封禁 IP\n"
        "/unban <code>IP</code> — 解封 IP\n"
        "/ban_asn <code>ASN</code> — 封禁 ASN\n"
        "/unban_asn <code>ASN</code> — 解封 ASN\n"
        "/banned — 封禁列表\n"
        "/export_banned — 导出封禁列表文件\n"
        "/security — 安全详情\n"
        "/summary — 每日综合摘要\n"
        "/logs <code>服务名</code> — 查看日志\n"
        "/run — 启动/拉起 Security 全部服务\n"
        "/stop — 停止 Security 全部服务\n"
        "/restart — 重启 Security 全部服务\n"
        "/help — 显示帮助",
        parse_mode="HTML",
    )

async def cmd_help(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    await cmd_start(update, ctx)

# ── 系统安全状态 ──

async def cmd_status(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
	if not is_admin(update.effective_user.id):
		return

	await update.message.reply_text("⏳ 正在查询 IP 信息...")

	# 读取所有封禁记录
	auto_bans = read_ban_json("auto-banned.json")
	manual_bans = read_ban_json("manual-banned.json")
	asn_bans = read_ban_json("asn-banned.json")

	msg = "📊 *安全状态*\n\n"
	msg += f"🛡️ *封禁统计:* 自动 `{len(auto_bans)}` | 手动 `{len(manual_bans)}` | ASN `{len(asn_bans)}`\n\n"

	# ── 封禁原因 Top10 统计 ──
	all_bans = []
	for b in auto_bans:
		b["_type"] = "自动"
		all_bans.append(b)
	for b in manual_bans:
		b["_type"] = "手动"
		all_bans.append(b)

	reason_counter = Counter()
	for b in all_bans:
		reason = b.get("reason", "unknown")
		if reason:
			reason_counter[reason] += 1

	if reason_counter:
		msg += "📈 *封禁原因 Top10:*\n"
		for reason, count in reason_counter.most_common(10):
			msg += f" `{reason}` — {count} 个\n"
		msg += "\n"

	# ── 最近 10 个封禁 IP ──
	def sort_key(b):
		try:
			return datetime.fromisoformat(b.get("banned_at", "1970-01-01").replace("Z", "+00:00"))
		except (ValueError, TypeError):
			return datetime.min.replace(tzinfo=timezone.utc)

	all_bans.sort(key=sort_key, reverse=True)
	recent_10 = all_bans[:10]

	if recent_10:
		# 批量查询 IP 位置
		ips = [b.get("ip", "") for b in recent_10 if b.get("ip")]
		ip_info = query_ip_info(ips)

		msg += "📋 *最近封禁 (10):*\n"
		for b in recent_10:
			ip = b.get("ip", "?")
			btype = b.get("_type", "?")
			reason = b.get("reason", "")[:15]
			port = b.get("port", "")
			path = b.get("path", "")[:20]
			info = ip_info.get(ip, {})
			loc = info.get("country", "")
			city = info.get("city", "")
			if city:
				loc = f"{loc}/{city}"
			ban_time = format_short_dt(b.get("banned_at", ""))
			extra = ""
			if port:
				extra += f":{port}"
			if path:
				extra += f" {path}"
			msg += f" `{ip}`{extra} | {loc} | {btype} | {reason} | {ban_time}\n"
	else:
		msg += "📋 暂无封禁记录\n"

	# ── ASN 统计 (所有已封禁 IP 的 ASN 分布) ──
	all_ips = [b.get("ip", "") for b in all_bans if b.get("ip")]
	if all_ips:
		# 查询前 100 个 IP 的 ASN
		sample_ips = list(set(all_ips))[:100]
		all_ip_info = query_ip_info(sample_ips)

		asn_counter = Counter()
		for ip, info in all_ip_info.items():
			asn = info.get("asn", "").strip()
			if asn:
				asn_counter[asn] += 1

		if asn_counter:
			msg += "\n📡 *ASN 统计 (Top 10):*\n"
			for asn, count in asn_counter.most_common(10):
				msg += f" `{asn}` — {count} 个 IP\n"

	if len(msg) > 4000:
		msg = msg[:4000] + "\n... (已截断)"

	await update.message.reply_text(msg, parse_mode="Markdown")

# ── 封禁/解禁 (通过宿主机执行) ──

async def cmd_ban(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not is_admin(update.effective_user.id):
        return
    args = ctx.args
    if not args:
        await update.message.reply_text("用法: /ban `IP`", parse_mode="Markdown")
        return
    ip = args[0]
    result = run_host_cmd(f"security-harden ban {ip}")
    await update.message.reply_text(f"🔒 封禁结果:\n```\n{result}\n```", parse_mode="Markdown")

async def cmd_unban(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not is_admin(update.effective_user.id):
        return
    args = ctx.args
    if not args:
        await update.message.reply_text("用法: /unban `IP`", parse_mode="Markdown")
        return
    ip = args[0]
    result = run_host_cmd(f"security-harden unban {ip}")
    await update.message.reply_text(f"🔓 解封结果:\n```\n{result}\n```", parse_mode="Markdown")

async def cmd_ban_asn(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not is_admin(update.effective_user.id):
        return
    args = ctx.args
    if not args:
        await update.message.reply_text("用法: /ban\\_asn `ASN`\n示例: /ban\\_asn 13335", parse_mode="Markdown")
        return

    asn = args[0]
    reason = " ".join(args[1:]) or "tg-manual"
    await update.message.reply_text(f"⏳ 正在查询 AS{asn} 并封禁...")
    result = run_host_cmd(f"security-harden ban-asn {asn} '{reason}'")
    await update.message.reply_text(f"🔒 ASN 封禁:\n```\n{result}\n```", parse_mode="Markdown")

async def cmd_unban_asn(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not is_admin(update.effective_user.id):
        return
    args = ctx.args
    if not args:
        await update.message.reply_text("用法: /unban\\_asn `ASN`", parse_mode="Markdown")
        return
    result = run_host_cmd(f"security-harden unban-asn {args[0]}")
    await update.message.reply_text(f"🔓 ASN 解封:\n```\n{result}\n```", parse_mode="Markdown")

async def cmd_banned(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
	if not is_admin(update.effective_user.id):
		return

	msg = "🚫 *封禁列表*\n\n"

	# 直接读取文件
	manual_bans = read_ban_json("manual-banned.json")
	auto_bans = read_ban_json("auto-banned.json")
	asn_bans = read_ban_json("asn-banned.json")

	msg += f"*手动封禁 (永久): {len(manual_bans)}*\n"
	for b in manual_bans[:10]:
		ip = b.get('ip', '')
		reason = b.get('reason', '')
		port = b.get('port', '')
		path = b.get('path', '')
		extra = f":{port}" if port else ""
		extra += f" {path[:15]}" if path else ""
		msg += f" `{ip}`{extra} | {format_short_dt(b.get('banned_at',''))} | {reason}\n"
	if len(manual_bans) > 10:
		msg += f" _... 还有 {len(manual_bans)-10} 条_\n"

	msg += f"\n*自动封禁 (30天): {len(auto_bans)}*\n"
	for b in auto_bans[:10]:
		ip = b.get('ip', '')
		reason = b.get('reason', '')
		port = b.get('port', '')
		path = b.get('path', '')
		extra = f":{port}" if port else ""
		extra += f" {path[:15]}" if path else ""
		msg += f" `{ip}`{extra} | {format_short_dt(b.get('banned_at',''))} | {reason}\n"
	if len(auto_bans) > 10:
		msg += f" _... 还有 {len(auto_bans)-10} 条_\n"

	msg += f"\n*ASN 封禁: {len(asn_bans)}*\n"
	for b in asn_bans[:10]:
		msg += f" AS`{b.get('asn','')}` | {b.get('prefix_count',0)} 个前缀 | {b.get('reason','')}\n"

	if len(msg) > 4000:
		msg = msg[:4000] + "\n... (已截断)"

	await update.message.reply_text(msg, parse_mode="Markdown")

# ── 安全详情 ──

async def cmd_security(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not is_admin(update.effective_user.id):
        return

    msg = "🛡️ *安全详情*\n\n"

    # 封禁统计 (直接读取文件)
    auto_bans = read_ban_json("auto-banned.json")
    manual_bans = read_ban_json("manual-banned.json")
    asn_bans = read_ban_json("asn-banned.json")

    # 24h 内新增（基于 fail2ban 日志）
    recent_count = get_recent_ban_count_24h()

    msg += f"*封禁统计:*\n"
    msg += f"  • 自动封禁: `{len(auto_bans)}`\n"
    msg += f"  • 手动封禁: `{len(manual_bans)}`\n"
    msg += f"  • ASN 封禁: `{len(asn_bans)}`\n"
    msg += f"  • 24h 新增: `{recent_count}`\n"

    # Fail2Ban 状态 (通过宿主机)
    f2b = run_host_cmd("systemctl is-active fail2ban 2>/dev/null || echo 未安装")
    msg += f"\n*Fail2Ban:* `{f2b}`\n"

    # UFW 状态 (通过宿主机)
    ufw_status = run_host_cmd("ufw status | head -8")
    msg += f"\n*UFW:*\n```\n{ufw_status}\n```"

    await update.message.reply_text(msg, parse_mode="Markdown")

# ── 日志查看 ──

async def cmd_logs(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not is_admin(update.effective_user.id):
        return
    svc = ctx.args[0] if ctx.args else "fail2ban"
    valid = {"fail2ban", "nginx", "ufw"}
    if svc not in valid:
        await update.message.reply_text(f"可选: {', '.join(sorted(valid))}")
        return
    if svc == "fail2ban":
        result = run_host_cmd("journalctl -u fail2ban -n 20 --no-pager")
    elif svc == "nginx":
        result = run_host_cmd("tail -30 /var/log/nginx/error.log 2>/dev/null || echo '无日志'")
    elif svc == "ufw":
        result = run_host_cmd("tail -30 /var/log/ufw.log 2>/dev/null || echo '无日志'")
    else:
        result = "(未知服务)"
    if len(result) > 3800:
        result = result[-3800:]
    await update.message.reply_text(f"📄 `{svc}` 日志:\n```\n{result}\n```", parse_mode="Markdown")

async def cmd_start_bot(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    """运行 Security Bot"""
    if not is_admin(update.effective_user.id):
        return
    result = run_host_cmd("systemctl restart security-guard-compose.service && systemctl restart fail2ban.service && systemctl start security-guard-healthcheck.timer")
    await update.message.reply_text(f"▶️ 运行 Security Bot:\n```\n{result}\n```", parse_mode="Markdown")

async def cmd_stop_bot(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    """停止 Security Bot"""
    if not is_admin(update.effective_user.id):
        return
    result = run_host_cmd("systemctl stop security-guard-healthcheck.timer && systemctl stop security-guard-compose.service && systemctl stop fail2ban.service")
    await update.message.reply_text(f"⏹️ 停止 Security Bot:\n```\n{result}\n```", parse_mode="Markdown")

async def cmd_restart_bot(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    """重启 Security Bot"""
    if not is_admin(update.effective_user.id):
        return
    result = run_host_cmd("systemctl restart security-guard-compose.service && systemctl restart fail2ban.service && systemctl restart security-guard-healthcheck.timer")
    await update.message.reply_text(f"🔄 重启 Security Bot:\n```\n{result}\n```", parse_mode="Markdown")

async def cmd_export_banned(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
	"""以文件方式发送完整封禁IP列表"""
	if not is_admin(update.effective_user.id):
		return

	auto_bans = read_ban_json("auto-banned.json")
	manual_bans = read_ban_json("manual-banned.json")
	asn_bans = read_ban_json("asn-banned.json")

	import tempfile
	with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
		f.write(f"# Security Guard 封禁列表导出\n")
		f.write(f"# 导出时间: {datetime.now(timezone.utc).isoformat()}\n")
		f.write(f"# 自动封禁: {len(auto_bans)} | 手动封禁: {len(manual_bans)} | ASN封禁: {len(asn_bans)}\n\n")

		f.write("## 手动封禁 (永久)\n")
		f.write("# IP\t端口\t路径\t封禁时间\t原因\n")
		for b in manual_bans:
			ip = b.get('ip', '')
			port = b.get('port', '')
			path = b.get('path', '')
			banned_at = b.get('banned_at', '')
			reason = b.get('reason', '')
			f.write(f"{ip}\t{port}\t{path}\t{banned_at}\t{reason}\n")

		f.write("\n## 自动封禁 (30天)\n")
		f.write("# IP\t端口\t路径\t封禁时间\t过期时间\t原因\n")
		for b in auto_bans:
			ip = b.get('ip', '')
			port = b.get('port', '')
			path = b.get('path', '')
			banned_at = b.get('banned_at', '')
			expires_at = b.get('expires_at', 'N/A')
			reason = b.get('reason', '')
			f.write(f"{ip}\t{port}\t{path}\t{banned_at}\t{expires_at}\t{reason}\n")

		f.write("\n## ASN 封禁\n")
		f.write("# ASN\t前缀数\t封禁时间\t原因\n")
		for b in asn_bans:
			f.write(f"AS{b.get('asn', '')}\t{b.get('prefix_count', 0)}\t{b.get('banned_at', '')}\t{b.get('reason', '')}\n")

		temp_path = f.name

	await update.message.reply_document(
		document=open(temp_path, 'rb'),
		filename=f"banned_ips_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
		caption=f"📋 封禁列表导出\n自动: {len(auto_bans)} | 手动: {len(manual_bans)} | ASN: {len(asn_bans)}"
	)
	os.unlink(temp_path)


# ════════════════════════════════════════════════════════════
# 定时任务: 每日摘要 + 异常检测
# ════════════════════════════════════════════════════════════

async def build_daily_summary() -> str:
	"""构建每日安全摘要"""
	now = datetime.now(timezone(timedelta(hours=8)))
	msg = f"📋 *每日安全摘要* ({now.strftime('%Y-%m-%d %H:%M')})\n\n"

	# 封禁摘要 (直接读取文件)
	auto_bans = read_ban_json("auto-banned.json")
	manual_bans = read_ban_json("manual-banned.json")
	asn_bans = read_ban_json("asn-banned.json")

	# 24h 新增
	now_ts = datetime.now(timezone.utc)
	yesterday = now_ts - timedelta(hours=24)
	recent_count = 0
	for b in auto_bans:
		try:
			ban_time = datetime.fromisoformat(b.get("banned_at", "").replace("Z", "+00:00"))
			if ban_time > yesterday:
				recent_count += 1
		except (ValueError, TypeError):
			pass

	msg += "🛡️ *封禁:*\n"
	msg += f" 24h 新封禁: `{recent_count}`\n"
	msg += f" 自动/手动/ASN: `{len(auto_bans)}/{len(manual_bans)}/{len(asn_bans)}`\n"

	# 封禁原因 Top10 统计
	all_bans = auto_bans + manual_bans
	reason_counter = Counter()
	for b in all_bans:
		reason = b.get("reason", "unknown")
		if reason:
			reason_counter[reason] += 1

	if reason_counter:
		msg += "\n📈 *封禁原因 Top10:*\n"
		for reason, count in reason_counter.most_common(10):
			msg += f" `{reason}` — {count}\n"

	# 新架构拦截链路健康检查
	try:
		realip_status = run_host_cmd("nginx -T 2>/dev/null | grep -q 'real_ip_header CF-Connecting-IP' && echo on || echo off").strip()
		blacklist_include = run_host_cmd("nginx -T 2>/dev/null | grep -q '/etc/nginx/dynamic/blacklist.conf' && echo on || echo off").strip()
		f2b_status = run_host_cmd("systemctl is-active fail2ban 2>/dev/null || echo inactive").strip()

		jail_text = run_host_cmd("cat /etc/fail2ban/jail.local 2>/dev/null")
		cc_maxretry = "?"
		cc_bantime = "?"
		in_cc = False
		for line in jail_text.splitlines():
			raw = line.strip()
			if raw.startswith("[") and raw.endswith("]"):
				in_cc = (raw == "[nginx-cc]")
				continue
			if not in_cc:
				continue
			if raw.startswith("maxretry") and "=" in raw:
				cc_maxretry = raw.split("=", 1)[1].strip()
			elif raw.startswith("bantime") and "=" in raw:
				cc_bantime = raw.split("=", 1)[1].strip()

		cloudflare_ranges = run_host_cmd("grep -c '^set_real_ip_from ' /etc/nginx/conf.d/realip-cloudflare.conf 2>/dev/null || echo 0").strip()

		msg += "\n🧪 *拦截链路健康:*\n"
		msg += f" Real-IP 还原: `{realip_status}`\n"
		msg += f" Blacklist Include: `{blacklist_include}`\n"
		msg += f" Fail2Ban: `{f2b_status}`\n"
		msg += f" nginx-cc 阈值: `maxretry={cc_maxretry}, bantime={cc_bantime}`\n"
		msg += f" 可信代理网段: `{cloudflare_ranges}`\n"
	except Exception:
		msg += "\n🧪 *拦截链路健康:* `检查失败`\n"

	return msg

async def cmd_summary(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not is_admin(update.effective_user.id):
        return
    msg = await build_daily_summary()
    await update.message.reply_text(msg, parse_mode="Markdown")


async def scheduled_daily_summary(ctx: ContextTypes.DEFAULT_TYPE):
    """定时发送每日摘要（带幂等与补偿）"""
    if not TG_CHAT_ID:
        return

    today = datetime.now(SCHEDULE_TZ).date().isoformat()
    if load_last_daily_date() == today:
        log.info("每日安全摘要已发送过，跳过重复发送")
        return

    try:
        msg = await build_daily_summary()
        kwargs = {"chat_id": int(TG_CHAT_ID), "text": msg, "parse_mode": "Markdown"}
        if TG_TOPIC_ID:
            kwargs["message_thread_id"] = int(TG_TOPIC_ID)
        await ctx.bot.send_message(**kwargs)
        save_last_daily_date(today)
        log.info("每日安全摘要已发送")
    except Exception as e:
        log.exception(f"发送每日安全摘要失败: {e}")


async def scheduled_anomaly_check(ctx: ContextTypes.DEFAULT_TYPE):
    """定时异常检测"""
    if not TG_CHAT_ID:
        return

    alerts = []

    # 1. 检测每分钟封禁数量 (高频攻击检测)
    try:
        auto_bans = read_ban_json("auto-banned.json")
        now_ts = datetime.now(timezone.utc)
        one_minute_ago = now_ts - timedelta(minutes=1)
        minute_count = 0
        for b in auto_bans:
            try:
                ban_time = datetime.fromisoformat(b.get("banned_at", "").replace("Z", "+00:00"))
                if ban_time > one_minute_ago:
                    minute_count += 1
            except (ValueError, TypeError):
                pass
        if minute_count >= ALERT_BAN_PER_MINUTE:
            alerts.append(f"🚨 *高频封禁警告*: 1分钟内新增 `{minute_count}` 个封禁，可能遭受攻击!")
    except Exception:
        pass

    # 2. 检测 Fail2Ban 服务 (仅在已安装时检查)
    f2b_installed = run_host_cmd("which fail2ban-server 2>/dev/null && echo installed || echo missing")
    if "installed" in f2b_installed:
        f2b_status = run_host_cmd("systemctl is-active fail2ban 2>/dev/null || echo stopped")
        if f2b_status.strip() not in ("active",):
            alerts.append(f"❌ Fail2Ban 已安装但未运行: `{f2b_status.strip()}`")

    # 3. 检测磁盘空间 (通过宿主机)
    try:
        disk_output = run_host_cmd("df / | tail -1 | awk '{print $5}' | tr -d '%'")
        disk_pct = int(disk_output)
        if disk_pct > 90:
            alerts.append(f"⚠️ 磁盘使用率 `{disk_pct}%`，请及时清理!")
    except (ValueError, Exception):
        pass

    # 4. 检测内存 (通过宿主机)
    try:
        mem_output = run_host_cmd("free | awk '/Mem/{printf \"%.0f\", $3/$2*100}'")
        mem_pct = int(mem_output)
        if mem_pct > 90:
            alerts.append(f"⚠️ 内存使用率 `{mem_pct}%`!")
    except (ValueError, Exception):
        pass

    # 发送告警
    if alerts:
        msg = "🚨 *安全告警*\n\n" + "\n".join(alerts)
        kwargs = {"chat_id": int(TG_CHAT_ID), "text": msg, "parse_mode": "Markdown"}
        if TG_TOPIC_ID:
            kwargs["message_thread_id"] = int(TG_TOPIC_ID)
        await ctx.bot.send_message(**kwargs)
        log.warning(f"发送 {len(alerts)} 条安全告警")


# ════════════════════════════════════════════════════════════
# 主入口
# ════════════════════════════════════════════════════════════

def main():
    if not TG_BOT_TOKEN:
        log.error("请设置 TG_BOT_TOKEN 环境变量")
        sys.exit(1)

    if not TG_CHAT_ID:
        log.warning("未设置 TG_CHAT_ID，定时任务将不会发送消息")

    log.info("Security Guard TG Bot 启动中...")

    app = Application.builder().token(TG_BOT_TOKEN).build()

    # 注册命令
    app.add_handler(CommandHandler("start", cmd_start))
    app.add_handler(CommandHandler("help", cmd_help))
    app.add_handler(CommandHandler("status", cmd_status))
    app.add_handler(CommandHandler("ban", cmd_ban))
    app.add_handler(CommandHandler("unban", cmd_unban))
    app.add_handler(CommandHandler("uban", cmd_unban))
    app.add_handler(CommandHandler("ban_asn", cmd_ban_asn))
    app.add_handler(CommandHandler("unban_asn", cmd_unban_asn))
    app.add_handler(CommandHandler("banned", cmd_banned))
    app.add_handler(CommandHandler("security", cmd_security))
    app.add_handler(CommandHandler("summary", cmd_summary))
    app.add_handler(CommandHandler("logs", cmd_logs))
    app.add_handler(CommandHandler("run", cmd_start_bot))
    app.add_handler(CommandHandler("stop", cmd_stop_bot))
    app.add_handler(CommandHandler("restart", cmd_restart_bot))
    app.add_handler(CommandHandler("export_banned", cmd_export_banned))

    # 定时任务
    job_queue = app.job_queue
    if TG_CHAT_ID:
        # 每天 08:00 CST 发送每日安全摘要（显式时区+misfire容错）
        job_queue.run_daily(
            scheduled_daily_summary,
            time=dt_time(hour=8, minute=0, tzinfo=SCHEDULE_TZ),
            name="daily_security_summary",
            job_kwargs={"misfire_grace_time": 21600, "coalesce": True, "max_instances": 1},
        )
        # 每 5 分钟异常检测
        job_queue.run_repeating(
            scheduled_anomaly_check,
            interval=300,
            first=60,
            name="security_anomaly_check",
            job_kwargs={"misfire_grace_time": 120, "coalesce": True, "max_instances": 1},
        )
        log.info("定时任务已注册: 每日安全摘要(08:00 CST) + 异常检测(5min)")

        # 启动补偿: 若今日未发日报则补发一次
        try:
            today = datetime.now(SCHEDULE_TZ).date().isoformat()
            if load_last_daily_date() != today:
                job_queue.run_once(scheduled_daily_summary, when=5, name="daily_security_summary_catchup")
                log.info("检测到今日未发日报，已触发启动补发")
        except Exception as e:
            log.warning(f"启动补发失败: {e}")

    log.info("Bot 已就绪，开始轮询...")
    app.run_polling(drop_pending_updates=True)


if __name__ == "__main__":
    main()
