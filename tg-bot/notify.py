#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TG 通知工具 - 供其他脚本调用发送 Telegram 消息

用法:
  # 作为命令行工具
  python notify.py "消息内容"
  python notify.py --title "标题" --body "正文"

  # 作为 Python 模块
  from notify import send_tg
  send_tg("🛡️ 安全告警: 检测到异常")
"""

import asyncio
import json
import os
import sys
import urllib.request

TG_BOT_TOKEN = os.environ.get("TG_BOT_TOKEN", "")
TG_CHAT_ID = os.environ.get("TG_CHAT_ID", "")


def send_tg(message: str, parse_mode: str = "Markdown") -> bool:
    """
    同步发送 Telegram 消息。
    可在任何 Python 脚本中 import 使用。
    """
    if not TG_BOT_TOKEN or not TG_CHAT_ID:
        print("[TG Notify] 未配置 TG_BOT_TOKEN 或 TG_CHAT_ID")
        return False

    url = f"https://api.telegram.org/bot{TG_BOT_TOKEN}/sendMessage"
    payload = json.dumps({
        "chat_id": TG_CHAT_ID,
        "text": message,
        "parse_mode": parse_mode,
    }).encode("utf-8")

    try:
        req = urllib.request.Request(
            url,
            data=payload,
            method="POST",
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            result = json.loads(resp.read().decode())
            if result.get("ok"):
                return True
            else:
                print(f"[TG Notify] API 错误: {result}")
                return False
    except Exception as e:
        print(f"[TG Notify] 发送失败: {e}")
        return False


def send_alert(title: str, body: str, level: str = "info") -> bool:
    """
    发送结构化告警消息。

    level: info | warn | error | critical
    """
    emojis = {
        "info": "ℹ️",
        "warn": "⚠️",
        "error": "❌",
        "critical": "🚨",
    }
    emoji = emojis.get(level, "ℹ️")
    msg = f"{emoji} *{title}*\n\n{body}"
    return send_tg(msg)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="发送 Telegram 通知")
    parser.add_argument("message", nargs="?", help="消息内容")
    parser.add_argument("--title", "-t", help="标题")
    parser.add_argument("--body", "-b", help="正文")
    parser.add_argument("--level", "-l", default="info",
                        choices=["info", "warn", "error", "critical"])

    args = parser.parse_args()

    if args.title and args.body:
        ok = send_alert(args.title, args.body, args.level)
    elif args.message:
        ok = send_tg(args.message)
    else:
        # 从 stdin 读取
        msg = sys.stdin.read().strip()
        if msg:
            ok = send_tg(msg)
        else:
            parser.print_help()
            sys.exit(1)

    sys.exit(0 if ok else 1)
