#!/bin/bash
# ============================================================
# Security Guard - 一键部署脚本
# 功能: 安装安全加固脚本 + 配置 TG Bot + 安装 sg 管理工具
# ============================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ "$(basename "$SCRIPT_DIR")" = "scripts" ]; then
    PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
else
    PROJECT_DIR="$SCRIPT_DIR"
fi
BASE_DIR="/etc/security-guard"
ENV_FILE="${BASE_DIR}/.env"

# ── 颜色 ──
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

log()   { echo -e "${GREEN}[✓]${NC} $1"; }
error() { echo -e "${RED}[✗]${NC} $1" >&2; }
warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
info()  { echo -e "${BLUE}[→]${NC} $1"; }
step()  { echo -e "\n${CYAN}${BOLD}━━━ $1 ━━━${NC}\n"; }

sync_tree() {
    local src="$1"
    local dst="$2"

    [ -d "$src" ] || return 0
    mkdir -p "$dst"

    if command -v rsync >/dev/null 2>&1; then
        rsync -a --delete \
            --exclude "__pycache__/" \
            --exclude "*.pyc" \
            --exclude "*.pyo" \
            "${src}/" "${dst}/"
    else
        cp -a "${src}/." "${dst}/"
        find "$dst" -type d -name "__pycache__" -prune -exec rm -rf {} + 2>/dev/null || true
        find "$dst" -type f \( -name "*.pyc" -o -name "*.pyo" \) -delete 2>/dev/null || true
    fi
}

# ── 检查 Root ──
if [ "$EUID" -ne 0 ]; then
    error "请使用 root 权限运行: sudo bash deploy.sh"
    exit 1
fi

# ══════════════════════════════════════════════════════════════
# 1. 创建目录结构
# ══════════════════════════════════════════════════════════════
step "1/6 创建目录结构"

mkdir -p "${BASE_DIR}"/{ban,scripts,tg-bot}
cd "$BASE_DIR"
log "工作目录: $BASE_DIR"

# ══════════════════════════════════════════════════════════════
# 2. 配置 Telegram Bot
# ══════════════════════════════════════════════════════════════
step "2/6 配置 Telegram Bot"

if [ -f "$ENV_FILE" ]; then
    log "检测到已有配置"
    source "$ENV_FILE"
    echo -e "  当前 Token: ${GREEN}${SEC_TG_BOT_TOKEN:-(未配置)}${NC}"
    echo -e "  当前 Chat ID: ${GREEN}${SEC_TG_CHAT_ID:-(未配置)}${NC}"
    echo
    read -p "是否重新配置 TG Bot? (y/N): " reconfig
    if [[ ! "$reconfig" =~ ^[Yy]$ ]]; then
        log "保留已有配置"
    else
        unset SEC_TG_BOT_TOKEN SEC_TG_CHAT_ID SEC_TG_ADMIN_IDS
    fi
fi

if [ -z "${SEC_TG_BOT_TOKEN:-}" ]; then
    info "从 @BotFather 创建 Bot 获取 Token"
    info "从 @userinfobot 获取 Chat ID"
    echo
    read -p "Security Bot Token (留空可稍后配置): " SEC_TG_BOT_TOKEN
    SEC_TG_BOT_TOKEN=${SEC_TG_BOT_TOKEN:-}
    read -p "TG Chat ID (留空可稍后配置): " SEC_TG_CHAT_ID
    SEC_TG_CHAT_ID=${SEC_TG_CHAT_ID:-}
    read -p "TG Admin IDs (逗号分隔，留空同 Chat ID): " SEC_TG_ADMIN_IDS
    SEC_TG_ADMIN_IDS=${SEC_TG_ADMIN_IDS:-${SEC_TG_CHAT_ID}}
    read -p "群组话题 ID (可选，留空不使用话题): " SEC_TG_TOPIC_ID
    SEC_TG_TOPIC_ID=${SEC_TG_TOPIC_ID:-}

    cat > "$ENV_FILE" <<ENVEOF
# Security Guard 配置 (由 deploy.sh 生成)
# 生成时间: $(date '+%Y-%m-%d %H:%M:%S')

# Telegram Bot (安全模块专用)
SEC_TG_BOT_TOKEN=${SEC_TG_BOT_TOKEN}
SEC_TG_CHAT_ID=${SEC_TG_CHAT_ID}
SEC_TG_ADMIN_IDS=${SEC_TG_ADMIN_IDS}
SEC_TG_TOPIC_ID=${SEC_TG_TOPIC_ID}

# 告警阈值 (每分钟封禁超过此数触发告警)
ALERT_BAN_PER_MINUTE=60
ENVEOF
    chmod 600 "$ENV_FILE"
    log "配置已保存: $ENV_FILE"
fi

# ══════════════════════════════════════════════════════════════
# 3. 部署文件
# ══════════════════════════════════════════════════════════════
step "3/6 部署配置文件"

if [ "$PROJECT_DIR" != "$BASE_DIR" ]; then
    # 复制 docker-compose
    cp -f "${PROJECT_DIR}/docker-compose.yml" "${BASE_DIR}/"

    # 同步源码目录到 /etc/security-guard（自动过滤 __pycache__）
    sync_tree "${PROJECT_DIR}/tg-bot" "${BASE_DIR}/tg-bot"
    sync_tree "${PROJECT_DIR}/scripts" "${BASE_DIR}/scripts"
    log "源码已同步到 ${BASE_DIR} (tg-bot/, scripts/, docker-compose.yml)"
fi

# 验证关键文件
if [ ! -f "${BASE_DIR}/tg-bot/Dockerfile" ]; then
    error "tg-bot/Dockerfile 缺失！请检查项目文件完整性"
    error "期望位置: ${BASE_DIR}/tg-bot/Dockerfile"
    ls -la "${BASE_DIR}/tg-bot/" 2>/dev/null || true
fi

log "配置文件部署完成"

# ══════════════════════════════════════════════════════════════
# 4. 安装安全加固脚本
# ══════════════════════════════════════════════════════════════
step "4/6 安装安全加固脚本"

if [ -f "${BASE_DIR}/scripts/security-harden.sh" ]; then
    cp -f "${BASE_DIR}/scripts/security-harden.sh" /usr/local/bin/security-harden
    chmod +x /usr/local/bin/security-harden
    log "'security-harden' 已安装到 /usr/local/bin/"
fi

# Fail2Ban 脚本
for script in Fail2ban.sh nginx-ban.sh; do
    if [ -f "${BASE_DIR}/scripts/${script}" ]; then
        cp -f "${BASE_DIR}/scripts/${script}" "/usr/local/bin/${script%.sh}"
        chmod +x "/usr/local/bin/${script%.sh}"
        log "'${script%.sh}' 已安装"
    fi
done

# ══════════════════════════════════════════════════════════════
# 5. 安装 sg 管理工具
# ══════════════════════════════════════════════════════════════
step "5/6 安装 'sg' 管理工具"

cat > /usr/local/bin/sg <<'SG_EOF'
#!/bin/bash
# ============================================================
# sg - Security Guard 管理工具
# ============================================================

set -euo pipefail

BASE_DIR="/etc/security-guard"
ENV_FILE="${BASE_DIR}/.env"

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

cd "$BASE_DIR" 2>/dev/null || { echo -e "${RED}目录不存在: ${BASE_DIR}${NC}"; exit 1; }

show_menu() {
    clear
    echo -e "${GREEN}${BOLD}=== Security Guard 管理工具 ===${NC}"
    echo
    echo "1. 启动 Security Bot     (start)"
    echo "2. 停止 Security Bot     (stop)"
    echo "3. 重启 Security Bot     (restart)"
    echo "4. 查看服务状态          (status)"
    echo "5. 查看 Bot 日志         (logs)"
    echo "6. 安全状态总览          (security)"
    echo "7. 封禁列表              (banned)"
    echo "8. 编辑配置              (config)"
    echo "9. 证书管理              (certbot)"
    echo -e "${YELLOW}10. 运行安全加固          (harden)${NC}"
    echo -e "${RED}11. 卸载                 (uninstall)${NC}"
    echo "0. 退出"
    echo
    read -p "请输入选项 [0-11]: " choice

    case $choice in
        1) do_start ;;
        2) do_stop ;;
        3) do_restart ;;
        4) do_status ;;
        5) do_logs ;;
        6) do_security ;;
        7) do_banned ;;
        8) do_config ;;
        9) do_certbot ;;
        10) do_harden ;;
        11) do_uninstall ;;
        0) exit 0 ;;
        *) echo -e "${RED}无效选项${NC}"; sleep 1; show_menu ;;
    esac
}

do_start() {
    echo -e "${GREEN}启动 Security Bot...${NC}"
    docker compose up -d
    echo -e "${GREEN}✓ 服务已启动${NC}"
    read -p "按回车继续..."; show_menu
}

do_stop() {
    echo -e "${YELLOW}停止 Security Bot...${NC}"
    docker compose down
    echo -e "${GREEN}✓ 服务已停止${NC}"
    read -p "按回车继续..."; show_menu
}

do_restart() {
    echo -e "${YELLOW}重启 Security Bot...${NC}"
    docker compose down && docker compose up -d
    echo -e "${GREEN}✓ 服务已重启${NC}"
    read -p "按回车继续..."; show_menu
}

do_status() {
    echo -e "${BOLD}容器状态:${NC}"
    docker compose ps
    echo
    if command -v security-harden &>/dev/null; then
        security-harden status
    fi
    read -p "按回车继续..."; show_menu
}

do_logs() {
    docker compose logs -f --tail=100 security-bot
}

do_security() {
    if command -v security-harden &>/dev/null; then
        security-harden status
    else
        echo -e "${RED}security-harden 未安装${NC}"
    fi
    read -p "按回车继续..."; show_menu
}

do_banned() {
    if command -v security-harden &>/dev/null; then
        security-harden banned
    else
        echo -e "${RED}security-harden 未安装${NC}"
    fi
    read -p "按回车继续..."; show_menu
}

do_config() {
    echo "可编辑文件:"
    echo "  1. .env (TG Bot 配置)"
    echo "  2. docker-compose.yml"
    echo "  3. security-harden.sh"
    read -p "选择 [1-3]: " fc
    case $fc in
        1) ${EDITOR:-nano} "${BASE_DIR}/.env" ;;
        2) ${EDITOR:-nano} "${BASE_DIR}/docker-compose.yml" ;;
        3) ${EDITOR:-nano} "/usr/local/bin/security-harden" ;;
    esac
    show_menu
}

do_certbot() {
    echo -e "${GREEN}${BOLD}=== Certbot 证书管理 ===${NC}"
    echo
    echo "1. 申请证书 (HTTP 验证)"
    echo "2. 续期所有证书"
    echo "3. 查看证书列表"
    echo "4. 安装 Certbot 插件"
    echo "0. 返回"
    echo
    read -p "选择 [0-4]: " cb
    case $cb in
        1)
            read -p "输入域名 (例如: example.com): " domain
            read -p "输入邮箱 (可选): " email
            security-harden certbot-apply "$domain" "$email"
            ;;
        2) security-harden certbot-renew ;;
        3) security-harden certbot-list ;;
        4) security-harden certbot-install ;;
        0) show_menu ;;
    esac
    read -p "按回车继续..."; show_menu
}

do_harden() {
    if command -v security-harden &>/dev/null; then
        security-harden install
    else
        echo -e "${RED}security-harden 未安装${NC}"
    fi
    read -p "按回车继续..."; show_menu
}

do_uninstall() {
    echo -e "${RED}${BOLD}=== 卸载 Security Guard ===${NC}"
    echo

    # 1. 停止并删除容器
    read -p "是否停止并删除 Security Bot 容器? [Y/n]: " del_bot
    if [[ ! "$del_bot" =~ ^[Nn]$ ]]; then
        docker compose down --rmi local 2>/dev/null || true
        echo -e "${GREEN}✓ 容器已停止并删除${NC}"
    fi

    # 1.1 移除开机自启与健康检查
    systemctl stop security-guard-healthcheck.timer security-guard-healthcheck.service security-guard-compose.service 2>/dev/null || true
    systemctl disable security-guard-healthcheck.timer security-guard-compose.service 2>/dev/null || true
    rm -f /etc/systemd/system/security-guard-healthcheck.timer
    rm -f /etc/systemd/system/security-guard-healthcheck.service
    rm -f /etc/systemd/system/security-guard-compose.service
    systemctl daemon-reload 2>/dev/null || true

    # 2. 卸载 CLI 工具
    read -p "是否卸载 CLI 工具 (sg, security-harden)? [Y/n]: " del_cli
    if [[ ! "$del_cli" =~ ^[Nn]$ ]]; then
        rm -f /usr/local/bin/sg
        rm -f /usr/local/bin/security-harden
        rm -f /usr/local/bin/Fail2ban
        rm -f /usr/local/bin/nginx-ban
        echo -e "${GREEN}✓ CLI 工具已卸载${NC}"
    fi

    # 3. 卸载安全组件 (Fail2Ban/黑名单/内核/Cron)
    read -p "是否卸载安全组件 (Fail2Ban/Nginx黑名单/内核优化/Cron)? [y/N]: " del_sec
    if [[ "$del_sec" =~ ^[Yy]$ ]]; then
        systemctl stop fail2ban 2>/dev/null || true
        systemctl disable fail2ban 2>/dev/null || true
        apt-get remove -y fail2ban 2>/dev/null || true
        systemctl stop nginx-blacklist-watcher 2>/dev/null || true
        systemctl disable nginx-blacklist-watcher 2>/dev/null || true
        rm -f /etc/systemd/system/nginx-blacklist-watcher.service
        rm -f /usr/local/bin/gen_nginx_blacklist.sh
        rm -f /usr/local/bin/nginx-blacklist-watcher.sh
        rm -f /etc/sysctl.d/99-security-guard.conf
        crontab -l 2>/dev/null | grep -v "security-harden" | crontab - 2>/dev/null || true
        sysctl --system 2>/dev/null || true
        systemctl daemon-reload
        echo -e "${GREEN}✓ 安全组件已卸载${NC}"
    fi

    # 4. 删除配置和数据
    echo
    echo -e "${YELLOW}配置目录: ${BASE_DIR}${NC}"
    echo -e "${YELLOW}包含: .env, 封禁记录 (ban/), docker-compose.yml 等${NC}"
    read -p "是否删除配置和数据? [y/N]: " del_data
    if [[ "$del_data" =~ ^[Yy]$ ]]; then
        rm -rf "$BASE_DIR"
        echo -e "${GREEN}✓ 配置和数据已删除${NC}"
    else
        echo -e "${BLUE}配置已保留在: ${BASE_DIR}${NC}"
    fi

    echo
    echo -e "${GREEN}卸载完成${NC}"
    exit 0
}

# 命令行参数处理
case "${1:-}" in
    start)     docker compose up -d ;;
    stop)      docker compose down ;;
    restart)   docker compose down && docker compose up -d ;;
    status)    if command -v security-harden &>/dev/null; then security-harden status; fi; docker compose ps ;;
    logs)      docker compose logs -f --tail=100 security-bot ;;
    security)  security-harden status 2>/dev/null ;;
    banned)    security-harden banned 2>/dev/null ;;
    ban)       security-harden ban "${2:-}" "${3:-manual}" ;;
    unban)     security-harden unban "${2:-}" ;;
    ban-asn)   security-harden ban-asn "${2:-}" "${3:-manual}" ;;
    unban-asn) security-harden unban-asn "${2:-}" ;;
    certbot)   security-harden certbot-list ;;
    harden)    security-harden install ;;
    config)    ${EDITOR:-nano} "${BASE_DIR}/.env" ;;
    uninstall) do_uninstall ;;
    *)         show_menu ;;
esac
SG_EOF

chmod +x /usr/local/bin/sg
log "'sg' 管理工具已安装"

# ══════════════════════════════════════════════════════════════
# 6. 运行安全加固 + 启动 TG Bot
# ══════════════════════════════════════════════════════════════
step "6/6 启动服务"

# 安全加固
echo -e "${YELLOW}是否现在运行安全加固？(Y/n)${NC}"
read -p "> " run_harden
if [[ ! "$run_harden" =~ ^[Nn]$ ]]; then
    security-harden install
else
    info "跳过安全加固，可稍后运行: security-harden install"
fi

# 启动 TG Bot
source "$ENV_FILE" 2>/dev/null || true

if [ -z "${SEC_TG_BOT_TOKEN:-}" ]; then
    warn "未配置 SEC_TG_BOT_TOKEN"
    warn "请编辑 ${BASE_DIR}/.env 填入 Token 后运行: sg start"
else
    if command -v docker &>/dev/null; then
        docker compose build security-bot
        docker compose up -d
        log "Security Bot 已启动"
    else
        warn "Docker 未安装，跳过 TG Bot 部署"
    fi
fi

if [ -x "${BASE_DIR}/scripts/install-autostart-healthcheck.sh" ]; then
    "${BASE_DIR}/scripts/install-autostart-healthcheck.sh" || warn "安装开机自启与健康检查失败，可手动执行: ${BASE_DIR}/scripts/install-autostart-healthcheck.sh"
else
    warn "未找到开机自启安装脚本，跳过"
fi

echo
echo -e "${BOLD}${GREEN}═══════════════════════════════════════════${NC}"
echo -e "${BOLD}${GREEN}  Security Guard 部署完成！${NC}"
echo -e "${BOLD}${GREEN}═══════════════════════════════════════════${NC}"
echo
echo -e "  管理工具: ${CYAN}sg${NC}  (交互式菜单)"
echo -e "  安全加固: ${CYAN}sg harden${NC}"
echo -e "  安全状态: ${CYAN}sg security${NC}"
echo -e "  封禁管理: ${CYAN}sg ban <IP>${NC} / ${CYAN}sg unban <IP>${NC}"
echo -e "  ASN 封禁: ${CYAN}sg ban-asn <ASN>${NC}"
echo -e "  Bot 日志: ${CYAN}sg logs${NC}"
echo -e "  编辑配置: ${CYAN}sg config${NC}"
echo
echo -e "  也可直接使用: ${CYAN}security-harden [install|ban|status|help]${NC}"
echo
