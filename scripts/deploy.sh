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
ENV_TEMPLATE="${PROJECT_DIR}/.env.example"
IMAGE_NAME="security-guard-bot:latest"

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

read_env_key() {
    local file="$1"
    local key="$2"
    [ -f "$file" ] || return 0
    awk -F= -v k="$key" '$1==k {sub(/^[^=]*=/, ""); print; exit}' "$file"
}

upsert_env_key() {
    local file="$1"
    local key="$2"
    local value="$3"
    mkdir -p "$(dirname "$file")"
    touch "$file"
    if grep -q "^${key}=" "$file"; then
        local escaped
        escaped=$(printf '%s' "$value" | sed 's/[\/&]/\\&/g')
        sed -i "s/^${key}=.*/${key}=${escaped}/" "$file"
    else
        echo "${key}=${value}" >> "$file"
    fi
}

has_real_env_value() {
    local value="${1:-}"
    case "$value" in
        ""|"your-token-here"|"your-chat-id")
            return 1
            ;;
        *)
            return 0
            ;;
    esac
}

service_container_id() {
    docker ps -q --filter "label=com.docker.compose.service=security-bot" | head -1
}

service_env_value() {
    local key="$1"
    local cid
    cid="$(service_container_id)"
    [ -n "$cid" ] || return 0
    docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$cid" 2>/dev/null \
      | awk -F= -v k="$key" '$1==k {$1=""; sub(/^=/, ""); print; exit}'
}

infer_running_value() {
    local key="$1"
    case "$key" in
        SEC_TG_BOT_TOKEN) service_env_value "SEC_TG_BOT_TOKEN" ;;
        SEC_TG_CHAT_ID) service_env_value "SEC_TG_CHAT_ID" ;;
        SEC_TG_ADMIN_IDS) service_env_value "SEC_TG_ADMIN_IDS" ;;
        SEC_TG_TOPIC_ID) service_env_value "SEC_TG_TOPIC_ID" ;;
        ALERT_BAN_PER_MINUTE)
            local v
            v="$(service_env_value "ALERT_BAN_PER_MINUTE")"
            [ -n "$v" ] && { echo "$v"; return 0; }
            v="$(service_env_value "ALERT_BAN_THRESHOLD")"
            [ -n "$v" ] && { echo "$v"; return 0; }
            read_env_key "$ENV_FILE" "ALERT_BAN_THRESHOLD"
            ;;
        RUN_HARDEN_ON_DEPLOY)
            read_env_key "$ENV_FILE" "RUN_HARDEN_ON_DEPLOY"
            ;;
        *)
            ;;
    esac
}

ensure_env_key() {
    local key="$1"
    local fallback="${2:-}"
    local current inferred value
    current="$(read_env_key "$ENV_FILE" "$key")"
    if [ -z "${current:-}" ]; then
        inferred="$(infer_running_value "$key")"
        value="${inferred:-$fallback}"
        upsert_env_key "$ENV_FILE" "$key" "$value"
        log ".env 补充字段: ${key}"
    fi
}

build_security_bot_image() {
    if [ ! -f "${PROJECT_DIR}/tg-bot/Dockerfile" ]; then
        error "源码目录缺少 tg-bot/Dockerfile: ${PROJECT_DIR}/tg-bot/Dockerfile"
        exit 1
    fi

    info "在源码目录构建 Security Bot 镜像"
    docker build -t "${IMAGE_NAME}" "${PROJECT_DIR}/tg-bot"
    log "镜像构建完成: ${IMAGE_NAME}"
}

install_helper_script() {
    local src="$1"
    local dst="$2"

    if [ ! -f "${src}" ]; then
        error "缺少脚本: ${src}"
        exit 1
    fi

    cp -f "${src}" "${dst}"
    chmod +x "${dst}"
}

clean_runtime_code() {
    rm -rf \
        "${BASE_DIR}/scripts" \
        "${BASE_DIR}/tg-bot" \
        "${BASE_DIR}/.git" \
        "${BASE_DIR}/README.md" \
        "${BASE_DIR}/AGENTS.md" \
        "${BASE_DIR}/GEMINI.md"
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

mkdir -p "${BASE_DIR}"/{ban,state}
cd "$BASE_DIR"
log "工作目录: $BASE_DIR"

# ══════════════════════════════════════════════════════════════
# 2. 配置 Telegram Bot
# ══════════════════════════════════════════════════════════════
step "2/6 配置 Telegram Bot"

if [ ! -f "$ENV_FILE" ] && [ -f "$ENV_TEMPLATE" ]; then
    cp -f "$ENV_TEMPLATE" "$ENV_FILE"
fi
touch "$ENV_FILE"
chmod 600 "$ENV_FILE"

# 统一从 /etc/security-guard/.env 读取，缺失项回填运行中实例值
ensure_env_key "SEC_TG_BOT_TOKEN" ""
ensure_env_key "SEC_TG_CHAT_ID" ""
SEC_TG_CHAT_ID_VAL="$(read_env_key "$ENV_FILE" "SEC_TG_CHAT_ID")"
ensure_env_key "SEC_TG_ADMIN_IDS" "${SEC_TG_CHAT_ID_VAL}"
ensure_env_key "SEC_TG_TOPIC_ID" ""
ensure_env_key "ALERT_BAN_PER_MINUTE" "60"
ensure_env_key "RUN_HARDEN_ON_DEPLOY" "false"

if [ -n "$(read_env_key "$ENV_FILE" "ALERT_BAN_THRESHOLD")" ] && [ "$(read_env_key "$ENV_FILE" "ALERT_BAN_PER_MINUTE")" = "60" ]; then
    upsert_env_key "$ENV_FILE" "ALERT_BAN_PER_MINUTE" "$(read_env_key "$ENV_FILE" "ALERT_BAN_THRESHOLD")"
fi

SEC_TG_BOT_TOKEN_VAL="$(read_env_key "$ENV_FILE" "SEC_TG_BOT_TOKEN")"
SEC_TG_CHAT_ID_VAL="$(read_env_key "$ENV_FILE" "SEC_TG_CHAT_ID")"
if has_real_env_value "$SEC_TG_BOT_TOKEN_VAL"; then
    log "SEC_TG_BOT_TOKEN: 已配置"
else
    log "SEC_TG_BOT_TOKEN: 未配置"
fi
if has_real_env_value "$SEC_TG_CHAT_ID_VAL"; then
    log "SEC_TG_CHAT_ID: 已配置"
else
    log "SEC_TG_CHAT_ID: 未配置"
fi

# ══════════════════════════════════════════════════════════════
# 3. 部署文件
# ══════════════════════════════════════════════════════════════
step "3/6 构建镜像并同步运行文件"

build_security_bot_image

if [ "$PROJECT_DIR" != "$BASE_DIR" ]; then
    cp -f "${PROJECT_DIR}/docker-compose.yml" "${BASE_DIR}/"
    log "运行文件已同步到 ${BASE_DIR} (docker-compose.yml)"
fi

clean_runtime_code
log "配置与编排文件部署完成"

# ══════════════════════════════════════════════════════════════
# 4. 安装安全加固脚本
# ══════════════════════════════════════════════════════════════
step "4/6 安装安全加固脚本"

if [ -f "${PROJECT_DIR}/scripts/security-harden.sh" ]; then
    install_helper_script "${PROJECT_DIR}/scripts/security-harden.sh" /usr/local/bin/security-harden
    log "'security-harden' 已安装到 /usr/local/bin/"
fi

# Fail2Ban 脚本
for script in Fail2ban.sh nginx-ban.sh; do
    if [ -f "${PROJECT_DIR}/scripts/${script}" ]; then
        install_helper_script "${PROJECT_DIR}/scripts/${script}" "/usr/local/bin/${script%.sh}"
        log "'${script%.sh}' 已安装"
    fi
done

install_helper_script "${PROJECT_DIR}/scripts/compose-healthcheck.sh" /usr/local/bin/security-guard-compose-healthcheck
log "'security-guard-compose-healthcheck' 已安装"

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
RUN_HARDEN_ON_DEPLOY="$(read_env_key "$ENV_FILE" "RUN_HARDEN_ON_DEPLOY")"
RUN_HARDEN_ON_DEPLOY="${RUN_HARDEN_ON_DEPLOY:-false}"
if [[ "${RUN_HARDEN_ON_DEPLOY,,}" =~ ^(1|y|yes|true)$ ]]; then
    security-harden install
else
    info "根据 .env 配置跳过安全加固 (RUN_HARDEN_ON_DEPLOY=${RUN_HARDEN_ON_DEPLOY})"
fi

# 启动 TG Bot
SEC_TG_BOT_TOKEN_VAL="$(read_env_key "$ENV_FILE" "SEC_TG_BOT_TOKEN")"
if ! has_real_env_value "$SEC_TG_BOT_TOKEN_VAL"; then
    warn "未配置 SEC_TG_BOT_TOKEN"
    warn "请编辑 ${BASE_DIR}/.env 填入 Token 后运行: sg start"
else
    if command -v docker &>/dev/null; then
        docker compose up -d
        log "Security Bot 已启动"
    else
        warn "Docker 未安装，跳过 TG Bot 部署"
    fi
fi

if [ -x "${PROJECT_DIR}/scripts/install-autostart-healthcheck.sh" ]; then
    "${PROJECT_DIR}/scripts/install-autostart-healthcheck.sh" || warn "安装开机自启与健康检查失败，可手动执行: ${PROJECT_DIR}/scripts/install-autostart-healthcheck.sh"
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
