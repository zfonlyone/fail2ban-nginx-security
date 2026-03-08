#!/bin/bash
# ============================================================
# security-harden.sh - 服务器安全加固一键脚本 (增强版)
# 功能: Fail2Ban + Nginx 黑名单 + 内核优化 + ASN 封禁
#       自动解禁 (1个月滚动) + 手动标记永久封禁
# 项目: security (独立安全模块)
# ============================================================

set -euo pipefail

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

log()   { echo -e "${GREEN}[✓]${NC} $1"; }
error() { echo -e "${RED}[✗]${NC} $1" >&2; }
warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
info()  { echo -e "${BLUE}[→]${NC} $1"; }
step()  { echo -e "\n${CYAN}${BOLD}━━━ $1 ━━━${NC}\n"; }

if [ "$EUID" -ne 0 ]; then error "请使用 root 权限运行"; exit 1; fi

# ── 路径定义 ──
BAN_DIR="/etc/security-guard/ban"
AUTO_BAN_FILE="${BAN_DIR}/auto-banned.json"    # 自动封禁记录 (含时间戳, 可自动解禁)
MANUAL_BAN_FILE="${BAN_DIR}/manual-banned.json" # 手动封禁记录 (永不自动解禁)
ASN_BAN_FILE="${BAN_DIR}/asn-banned.json"       # ASN 封禁记录
BAN_LOCK_FILE="/run/security-guard-ban.lock"
BLACKLIST_TXT="/etc/nginx/blacklist.txt"
AUTO_UNBAN_DAYS=30                             # 自动解禁天数
BANACTION_DEFAULT="${SECURITY_BANACTION:-iptables-multiport}"  # 默认不依赖 UFW
FAIL2BAN_BLOCKTYPE="${SECURITY_FAIL2BAN_BLOCKTYPE:-DROP}"      # Fail2Ban 动作: DROP
IPTABLES_BLOCK_TARGET="${SECURITY_IPTABLES_TARGET:-DROP}"       # ipset 规则动作: DROP
UFW_MIGRATED_REASON="migrated-ufw-auto"                         # UFW迁移后的自动封禁原因

mkdir -p "$BAN_DIR"

get_public_ipv4() {
    local ip=""
    for url in "https://api.ipify.org" "https://ifconfig.me/ip" "https://icanhazip.com"; do
        ip=$(curl -4fsS --max-time 5 "$url" 2>/dev/null || true)
        ip=$(echo "$ip" | tr -d '\r\n[:space:]')
        if [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
            echo "$ip"
            return 0
        fi
    done
    return 1
}

SELF_PUBLIC_IP="$(get_public_ipv4 || true)"

# ── 初始化 JSON 文件 ──
init_json() {
    local f="$1"
    if [ ! -f "$f" ]; then
        echo '[]' > "$f"
        return
    fi
    if ! jq -e 'type=="array"' "$f" >/dev/null 2>&1; then
        echo '[]' > "$f"
    fi
}
init_json "$AUTO_BAN_FILE"
init_json "$MANUAL_BAN_FILE"
init_json "$ASN_BAN_FILE"

ban_lock_acquire() {
    exec 8>"${BAN_LOCK_FILE}"
    flock -x 8
}

ban_lock_release() {
    flock -u 8 || true
}

trigger_blacklist_refresh() {
    local script="/usr/local/bin/gen_nginx_blacklist.sh"
    local stamp="/run/security-guard-blacklist.last"
    local min_interval=5
    local now last=0

    [ -x "$script" ] || return 0
    now=$(date +%s)
    if [ -f "$stamp" ]; then
        last=$(cat "$stamp" 2>/dev/null || echo 0)
    fi

    if [ $((now - last)) -lt "$min_interval" ]; then
        return 0
    fi

    echo "$now" > "$stamp"
    "$script" >/dev/null 2>&1 &
}

# ════════════════════════════════════════════════════════════
# 帮助
# ════════════════════════════════════════════════════════════
show_help() {
echo -e "${BOLD}${CYAN}security-harden - 服务器安全加固工具 (增强版)${NC}"
echo
echo "安装/卸载:"
echo " security-harden install 一键安装所有安全组件"
echo " security-harden uninstall 卸载所有安全组件"
echo
echo "IP 封禁/解禁:"
echo " security-harden ban <IP> [原因] [端口] [路径] 手动封禁 IP (永不自动解禁)"
echo " security-harden ban-auto <IP> [原因] [端口] [路径] 自动封禁 IP (30天后自动解禁)"
echo " security-harden unban <IP> 解封 IP"
echo " security-harden banned 查看所有封禁 IP+ASN"
echo " security-harden migrate-ufw [--keep-ufw] 将 UFW 封禁 IP 迁移到 iptables/ipset"
echo
echo "端口防护:"
echo " security-harden port-protect <端口> [协议] 添加端口暴力破解防护"
echo " security-harden port-unprotect <端口> 移除端口防护"
echo " security-harden port-list 查看已防护端口"
echo " security-harden port-scan 检测服务器开放端口"
echo
echo "ASN 封禁/解禁:"
echo " security-harden ban-asn <ASN> [备注] 封禁整个 ASN"
echo " security-harden unban-asn <ASN> 解封 ASN"
echo " security-harden list-asn 列出 ASN 封禁"
echo
echo "自动解禁:"
echo " security-harden auto-unban 立即执行自动解禁检查"
echo " security-harden install-unban 安装自动解禁定时任务"
echo
echo "状态:"
echo " security-harden status 查看安全状态"
echo " security-harden logs 查看安全日志"
echo " security-harden summary 生成封禁摘要 (JSON)"
echo " security-harden help 显示帮助"
}

# ════════════════════════════════════════════════════════════
# 获取 SSH 端口
# ════════════════════════════════════════════════════════════
get_ssh_port() {
    local p=$(grep -E "^Port\s+" /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' | head -1)
    [ -n "$p" ] && echo "$p" || echo "22"
}

ensure_ipset_blocklist() {
    if ! command -v ipset &>/dev/null; then
        apt-get update -qq
        apt-get install -y -qq ipset
    fi
    ipset create sg_blocklist hash:ip family inet maxelem 262144 -exist 2>/dev/null || true
    iptables -D INPUT -m set --match-set sg_blocklist src -j DROP 2>/dev/null || true
    iptables -D INPUT -m set --match-set sg_blocklist src -j REJECT 2>/dev/null || true
    /usr/sbin/iptables -D INPUT -m set --match-set sg_blocklist src -j DROP 2>/dev/null || true
    /usr/sbin/iptables -D INPUT -m set --match-set sg_blocklist src -j REJECT 2>/dev/null || true
    if command -v iptables &>/dev/null; then
        iptables -C INPUT -m set --match-set sg_blocklist src -j "${IPTABLES_BLOCK_TARGET}" 2>/dev/null || \
            iptables -I INPUT 1 -m set --match-set sg_blocklist src -j "${IPTABLES_BLOCK_TARGET}"
    elif [ -x /usr/sbin/iptables ]; then
        /usr/sbin/iptables -C INPUT -m set --match-set sg_blocklist src -j "${IPTABLES_BLOCK_TARGET}" 2>/dev/null || \
            /usr/sbin/iptables -I INPUT 1 -m set --match-set sg_blocklist src -j "${IPTABLES_BLOCK_TARGET}"
    fi
}

get_fail2ban_jails() {
    fail2ban-client status 2>/dev/null | sed -n 's/.*Jail list:[[:space:]]*//p' | tr ',' '\n' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | sed '/^$/d'
}

get_fail2ban_total_banned() {
    local total=0
    local jail
    while read -r jail; do
        [ -z "$jail" ] && continue
        local b
        b=$(fail2ban-client status "$jail" 2>/dev/null | awk '/Currently banned:/ {print $NF; exit}' || echo 0)
        [[ "$b" =~ ^[0-9]+$ ]] || b=0
        total=$((total + b))
    done < <(get_fail2ban_jails)
    echo "$total"
}

get_ufw_denied_ipv4() {
    local raw
    raw="$(ufw status 2>/dev/null || true)"
    [ -n "$raw" ] || return 0
    echo "$raw" | grep -E '\b(REJECT|DENY)\b' | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}(/32)?' | sed 's#/32$##' | sort -u || true
}

get_ufw_deny_count() {
    get_ufw_denied_ipv4 2>/dev/null | wc -l | awk '{print $1}'
}

cmd_migrate_ufw() {
    local keep_ufw="${1:-}"
    local remove_ufw="true"
    if [ "$keep_ufw" = "--keep-ufw" ]; then
        remove_ufw="false"
    fi

    if ! command -v ufw &>/dev/null; then
        warn "UFW 未安装，跳过迁移"
        return 0
    fi

    ensure_ipset_blocklist

    # 历史兼容: 将旧的 migrated-from-ufw 手动封禁转为自动封禁
    mapfile -t legacy_ips < <(
        jq -r '.[] | select((.reason=="migrated-from-ufw" or .reason=="migrated-ufw-auto") and (.ip|type=="string")) | .ip' \
            "$MANUAL_BAN_FILE" 2>/dev/null | sort -u
    )
    if [ ${#legacy_ips[@]} -gt 0 ]; then
        jq '[.[] | select(.reason != "migrated-from-ufw" and .reason != "migrated-ufw-auto")]' \
            "$MANUAL_BAN_FILE" > "${MANUAL_BAN_FILE}.tmp" && mv "${MANUAL_BAN_FILE}.tmp" "$MANUAL_BAN_FILE"
        for ip in "${legacy_ips[@]}"; do
            cmd_ban_auto "$ip" "${UFW_MIGRATED_REASON}"
        done
        log "已修复历史迁移记录: ${#legacy_ips[@]} 条 (手动 -> 自动)"
    fi

    mapfile -t ips < <(get_ufw_denied_ipv4)
    if [ ${#ips[@]} -eq 0 ]; then
        log "未发现可迁移的 UFW REJECT/DENY IP"
        return 0
    fi

    local migrated=0
    local removed=0
    local ip
    for ip in "${ips[@]}"; do
        [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || continue
        jq --arg ip "$ip" \
            '[.[] | select(.ip != $ip or (.reason != "migrated-from-ufw" and .reason != "migrated-ufw-auto"))]' \
            "$MANUAL_BAN_FILE" > "${MANUAL_BAN_FILE}.tmp" && mv "${MANUAL_BAN_FILE}.tmp" "$MANUAL_BAN_FILE"
        cmd_ban_auto "$ip" "${UFW_MIGRATED_REASON}"
        ((migrated++)) || true

        if [ "$remove_ufw" = "true" ]; then
            ufw --force delete reject from "$ip" >/dev/null 2>&1 || true
            ufw --force delete deny from "$ip" >/dev/null 2>&1 || true
            ((removed++)) || true
        fi
    done

    log "UFW -> iptables 迁移完成: ${migrated} 条"
    if [ "$remove_ufw" = "true" ]; then
        log "已尝试删除 UFW 规则: ${removed} 条"
    else
        warn "保留了原 UFW 规则 (--keep-ufw)"
    fi
}

# ════════════════════════════════════════════════════════════
# Fail2Ban 安装
# ════════════════════════════════════════════════════════════
install_fail2ban() {
    step "安装 Fail2Ban"

    if ! command -v fail2ban-server &>/dev/null; then
        apt-get update -qq
        apt-get install -y -qq fail2ban rsyslog
    fi
    log "Fail2Ban 已安装"

    # ── Nginx 防恶意扫描过滤器 ──
    cat > /etc/fail2ban/filter.d/nginx-bad-request.conf <<'FILTER1'
[Definition]
failregex = ^<HOST> - - \[.*\] "(GET|POST|HEAD) .*\.(php|asp|aspx|jsp|cgi|env|git|yml|sql|bak|tar|gz|zip|rar|sh) HTTP.*" (400|401|403|404|444)
           ^<HOST> - - \[.*\] "(GET|POST|HEAD) .*/(phpmyadmin|admin|setup|manager|dashboard|wp-login|xmlrpc).* HTTP.*" (400|401|403|404|444)
           ^<HOST> - - \[.*\] "(GET|POST) .*/\.\./.* HTTP.*" (400|401|403|404|444)
           ^<HOST> - - \[.*\] "(POST) .*(php://input).* HTTP.*" (400|401|403|404|444)
           ^<HOST> - - \[.*\] "PROPFIND .* HTTP.*" (400|401|403|404|444)
           ^<HOST> - - \[.*\] "(GET|POST) .*(%%2e|%%2f|%%25).* HTTP.*" (400|401|403|404|444)
           ^<HOST> - - \[.*\] "CONNECT .*:\d+ HTTP.*" (400|444)
           ^<HOST> - - \[.*\] "GET .* HTTP.*" (400|401|403|404|444) .*"(zgrab|Nuclei|nikto|sqlmap|wpscan|Wfuzz)"
           ^<HOST> - - \[.*\] "[^[:print:]]{3,}" (400|444)
datepattern = ^[^\[]*\[({DATE})
              {DAY} {MON} {YEAR} {HOUR}:{MIN}:{SEC} {TZ}
ignoreregex = ^<HOST> - - \[.*\] ".*" 200
FILTER1

    # ── Nginx 防 CC 过滤器 ──
    cat > /etc/fail2ban/filter.d/nginx-cc.conf <<'FILTER2'
[Definition]
failregex = ^<HOST> .* HTTP.* (403|429) .*$
ignoreregex = ^.*(\/(?:robots\.txt|favicon\.ico|.*\.(?:jpg|png|gif|jpeg|svg|webp|css|js|woff|woff2|eot|ttf|otf))$)
FILTER2

    # ── Nginx 服务登录失败过滤器 (401/403) ──
    cat > /etc/fail2ban/filter.d/nginx-service-auth.conf <<'FILTER3'
[Definition]
failregex = ^<HOST> - \S+ \[.*\] "(GET|POST|PUT|DELETE|PATCH) .* HTTP/[^"]*" (401|403) 
            ^<HOST> - - \[.*\] "(GET|POST|PUT|DELETE|PATCH) .* HTTP/[^"]*" (401|403) 
datepattern = ^[^\[]*\[({DATE})
              {DAY} {MON} {YEAR} {HOUR}:{MIN}:{SEC} {TZ}
ignoreregex = ^<HOST> .* "(GET|POST) .*/\.well-known/.* HTTP.*"
              ^<HOST> .* "(GET|POST) .*/favicon\.ico HTTP.*"
FILTER3

    log "Nginx 过滤器已配置"

    # ── Jail 配置 ──
    local ssh_port=$(get_ssh_port)
    mkdir -p /var/log/nginx
    touch /var/log/nginx/access.log
    chmod 644 /var/log/nginx/access.log

    [ -f /etc/fail2ban/jail.local ] && cp /etc/fail2ban/jail.local "/etc/fail2ban/jail.local.bak.$(date +%s)"

# ── 核心 Jail 配置 (SSH + Nginx, 始终启用) ──
cat > /etc/fail2ban/jail.local <<JAIL_EOF
[DEFAULT]
ignoreip = 127.0.0.1/8 192.168.0.0/16 10.0.0.0/8 ::1/128 fe80::/10 fc00::/7 ${SELF_PUBLIC_IP}
bantime = 30d
findtime = 15m
maxretry = 10
banaction = ${BANACTION_DEFAULT}[blocktype=${FAIL2BAN_BLOCKTYPE}]
action = %(action_)s
         security-guard-record

# ── SSH 暴力破解防护 ──
[sshd]
enabled  = true
port     = ${ssh_port}
filter   = sshd
logpath = /var/log/auth.log
maxretry = 3
findtime = 300
bantime = 30d
ignoreip = 127.0.0.1/8 ::1/128

# ── Nginx 恶意扫描 ──
[nginx-bad-request]
enabled  = true
logpath  = /var/log/nginx/access.log
filter   = nginx-bad-request
port     = 80,443
maxretry = 5
bantime  = 30d
findtime = 600

# ── Nginx CC 攻击 ──
[nginx-cc]
enabled = true
port = 80,443
logpath = /var/log/nginx/access.log
filter = nginx-cc
findtime = 300
maxretry = 30
bantime = 30d
JAIL_EOF

    # ── 可选 Jail: 仅在对应日志文件存在时启用 ──
    # 格式: "jail名|端口|日志路径|maxretry|额外选项"
    local optional_jails=(
        "vsftpd|21,20|/var/log/vsftpd.log|5|"
        "proftpd|21,20|/var/log/proftpd/proftpd.log|5|"
        "pure-ftpd|21,20|/var/log/syslog|5|"
        "postfix|25,587,465|/var/log/mail.log|5|"
        "dovecot|110,143,993,995|/var/log/mail.log|5|"
        "mysqld-auth|3306|/var/log/mysql/error.log|5|"
        "postgres-auth|5432|/var/log/postgresql/postgresql-*.log|5|"
        "mongodb-auth|27017|/var/log/mongodb/mongod.log|5|"
        "redis-auth|6379|/var/log/redis/redis-server.log|5|"
        "named-refused|53,953|/var/log/named/security.log|5|protocol = udp"
        "apache-auth|80,443|/var/log/apache2/error.log|5|"
        "apache-badbots|80,443|/var/log/apache2/access.log|2|"
        "apache-overflows|80,443|/var/log/apache2/error.log|2|"
        "php-url-fopen|80,443|/var/log/apache2/error.log|5|"
        "xrdp|3389|/var/log/xrdp.log|5|"
    )

    local enabled_optional=0
    for entry in "${optional_jails[@]}"; do
        IFS='|' read -r name port logpath maxretry extra <<< "$entry"
        # 检查日志文件是否存在 (支持通配符)
        if compgen -G "$logpath" > /dev/null 2>&1; then
            cat >> /etc/fail2ban/jail.local <<OPTIONAL_EOF

# ── ${name} (自动检测) ──
[${name}]
enabled = true
port = ${port}
logpath = ${logpath}
maxretry = ${maxretry}
findtime = 300
bantime = 30d
OPTIONAL_EOF
            [ -n "$extra" ] && echo "$extra" >> /etc/fail2ban/jail.local
            ((enabled_optional++)) || true
        fi
    done

    log "已启用 ${enabled_optional} 个可选 Jail (基于已安装服务自动检测)"

    log "Jail 规则已配置 (SSH端口: ${ssh_port}, bantime=30d)"

  # ── Fail2Ban action: 封禁时同步记录到 auto-banned.json ──
  cat > /etc/fail2ban/action.d/security-guard-record.conf <<'ACTION_EOF'
[Definition]
actionstart =
actionban = SECURITY_HARDEN_FROM_F2B=1 /usr/local/bin/security-harden ban-auto <ip> <name>
actionunban = SECURITY_HARDEN_FROM_F2B=1 /usr/local/bin/security-harden unban <ip>
ACTION_EOF

    log "Fail2Ban action 已配置"

    systemctl enable fail2ban
    systemctl restart fail2ban

    if systemctl is-active --quiet fail2ban; then
        log "Fail2Ban 服务已启动"
    else
        error "Fail2Ban 启动失败"
        systemctl status fail2ban --no-pager
    fi
}

# ════════════════════════════════════════════════════════════
# Nginx IP 黑名单 (inotify 热加载)
# ════════════════════════════════════════════════════════════
install_nginx_blacklist() {
    step "配置 Nginx IP 黑名单"

    apt-get install -y -qq inotify-tools 2>/dev/null || true

    mkdir -p /etc/nginx/dynamic
    [ -f "$BLACKLIST_TXT" ] || echo "# 黑名单 IP，每行一个" > "$BLACKLIST_TXT"
    touch /etc/nginx/dynamic/blacklist.conf

    cat > /usr/local/bin/gen_nginx_blacklist.sh <<'GEN_EOF'
#!/bin/bash
INPUT="/etc/nginx/blacklist.txt"
OUTPUT="/etc/nginx/dynamic/blacklist.conf"
LOCK="/run/security-guard-blacklist.lock"
TMP="$(mktemp)"

exec 9>"$LOCK"
flock -n 9 || exit 0

{
    echo "# Auto-generated. DO NOT EDIT."
    while IFS= read -r line; do
        line="${line%%#*}"
        line="$(echo "$line" | xargs)"
        if [[ -n "$line" ]]; then
            echo "deny $line;"
        fi
    done < "$INPUT"
} > "$TMP"

if ! cmp -s "$TMP" "$OUTPUT" 2>/dev/null; then
    mv "$TMP" "$OUTPUT"
    nginx -t 2>/dev/null && systemctl reload nginx 2>/dev/null || true
else
    rm -f "$TMP"
fi
GEN_EOF
    chmod +x /usr/local/bin/gen_nginx_blacklist.sh

    cat > /usr/local/bin/nginx-blacklist-watcher.sh <<'WATCH_EOF'
#!/bin/bash
# Nginx blacklist watcher — 防抖版本
# 使用 inotifywait --monitor 持续监听，不会漏事件
# 收到事件后等待 DEBOUNCE 秒无新事件再执行刷新
WATCH_FILE="/etc/nginx/blacklist.txt"
DEBOUNCE=3

inotifywait -m -q -e close_write,moved_to,attrib,modify "$WATCH_FILE" |
while true; do
    # 等待第一个事件
    read line || break
    # 防抖: 持续读取事件直到 $DEBOUNCE 秒内无新事件
    while read -t $DEBOUNCE line 2>/dev/null; do :; done
    echo "[$(date)] blacklist.txt changed, regenerating..."
    /usr/local/bin/gen_nginx_blacklist.sh
done
WATCH_EOF
    chmod +x /usr/local/bin/nginx-blacklist-watcher.sh

    cat > /etc/systemd/system/nginx-blacklist-watcher.service <<SVC_EOF
[Unit]
Description=Nginx Blacklist File Watcher
After=nginx.service
[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/nginx-blacklist-watcher.sh
Restart=always
RestartSec=3
[Install]
WantedBy=multi-user.target
SVC_EOF

    systemctl daemon-reload
    systemctl enable nginx-blacklist-watcher
    systemctl restart nginx-blacklist-watcher
    log "Nginx 黑名单监听服务已启动"
}

# ════════════════════════════════════════════════════════════
# 内核安全优化
# ════════════════════════════════════════════════════════════
install_kernel_hardening() {
    step "内核安全优化"
    cat > /etc/sysctl.d/99-security-guard.conf <<'KERN_EOF'
# SYN Flood 防护
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 8192
net.ipv4.tcp_syn_retries = 2
net.ipv4.tcp_synack_retries = 2
# 连接优化
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_keepalive_time = 300
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.tcp_keepalive_intvl = 15
# 防 IP 欺骗
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
# 禁止 ICMP 重定向
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
# 忽略广播 ping
net.ipv4.icmp_echo_ignore_broadcasts = 1
# 连接数
net.core.somaxconn = 4096
net.core.netdev_max_backlog = 4096
fs.file-max = 1048576
# IPv6 安全配置
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0
net.ipv6.conf.all.forwarding = 0
net.ipv6.conf.default.forwarding = 0
KERN_EOF
    sysctl -p /etc/sysctl.d/99-security-guard.conf 2>/dev/null || true
    log "内核安全参数已应用"
}

# ════════════════════════════════════════════════════════════
# Web 服务动态 Jail (基于 Nginx 日志自动检测)
# ════════════════════════════════════════════════════════════
install_service_jails() {
    step "配置 Web 服务防护 (Nginx 401/403 检测)"

    local nginx_log_dir="/var/log/nginx"
    local service_count=0

    if [ ! -d "$nginx_log_dir" ]; then
        warn "Nginx 日志目录不存在，跳过服务防护"
        return 0
    fi

    # 扫描所有独立的 access.log 文件 (排除全局 access.log)
    for logfile in "${nginx_log_dir}/"*-access.log; do
        [ -f "$logfile" ] || continue

        # 提取服务名: openlist.example.com-access.log → openlist
        local basename=$(basename "$logfile")
        local service_domain=${basename%-access.log}
        local service_name=${service_domain%%.*}

        # 跳过空名
        [ -z "$service_name" ] && continue

        local jail_name="nginx-${service_name}"

        # 检查是否已存在
        if grep -q "\[${jail_name}\]" /etc/fail2ban/jail.local 2>/dev/null; then
            continue
        fi

        cat >> /etc/fail2ban/jail.local <<SERVICE_EOF

# ── ${service_name} 登录防护 (自动检测: ${service_domain}) ──
[${jail_name}]
enabled = true
port = 80,443
logpath = ${logfile}
filter = nginx-service-auth
maxretry = 5
findtime = 600
bantime = 30d
SERVICE_EOF
        ((service_count++)) || true
        log "已添加服务防护: ${jail_name} (${logfile})"
    done

    if [ "$service_count" -gt 0 ]; then
        # 重启 Fail2Ban 加载新 jail
        systemctl restart fail2ban 2>/dev/null || true
        log "已添加 ${service_count} 个 Web 服务防护 Jail"
    else
        log "未检测到需要防护的 Web 服务日志"
    fi
}

# ════════════════════════════════════════════════════════════
# 安装自动解禁定时任务
# ════════════════════════════════════════════════════════════
install_auto_unban_cron() {
    step "安装自动解禁定时任务"
    # 每天凌晨 3 点执行自动解禁
    (crontab -l 2>/dev/null | grep -v "security-harden auto-unban"; \
     echo "0 3 * * * /usr/local/bin/security-harden auto-unban >> /var/log/security-guard-unban.log 2>&1") | crontab -
    log "Cron 已安装: 每天 03:00 自动解禁超过 ${AUTO_UNBAN_DAYS} 天的 IP"
}

# ════════════════════════════════════════════════════════════
# IP 封禁 (手动 — 永不自动解禁)
# ════════════════════════════════════════════════════════════
cmd_ban_manual() {
	local ip="$1"
	local reason="${2:-manual}"
	local port="${3:-}"
	local path="${4:-}"
	local ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)

	# Fail2Ban 封禁
	for jail in sshd nginx-bad-request nginx-cc; do
		fail2ban-client set "$jail" banip "$ip" 2>/dev/null || true
	done

	# Firewall/IPSet (可选，缺失命令时不影响记录链路)
	if command -v ipset &>/dev/null; then
		ipset create sg_blocklist hash:ip family inet maxelem 262144 -exist 2>/dev/null || true
		if command -v iptables &>/dev/null; then
			iptables -C INPUT -m set --match-set sg_blocklist src -j "${IPTABLES_BLOCK_TARGET}" 2>/dev/null || iptables -I INPUT 1 -m set --match-set sg_blocklist src -j "${IPTABLES_BLOCK_TARGET}"
		elif [ -x /usr/sbin/iptables ]; then
			/usr/sbin/iptables -C INPUT -m set --match-set sg_blocklist src -j "${IPTABLES_BLOCK_TARGET}" 2>/dev/null || /usr/sbin/iptables -I INPUT 1 -m set --match-set sg_blocklist src -j "${IPTABLES_BLOCK_TARGET}"
		fi
		ipset add sg_blocklist "$ip" -exist 2>/dev/null || true
	fi

	# Nginx 黑名单
	mkdir -p "$(dirname "$BLACKLIST_TXT")"
	touch "$BLACKLIST_TXT"
	if ! grep -qF "$ip" "$BLACKLIST_TXT" 2>/dev/null; then
		echo "$ip" >> "$BLACKLIST_TXT"
	fi

	# 记录到手动封禁文件 (永不自动解禁)；加锁避免并发写坏 JSON
	ban_lock_acquire
	local existing
	existing=$(jq --arg ip "$ip" '[.[] | select(.ip != $ip)]' "$MANUAL_BAN_FILE")
	echo "$existing" | jq --arg ip "$ip" --arg ts "$ts" --arg r "$reason" \
		--arg port "$port" --arg path "$path" \
		'. + [{"ip":$ip,"banned_at":$ts,"reason":$r,"port":$port,"path":$path,"permanent":true}]' > "${MANUAL_BAN_FILE}.tmp" \
		&& mv "${MANUAL_BAN_FILE}.tmp" "$MANUAL_BAN_FILE"

	# 从自动封禁中移除 (升级为永久)
	jq --arg ip "$ip" '[.[] | select(.ip != $ip)]' "$AUTO_BAN_FILE" > "${AUTO_BAN_FILE}.tmp" \
		&& mv "${AUTO_BAN_FILE}.tmp" "$AUTO_BAN_FILE"
	ban_lock_release

	# 刷新 Nginx 黑名单（带节流，避免高频封禁造成 CPU 风暴）
	trigger_blacklist_refresh

	log "已永久封禁: ${ip} (原因: ${reason})"
}

# ════════════════════════════════════════════════════════════
# IP 封禁 (自动 — 30天后自动解禁)
# ════════════════════════════════════════════════════════════
cmd_ban_auto() {
	local ip="$1"
	local reason="${2:-auto}"
	local port="${3:-}"
	local path="${4:-}"
	local ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)
	local expire=$(date -u -d "+${AUTO_UNBAN_DAYS} days" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || \
		date -u -v+${AUTO_UNBAN_DAYS}d +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || echo "")

	if [ -n "${SELF_PUBLIC_IP:-}" ] && [ "$ip" = "$SELF_PUBLIC_IP" ]; then
		warn "跳过自动封禁本机公网 IP: ${ip} (原因: ${reason})"
		return 0
	fi

	# 加锁处理手动检查+自动写入，避免并发覆盖
	ban_lock_acquire
	if jq -e --arg ip "$ip" '.[] | select(.ip == $ip)' "$MANUAL_BAN_FILE" &>/dev/null; then
		ban_lock_release
		return 0
	fi

	# Firewall/IPSet (可选，缺失命令时不影响记录链路)
	if command -v ipset &>/dev/null; then
		ipset create sg_blocklist hash:ip family inet maxelem 262144 -exist 2>/dev/null || true
		if command -v iptables &>/dev/null; then
			iptables -C INPUT -m set --match-set sg_blocklist src -j "${IPTABLES_BLOCK_TARGET}" 2>/dev/null || iptables -I INPUT 1 -m set --match-set sg_blocklist src -j "${IPTABLES_BLOCK_TARGET}"
		elif [ -x /usr/sbin/iptables ]; then
			/usr/sbin/iptables -C INPUT -m set --match-set sg_blocklist src -j "${IPTABLES_BLOCK_TARGET}" 2>/dev/null || /usr/sbin/iptables -I INPUT 1 -m set --match-set sg_blocklist src -j "${IPTABLES_BLOCK_TARGET}"
		fi
		ipset add sg_blocklist "$ip" -exist 2>/dev/null || true
	fi

	# Nginx 黑名单
	mkdir -p "$(dirname "$BLACKLIST_TXT")"
	touch "$BLACKLIST_TXT"
	if ! grep -qF "$ip" "$BLACKLIST_TXT" 2>/dev/null; then
		echo "$ip" >> "$BLACKLIST_TXT"
	fi

	# 记录到自动封禁文件
	local existing
	existing=$(jq --arg ip "$ip" '[.[] | select(.ip != $ip)]' "$AUTO_BAN_FILE")
	echo "$existing" | jq --arg ip "$ip" --arg ts "$ts" --arg r "$reason" --arg exp "$expire" \
		--arg port "$port" --arg path "$path" \
		'. + [{"ip":$ip,"banned_at":$ts,"expires_at":$exp,"reason":$r,"port":$port,"path":$path,"permanent":false}]' > "${AUTO_BAN_FILE}.tmp" \
		&& mv "${AUTO_BAN_FILE}.tmp" "$AUTO_BAN_FILE"
	ban_lock_release

	# 刷新 Nginx 黑名单（带节流，避免高频封禁造成 CPU 风暴）
	trigger_blacklist_refresh

	log "已自动封禁: ${ip} (${AUTO_UNBAN_DAYS}天后解禁)"
}

# ════════════════════════════════════════════════════════════
# IP 解禁
# ════════════════════════════════════════════════════════════
cmd_unban() {
    local ip="$1"
    local was_auto=0
    local was_manual=0
    local removed_blacklist=0

    if jq -e --arg ip "$ip" '.[] | select(.ip == $ip)' "$AUTO_BAN_FILE" &>/dev/null; then
        was_auto=1
    fi
    if jq -e --arg ip "$ip" '.[] | select(.ip == $ip)' "$MANUAL_BAN_FILE" &>/dev/null; then
        was_manual=1
    fi
    if grep -qFx "$ip" "$BLACKLIST_TXT" 2>/dev/null; then
        removed_blacklist=1
    fi

    if [ "$was_auto" -eq 0 ] && [ "$was_manual" -eq 0 ] && [ "$removed_blacklist" -eq 0 ]; then
        warn "IP 未处于封禁列表: ${ip}"
        return 0
    fi

    # Fail2Ban 解禁 (由 fail2ban action 调用时跳过，避免递归/超时)
    if [ "${SECURITY_HARDEN_FROM_F2B:-0}" != "1" ]; then
        for jail in sshd nginx-bad-request nginx-cc; do
            fail2ban-client set "$jail" unbanip "$ip" 2>/dev/null || true
        done
    fi

    # Firewall/IPSet 移除（可选）
    if command -v ipset &>/dev/null; then
        ipset del sg_blocklist "$ip" -exist 2>/dev/null || true
    fi

    # Nginx 黑名单移除
    sed -i "/^${ip}$/d" "$BLACKLIST_TXT" 2>/dev/null || true

    # 从两个记录文件中移除（加锁避免并发写坏）
    ban_lock_acquire
    jq --arg ip "$ip" '[.[] | select(.ip != $ip)]' "$AUTO_BAN_FILE" > "${AUTO_BAN_FILE}.tmp" \
        && mv "${AUTO_BAN_FILE}.tmp" "$AUTO_BAN_FILE"
    jq --arg ip "$ip" '[.[] | select(.ip != $ip)]' "$MANUAL_BAN_FILE" > "${MANUAL_BAN_FILE}.tmp" \
        && mv "${MANUAL_BAN_FILE}.tmp" "$MANUAL_BAN_FILE"
    ban_lock_release

    # 刷新 Nginx 黑名单（带节流，避免高频封禁造成 CPU 风暴）
    trigger_blacklist_refresh

    log "已解封: ${ip}"
}

# ════════════════════════════════════════════════════════════
# ASN 封禁/解禁 (使用 ipset + iptables)
# ════════════════════════════════════════════════════════════
install_asn_tools() {
    if ! command -v ipset &>/dev/null; then
        apt-get install -y -qq ipset 2>/dev/null || true
    fi
    if ! command -v whois &>/dev/null; then
        apt-get install -y -qq whois 2>/dev/null || true
    fi
}

get_asn_prefixes() {
local asn="$1"
asn="${asn#AS}"
asn="${asn#as}"
whois -h whois.radb.net -- "-i origin AS${asn}" 2>/dev/null | grep -E "^route:|^route6:" | awk '{print $2}' | sort -u
}

cmd_ban_asn() {
    local asn="$1"
    local reason="${2:-manual}"
    local ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    asn="${asn#AS}"
    asn="${asn#as}"

    install_asn_tools

    info "查询 AS${asn} 的 IP 前缀..."
    local prefixes
    prefixes=$(get_asn_prefixes "$asn")
    local count=$(echo "$prefixes" | grep -c "." || echo 0)

    if [ "$count" -eq 0 ]; then
        error "未找到 AS${asn} 的 IP 前缀"
        return 1
    fi

    log "AS${asn}: 找到 ${count} 个前缀"

    # 创建 ipset
    local setname="asn_${asn}"
    ipset create "$setname" hash:net -exist 2>/dev/null || true
    ipset flush "$setname" 2>/dev/null || true

    # 添加前缀到 ipset
    while IFS= read -r prefix; do
        [ -z "$prefix" ] && continue
        ipset add "$setname" "$prefix" -exist 2>/dev/null || true
    done <<< "$prefixes"

    # iptables 规则
    if ! iptables -C INPUT -m set --match-set "$setname" src -j "${IPTABLES_BLOCK_TARGET}" 2>/dev/null; then
        iptables -I INPUT -m set --match-set "$setname" src -j "${IPTABLES_BLOCK_TARGET}"
    fi

    # 添加到 Nginx 黑名单
    local added=0
    while IFS= read -r prefix; do
        [ -z "$prefix" ] && continue
        if ! grep -qF "$prefix" "$BLACKLIST_TXT" 2>/dev/null; then
            echo "$prefix   # AS${asn}" >> "$BLACKLIST_TXT"
            ((added++))
        fi
    done <<< "$prefixes"

    # 记录 ASN 封禁
    local existing
    existing=$(jq --arg asn "$asn" '[.[] | select(.asn != $asn)]' "$ASN_BAN_FILE")
    echo "$existing" | jq --arg asn "$asn" --arg ts "$ts" --arg r "$reason" \
        --argjson c "$count" --arg perm "true" \
        '. + [{"asn":$asn,"banned_at":$ts,"reason":$r,"prefix_count":$c,"permanent":true}]' > "$ASN_BAN_FILE"

    # 刷新 Nginx 黑名单（带节流，避免高频封禁造成 CPU 风暴）
    trigger_blacklist_refresh

    log "已封禁 AS${asn}: ${count} 个前缀 (永久)"
}

cmd_unban_asn() {
    local asn="$1"
    asn="${asn#AS}"
    asn="${asn#as}"

    local setname="asn_${asn}"

    # 移除 iptables 规则
    iptables -D INPUT -m set --match-set "$setname" src -j "${IPTABLES_BLOCK_TARGET}" 2>/dev/null || true
    iptables -D INPUT -m set --match-set "$setname" src -j DROP 2>/dev/null || true
    iptables -D INPUT -m set --match-set "$setname" src -j REJECT 2>/dev/null || true

    # 移除 ipset
    ipset destroy "$setname" 2>/dev/null || true

    # 从 Nginx 黑名单移除 ASN 相关行
    sed -i "/# AS${asn}$/d" "$BLACKLIST_TXT" 2>/dev/null || true

    # 从记录中移除
    jq --arg asn "$asn" '[.[] | select(.asn != $asn)]' "$ASN_BAN_FILE" > "${ASN_BAN_FILE}.tmp" \
        && mv "${ASN_BAN_FILE}.tmp" "$ASN_BAN_FILE"

    # 刷新 Nginx 黑名单（带节流，避免高频封禁造成 CPU 风暴）
    trigger_blacklist_refresh

    log "已解封 AS${asn}"
}

cmd_list_asn() {
echo -e "${BOLD}ASN 封禁列表:${NC}"
if [ -f "$ASN_BAN_FILE" ] && [ "$(jq length "$ASN_BAN_FILE")" -gt 0 ]; then
jq -r '.[] | " AS\(.asn) | \(.prefix_count) 个前缀 | \(.banned_at) | \(.reason)"' "$ASN_BAN_FILE"
else
echo " (空)"
fi
}

# ════════════════════════════════════════════════════════════
# 端口扫描检测
# ════════════════════════════════════════════════════════════
cmd_port_scan() {
step "检测服务器开放端口"
info "使用 ss 扫描监听端口..."
echo
echo -e "${BOLD}TCP 监听端口:${NC}"
ss -tlnp | grep LISTEN | awk '{printf " %-8s %-22s %s\n", $4, $1, $NF}' | column -t
echo
echo -e "${BOLD}UDP 监听端口:${NC}"
ss -ulnp | grep -v "^State" | head -20
echo
echo -e "${BOLD}已防护端口 (Fail2Ban jails):${NC}"
fail2ban-client status 2>/dev/null | grep -E "^\s*-\s+" | sed 's/^\s*-\s*//' || echo " (无)"
}

# ════════════════════════════════════════════════════════════
# 端口防护管理
# ════════════════════════════════════════════════════════════
PORT_BAN_FILE="${BAN_DIR}/port-protect.json"
init_json "$PORT_BAN_FILE"

cmd_port_protect() {
local port="$1"
local protocol="${2:-tcp}"
local jail_name="port-${port}"

if [[ ! "$port" =~ ^[0-9]+$ ]] || [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
error "无效端口号: $port"
return 1
fi

step "添加端口 ${port}/${protocol} 防护"

# 检查是否已存在
if jq -e --arg port "$port" --arg proto "$protocol" '.[] | select(.port == $port and .protocol == $proto)' "$PORT_BAN_FILE" &>/dev/null; then
warn "端口 ${port}/${protocol} 已在防护列表中"
return 0
fi

# 创建日志文件
local log_file="/var/log/port-${port}.log"
touch "$log_file" 2>/dev/null || log_file="/var/log/syslog"

# 创建 Fail2Ban 过滤器
cat > "/etc/fail2ban/filter.d/${jail_name}.conf" <<FILTER_EOF
[Definition]
failregex = ^\s*\S+\s+\S+\s+.*(?:connection|login|auth).*failed.*port\s*=?\s*${port}
^\s*\S+\s+\S+\s+.*(?:invalid|failed|refused|denied).*${port}
^\s*\S+\s+\S+\s+.*port\s+${port}.*(?:blocked|rejected)
ignoreregex =
FILTER_EOF

# 添加到 jail.local
cat >> /etc/fail2ban/jail.local <<JAIL_ADD

# ── 自定义端口防护: ${port}/${protocol} ──
[${jail_name}]
enabled = true
port = ${port}
protocol = ${protocol}
logpath = ${log_file}
maxretry = 5
findtime = 300
bantime = 30d
filter = ${jail_name}
JAIL_ADD

# 记录
local ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)
local existing
existing=$(jq --arg port "$port" --arg proto "$protocol" '[.[] | select(.port != $port or .protocol != $proto)]' "$PORT_BAN_FILE")
echo "$existing" | jq --arg port "$port" --arg proto "$protocol" --arg ts "$ts" \
'. + [{"port":$port,"protocol":$proto,"added_at":$ts}]' > "$PORT_BAN_FILE"

# 重启 Fail2Ban
systemctl restart fail2ban
log "已添加端口 ${port}/${protocol} 防护"
}

cmd_port_unprotect() {
local port="$1"
local jail_name="port-${port}"

if [[ ! "$port" =~ ^[0-9]+$ ]]; then
error "无效端口号: $port"
return 1
fi

step "移除端口 ${port} 防护"

# 从 jail.local 删除
sed -i "/^\[# ── 自定义端口防护: ${port}/,/^\[/d" /etc/fail2ban/jail.local 2>/dev/null || true
sed -i "/^\[${jail_name}\]/,/^\[/d" /etc/fail2ban/jail.local 2>/dev/null || true

# 删除过滤器
rm -f "/etc/fail2ban/filter.d/${jail_name}.conf"

# 从记录中移除
jq --arg port "$port" '[.[] | select(.port != $port)]' "$PORT_BAN_FILE" > "${PORT_BAN_FILE}.tmp" \
&& mv "${PORT_BAN_FILE}.tmp" "$PORT_BAN_FILE"

# 重启 Fail2Ban
systemctl restart fail2ban
log "已移除端口 ${port} 防护"
}

cmd_port_list() {
echo -e "${BOLD}${CYAN}═══ 端口防护列表 ═══${NC}"
echo

echo -e "${BOLD}系统预设防护:${NC}"
echo " SSH: 22 (或自定义)"
echo " HTTP/HTTPS: 80, 443"
echo " FTP: 21, 20"
echo " SMTP: 25, 587, 465"
echo " MySQL: 3306"
echo " PostgreSQL: 5432"
echo " MongoDB: 27017"
echo " Redis: 6379"
echo " DNS: 53"
echo " VNC: 5900-5910"
echo " RDP: 3389"
echo

echo -e "${BOLD}自定义防护端口:${NC}"
if [ -f "$PORT_BAN_FILE" ] && [ "$(jq length "$PORT_BAN_FILE" 2>/dev/null || echo 0)" -gt 0 ]; then
jq -r '.[] | " 端口 \(.port)/\(.protocol) | 添加时间: \(.added_at)"' "$PORT_BAN_FILE"
else
echo " (无)"
fi

echo
echo -e "${BOLD}当前活跃的 Fail2Ban jails:${NC}"
fail2ban-client status 2>/dev/null | grep -E "^\s*-\s+" | sed 's/^\s*-\s*//' || echo " (无)"
}

# ════════════════════════════════════════════════════════════
# 自动解禁 (滚动 30 天)
# ════════════════════════════════════════════════════════════
cmd_auto_unban() {
    local now_ts=$(date -u +%s)
    local unban_count=0

    log "开始自动解禁检查 (超过 ${AUTO_UNBAN_DAYS} 天的自动封禁)"

    # 读取自动封禁列表
    local to_unban
    to_unban=$(jq -r --argjson now "$now_ts" --argjson days "$AUTO_UNBAN_DAYS" \
        '[.[] | select(
            .permanent != true and
            ((.banned_at | sub("\\.[0-9]+"; "") | sub("Z$"; "+00:00") | fromdate) + ($days * 86400)) < $now
        ) | .ip]' "$AUTO_BAN_FILE" 2>/dev/null || echo '[]')

    local count=$(echo "$to_unban" | jq length)

    if [ "$count" -gt 0 ]; then
        echo "$to_unban" | jq -r '.[]' | while read -r ip; do
            [ -z "$ip" ] && continue
            # 检查不在手动封禁列表中
            if jq -e --arg ip "$ip" '.[] | select(.ip == $ip)' "$MANUAL_BAN_FILE" &>/dev/null; then
                warn "跳过手动封禁: ${ip}"
                continue
            fi
            cmd_unban "$ip"
            ((unban_count++)) || true
        done
        log "自动解禁完成: ${count} 个 IP"
    else
        log "无需解禁的 IP"
    fi

    # 注意: ASN 封禁和手动封禁不自动解禁
}

# ════════════════════════════════════════════════════════════
# 状态
# ════════════════════════════════════════════════════════════
cmd_status() {
    echo -e "${BOLD}${CYAN}═══ 安全状态 ═══${NC}"
    echo

    # Fail2Ban
    echo -e "${BOLD}Fail2Ban:${NC}"
    if systemctl is-active --quiet fail2ban 2>/dev/null; then
        echo -e "  状态: ${GREEN}运行中${NC}"
        local f2b_total
        f2b_total="$(get_fail2ban_total_banned)"
        echo -e "  总封禁: ${YELLOW}${f2b_total}${NC}"
        while read -r jail; do
            [ -z "$jail" ] && continue
            local banned
            banned=$(fail2ban-client status "$jail" 2>/dev/null | awk '/Currently banned:/ {print $NF; exit}' || echo 0)
            echo -e "  ${BLUE}${jail}${NC}: ${banned} 个封禁"
        done < <(get_fail2ban_jails)
    else
        echo -e "  状态: ${RED}未运行${NC}"
    fi

    echo
    echo -e "${BOLD}封禁统计:${NC}"
    local auto_count=$(jq '[.[].ip] | map(select(type=="string" and length>0)) | unique | length' "$AUTO_BAN_FILE" 2>/dev/null || echo 0)
    local manual_count=$(jq '[.[].ip] | map(select(type=="string" and length>0)) | unique | length' "$MANUAL_BAN_FILE" 2>/dev/null || echo 0)
    local total_unique
    total_unique=$(jq -s '[.[0][].ip, .[1][].ip] | map(select(type=="string" and length>0)) | unique | length' "$AUTO_BAN_FILE" "$MANUAL_BAN_FILE" 2>/dev/null || echo 0)
    local asn_count=$(jq length "$ASN_BAN_FILE" 2>/dev/null || echo 0)
    echo -e "  自动封禁 (可解禁): ${YELLOW}${auto_count}${NC}"
    echo -e "  手动封禁 (永久):   ${RED}${manual_count}${NC}"
    echo -e "  ASN 封禁 (永久):   ${RED}${asn_count}${NC}"
    echo -e "  唯一 IP 合计:      ${CYAN}${total_unique}${NC}"

    echo
    echo -e "${BOLD}Nginx 黑名单:${NC}"
    if systemctl is-active --quiet nginx-blacklist-watcher 2>/dev/null; then
        local bl_count=$(grep -cv "^#\|^$" "$BLACKLIST_TXT" 2>/dev/null || echo 0)
        echo -e "  状态: ${GREEN}监听中${NC} (${bl_count} 条规则)"
    else
        echo -e "  状态: ${RED}未运行${NC}"
    fi

    echo
    echo -e "${BOLD}Firewall Action:${NC}"
    echo -e "  Fail2Ban banaction: ${CYAN}${BANACTION_DEFAULT}[blocktype=${FAIL2BAN_BLOCKTYPE}]${NC}"
    echo -e "  ipset/iptables target: ${CYAN}${IPTABLES_BLOCK_TARGET}${NC}"
    if command -v ufw &>/dev/null; then
        local ufw_count
        ufw_count="$(get_ufw_deny_count)"
        echo -e "  UFW: ${YELLOW}已安装(非默认依赖)${NC}, DENY IP=${ufw_count}"
    else
        echo -e "  UFW: ${DIM}未安装${NC}"
    fi
}

# ════════════════════════════════════════════════════════════
# 封禁摘要 (JSON, 供 TG Bot 使用)
# ════════════════════════════════════════════════════════════
cmd_summary() {
    local auto_count=$(jq '[.[].ip] | map(select(type=="string" and length>0)) | unique | length' "$AUTO_BAN_FILE" 2>/dev/null || echo 0)
    local manual_count=$(jq '[.[].ip] | map(select(type=="string" and length>0)) | unique | length' "$MANUAL_BAN_FILE" 2>/dev/null || echo 0)
    local unique_total
    unique_total=$(jq -s '[.[0][].ip, .[1][].ip] | map(select(type=="string" and length>0)) | unique | length' "$AUTO_BAN_FILE" "$MANUAL_BAN_FILE" 2>/dev/null || echo 0)
    local asn_count=$(jq length "$ASN_BAN_FILE" 2>/dev/null || echo 0)

    # 24小时内新增封禁
    local yesterday=$(date -u -d "-24 hours" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || \
                      date -u -v-24H +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || echo "")
    local recent_auto=0
    if [ -n "$yesterday" ]; then
        recent_auto=$(jq --arg ts "$yesterday" \
            '[.[] | select(.banned_at > $ts) | .ip] | map(select(type=="string" and length>0)) | unique | length' "$AUTO_BAN_FILE" 2>/dev/null || echo 0)
    fi

    # Fail2Ban 统计
    local f2b_total
    f2b_total="$(get_fail2ban_total_banned)"

    jq -n \
        --argjson auto "$auto_count" \
        --argjson manual "$manual_count" \
        --argjson asn "$asn_count" \
        --argjson recent "$recent_auto" \
        --argjson f2b "$f2b_total" \
        --argjson unique "$unique_total" \
        '{
            auto_banned: $auto,
            manual_banned: $manual,
            asn_banned: $asn,
            unique_ip_total: $unique,
            recent_24h: $recent,
            fail2ban_active: $f2b,
            timestamp: (now | todate)
        }'
}

# ════════════════════════════════════════════════════════════
# 查看已封禁列表
# ════════════════════════════════════════════════════════════
cmd_banned() {
    echo -e "${BOLD}${CYAN}═══ 封禁列表 ═══${NC}"
    echo

    echo -e "${BOLD}手动封禁 (永久):${NC}"
    if [ "$(jq length "$MANUAL_BAN_FILE" 2>/dev/null || echo 0)" -gt 0 ]; then
        jq -r '.[] | "  \(.ip) | \(.banned_at) | \(.reason)"' "$MANUAL_BAN_FILE"
    else
        echo "  (空)"
    fi

    echo
    echo -e "${BOLD}自动封禁 (${AUTO_UNBAN_DAYS}天后解禁):${NC}"
    if [ "$(jq length "$AUTO_BAN_FILE" 2>/dev/null || echo 0)" -gt 0 ]; then
        jq -r '.[] | "  \(.ip) | \(.banned_at) → \(.expires_at // "N/A") | \(.reason)"' "$AUTO_BAN_FILE"
    else
        echo "  (空)"
    fi

    echo
    cmd_list_asn
}

# ════════════════════════════════════════════════════════════
# Certbot 证书管理
# ════════════════════════════════════════════════════════════
install_certbot() {
    step "安装 Certbot & Nginx 插件"
    if ! command -v certbot &>/dev/null; then
        apt-get update -qq
        apt-get install -y -qq certbot python3-certbot-nginx
    fi
    log "Certbot 已安装"
}

cmd_certbot_apply() {
    local domain="$1"
    local email="${2:-}"
    
    if [ -z "$domain" ]; then
        error "请提供域名: security-harden certbot-apply <domain> [email]"
        return 1
    fi

    local email_arg="--register-unsafely-without-email"
    if [ -n "$email" ]; then
        email_arg="--email $email --no-eff-email"
    fi

    info "正在为 ${domain} 申请证书..."
    certbot --nginx -d "$domain" $email_arg --agree-tos --non-interactive --redirect
    
    if [ $? -eq 0 ]; then
        log "证书申请成功并已应用到 Nginx"
    else
        error "证书申请失败"
    fi
}

cmd_certbot_renew() {
    step "证书续期检查"
    certbot renew
}

cmd_certbot_list() {
    step "证书列表"
    certbot certificates
}

# ════════════════════════════════════════════════════════════
# 主入口
# ════════════════════════════════════════════════════════════
case "${1:-}" in
    install)
        install_fail2ban
        install_nginx_blacklist
        install_kernel_hardening
        install_service_jails
        install_auto_unban_cron
        install_certbot
        echo
        echo -e "${GREEN}${BOLD}安全加固完成!${NC}"
        echo
        cmd_status
        ;;
    certbot-apply) cmd_certbot_apply "${2:-}" "${3:-}" ;;
    certbot-renew) cmd_certbot_renew ;;
    certbot-list) cmd_certbot_list ;;
    certbot-install) install_certbot ;;
    uninstall)
        warn "卸载安全组件..."
        systemctl stop fail2ban 2>/dev/null || true
        systemctl disable fail2ban 2>/dev/null || true
        apt-get remove -y fail2ban 2>/dev/null || true
        systemctl stop nginx-blacklist-watcher 2>/dev/null || true
        systemctl disable nginx-blacklist-watcher 2>/dev/null || true
        rm -f /etc/systemd/system/nginx-blacklist-watcher.service
        rm -f /usr/local/bin/gen_nginx_blacklist.sh
        rm -f /usr/local/bin/nginx-blacklist-watcher.sh
        rm -f /etc/sysctl.d/99-security-guard.conf
        crontab -l 2>/dev/null | grep -v "security-harden" | crontab -
        sysctl --system 2>/dev/null || true
        systemctl daemon-reload
        log "安全组件已卸载"
        ;;
status) cmd_status ;;
ban) cmd_ban_manual "${2:-}" "${3:-manual}" "${4:-}" "${5:-}" ;;
ban-auto) cmd_ban_auto "${2:-}" "${3:-auto}" "${4:-}" "${5:-}" ;;
unban) cmd_unban "${2:-}" ;;
banned) cmd_banned ;;
ban-asn) cmd_ban_asn "${2:-}" "${3:-manual}" ;;
unban-asn) cmd_unban_asn "${2:-}" ;;
list-asn) cmd_list_asn ;;
port-protect) cmd_port_protect "${2:-}" "${3:-tcp}" ;;
port-unprotect) cmd_port_unprotect "${2:-}" ;;
port-list) cmd_port_list ;;
port-scan) cmd_port_scan ;;
auto-unban) cmd_auto_unban ;;
install-unban) install_auto_unban_cron ;;
migrate-ufw) cmd_migrate_ufw "${2:-}" ;;
summary) cmd_summary ;;
logs)
echo -e "${BOLD}Fail2Ban 日志:${NC}"
journalctl -u fail2ban -n 30 --no-pager 2>/dev/null || tail -30 /var/log/fail2ban.log 2>/dev/null
echo
echo -e "${BOLD}自动解禁日志:${NC}"
tail -20 /var/log/security-guard-unban.log 2>/dev/null || echo " (无)"
;;
help|-h|--help|"") show_help ;;
*) error "未知命令: $1"; show_help; exit 1 ;;
esac
