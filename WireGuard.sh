#!/bin/bash
# WireGuard 一体化管理脚本（部署 + 用户管理 + 备份恢复 + 导出 + 卸载清理）
# 导出目录固定：/home/ubuntu/user（自动创建；目录 755，文件 644）
# 查看/删除/恢复：统一交互（先列出，支持序号或名称；回车默认 1；仅 1 个时自动选中）
# 版本：2025-11-22-4（集成 BBR 自动开启）

set -euo pipefail

SCRIPT_VERSION="2025-12-14-3"

# ================== APT 预热 ==================
apt_warmup() {
  echo "=== APT 预热：清理缓存、修复缺失、刷新包列表 ==="
  apt-get clean
  apt-get update --fix-missing -y
  apt-get update -y
  echo "=== APT 预热完成 ==="
  echo
}

# ================== 全局路径 ==================
WIREGUARD_DIR="/etc/wireguard"
WG_CONF="$WIREGUARD_DIR/wg0.conf"
USER_CONFIG_DIR="$WIREGUARD_DIR/users"

EXPORT_BASE="/home/ubuntu/user"
BACKUP_BASE="$EXPORT_BASE/backup"
QRCODE_DIR="$EXPORT_BASE/qrcode"

# ================== 基础函数 ==================
require_root() {
  if [ "${EUID:-$(id -u)}" -ne 0 ]; then
    echo "请以 root 权限运行：sudo $0"
    exit 1
  fi
}
ensure_dirs() {
  mkdir -p "$WIREGUARD_DIR" "$USER_CONFIG_DIR" "$EXPORT_BASE" "$BACKUP_BASE" "$QRCODE_DIR"
  chmod 700 "$WIREGUARD_DIR"
  chmod 755 "$EXPORT_BASE"
  chmod 700 "$QRCODE_DIR"
  if id "ubuntu" &>/dev/null; then
    chown -R ubuntu:ubuntu "$EXPORT_BASE" || true
  fi
}

# ================== 工具函数 ==================
detect_main_interface() {
  local ifc; ifc=$(ip route show default 0.0.0.0/0 | awk '{print $5}' | head -n1)
  echo "${ifc:-eth0}"
}
hot_reload() {
  if ip link show wg0 >/dev/null 2>&1; then
    wg addconf wg0 <(wg-quick strip wg0)
  else
    echo "（提示）wg0 未运行，跳过热加载。" >&2
  fi
}
get_server_pubkey() {
  wg show wg0 public-key 2>/dev/null || {
    echo "无法获取服务器公钥，请先 0) 初始化/部署 并确保 wg0 已运行。" >&2
    exit 1
  }
}
get_public_ip() {
  local ip
  for url in "https://api.ipify.org" "https://ifconfig.me" "http://ipinfo.io/ip"; do
    ip=$(curl -s --max-time 5 "$url" || true)
    [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] && { echo "$ip"; return; }
  done
  echo ""
}
get_wg_cidr() {
  awk -F'= *' '/^[[:space:]]*Address[[:space:]]*=/ {print $2; exit}' "$WG_CONF" \
    | sed 's/[[:space:]]\+#.*$//' | tr -d ' '
}
calc_net_base() {
  local cidr="${1:-}"; local ip="${cidr%/*}"
  IFS='.' read -r o1 o2 o3 o4 <<<"$ip"
  echo "$o1.$o2.$o3"
}
find_next_ip_dynamic() {
  local base="${1:-}"; [ -n "$base" ] || { echo "内部错误：find_next_ip_dynamic() 未收到网段 base" >&2; exit 1; }
  local esc="${base//./\\.}"
  for i in $(seq 2 254); do
    if ! grep -qE "${esc}\.${i}(/32)?" "$WG_CONF" 2>/dev/null; then
      echo "$i"; return
    fi
  done
  echo "没有可用的 IP，请扩展网段。" >&2; exit 1
}
chown_safe() { if id "ubuntu" &>/dev/null; then chown -R ubuntu:ubuntu "$1" 2>/dev/null || true; fi; }

# ================== BBR 自动开启 ==================
enable_bbr() {
  # 检查内核是否支持该 sysctl 项
  if ! sysctl net.ipv4.tcp_congestion_control >/dev/null 2>&1; then
    echo "当前内核不支持 net.ipv4.tcp_congestion_control，跳过 BBR 配置。"
    return 0
  fi

  local current
  current=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo "")
  if [ "$current" = "bbr" ]; then
    echo "检测到已启用 BBR（$current），无需重复配置。"
    return 0
  fi

  # 配置 fq 队列
  if grep -q "^net.core.default_qdisc=" /etc/sysctl.conf 2>/dev/null; then
    sed -i 's/^net.core.default_qdisc=.*/net.core.default_qdisc=fq/' /etc/sysctl.conf
  else
    echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
  fi

  # 配置 BBR 拥塞控制算法
  if grep -q "^net.ipv4.tcp_congestion_control=" /etc/sysctl.conf 2>/dev/null; then
    sed -i 's/^net.ipv4.tcp_congestion_control=.*/net.ipv4.tcp_congestion_control=bbr/' /etc/sysctl.conf
  else
    echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
  fi

  if sysctl -p >/dev/null 2>&1; then
    current=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo "")
    echo "当前拥塞控制算法：${current:-未知}"
  else
    echo "⚠️ sysctl -p 执行失败，请手动检查 /etc/sysctl.conf"
  fi
}

# ================== 导出打包 ==================
export_user_bundle() {
  local CLIENT_NAME="${1:-}"; [ -n "$CLIENT_NAME" ] || { echo "export_user_bundle 需要用户名参数" >&2; return 1; }
  local conf_path="$USER_CONFIG_DIR/$CLIENT_NAME.conf"
  [ -f "$conf_path" ] || { echo "未找到客户端配置：$conf_path" >&2; return 1; }

  local ts user_dir bundle
  ts=$(date +%Y%m%d-%H%M%S)
  user_dir="$EXPORT_BASE/${CLIENT_NAME}_$ts"
  mkdir -p "$user_dir"

  cp "$conf_path" "$user_dir/$CLIENT_NAME.conf"
  chmod 644 "$user_dir/$CLIENT_NAME.conf"

  cat > "$user_dir/README.txt" <<'TXT'
导入说明（WireGuard）
--------------------
iOS / Android：将 .conf 发送到手机 → WireGuard App 导入
Windows：安装 WireGuard → 双击 .conf 或客户端导入
macOS：安装 WireGuard → 客户端导入 .conf
Linux：sudo wg-quick up /路径/到/文件.conf
TXT

  if command -v zip >/devnull 2>&1; then
    (cd "$EXPORT_BASE" && zip -q -r "${CLIENT_NAME}_$ts.zip" "${CLIENT_NAME}_$ts")
    bundle="$EXPORT_BASE/${CLIENT_NAME}_$ts.zip"
  else
    (cd "$EXPORT_BASE" && tar -czf "${CLIENT_NAME}_$ts.tar.gz" "${CLIENT_NAME}_$ts")
    bundle="$EXPORT_BASE/${CLIENT_NAME}_$ts.tar.gz"
  fi

  chown_safe "$user_dir"; chown_safe "$(dirname "$bundle")"
  chmod 755 "$user_dir"; chmod 644 "$user_dir"/* 2>/dev/null || true; chmod 644 "$bundle" 2>/dev/null || true

  echo "📦 已导出目录：$user_dir"
  echo "🗜️  打包文件：$bundle"
  echo "（示例下载：scp ubuntu@<服务器IP>:'$bundle' . ）"
}

# ================== 备份与用户列表工具 ==================
# 稳定提取用户名：只返回纯用户名（不带任何提示文本）
list_users_raw() {
  # 优先用 grep -P，若不可用则用 sed 退化
  if grep -oP '' </dev/null >/dev/null 2>&1; then
    grep -oP '(?<=^# ---BEGIN PEER ).*(?=---$)' "$WG_CONF" 2>/dev/null || true
  else
    sed -n 's/^# ---BEGIN PEER \(.*\)---$/\1/p' "$WG_CONF" 2>/dev/null
  fi
}

# 所有列表/提示输出到 stderr；仅把最终选择的用户名打印到 stdout
select_user_interactive() {
  local users count choice name
  users=$(list_users_raw)
  if [ -z "$users" ]; then
    echo "暂无用户" >&2
    return 1
  fi
  count=$(echo "$users" | wc -l)

  echo "—— 当前用户 ——" >&2
  nl -w2 -s') ' <<< "$users" >&2

  # 只有 1 个用户 → 自动选中
  if [ "$count" -eq 1 ]; then
    name="$(echo "$users" | sed -n '1p')"
    echo "（仅有一个用户，已自动选择：$name）" >&2
    printf '%s' "$name"
    return 0
  fi

  read -rp "请输入【序号或名称】（回车默认 1）: " choice
  if [ -z "${choice:-}" ]; then
    name="$(echo "$users" | sed -n '1p')"
    printf '%s' "$name"
    return 0
  fi

  if [[ "$choice" =~ ^[0-9]+$ ]]; then
    if [ "$choice" -ge 1 ] && [ "$choice" -le "$count" ]; then
      name=$(echo "$users" | sed -n "${choice}p")
    else
      echo "序号超出范围" >&2; return 1
    fi
  else
    if echo "$users" | grep -Fxq "$choice"; then
      name="$choice"
    else
      echo "未找到用户：$choice" >&2; return 1
    fi
  fi

  printf '%s' "$name"
  return 0
}

list_backups_for_user(){ ls -dt "${BACKUP_BASE}/${1}_"* 2>/dev/null | nl -w2 -s') '; }
pick_backup_for_user(){
  local CLIENT_NAME="$1" tmp_list
  tmp_list=$(ls -dt "${BACKUP_BASE}/${CLIENT_NAME}_"* 2>/dev/null) || true
  [ -z "$tmp_list" ] && { echo ""; return 0; }
  echo "该用户的备份（新→旧）：" >&2
  list_backups_for_user "$CLIENT_NAME" >&2
  read -rp "输入备份序号进行恢复（回车取消）： " idx
  [ -z "$idx" ] && { echo ""; return 0; }
  ls -dt "${BACKUP_BASE}/${CLIENT_NAME}_"* 2>/dev/null | sed -n "${idx}p" || true
}
select_user_from_backups_interactive() {
  local names choice count name
  names=$(ls -1 "$BACKUP_BASE" 2>/dev/null | sed -n 's/_20[0-9][0-9][01][0-9][0-3][0-9]-[0-9]\{6\}$//p' | sort -u)
  if [ -z "${names:-}" ]; then echo "暂无任何用户备份" >&2; return 1; fi
  count=$(echo "$names" | wc -l)
  echo "—— 备份库中的用户 ——" >&2
  nl -w2 -s') ' <<< "$names" >&2
  if [ "$count" -eq 1 ]; then
    name="$(echo "$names" | sed -n '1p')"
    echo "（仅有一个备份用户，已自动选择：$name）" >&2
    printf '%s' "$name"
    return 0
  fi
  read -rp "请输入【序号或名称】（回车默认 1）: " choice
  if [ -z "${choice:-}" ]; then
    name="$(echo "$names" | sed -n '1p')"
    printf '%s' "$name"
    return 0
  fi
  if [[ "$choice" =~ ^[0-9]+$ ]]; then
    if [ "$choice" -ge 1 ] && [ "$choice" -le "$count" ]; then
      name=$(echo "$names" | sed -n "${choice}p")
    else
      echo "序号超出范围" >&2; return 1
    fi
  else
    if echo "$names" | grep -Fxq "$choice"; then name="$choice"; else echo "备份库未找到用户：$choice" >&2; return 1; fi
  fi
  printf '%s' "$name"
  return 0
}

# ================== 0) 初始化/部署 ==================
init_server() {
  echo "=== 初始化 WireGuard 服务端 ==="
  ensure_dirs
  apt_warmup

  if ! command -v wg &>/dev/null; then
    echo "[1/8] 安装 WireGuard..."
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq && apt-get install -y -qq wireguard
  else
    echo "[1/8] WireGuard 已安装"
  fi

  echo "[2/8] 安装 qrencode（用于生成二维码）"
  if ! command -v qrencode >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    if apt-get install -y -qq qrencode; then
      echo "qrencode 安装成功"
    else
      echo "⚠️ 安装 qrencode 失败，请稍后手动执行：apt-get install qrencode"
    fi
  else
    echo "qrencode 已安装"
  fi

  MAIN_IF=$(detect_main_interface)
  echo "[3/8] 主网络接口：$MAIN_IF"

  if [ ! -f "$WG_CONF" ]; then
    echo "[4/8] 未检测到 wg0.conf，正在创建..."
    SERVER_PRIVATE_KEY=$(wg genkey)
    SERVER_PUBLIC_KEY=$(echo -n "$SERVER_PRIVATE_KEY" | wg pubkey)
    cat << EOF > "$WG_CONF"
[Interface]
Address = 10.0.0.1/24
PrivateKey = $SERVER_PRIVATE_KEY
ListenPort = 51820
PostUp   = iptables -C FORWARD -i wg0 -o $MAIN_IF -j ACCEPT 2>/dev/null || iptables -A FORWARD -i wg0 -o $MAIN_IF -j ACCEPT
PostUp   = iptables -C FORWARD -i $MAIN_IF -o wg0 -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || iptables -A FORWARD -i $MAIN_IF -o wg0 -m state --state RELATED,ESTABLISHED -j ACCEPT
PostUp   = iptables -t nat -C POSTROUTING -o $MAIN_IF -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -o $MAIN_IF -j MASQUERADE
PostDown = iptables -D FORWARD -i wg0 -o $MAIN_IF -j ACCEPT 2>/dev/null || true
PostDown = iptables -D FORWARD -i $MAIN_IF -o wg0 -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true
PostDown = iptables -t nat -D POSTROUTING -o $MAIN_IF -j MASQUERADE 2>/dev/null || true
EOF
    chmod 600 "$WG_CONF"
    echo "服务器公钥：$SERVER_PUBLIC_KEY"
  else
    echo "[4/8] 检测到现有 wg0.conf，默认保留现有配置。"
    read -rp "是否覆盖并重新部署（将备份旧文件）？(y/N): " overwrite || true
    if [[ "${overwrite:-N}" =~ ^[Yy]$ ]]; then
      ts=$(date +%Y%m%d-%H%M%S)
      cp "$WG_CONF" "$WG_CONF.bak.$ts"
      echo "已备份旧配置为：$WG_CONF.bak.$ts"
      SERVER_PRIVATE_KEY=$(wg genkey)
      SERVER_PUBLIC_KEY=$(echo -n "$SERVER_PRIVATE_KEY" | wg pubkey)
      cat << EOF > "$WG_CONF"
[Interface]
Address = 10.0.0.1/24
PrivateKey = $SERVER_PRIVATE_KEY
ListenPort = 51820
PostUp   = iptables -C FORWARD -i wg0 -o $MAIN_IF -j ACCEPT 2>/dev/null || iptables -A FORWARD -i wg0 -o $MAIN_IF -j ACCEPT
PostUp   = iptables -C FORWARD -i $MAIN_IF -o wg0 -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || iptables -A FORWARD -i $MAIN_IF -o wg0 -m state --state RELATED,ESTABLISHED -j ACCEPT
PostUp   = iptables -t nat -C POSTROUTING -o $MAIN_IF -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -o $MAIN_IF -j MASQUERADE
PostDown = iptables -D FORWARD -i wg0 -o $MAIN_IF -j ACCEPT 2>/dev/null || true
PostDown = iptables -D FORWARD -i $MAIN_IF -o wg0 -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true
PostDown = iptables -t nat -D POSTROUTING -o $MAIN_IF -j MASQUERADE 2>/dev/null || true
EOF
      chmod 600 "$WG_CONF"
      echo "✅ 已覆盖并重建 wg0.conf（旧文件已备份）。"
    else
      echo "➡️ 保留现有 wg0.conf，不做覆盖。"
    fi
  fi

  echo "[5/8] 启用 IPv4 转发"
  SYSCTL_FILE="/etc/sysctl.d/99-wireguard.conf"
  if ! grep -q "net.ipv4.ip_forward=1" "$SYSCTL_FILE" 2>/dev/null; then
    echo "net.ipv4.ip_forward=1" | tee -a "$SYSCTL_FILE" >/dev/null
  fi
  sysctl --system >/dev/null || true

  echo "[6/8] 启用 BBR 加速（如内核支持）"
  enable_bbr

  echo "[7/8] 配置 UFW 规则"
  if ! command -v ufw &>/dev/null; then apt-get install -y -qq ufw; fi
  ufw allow 22/tcp || true
  ufw allow 51820/udp || true
  if ! ufw status | grep -q "Status: active"; then
    echo "⚠️ UFW 未启用。如需启用：ufw --force enable"
  else
    echo "UFW 已启用，已放行 22/tcp 与 51820/udp"
  fi

  echo "[8/8] 启动服务"
  systemctl enable wg-quick@wg0
  systemctl restart wg-quick@wg0 || true
  if systemctl is-active --quiet wg-quick@wg0; then
    echo "✅ WireGuard 已启动成功"
  else
    echo "⚠️ WireGuard 未运行，可：journalctl -u wg-quick@wg0 查看原因"
  fi
}

# ================== 1) 添加用户 ==================
add_user() {
  echo "—— 添加新用户 ——"
  [ -f "$WG_CONF" ] || { echo "未初始化，请先执行 0) 初始化/部署"; return; }

  read -rp "请输入新用户名（例如 user）: " CLIENT_NAME
  [ -z "${CLIENT_NAME}" ] && { echo "用户名不能为空"; return; }
  grep -q "^# ---BEGIN PEER ${CLIENT_NAME}---$" "$WG_CONF" && { echo "用户已存在"; return; }

  local CIDR NET_BASE; CIDR="$(get_wg_cidr)"
  if [ -z "$CIDR" ]; then echo "无法从 $WG_CONF 读取 Address 网段，请先初始化。"; return; fi
  NET_BASE="$(calc_net_base "$CIDR")"

  read -rp "是否自动分配 IP? (Y/n): " auto || true
  local USER_IP
  if [[ "${auto:-Y}" =~ ^[Nn]$ ]]; then
    read -rp "请输入 IP (${NET_BASE}.X): " USER_IP
    [[ "$USER_IP" =~ ^${NET_BASE//./\\.}\.[0-9]{1,3}$ ]] || { echo "IP 必须在 ${NET_BASE}.0/24 网段"; return; }
  else
    USER_IP="${NET_BASE}.$(find_next_ip_dynamic "$NET_BASE")"
    echo "分配到 IP: $USER_IP"
  fi

  echo "请选择 DNS（地区优先 + 公共备份）："
  echo " 1) Google (8.8.8.8, 8.8.4.4)"
  echo " 2) Cloudflare (1.1.1.1, 1.0.0.1)"
  echo " 3) OpenDNS (208.67.222.222, 208.67.220.220)"
  echo " 4) Quad9 (9.9.9.9, 149.112.112.112)"
  echo " 5) AdGuard (94.140.14.14, 94.140.15.15)"
  echo " 6) DNS0.eu (193.110.81.0, 185.253.5.0)"
  echo " 7) Taiwan (168.95.1.1, 1.1.1.1)"
  echo " 8) Hong Kong (203.80.96.9, 1.1.1.1)"
  echo " 9) Japan (129.250.35.250, 8.8.8.8)"
  echo "10) South Korea (168.126.63.1, 1.1.1.1)"
  echo "11) 自定义（逗号分隔）"
  read -rp "请输入选项 (默认 2): " dns_choice || true
  case "${dns_choice:-2}" in
    1)  DNS_SERVER="8.8.8.8, 8.8.4.4" ;;
    2)  DNS_SERVER="1.1.1.1, 1.0.0.1" ;;
    3)  DNS_SERVER="208.67.222.222, 208.67.220.220" ;;
    4)  DNS_SERVER="9.9.9.9, 149.112.112.112" ;;
    5)  DNS_SERVER="94.140.14.14, 94.140.15.15" ;;
    6)  DNS_SERVER="193.110.81.0, 185.253.5.0" ;;
    7)  DNS_SERVER="168.95.1.1, 1.1.1.1" ;;
    8)  DNS_SERVER="203.80.96.9, 1.1.1.1" ;;
    9)  DNS_SERVER="129.250.35.250, 8.8.8.8" ;;
    10) DNS_SERVER="168.126.63.1, 1.1.1.1" ;;
    11) read -rp "请输入自定义 DNS（如 1.1.1.1, 8.8.8.8）: " DNS_SERVER ;;
    *)  DNS_SERVER="1.1.1.1, 1.0.0.1" ;;
  esac

  umask 077
  PRIVATE_KEY=$(wg genkey)
  PUBLIC_KEY=$(echo "$PRIVATE_KEY" | wg pubkey)
  SERVER_PUBLIC_KEY=$(get_server_pubkey)

  DETECTED_IP=$(get_public_ip)
  echo "检测到公网地址：IPv4=${DETECTED_IP:-无}  IPv6=无"
  read -rp "服务器地址/域名 (默认 ${DETECTED_IP:-<必填>}): " SERVER_HOST || true
  if [ -z "${SERVER_HOST:-}" ]; then
    [ -n "$DETECTED_IP" ] || { echo "无法自动检测公网IP，请手动输入"; return; }
    SERVER_HOST="$DETECTED_IP"
  fi
  read -rp "服务器端口 (默认 51820): " SERVER_PORT || true
  SERVER_PORT="${SERVER_PORT:-51820}"
  SERVER_ENDPOINT="$SERVER_HOST:$SERVER_PORT"

  # —— 写入服务端（带标记）——
  {
    echo "# ---BEGIN PEER ${CLIENT_NAME}---"
    echo "[Peer]"
    echo "# 用户名: ${CLIENT_NAME}"
    echo "PublicKey = ${PUBLIC_KEY}"
    echo "AllowedIPs = ${USER_IP}/32"
    echo "# ---END PEER ${CLIENT_NAME}---"
  } >> "$WG_CONF"

  # —— 写入客户端 —— 
  cat << EOF > "$USER_CONFIG_DIR/${CLIENT_NAME}.conf"
[Interface]
Address = ${USER_IP}/32
PrivateKey = ${PRIVATE_KEY}
DNS = ${DNS_SERVER}

[Peer]
PublicKey = ${SERVER_PUBLIC_KEY}
Endpoint = ${SERVER_ENDPOINT}
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
EOF
  chmod 600 "$USER_CONFIG_DIR/${CLIENT_NAME}.conf"

  hot_reload

  # —— 自动生成二维码 PNG（默认不在终端预览，避免私钥泄露）——
  if ! command -v qrencode >/dev/null 2>&1; then
    echo "未检测到 qrencode，正在安装..."
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq && apt-get install -y -qq qrencode || { echo "⚠️ 安装 qrencode 失败，已跳过二维码生成（可在菜单 5 再试）"; }
  fi
  if command -v qrencode >/dev/null 2>&1; then
    mkdir -p "$QRCODE_DIR"; chmod 700 "$QRCODE_DIR" || true
    local PNG_PATH; PNG_PATH="$QRCODE_DIR/${CLIENT_NAME}.png"
    if qrencode -o "$PNG_PATH" -m 2 -s 8 -l M < "$USER_CONFIG_DIR/${CLIENT_NAME}.conf" 2>/dev/null; then
      chmod 600 "$PNG_PATH" 2>/dev/null || true
      echo "✅ 已生成二维码 PNG：$PNG_PATH"
      echo "（如需终端预览二维码，请使用菜单 5）"
    else
      echo "⚠️ 生成二维码失败（可在菜单 5 再试）"
    fi
  fi

  echo "✅ 用户 ${CLIENT_NAME} 已创建"
  echo "配置：$USER_CONFIG_DIR/${CLIENT_NAME}.conf"
  echo "——— 以下为可复制的客户端配置 ——"
  echo "----------------------------------------"
  cat "$USER_CONFIG_DIR/${CLIENT_NAME}.conf"
  echo "----------------------------------------"

  export_user_bundle "${CLIENT_NAME}"
}

# ================== 2) 删除用户（自动备份） ==================
delete_user() {
  echo "—— 删除用户（自动备份） ——"
  [ -f "$WG_CONF" ] || { echo "未初始化，请先执行 0) 初始化/部署"; return; }

  local CLIENT_NAME; CLIENT_NAME="$(select_user_interactive)" || { echo "已取消或暂无用户。"; return; }

  local ts dir; ts=$(date +%Y%m%d-%H%M%S); dir="$BACKUP_BASE/${CLIENT_NAME}_$ts"
  mkdir -p "$dir"

  awk "/^# ---BEGIN PEER ${CLIENT_NAME}---\$/{flag=1} flag{print} /^# ---END PEER ${CLIENT_NAME}---\$/{flag=0}" "$WG_CONF" > "$dir/server_peer.txt"
  [ -f "$USER_CONFIG_DIR/${CLIENT_NAME}.conf" ] && cp "$USER_CONFIG_DIR/${CLIENT_NAME}.conf" "$dir/${CLIENT_NAME}.conf" && chmod 600 "$dir/${CLIENT_NAME}.conf"

  sed -i "/^# ---BEGIN PEER ${CLIENT_NAME}---\$/,/# ---END PEER ${CLIENT_NAME}---\$/d" "$WG_CONF"
  rm -f "$USER_CONFIG_DIR/${CLIENT_NAME}.conf" || true

  hot_reload
  chown_safe "$dir"
  echo "✅ 已删除并备份到：$dir"
}

# ================== 3) 恢复用户 ==================
restore_user() {
  echo "—— 恢复用户（从备份库选择） ——"
  [ -f "$WG_CONF" ] || { echo "未初始化，请先执行 0) 初始化/部署"; return; }

  local CLIENT_NAME; CLIENT_NAME="$(select_user_from_backups_interactive)" || { echo "已取消或无备份。"; return; }
  if grep -q "^# ---BEGIN PEER ${CLIENT_NAME}---\$" "$WG_CONF"; then
    echo "同名用户已存在，请先删除或更换用户名。"; return
  fi

  local selected; selected=$(pick_backup_for_user "$CLIENT_NAME")
  [ -z "$selected" ] && { echo "未选择备份或没有可用备份。"; return; }
  [ -f "$selected/server_peer.txt" ] || { echo "备份缺少 server_peer.txt，无法恢复。"; return; }

  echo "" >> "$WG_CONF"
  cat "$selected/server_peer.txt" >> "$WG_CONF"

  if [ -f "$selected/${CLIENT_NAME}.conf" ]; then
    cp -n "$selected/${CLIENT_NAME}.conf" "$USER_CONFIG_DIR/${CLIENT_NAME}.conf" || true
    chmod 600 "$USER_CONFIG_DIR/${CLIENT_NAME}.conf" || true
  fi

  hot_reload
  echo "✅ 用户 ${CLIENT_NAME} 已从备份恢复（来源：$selected）"
}

# ================== 4) 查看用户配置（序号/名称） ==================
view_user() {
  [ -f "$WG_CONF" ] || { echo "未初始化，请先执行 0) 初始化/部署"; return; }
  local CLIENT_NAME conf_path; CLIENT_NAME="$(select_user_interactive)" || { echo "已取消或暂无用户。"; return; }
  conf_path="$USER_CONFIG_DIR/${CLIENT_NAME}.conf"
  if [ -f "$conf_path" ]; then
    echo "—— ${CLIENT_NAME} 的客户端配置 ——"
    echo "路径：$conf_path"
    echo "----------------------------------------"
    cat "$conf_path"
    echo "----------------------------------------"
  else
    echo "未找到客户端配置文件：$conf_path"
    echo "（可能是早期手动添加的 Peer。可删除重建，或手动补一份 .conf）"
  fi
}

# ================== 5) 导出/查看二维码（选择用户） ==================
export_qr_for_user() {
  # 检查 qrencode 依赖（通常在 0) 初始化 时已安装，这里只是兜底）
  if ! command -v qrencode >/dev/null 2>&1; then
    echo "未检测到 qrencode，正在安装..."
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq && apt-get install -y -qq qrencode || { echo "安装 qrencode 失败"; return; }
  fi

  # 列出已有用户
  mapfile -t USERS < <(ls "$USER_CONFIG_DIR"/*.conf 2>/dev/null | xargs -n1 basename | sed 's/\.conf$//')
  if [ ${#USERS[@]} -eq 0 ]; then
    echo "未找到任何用户配置文件"; return
  fi

  echo "已有用户配置："
  for i in "${!USERS[@]}"; do
    printf "%2d) %s\n" "$((i+1))" "${USERS[$i]}"
  done

  read -rp "请输入序号选择用户: " idx
  if ! [[ "$idx" =~ ^[0-9]+$ ]] || [ "$idx" -lt 1 ] || [ "$idx" -gt ${#USERS[@]} ]; then
    echo "无效选择"; return
  fi

  CLIENT_NAME="${USERS[$((idx-1))]}"
  CONF_PATH="$USER_CONFIG_DIR/${CLIENT_NAME}.conf"
  OUT_DIR="$QRCODE_DIR"
  mkdir -p "$OUT_DIR"; chmod 700 "$OUT_DIR" || true
  PNG_PATH="$OUT_DIR/${CLIENT_NAME}.png"

  qrencode -o "$PNG_PATH" -m 2 -s 8 -l M < "$CONF_PATH" || { echo "生成二维码失败"; return; }
  chmod 600 "$PNG_PATH" 2>/dev/null || true
  echo "✅ 已生成二维码：$PNG_PATH"
  echo
  echo "是否在终端预览二维码？（默认不预览，更安全）"
  echo " 1) 预览（仅当前终端显示，可能暴露私钥）"
  echo " 2) 不预览（返回菜单）"
  read -rp "请选择 [1-2] (默认 2): " SHOW_OPT || true
  SHOW_OPT="${SHOW_OPT:-2}"
  if [[ "$SHOW_OPT" == "1" ]]; then
    echo "⚠️ 提醒：请确认当前环境安全（无人旁观/无录屏/无会话录制）"
    read -rp "确认继续预览？(y/N): " CONFIRM_SHOW || true
    if [[ "${CONFIRM_SHOW:-N}" =~ ^[Yy]$ ]]; then
      qrencode -m 1 -t ANSIUTF8 < "$CONF_PATH"
    else
      echo "已取消预览。"
    fi
  fi
}

list_users() {
  echo "—— 当前用户 ——"
  local users; users=$(list_users_raw)
  if [ -z "$users" ]; then echo "暂无用户"; return; fi
  nl -w2 -s') ' <<< "$users"
}

# ================== 6) 查看备份 ==================
list_backups() {
  echo "—— 备份列表 ——"
  read -rp "（可选）输入用户名以仅查看该用户的备份，直接回车查看全部： " filter || true
  if [ -n "${filter:-}" ]; then
    ls -dt "${BACKUP_BASE}/${filter}_"* 2>/dev/null | nl -w2 -s') ' || echo "未找到该用户备份"; return
  fi
  ls -dt "${BACKUP_BASE}/"* 2>/dev/null | nl -w2 -s') ' || echo "暂无备份"
}

# ================== 7) 查看服务状态 ==================
show_status() {
  echo "—— WireGuard 状态 ——"
  systemctl status wg-quick@wg0 --no-pager || true
  echo
  wg show || true
}

# ================== 9) 卸载并清理（危险） ==================
uninstall_wireguard() {
  echo "⚠️  即将卸载 WireGuard 并删除所有相关数据："
  echo "    - 停止并禁用 wg-quick@wg0 / 下线接口"
  echo "    - 尝试清理 iptables/NAT 规则"
  echo "    - （如启用）移除 UFW 51820/udp 放行"
  echo "    - 删除 /etc/sysctl.d/99-wireguard.conf 并重载"
  echo "    - purge 卸载 wireguard / wireguard-tools（并 autoremove）"
  echo "    - 删除 /etc/wireguard"
  echo "    - 删除导出与备份目录：$EXPORT_BASE"
  read -rp "请键入 DELETE 确认执行（大小写敏感），或回车取消： " CONFIRM
  if [ "$CONFIRM" != "DELETE" ]; then echo "已取消。"; return; fi

  echo "==> 停止并禁用服务"
  systemctl stop wg-quick@wg0 2>/dev/null || true
  systemctl disable wg-quick@wg0 2>/dev/null || true

  echo "==> 下线接口"
  wg-quick down wg0 2>/dev/null || true
  ip link del wg0 2>/dev/null || true

  echo "==> 清理 iptables/NAT 规则"
  MAIN_IF=$(detect_main_interface)
  iptables -D FORWARD -i wg0 -o "$MAIN_IF" -j ACCEPT 2>/dev/null || true
  iptables -D FORWARD -i "$MAIN_IF" -o wg0 -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true
  iptables -t nat -D POSTROUTING -o "$MAIN_IF" -j MASQUERADE 2>/dev/null || true

  echo "==> UFW 规则（如启用，移除 51820/udp 放行；保留 22/tcp）"
  if command -v ufw >/dev/null 2>&1; then
    if ufw status | grep -q "Status: active"; then ufw delete allow 51820/udp 2>/dev/null || true; fi
  fi

  echo "==> 移除 sysctl 配置并重载"
  rm -f /etc/sysctl.d/99-wireguard.conf
  sysctl --system >/dev/null 2>&1 || true

  echo "==> 卸载软件包（purge）"
  export DEBIAN_FRONTEND=noninteractive
  apt-get remove --purge -y wireguard wireguard-tools wireguard-dkms 2>/dev/null || true
  apt-get autoremove -y 2>/dev/null || true

  echo "==> 删除配置与日志"
  rm -rf /etc/wireguard
  rm -f /var/log/wg_user.log

  echo "==> 删除导出与备份目录：$EXPORT_BASE"
  rm -rf "$EXPORT_BASE"

  echo "✅ 已完成卸载与清理。"
  echo "   如需重新部署：运行本脚本选择 0) 初始化/部署"
}

# ================== 主菜单 ==================
main_menu() {
  while true; do
    echo -e "\n=== WireGuard 一体化管理 v${SCRIPT_VERSION} ==="
    echo "0) 初始化/部署"
    echo "1) 添加用户"
    echo "2) 删除用户（自动备份）"
    echo "3) 恢复用户（按序号选择备份）"
    echo "4) 查看用户配置（序号/名称）"
    echo "5) 导出/查看二维码（选择用户）"
    echo "6) 列出所有用户"
    echo "7) 查看备份（可按用户名过滤）"
    echo "8) 查看服务状态"
    echo "9) 退出"
    echo "10) 卸载并清理（危险）"
    read -rp "请选择: " opt
    case "${opt:-}" in
      0) init_server ;;
      1) add_user ;;
      2) delete_user ;;
      3) restore_user ;;
      4) view_user ;;
      5) export_qr_for_user ;;
      6) list_users ;;
      7) list_backups ;;
      8) show_status ;;
      9) break ;;
      10) uninstall_wireguard ;;
      *) echo "无效选项" ;;
    esac
  done
}

# ================== 入口 ==================
require_root
ensure_dirs
main_menu