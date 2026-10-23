#!/bin/bash
# =============================================================================
# wireguard-install.sh — modern WireGuard server + client installer
#
#   Version: 2.1.0
#   Author:  SL_CE"I_"
#
#   v2.1.0 additions over v2.0.0:
#     * Per-client PersistentKeepalive (default 25, 0 for stationary)
#     * Per-client tunnel type (full / split / custom AllowedIPs)
#     * 'stats' subcommand — per-peer transfer and handshake visibility
#     * 'disable-client' / 'enable-client' — pause without deleting
#     * SaveConfig = false in server [Interface] (script-managed config)
#     * Automatic backup rotation (keep last 5)
#
#   Defensive tooling — configures only the local host's WireGuard server.
#
#   Sections:
#     §1  Constants and helpers
#     §2  Preflight (root, virt, OS detection)
#     §3  Input validation
#     §4  Network detection
#     §5  Package install
#     §6  Firewall management
#     §7  State and manifest (with v2.0 → v2.1 migration)
#     §8  Client management (add / remove / enable / disable / list / show)
#     §9  Subcommands (install, stats, uninstall, ...)
#     §10 Entry point
# =============================================================================

set -euo pipefail
umask 077

# =============================================================================
# §1  Constants and helpers
# =============================================================================
readonly SCRIPT_VERSION="2.1.0"
readonly SCRIPT_AUTHOR='SL_CE"I_"'
readonly WG_DIR="/etc/wireguard"
readonly CLIENT_DIR="/root/wg-clients"
readonly MANIFEST="${WG_DIR}/manifest.txt"
readonly STATE_FILE="${WG_DIR}/install.state"
readonly SYSCTL_FILE="/etc/sysctl.d/99-wireguard.conf"
readonly BACKUP_KEEP=5

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
log()    { printf "${GREEN}[*]${NC} %s\n" "$*"; }
warn()   { printf "${YELLOW}[!]${NC} %s\n" "$*"; }
err()    { printf "${RED}[x]${NC} %s\n" "$*" >&2; }
die()    { err "$*"; exit 1; }
header() { printf "\n${CYAN}=== %s ===${NC}\n" "$*"; }

humanize_bytes() {
    awk -v b="$1" 'BEGIN {
        split("B KiB MiB GiB TiB", u, " ")
        i = 1
        while (b >= 1024 && i < 5) { b /= 1024; i++ }
        if (i == 1) printf "%d %s", b, u[i]
        else printf "%.2f %s", b, u[i]
    }'
}

handshake_ago() {
    local ts=$1
    [[ -z "$ts" || "$ts" == "0" ]] && { echo "never"; return; }
    local now diff
    now=$(date +%s)
    diff=$((now - ts))
    if (( diff < 0 ));  then echo "just now"
    elif (( diff < 60 ));  then echo "${diff}s ago"
    elif (( diff < 3600 )); then echo "$((diff / 60))m ago"
    elif (( diff < 86400 )); then echo "$((diff / 3600))h ago"
    else echo "$((diff / 86400))d ago"
    fi
}

# =============================================================================
# §2  Preflight
# =============================================================================
require_root() {
    [[ $EUID -eq 0 ]] || die "this script must be run as root"
}

require_virt() {
    command -v systemd-detect-virt >/dev/null 2>&1 || return 0
    case "$(systemd-detect-virt 2>/dev/null || true)" in
        openvz) die "OpenVZ is not supported" ;;
        lxc)    die "LXC is not supported (kernel module must be on the host)" ;;
    esac
}

detect_os() {
    if [[ -r /etc/os-release ]]; then
        # shellcheck disable=SC1091
        . /etc/os-release
        case "${ID:-}" in
            debian|ubuntu)                echo "debian" ;;
            fedora)                       echo "fedora" ;;
            centos|rhel|rocky|almalinux)  echo "rhel"   ;;
            arch)                         echo "arch"   ;;
            *)                            echo "unknown" ;;
        esac
    else
        echo "unknown"
    fi
}

# =============================================================================
# §3  Input validation
# =============================================================================
is_ipv4() {
    [[ "$1" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
    local IFS='.' octet
    for octet in $1; do (( octet <= 255 )) || return 1; done
}

is_ipv6() {
    [[ "$1" == *:* ]] || return 1
    [[ "$1" =~ ^[0-9a-fA-F:]+$ ]] || return 1
    [[ "$1" != *":::"* ]] || return 1
    [[ "$1" =~ [0-9a-fA-F] ]] || return 1
}

is_port() {
    [[ "$1" =~ ^[0-9]+$ ]] && (( $1 >= 1 && $1 <= 65535 ))
}

is_iface() {
    [[ "$1" =~ ^[a-zA-Z0-9_-]{1,15}$ ]]
}

# =============================================================================
# §4  Network detection
# =============================================================================
detect_public_ipv4() {
    ip -4 route get 1.1.1.1 2>/dev/null \
        | awk '{for(i=1;i<=NF;i++) if($i=="src") {print $(i+1); exit}}' || true
}

detect_public_ipv6() {
    ip -6 route get 2606:4700:4700::1111 2>/dev/null \
        | awk '{for(i=1;i<=NF;i++) if($i=="src") {print $(i+1); exit}}' || true
}

detect_public_nic() {
    ip -4 route ls default 2>/dev/null \
        | awk '{for(i=1;i<=NF;i++) if($i=="dev") {print $(i+1); exit}}' || true
}

# =============================================================================
# §5  Package install
# =============================================================================
install_wireguard() {
    local os=$1
    log "Installing WireGuard and dependencies for: $os"
    case "$os" in
        debian)
            export DEBIAN_FRONTEND=noninteractive
            apt-get update -y >/dev/null
            apt-get install -y wireguard wireguard-tools iptables qrencode >/dev/null
            ;;
        fedora)
            dnf install -y wireguard-tools iptables qrencode >/dev/null
            ;;
        rhel)
            dnf install -y epel-release >/dev/null 2>&1 || true
            dnf install -y wireguard-tools iptables qrencode >/dev/null 2>&1 \
                || die "WireGuard not in repos. Enable EPEL (or CRB on RHEL 9+) and retry."
            ;;
        arch)
            pacman -Sy --noconfirm wireguard-tools iptables qrencode >/dev/null
            ;;
        *)
            die "unsupported OS: $os"
            ;;
    esac
}

# =============================================================================
# §6  Firewall management
# =============================================================================
open_firewall_port() {
    local port=$1
    if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
        ufw allow "${port}/udp" >/dev/null
        log "ufw: opened ${port}/udp"
    elif command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
        firewall-cmd --permanent --add-port="${port}/udp" >/dev/null
        firewall-cmd --reload >/dev/null
        log "firewalld: opened ${port}/udp"
    else
        warn "no active ufw/firewalld detected — open ${port}/udp manually if needed"
    fi
}

close_firewall_port() {
    local port=$1
    if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
        ufw delete allow "${port}/udp" >/dev/null 2>&1 || true
        log "ufw: closed ${port}/udp"
    elif command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
        firewall-cmd --permanent --remove-port="${port}/udp" >/dev/null 2>&1 || true
        firewall-cmd --reload >/dev/null 2>&1 || true
        log "firewalld: closed ${port}/udp"
    fi
}

# =============================================================================
# §7  State and manifest
# =============================================================================
# Manifest format (v2.1): name|pubkey|ipv4|ipv6|keepalive|allowed|enabled|psk
# v2.0 files have 4 fields; normalize_manifest() upgrades them in place.

ensure_dirs() {
    install -d -m 0700 "$WG_DIR" "$CLIENT_DIR"
    touch "$MANIFEST"
    chmod 0600 "$MANIFEST"
}

load_state() {
    [[ -f "$STATE_FILE" ]] || return 1
    # shellcheck disable=SC1090
    . "$STATE_FILE"
    return 0
}

save_state() {
    cat > "$STATE_FILE" <<EOF
# Managed by wireguard-install.sh ${SCRIPT_VERSION}
# Do not edit manually.
SERVER_WG_NIC="$SERVER_WG_NIC"
SERVER_WG_IPV4="$SERVER_WG_IPV4"
SERVER_WG_IPV6="$SERVER_WG_IPV6"
SERVER_PORT="$SERVER_PORT"
SERVER_PUB_IP="$SERVER_PUB_IP"
SERVER_PUB_NIC="$SERVER_PUB_NIC"
CLIENT_DNS_1="$CLIENT_DNS_1"
CLIENT_DNS_2="$CLIENT_DNS_2"
USE_PSK="$USE_PSK"
EOF
    chmod 0600 "$STATE_FILE"
}

# Parses a manifest line into M_* globals; fills defaults for v2.0 lines.
parse_manifest_line() {
    M_NAME=""; M_PUB=""; M_IPV4=""; M_IPV6=""
    M_KEEPALIVE="25"; M_ALLOWED="full"; M_ENABLED="1"; M_PSK=""
    IFS='|' read -r M_NAME M_PUB M_IPV4 M_IPV6 M_KEEPALIVE M_ALLOWED M_ENABLED M_PSK <<< "$1"
    [[ -z "$M_KEEPALIVE" ]] && M_KEEPALIVE=25
    [[ -z "$M_ALLOWED" ]]   && M_ALLOWED=full
    [[ -z "$M_ENABLED" ]]   && M_ENABLED=1
}

normalize_manifest() {
    [[ -f "$MANIFEST" ]] || return 0
    local tmp line
    tmp=$(mktemp)
    while IFS= read -r line; do
        [[ -z "$line" || "$line" == "#"* ]] && continue
        parse_manifest_line "$line"
        printf '%s|%s|%s|%s|%s|%s|%s|%s\n' \
            "$M_NAME" "$M_PUB" "$M_IPV4" "$M_IPV6" \
            "$M_KEEPALIVE" "$M_ALLOWED" "$M_ENABLED" "$M_PSK" >> "$tmp"
    done < "$MANIFEST"
    mv "$tmp" "$MANIFEST"
    chmod 0600 "$MANIFEST"
}

server_public_key() {
    awk -F' = ' '/^PrivateKey/{print $2}' "$WG_DIR/${SERVER_WG_NIC}.conf" | wg pubkey
}

server_v4_subnet() {
    local IFS='.' octets
    read -ra octets <<< "$SERVER_WG_IPV4"
    echo "${octets[0]}.${octets[1]}.${octets[2]}.0/24"
}

server_v6_subnet() {
    local v6="$SERVER_WG_IPV6"
    if [[ "$v6" =~ ^(.*)::[0-9a-fA-F]+$ ]]; then
        echo "${BASH_REMATCH[1]}::/64"
    elif [[ "$v6" =~ ^([0-9a-fA-F]+):([0-9a-fA-F]+):([0-9a-fA-F]+):([0-9a-fA-F]+): ]]; then
        echo "${BASH_REMATCH[1]}:${BASH_REMATCH[2]}:${BASH_REMATCH[3]}:${BASH_REMATCH[4]}::/64"
    else
        echo "fd42:42:42::/64"
    fi
}

format_endpoint() {
    if [[ "$SERVER_PUB_IP" == *:* ]]; then
        echo "[${SERVER_PUB_IP}]:${SERVER_PORT}"
    else
        echo "${SERVER_PUB_IP}:${SERVER_PORT}"
    fi
}

rotate_backups() {
    local base=$1
    ls -1t "${base}".bak.* 2>/dev/null \
        | tail -n +$((BACKUP_KEEP + 1)) \
        | xargs -r rm --
}

# =============================================================================
# §8  Client management
# =============================================================================
next_client_ip() {
    local last_v4=1 last_v6=1
    if [[ -s "$MANIFEST" ]]; then
        local line v4_base v4_host v4_last v6_suffix
        while IFS= read -r line; do
            [[ -z "$line" || "$line" == "#"* ]] && continue
            parse_manifest_line "$line"
            v4_base="${SERVER_WG_IPV4%.*}"
            v4_host="${M_IPV4%.*}"
            v4_last="${M_IPV4##*.}"
            [[ "$v4_host" == "$v4_base" ]] && (( v4_last > last_v4 )) && last_v4=$v4_last
            v6_suffix="${M_IPV6##*::}"
            [[ "$v6_suffix" =~ ^[0-9]+$ ]] && (( v6_suffix > last_v6 )) && last_v6=$v6_suffix
        done < "$MANIFEST"
    fi
    echo "$((last_v4 + 1)) $((last_v6 + 1))"
}

render_client_config() {
    local priv=$1 addr_v4=$2 addr_v6=$3 psk=$4 keepalive=$5 allowed=$6
    local server_pub endpoint client_allowed
    server_pub=$(server_public_key)
    endpoint=$(format_endpoint)

    case "$allowed" in
        full)  client_allowed="0.0.0.0/0, ::/0" ;;
        split) client_allowed="$(server_v4_subnet), $(server_v6_subnet)" ;;
        *)     client_allowed="$allowed" ;;
    esac

    cat <<EOF
[Interface]
PrivateKey = ${priv}
Address = ${addr_v4}/32, ${addr_v6}/128
DNS = ${CLIENT_DNS_1}, ${CLIENT_DNS_2}

[Peer]
PublicKey = ${server_pub}
Endpoint = ${endpoint}
AllowedIPs = ${client_allowed}
EOF
    [[ -n "$psk" ]] && echo "PresharedKey = ${psk}"
    [[ "$keepalive" != "0" ]] && echo "PersistentKeepalive = ${keepalive}"
}

show_qr() {
    local config_file=$1
    if command -v qrencode >/dev/null 2>&1; then
        header "QR code (scan with WireGuard mobile app)"
        qrencode -t ansiutf8 < "$config_file"
    fi
}

apply_peer_to_kernel() {
    local pub=$1 ipv4=$2 ipv6=$3 psk=$4
    local psk_tmp=""
    local -a args=(peer "$pub" allowed-ips "${ipv4}/32,${ipv6}/128")
    if [[ -n "$psk" ]]; then
        psk_tmp=$(mktemp)
        printf '%s' "$psk" > "$psk_tmp"
        args+=(preshared-key "$psk_tmp")
    fi
    wg set "$SERVER_WG_NIC" "${args[@]}" 2>/dev/null || true
    [[ -n "$psk_tmp" ]] && rm -f "$psk_tmp"
}

remove_peer_from_config() {
    local target_pub=$1
    local conf="$WG_DIR/${SERVER_WG_NIC}.conf"
    local tmp
    tmp=$(mktemp)
    awk -v target="$target_pub" '
        function flush_peer() {
            if (inpeer) {
                if (!match_key) printf "%s", buf
                inpeer = 0
            }
        }
        BEGIN { inpeer = 0; buf = ""; match_key = 0 }
        /^\[Peer\]/ { flush_peer(); inpeer = 1; buf = $0 "\n"; match_key = 0; next }
        inpeer && /^[A-Za-z#]/ {
            if ($0 ~ /^PublicKey = / && $3 == target) match_key = 1
            buf = buf $0 "\n"
            next
        }
        { flush_peer(); print }
        END { flush_peer() }
    ' "$conf" > "$tmp"
    mv "$tmp" "$conf"
    chmod 0600 "$conf"
}

append_peer_to_config() {
    local name=$1 pub=$2 ipv4=$3 ipv6=$4 psk=$5
    {
        echo ""
        echo "# Client: ${name} ($(date -u +%FT%TZ))"
        echo "[Peer]"
        echo "PublicKey = ${pub}"
        echo "AllowedIPs = ${ipv4}/32, ${ipv6}/128"
        [[ -n "$psk" ]] && echo "PresharedKey = ${psk}"
    } >> "$WG_DIR/${SERVER_WG_NIC}.conf"
    chmod 0600 "$WG_DIR/${SERVER_WG_NIC}.conf"
}

add_client() {
    local name="" keepalive="" tunnel_type="" custom_allowed="" noninteractive=0

    while (( $# )); do
        case "$1" in
            --keepalive)       [[ -n "${2:-}" ]] || die "--keepalive needs a value"
                               keepalive="$2"; shift 2 ;;
            --full-tunnel)     tunnel_type="full"; shift ;;
            --split-tunnel)    tunnel_type="split"; shift ;;
            --allowed-ips)     [[ -n "${2:-}" ]] || die "--allowed-ips needs a value"
                               tunnel_type="custom"; custom_allowed="$2"; shift 2 ;;
            --non-interactive) noninteractive=1; shift ;;
            -*)                die "unknown option: $1" ;;
            *)                 [[ -z "$name" ]] || die "unexpected argument: $1"
                               name="$1"; shift ;;
        esac
    done

    [[ -n "$name" ]] || die "usage: $0 add-client <name> [options]"
    [[ "$name" =~ ^[a-zA-Z0-9_-]{1,32}$ ]] || die "invalid client name (alnum/-/_ max 32)"
    load_state || die "no install state — run '$0 install' first"
    normalize_manifest

    if grep -q "^${name}|" "$MANIFEST" 2>/dev/null; then
        die "client '$name' already exists"
    fi

    if (( !noninteractive )); then
        if [[ -z "$keepalive" ]]; then
            local k
            read -rp "PersistentKeepalive seconds (0 = disable for stationary peers) [25]: " k
            keepalive="${k:-25}"
        fi
        if [[ -z "$tunnel_type" ]]; then
            local yn
            read -rp "Route all client traffic through the server (full tunnel)? [Y/n]: " yn
            if [[ "$yn" =~ ^[Nn] ]]; then
                tunnel_type="split"
            else
                tunnel_type="full"
            fi
        fi
    fi
    keepalive="${keepalive:-25}"
    tunnel_type="${tunnel_type:-full}"
    [[ "$keepalive" =~ ^[0-9]+$ ]] || die "keepalive must be a number"

    local v4_octet v6_suffix
    read -r v4_octet v6_suffix <<< "$(next_client_ip)"
    local v4_base="${SERVER_WG_IPV4%.*}"
    local client_v4="${v4_base}.${v4_octet}"
    local client_v6="${SERVER_WG_IPV6%%[0-9]*}${v6_suffix}"

    log "Adding client '${name}' (${client_v4}, ${client_v6}, keepalive=${keepalive}, tunnel=${tunnel_type})"

    local priv pub psk=""
    priv=$(wg genkey)
    pub=$(echo "$priv" | wg pubkey)
    [[ "$USE_PSK" =~ ^[Yy] ]] && psk=$(wg genpsk)

    append_peer_to_config "$name" "$pub" "$client_v4" "$client_v6" "$psk"

    local allowed_field="$tunnel_type"
    [[ "$tunnel_type" == "custom" ]] && allowed_field="$custom_allowed"
    printf '%s|%s|%s|%s|%s|%s|%s|%s\n' \
        "$name" "$pub" "$client_v4" "$client_v6" \
        "$keepalive" "$allowed_field" "1" "$psk" >> "$MANIFEST"

    local client_conf="${CLIENT_DIR}/${name}.conf"
    render_client_config "$priv" "$client_v4" "$client_v6" "$psk" "$keepalive" "$allowed_field" > "$client_conf"
    chmod 0600 "$client_conf"
    priv=""

    apply_peer_to_kernel "$pub" "$client_v4" "$client_v6" "$psk"

    header "Client '${name}' created"
    log "Config: $client_conf"
    cat "$client_conf"
    show_qr "$client_conf"
}

remove_client() {
    local name="${1:-}"
    [[ -n "$name" ]] || die "usage: $0 remove-client <name>"
    load_state || die "no install state"
    normalize_manifest

    grep -q "^${name}|" "$MANIFEST" 2>/dev/null || die "client '$name' not found"

    local pub
    pub=$(awk -F'|' -v n="$name" '$1==n {print $2}' "$MANIFEST")
    [[ -n "$pub" ]] || die "cannot find public key for '$name'"

    log "Removing peer ${pub} from ${SERVER_WG_NIC}"
    wg set "$SERVER_WG_NIC" peer "$pub" remove 2>/dev/null || true
    remove_peer_from_config "$pub"

    grep -v "^${name}|" "$MANIFEST" > "${MANIFEST}.tmp" || true
    mv "${MANIFEST}.tmp" "$MANIFEST"
    chmod 0600 "$MANIFEST"
    rm -f "${CLIENT_DIR}/${name}.conf"

    log "Client '${name}' removed"
}

disable_client() {
    local name="${1:-}"
    [[ -n "$name" ]] || die "usage: $0 disable-client <name>"
    load_state || die "no install state"
    normalize_manifest

    local found=0 tmp line
    tmp=$(mktemp)
    while IFS= read -r line; do
        [[ -z "$line" || "$line" == "#"* ]] && continue
        parse_manifest_line "$line"
        if [[ "$M_NAME" == "$name" ]]; then
            [[ "$M_ENABLED" == "0" ]] && { warn "client '$name' already disabled"; rm -f "$tmp"; return 0; }
            found=1
            wg set "$SERVER_WG_NIC" peer "$M_PUB" remove 2>/dev/null || true
            remove_peer_from_config "$M_PUB"
            printf '%s|%s|%s|%s|%s|%s|%s|%s\n' \
                "$M_NAME" "$M_PUB" "$M_IPV4" "$M_IPV6" \
                "$M_KEEPALIVE" "$M_ALLOWED" "0" "$M_PSK" >> "$tmp"
        else
            printf '%s|%s|%s|%s|%s|%s|%s|%s\n' \
                "$M_NAME" "$M_PUB" "$M_IPV4" "$M_IPV6" \
                "$M_KEEPALIVE" "$M_ALLOWED" "$M_ENABLED" "$M_PSK" >> "$tmp"
        fi
    done < "$MANIFEST"

    (( found )) || { rm -f "$tmp"; die "client '$name' not found"; }
    mv "$tmp" "$MANIFEST"
    chmod 0600 "$MANIFEST"
    log "Client '$name' disabled (peer removed from kernel and config; client config kept)"
}

enable_client() {
    local name="${1:-}"
    [[ -n "$name" ]] || die "usage: $0 enable-client <name>"
    load_state || die "no install state"
    normalize_manifest

    local found=0 tmp line
    tmp=$(mktemp)
    while IFS= read -r line; do
        [[ -z "$line" || "$line" == "#"* ]] && continue
        parse_manifest_line "$line"
        if [[ "$M_NAME" == "$name" ]]; then
            [[ "$M_ENABLED" == "1" ]] && { warn "client '$name' already enabled"; rm -f "$tmp"; return 0; }
            found=1
            append_peer_to_config "$M_NAME" "$M_PUB" "$M_IPV4" "$M_IPV6" "$M_PSK"
            apply_peer_to_kernel "$M_PUB" "$M_IPV4" "$M_IPV6" "$M_PSK"
            printf '%s|%s|%s|%s|%s|%s|%s|%s\n' \
                "$M_NAME" "$M_PUB" "$M_IPV4" "$M_IPV6" \
                "$M_KEEPALIVE" "$M_ALLOWED" "1" "$M_PSK" >> "$tmp"
        else
            printf '%s|%s|%s|%s|%s|%s|%s|%s\n' \
                "$M_NAME" "$M_PUB" "$M_IPV4" "$M_IPV6" \
                "$M_KEEPALIVE" "$M_ALLOWED" "$M_ENABLED" "$M_PSK" >> "$tmp"
        fi
    done < "$MANIFEST"

    (( found )) || { rm -f "$tmp"; die "client '$name' not found"; }
    mv "$tmp" "$MANIFEST"
    chmod 0600 "$MANIFEST"
    log "Client '$name' enabled"
}

list_clients() {
    load_state || die "no install state — run '$0 install' first"
    normalize_manifest
    if [[ ! -s "$MANIFEST" ]]; then log "no clients"; return; fi
    printf "%-20s %-16s %-28s %-10s %-8s %s\n" "NAME" "IPv4" "IPv6" "KEEPALIVE" "ENABLED" "PUBLIC KEY"
    printf "%-20s %-16s %-28s %-10s %-8s %s\n" "----" "----" "----" "---------" "-------" "----------"
    local line
    while IFS= read -r line; do
        [[ -z "$line" || "$line" == "#"* ]] && continue
        parse_manifest_line "$line"
        printf "%-20s %-16s %-28s %-10s %-8s %s\n" \
            "$M_NAME" "$M_IPV4" "$M_IPV6" "$M_KEEPALIVE" \
            "$([[ "$M_ENABLED" == "1" ]] && echo yes || echo no)" "$M_PUB"
    done < "$MANIFEST"
}

show_client() {
    local name="${1:-}"
    [[ -n "$name" ]] || die "usage: $0 show-client <name>"
    local conf="${CLIENT_DIR}/${name}.conf"
    [[ -f "$conf" ]] || die "client config not found: $conf"
    cat "$conf"
    show_qr "$conf"
}

# =============================================================================
# §9  Subcommands
# =============================================================================
cmd_stats() {
    require_root
    load_state || die "no install state — run '$0 install' first"
    normalize_manifest

    command -v wg >/dev/null 2>&1 || die "wg not found"
    local dump
    dump=$(wg show "$SERVER_WG_NIC" dump 2>/dev/null) \
        || die "cannot read $SERVER_WG_NIC (is wg-quick@${SERVER_WG_NIC} running?)"

    declare -A P_HANDSHAKE=() P_RX=() P_TX=() P_KEEPALIVE=()
    local first=1 f1 f2 f3 f4 f5 f6 f7 f8
    local total_rx=0 total_tx=0
    while IFS=$'\t' read -r f1 f2 f3 f4 f5 f6 f7 f8; do
        if (( first )); then first=0; continue; fi
        [[ -z "$f1" ]] && continue
        P_HANDSHAKE["$f1"]="$f5"
        P_RX["$f1"]="$f6"
        P_TX["$f1"]="$f7"
        P_KEEPALIVE["$f1"]="$f8"
        total_rx=$((total_rx + f6))
        total_tx=$((total_tx + f7))
    done <<< "$dump"

    printf "%-20s %-12s %-12s %-16s %-10s %s\n" \
        "NAME" "RX" "TX" "LATEST HANDSHAKE" "KEEPALIVE" "ENABLED"
    printf "%-20s %-12s %-12s %-16s %-10s %s\n" \
        "----" "--" "--" "----------------" "---------" "-------"

    local line
    while IFS= read -r line; do
        [[ -z "$line" || "$line" == "#"* ]] && continue
        parse_manifest_line "$line"
        local rx="-" tx="-" hs="-" ka="-"
        if [[ -n "${P_RX[$M_PUB]:-}" ]]; then
            rx=$(humanize_bytes "${P_RX[$M_PUB]}")
            tx=$(humanize_bytes "${P_TX[$M_PUB]}")
            hs=$(handshake_ago "${P_HANDSHAKE[$M_PUB]}")
            ka="${P_KEEPALIVE[$M_PUB]}s"
        fi
        printf "%-20s %-12s %-12s %-16s %-10s %s\n" \
            "$M_NAME" "$rx" "$tx" "$hs" "$ka" \
            "$([[ "$M_ENABLED" == "1" ]] && echo yes || echo no)"
    done < "$MANIFEST"

    printf "\n%-20s %-12s %-12s\n" "TOTAL" "$(humanize_bytes "$total_rx")" "$(humanize_bytes "$total_tx")"
}

cmd_install() {
    header "WireGuard installer ${SCRIPT_VERSION}"
    require_root
    require_virt

    local os
    os=$(detect_os)
    [[ "$os" != "unknown" ]] || die "unsupported OS — supported: Debian, Ubuntu, Fedora, RHEL/Rocky/Alma, Arch"
    log "OS detected: $os"

    if compgen -G "$WG_DIR/*.conf" >/dev/null; then
        warn "existing WireGuard config found in $WG_DIR"
        local ans ts f
        read -rp "Back up existing configs and continue? [y/N] " ans
        [[ "$ans" =~ ^[Yy]$ ]] || die "aborted by user"
        ts=$(date -u +%Y%m%dT%H%M%SZ)
        for f in "$WG_DIR"/*.conf; do
            cp -p "$f" "${f}.bak.${ts}"
            log "backed up $f → ${f}.bak.${ts}"
            rotate_backups "$f"
        done
    fi

    install_wireguard "$os"
    ensure_dirs

    local default_pubip="" pub4 pub6
    pub4=$(detect_public_ipv4); pub6=$(detect_public_ipv6)
    if [[ -n "$pub4" ]]; then default_pubip="$pub4"; log "detected IPv4: $pub4"
    elif [[ -n "$pub6" ]]; then default_pubip="$pub6"; log "detected IPv6: $pub6"; fi

    read -rp "Public address (IPv4 or IPv6): " -e -i "$default_pubip" SERVER_PUB_IP
    [[ -n "$SERVER_PUB_IP" ]] || die "public address required"
    is_ipv4 "$SERVER_PUB_IP" || is_ipv6 "$SERVER_PUB_IP" || die "invalid IP: $SERVER_PUB_IP"

    local default_nic
    default_nic=$(detect_public_nic)
    read -rp "Public interface: " -e -i "$default_nic" SERVER_PUB_NIC
    is_iface "$SERVER_PUB_NIC" || die "invalid interface: $SERVER_PUB_NIC"

    SERVER_WG_NIC="wg0"
    read -rp "WireGuard interface name: " -e -i "$SERVER_WG_NIC" SERVER_WG_NIC
    is_iface "$SERVER_WG_NIC" || die "invalid interface: $SERVER_WG_NIC"

    SERVER_WG_IPV4="10.66.66.1"
    read -rp "Server WireGuard IPv4: " -e -i "$SERVER_WG_IPV4" SERVER_WG_IPV4
    is_ipv4 "$SERVER_WG_IPV4" || die "invalid IPv4: $SERVER_WG_IPV4"

    SERVER_WG_IPV6="fd42:42:42::1"
    read -rp "Server WireGuard IPv6: " -e -i "$SERVER_WG_IPV6" SERVER_WG_IPV6
    is_ipv6 "$SERVER_WG_IPV6" || die "invalid IPv6: $SERVER_WG_IPV6"

    SERVER_PORT="51820"
    read -rp "WireGuard UDP port: " -e -i "$SERVER_PORT" SERVER_PORT
    is_port "$SERVER_PORT" || die "invalid port: $SERVER_PORT"

    CLIENT_DNS_1="1.1.1.1"
    read -rp "Client primary DNS: " -e -i "$CLIENT_DNS_1" CLIENT_DNS_1
    is_ipv4 "$CLIENT_DNS_1" || is_ipv6 "$CLIENT_DNS_1" || die "invalid DNS: $CLIENT_DNS_1"

    CLIENT_DNS_2="1.0.0.1"
    read -rp "Client secondary DNS: " -e -i "$CLIENT_DNS_2" CLIENT_DNS_2
    is_ipv4 "$CLIENT_DNS_2" || is_ipv6 "$CLIENT_DNS_2" || die "invalid DNS: $CLIENT_DNS_2"

    USE_PSK="y"
    read -rp "Use pre-shared key for extra security? [Y/n] " -e -i "$USE_PSK" USE_PSK

    save_state

    log "Generating server keys..."
    local server_priv server_pub
    server_priv=$(wg genkey)
    server_pub=$(echo "$server_priv" | wg pubkey)

    local server_conf="${WG_DIR}/${SERVER_WG_NIC}.conf"
    log "Writing $server_conf"

    cat > "$server_conf" <<EOF
# Managed by wireguard-install.sh ${SCRIPT_VERSION} (${SCRIPT_AUTHOR})
# Do not edit manually unless you know what you are doing.
[Interface]
Address = ${SERVER_WG_IPV4}/24, ${SERVER_WG_IPV6}/64
ListenPort = ${SERVER_PORT}
PrivateKey = ${server_priv}
SaveConfig = false
PostUp = sysctl -w net.ipv4.ip_forward=1; sysctl -w net.ipv6.conf.all.forwarding=1
PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -j ACCEPT
PostUp = iptables -t nat -A POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE
PostUp = ip6tables -A FORWARD -i %i -j ACCEPT; ip6tables -A FORWARD -o %i -j ACCEPT
PostUp = ip6tables -t nat -A POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT
PostDown = iptables -t nat -D POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE
PostDown = ip6tables -D FORWARD -i %i -j ACCEPT; ip6tables -D FORWARD -o %i -j ACCEPT
PostDown = ip6tables -t nat -D POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE
EOF
    chmod 0600 "$server_conf"
    server_priv=""; server_pub=""

    cat > "$SYSCTL_FILE" <<EOF
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1
EOF
    sysctl -p "$SYSCTL_FILE" >/dev/null 2>&1 || true

    open_firewall_port "$SERVER_PORT"

    systemctl enable --now "wg-quick@${SERVER_WG_NIC}"

    sleep 1
    if ! systemctl is-active "wg-quick@${SERVER_WG_NIC}" >/dev/null 2>&1; then
        systemctl status "wg-quick@${SERVER_WG_NIC}" --no-pager || true
        die "service failed to start — see status output above"
    fi
    log "service active: wg-quick@${SERVER_WG_NIC}"

    local client_name="client1"
    read -rp "First client name: " -e -i "$client_name" client_name
    add_client "$client_name"

    header "Installation complete"
    log "Server config:  $server_conf"
    log "Client configs: $CLIENT_DIR/"
    log ""
    log "Manage with:"
    log "  $0 add-client <name> [--keepalive N] [--full-tunnel|--split-tunnel]"
    log "  $0 remove-client <name>"
    log "  $0 disable-client <name>"
    log "  $0 enable-client <name>"
    log "  $0 list-clients"
    log "  $0 show-client <name>"
    log "  $0 stats"
    log "  $0 uninstall"
}

cmd_uninstall() {
    require_root
    load_state || die "no install state — nothing to uninstall"

    warn "This will:"
    warn "  * stop and disable wg-quick@${SERVER_WG_NIC}"
    warn "  * close UDP ${SERVER_PORT} in the firewall"
    warn "  * remove ${WG_DIR}/${SERVER_WG_NIC}.conf (and .bak.* backups)"
    warn "  * remove ${CLIENT_DIR}/, ${MANIFEST}, ${STATE_FILE}"
    warn "  * remove ${SYSCTL_FILE}"
    warn "Packages will NOT be removed."
    local ans
    read -rp "Continue? [y/N] " ans
    [[ "$ans" =~ ^[Yy]$ ]] || die "aborted"

    systemctl disable --now "wg-quick@${SERVER_WG_NIC}" 2>/dev/null || true
    close_firewall_port "$SERVER_PORT"

    rm -f "${WG_DIR}/${SERVER_WG_NIC}.conf" "${WG_DIR}/${SERVER_WG_NIC}.conf.bak."*
    rm -rf "$CLIENT_DIR"
    rm -f "$MANIFEST" "$STATE_FILE" "$SYSCTL_FILE"

    log "Uninstalled. Packages left in place."
}

# =============================================================================
# §10 Entry point
# =============================================================================
usage() {
    cat <<EOF
wireguard-install.sh ${SCRIPT_VERSION} (${SCRIPT_AUTHOR})

Usage: $0 [command] [args]

Commands:
  install                     Install WireGuard and add the first client
  add-client <name> [opts]    Add a new client
        --keepalive N            PersistentKeepalive seconds (default 25; 0 disables)
        --full-tunnel            Route all client traffic through server (default)
        --split-tunnel           Route only server subnets through the tunnel
        --allowed-ips CIDRS      Custom comma-separated CIDRs for client AllowedIPs
        --non-interactive        Do not prompt (use defaults or provided flags)
  remove-client <name>        Remove a client permanently
  disable-client <name>       Pause a client (keeps config, removes from kernel)
  enable-client <name>        Re-enable a disabled client
  list-clients                List all clients
  show-client <name>          Show client config and QR code
  stats                       Per-peer transfer, handshake age, keepalive
  uninstall                   Remove config and firewall rules
  version                     Print version
  help                        Print this help

Examples:
  $0
  $0 add-client laptop --keepalive 0 --split-tunnel --non-interactive
  $0 add-client phone
  $0 disable-client laptop
  $0 stats
  $0 uninstall
EOF
}

main() {
    local cmd="${1:-install}"
    shift || true
    case "$cmd" in
        install)                       cmd_install ;;
        add-client)                    add_client "$@" ;;
        remove-client)                 remove_client "$@" ;;
        disable-client)                disable_client "$@" ;;
        enable-client)                 enable_client "$@" ;;
        list-clients)                  list_clients ;;
        show-client)                   show_client "$@" ;;
        stats)                         cmd_stats ;;
        uninstall)                     cmd_uninstall ;;
        version|--version|-v)          echo "${SCRIPT_VERSION} (${SCRIPT_AUTHOR})" ;;
        help|--help|-h)                usage ;;
        "")                            usage ;;
        *) err "unknown command: $cmd"; usage; exit 1 ;;
    esac
}

main "$@"
