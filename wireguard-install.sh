#!/bin/bash
# =============================================================================
# wireguard-install.sh — modern WireGuard server + client installer
#
#   Interactive installer for a WireGuard server and any number of clients.
#   Handles package install, key generation, server/client configs, IP
#   forwarding, firewall opening, systemd service, and peer management.
#
#   Defensive tooling — this script only modifies the local host's own
#   network configuration. It does not scan, probe, or send traffic to any
#   remote host.
#
#   Version: 2.0.0
#   Author:  SL_CE"I_"
#
#   Sections:
#     §1  Constants and helpers
#     §2  Preflight (root, virt, OS detection)
#     §3  Input validation
#     §4  Network detection
#     §5  Package install
#     §6  Firewall management
#     §7  State and manifest
#     §8  Client management
#     §9  Subcommands
#     §10 Entry point
# =============================================================================

set -euo pipefail
umask 077

# =============================================================================
# §1  Constants and helpers
# =============================================================================
readonly SCRIPT_VERSION="2.0.0"
readonly SCRIPT_AUTHOR='SL_CE"I_"'
readonly WG_DIR="/etc/wireguard"
readonly CLIENT_DIR="/root/wg-clients"
readonly MANIFEST="${WG_DIR}/manifest.txt"
readonly STATE_FILE="${WG_DIR}/install.state"
readonly SYSCTL_FILE="/etc/sysctl.d/99-wireguard.conf"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
log()    { printf "${GREEN}[*]${NC} %s\n" "$*"; }
warn()   { printf "${YELLOW}[!]${NC} %s\n" "$*"; }
err()    { printf "${RED}[x]${NC} %s\n" "$*" >&2; }
die()    { err "$*"; exit 1; }
header() { printf "\n${CYAN}=== %s ===${NC}\n" "$*"; }

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
    local IFS='.'
    local octet
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

server_public_key() {
    awk -F' = ' '/^PrivateKey/{print $2}' "$WG_DIR/${SERVER_WG_NIC}.conf" | wg pubkey
}

# =============================================================================
# §8  Client management
# =============================================================================
next_client_ip() {
    local last_v4=1 last_v6=1
    if [[ -s "$MANIFEST" ]]; then
        local name pub ipv4 ipv6 v4_host v4_last v4_base v6_suffix
        while IFS='|' read -r name pub ipv4 ipv6; do
            [[ -z "$name" || "$name" == "#"* ]] && continue
            v4_base="${SERVER_WG_IPV4%.*}"
            v4_host="${ipv4%.*}"
            v4_last="${ipv4##*.}"
            [[ "$v4_host" == "$v4_base" ]] && (( v4_last > last_v4 )) && last_v4="$v4_last"
            v6_suffix="${ipv6##*::}"
            [[ "$v6_suffix" =~ ^[0-9]+$ ]] && (( v6_suffix > last_v6 )) && last_v6="$v6_suffix"
        done < "$MANIFEST"
    fi
    echo "$((last_v4 + 1)) $((last_v6 + 1))"
}

render_client_config() {
    local priv=$1 addr_v4=$2 addr_v6=$3 psk=$4
    local server_pub endpoint
    server_pub=$(server_public_key)

    if [[ "$SERVER_PUB_IP" == *:* ]]; then
        endpoint="[${SERVER_PUB_IP}]:${SERVER_PORT}"
    else
        endpoint="${SERVER_PUB_IP}:${SERVER_PORT}"
    fi

    cat <<EOF
[Interface]
PrivateKey = ${priv}
Address = ${addr_v4}/32, ${addr_v6}/128
DNS = ${CLIENT_DNS_1}, ${CLIENT_DNS_2}

[Peer]
PublicKey = ${server_pub}
Endpoint = ${endpoint}
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
EOF
    [[ -n "$psk" ]] && echo "PresharedKey = ${psk}"
}

show_qr() {
    local config_file=$1
    if command -v qrencode >/dev/null 2>&1; then
        header "QR code (scan with WireGuard mobile app)"
        qrencode -t ansiutf8 < "$config_file"
    fi
}

add_client() {
    local name="${1:-}"
    [[ -n "$name" ]] || die "usage: $0 add-client <name>"
    [[ "$name" =~ ^[a-zA-Z0-9_-]{1,32}$ ]] || die "invalid client name (alnum/-/_ max 32)"
    load_state || die "no install state — run '$0 install' first"

    if grep -q "^${name}|" "$MANIFEST" 2>/dev/null; then
        die "client '$name' already exists"
    fi

    local v4_octet v6_suffix
    read -r v4_octet v6_suffix <<< "$(next_client_ip)"
    local v4_base="${SERVER_WG_IPV4%.*}"
    local client_v4="${v4_base}.${v4_octet}"
    local client_v6="${SERVER_WG_IPV6%%[0-9]*}${v6_suffix}"

    log "Adding client '${name}' (${client_v4}, ${client_v6})"

    local priv pub psk=""
    priv=$(wg genkey)
    pub=$(echo "$priv" | wg pubkey)
    [[ "$USE_PSK" =~ ^[Yy] ]] && psk=$(wg genpsk)

    # Append to server config
    {
        echo ""
        echo "# Client: ${name} ($(date -u +%FT%TZ))"
        echo "[Peer]"
        echo "PublicKey = ${pub}"
        echo "AllowedIPs = ${client_v4}/32, ${client_v6}/128"
        [[ -n "$psk" ]] && echo "PresharedKey = ${psk}"
    } >> "$WG_DIR/${SERVER_WG_NIC}.conf"

    # Record in manifest
    echo "${name}|${pub}|${client_v4}|${client_v6}" >> "$MANIFEST"

    # Render client config
    local client_conf="${CLIENT_DIR}/${name}.conf"
    render_client_config "$priv" "$client_v4" "$client_v6" "$psk" > "$client_conf"
    chmod 0600 "$client_conf"
    priv=""

    # Apply at runtime (no interface restart)
    if systemctl is-active "wg-quick@${SERVER_WG_NIC}" >/dev/null 2>&1; then
        wg set "$SERVER_WG_NIC" peer "$pub" \
            allowed-ips "${client_v4}/32,${client_v6}/128" 2>/dev/null || true
    fi

    header "Client '${name}' created"
    log "Config: $client_conf"
    cat "$client_conf"
    show_qr "$client_conf"
}

remove_client() {
    local name="${1:-}"
    [[ -n "$name" ]] || die "usage: $0 remove-client <name>"
    load_state || die "no install state"

    grep -q "^${name}|" "$MANIFEST" 2>/dev/null || die "client '$name' not found"

    local pub
    pub=$(awk -F'|' -v n="$name" '$1==n {print $2}' "$MANIFEST")
    [[ -n "$pub" ]] || die "cannot find public key for '$name'"

    log "Removing peer ${pub} from ${SERVER_WG_NIC}"
    wg set "$SERVER_WG_NIC" peer "$pub" remove 2>/dev/null || true

    # Remove [Peer] block from server config
    local tmp
    tmp=$(mktemp)
    awk -v target="$pub" '
        function flush_peer() {
            if (inpeer) {
                if (!match_key) printf "%s", buf
                inpeer = 0
            }
        }
        BEGIN { inpeer = 0; buf = ""; match_key = 0 }
        /^\[Peer\]/ { flush_peer(); inpeer = 1; buf = $0 "\n"; match_key = 0; next }
        inpeer && /^[A-Za-z]/ {
            if ($0 ~ /^PublicKey = / && $3 == target) match_key = 1
            buf = buf $0 "\n"
            next
        }
        { flush_peer(); print }
        END { flush_peer() }
    ' "$WG_DIR/${SERVER_WG_NIC}.conf" > "$tmp"
    mv "$tmp" "$WG_DIR/${SERVER_WG_NIC}.conf"
    chmod 0600 "$WG_DIR/${SERVER_WG_NIC}.conf"

    # Remove from manifest and delete client config
    grep -v "^${name}|" "$MANIFEST" > "${MANIFEST}.tmp" || true
    mv "${MANIFEST}.tmp" "$MANIFEST"
    chmod 0600 "$MANIFEST"
    rm -f "${CLIENT_DIR}/${name}.conf"

    log "Client '${name}' removed"
}

list_clients() {
    load_state || die "no install state — run '$0 install' first"
    if [[ ! -s "$MANIFEST" ]]; then
        log "no clients"
        return
    fi
    printf "%-20s %-16s %-28s %s\n" "NAME" "IPv4" "IPv6" "PUBLIC KEY"
    printf "%-20s %-16s %-28s %s\n" "----" "----" "----" "----------"
    local name pub ipv4 ipv6
    while IFS='|' read -r name pub ipv4 ipv6; do
        [[ -z "$name" ]] && continue
        printf "%-20s %-16s %-28s %s\n" "$name" "$ipv4" "$ipv6" "$pub"
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
        local ans
        read -rp "Back up existing configs and continue? [y/N] " ans
        [[ "$ans" =~ ^[Yy]$ ]] || die "aborted by user"
        local ts
        ts=$(date -u +%Y%m%dT%H%M%SZ)
        local f
        for f in "$WG_DIR"/*.conf; do
            cp -p "$f" "${f}.bak.${ts}"
            log "backed up $f → ${f}.bak.${ts}"
        done
    fi

    install_wireguard "$os"
    ensure_dirs

    # --- Input collection ---
    local default_pubip="" pub4 pub6
    pub4=$(detect_public_ipv4)
    pub6=$(detect_public_ipv6)
    if [[ -n "$pub4" ]]; then
        default_pubip="$pub4"
        log "detected IPv4: $pub4"
    elif [[ -n "$pub6" ]]; then
        default_pubip="$pub6"
        log "detected IPv6: $pub6"
    fi

    read -rp "Public address (IPv4 or IPv6): " -e -i "$default_pubip" SERVER_PUB_IP
    [[ -n "$SERVER_PUB_IP" ]] || die "public address required"
    if ! is_ipv4 "$SERVER_PUB_IP" && ! is_ipv6 "$SERVER_PUB_IP"; then
        die "invalid IP: $SERVER_PUB_IP"
    fi

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

    # --- Server key generation ---
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
    server_priv=""     # wipe from memory
    server_pub=""

    # --- Persist IP forwarding ---
    cat > "$SYSCTL_FILE" <<EOF
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1
EOF
    sysctl -p "$SYSCTL_FILE" >/dev/null 2>&1 || true

    # --- Firewall ---
    open_firewall_port "$SERVER_PORT"

    # --- Start service ---
    systemctl enable --now "wg-quick@${SERVER_WG_NIC}"

    # --- Health check ---
    sleep 1
    if ! systemctl is-active "wg-quick@${SERVER_WG_NIC}" >/dev/null 2>&1; then
        systemctl status "wg-quick@${SERVER_WG_NIC}" --no-pager || true
        die "service failed to start — see status output above"
    fi
    log "service active: wg-quick@${SERVER_WG_NIC}"

    # --- First client ---
    local client_name="client1"
    read -rp "First client name: " -e -i "$client_name" client_name
    add_client "$client_name"

    header "Installation complete"
    log "Server config:  $server_conf"
    log "Client configs: $CLIENT_DIR/"
    log ""
    log "Manage with:"
    log "  $0 add-client <name>"
    log "  $0 remove-client <name>"
    log "  $0 list-clients"
    log "  $0 show-client <name>"
    log "  $0 uninstall"
}

cmd_uninstall() {
    require_root
    load_state || die "no install state — nothing to uninstall"

    warn "This will:"
    warn "  * stop and disable wg-quick@${SERVER_WG_NIC}"
    warn "  * close UDP ${SERVER_PORT} in the firewall"
    warn "  * remove ${WG_DIR}/${SERVER_WG_NIC}.conf"
    warn "  * remove ${CLIENT_DIR}/ and ${MANIFEST} and ${STATE_FILE}"
    warn "  * remove ${SYSCTL_FILE}"
    warn "Packages will NOT be removed."
    local ans
    read -rp "Continue? [y/N] " ans
    [[ "$ans" =~ ^[Yy]$ ]] || die "aborted"

    systemctl disable --now "wg-quick@${SERVER_WG_NIC}" 2>/dev/null || true
    close_firewall_port "$SERVER_PORT"

    rm -f "${WG_DIR}/${SERVER_WG_NIC}.conf"
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
  install                  Install WireGuard and add the first client (default)
  add-client <name>        Add a new client
  remove-client <name>     Remove a client
  list-clients             List all clients
  show-client <name>       Show client config and QR code
  uninstall                Remove config and firewall rules
  version                  Print version

Examples:
  $0
  $0 add-client laptop
  $0 list-clients
  $0 show-client laptop
EOF
}

main() {
    local cmd="${1:-install}"
    shift || true
    case "$cmd" in
        install)                        cmd_install ;;
        add-client)                     add_client "$@" ;;
        remove-client)                  remove_client "$@" ;;
        list-clients)                   list_clients ;;
        show-client)                    show_client "$@" ;;
        uninstall)                      cmd_uninstall ;;
        version|--version|-v)           echo "${SCRIPT_VERSION} (${SCRIPT_AUTHOR})" ;;
        help|--help|-h|"")              usage ;;
        *) err "unknown command: $cmd"; usage; exit 1 ;;
    esac
}

main "$@"
