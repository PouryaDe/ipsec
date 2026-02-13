#!/bin/bash

# ==========================================
# All-in-One IPsec+GRE Manager (Ultimate Edition)
# Features: Batch Install, MSS Clamping, Auto-Fix Watchdog
# ==========================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

LOG_FILE="/var/log/ipsec-ultimate.log"
SWANCTL_DIR="/etc/swanctl"
CONF_D_DIR="$SWANCTL_DIR/conf.d"

# چک کردن دسترسی روت
if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}Please run as root${NC}"
  exit 1
fi


install_core() {
    echo -e "${CYAN}[1/5] Installing/Repairing StrongSwan...${NC}"
    apt-get update -qq
    apt-get install -y -qq strongswan strongswan-pki libstrongswan-extra-plugins strongswan-swanctl charon-systemd coreutils iptables
    
    # پیدا کردن مسیر Charon برای ساخت سرویس دقیق
    CHARON_PATH=$(which charon-systemd 2>/dev/null || echo "/usr/sbin/charon-systemd")

    cat <<EOF > /etc/systemd/system/strongswan-swanctl.service
[Unit]
Description=strongSwan IPsec IKEv2 daemon (charon-systemd)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$CHARON_PATH
ExecStartPost=/bin/sleep 2
ExecStartPost=-/usr/sbin/swanctl --load-all
ExecReload=/usr/sbin/swanctl --reload
Restart=on-abnormal

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable strongswan-swanctl
    systemctl restart strongswan-swanctl
    echo -e "${GREEN}[1/5] Core Service is Ready.${NC}"
}


apply_optimizations() {
    echo -e "${CYAN}[2/5] Applying Firewall & TCP Optimizations...${NC}"
    # باز کردن پورت‌ها
    iptables -I INPUT -p udp --dport 500 -j ACCEPT 2>/dev/null
    iptables -I INPUT -p udp --dport 4500 -j ACCEPT 2>/dev/null
    iptables -I INPUT -p 47 -j ACCEPT 2>/dev/null
    iptables -I INPUT -p esp -j ACCEPT 2>/dev/null

    # MSS Clamping برای رفع مشکل باز نشدن سایت‌ها
    iptables -t mangle -D FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || true
    iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
    
    echo -e "${GREEN}[2/5] MSS Clamping & Firewall Applied.${NC}"
}


setup_tunnel() {
    local id=$1; local l_ip=$2; local r_ip=$3; local psk=$4; local g_loc=$5; local g_rem=$6

    # 1. IPsec Config
    cat > "$CONF_D_DIR/tun${id}.conf" <<EOF
connections {
    tun${id} {
        local_addrs = $l_ip
        remote_addrs = $r_ip
        version = 2
        unique = replace
        proposals = aes256-sha256-modp2048,aes128-sha1-modp1024
        local { auth = psk; id = $l_ip }
        remote { auth = psk; id = $r_ip }
        children {
            tun${id} {
                mode = transport
                esp_proposals = aes256-sha256,aes128-sha1
                start_action = start
                dpd_action = restart
                dpd_delay = 30s
            }
        }
    }
}
secrets { ike-tun${id} { id = $r_ip; secret = "$psk" } }
EOF
    swanctl --load-all

    # 2. GRE Interface Script
    cat > "/usr/local/bin/ipsec-gre-up-${id}.sh" <<EOF
#!/bin/bash
ip tunnel del gre${id} 2>/dev/null || true
ip tunnel add gre${id} mode gre remote $r_ip local $l_ip ttl 255
ip link set gre${id} mtu 1400
ip link set gre${id} up
ip addr add $g_loc/30 dev gre${id}
swanctl --initiate --child tun${id}
EOF
    chmod +x "/usr/local/bin/ipsec-gre-up-${id}.sh"

    # 3. GRE Service
    cat > "/etc/systemd/system/ipsec-gre-${id}.service" <<EOF
[Unit]
Description=GRE Tunnel ${id}
After=strongswan-swanctl.service
[Service]
Type=oneshot
ExecStart=/usr/local/bin/ipsec-gre-up-${id}.sh
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target
EOF

    # 4. Advanced Smart Keepalive (Fix Script Logic)
    cat > "/usr/local/bin/ipsec-keepalive-${id}.sh" <<EOF
#!/bin/bash
TARGET="$g_rem"
while true; do
    FAIL=0
    if ! ping -c 4 -W 2 \$TARGET > /dev/null; then FAIL=1; fi
    if [ \$FAIL -eq 0 ]; then
        if ! timeout 5 swanctl --list-sas --ike tun${id} | grep -qE "ESTABLISHED|CONNECTING"; then FAIL=1; fi
    fi
    if [ \$FAIL -eq 1 ]; then
        echo "Recovery initiated for tun${id}..."
        swanctl --terminate --ike tun${id} 2>/dev/null
        sleep 2
        systemctl restart ipsec-gre-${id}
        sleep 40
    fi
    sleep 10
done
EOF
    chmod +x "/usr/local/bin/ipsec-keepalive-${id}.sh"

    # 5. Keepalive Service
    cat > "/etc/systemd/system/ipsec-keepalive-${id}.service" <<EOF
[Unit]
Description=Keepalive tun${id}
After=ipsec-gre-${id}.service
[Service]
ExecStart=/usr/local/bin/ipsec-keepalive-${id}.sh
Restart=always
[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable --now "ipsec-gre-${id}" "ipsec-keepalive-${id}"
}


install_global_monitor() {
    echo -e "${CYAN}[4/5] Installing VICI Socket Monitor...${NC}"
    cat > /usr/local/bin/ipsec-health-monitor.sh <<'EOF'
#!/bin/bash
while true; do
    if ! timeout 5 swanctl --stats > /dev/null 2>&1; then
        echo "$(date): VICI Frozen! Restarting Charon..." >> /var/log/ipsec-health.log
        pkill -9 charon
        rm -f /var/run/charon.vici
        systemctl restart strongswan-swanctl
        sleep 20
    fi
    sleep 30
done
EOF
    chmod +x /usr/local/bin/ipsec-health-monitor.sh
    cat > /etc/systemd/system/ipsec-health-monitor.service <<EOF
[Unit]
Description=IPSec Health Monitor
After=strongswan-swanctl.service
[Service]
ExecStart=/usr/local/bin/ipsec-health-monitor.sh
Restart=always
[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable --now ipsec-health-monitor
}


batch_install() {
    read -p "Role (1: Iran, 2: Kharej): " role_opt
    read -p "Starting Tunnel ID (e.g. 1): " START_ID
    read -p "Remote IPs (space separated): " -a REMOTES
    read -p "PSK (empty for random): " PSK
    [ -z "$PSK" ] && PSK=$(tr -dc A-Za-z0-9 </dev/urandom | head -c 16)
    
    install_core
    apply_optimizations
    install_global_monitor

    local local_ip=$(ip route get 8.8.8.8 | awk '{print $7; exit}')

    for (( i=0; i<${#REMOTES[@]}; i++ )); do
        ID=$((START_ID + i))
        R_IP=${REMOTES[$i]}
        G_LOC="172.20.${ID}.1"; G_REM="172.20.${ID}.2"
        [ "$role_opt" == "2" ] && { tmp=$G_LOC; G_LOC=$G_REM; G_REM=$tmp; }

        echo -e "${YELLOW}Deploying Tunnel ${ID} to ${R_IP}...${NC}"
        setup_tunnel "$ID" "$local_ip" "$R_IP" "$PSK" "$G_LOC" "$G_REM"
    done
    echo -e "${GREEN}All systems deployed and monitored!${NC}"
}

clear
echo -e "${BLUE}==========================================${NC}"
echo -e "${BLUE}    ULTIMATE IPSEC & GRE BATCH MANAGER    ${NC}"
echo -e "${BLUE}==========================================${NC}"
echo "1) Full Batch Install + Health Monitor"
echo "2) Uninstall All"
echo "0) Exit"
read -p "Select: " opt
case $opt in
    1) batch_install ;;
    2) 
        systemctl stop ipsec-* 2>/dev/null
        systemctl disable ipsec-* 2>/dev/null
        rm -f /etc/systemd/system/ipsec-* /usr/local/bin/ipsec-* "$CONF_D_DIR"/*.conf
        systemctl daemon-reload
        echo "Cleaned." ;;
    *) exit 0 ;;
esac
