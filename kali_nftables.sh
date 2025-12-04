#!/usr/bin/env bash
# kali_nftables_ddos_protect.sh
# Purpose: Install and activate a hardened nftables firewall for Kali Linux
# - outside interface: eth3 (10.255.90.1)
# - dmz interface:     eth2 (10.255.200.5)
# - dmz webserver:    10.255.40.10
# - WAF public-facing IP: 10.255.40.21
# - inside network:   10.255.40.0/24
# - blocked inside IP:10.255.40.10

set -euo pipefail
IFS=$'
	'

# -------------------------
# Configurable variables
# -------------------------
OUT_IF="eth3"
DMZ_IF="eth2"
DMZ_WEB_IP="10.255.40.10"
WAF_PUBLIC_IP="10.255.40.21"
INSIDE_NET="10.255.40.0/24"
BLOCKED_HOST="10.255.40.10"
NFT_CONF_PATH="/etc/nftables.conf"
BACKUP_PATH="/etc/nftables.conf.bak.$(date +%s)"

# Rate limits (tune to your environment)
SYN_RATE="25/second"
SYN_BURST="50"
GLOBAL_NEW_RATE="30/second"
GLOBAL_NEW_BURST="40"

# -------------------------
# Helpers
# -------------------------
require_root() {
  if [ "$EUID" -ne 0 ]; then
    echo "This script must be run as root. Use: sudo ./$(basename "$0")" >&2
    exit 1
  fi
}

install_if_missing() {
  local pkg="$1"
  if ! command -v "$pkg" >/dev/null 2>&1; then
    echo "Installing $pkg..."
    if command -v apt >/dev/null 2>&1; then
      apt update && DEBIAN_FRONTEND=noninteractive apt install -y "$pkg"
    else
      echo "Package manager apt not found - please install $pkg manually." >&2
      exit 1
    fi
  fi
}

# -------------------------
# Main
# -------------------------
require_root

# Ensure essential packages
install_if_missing nft
install_if_missing conntrack
install_if_missing iproute2
install_if_missing fail2ban

# -------------------------
# Kernel tuning (SYN cookies, conntrack limits, timeouts)
# -------------------------
echo "Applying kernel hardening settings..."
# Enable TCP SYN cookies
sysctl -w net.ipv4.tcp_syncookies=1
# Increase the SYN backlog and hashsize (for high connection rates)
sysctl -w net.ipv4.tcp_max_syn_backlog=2048
sysctl -w net.ipv4.tcp_max_tw_buckets=5000
# Enable forwarding
sysctl -w net.ipv4.ip_forward=1
# Conntrack table size
sysctl -w net.netfilter.nf_conntrack_max=262144
# Conntrack timeouts (reduce some long-lived states)
sysctl -w net.netfilter.nf_conntrack_tcp_timeout_established=86400
sysctl -w net.netfilter.nf_conntrack_tcp_timeout_close_wait=60

# Persist sysctl changes (overwrite or append safely)
persist_sysctl() {
  local key="$1" value="$2"
  if grep -q "^$key" /etc/sysctl.conf 2>/dev/null; then
    sed -i "s|^$key.*|$key = $value|" /etc/sysctl.conf
  else
    echo "$key = $value" >> /etc/sysctl.conf
  fi
}

persist_sysctl net.ipv4.tcp_syncookies 1
persist_sysctl net.ipv4.tcp_max_syn_backlog 2048
persist_sysctl net.ipv4.tcp_max_tw_buckets 5000
persist_sysctl net.ipv4.ip_forward 1
persist_sysctl net.netfilter.nf_conntrack_max 262144
persist_sysctl net.netfilter.nf_conntrack_tcp_timeout_established 86400
persist_sysctl net.netfilter.nf_conntrack_tcp_timeout_close_wait 60

# -------------------------
# Backup and write nftables config
# -------------------------
if [ -f "$NFT_CONF_PATH" ]; then
  echo "Backing up existing $NFT_CONF_PATH to $BACKUP_PATH"
  cp "$NFT_CONF_PATH" "$BACKUP_PATH"
fi

cat > "$NFT_CONF_PATH" <<EOF
flush ruleset

# Hardened nftables ruleset for Kali (with SYN flood protections)

table inet firewall {

    chain input {
        type filter hook input priority 0;
        policy drop;

        # loopback
        iif "lo" accept

        # allow established / related
        ct state established,related accept

        # drop invalid
        ct state invalid drop

        # allow ICMP (rate-limited)
        icmp type echo-request limit rate 10/second burst 20 accept

        # Allow SSH from DMZ only (adjust as needed)
        iif "$DMZ_IF" tcp dport 22 ct state new,established accept

        # allow local management if needed (UNCOMMENT and adjust)
        # ip saddr 192.0.2.100 tcp dport 22 ct state new,established accept
    }

    chain forward {
        type filter hook forward priority 0;
        policy drop;

        # drop invalid
        ct state invalid drop

        # allow established/related
        ct state established,related accept

        # -------------------------------
        # SYN flood / DDoS mitigation
        # -------------------------------
        # Allow legitimate SYNs to WAF public IP up to a limit
        tcp flags syn tcp dport 80 iif "$OUT_IF" ip daddr $WAF_PUBLIC_IP limit rate $SYN_RATE burst $SYN_BURST accept

        # Anything beyond the limit is dropped (fast path)
        tcp flags syn tcp dport 80 iif "$OUT_IF" ip daddr $WAF_PUBLIC_IP drop

        # Global new-connection rate limit for outside interface
        ct state new iif "$OUT_IF" limit rate $GLOBAL_NEW_RATE burst $GLOBAL_NEW_BURST accept
        ct state new iif "$OUT_IF" drop

        # -------------------------------
        # Allow outside -> WAF (public IP) on HTTP only
        # -------------------------------
        iif "$OUT_IF" ip daddr $WAF_PUBLIC_IP tcp dport 80 ct state new accept

        # -------------------------------
        # Block outside -> backend server directly (deny bypass)
        # -------------------------------
        iif "$OUT_IF" ip daddr $BLOCKED_HOST reject

        # -------------------------------
        # Allow forwarding for DMZ/INSIDE -> OUTSIDE
        # -------------------------------
        iif "$DMZ_IF" oif "$OUT_IF" ct state new,established,related accept
        iif "$OUT_IF" oif "$DMZ_IF" ct state established,related accept

        # Allow forwarding to inside network if explicitly needed (adjust)
        iif "$OUT_IF" ip daddr $INSIDE_NET ct state new accept

        # Optional: log dropped packets (rate-limited to avoid log floods)
        # log prefix "FW-DROP: " limit rate 5/second counter
    }

}

# NAT table (IPv4)
table ip nat {
    chain prerouting {
        type nat hook prerouting priority -100;
        # If you want to DNAT WAF public IP to backend directly on firewall level
        # nft rule example (commented):
        # ip daddr $WAF_PUBLIC_IP tcp dport 80 dnat to $DMZ_WEB_IP:80
    }

    chain postrouting {
        type nat hook postrouting priority 100;

        # Masquerade inside -> outside
        ip saddr $INSIDE_NET oif "$OUT_IF" masquerade
    }
}
EOF

# Load the new rules immediately
echo "Applying nftables ruleset from $NFT_CONF_PATH"
nft -f "$NFT_CONF_PATH"

# Enable and start nftables service so it persists across reboots
systemctl enable nftables --now

# -------------------------
# Fail2ban quick setup (optional)
# -------------------------
# Provide a simple jail to ban IPs that generate too many SSH or HTTP failures.
# This complements nftables by removing repeat offenders.
cat > /etc/fail2ban/jail.d/custom-nftables.local <<'JAIL'
[DEFAULT]
ignoreip = 127.0.0.1/8 ::1
bantime  = 3600
findtime  = 600
maxretry = 5

[sshd]
enabled = true

# If you have an HTTP server logging 4xx/5xx, create a filter and enable a jail.
JAIL

systemctl restart fail2ban || true

# -------------------------
# Summary & quick checks
# -------------------------
echo
echo "----- nftables ruleset (first 200 lines) -----"
nft list ruleset | sed -n '1,200p'

echo
echo "Kernel settings applied:"
sysctl net.ipv4.tcp_syncookies net.ipv4.tcp_max_syn_backlog net.ipv4.ip_forward net.netfilter.nf_conntrack_max

cat <<MSG

DONE.

What I added beyond the previous script:
- Enabled TCP SYN cookies (net.ipv4.tcp_syncookies=1)
- Tuned tcp backlog and conntrack max values to resist conntrack exhaustion
- Explicitly drop 'invalid' conntrack state packets
- Kept SYN-rate limiting for the WAF public IP and a global new-connection rate limit
- Added a simple Fail2ban config to complement nftables (bans repeat offenders)

Notes & next steps (recommended):
1) For very large/volumetric DDoS (multiple Gbps) a single Kali host won't stop upstream saturation — upstream filtering (ISP or cloud scrubbing) is required.
2) For per-source (per-IP) advanced rate-limiting or persistent blacklists, consider integrating nft 'sets' and a small daemon that inserts offenders into a blacklist set, or use Fail2ban with direct nft actions.
3) If you want, I can add an example DNAT rule to forward WAF public IP to the backend (10.255.40.10) at the firewall level.

How to run:
1) Save this script to your Kali box: /tmp/kali_nftables_ddos_protect.sh
2) Make executable: chmod +x /tmp/kali_nftables_ddos_protect.sh
3) Run as root: sudo /tmp/kali_nftables_ddos_protect.sh

MSG

exit 0
