#!/bin/bash
set -euo pipefail

# -------------------------
# Variables
# -------------------------
OUT_IF="eth3"
DMZ_IF="eth2"
WAF_IP="10.255.40.21"
BACKEND_IP="10.255.40.10"
BLACKLIST_TIMEOUT="5m"

# -------------------------
# Enable IP forwarding
# -------------------------
echo "[*] Enabling IP forwarding..."
sysctl -w net.ipv4.ip_forward=1
grep -q "ip_forward" /etc/sysctl.conf || echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf

# -------------------------
# Install nftables + fail2ban
# -------------------------
echo "[*] Installing nftables and fail2ban..."
apt update
apt install -y nftables fail2ban
systemctl enable --now nftables
systemctl enable --now fail2ban

# -------------------------
# Kernel hardening / DDoS protection
# -------------------------
cat <<EOF >/etc/sysctl.d/99-ddos-hardening.conf
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 4096
net.ipv4.tcp_synack_retries = 3
net.ipv4.tcp_max_orphans = 8192
net.ipv4.conf.all.rp_filter = 1
net.core.somaxconn = 4096
net.netfilter.nf_conntrack_max = 262144
EOF
sysctl --system

# -------------------------
# nftables rules
# -------------------------
cat <<EOF >/etc/nftables.conf
flush ruleset

table inet firewall {
    set blacklist {
        type ipv4_addr
        flags dynamic
        timeout $BLACKLIST_TIMEOUT
    }

    chain input {
        type filter hook input priority 0;
        policy drop;

        iif "lo" accept
        ct state established,related accept
        ip saddr @blacklist drop

        # SYN flood protection
        tcp flags & (fin|syn|rst|ack) == syn limit rate 50/second accept
        tcp flags & (fin|syn|rst|ack) == syn drop

        # ICMP rate limiting
        ip protocol icmp limit rate 5/second accept
    }

    chain forward {
        type filter hook forward priority 0;
        policy drop

        ip saddr @blacklist drop
        ct state established,related accept

        # Outside -> WAF TCP 80 only
        iifname "$OUT_IF" oifname "$DMZ_IF" ip daddr $WAF_IP tcp dport 80 ct state new limit rate 500/second accept

        # Block outside -> backend directly
        iifname "$OUT_IF" ip daddr $BACKEND_IP drop

        # Allow WAF -> backend
        iifname "$DMZ_IF" ip saddr $WAF_IP oifname "$DMZ_IF" ip daddr $BACKEND_IP tcp dport 80 accept

        # Allow DMZ -> outside
        iifname "$DMZ_IF" oifname "$OUT_IF" accept
    }

    chain output {
        type filter hook output priority 0;
        policy accept
    }
}

table ip nat {
    chain postrouting {
        type nat hook postrouting priority 100;
        policy accept
        oifname "$OUT_IF" masquerade
    }
}
EOF

systemctl restart nftables

# -------------------------
# Fail2ban setup
# -------------------------
# Action for nftables
cat <<EOF >/etc/fail2ban/action.d/nftables.conf
[Definition]
actionstart =
actionstop =
actioncheck =
actionban = /usr/sbin/nft add element inet firewall blacklist { <ip> }
actionunban = /usr/sbin/nft delete element inet firewall blacklist { <ip> }
EOF

# Example HTTP abuse filter
cat <<EOF >/etc/fail2ban/filter.d/http-get-dos.conf
[Definition]
failregex = ^<HOST> - - \[.*\] "((GET|POST|HEAD) .*)"
ignoreregex =
EOF

# Jail configuration
cat <<EOF >/etc/fail2ban/jail.d/http-dos.local
[DEFAULT]
ignoreip = 127.0.0.1/8
bantime  = 5m
findtime = 600
maxretry = 50

[http-get-dos]
enabled = true
port = http
filter = http-get-dos
logpath = /var/log/apache2/access.log
action = nftables[name=HTTPDOS]
EOF

systemctl restart fail2ban

echo "[*] Kali1 firewall + nftables + Fail2ban setup complete."
