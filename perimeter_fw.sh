#!/bin/bash

# ---------------------------
# Flush existing iptables
# ---------------------------
sudo iptables -F
sudo iptables -t nat -F
sudo iptables -X
sudo iptables -t nat -X

# Set default policies
sudo iptables -P INPUT ACCEPT
sudo iptables -P OUTPUT ACCEPT
sudo iptables -P FORWARD DROP

# ---------------------------
# Enable IP forwarding
# ---------------------------
sudo sysctl -w net.ipv4.ip_forward=1
echo "net.ipv4.ip_forward = 1" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p

# ---------------------------
# Variables
# ---------------------------
OUTSIDE_NET="10.255.90.0/24"
PERIM_FIREWALL_OUT="10.255.90.10"
PERIM_FIREWALL_DMZ="10.255.200.5"
INTERNAL_WAF="10.255.40.21"

# ---------------------------
# Allow established connections
# ---------------------------
sudo iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT

# ---------------------------
# Allow outside HTTP/HTTPS traffic to WAF only
# ---------------------------
sudo iptables -A FORWARD -i eth3 -o eth2 -s $OUTSIDE_NET -d $INTERNAL_WAF -p tcp -m multiport --dports 80,443 -j ACCEPT

# Allow return traffic from WAF
sudo iptables -A FORWARD -i eth2 -o eth3 -s $INTERNAL_WAF -d $OUTSIDE_NET -p tcp -m multiport --sports 80,443 -m state --state ESTABLISHED,RELATED -j ACCEPT

# ---------------------------
# NAT so WAF sees traffic as from perimeter firewall DMZ IP
# (required if WAF doesn't have route back to outside subnet)
# ---------------------------
sudo iptables -t nat -A POSTROUTING -s $OUTSIDE_NET -d $INTERNAL_WAF -o eth2 -j SNAT --to-source $PERIM_FIREWALL_DMZ

# ---------------------------
# Optional: allow ICMP ping for testing
# ---------------------------
sudo iptables -A FORWARD -i eth3 -o eth2 -s $OUTSIDE_NET -d $INTERNAL_WAF -p icmp -j ACCEPT
sudo iptables -A FORWARD -i eth2 -o eth3 -s $INTERNAL_WAF -d $OUTSIDE_NET -p icmp -m state --state ESTABLISHED,RELATED -j ACCEPT

# ---------------------------
# Block all other DMZ hosts from outside
# ---------------------------
sudo iptables -A FORWARD -i eth3 -o eth2 -s $OUTSIDE_NET -d 10.255.40.0/24 -j REJECT

echo "Perimeter firewall configured: Outside clients can reach ONLY internal WAF ($INTERNAL_WAF)!"
