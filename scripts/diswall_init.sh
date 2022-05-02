#!/bin/bash

ipset create -exist diswall-wl hash:net comment
ipset create -exist diswall-bl hash:ip hashsize 32768 maxelem 1000000 timeout 86400

# Clearing current iptables rules
echo iptables -P INPUT ACCEPT
iptables -P INPUT ACCEPT
echo iptables -F INPUT
iptables -F INPUT

echo Creating firewall rules:
# Allow all localhost and related connections:
echo iptables -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
iptables -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
echo iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -i lo -j ACCEPT

# Allow all IPs from diswall-wl
echo iptables -A INPUT -m set --match-set diswall-wl src -j ACCEPT
iptables -A INPUT -m set --match-set diswall-wl src -j ACCEPT

# Drop all packets for blocked IPs
echo iptables -A INPUT -m set --match-set diswall-bl src -j DROP
iptables -A INPUT -m set --match-set diswall-bl src -j DROP

#diswall_init_rules

# Log all other packets:
echo iptables -A INPUT -j LOG --log-prefix "diswall: "
iptables -A INPUT -j LOG --log-prefix "diswall: "
