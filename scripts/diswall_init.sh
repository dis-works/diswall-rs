#!/bin/bash

ipset create -exist diswall-wl hash:net comment
ipset create -exist diswall-bl hash:ip hashsize 32768 maxelem 1000000 timeout 86400

# Clearing current iptables rules
iptables -P INPUT ACCEPT
iptables -F INPUT

# Allow all localhost and related connections:
iptables -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
iptables -A INPUT -i lo -j ACCEPT
# For rare conditions
iptables -A OUTPUT -p udp -m state --state NEW,ESTABLISHED -j ACCEPT

# For timed out responses from DNS servers
iptables -A INPUT -p udp --sport 53 -j ACCEPT
iptables -A INPUT -p tcp --sport 53 -j ACCEPT

# Allow all IPs from diswall-wl
iptables -A INPUT -m set --match-set diswall-wl src -j ACCEPT

# Drop all packets for blocked IPs
iptables -A INPUT -m set --match-set diswall-bl src -j DROP

# Allow ping requests
iptables -A INPUT -p icmp --icmp-type echo-request  -j ACCEPT

#diswall_init_rules

# Log all other packets:
iptables -A INPUT -p udp -j LOG --log-prefix "diswall-log: "
iptables -A INPUT -p tcp -j LOG --log-prefix "diswall-log: "

### IPv6 rules

ipset create -exist diswall-wl6 hash:net family inet6 comment
ipset create -exist diswall-bl6 hash:ip family inet6 hashsize 32768 maxelem 1000000 timeout 86400

# Clearing current iptables rules
ip6tables -P INPUT ACCEPT
ip6tables -F INPUT

# Allow all localhost and related connections:
ip6tables -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
ip6tables -A INPUT -i lo -j ACCEPT
ip6tables -A INPUT -s fe80::/10 -j ACCEPT

# For timed out responses from DNS servers
ip6tables -A INPUT -p udp --sport 53 -j ACCEPT
ip6tables -A INPUT -p tcp --sport 53 -j ACCEPT

# Allow all IPs from diswall-wl
ip6tables -A INPUT -m set --match-set diswall-wl6 src -j ACCEPT

# Drop all packets for blocked IPs
ip6tables -A INPUT -m set --match-set diswall-bl6 src -j DROP

# Allow ping requests
ip6tables -A INPUT -p icmpv6 -j ACCEPT

#diswall_init6_rules

# Log all other packets:
ip6tables -A INPUT -p udp -j LOG --log-prefix "diswall-log: "
ip6tables -A INPUT -p tcp -j LOG --log-prefix "diswall-log: "