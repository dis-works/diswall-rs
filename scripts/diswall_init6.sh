
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

# Allow all IPs from diswall-wl
ip6tables -A INPUT -m set --match-set diswall-wl6 src -j ACCEPT

# Drop all packets for blocked IPs
ip6tables -A INPUT -m set --match-set diswall-bl6 src -j DROP

# Allow ping requests
ip6tables -A INPUT -p icmpv6 -j ACCEPT

#diswall_init6_rules

# Log all other packets:
ip6tables -A INPUT -j LOG --log-prefix "diswall-log: "