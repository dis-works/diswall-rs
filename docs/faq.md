## Admin FAQ

### What if our command server is down?

Your own servers will exchange IP info between themselves.

### What if our NATS server is down?

Nothing bad happens. Your servers will continue ban IPs that are scanning them.

### What if my IP will get banned for some reason? By mistake.

Hopefully, if your server will not try to connect to blocked ports of other servers with DisWall, this ban will wear off after 15 minutes.
If in doubt just add your IPs to allow list of your other servers.
If your IP is blocked by mistake you can reach us by sending e-mail to the mail address that you've obtained your password from when you've registered on our website.

### What if something is going on very bad?

If your server is blocking some legitimate IP or something is going wrong you can disable DisWall by `service diswall stop` and flushing iptables by `iptables -F INPUT`.

### How can I find what a problem is and try to fix it?

1. Check if some IP is in ipset list: `ipset save diswall-bl | grep 1.2.3.4`, if it is there you can just remove id from the list: `ipset del diswall-bl 1.2.3.4`.
2. DisWall prints logs to syslog, therefore you can search IP there: `grep 1.2.3.4 /var/log/syslog`.
3. If you need more info about diswall working process you can add `-d` flag in service file and restart diswall service.

### Can I check if my server is really invisible to Shodan?

Yes, you can just search your IP in Shodan: `https://www.shodan.io/host/1.2.3.4`.

### How can I add my IPs to allow-list?

You can do this in two ways:
1. Just add it to ipset: `ipset add diswall-wl 1.2.3.4`, but it will lost after restart.
2. Or you can add it to the list on NATS server by `diswall wl-add-ip 1.2.3.4`, it will be downloaded from NATS server on your server load.