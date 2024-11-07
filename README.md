[![GitHub release (latest SemVer)](https://img.shields.io/github/v/release/dis-works/diswall-rs)](https://github.com/dis-works/diswall-rs/releases/latest) [![CodeQL](https://github.com/dis-works/diswall-rs/actions/workflows/release.yml/badge.svg)](https://github.com/dis-works/diswall-rs/actions/workflows/release.yml)

- [Description](#diswall-alfa-version)
- [ipset](#ipset)
- [NATS](#nats)
- [Installation](#installation)
- [Configuration](#configuration)
- [Installing your own server](#own-server-installation)
- [Autonomous](#autonomous-work)
- [Data collection](#data-collection)

# DisWall (alfa version!)

Diswall (distributed firewall) - a client of distributed firewall working on many servers and using [NATS](https://nats.io) for the transport level.
Its purpose - blocking IPs with a blink of the eye on all servers in any infrastructure when some IP checks any of the closed ports of anyone of these servers.
Therefore, diswall provides good protection of whole infrastructure (as anti-shodan) preventing intruder to get any system information.

The source of these "bad" IP-addresses is firewall log. But it is possible to use other sources in future (for example logs of WAF).
DisWall reads journald messages filtered by special rules, no other info is extracted from logs and is not sent anywhere.
All acquired IPs are added to a set in nftables or list in ipset and any open connection with that IP is closed (to prevent any interaction with open ports, for example exploitation of web-based vulnerability).
This IP is simultaneously sent through NATS to the central server ([diswall.stream](https://diswall.stream)) and is distributed to all other diswall clients.

You can use the same approach to distribute allowed IPs as a convenient way to control firewalls on your servers.
In contrast to blocklist allowlist is unique for every client, it supports comments and can store whole networks.

Now the banning intervals are variable - we ban for 15 minutes the first time, then 30 minutes, then an hour times scan attempts.
There are IPs that are banned for several months already.

When your server is started diswall client gets actual block and allow lists from NATS server.
This provides protection in accordance with any events that occurred on other servers when any of them was offline.

# ipset
(If you use obsolete iptables instead of nftables.)

Diswall uses two ipset lists - for blocked addresses (`diswall-bl`) and allowed ones (`diswall-wl`).

Allow list is created by `ipset create -exist diswall-wl hash:net comment` command.
It allows usage of whole networks and adding comments for every record.

Block list is created by `ipset create -exist diswall-bl hash:ip hashsize 32768 maxelem 1000000 timeout 86400` command.
It allows adding only individual IPs and doesn't support comments.

# NATS

By default, these subjects are used for IP publishing:
- `diswall.whitelist.<client_name>.add.<hostname>` - to add some IP to allowlist;
- `diswall.whitelist.<client_name>.del.<hostname>` - to remove IP from allowlist;
- `diswall.blacklist.<client_name>.add.<hostname>` - to add some IP to blocklist;
- `diswall.blacklist.<client_name>.del.<hostname>` - to remove IP from blocklist.

Also, there are two special subject - `diswall.blacklist.<client_name>.init.<hostname>` и `diswall.whitelist.<client_name>.init.<hostname>`.
They are used for initialization of the system (populating diswall-bl and diswall-wl lists).
But the most important subject is `diswall.blacklist.new` - the server, that is accumulating the IPs is sending all IPs to block with this subject.

# Installation

The simplest way to install diswall on your server is to use autoinstall functionality in diswall itself:
```bash
curl -s https://get.diswall.stream | bash
```
or
```bash
wget -q -O - https://get.diswall.stream | bash
```
It will download a short script that will determine your architecture and get the latest appropriate release binary from GitHub.
Then it will start installation procedure from this binary.

This will copy the binary to `/usr/bin`, create systemd service, diswall config (`/etc/diswall/diswall.conf`)
and configure nftables in `/etc/nftables.conf` or add iptables initialization script at `/usr/bin/diswall_init.sh`.

# Configuration

DisWall configuration file is located at `/etc/diswall/diswall.conf`. Its format is TOML.
If you register on our website and enter credentials in this config you will get all blocked IPs in a blink of an eye.\
But you can use DisWall without registration (using 'default/default' credentials). In this case you will not get "fresh" attackers IPs,
only those known to our DB and have banning period more than 1 day.

As said before the firewall configuration can be either in `/etc/nftables.conf` or `/usr/bin/diswall_init.sh`, depending on firewall installed.\
But you can edit appropriate file by using simple command `diswall -e`, it will run your preferred editor with appropriate file path.

Also, DisWall has command line arguments listed below.

```text
-h, --help                Print this help menu
-v, --version             Print version and exit
    --install             Install DisWall as system service (in client mode)
 	--update              Update DisWall to latest release from GitHub
	--uninstall           Uninstall DisWall from your server
-e 	--edit                Edit firewall config
-i 	--interface           Run text interface to see what's going on
-d, --debug               Show trace messages, more than debug
-g, --generate            Generate fresh configuration file. It is better to redirect contents to file.
-c, --config FILE         Set configuration file path
    --log FILE            Set log file path
-f, --pipe-file FILE      Named pipe from which to fetch IPs
-s, --nats-server DOMAIN  NATS server name
-P, --port PORT           NATS server port
-n, --name NAME           NATS client name (login)
-p, --pass PASSWORD       NATS password
-l, --local-only          Don't connect to NATS server, work only locally
-a, --allow-list          Allow list name
-b, --block-list          Block list name
    --wl-add-ip IP        Add this IP to allow list
    --wl-add-comm COMMENT Comment to add with IP to allow list
    --wl-del-ip IP        Remove IP from allow list
    --bl-add-ip IP        Add this IP to block list
    --bl-del-ip IP        Remove IP from block list
-k, --kill                Kill already established connection using `ss -K`
    --server              Start diswall NATS server to handle init messages.
```

# Own server installation

To install and host your own diswall server, you need to install NATS and start diswall in `--server` mode.
You can find NATS installation instructions in [documentation](https://docs.nats.io/nats-server/installation).
After installation, you need to adjust permissions: example is below, and more examples are in [documentation](https://docs.nats.io/nats-server/configuration/securing_nats/authorization):

```
$ cat /etc/nats.conf
...
authorization {
  default_permissions = {
    subscribe = ["diswall.blacklist.init", "diswall.blacklist.new"]
  }
  DW_SERVER = {
    publish = "_INBOX.>"
    subscribe = ["diswall.blacklist.*", "diswall.whitelist.*"]
  }
  USER1 = {
    publish = ["diswall.blacklist.client1.*", "diswall.whitelist.client1.*"]
    subscribe = ["_INBOX.>", "diswall.blacklist.new", "diswall.whitelist.client1", "diswall.whitelist.client1"]
  }
  users = [
    {user: dw_server,   password: "QuodLicetJovi",   permissions: $DW_SERVER}
    {user: client1,  password: "NonLicetBovi",   permissions: $USER1}
  ]
}
```

You will need to create separate config file: `diswall -g > /etc/diswall/diswall-server.conf` and create separate systemd unit to run `/usr/bin/diswall -c /etc/diswall/diswall/diswall-server.conf`.
Make sure you set the client name in this config to `dw_server` and use appropriate password.
And don't forget to set `server_mode = true`.

# Autonomous work

If you don't want diswall to work as _distributed_ firewall you can start it in local only mode, just set `localonly = true` in config file.
In this case it will block all IPs that it gets from iptables log file without connection to NATS server.

# Data collection

If your node blocks some IP it will send bad IP to NATS server, and this IP will be added to bad IPs database.
