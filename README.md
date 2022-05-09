[![GitHub release (latest SemVer)](https://img.shields.io/github/v/release/dis-works/diswall-rs)](https://github.com/dis-works/diswall-rs/releases/latest) [![CodeQL](https://github.com/dis-works/diswall-rs/actions/workflows/release.yml/badge.svg)](https://github.com/dis-works/diswall-rs/actions/workflows/release.yml)

- [Description](#diswall-alfa-version)
- [ipset](#ipset)
- [NATS](#nats)
- [Installation](#installation)
- [Configuration](#configuration)
- [Installing your own server](#own-server-installation)
- [Autonomous](#autonomous-work)
- [Data collection](#data-collection)

# diswall (alfa version!)

diswall (distributed firewall) - a client of distributed firewall working on many servers and using [NATS](https://nats.io) for the transport level.
Its purpose - blocking IPs with a blink of the eye on all servers in any infrastructure when some IP checks any of the closed ports of anyone of these servers.
Therefore, diswall provides good protection of whole infrastructure (as anti-shodan) preventing intruder to get any system information.

The source of these "bad" IP-addresses is iptables log. But it is possible to use other sources in future (for example logs of WAF).
Thanks to log templates of rsyslog only IP is extracted from kernel, no other info is extracted from logs and is not sent anywhere.
All acquired IPs are added to a list in ipset and any open connection with that IP is closed (to prevent any interaction with open ports, for example exploitation of web-based vulnerability).
This IP is simultaneously sent through NATS to the central server (https://diswall.stream) and is distributed to all other diswall clients.

You can use the same approach to distribute allowed IPs as a convenient way to control firewalls on your servers.
In contrast to blocklist allowlist is unique for every client, it supports comments and can store whole networks.

Every IP that is added to blocklist is stored for a day, but IPs in allowlist are stored indefinitely. Deletion of IPs is also possible.

When your server is started diswall client currently actual block and allow lists.
This provides protection in accordance with any events that occurred on other servers when any of them was offline.

# ipset

diswall uses two ipset lists - for blocked addresses and allowed ones. Default names are - `diswall-bl` and `diswall-wl` respectively.

Allow list is created by `ipset create -exist diswall-wl hash:net comment` command.
It allows usage of whole networks and adding comments for every record.

Block list is created by `ipset create -exist diswall-bl hash:ip hashsize 32768 maxelem 1000000 timeout 86400` command.
It allows adding only individual IPs and doesn't support comments.

The lifetime of IP in blocklist is 1 day (24 hours). Maximum number of records in blocklist is 1 000 000 (one million), in allowlist - 65 536.

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

The simplest way to install diswall on your server is to use autoinstall functionality in diswall itself.
1. Download binary for your architecture: `wget -O diswall https://github.com/dis-works/diswall-rs/releases/download/v0.1.0/diswall-v0.1.0-x86_64`
2. Make it executable: `chmod +x diswall`
3. Run installation: `./diswall --install`

This will copy the binary to `/usr/bin`, create systemd service, diswall config (`/etc/diswall/diswall.conf`)
and iptables initialization script `/usr/bin/diswall_init.sh`.

Take a look into these files, enter client login and password in first, and add your iptables rules in the second.

# Configuration

Configuration file is located at `/etc/diswall/diswall.conf`. It's format is TOML.
Also, you can use command line arguments listed below.

```text
    -h, --help                Print this help menu
    -v, --version             Print version and exit
        --install             Install DisWall as system service (in client mode)
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
