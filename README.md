# WireGuard installer

![Lint](https://github.com/angristan/wireguard-install/workflows/Lint/badge.svg)
[![Say Thanks!](https://img.shields.io/badge/Say%20Thanks-!-1EAEDB.svg)](https://saythanks.io/to/angristan)

**This project is a bash script that aims to setup a [WireGuard](https://www.wireguard.com/) VPN on a Linux server, as easily as possible!**

WireGuard is a point-to-point VPN that can be used in different ways. Here, we mean a VPN as in: the client will forward all its traffic through an encrypted tunnel to the server.
The server will apply NAT to the client's traffic so it will appear as if the client is browsing the web with the server's IP.

The script supports both IPv4 and IPv6. Please check the [issues](https://github.com/angristan/wireguard-install/issues) for ongoing development, bugs and planned features! You might also want to check the [discussions](https://github.com/angristan/wireguard-install/discussions) for help.

WireGuard does not fit your environment? Check out [openvpn-install](https://github.com/angristan/openvpn-install).

## Requirements

Supported distributions:

- AlmaLinux >= 8
- Alpine Linux
- Arch Linux
- CentOS Stream >= 8
- Debian >= 10
- Fedora >= 32
- Oracle Linux
- Rocky Linux >= 8
- Ubuntu >= 18.04

## Usage

Download and execute the script. Answer the questions asked by the script and it will take care of the rest.

```bash
curl -O https://raw.githubusercontent.com/rmtshnik/wireguard-install/master/wireguard-install.sh
chmod +x wireguard-install.sh
./wireguard-install.sh
```

It will install WireGuard (kernel module and tools) on the server, configure it, create a systemd service and a client configuration file.

Run the script again to add or remove clients!

## Firewall management

During installation, choose a firewall mode:

- `auto` (default): preserve the original firewalld/iptables setup using `PostUp` and `PostDown` hooks.
- `external`: manage the firewall yourself, for example with nftables. The installer does not add firewall hooks or explicitly install iptables. It still enables IPv4 and IPv6 forwarding through `/etc/sysctl.d/wg.conf`.

The mode is saved in `/etc/wireguard/params`. This choice applies to new installations; changing that file alone does not remove hooks from an existing configuration. Adding or revoking clients does not change firewall rules. Uninstalling an external-mode installation leaves your firewall rules in place.

### Example with an existing nftables firewall

For `wg0`, public interface `ens3`, and subnet `10.7.0.0/24`, choose server WireGuard IPv4 `10.7.0.1` during setup. The installer otherwise defaults to `10.66.66.1`. Choose `external` and allow the selected WireGuard UDP port in your existing input chain (the installer suggests a random port):

```nft
# Example only: use the actual ListenPort from wg0.conf.
# Add to your existing input chain before any matching drop rule:
iifname "ens3" udp dport 51820 accept

# Add to your existing forward chain before any matching drop rule:
iifname "wg0" oifname "ens3" ip saddr 10.7.0.0/24 accept
iifname "ens3" oifname "wg0" ip daddr 10.7.0.0/24 ct state established,related accept
```

Keep your existing masquerade rule in the IPv4 NAT postrouting chain:

```nft
table ip nat {
    chain postrouting {
        type nat hook postrouting priority srcnat; policy accept;
        ip saddr 10.7.0.0/24 oifname "ens3" masquerade
    }
}
```

Merge these rules into your existing persistent ruleset; do not replace or flush it. This example covers IPv4. The installer also configures IPv6 and defaults client AllowedIPs to `0.0.0.0/0,::/0`: provide IPv6 forwarding and routing/NAT rules if you want IPv6 over the VPN. For IPv4-only routing, enter `0.0.0.0/0` at the AllowedIPs prompt; client IPv6 traffic will then remain outside the VPN.

### Migrating an existing installation

Perform the following with access to the server independent of the VPN, since stopping the interface disconnects VPN clients:

1. Back up `/etc/wireguard` securely (it contains private keys) and ensure your persistent nftables rules cover the VPN subnet, UDP port, forwarding and required NAT.
2. Stop WireGuard **before editing its hooks**, so the original `PostDown` commands can remove the rules added by `PostUp`: `systemctl stop wg-quick@wg0` (Alpine: `rc-service wg-quick.wg0 stop`). Substitute your interface name if different.
3. Inspect the active firewall rules and stop output. If old rules remain, remove only the installer-created rules using the corresponding firewall tool; never flush your ruleset.
4. Remove only the installer-generated firewall `PostUp`/`PostDown` lines from `/etc/wireguard/wg0.conf`. Keep any unrelated custom hooks and all interface/peer settings.
5. Set `FIREWALL_MODE=external` in `/etc/wireguard/params` (add it if missing).
6. Start WireGuard: `systemctl start wg-quick@wg0` (Alpine: `rc-service wg-quick.wg0 start`). Verify a client handshake and connectivity.

Existing installations are not migrated automatically.

## Providers

I recommend these cheap cloud providers for your VPN server:

- [Vultr](https://www.vultr.com/?ref=8948982-8H): Worldwide locations, IPv6 support, starting at \$5/month
- [Hetzner](https://hetzner.cloud/?ref=ywtlvZsjgeDq): Germany, Finland and USA. IPv6, 20 TB of traffic, starting at 4.5€/month
- [Digital Ocean](https://m.do.co/c/ed0ba143fe53): Worldwide locations, IPv6 support, starting at \$4/month

## Contributing

Contributions are welcome! Here's how you can help:

### Discuss changes

Please open an issue before submitting a PR if you want to discuss a change, especially if it's a big one.

### Code formatting

We use [shellcheck](https://github.com/koalaman/shellcheck) and [shfmt](https://github.com/mvdan/sh) to enforce bash styling guidelines and good practices. They are executed for each commit / PR with GitHub Actions, so you can check the configuration [here](https://github.com/angristan/wireguard-install/blob/master/.github/workflows/lint.yml).

## Say thanks

You can [say thanks](https://saythanks.io/to/angristan) if you want!

## Credits & Licence

This project is under the [MIT Licence](https://raw.githubusercontent.com/angristan/wireguard-install/master/LICENSE)

## Star History

[![Star History Chart](https://api.star-history.com/svg?repos=angristan/wireguard-install&type=Date)](https://star-history.com/#angristan/wireguard-install&Date)
