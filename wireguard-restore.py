#!/usr/bin/env python3
"""Restore trusted WireGuard backups after strict structural validation."""

import fnmatch
import ipaddress
import os
from pathlib import Path, PurePosixPath
import re
import shlex
import shutil
import subprocess
import sys
import tarfile
import tempfile

MAX_BYTES = 256 * 1024 * 1024
MAX_MEMBERS = 10000
PARAM_KEYS = {
    "SERVER_PUB_IP", "SERVER_PUB_NIC", "SERVER_WG_NIC", "SERVER_WG_IPV4",
    "SERVER_WG_IPV6", "SERVER_PORT", "SERVER_PRIV_KEY", "SERVER_PUB_KEY",
    "CLIENT_DNS_1", "CLIENT_DNS_2", "ALLOWED_IPS", "FIREWALL_MODE",
}
SYSCTL_KEYS = {"net.ipv4.ip_forward", "net.ipv6.conf.all.forwarding"}
NIC = re.compile(r"[a-zA-Z0-9_]{1,15}\Z")


def unpack(archive, destination):
    """Never use extractall: accept only regular files and directories."""
    seen = set()
    total = 0
    with tarfile.open(archive, "r:gz") as bundle:
        for count, member in enumerate(bundle, 1):
            if count > MAX_MEMBERS:
                raise ValueError("Archive contains too many entries")
            raw = member.name
            if raw.startswith("/") or "\\" in raw or any(ord(c) < 32 for c in raw):
                raise ValueError("Unsafe archive path")
            parts = raw.split("/")
            if ".." in parts:
                raise ValueError("Parent traversal in archive")
            name = str(PurePosixPath(raw))
            if name in seen:
                raise ValueError("Duplicate archive path")
            seen.add(name)
            if not (member.isdir() or member.isfile()):
                raise ValueError("Links and special files are not supported")
            if member.isdir():
                continue
            if not (name.startswith("etc/wireguard/") or name == "etc/sysctl.d/wg.conf"
                    or fnmatch.fnmatchcase(PurePosixPath(name).name, "*-client-*.conf")):
                raise ValueError("Unexpected file in archive")
            total += member.size
            if member.size < 0 or total > MAX_BYTES:
                raise ValueError("Archive exceeds the 256 MiB limit")
            target = destination / name
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            with bundle.extractfile(member) as source, target.open("xb") as output:
                shutil.copyfileobj(source, output)
            target.chmod(0o600)


def parse_params(path):
    values = {}
    for line in path.read_text().splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        key, separator, raw = line.partition("=")
        if not separator or key not in PARAM_KEYS or key in values:
            raise ValueError("Unsupported or duplicate installer parameter")
        tokens = shlex.split(raw)
        if len(tokens) != 1 or not re.fullmatch(r"[a-zA-Z0-9_.:/,+=\[\]-]+", tokens[0]):
            raise ValueError("Unsafe installer parameter value")
        values[key] = tokens[0]
    if not PARAM_KEYS.difference({"FIREWALL_MODE"}).issubset(values):
        raise ValueError("Missing installer parameters")
    for key in ("SERVER_PUB_NIC", "SERVER_WG_NIC"):
        if not NIC.fullmatch(values[key]):
            raise ValueError("Unsupported interface name")
    if values.get("FIREWALL_MODE", "auto") not in ("auto", "external"):
        raise ValueError("Invalid firewall mode")
    if not values["SERVER_PORT"].isdigit() or not 1 <= int(values["SERVER_PORT"]) <= 65535:
        raise ValueError("Invalid WireGuard port")
    ipaddress.IPv4Address(values["SERVER_WG_IPV4"])
    ipaddress.IPv6Address(values["SERVER_WG_IPV6"])
    for network in values["ALLOWED_IPS"].split(","):
        ipaddress.ip_network(network, strict=False)
    # Write canonical shell-safe assignments for the installer's later source.
    path.write_text("".join(f"{key}={shlex.quote(value)}\n" for key, value in values.items()))
    return values


def inspect(stage):
    wg_dir = stage / "etc/wireguard"
    params = parse_params(wg_dir / "params")
    configs = sorted(wg_dir.glob("*.conf"))
    if not configs or not (wg_dir / (params["SERVER_WG_NIC"] + ".conf")).is_file():
        raise ValueError("No matching server configuration")
    summaries = []
    for config in configs:
        if not NIC.fullmatch(config.stem):
            raise ValueError("Unsupported WireGuard interface name")
        content = config.read_text()
        if "[Interface]" not in content or not re.search(r"(?m)^\s*PrivateKey\s*=", content):
            raise ValueError("Incomplete interface configuration")
        hooks = len(re.findall(r"(?mi)^\s*(?:PreUp|PostUp|PreDown|PostDown)\s*=", content))
        peers = len(re.findall(r"(?m)^\s*\[Peer\]\s*$", content))
        summaries.append((config.stem, peers, hooks))
    sysctl = stage / "etc/sysctl.d/wg.conf"
    if sysctl.exists():
        seen = set()
        for line in sysctl.read_text().splitlines():
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            key, sep, value = line.partition("=")
            key = key.strip()
            if not sep or key not in SYSCTL_KEYS or key in seen or value.strip() not in ("0", "1"):
                raise ValueError("Unsupported sysctl setting")
            seen.add(key)
    return params, summaries


def run(*args, check=True):
    result = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if check and result.returncode:
        # Tool output can contain keys or hook contents. Do not print it.
        raise RuntimeError(f"Command failed: {args[0]} {args[1]} (exit {result.returncode})")
    return result


class Services:
    def __init__(self):
        self.alpine = Path("/etc/alpine-release").exists()

    def active(self, nic):
        if self.alpine:
            return run("rc-service", f"wg-quick.{nic}", "status", check=False).returncode == 0
        result = run("systemctl", "is-active", f"wg-quick@{nic}", check=False)
        if result.returncode not in (0, 3, 4):
            raise RuntimeError("Cannot inspect systemd service state")
        return result.returncode == 0

    def action(self, nic, action):
        if self.alpine:
            run("rc-service", f"wg-quick.{nic}", action)
        else:
            run("systemctl", action, f"wg-quick@{nic}")


def safe_target(path):
    for part in (path, *path.parents):
        if part.is_symlink():
            raise ValueError("Destination contains a symbolic link")
    if path.exists() and not path.is_file():
        raise ValueError("Destination is not a regular file")


def transaction(stage, root, summaries, services, snapshot, command=run):
    """Replace only top-level interface configs, params and the forwarding file."""
    sources = list((stage / "etc/wireguard").glob("*.conf"))
    sources.append(stage / "etc/wireguard/params")
    if (stage / "etc/sysctl.d/wg.conf").exists():
        sources.append(stage / "etc/sysctl.d/wg.conf")
    saved = []
    for source in sources:
        relative = source.relative_to(stage)
        target = root / relative
        safe_target(target)
        previous = snapshot / relative
        existed = target.exists()
        owner = (target.stat().st_uid, target.stat().st_gid) if existed else None
        if existed:
            previous.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(target, previous)
        saved.append((source, target, previous, existed, owner))
    active = {nic: services.active(nic) for nic, _, _ in summaries}
    old_sysctl = {}
    if (stage / "etc/sysctl.d/wg.conf").exists():
        for key in SYSCTL_KEYS:
            value = command("sysctl", "-n", key).stdout.strip()
            if value not in ("0", "1"):
                raise ValueError("Unexpected current forwarding value")
            old_sysctl[key] = value
    stopped = []
    attempted = []
    modified = False
    try:
        for nic, running in active.items():
            if running:
                stopped.append(nic)
                services.action(nic, "stop")
        modified = True
        for source, target, _, _, _ in saved:
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            shutil.copyfile(source, target)
            target.chmod(0o600)
            if hasattr(os, "chown"):
                os.chown(target, os.geteuid(), os.getegid())
        (root / "etc/wireguard").chmod(0o700)
        if old_sysctl:
            command("sysctl", "-p", str(root / "etc/sysctl.d/wg.conf"))
        for nic, _, _ in summaries:
            attempted.append(nic)
            services.action(nic, "start")
            if not services.active(nic):
                raise RuntimeError("Restored interface is not active")
            command("wg", "show", nic)
    except (Exception, KeyboardInterrupt) as error:
        failures = []
        for nic in reversed(attempted):
            try:
                services.action(nic, "stop")
            except Exception:
                failures.append("stop restored interface " + nic)
        if modified:
            for _, target, previous, existed, owner in saved:
                try:
                    if existed:
                        shutil.copy2(previous, target)
                        if hasattr(os, "chown"):
                            os.chown(target, *owner)
                    else:
                        target.unlink(missing_ok=True)
                except Exception:
                    failures.append("restore previous file")
            for key, value in old_sysctl.items():
                try:
                    command("sysctl", "-w", f"{key}={value}")
                except Exception:
                    failures.append("restore forwarding")
        for nic in stopped:
            try:
                if not services.active(nic):
                    services.action(nic, "start")
            except Exception:
                failures.append("restart previous interface " + nic)
        message = "Restore failed; previous files and service states were restored."
        if failures:
            message = "Restore failed; rollback needs manual attention: " + ", ".join(failures)
        raise RuntimeError(message + " Firewall hook side effects require inspection.") from error


def main():
    if sys.version_info < (3, 8):
        raise ValueError("Python 3.8 or later is required")
    if len(sys.argv) != 2:
        raise ValueError("Usage: python3 wireguard-restore.py ARCHIVE.tar.gz")
    if os.geteuid() != 0:
        raise ValueError("Run as root")
    os.umask(0o077)
    for tool in ("wg", "wg-quick", "ip", "sysctl", "bash"):
        if not shutil.which(tool):
            raise ValueError(f"Install {tool} before restoring")
    helper = Path(__file__).resolve().with_name("wireguard-backup.sh")
    if not helper.is_file():
        raise ValueError("Keep wireguard-backup.sh next to this script")
    with tempfile.TemporaryDirectory(prefix="wg-restore-") as work:
        stage = Path(work) / "archive"
        stage.mkdir(mode=0o700)
        unpack(sys.argv[1], stage)
        params, summaries = inspect(stage)
        run("ip", "link", "show", "dev", params["SERVER_PUB_NIC"])
        services = Services()
        for nic, peers, hooks in summaries:
            run("wg-quick", "strip", str(stage / "etc/wireguard" / (nic + ".conf")))
            if services.alpine and not Path(f"/etc/init.d/wg-quick.{nic}").exists():
                raise ValueError(f"Prepare the OpenRC service wg-quick.{nic} before restoring")
            if not services.active(nic) and run("ip", "link", "show", "dev", nic, check=False).returncode == 0:
                raise ValueError(f"Interface {nic} exists outside the managed service; stop it manually first")
            print(f"Interface {nic}: {peers} peers, {hooks} shell hooks; configuration will be replaced.")
        extras = [p for p in stage.rglob("*") if p.is_file() and not (
            p.parent == stage / "etc/wireguard" and (p.suffix == ".conf" or p.name == "params")
            or p == stage / "etc/sysctl.d/wg.conf")]
        print(f"Additional files (including client configs): {len(extras)}; recovered separately, not overwritten.")
        print("Old backups may re-enable revoked clients. Archived hooks execute as root on start/stop.")
        print("Use a trusted archive and SSH independent of this VPN. Prepare your nftables rules first.")
        print("Autostart settings are unchanged. Public IP/Endpoint and external network settings are not updated.")
        if input("Type RESTORE to replace the listed configurations and restart these interfaces: ") != "RESTORE":
            print("Restore cancelled.")
            return
        backup_dir = Path("/root/wireguard-backups")
        if Path("/etc/wireguard").exists():
            result = run("bash", str(helper), str(backup_dir))
            print(result.stdout.strip())
        # Keep a durable transaction snapshot even if rollback itself fails.
        backup_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        recovery = Path(tempfile.mkdtemp(prefix="restore-recovery-", dir=backup_dir))
        print(f"Recovery files: {recovery}")
        for source in extras:
            target = recovery / "recovered-files" / source.relative_to(stage)
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            shutil.copyfile(source, target)
            target.chmod(0o600)
        transaction(stage, Path("/"), summaries, services, recovery / "previous-files")
        print("Interfaces started. Check client handshake, DNS, IPv4 and IPv6 connectivity.")
        print("On a new server enable autostart for each restored interface after verification.")


if __name__ == "__main__":
    try:
        main()
    except (Exception, KeyboardInterrupt) as exc:
        # Do not display archive contents or tool stderr (may contain keys).
        if isinstance(exc, (ValueError, RuntimeError)):
            print(str(exc), file=sys.stderr)
        else:
            print(f"Restore aborted ({type(exc).__name__}); inspect configuration and recovery files.", file=sys.stderr)
        sys.exit(1)
