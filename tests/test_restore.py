import importlib.util
import io
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest

spec = importlib.util.spec_from_file_location(
    "restore", Path(__file__).resolve().parents[1] / "wireguard-restore.py")
restore = importlib.util.module_from_spec(spec)
spec.loader.exec_module(restore)

PARAMS = """SERVER_PUB_IP=192.0.2.1
SERVER_PUB_NIC=ens3
SERVER_WG_NIC=wg0
SERVER_WG_IPV4=10.66.66.1
SERVER_WG_IPV6=fd42:42:42::1
SERVER_PORT=51820
SERVER_PRIV_KEY=example=
SERVER_PUB_KEY=example=
CLIENT_DNS_1=1.1.1.1
CLIENT_DNS_2=1.0.0.1
ALLOWED_IPS=0.0.0.0/0,::/0
FIREWALL_MODE=external
"""


class RestoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.stage = self.base / "stage"
        self.stage.mkdir()

    def archive(self, entries):
        path = self.base / "backup.tar.gz"
        with tarfile.open(path, "w:gz") as output:
            for name, kind, data in entries:
                member = tarfile.TarInfo(name)
                member.type = kind
                member.linkname = "/etc/passwd" if kind == tarfile.SYMTYPE else ""
                member.size = len(data) if kind == tarfile.REGTYPE else 0
                output.addfile(member, io.BytesIO(data) if member.size else None)
        return path

    def fixture(self):
        wg = self.stage / "etc/wireguard"
        wg.mkdir(parents=True)
        (wg / "params").write_text(PARAMS)
        (wg / "wg0.conf").write_text("[Interface]\nPrivateKey = example=\n[Peer]\n")
        return wg

    def test_archive_round_trip_with_spaces(self):
        data = b"private client config"
        path = self.archive([("./home/a user/wg0-client-phone.conf", tarfile.REGTYPE, data)])
        restore.unpack(path, self.stage)
        self.assertEqual((self.stage / "home/a user/wg0-client-phone.conf").read_bytes(), data)

    def test_reject_unsafe_archive_entries(self):
        for name, kind in [("../etc/wireguard/params", tarfile.REGTYPE),
                           ("/etc/wireguard/params", tarfile.REGTYPE),
                           ("etc/wireguard/link", tarfile.SYMTYPE),
                           ("etc/wireguard/hard", tarfile.LNKTYPE),
                           ("etc/wireguard/fifo", tarfile.FIFOTYPE),
                           ("etc/passwd", tarfile.REGTYPE)]:
            with self.subTest(name=name):
                path = self.archive([(name, kind, b"data")])
                with self.assertRaises(ValueError):
                    restore.unpack(path, self.stage)

    def test_duplicate_and_size_limit(self):
        entry = ("etc/wireguard/params", tarfile.REGTYPE, b"data")
        with self.assertRaises(ValueError):
            restore.unpack(self.archive([entry, entry]), self.stage)
        old_limit = restore.MAX_BYTES
        restore.MAX_BYTES = 1
        try:
            with self.assertRaises(ValueError):
                restore.unpack(self.archive([entry]), self.base / "other")
        finally:
            restore.MAX_BYTES = old_limit

    def test_params_are_not_shell_code(self):
        wg = self.fixture()
        for suffix in ["UNKNOWN=value\n", "SERVER_PORT=22\n"]:
            (wg / "params").write_text(PARAMS + suffix)
            with self.assertRaises(ValueError):
                restore.inspect(self.stage)
        (wg / "params").write_text(PARAMS.replace("192.0.2.1", "$(touch /tmp/unsafe)"))
        with self.assertRaises(ValueError):
            restore.inspect(self.stage)

    def test_legacy_params_and_hook_preview(self):
        wg = self.fixture()
        (wg / "params").write_text(PARAMS.replace("FIREWALL_MODE=external\n", ""))
        with (wg / "wg0.conf").open("a") as output:
            output.write("PostUp = true\n")
        _, summaries = restore.inspect(self.stage)
        self.assertEqual(summaries, [("wg0", 1, 1)])

    def test_reject_unrelated_sysctl(self):
        self.fixture()
        sysctl = self.stage / "etc/sysctl.d/wg.conf"
        sysctl.parent.mkdir()
        sysctl.write_text("kernel.randomize_va_space = 0\n")
        with self.assertRaises(ValueError):
            restore.inspect(self.stage)

    def test_transaction_success_and_rollback(self):
        self.fixture()
        sysctl = self.stage / "etc/sysctl.d/wg.conf"
        sysctl.parent.mkdir()
        sysctl.write_text("net.ipv4.ip_forward = 1\n")
        for fail in (False, True):
            with self.subTest(fail=fail):
                root = self.base / str(fail)
                config = root / "etc/wireguard/wg0.conf"
                config.parent.mkdir(parents=True)
                config.write_text("OLD")
                unrelated = config.with_name("other.conf")
                unrelated.write_text("KEEP")

                class FakeServices:
                    running = True
                    first_start = True

                    def active(self, nic):
                        return self.running

                    def action(self, nic, action):
                        if action == "start" and fail and self.first_start:
                            self.first_start = False
                            raise RuntimeError("simulated start failure")
                        self.running = action == "start"

                calls = []

                def command(*args):
                    calls.append(args)
                    return subprocess.CompletedProcess(args, 0, stdout="0\n")

                services = FakeServices()
                arguments = (self.stage, root, [("wg0", 1, 0)], services,
                             self.base / ("snapshot" + str(fail)), command)
                if fail:
                    with self.assertRaises(RuntimeError):
                        restore.transaction(*arguments)
                    self.assertEqual(config.read_text(), "OLD")
                    self.assertFalse(config.with_name("params").exists())
                    self.assertFalse((root / "etc/sysctl.d/wg.conf").exists())
                    self.assertIn(("sysctl", "-w", "net.ipv4.ip_forward=0"), calls)
                else:
                    restore.transaction(*arguments)
                    self.assertIn("[Interface]", config.read_text())
                self.assertTrue(services.running)
                self.assertEqual(unrelated.read_text(), "KEEP")

    def test_destination_directory_rejected_before_service_changes(self):
        self.fixture()
        root = self.base / "root"
        (root / "etc/wireguard/wg0.conf").mkdir(parents=True)
        with self.assertRaises(ValueError):
            restore.transaction(self.stage, root, [("wg0", 1, 0)], None, self.base / "snapshot")

    def test_stop_failure_does_not_replace_files(self):
        self.fixture()
        root = self.base / "root"
        config = root / "etc/wireguard/wg0.conf"
        config.parent.mkdir(parents=True)
        config.write_text("ORIGINAL")

        class CannotStop:
            def active(self, nic):
                return True

            def action(self, nic, action):
                raise RuntimeError("stop failed")

        with self.assertRaises(RuntimeError):
            restore.transaction(self.stage, root, [("wg0", 1, 0)], CannotStop(), self.base / "snapshot")
        self.assertEqual(config.read_text(), "ORIGINAL")

    def test_failed_rollback_is_reported(self):
        self.fixture()
        root = self.base / "root"
        root.mkdir()

        class BrokenService:
            def active(self, nic):
                return False

            def action(self, nic, action):
                raise RuntimeError("service failed")

        with self.assertRaisesRegex(RuntimeError, "manual attention"):
            restore.transaction(self.stage, root, [("wg0", 1, 0)], BrokenService(), self.base / "snapshot")
        self.assertFalse((root / "etc/wireguard/wg0.conf").exists())


if __name__ == "__main__":
    unittest.main()
