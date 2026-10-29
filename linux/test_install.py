import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('native_installer', Path(__file__).with_name('install.py'))
app = importlib.util.module_from_spec(spec)
spec.loader.exec_module(app)


class NativeTests(unittest.TestCase):
    def test_resolv_restore_replaces_symlink_not_target(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d); original=p/'resolv.conf';target=p/'stub'
            original.write_text('nameserver 10.0.0.1\n')
            saved=app.snapshot_file(original)
            original.unlink();target.write_text('nameserver 127.0.0.53\n');original.symlink_to(target)
            with patch.object(app,'RES',original):app.replace_resolv(saved)
            self.assertFalse(original.is_symlink())
            self.assertEqual(original.read_text(),'nameserver 10.0.0.1\n')
            self.assertEqual(target.read_text(),'nameserver 127.0.0.53\n')

    def test_restore_original_symlink(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d);target=p/'original';target.write_text('DNS')
            link=p/'resolv.conf';link.symlink_to(target)
            saved=app.snapshot_file(link);link.unlink();link.write_text('new')
            with patch.object(app,'RES',link):app.replace_resolv(saved)
            self.assertTrue(link.is_symlink());self.assertEqual(link.readlink(),target)

    def test_profile_read_disables_nmcli_escaping(self):
        calls=[]
        with patch.object(app,'run',side_effect=lambda *args: calls.append(args) or ''):
            app.profile('test')
        self.assertTrue(all(args[1:3]==('--escape','no') for args in calls))

    def test_dns_rcode_failure_is_not_success(self):
        q=app.query('example.org')
        fail=q[:2]+bytes.fromhex('81820001000000000000')+q[12:]
        with self.assertRaises(RuntimeError):app.verify_answer(q,fail)

    def test_dhcp_dns_parser_keeps_safe_unique_ipv4(self):
        output = ('DHCP4.OPTION[1]: domain_name_servers = 192.168.1.254 10.0.0.7 192.168.1.254\n'
                  'DHCP4.OPTION[2]: routers = 192.168.1.254\n')
        with patch.object(app,'run',return_value=output):
            self.assertEqual(app.dhcp_dns('enp3s0'), ['192.168.1.254','10.0.0.7'])

    def test_split_service_is_unprivileged_and_local(self):
        unit = app.split_unit()
        self.assertIn('127.0.0.1', Path(app.__file__).read_text())
        self.assertIn('NoNewPrivileges=yes', unit)
        self.assertIn('RestrictAddressFamilies=AF_INET AF_UNIX', unit)
        self.assertIn('/var/lib/privetdns-native/splitdns.json', unit)

if __name__=='__main__':unittest.main()
