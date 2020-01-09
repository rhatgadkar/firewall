import unittest

from firewall import Firewall
from firewall_rule import FirewallRule


class TestFirewall(unittest.TestCase):
    def test_no_add_duplicate_rules(self):
        """Verify that duplicate rules cannot be added."""
        fw = Firewall()
        fw.add_fw_rule(
            FirewallRule(
                direction="inbound", protocol="tcp", port="80",
                ip_address="192.168.1.2"
            )
        )
        bucket_num = 80 // fw.num_ports_bucket
        self.assertEqual(len(fw.fw_rules["inbound"]["tcp"][bucket_num]), 1)
        fw.add_fw_rule(
            FirewallRule(
                direction="inbound", protocol="tcp", port="80",
                ip_address="192.168.1.2"
            )
        )
        self.assertEqual(len(fw.fw_rules["inbound"]["tcp"][bucket_num]), 1)

    def test_no_add_duplicate_range_port_rules(self):
        """Verify that duplicate range port rules cannot be added."""
        fw = Firewall()
        fw.add_fw_rule(
            FirewallRule(
                direction="inbound", protocol="tcp", port="50-2000",
                ip_address="192.168.1.2"
            )
        )
        start_bucket = 50 // fw.num_ports_bucket
        end_bucket = 2000 // fw.num_ports_bucket
        for bucket_num in range(start_bucket, end_bucket + 1):
            self.assertEqual(len(fw.fw_rules["inbound"]["tcp"][bucket_num]), 1)
        fw.add_fw_rule(
            FirewallRule(
                direction="inbound", protocol="tcp", port="50-2000",
                ip_address="192.168.1.2"
            )
        )
        for bucket_num in range(start_bucket, end_bucket + 1):
            self.assertEqual(len(fw.fw_rules["inbound"]["tcp"][bucket_num]), 1)

    def test_no_add_duplicate_ipaddr_rules(self):
        """Verify that duplicate range IP address rules cannot be added."""
        fw = Firewall()
        fw.add_fw_rule(
            FirewallRule(
                direction="inbound", protocol="tcp", port="80",
                ip_address="192.168.1.2-192.168.2.2"
            )
        )
        bucket_num = 80 // fw.num_ports_bucket
        self.assertEqual(len(fw.fw_rules["inbound"]["tcp"][bucket_num]), 1)
        fw.add_fw_rule(
            FirewallRule(
                direction="inbound", protocol="tcp", port="80",
                ip_address="192.168.1.2-192.168.2.2"
            )
        )
        self.assertEqual(len(fw.fw_rules["inbound"]["tcp"][bucket_num]), 1)

    def test_firewall_allow_packet(self):
        """Verify firewall allows a packet that matches a rule."""
        fw = Firewall()
        fw.add_fw_rule(
            FirewallRule(
                direction="inbound", protocol="tcp", port="80",
                ip_address="192.168.1.2"
            )
        )
        self.assertTrue(
            fw.accept_packet(
                direction="inbound", protocol="tcp", port=80,
                ip_address="192.168.1.2"
            )
        )

    def test_firewall_block_packet(self):
        """Verify firewall blocks a packet that doesn't match a rule."""
        fw = Firewall()
        fw.add_fw_rule(
            FirewallRule(
                direction="inbound", protocol="tcp", port="80",
                ip_address="192.168.1.2"
            )
        )
        self.assertFalse(
            fw.accept_packet(
                direction="outbound", protocol="tcp", port=80,
                ip_address="192.168.1.2"
            )
        )
        self.assertFalse(
            fw.accept_packet(
                direction="inbound", protocol="udp", port=80,
                ip_address="192.168.1.2"
            )
        )
        self.assertFalse(
            fw.accept_packet(
                direction="inbound", protocol="udp", port=81,
                ip_address="192.168.1.2"
            )
        )
        self.assertFalse(
            fw.accept_packet(
                direction="outbound", protocol="tcp", port=80,
                ip_address="192.168.1.3"
            )
        )

    def test_firewall_allow_range_port_packet(self):
        """
        Verify firewall allows a packet that matches a rule with ranged port
        numbers.
        """
        fw = Firewall()
        fw.add_fw_rule(
            FirewallRule(
                direction="inbound", protocol="tcp", port="1-65535",
                ip_address="192.168.1.2"
            )
        )
        self.assertTrue(
            fw.accept_packet(
                direction="inbound", protocol="tcp", port=1,
                ip_address="192.168.1.2"
            )
        )
        self.assertTrue(
            fw.accept_packet(
                direction="inbound", protocol="tcp", port=65535,
                ip_address="192.168.1.2"
            )
        )
        self.assertTrue(
            fw.accept_packet(
                direction="inbound", protocol="tcp", port=30000,
                ip_address="192.168.1.2"
            )
        )

    def test_firewall_block_range_port_packet(self):
        """
        Verify firewall blocks a packet that doesn't match a rule with ranged
        port numbers.
        """
        fw = Firewall()
        fw.add_fw_rule(
            FirewallRule(
                direction="inbound", protocol="tcp", port="80-90",
                ip_address="192.168.1.2"
            )
        )
        self.assertFalse(
            fw.accept_packet(
                direction="inbound", protocol="tcp", port=79,
                ip_address="192.168.1.2"
            )
        )
        self.assertFalse(
            fw.accept_packet(
                direction="inbound", protocol="tcp", port=91,
                ip_address="192.168.1.2"
            )
        )

    def test_firewall_allow_range_ipaddr_packet(self):
        """
        Verify firewall allows a packet that matches a rule with ranged IP
        addresses.
        """
        fw = Firewall()
        fw.add_fw_rule(
            FirewallRule(
                direction="inbound", protocol="tcp", port="80",
                ip_address="0.0.0.0-255.255.255.255"
            )
        )
        self.assertTrue(
            fw.accept_packet(
                direction="inbound", protocol="tcp", port=80,
                ip_address="0.0.0.0"
            )
        )
        self.assertTrue(
            fw.accept_packet(
                direction="inbound", protocol="tcp", port=80,
                ip_address="255.255.255.255"
            )
        )
        self.assertTrue(
            fw.accept_packet(
                direction="inbound", protocol="tcp", port=80,
                ip_address="192.168.1.2"
            )
        )

    def test_firewall_block_range_ipaddr_packet(self):
        """
        Verify firewall blocks a packet that doesn't match a rule with ranged
        IP addresses.
        """
        fw = Firewall()
        fw.add_fw_rule(
            FirewallRule(
                direction="inbound", protocol="tcp", port="80",
                ip_address="192.168.1.2-192.168.2.1"
            )
        )
        self.assertFalse(
            fw.accept_packet(
                direction="inbound", protocol="tcp", port=80,
                ip_address="192.168.1.1"
            )
        )
        self.assertFalse(
            fw.accept_packet(
                direction="inbound", protocol="tcp", port=91,
                ip_address="192.168.2.2"
            )
        )


if __name__ == "__main__":
    unittest.main()
