import csv
import time
from typing import Optional

from firewall_rule import FirewallRule
from ip_address import IPAddress


class Firewall(object):
    """
    A data structure to represent a firewall. A firewall contains a list of
    firewall rules.

    The data structure is a hash-set of firewall rules. The hash-set prevents
    duplicate firewall rules from being added.
    """

    def __init__(self, csv_file_path: Optional[str] = None):
        """
        Initialize the firewall by reading and storing the firewall rules of
        the CSV file.
        """
        self.fw_rules = set()
        if csv_file_path:
            with open(csv_file_path, "r") as csv_file:
                csv_reader = csv.reader(csv_file)
                for csv_fw_rule in csv_reader:
                    self.add_fw_rule(FirewallRule(*csv_fw_rule))

    def add_fw_rule(self, fw_rule: FirewallRule) -> None:
        """Add the provided firewall rule to the data structure."""
        self.fw_rules.add(fw_rule)

    def accept_packet(
        self, direction: str, protocol: str, port: int, ip_address: str
    ) -> bool:
        """
        Determine whether the firewall can accept the packet with its rules.
        """
        for fw_rule in self.fw_rules:
            if fw_rule.is_match(direction, protocol, port, ip_address):
                return True
        return False


if __name__ == "__main__":
    start_time = time.time()
    fw = Firewall("500k_rules.csv")
    end_time = time.time()
    duration = end_time - start_time
    print(f"Naive firewall time duration to add rules: {duration}")

    start_time = time.time()
    print(fw.accept_packet("inbound", "tcp", 80, "192.168.1.2"))
    print(fw.accept_packet("inbound", "udp", 53, "192.168.2.1"))
    print(fw.accept_packet("inbound", "udp", 53, "192.168.2.1"))
    print(fw.accept_packet("inbound", "tcp", 81, "192.168.1.2"))
    print(fw.accept_packet("inbound", "udp", 24, "52.12.48.92"))
    end_time = time.time()
    duration = end_time - start_time
    print(f"Naive firewall time duration to accept packets: {duration}")
