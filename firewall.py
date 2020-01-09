import csv
import time
from typing import Optional

from firewall_rule import FirewallRule
from ip_address import IPAddress


class Firewall(object):
    """
    A data structure to represent a firewall. A firewall contains a list of
    firewall rules.

    The data structure to store the firewall rules is organized based on
    direction, protocol, and port values.

    There are four possible combinations of direction and protocol values:
    Combination 1: direction="inbound", protocol="tcp"
    Combination 2: direction="inbound", protocol="udp"
    Combination 3: direction="outbound", protocol="tcp"
    Combination 4: direction="outbound", protocol="udp"

    Each combination contains a list of 64 buckets. Each bucket is
    responsible for storing references to unique firewall rules that fall
    within a range of 1024 port values. For example, bucket 0 stores firewall
    rules for port values between 0-1023, bucket 1 stores firewall rules for
    port values between 1024-2047, and bucket 63 stores firewall rules for port
    values between 64512-65535.

    Duplicate references to the same firewall rule are prevented from being
    added to the same bucket, because the bucket is a hash-set data structure.

    It is possible for a firewall rule, which has a range of port values, to
    have references that belong to multiple buckets. For example, references to
    a firewall rule with fields:
    (direction="inbound", protocol="tcp", port="50-2000", IP address="1.1.1.1")
    would belong to Combination 1's bucket 0 and bucket 1.
    """

    def __init__(self, csv_file_path: Optional[str] = None):
        """
        Initialize the firewall by reading and storing the firewall rules of
        the CSV file.
        """
        # initialize the data structure to store firewall rules
        num_buckets = 64
        self.num_ports_bucket = 65536 // num_buckets
        self.fw_rules = {
            "inbound": {
                "tcp": [set() for i in range(num_buckets)],
                "udp": [set() for i in range(num_buckets)],
            },
            "outbound": {
                "tcp": [set() for i in range(num_buckets)],
                "udp": [set() for i in range(num_buckets)],
            },
        }

        # read firewall rules from CSV file and add them to the data structure
        if csv_file_path:
            with open(csv_file_path, "r") as csv_file:
                csv_reader = csv.reader(csv_file)
                for csv_fw_rule in csv_reader:
                    fw_rule = FirewallRule(*csv_fw_rule)
                    self.add_fw_rule(fw_rule)

    def add_fw_rule(self, fw_rule: FirewallRule) -> None:
        """Add the provided firewall rule to the data structure."""
        start_bucket = fw_rule.min_port // self.num_ports_bucket
        end_bucket = fw_rule.max_port // self.num_ports_bucket
        curr_fw_rules = self.fw_rules[fw_rule.direction][fw_rule.protocol]
        for bucket_num in range(start_bucket, end_bucket + 1):
            curr_fw_rules[bucket_num].add(fw_rule)

    def accept_packet(
        self, direction: str, protocol: str, port: int, ip_address: str
    ) -> bool:
        """
        Determine whether the firewall can accept the packet with its rules.
        """
        bucket_num = port // self.num_ports_bucket
        for fw_rule in self.fw_rules[direction][protocol][bucket_num]:
            if fw_rule.is_match(direction, protocol, port, ip_address):
                return True
        return False


if __name__ == "__main__":
    start_time = time.time()
    fw = Firewall("500k_rules.csv")
    end_time = time.time()
    duration = end_time - start_time
    print(f"Firewall time duration to add rules: {duration}")

    start_time = time.time()
    print(fw.accept_packet("inbound", "tcp", 80, "192.168.1.2"))
    print(fw.accept_packet("inbound", "udp", 53, "192.168.2.1"))
    print(fw.accept_packet("inbound", "udp", 53, "192.168.2.1"))
    print(fw.accept_packet("inbound", "tcp", 81, "192.168.1.2"))
    print(fw.accept_packet("inbound", "udp", 24, "52.12.48.92"))
    end_time = time.time()
    duration = end_time - start_time
    print(f"Firewall time duration to accept packets: {duration}")
