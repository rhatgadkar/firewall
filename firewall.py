import csv


class IPAddress:
    """Defines an `IPAddress` type."""
    pass


class IPAddress(object):
    """
    A data structure to represent an IP address.

    An IP address contains four octets separated by "."s. Each octet has a
    value between 0-255.

    This data structure stores each IP address as a tuple. Each element of the
    tuple is an octet. For example, IP address 192.168.56.1 is represented as:
    (192, 168, 56, 1).
    """
    
    def __init__(self, ip_address: str):
        """Constructs the tuple to represent the provided IP address."""
        self.octets = tuple([int(octet) for octet in ip_address.split(".")])

    def __lt__(self, other: IPAddress):
        """Implements the "<" operator to compare `IPAddress` objects."""
        for i in range(4):
            if self.octets[i] < other.octets[i]:
                return True
            if self.octets[i] > other.octets[i]:
                return False
        return False

    def __gt__(self, other: IPAddress):
        """Implements the ">" operator to compare `IPAddress` objects."""
        for i in range(4):
            if self.octets[i] > other.octets[i]:
                return True
            if self.octets[i] < other.octets[i]:
                return False
        return False

    def __hash__(self):
        """Returns the hash value of the current `IPAddress` object."""
        return hash(self.octets)


class FirewallRule(object):
    """
    A data structure to represent a firewall rule.

    A firewall rule consists of four fields:
    1. direction: can either be "inbound" or "outbound".
    2. protocol: can either be "tcp" or "udp".
    3. port: can either be a single value (i.e. "192") or a range of values
             (i.e. "192-202"). A single port value can have a value between
             1-65535.
    4. IP address: can either be a single value (i.e. "192.168.56.1") or a
                   range of values (i.e. "192.168.56.1-192.56.100").

    This data structure represents each of the four fields in this way:
    1. direction: a string variable.
    2. protocol: a string variable.
    3. port: there are two integer variables - a min port value and a max port
             value. When the port is a single value, the min port and max port
             values are set to the provided port's value. When the port is a
             range value, the min port value is set to the minimum value in the
             range, and the max port value is set to the maximum value in the
             range.
    4. IP address: there are two `IPAddress` variables - a min IP address value
                   and a max IP address value. The min and max IP address
                   values are initialized similarly to how the min and max port
                   values are initialized.
    """

    def __init__(
        self, direction: str, protocol: str, port: str, ip_address: str
    ):
        """Constructs a firewall rule given the provided four fields."""
        self.direction = direction
        self.protocol = protocol
        ports = port.split("-")
        if len(ports) == 1:
            self.min_port = int(ports[0])
            self.max_port = int(ports[0])
        else:
            self.min_port = int(ports[0])
            self.max_port = int(ports[1])
        ip_addresses = ip_address.split("-")
        if len(ip_addresses) == 1:
            self.min_ip = IPAddress(ip_addresses[0])
            self.max_ip = IPAddress(ip_addresses[0])
        else:
            self.min_ip = IPAddress(ip_addresses[0])
            self.max_ip = IPAddress(ip_addresses[1])

    def is_match(
        self, direction: str, protocol: str, port: int, ip_address: str
    ) -> bool:
        """
        Determines whether the provided four fields match the current
        `FirewallRule` object's four fields.
        """
        if self.direction != direction:
            return False
        if self.protocol != protocol:
            return False
        if port < self.min_port or port > self.max_port:
            return False
        ip = IPAddress(ip_address)
        if ip < self.min_ip or ip > self.max_ip:
            return False
        return True

    def __hash__(self):
        """Returns the hash value of the current `FirewallRule` object."""
        return hash((
            self.direction, self.protocol, self.min_port, self.max_port,
            self.min_ip, self.max_ip
        ))


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

    Each combination contains a list of 1024 buckets. Each bucket is
    responsible for storing references to unique firewall rules that fall
    within a range of 64 port values. For example, bucket 0 stores firewall
    rules for port values between 0-63, bucket 1 stores firewall rules for port
    values between 64-127, and bucket 1023 stores firewall rules for port
    values between 65472-65535.

    Duplicate references to the same firewall rule are prevented from being
    added to the same bucket, because the bucket is a hash-set data structure.

    It is possible for a firewall rule, which has a range of port values, to
    have references that belong to multiple buckets. For example, references to
    a firewall rule with fields:
    (direction="inbound", protocol="tcp", port="50-100", IP address="1.1.1.1")
    would belong to Combination 1's bucket 0 and bucket 1.
    """

    def __init__(self, csv_file_path: str):
        """Read and store the firewall rules from the CSV file."""
        # initialize the data structure to store firewall rules
        num_buckets = 1024
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
        with open(csv_file_path, "r") as csv_file:
            csv_reader = csv.reader(csv_file)
            for csv_fw_rule in csv_reader:
                fw_rule = FirewallRule(*csv_fw_rule)
                fw_rules = self.fw_rules[fw_rule.direction][fw_rule.protocol]
                start_bucket = fw_rule.min_port // self.num_ports_bucket
                end_bucket = fw_rule.max_port // self.num_ports_bucket
                for bucket_num in range(start_bucket, end_bucket + 1):
                    fw_rules[bucket_num].add(fw_rule)

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
    fw = Firewall("sample_rules.csv")
    assert fw.accept_packet("inbound", "tcp", 80, "192.168.1.2")
    assert fw.accept_packet("inbound", "udp", 53, "192.168.2.1")
    assert fw.accept_packet("inbound", "udp", 53, "192.168.2.1")
    assert not fw.accept_packet("inbound", "tcp", 81, "192.168.1.2")
    assert not fw.accept_packet("inbound", "udp", 24, "52.12.48.92")
