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
        return hash(self.octets)


class FirewallRule(object):
    """
    A data structure to represent a firewall rule.

    A firewall rule consists of four fields:
    1. direction: can either be "inbound" or "outbound".
    2. protocol: can either be "tcp" or "udp".
    3. port: can either be a single value (i.e. "192") or a range of values
             (i.e. "192-202").
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

    The data structure is a hash-set of firewall rules. The hash-set prevents
    duplicate firewall rules from being added.
    """

    def __init__(self, csv_file_path: str):
        """Read and store the firewall rules from the CSV file."""
        self.fw_rules = set()
        with open(csv_file_path, "r") as csv_file:
            csv_reader = csv.reader(csv_file)
            for csv_fw_rule in csv_reader:
                self.fw_rules.add(FirewallRule(*csv_fw_rule))

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
    fw = Firewall("sample_rules.csv")
    assert fw.accept_packet("inbound", "tcp", 80, "192.168.1.2")
    assert fw.accept_packet("inbound", "udp", 53, "192.168.2.1")
    assert fw.accept_packet("inbound", "udp", 53, "192.168.2.1")
    assert not fw.accept_packet("inbound", "tcp", 81, "192.168.1.2")
    assert not fw.accept_packet("inbound", "udp", 24, "52.12.48.92")
