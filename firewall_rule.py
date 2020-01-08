from ip_address import IPAddress


class FirewallRule:
    """Defines a `FirewallRule` type."""
    pass


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

    def __eq__(self, other: FirewallRule):
        """Implements the "==" operator to compare `FirewallRule` objects."""
        return (
            self.direction == other.direction and
            self.protocol == other.protocol and
            self.min_port == other.min_port and
            self.max_port == other.max_port and
            self.min_ip == other.min_ip and
            self.max_ip == other.max_ip
        )

    def __hash__(self):
        """Returns the hash value of the current `FirewallRule` object."""
        return hash((
            self.direction, self.protocol, self.min_port, self.max_port,
            self.min_ip, self.max_ip
        ))
