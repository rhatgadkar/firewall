"""This file defines the data structure to represent an IP address."""


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

    def __eq__(self, other: IPAddress):
        """Implements the "==" operator to compare `IPAddress` objects."""
        for i in range(4):
            if self.octets[i] != other.octets[i]:
                return False
        return True

    def __hash__(self):
        """Returns the hash value of the current `IPAddress` object."""
        return hash(self.octets)
