import random
from typing import Tuple

from ip_address import IPAddress


def get_rand_direction() -> str:
    """Return a random direction."""
    return random.choice(("inbound", "outbound"))


def get_rand_protocol() -> str:
    """Return a random protocol."""
    return random.choice(("tcp", "udp"))


def get_rand_port_value() -> str:
    """Return a random port between 1-65535."""
    return str(random.randint(1, 65535))


def get_rand_port_range() -> str:
    """Return a random port range. The min port must be <= max port."""
    min_port = int(get_rand_port_value())
    max_port = random.randint(min_port, 65535)
    assert min_port <= max_port
    return f"{min_port}-{max_port}"


def get_rand_port() -> str:
    """Randomly return either a single port value or a port range."""
    return random.choice((get_rand_port_value(), get_rand_port_range()))


def get_rand_ip_address_value() -> str:
    """Return a random IP address."""
    octets = []
    for i in range(4):
        octets.append(str(random.randint(0, 255)))
    return ".".join(octets)


def get_rand_ip_address_range() -> str:
    """
    Return a random IP address range.
    The min IP address must be <= max IP address.
    """
    min_ip_address = get_rand_ip_address_value()
    min_ip = IPAddress(min_ip_address)
    min_octets = min_ip.octets
    max_octets = [random.randint(min_octets[0], 255)]
    num_max_octets = len(max_octets)
    while (
        max_octets[num_max_octets - 1] == min_octets[num_max_octets - 1] and
        num_max_octets < 4
    ):
        max_octets.append(random.randint(min_octets[num_max_octets], 255))
        num_max_octets += 1
    while num_max_octets < 4:
        max_octets.append(random.randint(0, 255))
        num_max_octets += 1
    max_ip_address = ".".join([str(octet) for octet in max_octets])
    max_ip = IPAddress(max_ip_address)
    assert min_ip < max_ip or min_ip == max_ip
    return f"{min_ip_address}-{max_ip_address}"


def get_rand_ip_address() -> str:
    """Randomly return either a single IP address or an IP address range."""
    return random.choice(
        (get_rand_ip_address_value(), get_rand_ip_address_range())
    )


def get_rand_rule() -> Tuple[str]:
    """
    Return a random firewall rule as a tuple of four items. The four items are:
    direction, protocol, port, and IP address.
    """
    return (
        get_rand_direction(), get_rand_protocol(), get_rand_port(),
        get_rand_ip_address()
    )
