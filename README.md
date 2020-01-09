Firewall implementations
------------------------

This project implements two firewall programs: `firewall.py` and
`naive_firewall.py`. Both firewall programs store a set of firewall rules. Based
on its rules, the firewall is able to accept or block certain packets. If the
fields of a packet matches a firewall rule, the packet is accepted. Otherwise,
the packet is blocked.

About `naive_firewall.py`:
`naive_firewall.py` stores firewall rules in a set. Adding firewall rules is
fast in the naive firewall, because it is an O(1) operation to append a set.
But deciding to accept or block a packet in the naive firewall is slow, because
it involves having to iterate through all the firewall rules in the set.


About `firewall.py`:
`firewall.py` stores firewall rules in an organized manner. Firewall rules that
contain the same directions, protocols, and port values are stored in the same
set. This means that there are multiple sets that store firewall rules. Adding
firewall rules is slower in this firewall, because it may involve having to add
the rule into multiple sets. But deciding to accept or block a packet in this
firewall is faster, because each set contains a subset of all the firewall
rules. And iterating through this subset is faster than iterating through all
the firewall rules.

Information about the files of this directory:
- `1m_rules.csv`: a generated CSV file with 1M firewall rules.
- `500k_rules.csv`: a generated CSV file with 500K firewall rules.
- `firewall.py`: a program that contains the implementation of the organized
                 firewall.
- `firewall_rule.py`: contains the definition of the `FirewallRule` data
                      structure.
- `generate_1m_rules_csv.py`: a script to generate the `1m_rules.csv` file.
- `generate_500k_rules_csv.py`: a script to generate the `500k_rules.csv` file.
- `ip_address.py`: contains the definition of the `IPAddress` data structure.
- `naive_firewall.py`: a program that contains the implementation of the naive
                       firewall.
- `rand_fields.py`: contains functions to generate random firewall fields.
- `sample_rules.csv`: the CSV file given in the project specification.
- `test_firewall.py`: the unit tests to verify the functionality of
                      `firewall.py`.
- `test_naive_firewall.py`: the unit tests to verify the functionality of
                            `naive_firewall.py`.

Information about testing:
- The `test_firewall.py` and `test_naive_firewall.py` contain unit tests to
  verify the correct behavior of accepting packets for the organized firewall
  and naive firewall, respectively.
- Manual testing was done with the `1m_rules.csv` and `500k_rules.csv` files.
  It was found that naive firewall performs faster when inserting new firewall
  rules. But the organized firewall performs faster when deciding whether to
  accept a packet or not.

Here is sample output of running the programs using `500k_rules.csv`:
```
rishabh@LAPTOP-MVE315P9:/mnt/c/Users/rhatg/Desktop/firewall$ python3 naive_firewall.py
Naive firewall time duration to add rules: 4.979974031448364
True
True
True
True
True
Naive firewall time duration to accept packets: 0.2236037254333496
rishabh@LAPTOP-MVE315P9:/mnt/c/Users/rhatg/Desktop/firewall$ python3 firewall.py
Firewall time duration to add rules: 9.715972185134888
True
True
True
True
True
Firewall time duration to accept packets: 0.0023255348205566406
```

Optimizations if I had more time:
- Think about how to add support for merging firewall rules. For example,
rule ("inbound", "tcp", "80", "192.168.56.1") and
rule ("inbound", "tcp", "80", "192.168.56.2") can be merged into a single
rule ("inbound", "tcp", "80", "192.168.56.1-192.168.56.2").
- Add support to delete firewall rules.

Time spent:
- I spend 2 hours to implement the naive firewall and most of organized
  firewall.
- I spent 5 more hours for finishing organized firewall, code organization,
  comments, unit testing, and 500K and 1M testing.
