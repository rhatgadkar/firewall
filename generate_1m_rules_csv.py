"""
This file is a script that generates the 1m_rules.csv file, which contains
1000000 randomly generated comma-separated firewall rules.

This script can be run in the terminal using this command:
    python3 generate_1m_rules.csv.py
"""


import csv

from rand_fields import get_rand_rule


with open("1m_rules.csv", "w") as csv_file:
    csv_writer = csv.writer(csv_file)
    for rule_num in range(1000000):
        csv_writer.writerow(get_rand_rule())
