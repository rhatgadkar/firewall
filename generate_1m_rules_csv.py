import csv

from rand_fields import get_rand_rule


with open("1m_rules.csv", "w") as csv_file:
    csv_writer = csv.writer(csv_file)
    for rule_num in range(1000000):
        csv_writer.writerow(get_rand_rule())
