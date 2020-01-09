import csv

from rand_fields import get_rand_rule


with open("500k_rules.csv", "w") as csv_file:
    csv_writer = csv.writer(csv_file)
    for rule_num in range(500000):
        csv_writer.writerow(get_rand_rule())
