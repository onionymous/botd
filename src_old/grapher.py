# SURF2017
# File: grapher.py
# Created: 21/06/2017
# Author: Stephanie Ding

import settings
import constants
from TrainingSession import *
import numpy as np
import matplotlib.pyplot as plt

def main():
    ts = GraphSession(settings.PCAP_FILENAME, constants.DATASET_9_INFECTED_HOSTS,
                         constants.DATASET_9_NORMAL_HOSTS)

    ts.show_graph()
    # time_values = []
    # packet_counts = []
    #
    #
    #
    # starting_time = packets[0].timestamp
    # current_time = starting_time
    # current_count = 0
    #
    # for p in packets:
    #     if p.timestamp == current_time:
    #         current_count += 1
    #     else:
    #         time_values.append(current_time - starting_time)
    #         packet_counts.append(current_count)
    #         current_time = p.timestamp
    #         current_count = 0
    #
    # plt.plot(np.array(time_values), np.array(packet_counts))
    # plt.show()


if __name__ == "__main__":
    main()
