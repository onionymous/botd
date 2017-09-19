# SURF2017
# File: GraphSession.py
# Created: 22/06/2017
# Author: Stephanie Ding

# from scapy.all import rdpcap
import os
import settings
import constants
import binascii
import numpy as np
import networkx as nx
import matplotlib.pyplot as plt
from pcapfile.protocols.linklayer import ethernet
from pcapfile.protocols.network import ip
from pcapfile.protocols.transport import tcp, udp
from pcapfile import savefile

SESSION_LENGTH = 120

class GraphSession:
    _infected_ips = {}
    _normal_ips = {}
    packets = ''
    graph = nx.Graph()
    statistics = {"total_packets":0, "non_ip_packets":0, "largest_packet":0}

    def __init__(self, bg_packets_folder, botnet_packets_folder, _infected_ips, _normal_ips):
        '''Starts a new session with the specified .pcap file'''
        self._infected_ips = _infected_ips
        self._normal_ips = _normal_ips


    def generate_graph(self, filename):
        # Open the .pcap file
        capture = open(filename, "rb")
        self.packets = savefile.load_savefile(capture, verbose=True).packets

        # Process the packets and generate the adjacency list based on the graph
        for p in self.packets:
            try:
                eth_frame = ethernet.Ethernet(p.raw())
                ip_packet = ip.IP(binascii.unhexlify(eth_frame.payload))
                source = ip_packet.src
                destination = ip_packet.dst
                packet_length = ip_packet.len
                protocol = constants.PROTOCOLS[ip_packet.p]

                #if source not in _infected_ips and source not in _normal_ips:
                #    u = ("WAN", protocol)
                #else:
                infected = True if source in _infected_ips else False
                u = (source, protocol, infected)

                #if destination not in _infected_ips and destination not in _normal_ips:
                #    v = ("WAN", protocol)
                #else:
                infected = True if destination in _infected_ips else False
                v = (destination, protocol, infected)

                if self.graph.has_edge(u, v):
                    self.graph[u][v]['weight'] += packet_length
                else:
                    self.graph.add_edge(u, v, weight=packet_length)

                self.statistics["total_packets"] += 1
                self.statistics["largest_packet"] = max(packet_length, self.statistics["largest_packet"])

                if settings.VERBOSE:
                    if self.statistics["total_packets"] % 50000 == 0:
                        print("Processed " + str(self.statistics["total_packets"]) + " packets")

            except Exception, e:
                self.statistics["non_ip_packets"] += 1

        if settings.VERBOSE:
            print("Processed all " + str(self.statistics["total_packets"]) + " packets")

    def compute_statistics(self):
        pass


    def show_graph(self):
        print(len(self.graph.nodes()))
        #nx.draw(self.graph, pos=nx.spring_layout(self.graph))
        #plt.savefig(settings.OUTPUT_FILENAME)
        #plt.show()