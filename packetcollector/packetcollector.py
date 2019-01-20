from scapy.all import *


class PacketCollector:
    def __init__(self, timeout=60, interface="ens33", out_dir="/home/julian/Desktop/test.pcap"):
        self.timeout = timeout
        self.interface = interface
        self.out_dir = out_dir
        self.packets = None

    def capture(self):
        self.packets = sniff(iface=self.interface, timeout=self.timeout)

    def save(self):
        wrpcap(self.out_dir, self.packets)
