from scapy.all import sniff, wrpcap
import time
import os


class PacketCollector:
    def __init__(self, timeout=10, interface=None, out_dir=None):
        self.timeout = timeout
        self.interface = interface

        if out_dir is None:
            self.out_dir = os.getcwd()
        else:
            self.out_dir = out_dir

        self.packets = None

    def capture(self):
        # starts sniffing packets. If the device is incorrectly named, it will show
        try:
            self.packets = sniff(iface=self.interface, timeout=self.timeout)
        except OSError as e:
            print(e)

    def save(self):
        # checks if pcap directory exists. Creates one if it isn't
        if not os.path.exists(self.out_dir):
            os.makedirs(self.out_dir)

        filename = self.out_dir + "/" + self._get_filename()
        wrpcap(filename, self.packets)

    def _get_filename(self):
        return str(time.time()) + ".pcap"

    # allows for specific number of captures. Used for debugging. stream(0) is a constant capture and save.
    def stream(self, x):
        if x is 0:
            while True:
                self.capture()
                self.save()
        else:
            for i in range(0, x):
                self.capture()
                self.save()
