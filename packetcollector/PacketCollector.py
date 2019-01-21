from scapy.all import sniff, wrpcap
import time
import os


class PacketCollector:
    def __init__(self, timeout=10, interface=None, out_dir=None):
        self.timeout = timeout
        self.interface = interface
        
        if out_dir == None:
            self.out_dir = os.getcwd()
        else:
            self.out_dir = out_dir
        
        self.packets = None

    def capture(self):
        try:
            self.packets = sniff(iface=self.interface, timeout=self.timeout)
        except ValueError:
            print("Could not capture on {}".format(self.interface))
        
    def save(self):
        filename = 	self.out_dir + "/" + self._get_filename()
        wrpcap(filename, self.packets)

    def _get_filename(self):
	    return str(time.time()) + ".pcap" 
	
	    #Stream allows for multiple captures to occur and to continue to save to the same folder
    def stream(self, amount):
        for i in range(0, amount):
            self.capture()
            self.save()
