from scapy.all import *
import time
import os

class packetCollector:
	
	def __init__(self, count=100, interface, out_dir=None):
	
		'''
		inputs:

		time: float
			time input tells collectTraffic how long to collect packets in seconds
			on the interface.
			example: time=5 for collecting traffic for 5 seconds

		interface: string
			
		'''
		
		self.time = time
		self.interface = interface
		self.out_dir = os.getcwd()
		self.packets = None
		
	
	def sniff_packets(self, count=None, interface=None) :
		
		
		if count == None:
			count = self.count
		if interface == None:
			interface = self.interface
		
		self.packets = sniff(count=count, iface=interface, store=0)
		
	
	def get_filename(self):
		return str(time.time())
	
	
	def save_to_pcap(self, out_dir=None):
		if out_path == None:
			out_path = self.outpath
		filename = 	out_dir + get_filename()
		
		wrpcap(filename, self.packets)
