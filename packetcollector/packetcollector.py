class packetcollector:
	
	def __init__(self, time=60, interface, out_dir=None):
	
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