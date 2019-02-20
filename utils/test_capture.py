from PacketCollector import *
import time
t0 = time.time()

'''
collector = PacketCollector(timeout=5, interface="en0")
collector.capture()
collector.save()
'''
collector = PacketCollector(timeout=60, interface="en0", out_dir="/Users/kyletopasna/Documents/hunter/pcap")
collector.capture()
collector.save()
'''
collector = PacketCollector(timeout=5, interface="ff")
collector.capture()
collector.save()
'''
t1 = time.time()

print(t1-t0)
#print(os.getcwd() + "/" + str(time.time()) + ".pcap")