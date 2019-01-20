from PacketCollector import *

collector = PacketCollector(timeout=10, interface="ens33", out_dir="/home/julian/Desktop/test.pcap")
collector.capture()
collector.save()
