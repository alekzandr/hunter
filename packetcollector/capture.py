from PacketCollector import *

collector = PacketCollector(timeout=10, interface="wlan0", out_dir=None)
collector.stream(1)
