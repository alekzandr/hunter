from scapy.all import *
import argparse
import datetime

count = 0

def batch_generator(pcap_file, window=5):
    packet_out = []

    source_iterable = iter(pcap_file)
    while True:
        for packet in source_iterable:
            packet_out.append(packet)
            time_diff = packet.time - packet_out[0].time
            if time_diff > time_window:
                count += 1
                last_packet = packet_out.pop()
                batch_iter = iter(packet_out)
                packet_out = [last_packet]
                yield chain([batch_iter.next()])

def breakout_pcap(pcap_file, out_file_name, time_window=5, ):

    packet_out = []
    count = 0
    try:
        for packet in pcap_file:
            packet_out.append(packet)
            time_diff = packet.time - packet_out[0].time
            if time_diff > time_window:
                count += 1
                last_packet = packet_out.pop()
                print(count)
                wrpcap(out_file_name + str(count) + ".pcap", packet_out)
                packet_out = [last_packet]
                
    except:
        count += 1
        print(count)
        wrpcap(out_file_name + str(count) + ".pcap", packet_out)
        packet_out = []

    
        

if __name__ == "__main__":

    # setup commandline arguments  
    parser = argparse.ArgumentParser(description='Packet Sniffer')
    parser.add_argument('--infile', action="store", dest="infile")

    # parse arguments  
    given_args = ga = parser.parse_args()   
    infile =  ga.infile
    try:
        pkt_reader = PcapReader(infile)
        breakout_pcap(pkt_reader, "test_out_file", 5)
    except IOError:
        print("Failed reading file %s contents" % infile)
        sys.exit(1)