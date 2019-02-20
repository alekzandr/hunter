from scapy.all import *
import argparse
import datetime



def batch_generator(iterable, window)= 5:
    packet_out = []
    count
    source_iterable = iter(iterable)
    while True:
        batch_iterable

def breakout_pcap(pcap_file, time_window=5):

    packet_out = []
    count = 0
    try:
        for packet in pcap_file:
            packet_out.append(packet)
            time_diff = packet.time - packet_out[0].time
            if time_diff > time_window:
                count += 1
                packet_out.pop()
                print(count)
                wrpcap("packet_replay_test_" + str(count) + ".pcap", packet_out)
                packet_out = []
                
    except:
        count += 1
        print(count)
        wrpcap("packet_replay_test_" + str(count) + ".pcap", packet_out)
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
        breakout_pcap(pkt_reader)
    except IOError:
        print("Failed reading file %s contents" % infile)
        sys.exit(1)