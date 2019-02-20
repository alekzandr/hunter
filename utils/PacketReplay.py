from scapy.all import *
import argparse

pcap = 

def breakout_pcap(pcap_file):
    

if __name__ == "__main__":

    # setup commandline arguments  
    parser = argparse.ArgumentParser(description='Packet Sniffer')
    parser.add_argument('--infile', action="store", dest="infile")

    # parse arguments  
    given_args = ga = parser.parse_args()   
    infile =  ga.infile
    try:
        pkt_reader = PcapReader(infile)
    except IOError:
        print "Failed reading file %s contents" % infile
        sys.exit(1)