from scapy.all import *
import argparse
import datetime
import time
import os
from flowmeter.flowmeter import Flowmeter
import gc
import warnings
warnings.simplefilter(action='ignore', category=FutureWarning)
import pandas as pd
pd.options.mode.chained_assignment = None 



def delete_temp_pcaps(filename):
    if os.path.exists(filename):
        os.remove(filename)

def convert_df_to_csv(df, out_file_name, count):
    if count == 1:
        df.to_csv(out_file_name, header=True, mode='a')
        print("Creating File")
    else:
        df.to_csv(out_file_name, header=False, mode='a')
        print("File Updated")

def convert_pcap_to_df(out_file_name):
    feature_gen = Flowmeter(out_file_name)
    df = feature_gen.build_feature_dataframe()
    return df

def breakout_pcap(pcap_file, out_file_name, time_window=5, ):

    packet_out = []
    count = 0
    for packet in pcap_file:
        packet_out.append(packet)
        time_diff = packet.time - packet_out[0].time
        if time_diff > time_window:
            count += 1
            last_packet = packet_out.pop()
            wrpcap(out_file_name + str(count)+ ".pcap", packet_out)
            packet_out = [last_packet]

            df = convert_pcap_to_df(out_file_name + str(count)+ ".pcap")
            convert_df_to_csv(df, out_file_name+".csv", count)
            delete_temp_pcaps(out_file_name + str(count)+ ".pcap")
            df = None
            gc.collect()
                    

if __name__ == "__main__":

    # setup commandline arguments  
    parser = argparse.ArgumentParser(description='Packet Sniffer')
    parser.add_argument('--infile', action="store", dest="infile")

    # parse arguments  
    given_args = ga = parser.parse_args()   
    infile =  ga.infile
    try:
        t0 = time.time()
        pkt_reader = PcapReader(infile)
        breakout_pcap(pkt_reader, "tuesday-working-hours", 60)
        t1 = time.time()
        print(t1-t0)
    except IOError:
        print("Failed reading file %s contents" % infile)
        sys.exit(1)