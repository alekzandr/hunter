# import libraries
from scapy.all import *
from collections import Counter
from prettytable import PrettyTable
from plotly import __version__
from plotly.offline import download_plotlyjs, init_notebook_mode, plot, iplot
from datetime import datetime
import pandas as pd
import re

init_notebook_mode(connected=True)

class processor:
    def __init__(self, file):
        self.pcap_file = rdpcap(file)
        
    def dataframe(self, time="ue"):
        self.time=time
        srcIP = []
        dstIP = []
        pktTimes = []
        pktBytes = []
        for pkt in self.pcap_file:
            if IP in pkt:
        # try and except block is used to iterate over possible malformed information
                try:
                    srcIP.append(pkt[IP].src)
                    dstIP.append(pkt[IP].dst)
                    pktBytes.append(pkt[IP].len)
                    pktTime=datetime.fromtimestamp(pkt.time)
                    pktTimes.append(pktTime.strftime("%Y%m%d%H%M%S"))
                    
                except:
                    pass
        
        if self.time=="datetime":
            pktTimes = pd.to_datetime(pd.Series(pktTimes).astype(str),  errors="coerce")
        else:
            pktTimes = pd.Series(pktTimes)
        
        data = [[t, s, d, b] for t,s,d,b in zip(pktTimes,srcIP,dstIP,pktBytes)]
        labels = ['Time', 'Source', 'Destination', 'Bytes']
        
        df = pd.DataFrame.from_records(data, columns=labels)
        #df = df.set_index("Time")
        #df = df.resample("2S").sum()
        '''
        #This converts list to series
        byte = pd.Series(pktBytes).astype(int)
        source = pd.Series(srcIP)
        destination = pd.Series(dstIP)                        
        #Convert the timestamp list to a pd date_time
        times = pd.to_datetime(pd.Series(pktTimes).astype(str),  errors="coerce")
        #Create the dataframe
        df  = pd.DataFrame({"Source":source, "Destination":destination, "Bytes": bytes, "Times":times})
        #set the date from a range to an timestamp
        df = df.set_index("Times")
        df2=df.resample("2S").sum()
        '''
        return df
    
'''
    ProcessorV2 requres the tcp stat output file from a tshark command (sudo tshark -r sample.pcap -q -z conv,tcp > tcp_stats.csv)
    TODO:
    Extend to ingest a pcap file instead of the tshark output
'''
class processorV2:
    def __init__(self, file):
        # Store file
        print("\n[+] Reading File")
        self.file = file
    
        # Initialize an empty array to hold the dataset
        self.data = []
        
        # Store TCP labels
        self.labels = []
        
        print("\n[+] File has been read into memory")

    def clean(self): 
        self.labels = ["src_ip", "src_port", "dst_ip", "dst_port", "src_frames", "src_bytes", "dst_frames", "dst_bytes", "total_frames", "total_bytes", "relative_start", "duration"]

        # Open file and read into self.data as string of text
        with open(self.file) as file:
            self.data = list(file)
        print("\n[+] Opening file for cleaning")  

        # Remove the original tshark column headers
        print("\n[+] Locating unstructured column labels")
        print(self.data[:5])
        print("\n[+] Removing unstructured column labels")
        self.data = self.data[5:]
        print("\n[+] Current state:")
        print(self.data[9])

        # Split the string of data on spaces and store as a list
        print("\n[+] Cleaning dataset step 1/2")
        self.data = [e.split(" ") for e in self.data]
        print(self.data[9])
        print("\n[+] Cleaning dataset step 2/2")
        # Iterate through each element to clean and format the data
        for index, element in enumerate(self.data):
            temp = [e for e in element if e != '']
            temp = [e for e in temp if e != '<->']
            temp = [e.rsplit(":", 1) for e in temp]
            _ = []
            for e in temp:
                _ += e
                temp = _
                for i,e in enumerate(temp):
                    if re.search("\\n", e) is not None:
                        temp[i] = e.split("\n")[0]
                        self.data[index] = temp
        
        print("\n[+] Dataset has been cleaned")
        print(self.data[9])
        
        # Remove last entry which is a border
        print("\n[+] Remove bottom border")
        self.data.pop()
        #print("\n[+] Number of columns for final dataset")
        #print(len(self.data))
        
        
        
        # Convert list to pandas dataframe
        print("\n[+] Converting dataset to Pandas Dataframe")
        self.data = pd.DataFrame.from_records(self.data, columns=self.labels)
        
        print("\n[+] Setting appropriate dataframe columns to numeric datatypes")
        # Convert some columns statisical data from string to integers
        self.data[["src_frames", "src_bytes", "dst_frames", "dst_bytes", "total_frames", "total_bytes", "relative_start", "duration"]] = self.data[["src_frames", "src_bytes", "dst_frames", "dst_bytes", "total_frames", "total_bytes", "relative_start", "duration"]].apply(pd.to_numeric)
        #print("\n[*] DEBUG: Ignoring conversion to pandas...returning as list")
        print("\n[+] Done")
        return self.data
        
def get_lookup_table(list_data, form='dict'):
        forms=['dict', 'list']
        if form not in forms:
            raise ValueError("Invalid output form. Expected {}".format(forms))
        
        x = set(list_data)
        
        if form == 'dict':
            dictionary = {}
  
            for i,k in enumerate(list(set(x))):
                dictionary[k] = i
            x = dictionary
        
        return x
    