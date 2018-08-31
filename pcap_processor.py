# import libraries
from scapy.all import *
from collections import Counter
from prettytable import PrettyTable
from plotly import __version__
from plotly.offline import download_plotlyjs, init_notebook_mode, plot, iplot
from datetime import datetime
import pandas as pd

init_notebook_mode(connected=True)

class processor:
    def __init__(self, file):
        self.pcap_file = rdpcap(file)
        
    def dataframe(self):
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
                    pktTimes.append(pktTime.strftime("%Y-%m-%d %H:%M:%S.%f"))
                except:
                    pass
        pktTimes = pd.to_datetime(pd.Series(pktTimes).astype(str),  errors="coerce")
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
        