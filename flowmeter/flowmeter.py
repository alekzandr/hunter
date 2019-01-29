from scapy.all import *
import pandas as pd
import numpy as np

class flowmeter:

    """
    This is the flowmeter class. It's purpose is to
    take in a pcap file and output a csv file
    containing 84 features to be used in machine
    learning applications.
    """
    
    def __init__(self, pcap=None):
        
        """
        Args:
            pcap (str): OS location to a pcap file.
        """

        self._pcap = rdpcap(pcap)

    def load_pcap(self, pcap):

        """
        This function takes in a pcap file saves it
        as a scapy PacketList.

        Args:
            pcap (str): OS location to a pcap file.
        """
        self._pcap = rdpcap(pcap)
    
    def _get_sessions(self, packet):

        """
        This function takes in packets and builds
        bi-directional flows between source and
        destinations.

        This is to be used in conjuction with a
        scapy PacketList object.

        Example:

        packet_capture = rdpcap(test.pcap)
        session_flows = packet_capture.sessions(_get_sessions)

        Args:
            packet (packet): A packet placeholder handled by scapy.

        Returns a dictionary with session information as the key
        and the corresponding bi-directional PacketList object

        Example Output:

            {
            "['192.168.86.21', '192.168.86.22', 60604, 8009, 'TCP']": <PacketList: TCP:6 UDP:0 ICMP:0 Other:0>, 
            "['192.168.86.21', '34.212.215.14', 443, 60832, 'TCP']": <PacketList: TCP:9 UDP:0 ICMP:0 Other:0>
            }

        """
        sess = "Other"
        if "Ether" in packet:
            if "IP" in packet:
                if "TCP" in packet:
                    sess = str(sorted(["TCP", packet["IP"].src, packet["TCP"].sport,
                                    packet["IP"].dst, packet["TCP"].dport], key=str))
                elif "UDP" in packet:
                    sess = str(sorted(["UDP", packet["IP"].src, packet["UDP"].sport,
                                    packet["IP"].dst, packet["UDP"].dport], key=str))
                elif "ICMP" in packet:
                    sess = str(sorted(["ICMP", packet["IP"].src, packet["IP"].dst,
                                    packet["ICMP"].code, packet["ICMP"].type, packet["ICMP"].id], key=str))
                else:
                    sess = str(sorted(["IP", packet["IP"].src, packet["IP"].dst,
                                    packet["IP"].proto], key=str))
            elif "ARP" in packet:
                sess = str(sorted(["ARP", packet["ARP"].psrc, packet["ARP"].pdst], key=str))
            else:
                sess = packet.sprintf("Ethernet type = %04xr,Ether.type%")
        return sess

    def build_dataframe(self, packet_list):

        """
        This function takes in a scapy PacketList object and 
        builds a pandas dataframe.

        Args:
            packet_list (PacketList): A scapy PacketList object.
        
        """
        
        ip_fields = [field.name for field in IP().fields_desc]
        tcp_fields = [field.name for field in TCP().fields_desc]
        udp_fields = [field.name for field in UDP().fields_desc]

        dataframe_fields = ip_fields + ['time'] + tcp_fields + ['size','payload','payload_raw','payload_hex']

        # Create blank DataFrame
        df = pd.DataFrame(columns=dataframe_fields)
        for packet in packet_list[IP]:
            # Field array for each row of DataFrame
            field_values = []
            # Add all IP fields to dataframe
            for field in ip_fields:
                if field == 'options':
                    # Retrieving number of options defined in IP Header
                    field_values.append(len(packet[IP].fields[field]))
                else:
                    field_values.append(packet[IP].fields[field])

            field_values.append(packet.time)

            layer_type = type(packet[IP].payload)
            for field in tcp_fields:
                try:
                    if field == 'options':
                        field_values.append(len(packet[layer_type].fields[field]))
                    else:
                        field_values.append(packet[layer_type].fields[field])
                except:
                    field_values.append(None)
            
            # Append payload
            field_values.append(len(packet))
            field_values.append(len(packet[layer_type].payload))
            field_values.append(packet[layer_type].payload.original)
            field_values.append(binascii.hexlify(packet[layer_type].payload.original))
            # Add row to DF
            df_append = pd.DataFrame([field_values], columns=dataframe_fields)
            df = pd.concat([df, df_append], axis=0)
            
        # Reset Index
        df = df.reset_index()
        # Drop old index column
        df = df.drop(columns="index")
        return df

    def build_sessions(self):
			  
		"""
		This function returns dictionary of bi-directional
        flows.

		"""
        
        return self._pcap.sessions(self._get_sessions)

    def get_src_ip(self, df):

        """
        This function should take in a pandas dataframe object
        that contains all the information for a single bi-directional
        flow. It will return the source IP address of the flow.

        Args:
            df (Dataframe): A bi-directional flow pandas dataframe.
        
        """
        
        return df["src"].unique().tolist()[0]

    def get_dst_ip(self, df):

        """
        This function should take in a pandas dataframe object
        that contains all the information for a single bi-directional
        flow. It will return the destination IP address of the flow.

        Args:
            df (Dataframe): A bi-directional flow pandas dataframe.
        """
        
        return df["src"].unique().tolist()[1]
		
	def get_flow_duration(self, df):
        
        """
        This function returns the total time for the session flow.
        """
        
        idx = df.columns.get_loc("time")
        return 1000000 * (df.iloc[-1, idx] - test_flow.iloc[0,idx])
	
