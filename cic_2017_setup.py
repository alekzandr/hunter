import glob
import tensorflow as tf 
import numpy as np
import pandas as pd

dtypes = {
    ' Destination Port' : 'int32',
    ' Flow Duration' : 'int32',
    ' Total Fwd Packets' :  'int32',
    ' Total Backward Packets' : 'int32',
    'Total Length of Fwd Packets' : 'int32',
    ' Total Length of Bwd Packets' : 'int32', 
    ' Fwd Packet Length Max' : 'int32',
    ' Fwd Packet Length Min' : 'int32', 
    ' Fwd Packet Length Mean' : 'float16',
    ' Fwd Packet Length Std' : 'float16', 
    'Bwd Packet Length Max': 'int32',
    ' Bwd Packet Length Min' : 'int32', 
    ' Bwd Packet Length Mean' : 'float16',
    ' Bwd Packet Length Std' : 'float16', 
    'Flow Bytes/s' : 'category', 
    ' Flow Packets/s' : 'category',
    ' Flow IAT Mean' : 'float16', 
    ' Flow IAT Std' : 'float16', 
    ' Flow IAT Max' : 'int32', 
    ' Flow IAT Min' : 'int32',
    'Fwd IAT Total' : 'int32', 
    ' Fwd IAT Mean' : 'float16', 
    ' Fwd IAT Std' : 'float16', 
    ' Fwd IAT Max' : 'int32',
    ' Fwd IAT Min' : 'int32', 
    'Bwd IAT Total' : 'int32', 
    ' Bwd IAT Mean' : 'float16', 
    ' Bwd IAT Std' : 'float16',
    ' Bwd IAT Max' : 'int32', 
    ' Bwd IAT Min' : 'int32', 
    'Fwd PSH Flags' : 'int32', 
    ' Bwd PSH Flags' : 'int32',
    ' Fwd URG Flags' : 'int32', 
    ' Bwd URG Flags' : 'int32', 
    ' Fwd Header Length' : 'int32',
    ' Bwd Header Length' : 'int32', 
    'Fwd Packets/s' : 'float16', 
    ' Bwd Packets/s' : 'float16',
    ' Min Packet Length' : 'int32', 
    ' Max Packet Length' : 'int32', 
    ' Packet Length Mean' : 'float16',
    ' Packet Length Std' : 'float16', 
    ' Packet Length Variance' : 'float16', 
    'FIN Flag Count' : 'int32',
    ' SYN Flag Count' : 'int32', 
    ' RST Flag Count' : 'int32', 
    ' PSH Flag Count' : 'int32',
    ' ACK Flag Count' : 'int32', 
    ' URG Flag Count' : 'int32', 
    ' CWE Flag Count' : 'int32',
    ' ECE Flag Count' : 'int32', 
    ' Down/Up Ratio' : 'int32', 
    ' Average Packet Size' : 'float16',
    ' Avg Fwd Segment Size' : 'float16', 
    ' Avg Bwd Segment Size' : 'float16',
    ' Fwd Header Length.1' : 'int32', 
    'Fwd Avg Bytes/Bulk' : 'int32', 
    ' Fwd Avg Packets/Bulk' : 'int32',
    ' Fwd Avg Bulk Rate' : 'int32', 
    ' Bwd Avg Bytes/Bulk' : 'int32', 
    ' Bwd Avg Packets/Bulk' : 'int32',
    'Bwd Avg Bulk Rate' : 'int32', 
    'Subflow Fwd Packets' : 'int32', 
    ' Subflow Fwd Bytes' : 'int32',
    ' Subflow Bwd Packets' : 'int32', 
    ' Subflow Bwd Bytes' : 'int32', 
    'Init_Win_bytes_forward' : 'int32',
    ' Init_Win_bytes_backward' : 'int32', 
    ' act_data_pkt_fwd' : 'int32',
    ' min_seg_size_forward' : 'int32', 
    'Active Mean' : 'float16', 
    ' Active Std' : 'float16', 
    ' Active Max' : 'int32',
    ' Active Min' : 'int32', 
    'Idle Mean' : 'float16', 
    ' Idle Std' : 'float16', 
    ' Idle Max' : 'int32', 
    ' Idle Min' : 'int32',
    ' Label' : 'category',
}


def clean_text(word):
    (laptops["cpu"].str.replace("GHz","")
                    .str.rsplit(n=1,expand=True)
                        .iloc[:,1]
                        .astype(float)
                        )


def setup():
    
    # read in datasets for each day
    path = "/Users/kyletopasna/Documents/hunter/ISCX CIC/CIC-IDS-2017/MachineLearningCVE/"
    monday = pd.read_csv(path + "Monday-WorkingHours.pcap_ISCX.csv", dtype=dtypes)
    tuesday = pd.read_csv(path + "Tuesday-WorkingHours.pcap_ISCX.csv", dtype=dtypes)
    wednesday = pd.read_csv(path + "Wednesday-workingHours.pcap_ISCX.csv", dtype=dtypes)
    thursday_morning = pd.read_csv(path + "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv", dtype=dtypes)
    thursday_afternoon = pd.read_csv(path + "Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv", dtype=dtypes)
    friday_morning = pd.read_csv(path + "Friday-WorkingHours-Morning.pcap_ISCX.csv", dtype=dtypes)
    friday_afternoon_port_scan = pd.read_csv(path + "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv", dtype=dtypes)
    friday_afternoon_ddos = pd.read_csv(path + "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv", dtype=dtypes)
    
    # combine each dataset into one pandas dataframe
    frames = [monday, tuesday, wednesday, thursday_morning, 
          thursday_afternoon, friday_morning, friday_afternoon_port_scan, friday_afternoon_ddos]
    data = pd.concat(frames)
    
    # cast "Flow Bytes/s" and " Flow Packets/s" to float dtypes
    data.loc[:,["Flow Bytes/s", " Flow Packets/s"]] = data.loc[:,["Flow Bytes/s", " Flow Packets/s"]].apply(pd.to_numeric, errors='coerce')
    
    data.columns = data.columns.str.lower().str.strip().str.replace(" ","_")
    
    
    # collect all rows that contain null values
    nan_rows = data[data.isnull().any(1)]
    
    # grab labels and remove from data
    y_labels = data["label"]
    data = data.drop(labels="label", axis=1)
    
    # fill each null value with the mean from the column
    data_cleaned = data.apply(lambda x: x.fillna(x.mean()),axis=0)
    
    # recombine labels with the dataset
    data["label"] = y_labels
    
    # remove symbols from labels and lower
    data["label"] = data["label"].str.replace("�", "")
    data["label"] = data["label"].str.lower()
                      
    
    # Save all maicious traffic to malicious_traffic
    malicious_traffic = data[data["label"] != "BENIGN"]
    
    # sample additional training data to be 2x the size of the ground truth labeled malicious traffic
    training_data = data.sample(int(len(malicious_traffic)))
    
    # concatnate additional training data and known malicious traffic
    training_data = pd.concat([malicious_traffic, training_data])
    
    return data, training_data