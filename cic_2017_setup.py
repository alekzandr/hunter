import glob
import tensorflow as tf 
import pcap_processor
import numpy as np
import pandas as pd

def setup():
    
    # read in datasets for each day
    path = "/Users/kyletopasna/Documents/hunter/ISCX CIC/CIC-IDS-2017/MachineLearningCVE/"
    monday = pd.read_csv(path + "Monday-WorkingHours.pcap_ISCX.csv")
    tuesday = pd.read_csv(path + "Tuesday-WorkingHours.pcap_ISCX.csv")
    wednesday = pd.read_csv(path + "Wednesday-workingHours.pcap_ISCX.csv")
    thursday_morning = pd.read_csv(path + "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv")
    thursday_afternoon = pd.read_csv(path + "Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv")
    friday_morning = pd.read_csv(path + "Friday-WorkingHours-Morning.pcap_ISCX.csv")
    friday_afternoon_port_scan = pd.read_csv(path + "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv")
    friday_afternoon_ddos = pd.read_csv(path + "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv")
    
    # combine each dataset into one pandas dataframe
    frames = [monday, tuesday, wednesday, thursday_morning, 
          thursday_afternoon, friday_morning, friday_afternoon_port_scan, friday_afternoon_ddos]
    data = pd.concat(frames)
    
    # cast "Flow Bytes/s" and " Flow Packets/s" to float dtypes
    data.loc[:,["Flow Bytes/s", " Flow Packets/s"]] = data.loc[:,["Flow Bytes/s", " Flow Packets/s"]].apply(pd.to_numeric, errors='coerce')
    
    # collect all rows that contain null values
    nan_rows = data[data.isnull().any(1)]
    
    # grab labels and remove from data
    y_labels = data[" Label"]
    data = data.drop(labels=" Label", axis=1)
    
    # fill each null value with the mean from the column
    data_cleaned = data.apply(lambda x: x.fillna(x.mean()),axis=0)
    
    # recombine labels with the dataset
    data["labels"] = y_labels
    
    # Save all maicious traffic to malicious_traffic
    malicious_traffic = data[data["labels"] != "BENIGN"]
    
    # sample additional training data to be 2x the size of the ground truth labeled malicious traffic
    training_data = data.sample(int(len(malicious_traffic)))
    
    # concatnate additional training data and known malicious traffic
    training_data = pd.concat([malicious_traffic, training_data])
    
    return data, training_data