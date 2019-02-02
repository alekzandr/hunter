from scapy.all import *
import pandas as pd
import glob
import os
from flask import Flask, jsonify
from features import *

app = Flask(__name__)      

input_path = "/input/"
output_path = "/output/"

def get_latest_pcap():
    list_of_files = glob.glob(input_path + '*.pcap')
    return max(list_of_files, key=os.path.getctime)


@app.route('/api/flowmeter/build')     
def flowmeter():
    pcap_file = get_latest_pcap()


    






if __name__ == '__main__':         
    app.run() 