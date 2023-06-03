from flask import Flask, render_template, request, jsonify
from scapy.all import *
from manuf import manuf
from werkzeug.utils import secure_filename
import pyshark
import netifaces
import pandas as pd
import os
import time
import requests
import plotly.express as px 
import plotly.graph_objects as go
import html
import numpy as np

# ML
import xml.etree.ElementTree as ET
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score
import sys 
import pickle



def storeData(model, filename):
    # Its important to use binary mode
    dbfile = open(filename, 'ab')
    # source, destination
    pickle.dump(model, dbfile)                     
    dbfile.close()

def loadData(filename):
    # for reading also binary mode is important
    dbfile = open(filename, 'rb')     
    db = pickle.load(dbfile)
    dbfile.close()
    return db

def extract_tcp_signature(packet, predicted_device, model, vectorizer):
    tcp = packet[TCP]
    # print(tcp.options)
    # tcp_flag = tcp.flags.flagrepr()
    try:
        tcp_sign=[]
        if tcp.options[0][0]=='MSS':
            # tcp_sign.append(str(tcp.options[0][1]))
            if TCP in packet:
                tcp_sign.append(str(packet[TCP].window))

            if IP in packet:
                ttl=packet[IP].ttl
                tcp_sign.append(str(ttl))
                tos=packet[IP].tos
                tcp_sign.append(str(tos))
                tcp_sign.append("M"+str(tcp.options[0][1]))


                tcp_flag = tcp.flags.flagrepr()


                for option in tcp.options:
                    if option[0].lower()=="wscale":
                            window_scaling = option[1]
                            tcp_sign.append("W"+str(window_scaling))

        # print(tcp_flag+' '+':'.join(tcp_sign))
        new_data=[tcp_flag+' '+':'.join(tcp_sign)]
        new_data_vectorized = vectorizer.transform(new_data)
        predicted_device_name = model.predict(new_data_vectorized)
        # print("Predicted Device Name:", predicted_device_name[0])
        predicted_device.add(predicted_device_name[0])
    except:
        pass

# ARP-TABLE
def get_arp_table(filename):
    packets = rdpcap(filename)
    arp_table = {}
    vendor = ''
    for packet in packets:
        if ARP in packet:
            arp = packet[ARP]
            try:
                vendor = mac_parser.get_manuf_long(arp.hwsrc)
            except:
                pass
            # vendor="JOKER INC"
            arp_table[arp.psrc] = [arp.hwsrc, vendor]
    return arp_table

def lookup_cve(vendor, pages):
    cve_list = []
    try:
        url = f'https://services.nvd.nist.gov/rest/json/cves/1.0?keyword={vendor}&resultsPerPage={pages}'
        response = requests.get(url)
        if response.status_code == 200:
            cve_data = response.json()
            for result in cve_data['result']['CVE_Items']:
                cve_list.append(result)
    except:
        pass
    return cve_list


def process_pcap(filename, predicted_device):
    # Read the pcap file
    # TODO: Check the format for pyshark.FileCapture.
    cap = pyshark.FileCapture(filename)
    protocol__count = {}
    data = loadData("AssetIdentification1.pickle")
    print(data)
    model = data['model']
    vectorizer = data['vectorizer']
    ## ARP ADD
    # Get the ARP table
    arp_table = get_arp_table(filename)

    
    # Create a manuf object to resolve MAC addresses to vendor names
    mac_vendor_resolver = manuf.MacParser()

    # TODO: Check the format of the cap file to optimize the processing

    # Draw the plot
    for pkt in cap:
        for layer in pkt.layers:
            protocol_ = layer.layer_name
            protocol__count[protocol_] = protocol__count.get(protocol_, 0) + 1

    # Create a list of protocol_ names and counts
    labels = list(protocol__count.keys())
    values = list(protocol__count.values())

    protocol_plots = [['Protocol', 'Network Count']]
    for i in protocol__count.keys():
        name = i
        if not name:
            name = "Unknown"
        protocol_plots.append([name, protocol__count[i]])

    protocol_counts = zip(labels, values)
    print(protocol_counts)
    protocol_counts = dict(protocol_counts)

    # Create a dictionary to store the MAC addresses and vendor names
    mac_vendor_dict = {}

    # Initialize a list to store the connections
    connections = []
    # Create a dictionary to store the unique vendor names for each IP address
    vendor_map = {}
    all_protocols = []
    outcount = 0
    incount = 0
    # Iterate over each packet in the pcap file
    for packet in cap:
        protocol="Unknown"       
        try:
            os_name=""
            layers = list(packet.layers)
            proto_list=[_.layer_name for _ in layers]
            # Check if the packet has an Ethernet layer
            if 'ETH Layer' in str(packet.layers):
                # Get the source and destination MAC addresses
                src_mac = packet.eth.src.lower()
                dst_mac = packet.eth.dst.lower()

                # Check if the MAC addresses are already in the dictionary
                if src_mac not in mac_vendor_dict:
                    # Get the vendor name for the source MAC address
                    # vendor = mac_vendor_resolver.get_manuf(src_mac)
                    vendor = mac_vendor_resolver.get_manuf_long(src_mac)
                    mac_vendor_dict[src_mac] = vendor

                if dst_mac not in mac_vendor_dict:
                    # Get the vendor name for the destination MAC address
                    # vendor = mac_vendor_resolver.get_manuf(dst_mac)
                    vendor = mac_vendor_resolver.get_manuf_long(dst_mac)
                    mac_vendor_dict[dst_mac] = vendor

            # Check if the packet has an IP layer
            if 'IP Layer' in str(packet.layers):
                # Get the source and destination IP addresses
                src_ip = packet.ip.src
                dst_ip = packet.ip.dst
                
                if src_mac not in vendor_map:
                    # Get the vendor name for the MAC address
                    vendor = mac_vendor_resolver.get_manuf(src_mac)
                    vendor_map[src_mac] = {
                        'vendor_name': vendor,
                        'ip_addresses': list(set([src_ip]))  # Store unique IP addresses in a set
                    }
                else:
                    # Append the IP address to the existing MAC address entry
                    vendor_map[src_mac]['ip_addresses'].append(src_ip)             

                # Get the TTL and Window Size values
                ttl = int(packet.ip.ttl)
                window_size = int(packet.tcp.window_size)
 
                os_name, os_image = get_os_details(ttl, window_size)                 
               
                for layer in layers:
                    all_protocols.append(layer.layer_name)

                    protocol=layer.layer_name
                    # Create a connection dictionary
                    connection_dict = {
                        "src_mac": src_mac,
                        "dst_mac": dst_mac,
                        "src_vendor": mac_vendor_dict[src_mac],
                        "dst_vendor": mac_vendor_dict[dst_mac],
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "ttl": ttl,
                        "window_size": window_size,
                        "os_name": os_name,
                        "protocol": protocol
                    }

                    # Append the connection information to the list
                    connections.append(connection_dict)
                    outcount += 1
        except Exception as e:
            print(f"Error processing packet: {e}")
            pass


    # Iterate over each ARP table entry
    for ip_address, arp_entry in arp_table.items():
        mac_address, vendor = arp_entry
    # Check if the MAC address is already in the dictionary
    try:
        if mac_address not in vendor_map:
            vendor_map[mac_address] = {
                'vendor_name': vendor,
                'ip_addresses': set([ip_address])  # Store unique IP addresses in a set
            }
    except:
        pass
    else:
        # Add the IP address to the existing MAC address entry
        print(type(vendor_map[mac_address]['ip_addresses']))
        try:
            vendor_map[mac_address]['ip_addresses'].add(ip_address)
        except:
            pass


    # Get the unique assets
    # Convert the vendor map to a list for rendering in the template
    unique_vendors = list(vendor_map.values())
    vendor_plots = [['Vendor', 'Device Count']]
    for i in vendor_map.keys():
        name = vendor_map[i]['vendor_name']
        if not name:
            name = "Unknown"
        vendor_plots.append([name, len(vendor_map[i]['ip_addresses'])])
               
    
    # PACKET ML
    packets_ = rdpcap(filename)
    for packet in packets_:
        if TCP in packet:
            extract_tcp_signature(packet,predicted_device, model, vectorizer)
    print(predicted_device)
    # Convert the list of connections to a pandas dataframe

    # processing connections for the table
    df = pd.DataFrame(connections)
    source_list = list(df[['src_mac', 'src_vendor','src_ip', 'protocol']].values)
    dest_list = list(df[['dst_mac', 'dst_vendor','dst_ip', 'protocol']].values)
    columns = ['MAC', 'Vendor', 'IP', 'Protocol']
    arr = np.concatenate((source_list, dest_list), axis=0)
    combined_df = pd.DataFrame(arr)
    combined_df.columns = columns
    combined_df.drop_duplicates(inplace=True)
    combined_df = combined_df.groupby(['MAC', 'Vendor', 'IP'])['Protocol'].apply(','.join).reset_index()
    combined_df.to_dict('records')
    # Return the connection information
    return protocol_plots, combined_df.to_dict('records'), vendor_plots


# def extract_tcp_signature(packet):
#     tcp = packet[TCP]
#     # print(tcp.options)
#     # tcp_flag = tcp.flags.flagrepr()
#     try:

#         tcp_sign=[]
#         if tcp.options[0][0]=='MSS':
#             # tcp_sign.append(str(tcp.options[0][1]))
#             if TCP in packet:
#                 tcp_sign.append(str(packet[TCP].window))

#             if IP in packet:
#                 ttl=packet[IP].ttl
#                 tcp_sign.append(str(ttl))
#                 tos=packet[IP].tos
#                 tcp_sign.append(str(tos))
#                 tcp_sign.append("M"+str(tcp.options[0][1]))


#                 tcp_flag = tcp.flags.flagrepr()


#                 for option in tcp.options:
#                     if option[0].lower()=="wscale":
#                             window_scaling = option[1]
#                             tcp_sign.append("W"+str(window_scaling))

#         # print(tcp_flag+' '+':'.join(tcp_sign))
#         new_data=[tcp_flag+' '+':'.join(tcp_sign)]
#         new_data_vectorized = vectorizer.transform(new_data)
#         predicted_device_name = model.predict(new_data_vectorized)
#         # print("Predicted Device Name:", predicted_device_name[0])
#         predicted_device.add(predicted_device_name[0])


#     except:
#         pass

def get_os_details(ttl, window_size):
    os_image = ''
    os_name = ''
    if ttl == 64 and window_size == 5840:
        os_name = 'Linux (Kernel 2.4 and 2.6)'
        os_image = 'linux.png'
    elif ttl==64 and window_size==5720:
        os_name = 'Google Linux'
        os_image = 'linux.png'
    elif ttl==64 and window_size==65535:
        os_name='FreeBSD'
        os_image = 'linux.png'
    elif ttl==64 and window_size==16384:
        os_name='OpenBSD'
        os_image = 'linux.png'
    elif ttl==128 and window_size==65535:
        os_name='Windows XP'
        os_image = 'windows_PC.png'
    elif ttl==32 and window_size==8192:
        os_name='Windows 95'
        os_image = 'windows_PC.png'
    elif ttl==128 and window_size==16384:
        os_name='Windows 2000'
        os_image = 'windows_PC.png'
    elif ttl == 128 and window_size == 8192:
        os_name = 'Windows Vista and 7 (Server 2008)'
        os_image = 'windows_PC.png'
    elif ttl==25 and window_size==4128:
        os_name='iOS 12.4 (Cisco Routers)'
        os_image = 'apple_PC.png'
    elif ttl==255 and window_size==8760:
        os_name='Solaris 7'
        os_image = 'pc.png'
    elif ttl==64 and window_size==16384:
        os_name='AIX 4.3'
        os_image = 'pc.png'
    else:
        os_name = 'Unknown'
        os_image = 'pc.png'
    return os_name, os_image