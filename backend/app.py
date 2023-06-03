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

# ML
import xml.etree.ElementTree as ET
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score
import sys 



# ML
dataset_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'datasets', 'dataset.xml')



# Step 1: Data Preparation
tree = ET.parse(dataset_path)
root = tree.getroot()

data = []
labels = []

# Predicted device
predicted_device=set()

for fingerprint in root.findall('fingerprints/fingerprint'):
    fingerprint_name = fingerprint.get('name')
    tcp_tests = fingerprint.find('tcp_tests')
    for test in tcp_tests.findall('test'):
        tcp_flag = test.get('tcpflag')
        tcp_signature = test.get('tcpsig')
        labels.append(fingerprint_name)
        data.append(tcp_flag + ' ' + tcp_signature)
        # print("DATA",data)

# Step 2: Feature Extraction
vectorizer = CountVectorizer()
X = vectorizer.fit_transform(data)

# Step 3: Model Training
X_train, X_test, y_train, y_test = train_test_split(X, labels, test_size=0.25, random_state=42)

model = RandomForestClassifier()
model.fit(X_train, y_train)

# Step 4: Model Evaluation
predictions = model.predict(X_test)
accuracy = accuracy_score(y_test, predictions)
print("Accuracy:", accuracy)



app = Flask(__name__)
mac_parser = manuf.MacParser()
app.config['UPLOAD_FOLDER'] = 'uploads'

# ML MODEL

def extract_tcp_signature(packet):
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
    for packet in packets:
        if ARP in packet:
            arp = packet[ARP]
            vendor = mac_parser.get_manuf_long(arp.hwsrc)
            # vendor="JOKER INC"
            arp_table[arp.psrc] = [arp.hwsrc, vendor]
    return arp_table

# Define the analyze endpoint
@app.route('/analyze', methods=['POST'])
def analyze():
    # Get the uploaded file from the request object
    pcap_file = request.files['pcap-file']
        # Save the uploaded file to disk in the UPLOAD_FOLDER directory
    filename = secure_filename(pcap_file.filename)
    pcap_file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
    pcap_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    arp_table = get_arp_table(pcap_path)
    print(arp_table)


    
    # Process the pcap file
    incount, outcount, connections,plot_html, unique_vendors,len_vendors,predicted_device = process_pcap(pcap_path)

    # Get the name of the pcap file
    pcap_name = os.path.basename(pcap_path) 
      
    # Render the results template with the connection information and the network graph
    # return render_template('results.html', connections=connections, incount=incount, outcount=outcount, arp_table=arp_table,plot_html=plot_html)
    print("=>",pcap_name)
    print("==>",len_vendors)
    return render_template('results.html', connections=connections, incount=incount, outcount=outcount, arp_table=arp_table, plot_html=plot_html, pcap_name=pcap_name, unique_vendors=unique_vendors,len_vendors=len_vendors,predicted_devices=predicted_device)


# Define the home endpoint
@app.route('/')
def home():
    interfaces = netifaces.interfaces()
    interfaces=interfaces[::-1]
    return render_template('index.html',interfaces=interfaces)

def process_pcap(filename):
    # Read the pcap file
    cap = pyshark.FileCapture(filename)
    protocol__count = {}




    ## ARP ADD

    # Get the ARP table
    arp_table = get_arp_table(filename)

    # Graph
    # Create a dictionary to store the nodes
    nodes = {}

    # Create a list to store the links
    links = []




    # All protocols
    all_protocols=set()
    incount=0
    outcount=0
    # Create a manuf object to resolve MAC addresses to vendor names
    mac_vendor_resolver = manuf.MacParser()

    # Draw the plot
    for pkt in cap:
        for layer in pkt.layers:
            protocol_ = layer.layer_name
            protocol__count[protocol_] = protocol__count.get(protocol_, 0) + 1

    # Create a list of protocol_ names and counts
    labels = list(protocol__count.keys())
    values = list(protocol__count.values())

    # Define custom colors for the pie chart
    colors = ['#FFC300', '#FF5733', '#C70039', '#900C3F', '#581845', '#1F271B']

    # Create a pie chart using plotly
    fig = go.Figure(data=[go.Pie(labels=labels, values=values)])
    fig.update_layout(
    title='Protocol Count',
    title_x=0.05,
    title_y=0.99,  # Adjust this parameter to move the title up
    width=1000,
    height=800,
    font=dict(size=24, family='Arial, sans-serif'),
    margin=dict(l=10, r=50, b=50, t=100),
    paper_bgcolor='rgba(0,0,0,0)',
    plot_bgcolor='rgba(0,0,0,0)',
    legend=dict(
        orientation='h',
        y=1.02,
        xanchor='right',
        x=1
    ),


)

    fig.update_traces(
    textposition='inside',
    textinfo='label+percent',
    marker=dict(colors=colors, line=dict(color='#FFFFFF', width=2))
)



    # Convert the plotly figure to HTML format
    plot_html = fig.to_html(full_html=False)


    # Create a dictionary to store the MAC addresses and vendor names
    mac_vendor_dict = {}

    # Initialize a list to store the connections
    connections = []
    # Create a dictionary to store the unique vendor names for each IP address
    vendor_map = {}
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
                        'ip_addresses': set([src_ip])  # Store unique IP addresses in a set
                    }
                else:
                    # Append the IP address to the existing MAC address entry
                    vendor_map[src_mac]['ip_addresses'].append(src_ip)

                



                # Get the TTL and Window Size values
                ttl = int(packet.ip.ttl)
                window_size = int(packet.tcp.window_size)
                
                if ttl == 64 and window_size == 5840:
                    os_name = 'Linux (Kernel 2.4 and 2.6)'
                elif ttl==64 and window_size==5720:
                    os_name = 'Google Linux'
                elif ttl==64 and window_size==65535:
                    os_name='FreeBSD'
                elif ttl==64 and window_size==16384:
                    os_name='OpenBSD'
                elif ttl==128 and window_size==65535:
                    os_name='Windows XP'
                elif ttl==32 and window_size==8192:
                    os_name='Windows 95'
                elif ttl==128 and window_size==16384:
                    os_name='Windows 2000'
                elif ttl == 128 and window_size == 8192:
                    os_name = 'Windows Vista and 7 (Server 2008)'
                elif ttl==25 and window_size==4128:
                    os_name='iOS 12.4 (Cisco Routers)'
                elif ttl==255 and window_size==8760:
                    os_name='Solaris 7'
                elif ttl==64 and window_size==16384:
                    os_name='AIX 4.3'
                else:
                    os_name = 'Unknown'
               
                for layer in layers:
                    all_protocols.add(layer.layer_name)

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
            # print(f"Error processing packet: {e}")
            pass
    print(all_protocols)


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
        vendor_map[mac_address]['ip_addresses'].add(ip_address)


    # Get the unique assets
    # Convert the vendor map to a list for rendering in the template
    unique_vendors = list(vendor_map.values())



    # PREDICT OS USING ML

    def extract_tcp_signature(packet):
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






    # PACKET ML
    packets_ = rdpcap(filename)
    for packet in packets_:
        if TCP in packet:
            extract_tcp_signature(packet)
    print(predicted_device)
    # Convert the list of connections to a pandas dataframe

    df = pd.DataFrame(connections)
    plot_html=plot_html
    # Return the connection information
    return incount, outcount, df.to_dict('records'), plot_html,unique_vendors,len(unique_vendors),predicted_device

@app.route('/graph', methods=['POST'])
def graph():
    pcap_file = request.files["pcap-file"]
    filename = secure_filename(pcap_file.filename)
    pcap_file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
    pcap_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    print(pcap_path)
    pcap_name = os.path.basename(pcap_path) 
    capture = pyshark.FileCapture(pcap_path)
    edges = {}
    links = set()
    mac_vendor_dict = {}
    unique_protocols = set()
    protocols=set()
    # Create a manuf object to resolve MAC addresses to vendor names
    mac_vendor_resolver = manuf.MacParser()
    
    os_name = 'Unknown'
    os_image = 'pc.png'
    vendor_found = False
    for packet in capture:
        try:
            layers = list(packet.layers)
            
            # Check if the packet has an Ethernet layer
            if 'ETH Layer' in str(packet.layers):
                # Get the source and destination MAC addresses
                src_mac = packet.eth.src.lower()
                dst_mac = packet.eth.dst.lower()

                # Check if the MAC addresses are already in the dictionary
                if src_mac not in mac_vendor_dict:
                    # Get the vendor name for the source MAC address
                    vendor = mac_vendor_resolver.get_manuf(src_mac)
                    mac_vendor_dict[src_mac] = vendor
                    # if vendor.lower() == 'netgear' and not vendor_found:
                    #     os_image = 'switch.png'
                    #     vendor_found = True
                    

                if dst_mac not in mac_vendor_dict:
                    # Get the vendor name for the destination MAC address
                    vendor = mac_vendor_resolver.get_manuf(dst_mac)
                    mac_vendor_dict[dst_mac] = vendor
                    # if vendor.lower() == 'netgear' and not vendor_found:
                    #     os_image = 'switch.png'
                    #     vendor_found = True

            if "IP" in str(packet.layers):
                src_ip = packet.ip.src
                dst_ip = packet.ip.dst
               
                # Get the TTL and Window Size values
                ttl = int(packet.ip.ttl)
                window_size = int(packet.tcp.window_size)
                
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
                

                 # Check if the IP addresses are already in the dictionary
                if src_ip not in mac_vendor_dict:
                    # Get the vendor name for the source IP address
                    vendor = mac_vendor_resolver.get_manuf(packet.eth.src)
                    mac_vendor_dict[src_ip] = vendor
                    
                
                if dst_ip not in mac_vendor_dict:
                    # Get the vendor name for the destination IP address
                    vendor = mac_vendor_resolver.get_manuf(packet.eth.dst)
                    mac_vendor_dict[dst_ip] = vendor
                    
                
                # protocols = {layer.layer_name for layer in packet.layers}
                for layer in layers:
                    protocols.add(layer.layer_name)
                protocol = ", ".join(protocols)
                
                if (src_ip, dst_ip, protocol) in links or (dst_ip, src_ip, protocol) in links:
                    continue
                else:
                    links.add((src_ip, dst_ip, protocol))
                    if src_ip in edges and dst_ip in edges[src_ip]:
                        edges[src_ip][dst_ip]["label"].add(protocol)
                    else:
                        if src_ip not in edges:
                            edges[src_ip] = {}
                    edges[src_ip][dst_ip] = {"label": {protocol}}

                
                if src_ip in edges and dst_ip in edges[src_ip]:
                    edges[src_ip][dst_ip]["label"] += ", " + protocol
                else:
                    if src_ip not in edges:
                        edges[src_ip] = {}
                    edges[src_ip][dst_ip] = {"label": protocol}
        except Exception as e:
            print(f"Error processing packet: {e}")
            
    nodes = list(set(list(edges.keys()) + [k for v in edges.values() for k in v.keys()]))
    # nodes_data = [{"id": node, "label": f"{node} ({mac_vendor_dict.get(node, 'Unknown Vendor')})"} for node in nodes]

    nodes_data = [
    {
        "id": node,
        "label": f"{node} ({html.escape(mac_vendor_dict.get(node, 'Unknown Vendor'))})"
       
    }
    for node in nodes
]
       

    # edges_data = [{"from": src, "to": dst, "label": edge_data["label"]} for src, dst_data in edges.items() for dst, edge_data in dst_data.items()]
    edges_data = [
    {"from": src, "to": dst, "label": ", ".join(edge_data["label"])}
    for src, dst_data in edges.items()
    for dst, edge_data in dst_data.items()
]


    graph_data = {
        "nodes": nodes_data,
        "edges": edges_data,
        "os_name": os_name,
        "os_image": os_image
    }

    return render_template("network.html", graph_data=graph_data, pcap_name=pcap_name)



# tcpdump
@app.route('/start_capture', methods=['POST'])
def start_capture():
    interface = request.json['interface']
    file_name = request.json['file_name']
    pcap_dir = os.path.join(os.getcwd(), 'pcap')
    os.makedirs(pcap_dir, exist_ok=True)
    pcap_file = os.path.join(pcap_dir, file_name)
    os.system(f'sudo tcpdump -i {interface} -w {pcap_file} &')
    return jsonify({'message': f'Starting capture on interface {interface} and saving to file {pcap_file}'})

@app.route('/stop_capture', methods=['POST'])
def stop_capture():
    os.system('sudo killall tcpdump')
    return jsonify({'message': 'Capture stopped.'})


@app.route('/cve/<vendor>')
def cve(vendor):
    pages = request.args.get('pages', default='50', type=int)
    cve_list = lookup_cve(vendor, pages)
    return render_template('cve.html', vendor=vendor, cve_list=cve_list)


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


if __name__ == '__main__':
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    app.run(debug=True)
