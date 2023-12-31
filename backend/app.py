import html
import json
import os
import time

import xml.etree.ElementTree as ET
from pathlib import Path

import netifaces
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import pyshark
import requests
from flask import Flask, jsonify, render_template, request
from flask_cors import CORS
from flask_cors import CORS, cross_origin
from manuf import manuf
from scapy.all import *
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.metrics import accuracy_score
from sklearn.model_selection import train_test_split
from werkzeug.utils import secure_filename

from helper import *

app = Flask(__name__)
mac_parser = manuf.MacParser()
app.config["UPLOAD_FOLDER"] = "uploads"
cors = CORS(app, support_credentials=True)
app.config["CORS_HEADERS"] = "Content-Type"


# Define the analyze endpoint
@app.route("/analyze", methods=["POST"])
@cross_origin(origin="*", headers=["Content-Type", "Authorization"])
def analyze():
    # Get the uploaded file from the request object
    print(request.files)
    pcap_file = request.files["data"]
    # Save the uploaded file to disk in the UPLOAD_FOLDER directory
    filename = secure_filename(pcap_file.filename)
    pcap_path = Path(app.config['UPLOAD_FOLDER']) / filename
    pcap_file.save(pcap_path)

    predicted_device = set()

    # Process the pcap file
    protocol_counts, connections, vendor_plots = process_pcap(pcap_path.as_posix(), predicted_device)

    # Get the name of the pcap file
    pcap_name = pcap_path.name

    print("=>", pcap_name)

    return_obj = {
        "connections": connections,
        "protocol_plots": protocol_counts,
        "vendor_plots": vendor_plots,
        "predicted_devices": list(predicted_device),
    }

    print(return_obj)
    response = jsonify(return_obj)
    response.headers.add("Access-Control-Allow-Origin", "*")
    response.headers.add("Access-Control-Allow-Headers", "*")
    response.headers.add("Access-Control-Allow-Methods", "*")
    return response


# Define the home endpoint
@app.route("/")
def home():
    interfaces = netifaces.interfaces()
    interfaces = interfaces[::-1]
    return render_template("index.html", interfaces=interfaces)


@app.route("/graph", methods=["POST"])
def graph():
    pcap_file = request.files["pcap-file"]
    filename = secure_filename(pcap_file.filename)
    pcap_file.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))
    pcap_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
    print(pcap_path)
    pcap_name = os.path.basename(pcap_path)
    capture = pyshark.FileCapture(pcap_path)
    edges = {}
    links = set()
    mac_vendor_dict = {}
    unique_protocols = set()
    protocols = set()
    # Create a manuf object to resolve MAC addresses to vendor names
    mac_vendor_resolver = manuf.MacParser()

    os_name = 'Unknown'
    os_image = 'pc.png'
    for packet in capture:
        try:
            layers = list(packet.layers)
            # Check if the packet has an Ethernet layer
            if "ETH Layer" in str(packet.layers):
                # Get the source and destination MAC addresses
                src_mac = packet.eth.src.lower()
                dst_mac = packet.eth.dst.lower()

                # Check if the MAC addresses are already in the dictionary
                if src_mac not in mac_vendor_dict:
                    # Get the vendor name for the source MAC address
                    vendor = mac_vendor_resolver.get_manuf(src_mac)
                    mac_vendor_dict[src_mac] = vendor

                if dst_mac not in mac_vendor_dict:
                    # Get the vendor name for the destination MAC address
                    vendor = mac_vendor_resolver.get_manuf(dst_mac)
                    mac_vendor_dict[dst_mac] = vendor

            if "IP" in str(packet.layers):
                src_ip = packet.ip.src
                dst_ip = packet.ip.dst

                # Get the TTL and Window Size values
                ttl = int(packet.ip.ttl)
                window_size = int(packet.tcp.window_size)

                os_name, os_image = get_os_details(ttl, window_size)

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

    nodes_data = [
        {
            "id": node,
            "label": f"{node} ({html.escape(mac_vendor_dict.get(node, 'Unknown Vendor'))})"
        }
        for node in nodes
    ]

    edges_data = [
        {"from": src, "to": dst, "label": ", ".join(edge_data["label"])}
        for src, dst_data in edges.items()
        for dst, edge_data in dst_data.items()
    ]
    graph_data = {
        "nodes": nodes_data,
        "edges": edges_data,
        "os_name": os_name,
        "os_image": os_image,
    }
    return graph_data


# tcpdump
@app.route("/start_capture", methods=["POST"])
def start_capture():
    interface = request.json["interface"]
    file_name = request.json["file_name"]
    pcap_dir = os.path.join(os.getcwd(), "pcap")
    os.makedirs(pcap_dir, exist_ok=True)
    pcap_file = os.path.join(pcap_dir, file_name)
    os.system(f"sudo tcpdump -i {interface} -w {pcap_file} &")
    return jsonify(
        {
            "message": f"Starting capture on interface {interface} and saving to file {pcap_file}"
        }
    )


@app.route("/stop_capture", methods=["POST"])
def stop_capture():
    os.system("sudo killall tcpdump")
    return jsonify({"message": "Capture stopped."})


@app.route("/cve/<mac>")
def cve(mac):
    vendor = mac_parser.get_manuf(mac)
    pages = request.args.get("pages", default="50", type=int)
    cve_list = lookup_cve(vendor, pages)
    return cve_list


if __name__ == "__main__":
    os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
    app.run("0.0.0.0", debug=True)
