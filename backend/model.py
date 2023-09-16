import html
import os
import pickle
import sys
import time

import xml.etree.ElementTree as ET
from pathlib import Path

import netifaces
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import pyshark
import requests
from flask import Flask, render_template, request, jsonify
from manuf import manuf
from scapy.all import *
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.metrics import accuracy_score
from sklearn.model_selection import train_test_split
from werkzeug.utils import secure_filename

from helper import *

# ML
dataset_path = Path(__file__).absolute().parent / "datasets/dataset.xml"

# Step 1: Data Preparation
tree = ET.parse(dataset_path)
root = tree.getroot()

data = []
labels = []

# Predicted device
predicted_device = set()

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
data = {
    'model': model,
    'vectorizer': vectorizer
}
store_data(data, "AssetIdentification.pickle")
