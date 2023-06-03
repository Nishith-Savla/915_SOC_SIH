import xml.etree.ElementTree as ET
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.tree import DecisionTreeClassifier
from sklearn.metrics import accuracy_score
from scapy.all import *
import sys

# Step 1: Data Preparation
tree = ET.parse('dataset.xml')
root = tree.getroot()

data = []
labels = []

for fingerprint in root.findall('fingerprints/fingerprint'):
    fingerprint_name = fingerprint.get('name')
    tcp_tests = fingerprint.find('tcp_tests')
    for test in tcp_tests.findall('test'):
        tcp_flag = test.get('tcpflag')
        tcp_signature = test.get('tcpsig')
        labels.append(fingerprint_name)
        data.append(tcp_flag + ' ' + tcp_signature)

# Step 2: Feature Extraction
vectorizer = CountVectorizer()
X = vectorizer.fit_transform(data)

# Step 3: Model Training
model = DecisionTreeClassifier()  # Use DecisionTreeClassifier
model.fit(X, labels)

# Step 4: Model Evaluation
predictions = model.predict(X)
accuracy = accuracy_score(labels, predictions)
print("Accuracy:", accuracy)

# Step 5: Model Deployment

# Example prediction
new_tcp_flag = "SA"
new_tcp_signature = "32768:128:1:M1460:W0"
new_data = [new_tcp_flag + ' ' + new_tcp_signature]
new_data_vectorized = vectorizer.transform(new_data)
predicted_device_name = model.predict(new_data_vectorized)
print("Predicted Device Name:", predicted_device_name[0])
