import React from 'react'

const StaticGraph = () => {
    const html = `
    <html>
    <head>
        <meta charset="utf-8">
        
            <script src="lib/bindings/utils.js"></script>
            <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/vis-network/9.1.2/dist/dist/vis-network.min.css" integrity="sha512-WgxfT5LWjfszlPHXRmBWHkV2eceiWTOBvrKCNbdgDYTHrT2AeLCGbF4sZlZw3UMN3WtL0tGUoIAKsu8mllg/XA==" crossorigin="anonymous" referrerpolicy="no-referrer" />
            <script src="https://cdnjs.cloudflare.com/ajax/libs/vis-network/9.1.2/dist/vis-network.min.js" integrity="sha512-LnvoEWDFrqGHlHmDD2101OrLcbsfkrzoSpvtSQtxK3RMnRV0eOkhhBN2dXHKRrUU8p2DGRTk35n4O8nWSVe1mQ==" crossorigin="anonymous" referrerpolicy="no-referrer"></script>
            
        
<center>
<h1></h1>
</center>

<!-- <link rel="stylesheet" href="../node_modules/vis/dist/vis.min.css" type="text/css" />
<script type="text/javascript" src="../node_modules/vis/dist/vis.js"> </script>-->
        <link
          href="https://cdn.jsdelivr.net/npm/bootstrap@5.0.0-beta3/dist/css/bootstrap.min.css"
          rel="stylesheet"
          integrity="sha384-eOJMYsd53ii+scO/bJGFsiCZc+5NDVN2yr8+0RDqr0Ql0h+rP48ckxlpbzKgwra6"
          crossorigin="anonymous"
        />
        <script
          src="https://cdn.jsdelivr.net/npm/bootstrap@5.0.0-beta3/dist/js/bootstrap.bundle.min.js"
          integrity="sha384-JEW9xMcG8R+pH31jmWH6WWP0WintQrMb4s7ZOdauHnUtxwoG2vI5DkLtS3qm9Ekf"
          crossorigin="anonymous"
        ></script>


        <center>
          <h1></h1>
        </center>
        <style type="text/css">

             #mynetwork {
                 width: 100%;
                 height: 750px;
                 background-color: #222222;
                 border: 1px solid lightgray;
                 position: relative;
                 float: left;
             }

             

             
             #config {
                 float: left;
                 width: 400px;
                 height: 600px;
             }
             

             
        </style>
    </head>


    <body>
        <div class="card" style="width: 100%">
            
            
            <div id="mynetwork" class="card-body"></div>
        </div>

        
        
            <div id="config"></div>
        

        <script type="text/javascript">

              // initialize global variables.
              var edges;
              var nodes;
              var allNodes;
              var allEdges;
              var nodeColors;
              var originalNodes;
              var network;
              var container;
              var options, data;
              var filter = {
                  item : '',
                  property : '',
                  value : []
              };

              

              

              // This method is responsible for drawing the graph, returns the drawn network
              function drawGraph() {
                  var container = document.getElementById('mynetwork');

                  

                  // parsing and collecting nodes and edges from the python
                  nodes = new vis.DataSet([{"color": "yellow", "font": {"color": "white"}, "id": "172.16.0.79\n08.f1.ea.6d.c0.94\nHewlett Packard Enterprise", "label": "172.16.0.79\n08.f1.ea.6d.c0.94\nHewlett Packard Enterprise", "shape": "dot", "title": "172.16.0.79\n08.f1.ea.6d.c0.94\nHewlett Packard Enterprise"}, {"color": "yellow", "font": {"color": "white"}, "id": "172.16.0.20\n00.00.54.32.75.ca\nSchneider Electric", "label": "172.16.0.20\n00.00.54.32.75.ca\nSchneider Electric", "shape": "dot", "title": "172.16.0.20\n00.00.54.32.75.ca\nSchneider Electric"}, {"color": "yellow", "font": {"color": "white"}, "id": "172.16.0.80\n08.f1.ea.7d.3e.64\nHewlett Packard Enterprise", "label": "172.16.0.80\n08.f1.ea.7d.3e.64\nHewlett Packard Enterprise", "shape": "dot", "title": "172.16.0.80\n08.f1.ea.7d.3e.64\nHewlett Packard Enterprise"}, {"color": "yellow", "font": {"color": "white"}, "id": "172.16.0.25\n5c.88.16.ac.61.a9\nRockwell Automation", "label": "172.16.0.25\n5c.88.16.ac.61.a9\nRockwell Automation", "shape": "dot", "title": "172.16.0.25\n5c.88.16.ac.61.a9\nRockwell Automation"}, {"color": "yellow", "font": {"color": "white"}, "id": "fe80..9418.3620.1d8.4f5c\n08.f1.ea.7d.b4.a8\nHewlett Packard Enterprise", "label": "fe80..9418.3620.1d8.4f5c\n08.f1.ea.7d.b4.a8\nHewlett Packard Enterprise", "shape": "dot", "title": "fe80..9418.3620.1d8.4f5c\n08.f1.ea.7d.b4.a8\nHewlett Packard Enterprise"}, {"color": "yellow", "font": {"color": "white"}, "id": "33.33.00.01.00.02\nPossibleGateway", "label": "33.33.00.01.00.02\nPossibleGateway", "shape": "dot", "title": "33.33.00.01.00.02\nPossibleGateway"}, {"color": "yellow", "font": {"color": "white"}, "id": "172.16.1.107\na4.b4.39.57.4b.44\nCisco Systems, Inc", "label": "172.16.1.107\na4.b4.39.57.4b.44\nCisco Systems, Inc", "shape": "dot", "title": "172.16.1.107\na4.b4.39.57.4b.44\nCisco Systems, Inc"}, {"color": "yellow", "font": {"color": "white"}, "id": "01.00.5e.00.00.fb\nPossibleGateway", "label": "01.00.5e.00.00.fb\nPossibleGateway", "shape": "dot", "title": "01.00.5e.00.00.fb\nPossibleGateway"}, {"color": "yellow", "font": {"color": "white"}, "id": "172.16.0.5\n9c.7b.ef.28.87.81\nHewlett Packard", "label": "172.16.0.5\n9c.7b.ef.28.87.81\nHewlett Packard", "shape": "dot", "title": "172.16.0.5\n9c.7b.ef.28.87.81\nHewlett Packard"}, {"color": "yellow", "font": {"color": "white"}, "id": "239.255.255.250\n01.00.5e.7f.ff.fa\nUnknown", "label": "239.255.255.250\n01.00.5e.7f.ff.fa\nUnknown", "shape": "dot", "title": "239.255.255.250\n01.00.5e.7f.ff.fa\nUnknown"}, {"color": "yellow", "font": {"color": "white"}, "id": "10.8.0.22\n00.22.e5.24.1c.dd\nFisher-Rosemount Systems Inc.", "label": "10.8.0.22\n00.22.e5.24.1c.dd\nFisher-Rosemount Systems Inc.", "shape": "dot", "title": "10.8.0.22\n00.22.e5.24.1c.dd\nFisher-Rosemount Systems Inc."}, {"color": "yellow", "font": {"color": "white"}, "id": "172.16.0.255\nff.ff.ff.ff.ff.ff\nUnknown", "label": "172.16.0.255\nff.ff.ff.ff.ff.ff\nUnknown", "shape": "dot", "title": "172.16.0.255\nff.ff.ff.ff.ff.ff\nUnknown"}, {"color": "yellow", "font": {"color": "white"}, "id": "172.16.0.24\n00.00.54.32.75.d4\nSchneider Electric", "label": "172.16.0.24\n00.00.54.32.75.d4\nSchneider Electric", "shape": "dot", "title": "172.16.0.24\n00.00.54.32.75.d4\nSchneider Electric"}, {"color": "yellow", "font": {"color": "white"}, "id": "fe80..a6b4.39ff.fe57.4b61\na4.b4.39.57.4b.61\nCisco Systems, Inc", "label": "fe80..a6b4.39ff.fe57.4b61\na4.b4.39.57.4b.61\nCisco Systems, Inc", "shape": "dot", "title": "fe80..a6b4.39ff.fe57.4b61\na4.b4.39.57.4b.61\nCisco Systems, Inc"}, {"color": "yellow", "font": {"color": "white"}, "id": "172.16.0.76\n9c.7b.ef.28.87.72\nHewlett Packard", "label": "172.16.0.76\n9c.7b.ef.28.87.72\nHewlett Packard", "shape": "dot", "title": "172.16.0.76\n9c.7b.ef.28.87.72\nHewlett Packard"}, {"color": "yellow", "font": {"color": "white"}, "id": "172.16.0.10\n28.e9.8e.2c.36.2d\nMitsubishi Electric Corporation", "label": "172.16.0.10\n28.e9.8e.2c.36.2d\nMitsubishi Electric Corporation", "shape": "dot", "title": "172.16.0.10\n28.e9.8e.2c.36.2d\nMitsubishi Electric Corporation"}, {"color": "yellow", "font": {"color": "white"}, "id": "172.16.0.70\n08.00.27.22.46.4f\nPCS Systemtechnik GmbH", "label": "172.16.0.70\n08.00.27.22.46.4f\nPCS Systemtechnik GmbH", "shape": "dot", "title": "172.16.0.70\n08.00.27.22.46.4f\nPCS Systemtechnik GmbH"}, {"color": "yellow", "font": {"color": "white"}, "id": "172.16.0.40\ne0.dc.a0.80.77.2a\nSiemens Industrial Automation Products Ltd Chengdu", "label": "172.16.0.40\ne0.dc.a0.80.77.2a\nSiemens Industrial Automation Products Ltd Chengdu", "shape": "dot", "title": "172.16.0.40\ne0.dc.a0.80.77.2a\nSiemens Industrial Automation Products Ltd Chengdu"}, {"color": "yellow", "font": {"color": "white"}, "id": "01.00.5e.00.00.01\nPossibleGateway", "label": "01.00.5e.00.00.01\nPossibleGateway", "shape": "dot", "title": "01.00.5e.00.00.01\nPossibleGateway"}, {"color": "yellow", "font": {"color": "white"}, "id": "172.16.0.249\nd8.9e.f3.80.0f.8c\nDell Inc.", "label": "172.16.0.249\nd8.9e.f3.80.0f.8c\nDell Inc.", "shape": "dot", "title": "172.16.0.249\nd8.9e.f3.80.0f.8c\nDell Inc."}, {"color": "yellow", "font": {"color": "white"}, "id": "4c.71.0d.79.85.46\nPossibleGateway", "label": "4c.71.0d.79.85.46\nPossibleGateway", "shape": "dot", "title": "4c.71.0d.79.85.46\nPossibleGateway"}]);
                  edges = new vis.DataSet([{"arrows": "to", "color": "brown", "from": "172.16.0.79\n08.f1.ea.6d.c0.94\nHewlett Packard Enterprise", "smooth": {"roundness": 0.3333333333333333, "type": "curvedCW"}, "title": "UnknownProtocol/502: 172.16.0.20", "to": "172.16.0.20\n00.00.54.32.75.ca\nSchneider Electric"}, {"arrows": "to", "color": "brown", "from": "172.16.0.80\n08.f1.ea.7d.3e.64\nHewlett Packard Enterprise", "smooth": {"roundness": 0.6666666666666666, "type": "curvedCW"}, "title": "UnknownProtocol/502: 172.16.0.20", "to": "172.16.0.20\n00.00.54.32.75.ca\nSchneider Electric"}, {"arrows": "to", "color": "brown", "from": "172.16.0.25\n5c.88.16.ac.61.a9\nRockwell Automation", "smooth": {"roundness": 1.0, "type": "curvedCW"}, "title": "UnknownProtocol/502: 172.16.0.20", "to": "172.16.0.20\n00.00.54.32.75.ca\nSchneider Electric"}, {"arrows": "to", "color": "brown", "from": "fe80..9418.3620.1d8.4f5c\n08.f1.ea.7d.b4.a8\nHewlett Packard Enterprise", "smooth": {"roundness": 1.3333333333333333, "type": "curvedCW"}, "title": "UnknownProtocol/547: ff02..1.2", "to": "33.33.00.01.00.02\nPossibleGateway"}, {"arrows": "to", "color": "brown", "from": "172.16.1.107\na4.b4.39.57.4b.44\nCisco Systems, Inc", "smooth": {"roundness": 1.6666666666666667, "type": "curvedCW"}, "title": "UnknownProtocol/5353: 224.0.0.251", "to": "01.00.5e.00.00.fb\nPossibleGateway"}, {"arrows": "to", "color": "brown", "from": "172.16.0.5\n9c.7b.ef.28.87.81\nHewlett Packard", "smooth": {"roundness": 2.0, "type": "curvedCW"}, "title": "UnknownProtocol/1900: 239.255.255.250", "to": "239.255.255.250\n01.00.5e.7f.ff.fa\nUnknown"}, {"arrows": "to", "color": "brown", "from": "10.8.0.22\n00.22.e5.24.1c.dd\nFisher-Rosemount Systems Inc.", "smooth": {"roundness": 2.3333333333333335, "type": "curvedCW"}, "title": "UnknownProtocol/18510: 255.255.255.255", "to": "172.16.0.255\nff.ff.ff.ff.ff.ff\nUnknown"}, {"arrows": "to", "color": "#9A2EFE", "from": "172.16.0.24\n00.00.54.32.75.d4\nSchneider Electric", "smooth": {"roundness": 0.25, "type": "curvedCW"}, "title": "ClearTextProtocol/69: 172.16.0.20", "to": "172.16.0.20\n00.00.54.32.75.ca\nSchneider Electric"}, {"arrows": "to", "color": "brown", "from": "172.16.0.24\n00.00.54.32.75.d4\nSchneider Electric", "smooth": {"roundness": 2.6666666666666665, "type": "curvedCW"}, "title": "UnknownProtocol/61092: 172.16.0.24", "to": "172.16.0.20\n00.00.54.32.75.ca\nSchneider Electric"}, {"arrows": "to", "color": "brown", "from": "fe80..a6b4.39ff.fe57.4b61\na4.b4.39.57.4b.61\nCisco Systems, Inc", "smooth": {"roundness": 3.0, "type": "curvedCW"}, "title": "UnknownProtocol/547: ff02..1.2", "to": "33.33.00.01.00.02\nPossibleGateway"}, {"arrows": "to", "color": "brown", "from": "172.16.0.76\n9c.7b.ef.28.87.72\nHewlett Packard", "smooth": {"roundness": 3.3333333333333335, "type": "curvedCW"}, "title": "UnknownProtocol/1740: 172.16.0.255", "to": "172.16.0.255\nff.ff.ff.ff.ff.ff\nUnknown"}, {"arrows": "to", "color": "brown", "from": "172.16.0.76\n9c.7b.ef.28.87.72\nHewlett Packard", "smooth": {"roundness": 3.6666666666666665, "type": "curvedCW"}, "title": "UnknownProtocol/1741: 172.16.0.255", "to": "172.16.0.255\nff.ff.ff.ff.ff.ff\nUnknown"}, {"arrows": "to", "color": "brown", "from": "172.16.0.76\n9c.7b.ef.28.87.72\nHewlett Packard", "smooth": {"roundness": 4.0, "type": "curvedCW"}, "title": "UnknownProtocol/1742: 172.16.0.255", "to": "172.16.0.255\nff.ff.ff.ff.ff.ff\nUnknown"}, {"arrows": "to", "color": "brown", "from": "172.16.0.76\n9c.7b.ef.28.87.72\nHewlett Packard", "smooth": {"roundness": 4.333333333333333, "type": "curvedCW"}, "title": "UnknownProtocol/1743: 172.16.0.255", "to": "172.16.0.255\nff.ff.ff.ff.ff.ff\nUnknown"}, {"arrows": "to", "color": "brown", "from": "172.16.0.10\n28.e9.8e.2c.36.2d\nMitsubishi Electric Corporation", "smooth": {"roundness": 4.666666666666667, "type": "curvedCW"}, "title": "UnknownProtocol/502: 172.16.0.10", "to": "172.16.0.80\n08.f1.ea.7d.3e.64\nHewlett Packard Enterprise"}, {"arrows": "to", "color": "green", "from": "172.16.0.70\n08.00.27.22.46.4f\nPCS Systemtechnik GmbH", "smooth": {"roundness": 0.08333333333333333, "type": "curvedCW"}, "title": "HTTP: 172.16.0.40: ", "to": "172.16.0.40\ne0.dc.a0.80.77.2a\nSiemens Industrial Automation Products Ltd Chengdu"}, {"arrows": "to", "color": "brown", "from": "172.16.0.5\n9c.7b.ef.28.87.81\nHewlett Packard", "smooth": {"roundness": 5.0, "type": "curvedCW"}, "title": "UnknownProtocol/1740: 172.16.0.255", "to": "172.16.0.255\nff.ff.ff.ff.ff.ff\nUnknown"}, {"arrows": "to", "color": "brown", "from": "172.16.0.5\n9c.7b.ef.28.87.81\nHewlett Packard", "smooth": {"roundness": 5.333333333333333, "type": "curvedCW"}, "title": "UnknownProtocol/1741: 172.16.0.255", "to": "172.16.0.255\nff.ff.ff.ff.ff.ff\nUnknown"}, {"arrows": "to", "color": "brown", "from": "172.16.0.5\n9c.7b.ef.28.87.81\nHewlett Packard", "smooth": {"roundness": 5.666666666666667, "type": "curvedCW"}, "title": "UnknownProtocol/1742: 172.16.0.255", "to": "172.16.0.255\nff.ff.ff.ff.ff.ff\nUnknown"}, {"arrows": "to", "color": "brown", "from": "172.16.0.5\n9c.7b.ef.28.87.81\nHewlett Packard", "smooth": {"roundness": 6.0, "type": "curvedCW"}, "title": "UnknownProtocol/1743: 172.16.0.255", "to": "172.16.0.255\nff.ff.ff.ff.ff.ff\nUnknown"}, {"arrows": "to", "color": "purple", "from": "fe80..a6b4.39ff.fe57.4b61\na4.b4.39.57.4b.61\nCisco Systems, Inc", "smooth": {"roundness": 0.16666666666666666, "type": "curvedCCW"}, "title": "ICMP: 224.0.0.1", "to": "01.00.5e.00.00.01\nPossibleGateway"}, {"arrows": "to", "color": "brown", "from": "172.16.0.80\n08.f1.ea.7d.3e.64\nHewlett Packard Enterprise", "smooth": {"roundness": 6.333333333333333, "type": "curvedCW"}, "title": "UnknownProtocol/547: ff02..1.2", "to": "33.33.00.01.00.02\nPossibleGateway"}, {"arrows": "to", "color": "brown", "from": "172.16.1.107\na4.b4.39.57.4b.44\nCisco Systems, Inc", "smooth": {"roundness": 6.666666666666667, "type": "curvedCW"}, "title": "UnknownProtocol/547: ff02..1.2", "to": "33.33.00.01.00.02\nPossibleGateway"}, {"arrows": "to", "color": "brown", "from": "172.16.0.24\n00.00.54.32.75.d4\nSchneider Electric", "smooth": {"roundness": 7.0, "type": "curvedCW"}, "title": "UnknownProtocol/61093: 172.16.0.24", "to": "172.16.0.20\n00.00.54.32.75.ca\nSchneider Electric"}, {"arrows": "to", "color": "brown", "from": "172.16.0.249\nd8.9e.f3.80.0f.8c\nDell Inc.", "smooth": {"roundness": 7.333333333333333, "type": "curvedCW"}, "title": "UnknownProtocol/137: 172.16.0.255", "to": "172.16.0.255\nff.ff.ff.ff.ff.ff\nUnknown"}, {"arrows": "to", "color": "pink", "from": "172.16.0.70\n08.00.27.22.46.4f\nPCS Systemtechnik GmbH", "smooth": {"roundness": 0.2, "type": "curvedCW"}, "title": "DNS: 8.8.8.8", "to": "4c.71.0d.79.85.46\nPossibleGateway"}, {"arrows": "to", "color": "brown", "from": "172.16.0.24\n00.00.54.32.75.d4\nSchneider Electric", "smooth": {"roundness": 7.666666666666667, "type": "curvedCW"}, "title": "UnknownProtocol/61094: 172.16.0.24", "to": "172.16.0.20\n00.00.54.32.75.ca\nSchneider Electric"}, {"arrows": "to", "color": "brown", "from": "172.16.0.79\n08.f1.ea.6d.c0.94\nHewlett Packard Enterprise", "smooth": {"roundness": 8.0, "type": "curvedCW"}, "title": "UnknownProtocol/138: 172.16.0.255", "to": "172.16.0.255\nff.ff.ff.ff.ff.ff\nUnknown"}, {"arrows": "to", "color": "brown", "from": "172.16.0.24\n00.00.54.32.75.d4\nSchneider Electric", "smooth": {"roundness": 8.333333333333334, "type": "curvedCW"}, "title": "UnknownProtocol/61095: 172.16.0.24", "to": "172.16.0.20\n00.00.54.32.75.ca\nSchneider Electric"}]);

                  nodeColors = {};
                  allNodes = nodes.get({ returnType: "Object" });
                  for (nodeId in allNodes) {
                    nodeColors[nodeId] = allNodes[nodeId].color;
                  }
                  allEdges = edges.get({ returnType: "Object" });
                  // adding nodes and edges to the graph
                  data = {nodes: nodes, edges: edges};

                  var options = {
    "configure": {
        "enabled": true,
        "filter": [
            "physics"
        ]
    },
    "edges": {
        "color": {
            "inherit": true
        },
        "smooth": {
            "enabled": true,
            "type": "dynamic"
        }
    },
    "interaction": {
        "dragNodes": true,
        "hideEdgesOnDrag": false,
        "hideNodesOnDrag": false
    },
    "physics": {
        "barnesHut": {
            "avoidOverlap": 0,
            "centralGravity": 0.3,
            "damping": 0.09,
            "gravitationalConstant": -80000,
            "springConstant": 0.001,
            "springLength": 250
        },
        "enabled": true,
        "stabilization": {
            "enabled": true,
            "fit": true,
            "iterations": 1000,
            "onlyDynamicEdges": false,
            "updateInterval": 50
        }
    }
};

                  


                  
                  // if this network requires displaying the configure window,
                  // put it in its div
                  options.configure["container"] = document.getElementById("config");
                  

                  network = new vis.Network(container, data, options);

                  

                  

                  


                  

                  return network;

              }
              drawGraph();
        </script>
    </body>
</html>
    
    
    `;
    return <div dangerouslySetInnerHTML={{ __html: html }}/>;
  }

export default StaticGraph;