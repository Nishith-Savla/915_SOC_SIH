// network.js

document.addEventListener("DOMContentLoaded", function () {
    var container = document.getElementById("network");
    var graphData = JSON.parse(document.getElementById("graph-data").textContent);
  
    var options = {
      nodes: {
        shape: "image",
        image: "/static/windows.png",
        size: 20,
        color: {
          border: "lightgray",
          background: "white",
        },
        font: {
          size: 16,
          face: "Tahoma",
        },
        label: "IP",
        font: {
          size: 12,
          face: "Tahoma",
        },
      },
      edges: {
        length: 200,
        color: {
          color: "lightgray",
        },
        font: {
          size: 12,
          face: "Tahoma",
        },
      },
      physics: {
        enabled: true,
      },
    };
  
    var network = new vis.Network(container, graphData, options);
  });
  