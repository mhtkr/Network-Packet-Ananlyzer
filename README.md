🕵️‍♂️ Network Packet Tracer & Analyzer with Real-Time Visualization 🕸️
An intuitive network traffic analysis tool that captures, visualizes, and analyzes network packets in real-time using Scapy, Tkinter, and Matplotlib. This tool provides live packet sniffing, protocol breakdown, IP analysis, and insights into network behavior with detailed visualizations.

✨ Features
Live Packet Sniffing: Capture network packets in real-time using Scapy.
Real-Time Visualization: Visualize network statistics with dynamic bar charts and pie charts using Matplotlib.
Top IP Address Tracking: Identify the top 5 source and destination IP addresses by traffic volume.
Detailed Traffic Insights: Generate comprehensive traffic summaries and protocol-specific insights.
User-Friendly GUI: A clean and intuitive GUI built with Tkinter for easy interaction.
JSON Packet Logging: Log packet information in a packets.json file for future analysis.

🚀 Getting Started
Prerequisites
Ensure you have the following installed:

Python 3.6+
Scapy: pip install scapy
Matplotlib: pip install matplotlib
Tkinter: Pre-installed with Python, or use your system package manager to install it.

Installation
Clone the repository:

git clone https://github.com/yourusername/network-packet-tracer.git
cd network-packet-tracer
Install the required Python packages:

pip install -r requirements.txt
Run the application:

python packet_tracer.py

🖥️ Usage
Start Sniffing: Press the Start Sniffing button to capture live network traffic.
View Real-Time Stats: Monitor live packet statistics on the bar chart.
Stop Sniffing: Press the Stop Sniffing button to stop capturing and view final insights.
Visualize Protocol Distribution: Pie chart displaying traffic percentage per protocol.
Analyze IPs: Bar charts showing the top 5 source and destination IPs.
View Conclusion: Get detailed insights on the network's traffic pattern, including common protocols and top IPs.

📊 Visualizations
Bar Charts: Protocol counts and top IPs.
Pie Charts: Traffic distribution by protocol.

📜 Conclusion & Insights
At the end of the packet sniffing session, the tool provides a detailed conclusion about the most common protocols, top IP addresses, and insights into traffic patterns. Example insights include:

TCP: High web traffic, reliable communication.
UDP: Real-time applications like video streaming or gaming.
ICMP: Diagnostic activity, potential network troubleshooting.
🔧 Customization
Feel free to modify the following components to fit your specific needs:

Packet Callback Function: Customize packet processing logic in packet_callback() for specialized analysis.
Data Logging: Modify JSON logging in packets.json to capture additional packet details.

🛡️ Future Enhancements
Real-time bandwidth monitoring.
Protocol-specific traffic breakdown (e.g., HTTP, FTP).
Detailed IP geolocation analysis.
Enhanced UI/UX with more customization options.

🛠️ Contributing
Contributions are welcome! Feel free to open issues or submit pull requests to improve the tool. Here's how you can contribute:

Fork the repository.
Create a new branch for your feature/fix: git checkout -b feature-name.
Commit your changes: git commit -m 'Add some feature'.
Push the changes to your branch: git push origin feature-name.
Open a pull request.

🧑‍💻 Author
M O H I T  K U M A R
If you have any questions, feel free to reach out!
