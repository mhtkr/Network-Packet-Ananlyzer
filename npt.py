from scapy.all import sniff
from collections import defaultdict, Counter
import matplotlib.pyplot as plt
from matplotlib.animation import FuncAnimation
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import json
import threading
import tkinter as tk
from tkinter import ttk

# Initialize stats, IP lists, and create figure for Matplotlib
stats = defaultdict(int)
source_ips = []
destination_ips = []
fig, ax = plt.subplots()

# Event to control sniffing
stop_sniff_event = threading.Event()

# Function to reset the packets.json file
def reset_json_file():
    with open('packets.json', 'w') as f:
        f.write('')  # This will overwrite the existing file and clear its content

# Function to update plot with packet stats
def update_plot(frame):
    ax.clear()
    ax.bar(stats.keys(), stats.values())
    ax.set_xlabel('Protocol')
    ax.set_ylabel('Count')
    ax.set_title('Packet Statistics')

# Packet processing function
def packet_callback(packet):
    if stop_sniff_event.is_set():
        return  # Stop sniffing when the event is set

    if packet.haslayer('IP'):
        ip_src = packet['IP'].src
        ip_dst = packet['IP'].dst
        protocol = packet['IP'].proto
        proto_name = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}.get(protocol, 'Unknown')
        print(f'Source IP: {ip_src}, Destination IP: {ip_dst}, Protocol: {proto_name}')
        
        # Update protocol stats
        stats[proto_name] += 1
        source_ips.append(ip_src)
        destination_ips.append(ip_dst)
        
        # Save packet data as JSON
        packet_data = {
            "Source_IP": ip_src,
            "Destination_IP": ip_dst,
            "Protocol": proto_name
        }
        with open('packets.json', 'a') as f:
            json.dump(packet_data, f)
            f.write('\n')

# Function to display traffic distribution by protocol (pie chart)
def display_protocol_distribution():
    protocols = list(stats.keys())
    counts = list(stats.values())
    
    plt.figure(figsize=(6, 6))
    plt.pie(counts, labels=protocols, autopct='%1.1f%%', startangle=90,
            colors=['#ff9999','#66b3ff','#99ff99','#ffcc99'])
    plt.title('Traffic Distribution by Protocol')
    plt.axis('equal')
    plt.show()

# Function to display top 5 IPs (bar chart)
def display_top_ips(ip_list, title):
    counter = Counter(ip_list)
    top_ips = counter.most_common(5)  # Top 5 IPs
    
    if top_ips:
        ips, counts = zip(*top_ips)
    else:
        ips, counts = [], []
    
    plt.figure(figsize=(8, 6))
    plt.bar(ips, counts, color='skyblue')
    plt.xlabel('IP Address')
    plt.ylabel('Packet Count')
    plt.title(title)
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.show()

# Function to generate and display final conclusion with detailed insights
def generate_conclusion():
    if not stats:
        conclusion_text = "No traffic captured."
    else:
        # Determine the most common protocol
        most_common_protocol = max(stats, key=stats.get)
        protocol_count = stats[most_common_protocol]

        # Determine the top source and destination IPs
        top_source_ip = Counter(source_ips).most_common(1)[0][0] if source_ips else 'N/A'
        top_destination_ip = Counter(destination_ips).most_common(1)[0][0] if destination_ips else 'N/A'

        # Provide detailed insights based on the most common protocol
        protocol_insights = {
            'TCP': (
                "TCP (Transmission Control Protocol) is commonly used for reliable communication, "
                "such as web traffic (HTTP/HTTPS), file transfers, and emails. "
                "A predominance of TCP traffic suggests that your network is handling a lot of connection-based communication, "
                "possibly involving web browsing, file downloads, or cloud services."
            ),
            'UDP': (
                "UDP (User Datagram Protocol) is typically used for faster, connectionless communication. "
                "This protocol is often seen in real-time applications like video streaming, online gaming, and voice-over-IP (VoIP). "
                "If your network traffic is mostly UDP, it could indicate frequent use of such services, "
                "which prioritize speed over reliability."
            ),
            'ICMP': (
                "ICMP (Internet Control Message Protocol) is used mainly for diagnostic or control purposes, such as ping and traceroute. "
                "A large amount of ICMP traffic might indicate network troubleshooting activities or automated network monitoring. "
                "However, excessive ICMP traffic could also suggest a potential network issue or even an ICMP-based attack like a ping flood."
            ),
            'Unknown': (
                "Unknown protocol traffic indicates that some packets were using uncommon or less identifiable protocols. "
                "This could be due to proprietary applications or experimental protocols, and it's worth investigating further "
                "if you notice unusual or excessive 'Unknown' traffic."
            )
        }

        # Get the appropriate insight for the most common protocol
        insight = protocol_insights.get(most_common_protocol, "No specific insights available for this protocol.")

        # Build the conclusion text
        conclusion_text = (
            f"Conclusion:\n"
            f"- The most common protocol is {most_common_protocol} with {protocol_count} packets.\n"
            f"- The top source IP address is {top_source_ip}.\n"
            f"- The top destination IP address is {top_destination_ip}.\n"
            f"- Overall, the traffic was predominantly {most_common_protocol}.\n\n"
            f"Traffic Insight:\n{insight}"
        )

    # Display the conclusion in a new Tkinter window
    conclusion_window = tk.Toplevel(root)
    conclusion_window.title("Traffic Conclusion")

    # Create a Text widget to display the conclusion text
    text_widget = tk.Text(conclusion_window, wrap='word', width=60, height=20)
    text_widget.insert('1.0', conclusion_text)
    text_widget.config(state='disabled')  # Make the text read-only
    text_widget.pack(padx=10, pady=10)

    # Add a scrollbar in case the text overflows
    scrollbar = tk.Scrollbar(conclusion_window, command=text_widget.yview)
    text_widget['yscrollcommand'] = scrollbar.set
    scrollbar.pack(side='right', fill='y')

# Function to start sniffing in a separate thread
def start_sniff():
    sniff(prn=packet_callback, store=0, stop_filter=lambda _: stop_sniff_event.is_set())

# Function to start sniffing (triggered by Start button)
def start_sniffing():
    reset_json_file()  # Reset the JSON file before sniffing starts
    global sniff_thread
    stop_sniff_event.clear()  # Clear the stop event before starting sniffing
    sniff_thread = threading.Thread(target=start_sniff)
    sniff_thread.start()

# Function to stop sniffing and show insights
def stop_sniffing():
    stop_sniff_event.set()  # Signal the sniffing thread to stop
    sniff_thread.join()  # Wait for the thread to finish
    
    # Display visual insights after sniffing stops
    display_protocol_distribution()  # Show traffic distribution by protocol
    display_top_ips(source_ips, 'Top 5 Source IPs')  # Show top 5 source IPs
    display_top_ips(destination_ips, 'Top 5 Destination IPs')  # Show top 5 destination IPs
    
    # Generate and display the conclusion
    generate_conclusion()

# Setting up the main GUI window
root = tk.Tk()
root.title("Network Packet Tracer")

# Frame for Matplotlib plot
frame = ttk.Frame(root)
frame.pack(side=tk.TOP, fill=tk.BOTH, expand=1)

# Create a canvas for Matplotlib inside the Tkinter window
canvas = FigureCanvasTkAgg(fig, master=frame)
canvas.get_tk_widget().pack(side=tk.TOP, fill=tk.BOTH, expand=1)

# Start and Stop buttons
button_frame = ttk.Frame(root)
button_frame.pack(side=tk.BOTTOM)

start_button = ttk.Button(button_frame, text="Start Sniffing", command=start_sniffing)
start_button.pack(side=tk.LEFT, padx=10, pady=10)

stop_button = ttk.Button(button_frame, text="Stop Sniffing", command=stop_sniffing)
stop_button.pack(side=tk.RIGHT, padx=10, pady=10)

# Matplotlib animation to update the plot in real-time
ani = FuncAnimation(fig, update_plot, interval=1000, cache_frame_data=False)

# Start the Tkinter event loop
root.mainloop()
