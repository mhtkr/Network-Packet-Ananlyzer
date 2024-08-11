import mysql.connector
from collections import defaultdict
import matplotlib.pyplot as plt
from scapy.all import sniff, IP, TCP

conn = mysql.connector.connect(
    host='localhost',
    user='root',  
    password='9933mk', 
    database='network_traffic'
)
cursor = conn.cursor()

traffic_stats = defaultdict(int)
anomaly_threshold = 50

def packet_callback(packet):
    if packet.haslayer(IP):
        ip_src = packet[IP].src
        traffic_stats[ip_src] += 1

        try:
            cursor.execute('''
                INSERT INTO traffic (src_ip, packet_count)
                VALUES (%s, %s)
                ON DUPLICATE KEY UPDATE
                packet_count = packet_count + 1
            ''', (ip_src, 1))
            conn.commit()
        except mysql.connector.Error as err:
            print(f"Error: {err}")
            conn.rollback()

        if traffic_stats[ip_src] > anomaly_threshold:
            print(f"Anomaly detected: {ip_src} has {traffic_stats[ip_src]} packets")

def visualize_traffic():
    cursor.execute("SELECT src_ip, packet_count FROM traffic")
    result = cursor.fetchall()
    
    ip_addresses = [row[0] for row in result]
    packet_counts = [row[1] for row in result]

    plt.figure(figsize=(10, 5))
    plt.bar(ip_addresses, packet_counts)
    plt.xlabel('IP Addresses')
    plt.ylabel('Packet Count')
    plt.title('Network Traffic Analysis')
    plt.xticks(rotation=45, ha='right')
    plt.tight_layout()
    plt.show()

sniff(prn=packet_callback, count=50)

visualize_traffic()

cursor.close()
conn.close()
