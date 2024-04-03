"""Utility functions to read pcaps and convert to different structures for data analytics"""

import pandas as pd
import numpy as np
import dpkt

from collections import defaultdict
from scapy.all import *


def pcap_to_dataframe(pcap_reader: PcapReader) -> pd.DataFrame:
    """Converts raw packet capture to a Pandas dataframe.

    Args:
        pcap_reader (PcapReader): packet capture read using scapy

    Returns:
        pd.DataFrame: dataframe with pcap data
    """
    # Create an empty list to store the data
    data = []

    # Iterate through the packets in the pcap file
    for packet in pcap_reader:
        # Get the source and destination IP addresses
        if packet.haslayer(IP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            protocol = packet[IP].proto
        else:
            src_ip = None
            dst_ip = None
            protocol = None

        # Get the source and destination ports and payload
        if packet.haslayer(TCP):
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            payload = str(packet[TCP].payload)
            packet_len = len(packet[TCP])
        elif packet.haslayer(UDP):
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            payload = str(packet[UDP].payload)
            packet_len = len(packet[UDP])
        elif packet.haslayer(ICMP):
            payload = str(packet[ICMP].payload)
            packet_len = len(packet[ICMP])
            src_port = None
            dst_port = None
        else:
            src_port = None
            dst_port = None
            payload = str(packet.payload)
            packet_len = len(packet)

        # Append the data to the list
        data.append(
            [
                packet.time,
                src_ip,
                dst_ip,
                src_port,
                dst_port,
                payload,
                packet_len,
                protocol,
            ]
        )

    # Convert the list to a pandas dataframe
    df = pd.DataFrame(
        data,
        columns=[
            "Timestamp",
            "Source IP",
            "Destination IP",
            "Source Port",
            "Destination Port",
            "Payload",
            "Packet Length",
            "Protocol",
        ],
    )

    return df


def extract_flows(pcap_file):
    packets = rdpcap(pcap_file)
    flows = {}

    for packet in packets:
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            src_port = packet[IP].sport
            dst_port = packet[IP].dport
            flow_key = (src_ip, src_port, dst_ip, dst_port)

            if flow_key not in flows:
                flows[flow_key] = []

            flows[flow_key].append(packet)

    return flows

def extract_conversation(packet_capture_file):
    conversations = defaultdict(bytes)
    
    with open(packet_capture_file, 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
        for timestamp, buf in pcap:
            eth = dpkt.ethernet.Ethernet(buf)
            if isinstance(eth.data, dpkt.ip.IP):
                ip = eth.data
                if isinstance(ip.data, dpkt.tcp.TCP):
                    tcp = ip.data
                    key = (ip.src, tcp.sport, ip.dst, tcp.dport)
                    conversations[key] += tcp.data
                elif isinstance(ip.data, dpkt.udp.UDP):
                    udp = ip.data
                    key = (ip.src, udp.sport, ip.dst, udp.dport)
                    conversations[key] += udp.data
    
    return conversations

# def main():
#     packet_capture_file = 'your_packet_capture.pcap'
#     conversations = extract_conversation(packet_capture_file)
    
#     # Example: Print the contents of a specific conversation
#     for key, data in conversations.items():
#         src_ip, src_port, dst_ip, dst_port = key
#         print(f"Conversation between {src_ip}:{src_port} and {dst_ip}:{dst_port}")
#         print(data)

# if __name__ == "__main__":
#     main()
