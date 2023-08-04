import os
import sys
from scapy.all import *
from scapy.all import Ether, IP, TCP
from scapy.layers.inet import TCP, UDP, IP
from scapy.layers.tls.record import TLS
from scapy.layers.tls.extensions import ServerName
import datetime
import pandas as pd
from decimal import Decimal, ROUND_HALF_UP
import shutil
import time
import threading
import datetime
from scapy.all import sniff

from scapy.all import conf

class Packet:
    def __init__(self, packets):
        self.packets = packets
        self.dst_mac_list = self.get_dst_mac_list()
        self.src_mac_list = self.get_src_mac_list()
        self.dst_ip_list = self.get_dst_ip_list()
        self.src_ip_list = self.get_src_ip_list()
        self.packets_dictionary = self.get_packet_info()

    def get_packet_info(self):
        for packet in packets:
            if TCP in packet:
                p_dictonary = {
                    'src_ip' : self.src_ip_list,
                    'dest_ip' : self.dst_ip_list
                }

            
                print("Dest IP Address: ", p_dictonary['dest_ip'], "source Ip : ", p_dictonary['src_ip'])
        return p_dictonary
    def get_dst_ip_list(self):
        dst_ip = []
        for packet in packets:
            if IP in packet:
                ip_packet = packet[IP]
                dest_ip = ip_packet.dst

                # 추출된 목적 IP 주소 출력
                #print("Dest IP Address: ", dest_ip)
                dst_ip.append(dest_ip)
        return dst_ip
    
    
    
    
    
    def get_src_ip_list(self):
        # 패킷을 순회하며 IP 패킷의 소스 IP 주소 추출
        src_ip = []
        for packet in self.packets:
            if IP in packet:
                ip_packet = packet[IP]
                source_ip = ip_packet.src

                # 추출된 소스 IP 주소 출력
                #print("Source IP Address: ", source_ip)   
                src_ip.append(source_ip)
        return src_ip
    def get_src_mac_list(self):
        src_mac = []
        for packet in self.packets:
            if Ether in packet:
                eth_packet = packet[Ether]
                source_mac = eth_packet.src

                src_mac.append(source_mac)
                #print("Source MAC: ", source_mac)
        return source_mac
    
    def get_dst_mac_list(self):
        # 패킷을 순회하며 Ethernet 2 패킷의 목적지 MAC 주소 추출
        dst_mac = []
        for packet in self.packets:
            if Ether in packet: # packet에 [Ether, IP, TCP]
                eth_packet = packet[Ether]
                destination_mac = eth_packet.dst

                # 추출된 목적지 MAC 주소 출력
                dst_mac.append(destination_mac)
                #print("Destination MAC: ", destination_mac)
        return dst_mac
    # def process_packet(self):
    #     tls_versions = {
    #         769: "TLS 1.0",
    #         770: "TLS 1.1",
    #         771: "TLS 1.2",
    #         772: "TLS 1.3"
    #     }
    #     for packet in self.packet:
    #         if TCP in packet:
    #             if TLS in packet and (packet[TCP].dport == 443 or packet[TCP].sport == 443):
    #                 # TLS 핸드셰이크 정보 추출
    #                 sni = "N/A"  # 기본값으로 SNI를 "N/A"로 설정
    #                 tls_version = "N/A"  # 기본값으로 TLS 버전을 "N/A"로 설정

    #                 if packet[TLS].haslayer(ServerName):
    #                     sni = packet[TLS][ServerName].servername.decode()
                    
    #                 if packet[TLS].haslayer(TLS):
    #                     tls_version_number = packet[TLS][TLS].version
    #                     tls_version = tls_version(tls_version_number)
                        
    #                 # TCP 헤더 정보 추출
    #                 src_ip = packet[IP].src
    #                 src_port = packet[TCP].sport
    #                 dst_ip = packet[IP].dst
    #                 dst_port = packet[TCP].dport
                    
    #                 # 플로우 식별을 위한 5-tuple 생성
    #                 flow_key = (src_ip, src_port, dst_ip, dst_port)
    #                 reverse_flow_key = (dst_ip, dst_port, src_ip, src_port)  # 반대 방향 플로우의 5-tuple
                    
    #                 # 플로우에 패킷 정보 추가
                    
    #                 if flow_key in self.flows:
    #                     self.flows[flow_key]['forward_packets'] += 1
    #                     self.flows[flow_key]['packet_sizes'].append(len(packet))
    #                     self.flows[flow_key]['packets'].append(packet)
    #                     self.flows[flow_key]['end_time'] = packet.time

                
    #                 elif reverse_flow_key in self.flows:
    #                     self.flows[reverse_flow_key]['backward_packets'] += 1                          
    #                     self.flows[reverse_flow_key]['packet_sizes'].append(-len(packet))
    #                     self.flows[reverse_flow_key]['packets'].append(packet)
    #                     self.flows[reverse_flow_key]['end_time'] = packet.time
    #                 else:
    #                     self.flows[flow_key] = {
    #                         'flow_header': f"Flow : {flow_key}",
    #                         'src_ip': src_ip,
    #                         'src_port': src_port,
    #                         'dst_ip': dst_ip,
    #                         'dst_port': dst_port,
    #                         'protocol': packet[IP].proto,
    #                         'start_time': packet.time,
    #                         'end_time': packet.time,
    #                         'forward_packets': 1,
    #                         'backward_packets': 0,
    #                         'packet_sizes': [len(packet)],
    #                         'packets': [packet],
    #                         'sni': sni,  # SNI 정보 추가
    #                         'tls_version': tls_version  # TLS 버전 정보 추가
    #                     }
    def print_flows(self):
        pass

packets = rdpcap('LIVE1.pcap')
flows = Packet(packets)
print(flows.packets_dictionary)
