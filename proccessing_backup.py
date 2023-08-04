import os
import sys
import xml.etree.ElementTree as ET
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

# scapy 최적화 옵션 설정
conf.ipv6_enabled = False  # IPv6 비활성화
conf.sniff_promisc = False  # Promiscuous 모드 비활성화
conf.use_pcap = True  # pcap 사용 활성화

def process_packets_thread(packets):
    for packet in packets:
        process_packet(packet)

def createDirectory(directory):
    try:
        if not os.path.exists(directory):
            os.makedirs(directory)
    except OSError:
        print("Error: Failed to create the directory.")

def get_flow_time_range(packets):
    start_time = packets[0].time
    end_time = packets[-1].time

    for packet in packets:
        if packet.time < start_time:
            start_time = packet.time
        if packet.time > end_time:
            end_time = packet.time

    return start_time, end_time


flows = {}  # 플로우를 저장할 딕셔너리

def map_tls_version(version):
    tls_versions = {
        769: "TLS 1.0",
        770: "TLS 1.1",
        771: "TLS 1.2",
        772: "TLS 1.3"
    }
    return tls_versions.get(version, "Unknown")

# 패킷 처리 루프 최적화를 위한 스레드 수
num_threads = 8

# 패킷 처리 스레드의 작업 함수
def process_packets_thread(packets):
    for packet in packets:
        process_packet(packet)

def process_packet(packet):
    if TCP in packet:
        if TLS in packet and (packet[TCP].dport == 443 or packet[TCP].sport == 443):
            # TLS 핸드셰이크 정보 추출
            sni = "N/A"  # 기본값으로 SNI를 "N/A"로 설정
            tls_version = "N/A"  # 기본값으로 TLS 버전을 "N/A"로 설정

            if packet[TLS].haslayer(ServerName):
                sni = packet[TLS][ServerName].servername.decode()
            
            if packet[TLS].haslayer(TLS):
                tls_version_number = packet[TLS][TLS].version
                tls_version = map_tls_version(tls_version_number)
                
            # TCP 헤더 정보 추출
            src_ip = packet[IP].src
            src_port = packet[TCP].sport
            dst_ip = packet[IP].dst
            dst_port = packet[TCP].dport
            
            # 플로우 식별을 위한 5-tuple 생성
            flow_key = (src_ip, src_port, dst_ip, dst_port)
            reverse_flow_key = (dst_ip, dst_port, src_ip, src_port)  # 반대 방향 플로우의 5-tuple
            
            # 플로우에 패킷 정보 추가
            
            if flow_key in flows:
                flows[flow_key]['forward_packets'] += 1
                flows[flow_key]['packet_sizes'].append(len(packet))
                flows[flow_key]['packets'].append(packet)
                flows[flow_key]['end_time'] = packet.time

           
            elif reverse_flow_key in flows:
                flows[reverse_flow_key]['backward_packets'] += 1                          
                flows[reverse_flow_key]['packet_sizes'].append(-len(packet))
                flows[reverse_flow_key]['packets'].append(packet)
                flows[reverse_flow_key]['end_time'] = packet.time
            else:
                flows[flow_key] = {
                    'flow_header': f"Flow : {flow_key}",
                    'src_ip': src_ip,
                    'src_port': src_port,
                    'dst_ip': dst_ip,
                    'dst_port': dst_port,
                    'protocol': packet[IP].proto,
                    'start_time': packet.time,
                    'end_time': packet.time,
                    'forward_packets': 1,
                    'backward_packets': 0,
                    'packet_sizes': [len(packet)],
                    'packets': [packet],
                    'sni': sni,  # SNI 정보 추가
                    'tls_version': tls_version  # TLS 버전 정보 추가
                }

def save_flows_to_file(file_path):
    with open(file_path, 'w') as f:
        for flow_key, flow in flows.items():
            f.write(flow['flow_header'] + '\n')
            f.write(f"StartTime : {datetime.fromtimestamp(float(flow['start_time']))}\n")
            f.write(f"SrcIP : {flow['src_ip']}\n")
            f.write(f"SrcPort : {flow['src_port']}\n")
            f.write(f"Prot : {flow['protocol']}\n")            
            f.write(f"DstPort : {flow['dst_port']}\n")
            f.write(f"DstIP : {flow['dst_ip']}\n")
            f.write(f"Flow Duration : {flow['end_time'] - flow['start_time']} seconds\n")
            f.write(f"EndTime : {datetime.fromtimestamp(float(flow['end_time']))}\n")
            f.write(f"SNI : {flow['sni']}\n")            
            packet_sizes = flow['packet_sizes']
            f.write("PSD : ")
            f.write(", ".join(str(size) for size in packet_sizes))
            f.write("\n")
            f.write(f"Version: {flow['tls_version']}\n")

            f.write(f"Total Packet : {flow['forward_packets'] + flow['backward_packets']}\n")
            f.write(f"Forward Packet : {flow['forward_packets']}\n")
            f.write(f"Backward Packet : {flow['backward_packets']}\n")
            f.write("\n\n")



flows = {}  # 플로우를 저장할 딕셔너리

# 대상 디렉토리에서 pcap 파일 목록 가져오기
xml_path = sys.argv[1]
tree = ET.parse(xml_path)
rule_dir = tree.find('detection_rule')  

target_traffic_dir = tree.find('target_traffic')  
target_traffic_path = target_traffic_dir.find('pcap').text + "LIVE1.pcap"
#target_traffic_path = target_traffic_dir.find('pcap').text + "crack/crack1.pcap"

output_traffic_dir = tree.find('target_traffic')  
output_traffic_path = output_traffic_dir.find('fwp').text + "LIVE1.txt"


from datetime import datetime

print("Target Path : ", target_traffic_path)
print("Output Path : ", output_traffic_path)

# 패킷 읽기
packets = rdpcap(target_traffic_path)

# 멀티스레딩으로 패킷 처리
num_threads = 8  # 원하는 스레드 개수 설정
packets_per_thread = len(packets) // num_threads
threads = []

for i in range(num_threads):
    start_index = i * packets_per_thread
    end_index = (i + 1) * packets_per_thread if i < num_threads - 1 else len(packets)
    thread_packets = packets[start_index:end_index]
    
    thread = threading.Thread(target=process_packets_thread, args=(thread_packets,))
    threads.append(thread)
    thread.start()

for thread in threads:
    thread.join()

# 결과 저장
save_flows_to_file(output_traffic_path)

