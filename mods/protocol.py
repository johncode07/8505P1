import math
import time

from scapy.all import *
from scapy.layers.inet import IP, TCP 

from mods.shared import INTERFACE

class CustomPacket:
    sport: int

    data_len: int
    data: bytes

    is_final: bool
    is_ack: bool

def build_ack_packet(src: str, dst: str) -> Packet:
    return (
        IP(src=src, dst=dst) / 
        TCP(sport=7001, ack=0, seq=0,dport=8001, flags='A')
    )

def build_final_packet(src: str, dst: str) -> Packet:
    return (
        IP(src=src, dst=dst)
        /
        TCP(
            sport=7001,
            dport=8001,
            ack=0, seq=0,
            flags="F"
        )
    )

def build_tcp_packet(data: bytes, src: str, dst: str) -> Packet:
    seq_packed = int.from_bytes(data[:4], byteorder='big')
    return (
        IP(src=src, dst=dst)
        /
        TCP(
            sport=7001,
            dport=8001,
            ack=len(data),
            seq=seq_packed,
        )
    )


def parse_packet(packet: Packet) -> CustomPacket:
    custom_packet = CustomPacket()
    if packet.haslayer(TCP):
        custom_packet.sport = packet[TCP].sport
        data_len: int = packet[TCP].ack
        data_raw: int = packet[TCP].seq
        data = data_raw.to_bytes(data_len, byteorder='big')

        custom_packet.data_len = data_len
        custom_packet.data = data
        custom_packet.is_final = packet[TCP].flags.F
        custom_packet.is_ack = packet[TCP].flags.A
        
    
    return custom_packet

def check_for_ack(from_ip: str, timeout: int = 10) -> bool:
    res = receive_packet(from_ip, timeout=timeout)
    if res and res.is_ack:
        return True
    return False

def send_ack_packet(src: str, dst: str):
    p = build_ack_packet(src, dst)
    send(p, verbose=False)

def send_data(payload: bytes, src: str,  dst: str, sleep: int = 1):
    time.sleep(sleep)
    num_packets = math.ceil(len(payload) / 4.0)
    for i in range(num_packets):
        start_index = i * 4
        data_to_send = payload[start_index:start_index+4]
        p = build_tcp_packet(data_to_send, src=src, dst=dst)
        send(p, verbose=False)
    
    p = build_final_packet(src, dst)
    send(p, verbose=False)

def receive_packet(from_ip: str, iface: str = INTERFACE, timeout=10) -> CustomPacket:
    custom_packet: CustomPacket = None
    def should_stop(_: Packet):
        return True
    
    def process_packet(packet: Packet):
        nonlocal custom_packet
        custom_packet = parse_packet(packet)
    
    sniff(filter=f'tcp and src port 7001 and dst port 8001 src host {from_ip} and inbound', 
          prn=process_packet, iface=iface, store=False, stop_filter=should_stop, timeout=timeout)
    
    return custom_packet


def receive_data(from_ip: str, iface: str = INTERFACE, timeout=10) -> bytes:
    output: bytes = b''

    def should_stop(packet: Packet):
        parsed = parse_packet(packet)
        return parsed.is_final
    
    def process_packet(packet: Packet):
        nonlocal output
        parsed = parse_packet(packet)
        output += parsed.data
    
    sniff(filter=f'tcp and src port 7001 and dst port 8001 and src host {from_ip} and inbound', 
          prn=process_packet, iface=iface, store=False, stop_filter=should_stop, timeout=timeout)

    return output
