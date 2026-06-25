import socket
import time

from scapy.all import *
from scapy.layers.inet import IP, UDP

from mods.shared import Cfg

knocks_fsm = {3000: 4000, 4000: 5000, 5000: 6000, 6000: 'win'}

knocks_tracker = {}
flags = {'knocking_success': False}

def send_port_knocks(dst: str = '127.0.0.1'):
    message = "knock"

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    print(f'knocking on {dst}:3000')
    sock.sendto(bytes(message, "utf-8"), (dst, 3000))
    time.sleep(1)
    print(f'knocking on {dst}:4000')
    sock.sendto(bytes(message, "utf-8"), (dst, 4000))
    time.sleep(1)
    print(f'knocking on {dst}:5000')
    sock.sendto(bytes(message, "utf-8"), (dst, 5000))
    time.sleep(1)
    print(f'knocking on {dst}:6000')
    sock.sendto(bytes(message, "utf-8"), (dst, 6000))


def knock_knock(host: str, port: int) -> bool:
    if host not in knocks_tracker:
        knocks_tracker[host] = 3000
    
    next_in_sequence = knocks_tracker[host]

    if port != next_in_sequence:
        next_in_sequence = 3000
        return False
    
    next_port = knocks_fsm[port]
    if next_port == 'win':
        return True
    
    knocks_tracker[host] = next_port
    return False

def wait_for_knock(iface = None) -> bool:
    flags['knocking_success'] = False
    if iface == None: iface = Cfg.IFACE

    src: str = ''
    def should_stop(_: Packet) -> bool:
        time.sleep(1)
        return flags['knocking_success']

    def process_packet(packet: Packet):
        nonlocal src
        src = packet[IP].src
        port = packet[UDP].dport
        if knock_knock(src, port):
            flags['knocking_success'] = True

        if knock_knock(src, port):
            print('Port knocking success!')
        else:
            print(f"Port knocking attempt: {src}:{port}")

    sniff(filter='udp and (port 3000 or port 4000 or port 5000 or port 6000)', 
          prn=process_packet, stop_filter=should_stop, iface=iface, store=False)
    
    return src
