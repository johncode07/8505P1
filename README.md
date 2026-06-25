# README.md

## Project Overview

This is a covert C&C (command-and-control) RAT implementation for a security course assignment. It consists of two sides:
- `attacker.py` — the commander; runs an interactive menu to control the victim
- `victim.py` — runs on the victim machine; listens for port knocks and executes commands

Refer to `docs/SCOPE.md` for assignment requirements. All features should eventually adhere to these requirements.

## Running

Both sides require root/sudo (scapy needs raw socket access):

```bash
sudo python3 attacker.py
sudo python3 victim.py
```

Install dependencies:
```bash
pip install -r requirements.txt
```

## Storage configuration

Storage for watched files and directories should be under `data/watched/`. Watched command should create subfolders here for every run with timestamp of start time as part of the name. E.g. `data/watched/12_55_2026_06_11` or similar.
Storage for keylog files should be under `data/keylog/` with timestamp as part of the name. E.g. `data/keylog/12_55_2026_06_11` or similar.
Storage for other transferred files is located under `data/victim/` and `data/attacker/` for victim and attacker respectively.

## Network Configuration

IPs and the network interface are set passed in as command line arguments and set in `mods/shared.py`.

## Architecture

### Covert Protocol (`mods/protocol.py`)

Data is carried inside standard TCP header fields — no payload is used:
- **Data** (up to 4 bytes per packet) packed into the TCP `seq` field
- **Data length** carried in the TCP `ack` field
- **End of stream** signaled by a TCP FIN packet (`flags='F'`)
- **Acknowledgement** ßTCP ACK packet (`flags='A'`)

Port convention: `sport=7001`, `dport=8001` for main channel. Secondary channels (e.g., file watch) use `7002`/`8002` to avoid collisions.

Scapy's `sniff()` with `inbound` filter is used on both sides — no actual ports are opened; packets are intercepted before reaching the OS network stack.

### Port Knocking (`mods/knocking.py`)

Session initiation uses UDP port knocking in sequence: **3000 → 4000 → 5000 → 6000**.

- Attacker sends via `send_port_knocks(dst)` using a raw UDP socket
- Victim listens via `wait_for_knock()` using scapy sniff; tracks per-host FSM in `knocks_tracker`
- After successful knock, victim sends an ACK packet; attacker calls `check_for_ack()` to confirm

### Command Flow

1. Attacker menu (`attacker.py`) calls `handle_command()` in `mods/handlers.py`
2. Handler serializes the command (e.g., `b'sf filename'`) and calls `send_data()` to the victim
3. Victim's main loop (`victim.py`) calls `receive_data()` to get the command, parses it, acts, and sends back results
4. Handlers that expect a response call `receive_data()` or `check_for_ack()` after sending

### Modules

| File | Purpose |
|---|---|
| `mods/shared.py` | IPs, interface, `OPTIONS_LIST` menu labels |
| `mods/protocol.py` | Packet build/send/receive primitives |
| `mods/knocking.py` | Port knock send (`attacker`) and receive (`victim`) |
| `mods/handlers.py` | Attacker-side per-command logic |
| `mods/keylogger.py` | Keylogger start/stop (stubs — needs implementation) |
| `mods/monitoring.py` | File/directory watcher using `watchfiles` |

### Command Codes

Defined in `mods/shared.py` `OPTIONS_LIST`: `cn`, `dc`, `sf`, `dl`, `k+`, `k-`, `wf`, `wd`, `rn`, `un`, `ex`.

## Guidelines

- No comments except for genuinely non-obvious logic (existing TODOs are acceptable).
- If confidence in completing a task is below ~95%, stop and ask clarifying questions.
