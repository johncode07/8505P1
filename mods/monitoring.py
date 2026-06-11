import threading

from pathlib import Path

import watchfiles


def watch_file(path: str, on_data, stop_event: threading.Event):
    filepath = Path(path)
    on_data(filepath.read_bytes())
    for _ in watchfiles.watch(path, stop_event=stop_event):
        on_data(filepath.read_bytes())


def watch_directory(path: str, on_data, stop_event: threading.Event):
    watched_dir = Path(path)
    for f in sorted(watched_dir.rglob('*')):
        if f.is_file():
            rel = f.relative_to(watched_dir)
            on_data(str(rel).encode() + b'\0' + f.read_bytes())
    for changes in watchfiles.watch(path, stop_event=stop_event):
        for _, changed_path in changes:
            f = Path(changed_path)
            if f.is_file():
                rel = f.relative_to(watched_dir)
                on_data(str(rel).encode() + b'\0' + f.read_bytes())


def file_update_handler(watch_dir: Path, filename: str):
    def on_update(data: bytes):
        (watch_dir / filename).write_bytes(data)
        print(f'  [wf update] {filename} ({len(data)} bytes)')
    return on_update


def dir_update_handler(watch_dir: Path):
    def on_update(data: bytes):
        null_idx = data.index(b'\0')
        rel_path = data[:null_idx].decode()
        file_bytes = data[null_idx + 1:]
        target = watch_dir / rel_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(file_bytes)
        print(f'  [wd update] {rel_path} ({len(file_bytes)} bytes)')
    return on_update
