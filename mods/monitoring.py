from watchfiles import watch

def start_watching(path: str):
    for changes in watch(path):
        print(changes)