#!/usr/bin/env python3
"""
Слушает лог-файл Security.go, вытаскивает IP атакующих,
и дарит им букет болезней.
"""
import json, subprocess, time, sys

LOG_FILE = "logs.json"  # путь к JSON-логам
MODE = "infect" 

def process_event(ip, event_type):
    if event_type == "POSSIBLE DDOS DETECTED":
        # Запускаем букетв в тот IP
        if MODE == "infect":
            subprocess.Popen(["python3", "/opt/scripts/counter_ddos.py", "--target-ip", ip])
    elif event_type == "POSSIBLE BRUTEFORCE DETECTED":
        # Можно тоже
        subprocess.Popen(["python3", "/opt/scripts/counter_ddos.py", "--target-ip", ip])

def tail():
    with open(LOG_FILE, "r") as f:
        f.seek(0, 2)  # в конец файла
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.1)
                continue
            try:
                entry = json.loads(line)
                msg = entry.get("msg", "")
                ip = entry.get("ip", "")
                if "POSSIBLE DDOS" in msg or "POSSIBLE BRUTEFORCE" in msg:
                    process_event(ip, msg)
            except:
                pass

if __name__ == "__main__":
    tail()
