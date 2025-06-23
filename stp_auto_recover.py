import time
import re
from datetime import datetime
from netmiko import ConnectHandler
import pygame
import threading

log_file_path = "/var/log/syslog-remote/syslog.log"
pattern = r"%SPANTREE-2-BLOCK_BPDUGUARD.*port (\S+)"

switch = {
    "device_type": "cisco_ios",
    "host": "192.168.104.7",
    "username": "admin",
    "password": "cisco123",
    "secret": "cisco123",
}

interface_state = {}
poll_interval = 5
stable_threshold = 5

# Hàm phát âm thanh
def play_alert():
    pygame.mixer.init()
    pygame.mixer.music.load("/opt/alert.mp3")  # Đảm bảo file alert.mp3 nằm ở /opt/
    pygame.mixer.music.play()

def tail_log():
    with open(log_file_path, "r") as f:
        f.seek(0, 2)
        while True:
            dong = f.readline()
            if not dong:
                time.sleep(0.1)
                continue
            yield dong.strip()

def monitor_log():
    for dong_log in tail_log():
        match = re.search(pattern, dong_log)
        if match:
            interface = match.group(1)
            print(f"[{datetime.now()}] Phat hien tan cong BPDU tren {interface}: {dong_log}")
            
            # Phát âm thanh cảnh báo
            threading.Thread(target=play_alert, daemon=True).start()

            if interface not in interface_state:
                interface_state[interface] = {
                    "counter": 0,
                    "last_log": dong_log
                }
            else:
                if dong_log == interface_state[interface]["last_log"]:
                    interface_state[interface]["counter"] += 1
                    print(f"[{datetime.now()}] {interface} log khong thay doi ({interface_state[interface]['counter']}/{stable_threshold})")
                else:
                    interface_state[interface]["counter"] = 0
                    interface_state[interface]["last_log"] = dong_log
                    print(f"[{datetime.now()}] {interface} phat hien log moi -> dang con bi tan cong")

            if interface_state[interface]["counter"] >= stable_threshold:
                print(f"[{datetime.now()}] {interface} da on dinh -> co the hacker da ngung tan cong")
                interface_state[interface]["counter"] = 0

if __name__ == "__main__":
    monitor_log()































import time
import re
from datetime import datetime
from netmiko import ConnectHandler

log_file_path = "/var/log/syslog-remote/syslog.log"
pattern = r"%SPANTREE-2-BLOCK_BPDUGUARD.*port (\S+)"

switch = {
    "device_type": "cisco_ios",
    "host": "192.168.104.7",
    "username": "admin",
    "password": "cisco123",
    "secret": "cisco123",
}

# Trạng thái theo dõi từng interface
interface_state = {}  # { "Et0/3": {"shutdown": False, "stable_counter": 0, "last_log": ""} }

poll_interval = 5
stable_threshold = 5  # Số lần log không đổi thì cho rằng hacker đã ngưng

def shutdown_interface(net_connect, interface):
    print(f"[{datetime.now()}] Shutdown {interface}")
    net_connect.send_config_set([
        f"interface {interface}",
        "shutdown"
    ])
    interface_state[interface]["shutdown"] = True

def enable_interface(net_connect, interface):
    print(f"[{datetime.now()}] Enable {interface}")
    net_connect.send_config_set([
        f"interface {interface}",
        "no shutdown"
    ])
    interface_state[interface]["shutdown"] = False

def tail_log():
    with open(log_file_path, "r") as f:
        f.seek(0, 2)  # Di chuyển đến cuối file
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.1)
                continue
            yield line.strip()

def monitor_log():
    for log_line in tail_log():
        match = re.search(pattern, log_line)
        if match:
            interface = match.group(1)
            print(f"[{datetime.now()}] Phát hiện BPDU attack trên {interface}: {log_line}")

            if interface not in interface_state:
                interface_state[interface] = {
                    "shutdown": False,
                    "stable_counter": 0,
                    "last_log": ""
                }

            net_connect = None
            try:
                net_connect = ConnectHandler(**switch)
                net_connect.enable()

                # Nếu chưa bị shutdown thì shutdown
                if not interface_state[interface]["shutdown"]:
                    shutdown_interface(net_connect, interface)
                    interface_state[interface]["stable_counter"] = 0

            except Exception as e:
                print(f"Lỗi khi cấu hình switch: {e}")

            finally:
                if net_connect:
                    net_connect.disconnect()

        # Nếu port đang shutdown, theo dõi log có thay đổi không
        for interface, state in interface_state.items():
            if state["shutdown"]:
                # Nếu log không đổi, tăng counter
                if log_line == state["last_log"]:
                    state["stable_counter"] += 1
                    print(f"[{datetime.now()}] {interface} log không đổi ({state['stable_counter']}/{stable_threshold})")
                else:
                    state["stable_counter"] = 0
                state["last_log"] = log_line

                # Nếu ổn định, bật lại cổng
                if state["stable_counter"] >= stable_threshold:
                    net_connect = None
                    try:
                        net_connect = ConnectHandler(**switch)
                        net_connect.enable()
                        enable_interface(net_connect, interface)
                        state["stable_counter"] = 0
                    except Exception as e:
                        print(f"Lỗi khi bật lại cổng {interface}: {e}")
                    finally:
                        if net_connect:
                            net_connect.disconnect()

if __name__ == "__main__":
    monitor_log()




