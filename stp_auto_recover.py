import time
import re
from datetime import datetime
from netmiko import ConnectHandler

switch = {
    "device_type": "cisco_ios",
    "host": "192.168.104.7",
    "username": "admin",
    "password": "cisco123",
    "secret": "cisco123",
}

interface = "Ethernet0/3"
port_shutdown = False

# Thời gian kiểm tra (giây)
poll_interval = 5

def shutdown_interface(net_connect):
    global port_shutdown
    print(f"[{datetime.now()}] Shutdown {interface}")
    net_connect.send_config_set([
        f"interface {interface}",
        "shutdown"
    ])
    port_shutdown = True

def enable_interface(net_connect):
    global port_shutdown
    print(f"[{datetime.now()}] Enable {interface}")
    net_connect.send_config_set([
        f"interface {interface}",
        "no shutdown"
    ])
    port_shutdown = False

def monitor_interface():
    global port_shutdown
    last_packet_input = None
    stable_counter = 0
    stable_threshold = 5  # So lan khong thay doi => bat lai (2 * poll_interval = 10s)

    while True:
        try:
            net_connect = ConnectHandler(**switch)
            net_connect.enable()
            output = net_connect.send_command(f"show interface {interface}")
            net_connect.disconnect()

            match = re.search(r"(\d+) packets input", output)
            if match:
                packet_input = int(match.group(1))
                now = datetime.now()
                print(f"[{now}] {interface} packets input: {packet_input}")

                if last_packet_input is not None:
                    if packet_input == last_packet_input:
                        stable_counter += 1
                        print(f"Khong thay doi ({stable_counter}/{stable_threshold})")
                    else:
                        stable_counter = 0  # reset vi packets tang

                if not port_shutdown and last_packet_input is not None and packet_input > last_packet_input:
                    net_connect = ConnectHandler(**switch)
                    net_connect.enable()
                    shutdown_interface(net_connect)
                    net_connect.disconnect()
                    stable_counter = 0

                if port_shutdown and stable_counter >= stable_threshold:
                    net_connect = ConnectHandler(**switch)
                    net_connect.enable()
                    enable_interface(net_connect)
                    net_connect.disconnect()
                    stable_counter = 0

                last_packet_input = packet_input

            else:
                print("Khong tim thay 'packets input' trong output.")

        except Exception as e:
            print(f"Loi: {e}")

        time.sleep(poll_interval)

if __name__ == "__main__":
    monitor_interface()

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




