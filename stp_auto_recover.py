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
poll_interval = 5
stable_counter = 0
stable_threshold = 5  # Sau 5 lan log khong thay doi -> bat lai cong

last_attack_time = None

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

def monitor_log():
    global port_shutdown, stable_counter, last_attack_time

    last_log = ""

    while True:
        try:
            net_connect = ConnectHandler(**switch)
            net_connect.enable()

            log_output = net_connect.send_command("show log | include Et0/3")
            log_lines = log_output.strip().splitlines()
            latest_log = log_lines[-1] if log_lines else ""

            if "BLOCK_BPDUGUARD" in latest_log or "bpduguard error detected" in latest_log:
                print(f"[{datetime.now()}] Phat hien tan cong BPDU Guard tren {interface}")
                if not port_shutdown:
                    shutdown_interface(net_connect)
                last_attack_time = datetime.now()
                stable_counter = 0

            elif port_shutdown:
                # Neu da bi shutdown, theo doi xem log co thay doi hay khong
                if latest_log == last_log:
                    stable_counter += 1
                    print(f"[{datetime.now()}] Log khong thay doi ({stable_counter}/{stable_threshold})")
                else:
                    stable_counter = 0
                last_log = latest_log

                # Neu log on dinh => bat lai cong
                if stable_counter >= stable_threshold:
                    enable_interface(net_connect)
                    stable_counter = 0

            net_connect.disconnect()

        except Exception as e:
            print(f"Loi: {e}")

        time.sleep(poll_interval)

if __name__ == "__main__":
    monitor_log()



