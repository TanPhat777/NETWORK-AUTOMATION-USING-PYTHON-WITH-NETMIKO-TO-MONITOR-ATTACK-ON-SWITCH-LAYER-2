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

# Cau hinh switch
switch = {
    "device_type": "cisco_ios",
    "host": "192.168.104.7",
    "username": "admin",
    "password": "cisco123",
    "secret": "cisco123",
}

interface = "Ethernet0/3"
port_shutdown = False
last_violation_time = None

# Cau hinh nguong va thoi gian
attack_threshold_pps = 100            # nguong packets/sec
violation_timeout = 30                # thoi gian cho bat lai cong (giay)
poll_interval = 5                     # thoi gian kiem tra lap lai
stable_input_threshold = 3            # so lan khong doi packets input de xem la on dinh

# Regex de lay du lieu tu show interface
packet_input_pattern = r"(\d+) packets input"
packet_rate_pattern = r"5 minute input rate \d+ bits/sec, (\d+) packets/sec"

# Trang thai theo doi
last_packet_input = None
stable_counter = 0

def shutdown_interface(net_connect):
    global port_shutdown
    print(f"[{datetime.now()}] Shutdown {interface} do phat hien tan cong")
    net_connect.send_config_set([
        f"interface {interface}",
        "shutdown"
    ])
    port_shutdown = True

def enable_interface(net_connect):
    global port_shutdown
    print(f"[{datetime.now()}] Bat lai {interface} sau khi attacker ngung tan cong")
    net_connect.send_config_set([
        f"interface {interface}",
        "no shutdown"
    ])
    port_shutdown = False

def monitor_interface():
    global port_shutdown, last_violation_time, last_packet_input, stable_counter

    while True:
        try:
            net_connect = ConnectHandler(**switch)
            net_connect.enable()

            output = net_connect.send_command(f"show interface {interface}")

            # Lay packets input tong cong
            match_input = re.search(packet_input_pattern, output)
            match_rate = re.search(packet_rate_pattern, output)

            if not match_input or not match_rate:
                print(f"[{datetime.now()}] Khong tim thay thong tin can thiet")
                net_connect.disconnect()
                time.sleep(poll_interval)
                continue

            packet_input = int(match_input.group(1))
            packet_rate = int(match_rate.group(1))
            now = datetime.now()

            print(f"[{now}] Packets input: {packet_input} | Packets/sec: {packet_rate}")

            # Kiem tra su thay doi goi tin input
            if last_packet_input is not None:
                if packet_input == last_packet_input:
                    stable_counter += 1
                    print(f"[{now}] Packets input khong thay doi ({stable_counter}/{stable_input_threshold})")
                else:
                    stable_counter = 0
            last_packet_input = packet_input

            # Phat hien tan cong
            if packet_rate >= attack_threshold_pps:
                last_violation_time = now
                if not port_shutdown:
                    shutdown_interface(net_connect)

            # Neu da shutdown, kiem tra dieu kien bat lai
            if port_shutdown and last_violation_time:
                elapsed = (now - last_violation_time).total_seconds()
                if elapsed > violation_timeout:
                    # Kiem tra lai rate va input
                    output = net_connect.send_command(f"show interface {interface}")
                    match_input = re.search(packet_input_pattern, output)
                    match_rate = re.search(packet_rate_pattern, output)

                    if match_input and match_rate:
                        new_packet_input = int(match_input.group(1))
                        new_packet_rate = int(match_rate.group(1))
                        print(f"[{now}] Kiem tra lai - packets/sec: {new_packet_rate}, packets input: {new_packet_input}")

                        if new_packet_rate < attack_threshold_pps and stable_counter >= stable_input_threshold:
                            enable_interface(net_connect)
                            last_violation_time = None
                            stable_counter = 0
                        else:
                            print(f"[{now}] Tan cong van tiep dien. Khong bat lai cong")
                            last_violation_time = now  # reset timer

            net_connect.disconnect()

        except Exception as e:
            print(f"[{datetime.now()}] Loi: {e}")

        time.sleep(poll_interval)

if __name__ == "__main__":
    monitor_interface()

