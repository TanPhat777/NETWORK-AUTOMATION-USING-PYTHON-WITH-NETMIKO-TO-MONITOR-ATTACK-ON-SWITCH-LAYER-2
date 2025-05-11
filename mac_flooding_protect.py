import time
import re
from netmiko import ConnectHandler

switch = {
    "device_type": "cisco_ios",
    "host": "192.168.104.6",
    "username": "admin",
    "password": "cisco123",
    "secret": "cisco123",
}

log_file_path = "/var/log/syslog-remote/syslog.log"
pattern = r"%PORT_SECURITY-2-PSECURE_VIOLATION:.*port (\S+)"

def recover_interface_if_safe(interface):
    try:
        print(f"Ket noi den switch de xu ly cong {interface}...")
        net_connect = ConnectHandler(**switch)
        net_connect.enable()

        while True:
            # Doc thong tin interface
            output1 = net_connect.send_command(f"show interface {interface} | include packets input")
            match1 = re.search(r"(\d+) packets input", output1)
            if match1:
                packets_before = int(match1.group(1))
            else:
                print(f"Khong lay duoc thong tin packets input cua {interface}.")
                break

            time.sleep(10)  # Doi 10 giay

            output2 = net_connect.send_command(f"show interface {interface} | include packets input")
            match2 = re.search(r"(\d+) packets input", output2)
            if match2:
                packets_after = int(match2.group(1))
            else:
                print(f"Khong lay duoc thong tin packets input cua {interface}.")
                break

            print(f"Packets truoc: {packets_before}, Packets sau: {packets_after}")

            if packets_after > packets_before:
                print(f"Tan cong van tiep tuc tren {interface}, chua mo cong lai.")
            else:
                print(f"Tan cong da dung tren {interface}, tien hanh shutdown va no shutdown de mo cong.")
                # Shutdown + no shutdown de mo cong lai
                net_connect.send_config_set([
                    f"interface {interface}",
                    "shutdown",
                    "no shutdown"
                ])
                print(f"Da mo lai cong {interface}.")
                break

        net_connect.disconnect()
    except Exception as e:
        print(f"Loi khi xu ly cong {interface}: {e}")

def monitor_logs():
    print(f"Theo doi log tu {log_file_path}...")
    with open(log_file_path, "r") as file:
        file.seek(0, 2)  # Di chuyen den cuoi file
        while True:
            line = file.readline()
            if not line:
                time.sleep(1)
                continue

            match = re.search(pattern, line)
            if match:
                interface = match.group(1)
                print(f"Phat hien err-disable tren cong {interface}")
                recover_interface_if_safe(interface)

if __name__ == "__main__":
    monitor_logs()


import time
import re
from datetime import datetime
from netmiko import ConnectHandler

switch = {
    "device_type": "cisco_ios",
    "host": "192.168.104.6",
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


    











