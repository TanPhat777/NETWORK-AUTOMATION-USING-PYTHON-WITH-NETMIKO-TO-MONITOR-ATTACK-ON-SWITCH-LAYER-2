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
