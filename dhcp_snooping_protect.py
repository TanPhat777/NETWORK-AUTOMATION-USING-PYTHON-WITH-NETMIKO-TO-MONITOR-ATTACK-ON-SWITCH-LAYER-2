################### DHCP Snooping ##########################

Code: nano /opt/dhcp_snooping_protect.py

import time
import re
from netmiko import ConnectHandler

switch = {
    "device_type": "cisco_ios",
    "host": "192.168.104.7",  # Địa chỉ switch
    "username": "admin",
    "password": "cisco123",
    "secret": "cisco123",
}

log_file_path = "/var/log/syslog-remote/syslog.log"
# Regex tìm cổng từ log DHCP Snooping err-disable
pattern = r"%DHCP_SNOOPING.*interface (\S+)"

def shutdown_and_recover_interface(interface):
    try:
        print(f"Kết nối tới switch để xử lý cổng {interface}...")
        net_connect = ConnectHandler(**switch)
        net_connect.enable()

        # Shutdown cổng
        net_connect.send_config_set([
            f"interface {interface}",
            "shutdown"
        ])
        print(f"Đã shutdown cổng {interface}.")

        # Đợi 30 giây rồi bật lại
        print(f"Chờ 30 giây trước khi bật lại cổng {interface}...")
        time.sleep(30)

        net_connect.send_config_set([
            f"interface {interface}",
            "no shutdown"
        ])
        print(f"Đã bật lại cổng {interface}.")
        
        net_connect.disconnect()
    except Exception as e:
        print(f"Lỗi khi xử lý cổng {interface}: {e}")

def monitor_logs():
    print(f"Theo dõi log tại {log_file_path}...")
    with open(log_file_path, "r") as file:
        file.seek(0, 2)  # Đi đến cuối file
        while True:
            line = file.readline()
            if not line:
                time.sleep(1)
                continue

            match = re.search(pattern, line)
            if match:
                interface = match.group(1)
                print(f"Phát hiện DHCP Snooping attack trên {interface}!")
                shutdown_and_recover_interface(interface)

if __name__ == "__main__":
    monitor_logs()
